package gg.effront.anarcry.scanner.web.idor;

import gg.effront.anarcry.model.Finding;
import gg.effront.anarcry.model.Severity;
import gg.effront.anarcry.scanner.ScanConfig;
import gg.effront.anarcry.scanner.ScanContext;
import gg.effront.anarcry.scanner.Scanner;
import gg.effront.anarcry.scanner.util.Http;
import gg.effront.anarcry.scanner.util.HttpClientFactory;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import gg.effront.anarcry.model.CweRegistry;
import gg.effront.anarcry.model.CvssCalculator;

public class IdorModule implements Scanner {

    private static final List<String> ID_PATHS = List.of("/api/user/1", "/api/users/1", "/api/user/2", "/api/users/2",
            "/api/account/1", "/api/accounts/1", "/api/profile/1", "/api/me", "/api/order/1", "/api/orders/1",
            "/api/document/1", "/api/invoice/1", "/api/admin/1", "/api/v1/user/1", "/api/v1/users/1", "/api/v2/user/1");

    // Paths to attempt DELETE IDOR (cross-user deletion)
    private static final List<String> DELETE_PATHS = List.of("/api/user/2", "/api/users/2", "/api/account/2",
            "/api/order/2", "/api/document/2", "/api/invoice/2", "/api/v1/user/2", "/api/v1/users/2");

    // GraphQL IDOR mutations -- try with user IDs 1 and 2
    private static final List<String> GQL_MUTATIONS = List.of("{\"query\":\"mutation { deleteUser(id: 2) { id } }\"}",
            "{\"query\":\"mutation { updateUser(id: 2, input: {email: \\\"pwned@evil.com\\\"}) { id email } }\"}",
            "{\"query\":\"{ user(id: 2) { id email password role } }\"}",
            "{\"query\":\"{ orders(userId: 2) { id total items { name } } }\"}");

    private static final Pattern ID_PATTERN = Pattern.compile("/(\\d+)$");

    @Override
    public String id() {
        return "IDOR";
    }

    private static final String CWE_ID = CweRegistry.cweId("IDOR");
    private static final String CWE_TITLE = CweRegistry.cweTitle("IDOR");

    private static final String VECTOR_READ = "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N";
    private static final double SCORE_READ = CvssCalculator.calculate(VECTOR_READ);

    private static final String VECTOR_DELETE = "AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N";
    private static final double SCORE_DELETE = CvssCalculator.calculate(VECTOR_DELETE);

    private static final String VECTOR_GRAPHQL = "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N";
    private static final double SCORE_GRAPHQL = CvssCalculator.calculate(VECTOR_GRAPHQL);

    @Override
    public List<Finding> scan(ScanContext ctx, Consumer<String> log) throws Exception {
        String token1 = ctx.jwtToken();
        String token2 = ctx.jwtToken2();
        boolean hasBearerAuth = token1 != null && !token1.isBlank();
        boolean hasCookieAuth = !ctx.config().sessionCookie().isBlank();

        if (!hasBearerAuth && !hasCookieAuth) {
            log.accept("[*] IDOR: ignorado -- nenhuma autenticação informada");
            return List.of();
        }

        if (hasCookieAuth && !hasBearerAuth) {
            log.accept("[~] IDOR: usando autenticação via Cookie");
        }

        boolean canCrossUser = (hasBearerAuth && token2 != null && !token2.isBlank())
                || (hasCookieAuth && !ctx.config().sessionCookie2().isBlank());
        if (!canCrossUser) {
            String reason = hasCookieAuth ? "sessionCookie2 não informado" : "jwtToken2 não informado";
            log.accept("[*] IDOR: " + reason + " -- apenas probes DELETE e GraphQL");
        }

        List<Finding> findings = new ArrayList<>();
        HttpClient hc = HttpClientFactory.http2();

        String scheme = ctx.isHttps() ? "https" : "http";
        int defPort = ctx.isHttps() ? 443 : 80;
        String base = scheme + "://" + ctx.host() + (ctx.port() != defPort ? ":" + ctx.port() : "");

        log.accept("[~] IDOR: iniciando probes em " + base);

        String discoveredId = extractUserId(ctx, hc, base);

        List<String> effectivePaths;
        if (discoveredId != null) {
            List<String> uuidPaths = new ArrayList<>(List.of("/api/user/" + discoveredId, "/api/users/" + discoveredId,
                    "/api/account/" + discoveredId, "/api/profile/" + discoveredId));
            uuidPaths.addAll(ID_PATHS);
            effectivePaths = uuidPaths;
            log.accept("[~] IDOR: usando ID descoberto para probing: " + discoveredId);
        } else {
            effectivePaths = new ArrayList<>(ID_PATHS);
        }

        if (!ctx.discoveredPaths().isEmpty()) {
            for (String dp : ctx.discoveredPaths().paths()) {
                if (dp.matches(".*/(?:api|v[0-9])/.*") && !effectivePaths.contains(dp)) {
                    effectivePaths.add(dp);
                    effectivePaths.add(dp + "/1");
                    effectivePaths.add(dp + "/2");
                }
            }
            log.accept("[~] IDOR: " + effectivePaths.size() + " paths (+" + ctx.discoveredPaths().pathCount()
                    + " from Crawler)");
        }

        // Phase 1: cross-user GET (requires two auth contexts)
        if (canCrossUser) {
            boolean cookieCrossUser = hasCookieAuth && !hasBearerAuth;
            ScanContext ctx2 = cookieCrossUser ? swapCookie(ctx, ctx.config().sessionCookie2()) : ctx;
            for (String path : effectivePaths) {
                String r1 = fetch(ctx, hc, base + path, hasBearerAuth ? token1 : null);
                if (r1 == null || isHtml(r1)) {
                    continue;
                }

                String r2 = fetch(ctx2, hc, base + path, hasBearerAuth ? token2 : null);
                if (r2 == null) {
                    continue;
                }

                if (isSimilar(r1, r2)) {
                    log.accept("[!!] IDOR: acesso cruzado detectado em " + path);
                    String repro = cookieCrossUser
                            ? "# Com cookie do usuário 1:\ncurl -b '" + abbreviated(ctx.config().sessionCookie())
                                    + "' '" + base + path + "'\n"
                                    + "# Com cookie do usuário 2 (não deve ter acesso):\ncurl -b '"
                                    + abbreviated(ctx.config().sessionCookie2()) + "' '" + base + path + "'"
                            : "# Com token do usuário 1:\ncurl -H 'Authorization: Bearer " + abbreviated(token1) + "' '"
                                    + base + path + "'\n"
                                    + "# Com token do usuário 2 (não deve ter acesso):\ncurl -H 'Authorization: Bearer "
                                    + abbreviated(token2) + "' '" + base + path + "'";
                    String evidence = (cookieCrossUser ? "Cookie1 e Cookie2" : "Token1 e Token2")
                            + " recebem a mesma resposta em " + base + path + " | Similaridade: "
                            + similarityPercent(r1, r2) + "%" + " | Body preview: "
                            + r1.substring(0, Math.min(150, r1.length()));
                    findings.add(Finding.of("IDOR", path, "IDOR -- acesso não-autorizado ao recurso " + path,
                            Severity.MEDIUM, evidence,
                            "Insecure Direct Object Reference -- outro usuário pode acessar recursos "
                                    + "que não lhe pertencem. Expõe dados pessoais, financeiros ou administrativos.",
                            repro,
                            "Verificar autorização no nível de objeto (BOLA): validar que o usuário "
                                    + "autenticado é o dono do recurso. Use UUIDs aleatórios em vez de IDs sequenciais",
                            CWE_ID, CWE_TITLE, VECTOR_READ, SCORE_READ));
                    break;
                }
            }
        }

        // Phase 2: DELETE IDOR -- authenticated user attempts to delete another user's
        // resource (ID=2). Expected: 403 or 404. If 200/204 -> IDOR via DELETE.
        log.accept("[~] IDOR: testando DELETE cross-user em " + base);
        for (String path : DELETE_PATHS) {
            try {
                HttpRequest.Builder rb = HttpRequest.newBuilder().uri(URI.create(base + path))
                        .timeout(Duration.ofSeconds(5));
                if (hasBearerAuth) {
                    rb.header("Authorization", "Bearer " + token1);
                }
                HttpRequest req = rb.DELETE().build();
                HttpResponse<String> resp = Http.send(ctx, hc, req, HttpResponse.BodyHandlers.ofString(), id());
                int status = resp.statusCode();
                String deleteBody = resp.body() != null ? resp.body() : "";
                if ((status == 200 || status == 204) && !isHtml(deleteBody)) {
                    log.accept("[!!] IDOR DELETE: " + path + " retornou " + status);
                    String repro = hasCookieAuth
                            ? "curl -X DELETE -b '<SESSION_COOKIE>' '" + base + path + "'"
                            : "curl -X DELETE -H 'Authorization: Bearer <TOKEN>' '" + base + path + "'";
                    findings.add(Finding.of("IDOR", path, "IDOR DELETE -- deleção cross-user possível em " + path,
                            Severity.MEDIUM,
                            "DELETE " + base + path + " -> HTTP " + status
                                    + " | Esperado: 403/404 | Recurso de outro usuário foi deletado",
                            "IDOR via DELETE -- usuário pode deletar recursos de outros usuários sem autorização",
                            repro,
                            "Validar ownership do recurso antes de deletar; verificar que o ID no path "
                                    + "pertence ao usuário autenticado; retornar 403 para acesso não autorizado",
                            CWE_ID, CWE_TITLE, VECTOR_DELETE, SCORE_DELETE));
                    break;
                }
            } catch (Exception ignored) {
            }
        }

        // Phase 3: GraphQL IDOR -- mutations and queries with IDs of other users
        log.accept("[~] IDOR: testando GraphQL mutations em " + base);
        for (String gqlPath : List.of("/graphql", "/api/graphql", "/api/v1/graphql")) {
            boolean gqlFound = false;
            for (String mutation : GQL_MUTATIONS) {
                try {
                    HttpRequest.Builder rb = HttpRequest.newBuilder().uri(URI.create(base + gqlPath))
                            .timeout(Duration.ofSeconds(6)).header("Content-Type", "application/json");
                    if (hasBearerAuth) {
                        rb.header("Authorization", "Bearer " + token1);
                    }
                    HttpRequest req = rb.POST(HttpRequest.BodyPublishers.ofString(mutation)).build();
                    HttpResponse<String> resp = Http.send(ctx, hc, req, HttpResponse.BodyHandlers.ofString(), id());
                    String body = resp.body() != null ? resp.body() : "";

                    boolean hasData = body.contains("\"data\"") && !body.contains("\"data\":null");
                    boolean hasErrors = body.contains("\"errors\"");

                    if (resp.statusCode() == 200 && hasData && !hasErrors) {
                        log.accept("[!!] IDOR GraphQL: mutation/query retornou dados para ID alheio em " + gqlPath);
                        findings.add(Finding.of("IDOR", gqlPath, "IDOR GraphQL -- acesso/modificação de recurso alheio",
                                Severity.HIGH,
                                "POST " + base + gqlPath + " | Mutation: "
                                        + mutation.substring(0, Math.min(80, mutation.length()))
                                        + " | Response (200 chars): " + body.substring(0, Math.min(200, body.length())),
                                "GraphQL IDOR -- mutation ou query retorna dados de outro usuário sem "
                                        + "verificação de autorização no nível de objeto",
                                "curl -X POST -H 'Content-Type: application/json' "
                                        + "-H 'Authorization: Bearer <TOKEN>' '" + base + gqlPath + "' " + "-d '"
                                        + mutation + "'",
                                "Implementar autorização por campo e por resolver no GraphQL; "
                                        + "usar DataLoader com contexto do usuário; nunca confiar no ID enviado pelo"
                                        + " cliente",
                                CWE_ID, CWE_TITLE, VECTOR_GRAPHQL, SCORE_GRAPHQL));
                        gqlFound = true;
                        break;
                    }
                } catch (Exception ignored) {
                }
            }
            if (gqlFound) {
                break;
            }
        }

        if (findings.isEmpty()) {
            log.accept("[+] IDOR: nenhum acesso cruzado detectado");
        }
        return findings;
    }

    String extractUserId(ScanContext ctx, HttpClient hc, String base) {
        String[] mePaths = {"/api/me", "/api/profile", "/api/user/me", "/api/account"};
        Pattern idPat = Pattern.compile("\"(?:id|userId|_id|uuid|user_id)\"\\s*:\\s*\"?([A-Za-z0-9\\-_]{1,200})\"?");
        boolean hasBearerAuth = ctx.jwtToken() != null && !ctx.jwtToken().isBlank();
        for (String p : mePaths) {
            try {
                HttpRequest.Builder rb = HttpRequest.newBuilder().uri(URI.create(base + p))
                        .timeout(Duration.ofSeconds(5));
                if (hasBearerAuth) {
                    rb.header("Authorization", "Bearer " + ctx.jwtToken());
                }
                var resp = Http.send(ctx, hc, rb.GET().build(), HttpResponse.BodyHandlers.ofString(), id());
                if (resp.statusCode() == 200 && resp.body() != null) {
                    Matcher m = idPat.matcher(resp.body());
                    if (m.find()) {
                        return m.group(1);
                    }
                }
            } catch (Exception ignored) {
            }
        }
        return null;
    }

    private String fetch(ScanContext ctx, HttpClient hc, String url, String token) {
        try {
            HttpRequest.Builder rb = HttpRequest.newBuilder().uri(URI.create(url)).timeout(Duration.ofSeconds(6));
            if (token != null && !token.isBlank()) {
                rb.header("Authorization", "Bearer " + token);
            }
            HttpResponse<String> resp = Http.send(ctx, hc, rb.GET().build(), HttpResponse.BodyHandlers.ofString(),
                    id());
            if (resp.statusCode() == 200 && resp.body() != null && !resp.body().isBlank()) {
                return resp.body();
            }
        } catch (Exception ignored) {
        }
        return null;
    }

    private static boolean isHtml(String body) {
        String t = body.stripLeading();
        return t.startsWith("<!DOCTYPE") || t.startsWith("<html") || t.startsWith("<!doctype");
    }

    private boolean isSimilar(String a, String b) {
        if (a == null || b == null) {
            return false;
        }
        if (a.length() < 50 || b.length() < 50) {
            return false;
        }
        if (a.strip().equals(b.strip())) {
            return true;
        }
        int lenA = a.length(), lenB = b.length();
        if (lenA == 0 || lenB == 0) {
            return false;
        }
        double ratio = (double) Math.min(lenA, lenB) / Math.max(lenA, lenB);
        if (ratio < 0.9) {
            return false;
        }
        String prefA = a.substring(0, Math.min(100, lenA));
        String prefB = b.substring(0, Math.min(100, lenB));
        return prefA.equals(prefB);
    }

    private int similarityPercent(String a, String b) {
        if (a == null || b == null || a.isEmpty() || b.isEmpty()) {
            return 0;
        }
        return (int) ((double) Math.min(a.length(), b.length()) / Math.max(a.length(), b.length()) * 100);
    }

    private static String abbreviated(String token) {
        return token.substring(0, Math.min(20, token.length())) + "...";
    }

    private static ScanContext swapCookie(ScanContext ctx, String cookie) {
        ScanConfig altCfg = new ScanConfig(ctx.config().delayMs(), cookie, "", ctx.config().inScopeHosts(),
                ctx.config().suppressions(), ctx.config().redirectRelayUrl(), ctx.config().probeConcurrency());
        return new ScanContext(ctx.targetUrl(), ctx.jwtToken(), ctx.jwtToken2(), ctx.enabledModules(), altCfg,
                ctx.requestLog(), ctx.discoveredPaths(), ctx.wafState());
    }
}
