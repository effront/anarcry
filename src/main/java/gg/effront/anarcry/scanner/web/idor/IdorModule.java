package gg.effront.anarcry.scanner.web.idor;

import gg.effront.anarcry.model.CvssCalculator;
import gg.effront.anarcry.model.CweRegistry;
import gg.effront.anarcry.model.Finding;
import gg.effront.anarcry.model.Severity;
import gg.effront.anarcry.scanner.ScanConfig;
import gg.effront.anarcry.scanner.ScanContext;
import gg.effront.anarcry.scanner.Scanner;
import gg.effront.anarcry.scanner.util.CircuitBreakerException;
import gg.effront.anarcry.scanner.util.Http;
import gg.effront.anarcry.scanner.util.HttpClientFactory;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.function.Consumer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class IdorModule implements Scanner {

    private static final List<String> ID_PATHS = List.of("/api/user/1", "/api/users/1", "/api/user/2", "/api/users/2",
            "/api/account/1", "/api/accounts/1", "/api/profile/1", "/api/me", "/api/order/1", "/api/orders/1",
            "/api/document/1", "/api/invoice/1", "/api/admin/1", "/api/v1/user/1", "/api/v1/users/1", "/api/v2/user/1");

    private static final List<String> DELETE_PATHS = List.of("/api/user/2", "/api/users/2", "/api/account/2",
            "/api/order/2", "/api/document/2", "/api/invoice/2", "/api/v1/user/2", "/api/v1/users/2");

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

    private static final String CWE_BOLA_ID = "CWE-306";
    private static final String CWE_BOLA_TITLE = "Missing Authentication for Critical Function";
    private static final String VECTOR_BOLA = "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N";
    private static final double SCORE_BOLA = CvssCalculator.calculate(VECTOR_BOLA);

    private static final Pattern PII_EMAIL = Pattern.compile("[\\w.+-]+@[\\w.-]+\\.[a-zA-Z]{2,}");
    private static final Pattern PII_PHONE = Pattern.compile("\"(?:phone|telefone|cel)\"\\s*:\\s*\"\\+?\\d{10,15}\"");
    private static final Pattern PII_CPF = Pattern.compile("\\d{3}\\.?\\d{3}\\.?\\d{3}-?\\d{2}");
    private static final Pattern PII_COORDS = Pattern
            .compile("\"(?:lat|lng|latitude|longitude)\"\\s*:\\s*-?\\d+\\.\\d+");
    private static final Pattern PII_PASSWORD = Pattern
            .compile("\"(?:password|senha|wifiPW|keyCode|doorCode|wifi_password)\"\\s*:");
    private static final Pattern[] PII_PATTERNS = {PII_EMAIL, PII_PHONE, PII_CPF, PII_COORDS, PII_PASSWORD};

    private static final int MASS_DATA_SIZE_THRESHOLD = 100_000;
    private static final int MASS_DATA_OBJECT_THRESHOLD = 100;

    private static final Pattern VALIDATION_ERROR = Pattern
            .compile("\"code\"\\s*:\\s*\"invalid_type\"|\"expected\"\\s*:\\s*\"string\"|\"path\"\\s*:\\s*\\[");

    @Override
    public List<Finding> scan(ScanContext ctx, Consumer<String> log) throws Exception {
        List<Finding> findings = new ArrayList<>();
        HttpClient hc = HttpClientFactory.http2();

        String scheme = ctx.isHttps() ? "https" : "http";
        int defPort = ctx.isHttps() ? 443 : 80;
        String base = scheme + "://" + ctx.host() + (ctx.port() != defPort ? ":" + ctx.port() : "");

        log.accept("[~] IDOR: iniciando probes em " + base);

        findings.addAll(probeUnauthenticated(ctx, hc, base, log));
        findings.addAll(probeValidationErrors(ctx, hc, base, log));
        findings.addAll(probeTrpc(ctx, hc, base, log));

        String token1 = ctx.jwtToken();
        String token2 = ctx.jwtToken2();
        boolean hasBearerAuth = token1 != null && !token1.isBlank();
        boolean hasCookieAuth = !ctx.config().sessionCookie().isBlank();

        if (!hasBearerAuth && !hasCookieAuth) {
            log.accept("[~] IDOR: sem autenticacao -- apenas probes unauthenticated executados");
            if (findings.isEmpty()) {
                log.accept("[+] IDOR: nenhuma vulnerabilidade detectada");
            }
            return findings;
        }

        if (hasCookieAuth && !hasBearerAuth) {
            log.accept("[~] IDOR: usando autenticacao via Cookie");
        }

        boolean canCrossUser = (hasBearerAuth && token2 != null && !token2.isBlank())
                || (hasCookieAuth && !ctx.config().sessionCookie2().isBlank());
        if (!canCrossUser) {
            String reason = hasCookieAuth ? "sessionCookie2 nao informado" : "jwtToken2 nao informado";
            log.accept("[*] IDOR: " + reason + " -- apenas probes DELETE e GraphQL");
        }

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
                if (dp.matches(".*/(?:api|trpc|v[0-9])/.*") && !effectivePaths.contains(dp)) {
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
            int pathIdx = 0;
            int totalPaths = effectivePaths.size();
            for (String path : effectivePaths) {
                pathIdx++;
                log.accept("[~] IDOR: [" + pathIdx + "/" + totalPaths + "] " + path);
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
                            ? "# Com cookie do usuario 1:\ncurl -b '<SESSION_COOKIE_1>' '" + base + path + "'\n"
                                    + "# Com cookie do usuario 2 (nao deve ter acesso):\ncurl -b '<SESSION_COOKIE_2>' '"
                                    + base + path + "'"
                            : "# Com token do usuario 1:\ncurl -H 'Authorization: Bearer <TOKEN_1>' '" + base + path
                                    + "'\n"
                                    + "# Com token do usuario 2 (nao deve ter acesso):\ncurl -H 'Authorization: Bearer "
                                    + "<TOKEN_2>' '" + base + path + "'";
                    String evidence = (cookieCrossUser ? "Cookie1 e Cookie2" : "Token1 e Token2")
                            + " recebem a mesma resposta em " + base + path + " | Similaridade: "
                            + similarityPercent(r1, r2) + "%" + " | Body preview: "
                            + r1.substring(0, Math.min(150, r1.length()));
                    findings.add(Finding.of("IDOR", path, "IDOR -- acesso nao-autorizado ao recurso " + path,
                            Severity.MEDIUM, evidence,
                            "Insecure Direct Object Reference -- outro usuario pode acessar recursos "
                                    + "que nao lhe pertencem. Expoe dados pessoais, financeiros ou administrativos.",
                            repro,
                            "Verificar autorizacao no nivel de objeto (BOLA): validar que o usuario "
                                    + "autenticado e o dono do recurso. Use UUIDs aleatorios em vez de IDs sequenciais",
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
                    findings.add(Finding.of("IDOR", path, "IDOR DELETE -- delecao cross-user possivel em " + path,
                            Severity.MEDIUM,
                            "DELETE " + base + path + " -> HTTP " + status
                                    + " | Esperado: 403/404 | Recurso de outro usuario foi deletado",
                            "IDOR via DELETE -- usuario pode deletar recursos de outros usuarios sem autorizacao",
                            repro,
                            "Validar ownership do recurso antes de deletar; verificar que o ID no path "
                                    + "pertence ao usuario autenticado; retornar 403 para acesso nao autorizado",
                            CWE_ID, CWE_TITLE, VECTOR_DELETE, SCORE_DELETE));
                    break;
                }
            } catch (CircuitBreakerException cbe) {
                throw cbe;
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
                        findings.add(Finding.of("IDOR", gqlPath, "IDOR GraphQL -- acesso/modificacao de recurso alheio",
                                Severity.HIGH,
                                "POST " + base + gqlPath + " | Mutation: "
                                        + mutation.substring(0, Math.min(80, mutation.length()))
                                        + " | Response (200 chars): " + body.substring(0, Math.min(200, body.length())),
                                "GraphQL IDOR -- mutation ou query retorna dados de outro usuario sem "
                                        + "verificacao de autorizacao no nivel de objeto",
                                hasCookieAuth
                                        ? "curl -X POST -H 'Content-Type: application/json' -b '<SESSION_COOKIE>' '"
                                                + base + gqlPath + "' -d '" + mutation + "'"
                                        : "curl -X POST -H 'Content-Type: application/json' "
                                                + "-H 'Authorization: Bearer <TOKEN>' '" + base + gqlPath + "' -d '"
                                                + mutation + "'",
                                "Implementar autorizacao por campo e por resolver no GraphQL; "
                                        + "usar DataLoader com contexto do usuario; nunca confiar no ID enviado pelo"
                                        + " cliente",
                                CWE_ID, CWE_TITLE, VECTOR_GRAPHQL, SCORE_GRAPHQL));
                        gqlFound = true;
                        break;
                    }
                } catch (CircuitBreakerException cbe) {
                    throw cbe;
                } catch (Exception ignored) {
                }
            }
            if (gqlFound) {
                break;
            }
        }

        if (findings.isEmpty()) {
            log.accept("[+] IDOR: nenhuma vulnerabilidade detectada");
        }
        return findings;
    }

    // -- Phase 0: unauthenticated BOLA probing ------------------------------------

    private List<Finding> probeUnauthenticated(ScanContext ctx, HttpClient hc, String base, Consumer<String> log) {
        List<Finding> findings = new ArrayList<>();
        ScanContext noAuth = noAuthContext(ctx);
        List<String> candidatePaths = buildCandidatePaths(ctx);

        log.accept("[~] IDOR/BOLA: probing " + candidatePaths.size() + " endpoints sem autenticacao");
        Set<String> flaggedPaths = new HashSet<>();

        for (String path : candidatePaths) {
            try {
                HttpRequest getReq = HttpRequest.newBuilder().uri(URI.create(base + path))
                        .timeout(Duration.ofSeconds(6)).GET().build();
                HttpResponse<String> getResp = Http.send(noAuth, hc, getReq, HttpResponse.BodyHandlers.ofString(),
                        id());

                if (getResp.statusCode() == 200) {
                    String body = getResp.body() != null ? getResp.body() : "";
                    if (isJsonData(body)) {
                        int piiCount = countPiiMatches(body);
                        boolean massExposure = isMassDataExposure(body);
                        Severity sev = (piiCount >= 2 || massExposure) ? Severity.CRITICAL : Severity.HIGH;

                        String evidence = "GET " + base + path + " -> HTTP 200 (sem autenticacao)" + " | Body size: "
                                + body.length() + " bytes"
                                + (piiCount > 0 ? " | PII detectado: " + piiCount + " padroes" : "")
                                + (massExposure ? " | Exposicao em massa detectada" : "") + " | Preview: "
                                + body.substring(0, Math.min(200, body.length()));

                        log.accept("[!!] BOLA: endpoint acessivel sem autenticacao: " + path
                                + (sev == Severity.CRITICAL ? " (CRITICAL -- PII/mass data)" : ""));
                        findings.add(Finding.of("IDOR", path,
                                "BOLA -- endpoint retorna dados sem autenticacao: " + path, sev, evidence,
                                "Missing Authentication (CWE-306) -- endpoint retorna dados sensiveis "
                                        + "sem nenhuma autenticacao. Qualquer pessoa pode acessar recursos "
                                        + "de qualquer usuario.",
                                "curl '" + base + path + "'",
                                "Implementar autenticacao obrigatoria no endpoint; retornar 401 para "
                                        + "requisicoes sem credenciais; adicionar middleware de autenticacao "
                                        + "global na API",
                                CWE_BOLA_ID, CWE_BOLA_TITLE, VECTOR_BOLA, SCORE_BOLA));
                        flaggedPaths.add(path);
                    }
                }
            } catch (CircuitBreakerException cbe) {
                throw cbe;
            } catch (Exception ignored) {
            }

            if (flaggedPaths.contains(path)) {
                continue;
            }

            try {
                HttpRequest postReq = HttpRequest.newBuilder().uri(URI.create(base + path))
                        .timeout(Duration.ofSeconds(6)).header("Content-Type", "application/json")
                        .POST(HttpRequest.BodyPublishers.ofString("{}")).build();
                HttpResponse<String> postResp = Http.send(noAuth, hc, postReq, HttpResponse.BodyHandlers.ofString(),
                        id());

                if (postResp.statusCode() == 200) {
                    String body = postResp.body() != null ? postResp.body() : "";
                    if (isJsonData(body)) {
                        int piiCount = countPiiMatches(body);
                        boolean massExposure = isMassDataExposure(body);
                        Severity sev = (piiCount >= 2 || massExposure) ? Severity.CRITICAL : Severity.HIGH;

                        log.accept("[!!] BOLA: POST sem autenticacao retorna dados: " + path);
                        findings.add(Finding.of("IDOR", path, "BOLA -- POST sem autenticacao retorna dados: " + path,
                                sev,
                                "POST " + base + path + " {} -> HTTP 200 (sem autenticacao)" + " | Body size: "
                                        + body.length() + " bytes"
                                        + (piiCount > 0 ? " | PII: " + piiCount + " padroes" : "")
                                        + (massExposure ? " | Exposicao em massa" : "") + " | Preview: "
                                        + body.substring(0, Math.min(200, body.length())),
                                "Missing Authentication (CWE-306) -- endpoint aceita POST sem autenticacao "
                                        + "e retorna dados sensiveis",
                                "curl -X POST -H 'Content-Type: application/json' -d '{}' '" + base + path + "'",
                                "Implementar autenticacao obrigatoria; rejeitar requisicoes sem credenciais com 401",
                                CWE_BOLA_ID, CWE_BOLA_TITLE, VECTOR_BOLA, SCORE_BOLA));
                        flaggedPaths.add(path);
                    }
                }
            } catch (CircuitBreakerException cbe) {
                throw cbe;
            } catch (Exception ignored) {
            }
        }

        return findings;
    }

    // -- Validation error probe ---------------------------------------------------

    private List<Finding> probeValidationErrors(ScanContext ctx, HttpClient hc, String base, Consumer<String> log) {
        List<Finding> findings = new ArrayList<>();
        ScanContext noAuth = noAuthContext(ctx);
        List<String> candidatePaths = buildCandidatePaths(ctx);

        log.accept("[~] IDOR/BOLA: probing validation errors em " + candidatePaths.size() + " endpoints");

        for (String path : candidatePaths) {
            try {
                HttpRequest req = HttpRequest.newBuilder().uri(URI.create(base + path)).timeout(Duration.ofSeconds(6))
                        .header("Content-Type", "application/json").POST(HttpRequest.BodyPublishers.ofString(""))
                        .build();
                HttpResponse<String> resp = Http.send(noAuth, hc, req, HttpResponse.BodyHandlers.ofString(), id());

                int status = resp.statusCode();
                if (status == 401 || status == 403) {
                    continue;
                }

                if (status == 422 || status == 400) {
                    String body = resp.body() != null ? resp.body() : "";
                    if (VALIDATION_ERROR.matcher(body).find()) {
                        log.accept("[!!] BOLA: endpoint processa input sem autenticacao (validation error): " + path);
                        findings.add(Finding.of("IDOR", path,
                                "Authentication Bypass -- endpoint processa input sem autenticacao: " + path,
                                Severity.HIGH,
                                "POST " + base + path + " (empty body) -> HTTP " + status
                                        + " com validation error (sem 401/403)" + " | Body preview: "
                                        + body.substring(0, Math.min(300, body.length())),
                                "O endpoint processa e valida input antes de verificar autenticacao. "
                                        + "Isso indica ausencia de middleware de autenticacao, permitindo "
                                        + "que atacantes interajam com a logica do endpoint sem credenciais.",
                                "curl -X POST -H 'Content-Type: application/json' -d '' '" + base + path + "'",
                                "Mover verificacao de autenticacao para antes da validacao de input; "
                                        + "usar middleware global que rejeita requisicoes sem credenciais "
                                        + "com 401 antes de processar o body",
                                CWE_BOLA_ID, CWE_BOLA_TITLE, VECTOR_BOLA, SCORE_BOLA));
                        break;
                    }
                }
            } catch (CircuitBreakerException cbe) {
                throw cbe;
            } catch (Exception ignored) {
            }
        }

        return findings;
    }

    // -- Phase: tRPC BOLA probing
    // --------------------------------------------------

    private List<Finding> probeTrpc(ScanContext ctx, HttpClient hc, String base, Consumer<String> log) {
        List<Finding> findings = new ArrayList<>();
        ScanContext noAuth = noAuthContext(ctx);

        List<String> trpcProcedures = new ArrayList<>();
        for (String dp : ctx.discoveredPaths().paths()) {
            if (dp.startsWith("/trpc/") && dp.length() > 6) {
                trpcProcedures.add(dp.substring(6));
            }
        }
        if (trpcProcedures.isEmpty()) {
            return findings;
        }

        log.accept("[~] IDOR/tRPC: probing " + trpcProcedures.size() + " procedures sem autenticacao");
        Set<String> flaggedProcs = new HashSet<>();

        for (String proc : trpcProcedures) {
            String batchUrl = base + "/trpc/" + proc + "?batch=1&input="
                    + java.net.URLEncoder.encode("{\"0\":{\"json\":{}}}", java.nio.charset.StandardCharsets.UTF_8);
            try {
                HttpRequest getReq = HttpRequest.newBuilder().uri(URI.create(batchUrl)).timeout(Duration.ofSeconds(6))
                        .GET().build();
                HttpResponse<String> getResp = Http.send(noAuth, hc, getReq, HttpResponse.BodyHandlers.ofString(),
                        id());

                if (getResp.statusCode() == 200) {
                    String body = getResp.body() != null ? getResp.body() : "";
                    if (isJsonData(body) && !body.contains("\"error\"")) {
                        int piiCount = countPiiMatches(body);
                        boolean massExposure = isMassDataExposure(body);
                        Severity sev = (piiCount >= 2 || massExposure) ? Severity.CRITICAL : Severity.HIGH;

                        log.accept("[!!] BOLA/tRPC: " + proc + " acessivel sem auth"
                                + (sev == Severity.CRITICAL ? " (CRITICAL -- PII/mass)" : ""));
                        findings.add(Finding.of("IDOR", "/trpc/" + proc,
                                "BOLA -- tRPC procedure retorna dados sem autenticacao: " + proc, sev,
                                "GET " + batchUrl + " -> HTTP 200 (sem auth)" + " | Body size: " + body.length()
                                        + " bytes" + (piiCount > 0 ? " | PII: " + piiCount + " padroes" : "")
                                        + (massExposure ? " | Exposicao em massa" : "") + " | Preview: "
                                        + body.substring(0, Math.min(200, body.length())),
                                "Missing Authentication (CWE-306) -- tRPC procedure " + proc
                                        + " retorna dados sensiveis sem nenhuma autenticacao via batch query format",
                                "curl '" + batchUrl + "'",
                                "Implementar middleware de autenticacao no tRPC router; usar "
                                        + ".middleware(isAuthed) em procedures sensiveis; retornar UNAUTHORIZED "
                                        + "para requests sem credenciais",
                                CWE_BOLA_ID, CWE_BOLA_TITLE, VECTOR_BOLA, SCORE_BOLA));
                        flaggedProcs.add(proc);
                    }
                }
            } catch (CircuitBreakerException cbe) {
                throw cbe;
            } catch (Exception ignored) {
            }

            if (flaggedProcs.contains(proc)) {
                continue;
            }

            String postUrl = base + "/trpc/" + proc + "?batch=1";
            String trpcBody = "{\"0\":{\"json\":{}}}";
            try {
                HttpRequest postReq = HttpRequest.newBuilder().uri(URI.create(postUrl)).timeout(Duration.ofSeconds(6))
                        .header("Content-Type", "application/json").POST(HttpRequest.BodyPublishers.ofString(trpcBody))
                        .build();
                HttpResponse<String> postResp = Http.send(noAuth, hc, postReq, HttpResponse.BodyHandlers.ofString(),
                        id());

                if (postResp.statusCode() == 200) {
                    String body = postResp.body() != null ? postResp.body() : "";
                    if (isJsonData(body) && !body.contains("\"error\"")) {
                        int piiCount = countPiiMatches(body);
                        boolean massExposure = isMassDataExposure(body);
                        Severity sev = (piiCount >= 2 || massExposure) ? Severity.CRITICAL : Severity.HIGH;

                        log.accept("[!!] BOLA/tRPC: POST " + proc + " sem auth retorna dados");
                        findings.add(Finding.of("IDOR", "/trpc/" + proc,
                                "BOLA -- tRPC mutation sem autenticacao: " + proc, sev,
                                "POST " + postUrl + " " + trpcBody + " -> HTTP 200 (sem auth)" + " | Body size: "
                                        + body.length() + " bytes"
                                        + (piiCount > 0 ? " | PII: " + piiCount + " padroes" : "")
                                        + (massExposure ? " | Exposicao em massa" : "") + " | Preview: "
                                        + body.substring(0, Math.min(200, body.length())),
                                "Missing Authentication (CWE-306) -- tRPC mutation " + proc
                                        + " aceita requests sem autenticacao e retorna dados sensiveis",
                                "curl -X POST -H 'Content-Type: application/json' -d '" + trpcBody + "' '" + postUrl
                                        + "'",
                                "Implementar middleware de autenticacao no tRPC router; usar "
                                        + ".middleware(isAuthed) em mutations sensiveis",
                                CWE_BOLA_ID, CWE_BOLA_TITLE, VECTOR_BOLA, SCORE_BOLA));
                    }
                }
            } catch (CircuitBreakerException cbe) {
                throw cbe;
            } catch (Exception ignored) {
            }
        }

        if (!findings.isEmpty()) {
            log.accept("[~] IDOR/tRPC: " + findings.size() + " procedures vulneraveis");
        }
        return findings;
    }

    // -- Helper methods -----------------------------------------------------------

    private List<String> buildCandidatePaths(ScanContext ctx) {
        List<String> paths = new ArrayList<>(ID_PATHS);
        if (!ctx.discoveredPaths().isEmpty()) {
            for (String dp : ctx.discoveredPaths().paths()) {
                if (dp.matches(".*/(?:api|trpc|v[0-9])/.*") && !paths.contains(dp)) {
                    paths.add(dp);
                    paths.add(dp + "/1");
                    paths.add(dp + "/2");
                }
            }
        }
        return paths;
    }

    private static ScanContext noAuthContext(ScanContext ctx) {
        ScanConfig noAuthCfg = new ScanConfig(ctx.config().delayMs(), "", "", ctx.config().inScopeHosts(),
                ctx.config().suppressions(), ctx.config().redirectRelayUrl(), ctx.config().probeConcurrency());
        return new ScanContext(ctx.targetUrl(), "", "", ctx.enabledModules(), noAuthCfg, ctx.requestLog(),
                ctx.discoveredPaths(), ctx.wafState());
    }

    private static boolean isJsonData(String body) {
        if (body == null || body.length() < 50) {
            return false;
        }
        String t = body.stripLeading();
        if (!t.startsWith("{") && !t.startsWith("[")) {
            return false;
        }
        if (isHtml(body)) {
            return false;
        }
        return true;
    }

    static int countPiiMatches(String body) {
        int count = 0;
        for (Pattern p : PII_PATTERNS) {
            if (p.matcher(body).find()) {
                count++;
            }
        }
        return count;
    }

    static boolean isMassDataExposure(String body) {
        if (body == null) {
            return false;
        }
        if (body.length() > MASS_DATA_SIZE_THRESHOLD) {
            return true;
        }
        int braceCount = 0;
        for (int i = 0; i < body.length(); i++) {
            if (body.charAt(i) == '{') {
                braceCount++;
            }
        }
        return braceCount >= MASS_DATA_OBJECT_THRESHOLD;
    }

    // -- Existing helpers ---------------------------------------------------------

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
            } catch (CircuitBreakerException cbe) {
                throw cbe;
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
        } catch (CircuitBreakerException cbe) {
            throw cbe;
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
