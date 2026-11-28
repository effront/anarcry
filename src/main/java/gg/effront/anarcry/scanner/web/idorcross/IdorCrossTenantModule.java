package gg.effront.anarcry.scanner.web.idorcross;

import gg.effront.anarcry.model.CvssCalculator;
import gg.effront.anarcry.model.Finding;
import gg.effront.anarcry.model.Severity;
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
import java.util.List;
import java.util.function.Consumer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class IdorCrossTenantModule implements Scanner {

    private static final String CWE_ID = "CWE-639";
    private static final String CWE_TITLE = "Authorization Bypass Through User-Controlled Key";

    private static final String VECTOR_WRITE = "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N";
    private static final double SCORE_WRITE = CvssCalculator.calculate(VECTOR_WRITE);

    private static final String VECTOR_DELETE = "AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H";
    private static final double SCORE_DELETE = CvssCalculator.calculate(VECTOR_DELETE);

    private static final String VECTOR_SEQ = "AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:H/A:N";
    private static final double SCORE_SEQ = CvssCalculator.calculate(VECTOR_SEQ);

    private static final List<String> WRITE_PATHS = List.of("/api/user/1", "/api/users/1", "/api/account/1",
            "/api/profile/1", "/api/order/1", "/api/document/1", "/api/v1/user/1", "/api/v1/users/1", "/api/v2/user/1");

    private static final List<String> DELETE_PATHS = List.of("/api/user/2", "/api/users/2", "/api/account/2",
            "/api/order/2", "/api/document/2", "/api/v1/user/2", "/api/v1/users/2");

    private static final String PATCH_BODY = "{\"email\":\"xsstenant@evil.com\",\"role\":\"admin\"}";
    private static final String PUT_BODY = "{\"name\":\"CrossTenantTest\",\"email\":\"xsstenant@evil.com\"}";

    private static final Pattern ID_PATTERN = Pattern
            .compile("\"(?:id|userId|_id|uuid|user_id)\"\\s*:\\s*\"?([A-Za-z0-9\\-_]{1,200})\"?");

    private record EffectivePaths(List<String> writePaths, List<String> deletePaths) {
    }

    @Override
    public String id() {
        return "IdorCrossTenant";
    }

    @Override
    public List<Finding> scan(ScanContext ctx, Consumer<String> log) throws Exception {
        List<Finding> findings = new ArrayList<>();
        HttpClient hc = HttpClientFactory.http2();

        String base = ctx.baseUrl();

        String token1 = ctx.activeToken();
        String token2 = ctx.jwtToken2();
        boolean hasBearerAuth = token1 != null && !token1.isBlank();
        boolean hasCookieAuth = !ctx.config().sessionCookie().isBlank();

        if (!hasBearerAuth && !hasCookieAuth) {
            log.accept("[~] IdorCrossTenant: sem autenticacao -- modulo requer ao menos um token");
            return findings;
        }

        boolean hasTwoTokens = hasBearerAuth && token2 != null && !token2.isBlank();
        log.accept("[~] IdorCrossTenant: iniciando probes de write cross-tenant em " + base
                + (hasTwoTokens ? " (2 tokens)" : " (sequential ID)"));

        EffectivePaths paths = buildEffectivePaths(ctx);

        // Phase 1: Cross-tenant PUT/PATCH with two tokens
        if (hasTwoTokens) {
            findings.addAll(probeCrossTenantWrite(ctx, hc, base, token1, token2, paths.writePaths(), log));
        }

        // Phase 2: Sequential ID manipulation on write endpoints (single token)
        if (findings.isEmpty()) {
            findings.addAll(probeSequentialIdWrite(ctx, hc, base, token1, hasBearerAuth, paths.writePaths(), log));
        }

        // Phase 3: Cross-tenant DELETE
        findings.addAll(probeCrossTenantDelete(ctx, hc, base, token1, hasBearerAuth, paths.deletePaths(), log));

        if (findings.isEmpty()) {
            log.accept("[+] IdorCrossTenant: nenhuma vulnerabilidade de write cross-tenant detectada");
        }
        return findings;
    }

    private static EffectivePaths buildEffectivePaths(ScanContext ctx) {
        List<String> writePaths = new ArrayList<>(WRITE_PATHS);
        List<String> deletePaths = new ArrayList<>(DELETE_PATHS);
        if (!ctx.discoveredPaths().isEmpty()) {
            for (String dp : ctx.discoveredPaths().paths()) {
                if (dp.matches(".*/(?:api|v[0-9])/.*")) {
                    if (!writePaths.contains(dp)) {
                        writePaths.add(dp);
                    }
                    if (!deletePaths.contains(dp + "/2")) {
                        deletePaths.add(dp + "/2");
                    }
                }
            }
        }
        return new EffectivePaths(writePaths, deletePaths);
    }

    private List<Finding> probeCrossTenantWrite(ScanContext ctx, HttpClient hc, String base, String token1,
            String token2, List<String> paths, Consumer<String> log) {
        List<Finding> findings = new ArrayList<>();
        log.accept("[~] IdorCrossTenant: testando PUT/PATCH cross-tenant com 2 tokens");

        for (String path : paths) {
            Finding putFinding = attemptCrossTenantPut(ctx, hc, base, path, token2, log);
            if (putFinding != null) {
                findings.add(putFinding);
                return findings;
            }

            Finding patchFinding = attemptCrossTenantPatch(ctx, hc, base, path, token2, log);
            if (patchFinding != null) {
                findings.add(patchFinding);
                return findings;
            }
        }

        return findings;
    }

    private Finding attemptCrossTenantPut(ScanContext ctx, HttpClient hc, String base, String path, String token2,
            Consumer<String> log) {
        try {
            HttpRequest putReq = HttpRequest.newBuilder().uri(URI.create(base + path)).timeout(Duration.ofSeconds(6))
                    .header("Content-Type", "application/json").header("Authorization", "Bearer " + token2)
                    .PUT(HttpRequest.BodyPublishers.ofString(PUT_BODY)).build();
            HttpResponse<String> putResp = Http.send(ctx, hc, putReq, HttpResponse.BodyHandlers.ofString(), id());

            if (isWriteSuccess(putResp)) {
                String body = putResp.body() != null ? putResp.body() : "";
                log.accept("[!!] IdorCrossTenant: CRITICAL -- PUT cross-tenant aceito em " + path);
                return Finding.of(id(), path, "IDOR Cross-Tenant -- PUT modificou recurso alheio em " + path,
                        Severity.CRITICAL,
                        "PUT " + base + path + " com Token2 -> HTTP " + putResp.statusCode() + " | Body: " + PUT_BODY
                                + " | Response preview: " + body.substring(0, Math.min(200, body.length())),
                        "Cross-tenant IDOR via PUT -- usuario pode modificar recursos de outro "
                                + "tenant/usuario sem autorizacao. Permite alteracao de dados, "
                                + "escalacao de privilegios e comprometimento de contas",
                        "curl -X PUT -H 'Content-Type: application/json' "
                                + "-H 'Authorization: Bearer <TOKEN_USER_B>' '" + base + path + "' " + "-d '" + PUT_BODY
                                + "'",
                        "Implementar verificacao de ownership no nivel de objeto -- validar que o "
                                + "usuario autenticado e o dono do recurso antes de permitir escrita. "
                                + "Usar UUIDs em vez de IDs sequenciais. Implementar tenant isolation",
                        CWE_ID, CWE_TITLE, VECTOR_WRITE, SCORE_WRITE);
            }
        } catch (CircuitBreakerException cbe) {
            throw cbe;
        } catch (Exception ignored) {
        }
        return null;
    }

    private Finding attemptCrossTenantPatch(ScanContext ctx, HttpClient hc, String base, String path, String token2,
            Consumer<String> log) {
        try {
            HttpRequest patchReq = HttpRequest.newBuilder().uri(URI.create(base + path)).timeout(Duration.ofSeconds(6))
                    .header("Content-Type", "application/json").header("Authorization", "Bearer " + token2)
                    .method("PATCH", HttpRequest.BodyPublishers.ofString(PATCH_BODY)).build();
            HttpResponse<String> patchResp = Http.send(ctx, hc, patchReq, HttpResponse.BodyHandlers.ofString(), id());

            if (isWriteSuccess(patchResp)) {
                String body = patchResp.body() != null ? patchResp.body() : "";
                log.accept("[!!] IdorCrossTenant: CRITICAL -- PATCH cross-tenant aceito em " + path);
                return Finding.of(id(), path, "IDOR Cross-Tenant -- PATCH modificou recurso alheio em " + path,
                        Severity.CRITICAL,
                        "PATCH " + base + path + " com Token2 -> HTTP " + patchResp.statusCode() + " | Body: "
                                + PATCH_BODY + " | Response preview: "
                                + body.substring(0, Math.min(200, body.length())),
                        "Cross-tenant IDOR via PATCH -- usuario pode modificar campos de recursos "
                                + "de outro tenant/usuario. Permite account takeover via alteracao de email/role",
                        "curl -X PATCH -H 'Content-Type: application/json' "
                                + "-H 'Authorization: Bearer <TOKEN_USER_B>' '" + base + path + "' " + "-d '"
                                + PATCH_BODY + "'",
                        "Implementar verificacao de ownership no nivel de objeto antes de permitir "
                                + "PATCH. Validar que campos sensiveis (email, role) so podem ser "
                                + "alterados pelo proprio usuario ou admin",
                        CWE_ID, CWE_TITLE, VECTOR_WRITE, SCORE_WRITE);
            }
        } catch (CircuitBreakerException cbe) {
            throw cbe;
        } catch (Exception ignored) {
        }
        return null;
    }

    private List<Finding> probeSequentialIdWrite(ScanContext ctx, HttpClient hc, String base, String token1,
            boolean hasBearerAuth, List<String> paths, Consumer<String> log) {
        List<Finding> findings = new ArrayList<>();
        log.accept("[~] IdorCrossTenant: testando PUT/PATCH com IDs sequenciais manipulados");

        // Try to discover the authenticated user's ID first
        String myId = extractUserId(ctx, hc, base, token1, hasBearerAuth);
        if (myId != null) {
            log.accept("[~] IdorCrossTenant: ID do usuario: " + myId);
        }
        String targetId = resolveTargetId(myId);

        for (String path : paths) {
            String manipulatedPath = path.replaceFirst("/\\d+$", "/" + targetId);
            if (manipulatedPath.equals(path) && !path.endsWith("/" + targetId)) {
                manipulatedPath = path + "/" + targetId;
            }

            try {
                // Baseline: GET the original resource
                HttpRequest.Builder baseBuilder = HttpRequest.newBuilder().uri(URI.create(base + path))
                        .timeout(Duration.ofSeconds(6)).GET();
                addAuth(baseBuilder, token1, hasBearerAuth);
                HttpResponse<String> baseResp = Http.send(ctx, hc, baseBuilder.build(),
                        HttpResponse.BodyHandlers.ofString(), id());
                if (baseResp.statusCode() != 200) {
                    continue;
                }

                // PUT on the manipulated ID
                HttpRequest.Builder putBuilder = HttpRequest.newBuilder().uri(URI.create(base + manipulatedPath))
                        .timeout(Duration.ofSeconds(6)).header("Content-Type", "application/json")
                        .PUT(HttpRequest.BodyPublishers.ofString(PUT_BODY));
                addAuth(putBuilder, token1, hasBearerAuth);
                HttpResponse<String> putResp = Http.send(ctx, hc, putBuilder.build(),
                        HttpResponse.BodyHandlers.ofString(), id());

                if (isWriteSuccess(putResp)) {
                    String body = putResp.body() != null ? putResp.body() : "";
                    log.accept("[!!] IdorCrossTenant: CRITICAL -- PUT com ID manipulado aceito em " + manipulatedPath);
                    String repro = buildWriteRepro(base, manipulatedPath, hasBearerAuth);
                    findings.add(Finding.of(id(), manipulatedPath,
                            "IDOR Sequential ID -- PUT aceito em recurso alheio " + manipulatedPath, Severity.CRITICAL,
                            "PUT " + base + manipulatedPath + " -> HTTP " + putResp.statusCode() + " | Baseline GET "
                                    + path + " -> HTTP " + baseResp.statusCode() + " | Manipulated ID: " + targetId
                                    + " | Response preview: " + body.substring(0, Math.min(200, body.length())),
                            "IDOR via ID sequencial -- usuario autenticado pode escrever em recursos "
                                    + "de outro usuario manipulando o ID no path. IDs previsiveis facilitam "
                                    + "enumeracao e comprometimento em massa",
                            repro,
                            "Implementar verificacao de ownership antes de write operations. "
                                    + "Usar UUIDs aleatorios em vez de IDs sequenciais. "
                                    + "Adicionar tenant-id validation no middleware de autorizacao",
                            CWE_ID, CWE_TITLE, VECTOR_SEQ, SCORE_SEQ));
                    return findings;
                }
            } catch (CircuitBreakerException cbe) {
                throw cbe;
            } catch (Exception ignored) {
            }
        }

        return findings;
    }

    private static String resolveTargetId(String myId) {
        if (myId == null) {
            return "2";
        }
        try {
            return String.valueOf(Long.parseLong(myId) + 1);
        } catch (NumberFormatException nfe) {
            // UUID -- use a known different ID
            return "00000000-0000-0000-0000-000000000001";
        }
    }

    private static String buildWriteRepro(String base, String manipulatedPath, boolean hasBearerAuth) {
        if (hasBearerAuth) {
            return "curl -X PUT -H 'Content-Type: application/json' " + "-H 'Authorization: Bearer <TOKEN>' '" + base
                    + manipulatedPath + "' " + "-d '" + PUT_BODY + "'";
        }
        return "curl -X PUT -H 'Content-Type: application/json' " + "-b '<SESSION_COOKIE>' '" + base + manipulatedPath
                + "' " + "-d '" + PUT_BODY + "'";
    }

    private List<Finding> probeCrossTenantDelete(ScanContext ctx, HttpClient hc, String base, String token1,
            boolean hasBearerAuth, List<String> paths, Consumer<String> log) {
        List<Finding> findings = new ArrayList<>();
        log.accept("[~] IdorCrossTenant: testando DELETE cross-tenant");

        for (String path : paths) {
            try {
                HttpRequest.Builder rb = HttpRequest.newBuilder().uri(URI.create(base + path))
                        .timeout(Duration.ofSeconds(6));
                addAuth(rb, token1, hasBearerAuth);
                HttpRequest req = rb.DELETE().build();
                HttpResponse<String> resp = Http.send(ctx, hc, req, HttpResponse.BodyHandlers.ofString(), id());

                int status = resp.statusCode();
                String body = resp.body() != null ? resp.body() : "";
                if ((status == 200 || status == 204) && !Http.isHtmlResponse(body)) {
                    log.accept("[!!] IdorCrossTenant: CRITICAL -- DELETE cross-tenant aceito em " + path);
                    String repro = hasBearerAuth
                            ? "curl -X DELETE -H 'Authorization: Bearer <TOKEN>' '" + base + path + "'"
                            : "curl -X DELETE -b '<SESSION_COOKIE>' '" + base + path + "'";
                    findings.add(Finding.of(id(), path,
                            "IDOR Cross-Tenant DELETE -- delecao de recurso alheio em " + path, Severity.CRITICAL,
                            "DELETE " + base + path + " -> HTTP " + status
                                    + " | Esperado: 403/404 | Recurso de outro tenant/usuario foi deletado",
                            "Cross-tenant IDOR via DELETE -- usuario pode destruir recursos de outros "
                                    + "tenants/usuarios. Impacto: perda de dados, disrupcao de servico, "
                                    + "negacao de servico direcionada",
                            repro,
                            "Validar ownership do recurso antes de deletar. Implementar soft-delete "
                                    + "para permitir recuperacao. Adicionar confirmacao em operacoes destrutivas",
                            CWE_ID, CWE_TITLE, VECTOR_DELETE, SCORE_DELETE));
                    return findings;
                }
            } catch (CircuitBreakerException cbe) {
                throw cbe;
            } catch (Exception ignored) {
            }
        }

        return findings;
    }

    private String extractUserId(ScanContext ctx, HttpClient hc, String base, String token, boolean hasBearerAuth) {
        String[] mePaths = {"/api/me", "/api/profile", "/api/user/me", "/api/account"};
        for (String p : mePaths) {
            try {
                HttpRequest.Builder rb = HttpRequest.newBuilder().uri(URI.create(base + p))
                        .timeout(Duration.ofSeconds(5));
                addAuth(rb, token, hasBearerAuth);
                HttpResponse<String> resp = Http.send(ctx, hc, rb.GET().build(), HttpResponse.BodyHandlers.ofString(),
                        id());
                if (resp.statusCode() == 200 && resp.body() != null) {
                    Matcher m = ID_PATTERN.matcher(resp.body());
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

    private static void addAuth(HttpRequest.Builder builder, String token, boolean hasBearerAuth) {
        if (hasBearerAuth) {
            builder.header("Authorization", "Bearer " + token);
        }
    }

    private static boolean isWriteSuccess(HttpResponse<String> resp) {
        int status = resp.statusCode();
        if (status != 200 && status != 201 && status != 204) {
            return false;
        }
        String body = resp.body() != null ? resp.body() : "";
        return !Http.isHtmlResponse(body);
    }
}
