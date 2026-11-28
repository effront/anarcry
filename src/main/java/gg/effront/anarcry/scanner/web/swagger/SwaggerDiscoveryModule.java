package gg.effront.anarcry.scanner.web.swagger;

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

public class SwaggerDiscoveryModule implements Scanner {

    private static final String CWE_ID = "CWE-200";
    private static final String CWE_TITLE = "Exposure of Sensitive Information";
    private static final String CVSS_VECTOR = "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N";
    private static final double CVSS_SCORE = CvssCalculator.calculate(CVSS_VECTOR);

    private static final String CVSS_VECTOR_HIGH = "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N";
    private static final double CVSS_SCORE_HIGH = CvssCalculator.calculate(CVSS_VECTOR_HIGH);

    private static final List<String> PROBE_PATHS = List.of("/swagger.json", "/swagger-ui.html", "/v2/api-docs",
            "/v3/api-docs", "/openapi.json", "/api-docs", "/swagger/v1/swagger.json", "/swagger-resources",
            "/swagger-ui/index.html", "/api/swagger.json", "/api/v1/swagger.json", "/api/openapi.json",
            "/docs/api-docs", "/api/api-docs", "/swagger.yaml", "/openapi.yaml", "/v3/api-docs.yaml");

    private static final Pattern PATHS_KEY = Pattern.compile("\"paths\"\\s*:\\s*\\{");
    private static final Pattern OPENAPI_KEY = Pattern.compile("\"openapi\"\\s*:\\s*\"([^\"]+)\"");
    private static final Pattern SWAGGER_KEY = Pattern.compile("\"swagger\"\\s*:\\s*\"([^\"]+)\"");
    private static final Pattern PATH_ENTRY = Pattern.compile("\"(/[^\"]+)\"\\s*:\\s*\\{");
    private static final Pattern INFO_TITLE = Pattern
            .compile("\"info\"\\s*:\\s*\\{[^}]*\"title\"\\s*:\\s*\"([^\"]+)\"");

    @Override
    public String id() {
        return "SwaggerDiscovery";
    }

    @Override
    public List<Finding> scan(ScanContext ctx, Consumer<String> log) throws Exception {
        List<Finding> findings = new ArrayList<>();
        HttpClient hc = HttpClientFactory.http2();

        String scheme = ctx.isHttps() ? "https" : "http";
        int defPort = ctx.isHttps() ? 443 : 80;
        String base = scheme + "://" + ctx.host() + (ctx.port() != defPort ? ":" + ctx.port() : "");

        log.accept("[~] SwaggerDiscovery: probing " + PROBE_PATHS.size() + " paths em " + base);

        for (String path : PROBE_PATHS) {
            String url = base + path;
            try {
                HttpRequest.Builder builder = HttpRequest.newBuilder().uri(URI.create(url))
                        .timeout(Duration.ofSeconds(6)).GET();
                if (!ctx.jwtToken().isBlank()) {
                    builder.header("Authorization", "Bearer " + ctx.jwtToken());
                }
                HttpRequest req = builder.build();
                HttpResponse<String> resp = Http.send(ctx, hc, req, HttpResponse.BodyHandlers.ofString(), id());

                if (resp.statusCode() != 200) {
                    continue;
                }

                String body = resp.body() != null ? resp.body() : "";
                if (body.isBlank() || isHtml(body)) {
                    continue;
                }

                // Swagger UI HTML page detection
                if (path.contains("swagger-ui")) {
                    if (body.contains("swagger-ui") || body.contains("SwaggerUIBundle")) {
                        log.accept("[!] SwaggerDiscovery: Swagger UI acessivel em " + url);
                        findings.add(Finding.of(id(), path, "Swagger UI exposto publicamente", Severity.MEDIUM,
                                "URL: " + url + " | Status: 200 | Swagger UI detectado via HTML content",
                                "Swagger UI expoe a documentacao completa da API, permitindo que atacantes "
                                        + "mapeiem todos os endpoints, parametros e modelos de dados",
                                "curl '" + url + "'",
                                "Remover ou proteger Swagger UI em producao; restringir acesso por IP "
                                        + "ou autenticacao; usar springdoc.swagger-ui.enabled=false em producao",
                                CWE_ID, CWE_TITLE, CVSS_VECTOR, CVSS_SCORE));
                        continue;
                    }
                    continue;
                }

                // JSON spec detection
                boolean hasPaths = PATHS_KEY.matcher(body).find();
                Matcher openapiMatcher = OPENAPI_KEY.matcher(body);
                Matcher swaggerMatcher = SWAGGER_KEY.matcher(body);
                boolean hasOpenapi = openapiMatcher.find();
                boolean hasSwagger = swaggerMatcher.find();

                if (!hasPaths && !hasOpenapi && !hasSwagger) {
                    // swagger-resources returns a JSON array with API listing
                    if (path.contains("swagger-resources") && body.stripLeading().startsWith("[")) {
                        log.accept("[!] SwaggerDiscovery: swagger-resources acessivel em " + url);
                        findings.add(Finding.of(id(), path, "Swagger Resources endpoint exposto", Severity.LOW,
                                "URL: " + url + " | Status: 200 | Body preview: "
                                        + body.substring(0, Math.min(200, body.length())),
                                "Swagger Resources endpoint expoe metadados sobre a API, "
                                        + "incluindo localizacoes de specs OpenAPI",
                                "curl '" + url + "'",
                                "Desabilitar swagger-resources em producao; restringir acesso a endpoints "
                                        + "de documentacao",
                                CWE_ID, CWE_TITLE, CVSS_VECTOR, CVSS_SCORE));
                        continue;
                    }
                    continue;
                }

                String apiVersion = "";
                if (hasOpenapi) {
                    apiVersion = "OpenAPI " + openapiMatcher.group(1);
                } else if (hasSwagger) {
                    apiVersion = "Swagger " + swaggerMatcher.group(1);
                }

                int endpointCount = 0;
                if (hasPaths) {
                    Matcher pathMatcher = PATH_ENTRY.matcher(body);
                    while (pathMatcher.find()) {
                        endpointCount++;
                    }
                }

                String apiTitle = "";
                Matcher titleMatcher = INFO_TITLE.matcher(body);
                if (titleMatcher.find()) {
                    apiTitle = titleMatcher.group(1);
                }

                // Determine severity based on exposure level
                boolean hasInternalEndpoints = body.contains("/admin") || body.contains("/internal")
                        || body.contains("/debug") || body.contains("/management");
                boolean hasAuthInfo = body.contains("securityDefinitions") || body.contains("securitySchemes")
                        || body.contains("\"bearerAuth\"") || body.contains("\"apiKey\"");
                Severity sev = hasInternalEndpoints ? Severity.HIGH : Severity.MEDIUM;
                String vec = hasInternalEndpoints ? CVSS_VECTOR_HIGH : CVSS_VECTOR;
                double score = hasInternalEndpoints ? CVSS_SCORE_HIGH : CVSS_SCORE;

                String evidence = "URL: " + url + " | Status: 200"
                        + (!apiVersion.isEmpty() ? " | Version: " + apiVersion : "")
                        + (!apiTitle.isEmpty() ? " | Title: " + apiTitle : "")
                        + (endpointCount > 0 ? " | Endpoints: " + endpointCount : "")
                        + (hasAuthInfo ? " | Auth schemes expostos" : "")
                        + (hasInternalEndpoints ? " | Endpoints internos/admin detectados" : "");

                log.accept("[!!] SwaggerDiscovery: " + sev + " -- spec exposta em " + url + " ("
                        + (endpointCount > 0 ? endpointCount + " endpoints" : "spec") + ")");

                findings.add(Finding.of(id(), path,
                        "API spec exposta" + (!apiVersion.isEmpty() ? " (" + apiVersion + ")" : "") + " -- "
                                + (endpointCount > 0 ? endpointCount + " endpoints" : "documentacao completa"),
                        sev, evidence,
                        "Especificacao OpenAPI/Swagger exposta publicamente permite que atacantes "
                                + "mapeiem toda a superficie de ataque da API, incluindo endpoints, "
                                + "parametros, modelos de dados e esquemas de autenticacao"
                                + (hasInternalEndpoints
                                        ? ". Endpoints internos/admin detectados aumentam o risco de exploracao"
                                        : ""),
                        "curl '" + url + "' | python3 -m json.tool",
                        "Desabilitar endpoints de documentacao em producao; restringir acesso por IP "
                                + "ou autenticacao; configurar springdoc.api-docs.enabled=false ou "
                                + "swagger.production=false conforme o framework",
                        CWE_ID, CWE_TITLE, vec, score));

                // One confirmed spec is enough -- stop probing
                break;

            } catch (CircuitBreakerException cbe) {
                throw cbe;
            } catch (Exception ignored) {
                // Connection errors expected for unreachable paths
            }
        }

        if (findings.isEmpty()) {
            log.accept("[+] SwaggerDiscovery: nenhuma spec exposta detectada");
        }
        return findings;
    }

    private static boolean isHtml(String body) {
        String t = body.stripLeading();
        return t.startsWith("<!DOCTYPE") || t.startsWith("<html") || t.startsWith("<!doctype");
    }
}
