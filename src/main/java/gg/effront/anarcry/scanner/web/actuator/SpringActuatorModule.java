package gg.effront.anarcry.scanner.web.actuator;

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
import java.util.Optional;
import java.util.function.Consumer;
import gg.effront.anarcry.model.CweRegistry;
import gg.effront.anarcry.model.CvssCalculator;

public class SpringActuatorModule implements Scanner {

    private record ActuatorEndpoint(String path, String bodyPattern, Severity severity, String description) {}

    private static final List<ActuatorEndpoint> ENDPOINTS = List.of(
            // CRITICAL
            new ActuatorEndpoint("/actuator/env",        "propertySources|activeProfiles",    Severity.CRITICAL, "env — credenciais e propriedades expostas"),
            new ActuatorEndpoint("/actuator/heapdump",   null,                                Severity.CRITICAL, "heapdump — heap dump disponível"),
            // HIGH
            new ActuatorEndpoint("/actuator/mappings",   "requestMappings|dispatcherServlets", Severity.HIGH,    "mappings — mapa de endpoints exposto"),
            new ActuatorEndpoint("/actuator/beans",      "beanDefinitionNames|\"beans\":",    Severity.HIGH,     "beans — beans Spring expostos"),
            new ActuatorEndpoint("/actuator/configprops","contexts",                           Severity.HIGH,     "configprops — config properties expostas"),
            // MEDIUM
            new ActuatorEndpoint("/actuator",            "\"_links\":",                        Severity.MEDIUM,   "actuator — gateway habilitado"),
            new ActuatorEndpoint("/actuator/health",     "\"status\":",                        Severity.MEDIUM,   "health — detalhes de saúde expostos"),
            new ActuatorEndpoint("/actuator/info",       null,                                 Severity.MEDIUM,   "info — informações da aplicação"),
            new ActuatorEndpoint("/actuator/loggers",    "levels",                             Severity.MEDIUM,   "loggers — log levels modificáveis"),
            new ActuatorEndpoint("/actuator/threaddump", "threads",                            Severity.MEDIUM,   "threaddump — thread dump disponível"),
            new ActuatorEndpoint("/actuator/metrics",    "names",                              Severity.MEDIUM,   "metrics — métricas expostas"),
            // Spring Boot 1.x (no prefix)
            new ActuatorEndpoint("/env",                 "propertySources|activeProfiles",     Severity.CRITICAL, "env (Boot 1.x) — credenciais expostas"),
            new ActuatorEndpoint("/dump",                "threads",                             Severity.MEDIUM,   "dump (Boot 1.x) — thread dump"),
            new ActuatorEndpoint("/trace",               "method|headers",                     Severity.MEDIUM,   "trace (Boot 1.x) — request trace"),
            new ActuatorEndpoint("/mappings",            "bean|method",                        Severity.HIGH,     "mappings (Boot 1.x) — mapa de endpoints"),
            new ActuatorEndpoint("/beans",               "bean|scope",                         Severity.HIGH,     "beans (Boot 1.x) — beans expostos")
    );

    @Override
    public String id() { return "Actuator"; }

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
        log.accept("[~] Actuator: verificando " + ENDPOINTS.size() + " endpoints em " + baseUrl);

        for (ActuatorEndpoint ep : ENDPOINTS) {
            String url = baseUrl + ep.path();
            try {
                HttpRequest.Builder builder = HttpRequest.newBuilder()
                        .uri(URI.create(url))
                        .timeout(Duration.ofSeconds(5))
                        .GET();

                if (!ctx.jwtToken().isBlank()) {
                    builder.header("Authorization", "Bearer " + ctx.jwtToken());
                }

                HttpRequest req = builder.build();
                HttpResponse<String> resp = Http.send(ctx, hc, req, HttpResponse.BodyHandlers.ofString(), id());

                if (resp.statusCode() != 200) continue;

                String body = resp.body() != null ? resp.body() : "";

                // heapdump: require binary content-type or large body — 200+HTML is a SPA catch-all FP
                if (ep.path().contains("heapdump")) {
                    Optional<String> ct = resp.headers().firstValue("content-type");
                    boolean isBinary = ct.map(s -> s.contains("octet-stream")).orElse(false)
                            || (!isHtml(body) && body.length() > 100_000);
                    if (isBinary) {
                        log.accept("[!!] Actuator: CRITICAL — heapdump acessível em " + url);
                        findings.add(Finding.of("Actuator", ep.path(),
                                "Spring Actuator — " + ep.description(),
                                ep.severity(),
                                "URL: " + url + " | Status: 200 | Size: " + body.length() + " bytes",
                                "Heap dump disponível — pode conter senhas, tokens e dados sensíveis em memória",
                                "curl -o heap.hprof '" + url + "' && jhat heap.hprof",
                                "Desabilitar /actuator/heapdump em produção; restringir acesso ao actuator por IP ou autenticação",
                                _cweId, _cweTitle, _cveVector, _score));
                    }
                    continue;
                }

                // /actuator/info — only real JSON responses (skip HTML SPA catch-all)
                if (ep.path().equals("/actuator/info") && resp.statusCode() == 200 && !body.isBlank() && !isHtml(body)) {
                    log.accept("[!] Actuator: MEDIUM — info exposto em " + url);
                    findings.add(buildFinding(ep, url, body));
                    continue;
                }

                // Pattern-based detection — actuator endpoints always return JSON; HTML = SPA catch-all FP
                Optional<String> ct = resp.headers().firstValue("content-type");
                boolean looksJson = ct.map(s -> s.contains("application/json")).orElse(false)
                        || (!isHtml(body) && body.stripLeading().startsWith("{"));
                if (!looksJson) continue;

                if (ep.bodyPattern() != null && body.matches("(?s).*(" + ep.bodyPattern() + ").*")) {
                    log.accept("[!!] Actuator: " + ep.severity() + " — " + ep.description() + " em " + url);
                    findings.add(buildFinding(ep, url, body));
                }

            } catch (Exception e) {
                // Unreachable endpoint — expected
            }
        }

        if (findings.isEmpty()) {
            log.accept("[+] Actuator: nenhum endpoint exposto detectado");
        }
        return findings;
    }

    private static boolean isHtml(String body) {
        String t = body.stripLeading();
        return t.startsWith("<!DOCTYPE") || t.startsWith("<html") || t.startsWith("<!doctype");
    }

    private Finding buildFinding(ActuatorEndpoint ep, String url, String body) {
        String _cweId     = CweRegistry.cweId(id());
        String _cweTitle  = CweRegistry.cweTitle(id());
        String _cveVector = CweRegistry.cvssVector(id());
        double _score     = CvssCalculator.calculate(_cveVector);
        String snippet = body.length() > 300 ? body.substring(0, 300) + "..." : body;
        return Finding.of("Actuator", ep.path(),
                "Spring Actuator — " + ep.description(),
                ep.severity(),
                "URL: " + url + " | Body (300 chars): " + snippet,
                "Endpoint Spring Actuator acessível sem autenticação adequada — pode expor credenciais, configurações e estrutura interna",
                "curl '" + url + "'",
                "Restringir acesso ao actuator: spring.security.user.*, management.endpoints.web.exposure.include=health,info; "
                        + "exigir autenticação para endpoints sensíveis; desabilitar em produção o que não for necessário",
                _cweId, _cweTitle, _cveVector, _score);
    }
}
