package gg.effront.anarcry.scanner.web.xss;

import gg.effront.anarcry.model.CvssCalculator;
import gg.effront.anarcry.model.CweRegistry;
import gg.effront.anarcry.model.Finding;
import gg.effront.anarcry.model.KnowledgeBase;
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
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Consumer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class XssModule implements Scanner {

    private static final List<String> PROBE_PATHS = List.of("/", "/search", "/api/search", "/q", "/filter", "/api/",
            "/api/v1/", "/render", "/page");

    private static final List<String> PARAMS = List.of("q", "query", "search", "name", "msg", "text", "content", "page",
            "input", "s", "keyword", "filter");

    // DOM sink patterns -- dangerous assignments/calls that may receive
    // attacker-controlled data
    private static final Pattern DOM_SINKS = Pattern
            .compile("innerHTML\\s*=|outerHTML\\s*=|document\\.write\\s*\\(|eval\\s*\\(|"
                    + "location\\.href\\s*=|insertAdjacentHTML\\s*\\(|setTimeout\\s*\\(\\s*['\"]");

    private static final Pattern HTML_ENCODED_LT = Pattern.compile("&lt;|&#x3[Cc];|&#60;|\\\\u003[Cc]");

    private static final Pattern ALERT_CALL = Pattern.compile("alert\\([^)]*\\)");
    private static final Pattern EVENT_HANDLER = Pattern.compile("on(error|load|click|focus|toggle|mouseover|input)=");

    private record XssPayload(String template, String marker) {
    }

    private record ProbeResult(int status, String contentType, String body, String csp) {
        boolean isUsable() {
            return status >= 200 && status < 400 && contentType != null && contentType.contains("text/html");
        }
    }

    @Override
    public String id() {
        return "XSS";
    }

    @Override
    public List<Finding> scan(ScanContext ctx, Consumer<String> log) throws Exception {
        String cweId = CweRegistry.cweId(id());
        String cweTitle = CweRegistry.cweTitle(id());
        String cvssVec = CweRegistry.cvssVector(id());
        double score = CvssCalculator.calculate(cvssVec);

        List<Finding> findings = new ArrayList<>();
        HttpClient hc = HttpClientFactory.http2();

        String scheme = ctx.isHttps() ? "https" : "http";
        int defPort = ctx.isHttps() ? 443 : 80;
        String base = scheme + "://" + ctx.host() + (ctx.port() != defPort ? ":" + ctx.port() : "");

        log.accept("[~] XSS: iniciando probe em " + base);

        // Phase 3 (DOM sink analysis) -- fetch root page once and scan JS inline
        ProbeResult rootProbe = probe(ctx, hc, base + "/");
        String rootBody = rootProbe.body();
        if (rootProbe.isUsable() && !rootBody.isEmpty()) {
            var m = DOM_SINKS.matcher(rootBody);
            if (m.find()) {
                String sink = m.group().trim();
                log.accept("[~] XSS DOM: sink '" + sink + "' encontrado em /");
                findings.add(Finding.of(id(), "/", "DOM XSS -- Sink Perigoso Detectado (" + sink + ")", Severity.INFO,
                        "Sink '" + sink + "' encontrado no HTML/JS de " + base + "/",
                        "Potential DOM-based XSS: o sink '" + sink + "' pode receber dados controláveis "
                                + "pelo atacante via location.search, location.hash ou document.referrer "
                                + "sem sanitização adequada.",
                        "Inspecionar manualmente o JS de " + base + "/ e verificar se o sink "
                                + "recebe dados de location.search / location.hash / referrer.",
                        "Substituir innerHTML/outerHTML por textContent onde possível. "
                                + "Sanitizar com DOMPurify antes de qualquer atribuição a sinks HTML. "
                                + "Implementar Content-Security-Policy.",
                        cweId, cweTitle, cvssVec, score));
            }
        }

        // Build Phase 2 payload list: hardcoded + KB-enriched
        List<XssPayload> phase2Payloads = buildXssPayloads();
        log.accept("[~] XSS: " + PROBE_PATHS.size() + " paths × " + PARAMS.size() + " params × " + phase2Payloads.size()
                + " payloads");

        // Phase 1 + 2: Canary reflection + HTML payload injection (parallel by path)
        AtomicBoolean cancel = new AtomicBoolean(false);
        List<Callable<List<Finding>>> tasks = new ArrayList<>();

        for (int pi = 0; pi < PROBE_PATHS.size(); pi++) {
            String path = PROBE_PATHS.get(pi);
            int pathIdx = pi + 1;
            tasks.add(() -> {
                List<Finding> local = new ArrayList<>();
                log.accept("[~] XSS: [" + pathIdx + "/" + PROBE_PATHS.size() + "] " + path);
                for (String param : PARAMS) {
                    if (cancel.get()) {
                        return local;
                    }
                    // Generate unique canary per (path, param) pair
                    String canary = "xsstest" + UUID.randomUUID().toString().replace("-", "").substring(0, 8);

                    // Anti-FP: always fetch baseline before injection
                    ProbeResult baselineProbe = probe(ctx, hc, base + path + "?" + param + "=harmless");

                    // Phase 1: inject canary and check for verbatim reflection
                    String canaryEncoded = URLEncoder.encode(canary, "UTF-8");
                    ProbeResult canaryProbe = probe(ctx, hc, base + path + "?" + param + "=" + canaryEncoded);

                    if (!canaryProbe.isUsable() || !canaryProbe.body().contains(canary)
                            || baselineProbe.body().contains(canary)) {
                        continue;
                    }

                    log.accept("[~] XSS: canary refletido em " + path + "?" + param);

                    // Phase 2: try payloads until one confirms executable XSS
                    boolean anyUnescaped = false;
                    for (XssPayload xp : phase2Payloads) {
                        if (cancel.get()) {
                            return local;
                        }
                        String htmlPayload = xp.template();
                        String marker = xp.marker();
                        List<String> variants = WafEvasion.bypassPayloads(ctx, htmlPayload);
                        String encodedHtml = URLEncoder.encode(variants.getFirst(), "UTF-8");
                        String payloadUrl = base + path + "?" + param + "=" + encodedHtml;
                        ProbeResult payloadProbe = probe(ctx, hc, payloadUrl);
                        if (!payloadProbe.isUsable() && variants.size() > 1) {
                            for (int vi = 1; vi < variants.size(); vi++) {
                                encodedHtml = URLEncoder.encode(variants.get(vi), "UTF-8");
                                payloadUrl = base + path + "?" + param + "=" + encodedHtml;
                                payloadProbe = probe(ctx, hc, payloadUrl);
                                if (payloadProbe.isUsable()) {
                                    break;
                                }
                            }
                        }
                        String endpoint = path + "?" + param + "=" + encodedHtml;

                        if (!payloadProbe.isUsable()) {
                            continue;
                        }
                        String payloadBody = payloadProbe.body();
                        boolean appEscapes = HTML_ENCODED_LT.matcher(payloadBody).find();

                        if (!appEscapes && payloadBody.contains(marker)) {
                            log.accept(
                                    "[!!] XSS CRITICAL: '" + htmlPayload + "' refletido sem encoding em " + endpoint);
                            local.add(Finding.of(id(), endpoint, "Reflected XSS -- Payload Executável Refletido",
                                    Severity.CRITICAL,
                                    "Payload '" + htmlPayload + "' refletido sem encoding HTML em " + base + endpoint
                                            + " | Canary: " + canary + " | Marker: " + marker,
                                    "Reflected XSS confirmado: o payload é refletido sem escape, "
                                            + "permitindo execução de JavaScript arbitrário no contexto da página "
                                            + "com acesso ao DOM, cookies não-HttpOnly e session storage.",
                                    "curl -G '" + base + path + "' \\\n" + "  --data-urlencode '" + param + "="
                                            + htmlPayload + "'",
                                    "Escapar toda saída HTML com htmlspecialchars() / HtmlUtils.htmlEscape(). "
                                            + "Implementar Content-Security-Policy com default-src 'self'. "
                                            + "Validar e sanitizar entrada no servidor antes de renderizar.",
                                    cweId, cweTitle, cvssVec, score));
                            cancel.set(true);
                            return local;
                        }
                        if (!appEscapes) {
                            anyUnescaped = true;
                        }
                    }

                    if (anyUnescaped) {
                        String endpoint = path + "?" + param + "=" + canary;
                        boolean nonExec = isNonExecutableReflection(canaryProbe, canary);
                        Severity sev = nonExec ? Severity.INFO : Severity.MEDIUM;
                        String sevLabel = nonExec ? "INFO" : "MEDIUM";
                        log.accept("[~] XSS " + sevLabel + ": canary refletido, nenhum payload confirmou execução em "
                                + endpoint);
                        String title = nonExec
                                ? "Reflexão de Input em Contexto Não-Executável (JSON/RSC)"
                                : "Reflected XSS (Potencial) -- Reflexão de Input Sem Contexto Executável";
                        String impact = nonExec
                                ? "Input refletido em contexto não-executável (JSON serialization, RSC payload "
                                        + "ou CSP com nonce). Reflexão não resulta em execução de script."
                                : "Input refletido detectado, mas nenhum payload resultou em evento handler "
                                        + "executável neste contexto. Bypass pode ser possível em atributo, "
                                        + "script block ou via codificação alternativa (HTML entities, Unicode).";
                        local.add(Finding.of(id(), endpoint, title, sev,
                                "Canary '" + canary + "' refletido em " + base + endpoint + " | "
                                        + phase2Payloads.size() + " payloads testados sem execução confirmada; "
                                        + "contexto de injeção requer análise manual",
                                impact,
                                "curl -G '" + base + path + "' \\\n" + "  --data-urlencode '" + param + "=" + canary
                                        + "'",
                                "Revisar o contexto de reflexão manualmente. "
                                        + "Aplicar encoding específico ao contexto (HTML, JS, URL, CSS). "
                                        + "Implementar CSP e sanitização server-side com allowlist.",
                                cweId, cweTitle, cvssVec, score));
                        cancel.set(true);
                        return local;
                    }
                }
                return local;
            });
        }

        findings.addAll(ProbeExecutor.run(tasks, ctx.config().probeConcurrency(), cancel));

        if (findings.isEmpty()) {
            log.accept("[+] XSS: nenhum injection detectado");
        }

        return findings;
    }

    private List<XssPayload> buildXssPayloads() {
        List<XssPayload> payloads = new ArrayList<>();
        payloads.add(new XssPayload("<img src=x onerror=zz>", "onerror=zz"));
        for (String kbp : KnowledgeBase.getInstance().filteredPayloads(id())) {
            if (!kbp.contains("<")) {
                continue;
            }
            Matcher ev = EVENT_HANDLER.matcher(kbp);
            if (ev.find()) {
                String handler = ev.group();
                String adapted = ALERT_CALL.matcher(kbp).replaceFirst("xzz");
                if (!adapted.equals(kbp)) {
                    payloads.add(new XssPayload(adapted, handler + "xzz"));
                } else {
                    payloads.add(new XssPayload(kbp, handler));
                }
            } else if (kbp.contains("<script>")) {
                String adapted = ALERT_CALL.matcher(kbp).replaceFirst("xzz");
                payloads.add(new XssPayload(adapted, "<script>xzz"));
            }
        }
        return List.copyOf(payloads);
    }

    private static final ProbeResult EMPTY_PROBE = new ProbeResult(0, "", "", "");

    private ProbeResult probe(ScanContext ctx, HttpClient hc, String url) {
        try {
            HttpRequest req = HttpRequest.newBuilder().uri(URI.create(url)).timeout(Duration.ofSeconds(6)).GET()
                    .build();
            HttpResponse<String> r = Http.send(ctx, hc, req, HttpResponse.BodyHandlers.ofString(), id());
            String ct = r.headers().firstValue("content-type").orElse("");
            String csp = r.headers().firstValue("content-security-policy").orElse("");
            String body = r.body() != null ? r.body() : "";
            return new ProbeResult(r.statusCode(), ct, body, csp);
        } catch (Exception e) {
            return EMPTY_PROBE;
        }
    }

    private boolean isNonExecutableReflection(ProbeResult probe, String canary) {
        if (!probe.csp().isEmpty() && (probe.csp().contains("'nonce-") || probe.csp().contains("'strict-dynamic'"))) {
            return true;
        }
        String body = probe.body();
        if (body.contains("self.__next_f") || body.contains("__next_f.push")) {
            return true;
        }
        int idx = body.indexOf(canary);
        if (idx >= 0) {
            int start = Math.max(0, idx - 30);
            String before = body.substring(start, idx);
            if (before.contains("\":\"") || before.contains("\\\"")) {
                return true;
            }
        }
        return false;
    }
}
