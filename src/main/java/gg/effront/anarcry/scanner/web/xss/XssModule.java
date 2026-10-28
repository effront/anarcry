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

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
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

    // Detects common HTML-encoding of '<' that indicates the app is escaping output
    private static final Pattern HTML_ENCODED_LT = Pattern.compile("&lt;|&#x3[Cc];|&#60;");

    private static final Pattern ALERT_CALL = Pattern.compile("alert\\([^)]*\\)");
    private static final Pattern EVENT_HANDLER = Pattern.compile("on(error|load|click|focus|toggle|mouseover|input)=");

    private record XssPayload(String template, String marker) {
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
        String rootBody = fetchBody(ctx, hc, base + "/");
        if (!rootBody.isEmpty()) {
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

        // Phase 1 + 2: Canary reflection + HTML payload injection
        outer : for (int pi = 0; pi < PROBE_PATHS.size(); pi++) {
            String path = PROBE_PATHS.get(pi);
            log.accept("[~] XSS: [" + (pi + 1) + "/" + PROBE_PATHS.size() + "] " + path);
            for (String param : PARAMS) {
                // Generate unique canary per (path, param) pair
                String canary = "xsstest" + UUID.randomUUID().toString().replace("-", "").substring(0, 8);

                // Anti-FP: always fetch baseline before injection
                String baseline = fetchBody(ctx, hc, base + path + "?" + param + "=harmless");

                // Phase 1: inject canary and check for verbatim reflection
                String canaryEncoded = URLEncoder.encode(canary, "UTF-8");
                String canaryBody = fetchBody(ctx, hc, base + path + "?" + param + "=" + canaryEncoded);

                if (canaryBody.isEmpty() || !canaryBody.contains(canary) || baseline.contains(canary)) {
                    continue; // not reflected, or coincidental baseline match
                }

                log.accept("[~] XSS: canary refletido em " + path + "?" + param);

                // Phase 2: try payloads until one confirms executable XSS
                boolean anyUnescaped = false;
                for (XssPayload xp : phase2Payloads) {
                    String htmlPayload = xp.template();
                    String marker = xp.marker();
                    String encodedHtml = URLEncoder.encode(htmlPayload, "UTF-8");
                    String payloadUrl = base + path + "?" + param + "=" + encodedHtml;
                    String payloadBody = fetchBody(ctx, hc, payloadUrl);
                    String endpoint = path + "?" + param + "=" + encodedHtml;

                    if (payloadBody.isEmpty()) {
                        continue;
                    }
                    boolean appEscapes = HTML_ENCODED_LT.matcher(payloadBody).find();

                    if (!appEscapes && payloadBody.contains(marker)) {
                        log.accept("[!!] XSS HIGH: '" + htmlPayload + "' refletido sem encoding em " + endpoint);
                        findings.add(Finding.of(id(), endpoint, "Reflected XSS -- Payload Executável Refletido",
                                Severity.HIGH,
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
                        break outer;
                    }
                    if (!appEscapes) {
                        anyUnescaped = true;
                    }
                }

                if (anyUnescaped) {
                    String endpoint = path + "?" + param + "=" + canary;
                    log.accept("[~] XSS MEDIUM: canary refletido, nenhum payload confirmou execução em " + endpoint);
                    findings.add(Finding.of(id(), endpoint,
                            "Reflected XSS (Potencial) -- Reflexão de Input Sem Contexto Executável", Severity.MEDIUM,
                            "Canary '" + canary + "' refletido em " + base + endpoint + " | " + phase2Payloads.size()
                                    + " payloads testados sem execução confirmada; "
                                    + "contexto de injeção requer análise manual",
                            "Input refletido detectado, mas nenhum payload resultou em evento handler "
                                    + "executável neste contexto. Bypass pode ser possível em atributo, "
                                    + "script block ou via codificação alternativa (HTML entities, Unicode).",
                            "curl -G '" + base + path + "' \\\n" + "  --data-urlencode '" + param + "=" + canary + "'",
                            "Revisar o contexto de reflexão manualmente. "
                                    + "Aplicar encoding específico ao contexto (HTML, JS, URL, CSS). "
                                    + "Implementar CSP e sanitização server-side com allowlist.",
                            cweId, cweTitle, cvssVec, score));
                    break outer;
                }
            }
        }

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

    private String fetchBody(ScanContext ctx, HttpClient hc, String url) {
        try {
            HttpRequest req = HttpRequest.newBuilder().uri(URI.create(url)).timeout(Duration.ofSeconds(6)).GET()
                    .build();
            HttpResponse<String> r = Http.send(ctx, hc, req, HttpResponse.BodyHandlers.ofString(), id());
            return r.body() != null ? r.body() : "";
        } catch (Exception e) {
            return "";
        }
    }
}
