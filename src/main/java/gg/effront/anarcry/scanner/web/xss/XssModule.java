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
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
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

    private static final Pattern DOM_SINKS = Pattern
            .compile("innerHTML\\s*=|outerHTML\\s*=|document\\.write\\s*\\(|eval\\s*\\(|"
                    + "location\\.href\\s*=|insertAdjacentHTML\\s*\\(|setTimeout\\s*\\(\\s*['\"]");

    private static final Pattern HTML_ENCODED_LT = Pattern.compile("&lt;|&#x3[Cc];|&#60;|\\\\u003[Cc]");

    private static final Pattern ALERT_CALL = Pattern.compile("alert\\([^)]*\\)");
    private static final Pattern EVENT_HANDLER = Pattern.compile("on(error|load|click|focus|toggle|mouseover|input)=");

    private static final List<String> STORED_XSS_PATHS = List.of("/api/users", "/api/comments", "/api/posts",
            "/api/messages", "/api/notes", "/api/feedback", "/api/reviews", "/api/profiles", "/api/v1/users",
            "/api/v1/comments", "/api/v1/posts");

    private static final List<String> STORED_XSS_FIELDS = List.of("name", "title", "description", "comment", "message",
            "body", "content");

    private static final List<String> UPLOAD_CONFIG_PATHS = List.of("/api/uploadthing", "/upload", "/api/upload",
            "/api/files", "/api/media");

    private static final Pattern UPLOAD_CONFIG_PATTERN = Pattern
            .compile("\"(?:slug|maxFileSize|allowedMimeTypes|fileTypes|routeConfig)\"");

    private static final Pattern SVG_MIME_PATTERN = Pattern.compile("image/svg\\+xml|image/\\*|\\*\\.svg|\\.svg",
            Pattern.CASE_INSENSITIVE);

    private record XssPayload(String template, String marker) {
    }

    private record ProbeResult(int status, String contentType, String body, String csp) {
        boolean isUsable() {
            if (status < 200 || status >= 400 || contentType == null) {
                return false;
            }
            return contentType.contains("text/html") || contentType.contains("image/svg+xml")
                    || contentType.contains("application/xhtml+xml") || contentType.contains("text/xml")
                    || contentType.contains("application/xml");
        }

        boolean isJsonApi() {
            return status >= 200 && status < 400 && contentType != null && contentType.contains("application/json");
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
                        "Potential DOM-based XSS: o sink '" + sink + "' pode receber dados "
                                + "controlaveis pelo atacante via location.search, location.hash "
                                + "ou document.referrer sem sanitizacao adequada.",
                        "Inspecionar manualmente o JS de " + base + "/ e verificar se o sink "
                                + "recebe dados de location.search / location.hash / referrer.",
                        "Substituir innerHTML/outerHTML por textContent onde possivel. "
                                + "Sanitizar com DOMPurify antes de qualquer atribuicao a sinks HTML. "
                                + "Implementar Content-Security-Policy.",
                        cweId, cweTitle, cvssVec, score));
            }
        }

        // Build Phase 2 payload list: hardcoded + KB-enriched
        List<XssPayload> phase2Payloads = buildXssPayloads();
        log.accept("[~] XSS: " + PROBE_PATHS.size() + " paths x " + PARAMS.size() + " params x " + phase2Payloads.size()
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
                    String canary = "xsstest" + UUID.randomUUID().toString().replace("-", "").substring(0, 8);

                    ProbeResult baselineProbe = probe(ctx, hc, base + path + "?" + param + "=harmless");

                    String canaryEncoded = URLEncoder.encode(canary, "UTF-8");
                    ProbeResult canaryProbe = probe(ctx, hc, base + path + "?" + param + "=" + canaryEncoded);

                    if (!canaryProbe.isUsable() || !canaryProbe.body().contains(canary)
                            || baselineProbe.body().contains(canary)) {
                        continue;
                    }

                    log.accept("[~] XSS: canary refletido em " + path + "?" + param);

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
                            local.add(Finding.of(id(), endpoint, "Reflected XSS -- Payload Executavel Refletido",
                                    Severity.CRITICAL,
                                    "Payload '" + htmlPayload + "' refletido sem encoding HTML em " + base + endpoint
                                            + " | Canary: " + canary + " | Marker: " + marker,
                                    "Reflected XSS confirmado: o payload e refletido sem escape, "
                                            + "permitindo execucao de JavaScript arbitrario "
                                            + "no contexto da pagina com acesso ao DOM, "
                                            + "cookies nao-HttpOnly e session storage.",
                                    "curl -G '" + base + path + "' \\\n" + "  --data-urlencode '" + param + "="
                                            + htmlPayload + "'",
                                    "Escapar toda saida HTML com htmlspecialchars() / HtmlUtils.htmlEscape(). "
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
                        log.accept("[~] XSS " + sevLabel + ": canary refletido, nenhum payload confirmou execucao em "
                                + endpoint);
                        String title = nonExec
                                ? "Reflexao de Input em Contexto Nao-Executavel (JSON/RSC)"
                                : "Reflected XSS (Potencial) -- Reflexao de Input Sem Contexto Executavel";
                        String impact = nonExec
                                ? "Input refletido em contexto nao-executavel "
                                        + "(JSON serialization, RSC payload ou CSP com nonce). "
                                        + "Reflexao nao resulta em execucao de script."
                                : "Input refletido detectado, mas nenhum payload resultou "
                                        + "em evento handler executavel neste contexto. "
                                        + "Bypass pode ser possivel em atributo, script block "
                                        + "ou via codificacao alternativa (HTML entities, Unicode).";
                        local.add(Finding.of(id(), endpoint, title, sev,
                                "Canary '" + canary + "' refletido em " + base + endpoint + " | "
                                        + phase2Payloads.size() + " payloads testados sem execucao confirmada; "
                                        + "contexto de injecao requer analise manual",
                                impact,
                                "curl -G '" + base + path + "' \\\n" + "  --data-urlencode '" + param + "=" + canary
                                        + "'",
                                "Revisar o contexto de reflexao manualmente. "
                                        + "Aplicar encoding especifico ao contexto (HTML, JS, URL, CSS). "
                                        + "Implementar CSP e sanitizacao server-side com allowlist.",
                                cweId, cweTitle, cvssVec, score));
                        cancel.set(true);
                        return local;
                    }
                }
                return local;
            });
        }

        findings.addAll(ProbeExecutor.run(tasks, ctx.config().probeConcurrency(), cancel));

        // Phase 4: Stored XSS via JSON APIs
        log.accept("[~] XSS Phase 4: probing stored XSS via JSON APIs");
        findings.addAll(probeStoredXss(ctx, hc, base, log, cweId, cweTitle, cvssVec, score));

        // Phase 5: SVG Upload XSS via upload config disclosure
        log.accept("[~] XSS Phase 5: probing upload config for SVG XSS vectors");
        findings.addAll(probeUploadXss(ctx, hc, base, log, cweId, cweTitle, cvssVec, score));

        if (findings.isEmpty()) {
            log.accept("[+] XSS: nenhum injection detectado");
        }

        return findings;
    }

    private List<Finding> probeStoredXss(ScanContext ctx, HttpClient hc, String base, Consumer<String> log,
            String cweId, String cweTitle, String cvssVec, double score) {
        List<Finding> findings = new ArrayList<>();
        String canary = "anarcry_xss_" + UUID.randomUUID().toString().replace("-", "").substring(0, 8);
        String scriptCanary = "<script>alert('" + canary + "')</script>";

        Set<String> writableEndpoints = new LinkedHashSet<>(STORED_XSS_PATHS);

        // Enrich from crawler-discovered paths that look like REST write endpoints
        for (String discovered : ctx.discoveredPaths().paths()) {
            String lower = discovered.toLowerCase();
            if (lower.startsWith("/api/") || lower.startsWith("/trpc/") || lower.contains("/graphql")) {
                writableEndpoints.add(discovered);
            }
        }

        log.accept(
                "[~] XSS Stored: " + writableEndpoints.size() + " endpoints x " + STORED_XSS_FIELDS.size() + " fields");

        for (String endpoint : writableEndpoints) {
            String postUrl = base + endpoint;
            boolean isTrpc = endpoint.toLowerCase().startsWith("/trpc/");

            String jsonBody;
            if (isTrpc) {
                StringBuilder inner = new StringBuilder("{");
                for (int i = 0; i < STORED_XSS_FIELDS.size(); i++) {
                    if (i > 0) {
                        inner.append(",");
                    }
                    inner.append("\"").append(STORED_XSS_FIELDS.get(i)).append("\":\"").append(escapeJson(scriptCanary))
                            .append("\"");
                }
                inner.append("}");
                jsonBody = "{\"0\":{\"json\":" + inner + "}}";
                postUrl = postUrl + "?batch=1";
            } else {
                StringBuilder jsonBuilder = new StringBuilder("{");
                for (int i = 0; i < STORED_XSS_FIELDS.size(); i++) {
                    if (i > 0) {
                        jsonBuilder.append(",");
                    }
                    jsonBuilder.append("\"").append(STORED_XSS_FIELDS.get(i)).append("\":\"")
                            .append(escapeJson(scriptCanary)).append("\"");
                }
                jsonBuilder.append("}");
                jsonBody = jsonBuilder.toString();
            }

            ProbeResult postResult = probePost(ctx, hc, postUrl, jsonBody);

            if (!postResult.isJsonApi() && !postResult.isUsable()) {
                continue;
            }

            // POST accepted -- check if canary persists via GET on the same endpoint
            if (postResult.body().contains(canary) && !postResult.body().contains("&lt;script")) {
                log.accept("[!!] XSS Stored: canary refletido no POST response em " + endpoint);
                findings.add(
                        Finding.of(id(), endpoint, "Stored XSS -- Payload Persistido em API Response", Severity.HIGH,
                                "POST " + postUrl + " com payload '" + scriptCanary
                                        + "' retornou canary sem encoding no response body",
                                "Stored XSS confirmado: o payload XSS enviado via POST e armazenado "
                                        + "no backend e retornado sem sanitizacao no response. "
                                        + "Se o conteudo for renderizado em dashboard/admin, "
                                        + "permite execucao de JavaScript no contexto de outros usuarios.",
                                "curl -X POST '" + postUrl + "' \\\n  -H 'Content-Type: application/json' \\\n"
                                        + "  -d '" + jsonBody + "'",
                                "Sanitizar toda entrada antes de persistir (server-side). "
                                        + "Escapar output em toda renderizacao HTML (htmlspecialchars). "
                                        + "Implementar CSP com default-src 'self'.",
                                cweId, cweTitle, cvssVec, score));
                continue;
            }

            // POST returned 2xx/3xx -- try GET to check if canary was stored
            ProbeResult getResult = probe(ctx, hc, postUrl);
            if (getResult.isUsable() || getResult.isJsonApi()) {
                String getBody = getResult.body();
                if (getBody.contains(canary) && !getBody.contains("&lt;script") && !getBody.contains("\\u003cscript")) {
                    log.accept("[!!] XSS Stored: canary persistido e retornado sem encoding em " + endpoint);
                    findings.add(Finding.of(id(), endpoint, "Stored XSS -- Payload Persistido e Retornado Sem Encoding",
                            Severity.HIGH,
                            "POST " + postUrl + " armazenou payload, GET " + postUrl + " retornou canary '" + canary
                                    + "' sem encoding HTML",
                            "Stored XSS confirmado: payload injetado via POST persiste no backend "
                                    + "e e retornado sem sanitizacao em GET subsequente. "
                                    + "Atacante pode injetar scripts que executam no contexto "
                                    + "de qualquer usuario que visualize os dados.",
                            "curl -X POST '" + postUrl + "' \\\n  -H 'Content-Type: application/json' \\\n" + "  -d '"
                                    + jsonBody + "'\n\ncurl '" + postUrl + "'",
                            "Sanitizar toda entrada antes de persistir (server-side). "
                                    + "Escapar output em toda renderizacao HTML (htmlspecialchars). "
                                    + "Implementar CSP com default-src 'self'.",
                            cweId, cweTitle, cvssVec, score));
                }
            }
        }

        if (findings.isEmpty()) {
            log.accept("[+] XSS Stored: nenhum stored XSS detectado");
        }
        return findings;
    }

    private List<Finding> probeUploadXss(ScanContext ctx, HttpClient hc, String base, Consumer<String> log,
            String cweId, String cweTitle, String cvssVec, double score) {
        List<Finding> findings = new ArrayList<>();

        Set<String> uploadPaths = new LinkedHashSet<>(UPLOAD_CONFIG_PATHS);
        for (String discovered : ctx.discoveredPaths().paths()) {
            String lower = discovered.toLowerCase();
            if (lower.contains("upload") || lower.contains("uploadthing") || lower.contains("/files")
                    || lower.contains("/media")) {
                uploadPaths.add(discovered);
            }
        }

        log.accept("[~] XSS Upload: probing " + uploadPaths.size() + " upload config endpoints");

        for (String path : uploadPaths) {
            String configUrl = base + path;
            ProbeResult configProbe = probe(ctx, hc, configUrl);

            if (configProbe.status < 200 || configProbe.status >= 400) {
                continue;
            }

            String body = configProbe.body();
            boolean hasConfigKeys = UPLOAD_CONFIG_PATTERN.matcher(body).find();

            if (!hasConfigKeys) {
                continue;
            }

            log.accept("[~] XSS Upload: config disclosure em " + path);
            findings.add(Finding.of(id(), path, "Upload Config Disclosure -- Route Configuration Exposta",
                    Severity.MEDIUM,
                    "GET " + configUrl + " retorna configuracao de upload com route config: " + truncate(body, 300),
                    "Endpoint de upload expoe configuracao de rotas (slug, maxFileSize, "
                            + "allowedMimeTypes). Atacante pode usar esta informacao para "
                            + "identificar vetores de upload e mime types aceitos.",
                    "curl '" + configUrl + "'",
                    "Proteger endpoints de config de upload com autenticacao. "
                            + "Nao expor detalhes de configuracao em respostas publicas.",
                    cweId, cweTitle, cvssVec, score));

            boolean svgAllowed = SVG_MIME_PATTERN.matcher(body).find();
            if (!svgAllowed) {
                continue;
            }

            // SVG/image/* allowed -- check if endpoint requires auth
            ProbeResult noAuthProbe = probeWithoutAuth(ctx, hc, configUrl);
            boolean noAuthRequired = noAuthProbe.status >= 200 && noAuthProbe.status < 400;

            if (noAuthRequired) {
                log.accept("[!!] XSS Upload: SVG upload permitido sem autenticacao em " + path);
                findings.add(Finding.of(id(), path, "SVG XSS Vector -- Upload de SVG Permitido Sem Autenticacao",
                        Severity.HIGH,
                        "GET " + configUrl + " aceita SVG/image (mime: image/svg+xml ou image/*) "
                                + "sem autenticacao (HTTP " + noAuthProbe.status + ")",
                        "Upload de SVG sem autenticacao permite injecao de XSS persistente. "
                                + "SVG com tag <script> servido inline como image/svg+xml executa "
                                + "JavaScript no browser do visitante. Payload exemplo: "
                                + "<svg xmlns='http://www.w3.org/2000/svg'>"
                                + "<script>alert(document.cookie)</script></svg>",
                        "curl '" + configUrl + "'",
                        "Bloquear upload de SVG ou sanitizar SVG removendo tags de script. "
                                + "Servir uploads com Content-Disposition: attachment. "
                                + "Exigir autenticacao em endpoints de upload. "
                                + "Usar CSP para mitigar execucao de scripts inline.",
                        cweId, cweTitle, cvssVec, score));
            } else {
                findings.add(Finding.of(id(), path, "SVG XSS Vector -- Upload de SVG Permitido (Autenticado)",
                        Severity.MEDIUM,
                        "GET " + configUrl + " aceita SVG/image (mime: image/svg+xml ou image/*) "
                                + "mas requer autenticacao (HTTP " + noAuthProbe.status + " sem auth)",
                        "Upload de SVG com autenticacao permite stored XSS caso um "
                                + "usuario autenticado faca upload de SVG malicioso. "
                                + "SVG com <script> servido inline como image/svg+xml executa JS.",
                        "curl '" + configUrl + "'",
                        "Sanitizar SVG removendo tags de script antes de armazenar. "
                                + "Servir uploads com Content-Disposition: attachment. "
                                + "Usar CSP para mitigar execucao de scripts inline.",
                        cweId, cweTitle, cvssVec, score));
            }
        }

        if (findings.isEmpty()) {
            log.accept("[+] XSS Upload: nenhum vetor de SVG XSS detectado");
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

    private ProbeResult probePost(ScanContext ctx, HttpClient hc, String url, String jsonBody) {
        try {
            HttpRequest req = HttpRequest.newBuilder().uri(URI.create(url)).timeout(Duration.ofSeconds(6))
                    .header("Content-Type", "application/json").POST(HttpRequest.BodyPublishers.ofString(jsonBody))
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

    // Probe without injecting auth headers to test if endpoint is publicly
    // accessible
    private ProbeResult probeWithoutAuth(ScanContext ctx, HttpClient hc, String url) {
        try {
            HttpRequest req = HttpRequest.newBuilder().uri(URI.create(url)).timeout(Duration.ofSeconds(6)).GET()
                    .build();
            HttpResponse<String> r = hc.send(req, HttpResponse.BodyHandlers.ofString());
            String ct = r.headers().firstValue("content-type").orElse("");
            String body = r.body() != null ? r.body() : "";
            return new ProbeResult(r.statusCode(), ct, body, "");
        } catch (Exception e) {
            return EMPTY_PROBE;
        }
    }

    private boolean isNonExecutableReflection(ProbeResult probe, String canary) {
        String body = probe.body();
        boolean inRscPayload = body.contains("self.__next_f") || body.contains("__next_f.push");
        if (inRscPayload) {
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
        boolean hasStrictCsp = !probe.csp().isEmpty()
                && (probe.csp().contains("'nonce-") || probe.csp().contains("'strict-dynamic'"));
        if (hasStrictCsp && idx < 0) {
            return true;
        }
        return false;
    }

    private static String escapeJson(String s) {
        return s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "\\r");
    }

    private static String truncate(String s, int max) {
        if (s.length() <= max) {
            return s;
        }
        return s.substring(0, max) + "...";
    }
}
