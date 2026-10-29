package gg.effront.anarcry.scanner.web.cmdinject;

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
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Consumer;

/**
 * CommandInjectionModule -- CWE-78 scanner.
 *
 * Phase 1 (active): injects command separators appending 'id' and matches RCE
 * output (uid=, root:x:, www-data, nobody) in response body. Phase 2
 * (time-based blind): injects sleep payloads and measures timing differential
 * with proportional confirmation to eliminate slow-server FPs.
 *
 * <p>
 * Paths are probed in parallel via {@link ProbeExecutor}; within each path,
 * params and phases stay sequential.
 */
public class CommandInjectionModule implements Scanner {

    // Paths to probe for network-related endpoints
    private static final List<String> PATHS = List.of("/api/", "/api/v1/", "/ping", "/check", "/health", "/resolve",
            "/lookup", "/scan");

    // Parameter names considered high-value surfaces for command injection.
    // Also used as the keyword set: a param is probed only when its name
    // (lowercased) contains at least one of these words.
    private static final List<String> NETWORK_KEYWORDS = List.of("host", "ip", "url", "domain", "cmd", "exec",
            "command", "ping", "target", "server", "address", "dns", "query", "lookup", "hostname", "dest",
            "destination");

    // Phase 1: active output-based injection payloads (separator + 'id' command)
    private static final List<String> ACTIVE_PAYLOADS = List.of("; id", "| id", "|| id", "&& id", "$(id)");

    // Phase 2: time-based blind injection payloads (separator + sleep 5)
    private static final List<String> SLEEP_PAYLOADS = List.of("; sleep 5", "| sleep 5", "&& sleep 5", "$(sleep 5)",
            "; ping -c 5 127.0.0.1");

    // RCE output detection pattern -- anchored to avoid false matches on substrings
    // such as "userid" or "product_id". The (?i) flag makes it case-insensitive.
    private static final java.util.regex.Pattern RCE_OUTPUT = java.util.regex.Pattern
            .compile("(?i)(uid=\\d+|root:x:|www-data|nobody)");

    // Minimum timing differential (ms) above baseline to suspect time-based
    // injection
    private static final long TIMING_THRESHOLD_MS = 4000L;

    // Request timeout for time-based probes (must exceed sleep 5 payload)
    private static final int BLIND_TIMEOUT_S = 12;

    @Override
    public String id() {
        return "CmdInjection";
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

        List<String> activePayloads = mergeKbPayloads(false);
        List<String> sleepPayloads = mergeKbPayloads(true);
        log.accept("[~] CmdInjection: iniciando varredura em " + base + " (" + PATHS.size() + " paths × "
                + NETWORK_KEYWORDS.size() + " params, " + activePayloads.size() + " active + " + sleepPayloads.size()
                + " sleep payloads)");

        AtomicBoolean cancel = new AtomicBoolean(false);
        List<Callable<List<Finding>>> tasks = new ArrayList<>();

        for (int pi = 0; pi < PATHS.size(); pi++) {
            final String path = PATHS.get(pi);
            final int pathIdx = pi;
            tasks.add(() -> {
                List<Finding> local = new ArrayList<>();
                log.accept("[~] CmdInjection: [" + (pathIdx + 1) + "/" + PATHS.size() + "] " + path);
                for (String param : NETWORK_KEYWORDS) {
                    if (cancel.get()) {
                        return local;
                    }

                    // Only probe params whose name contains a network keyword (always true
                    // here since NETWORK_KEYWORDS IS the param list, but the check is
                    // explicit so subclasses or future callers that pass a different set
                    // still work).
                    if (!containsAnyKeyword(param)) {
                        continue;
                    }

                    // -- Baseline --
                    String baseline = fetchBody(ctx, hc, base + path + "?" + param + "=testvalue");

                    // Anti-FP: skip param if baseline already contains RCE pattern
                    if (RCE_OUTPUT.matcher(baseline).find()) {
                        log.accept("[~] CmdInjection: baseline contém padrão RCE -- pulando " + param + " em " + path);
                        continue;
                    }

                    // -- Phase 1: Active output-based injection --
                    for (String payload : activePayloads) {
                        if (cancel.get()) {
                            return local;
                        }
                        String injected = "testvalue" + WafEvasion.evasionPayload(ctx, payload);
                        String encoded;
                        try {
                            encoded = URLEncoder.encode(injected, "UTF-8");
                        } catch (Exception e) {
                            continue;
                        }
                        String probeUrl = base + path + "?" + param + "=" + encoded;
                        try {
                            HttpRequest req = HttpRequest.newBuilder().uri(URI.create(probeUrl))
                                    .timeout(Duration.ofSeconds(8)).GET().build();
                            HttpResponse<String> resp = Http.send(ctx, hc, req, HttpResponse.BodyHandlers.ofString(),
                                    id());
                            String body = resp.body() != null ? resp.body() : "";

                            java.util.regex.Matcher m = RCE_OUTPUT.matcher(body);
                            if (resp.statusCode() < 500 && m.find()) {
                                String hit = m.group(1);
                                // Anti-FP: ensure RCE output was NOT present in baseline
                                if (!baseline.contains(hit)) {
                                    String endpoint = path + "?" + param + "=" + encoded;
                                    log.accept("[!!!] CmdInjection CRITICAL -- injeção ativa" + " confirmada: "
                                            + endpoint + " (saída: " + hit + ")");
                                    local.add(Finding.of(id(), endpoint,
                                            "OS Command Injection -- execução de" + " comandos confirmada",
                                            Severity.CRITICAL,
                                            "Payload: " + injected + " → saída detectada: " + hit + " | URL: " + base
                                                    + endpoint,
                                            "Execução arbitrária de comandos do SO" + " via injeção no parâmetro '"
                                                    + param + "' -- acesso total ao" + " servidor comprometido",
                                            "curl -G '" + base + path + "' \\\n" + "  --data-urlencode '" + param + "="
                                                    + injected + "'",
                                            "Nunca passe input do usuário" + " diretamente a funções de"
                                                    + " execução de comandos" + " (exec/system/popen/ProcessBuilder)."
                                                    + " Use APIs de linguagem" + " seguras, validação allowlist"
                                                    + " estrita e sandbox isolado.",
                                            cweId, cweTitle, cvssVec, score));
                                    cancel.set(true);
                                    return local;
                                }
                            }
                        } catch (Exception ignored) {
                            // Connection errors / timeouts are not findings in Phase 1
                        }
                    }

                    // -- Phase 2: Time-based blind injection --
                    if (cancel.get()) {
                        return local;
                    }
                    long baselineMs = measureBaselineRtt(ctx, hc, base, path, param);

                    for (String sleepPayload : sleepPayloads) {
                        if (cancel.get()) {
                            return local;
                        }
                        long elapsed = measureElapsed(ctx, hc, base, path, param, sleepPayload);

                        if (elapsed <= baselineMs + TIMING_THRESHOLD_MS) {
                            continue; // No significant spike for this payload
                        }

                        // Proportional verification: eliminates slow-server false
                        // positives
                        boolean confirmed = verifyProportionalDelay(ctx, hc, baselineMs, base, path, param,
                                sleepPayload);
                        if (confirmed) {
                            String injected = "testvalue" + sleepPayload;
                            String encoded;
                            try {
                                encoded = URLEncoder.encode(injected, "UTF-8");
                            } catch (Exception e) {
                                continue;
                            }
                            String endpoint = path + "?" + param + "=" + encoded;
                            log.accept("[!!!] CmdInjection CRITICAL -- blind injection" + " temporal confirmada: "
                                    + endpoint + " (elapsed: " + elapsed + "ms, baseline: " + baselineMs + "ms)");
                            local.add(Finding.of(id(), endpoint,
                                    "OS Command Injection Blind (Time-Based) --"
                                            + " sleep confirmado proporcionalmente",
                                    Severity.CRITICAL,
                                    "Payload: " + injected + " → elapsed: " + elapsed + "ms" + " (baseline: "
                                            + baselineMs + "ms, delta: " + (elapsed - baselineMs) + "ms)"
                                            + " | Verificação proporcional:" + " confirmada" + " | URL: " + base
                                            + endpoint,
                                    "Command injection cega confirmada via delay"
                                            + " temporal proporcional no parâmetro '" + param
                                            + "' -- execução no SO comprovada" + " mesmo sem saída visível",
                                    "curl -G '" + base + path + "' \\\n" + "  --data-urlencode '" + param + "="
                                            + injected + "'",
                                    "Nunca passe input do usuário a funções de" + " execução de comandos. Use APIs"
                                            + " seguras, validação allowlist e"
                                            + " sandbox. Para operações de rede, use"
                                            + " bibliotecas que não invocam o shell.",
                                    cweId, cweTitle, cvssVec, score));
                            cancel.set(true);
                            return local;
                        } else {
                            log.accept("[~] CmdInjection: spike temporal detectado em " + path + "?" + param
                                    + " (delta=" + (elapsed - baselineMs) + "ms) -- verificação proporcional"
                                    + " falhou, LOW confidence -- não reportando");
                        }
                    }
                }
                return local;
            });
        }

        findings.addAll(ProbeExecutor.run(tasks, ctx.config().probeConcurrency(), cancel));

        if (findings.isEmpty()) {
            log.accept("[+] CmdInjection: nenhum command injection detectado");
        }
        return findings;
    }

    // -- Private helpers --

    private static final java.util.regex.Pattern TIME_BASED_CMD = java.util.regex.Pattern
            .compile("(?i)sleep|ping -c|timeout");

    private List<String> mergeKbPayloads(boolean timeBased) {
        LinkedHashSet<String> merged = new LinkedHashSet<>(timeBased ? SLEEP_PAYLOADS : ACTIVE_PAYLOADS);
        for (String kbp : KnowledgeBase.getInstance().filteredPayloads(id())) {
            boolean isTimeBased = TIME_BASED_CMD.matcher(kbp).find();
            if (isTimeBased == timeBased) {
                merged.add(kbp);
            }
        }
        return List.copyOf(merged);
    }

    /**
     * Returns true if {@code paramName} (lowercased) contains any NETWORK_KEYWORD.
     */
    private boolean containsAnyKeyword(String paramName) {
        String lower = paramName.toLowerCase();
        for (String kw : NETWORK_KEYWORDS) {
            if (lower.contains(kw)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Fetches the response body for a given URL, returning "" on any error. Used
     * for baseline collection and Phase 1 active probing.
     */
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

    /**
     * Measures the baseline RTT for a given path+param by taking 3 samples and
     * returning the median. Uses a safe "baseline" value so no injection occurs.
     */
    private long measureBaselineRtt(ScanContext ctx, HttpClient hc, String base, String path, String param) {
        long[] samples = new long[3];
        for (int i = 0; i < 3; i++) {
            long t0 = System.currentTimeMillis();
            fetchBody(ctx, hc, base + path + "?" + param + "=baseline" + i);
            samples[i] = System.currentTimeMillis() - t0;
        }
        Arrays.sort(samples);
        return samples[1]; // median
    }

    /**
     * Sends a single time-based probe with the given sleep payload and returns the
     * elapsed time in milliseconds. Times out at {@link #BLIND_TIMEOUT_S} seconds;
     * a timeout exception is caught and the elapsed time up to the exception is
     * returned (which will exceed the threshold).
     */
    private long measureElapsed(ScanContext ctx, HttpClient hc, String base, String path, String param,
            String sleepPayload) {
        String injected = "testvalue" + WafEvasion.evasionPayload(ctx, sleepPayload);
        try {
            String encoded = URLEncoder.encode(injected, "UTF-8");
            String url = base + path + "?" + param + "=" + encoded;
            HttpRequest req = HttpRequest.newBuilder().uri(URI.create(url)).timeout(Duration.ofSeconds(BLIND_TIMEOUT_S))
                    .GET().build();
            long t0 = System.currentTimeMillis();
            try {
                Http.send(ctx, hc, req, HttpResponse.BodyHandlers.ofString(), id());
            } catch (Exception e) {
                // Timeout or connection drop -- counts as a significant delay
                return System.currentTimeMillis() - t0;
            }
            return System.currentTimeMillis() - t0;
        } catch (Exception e) {
            return 0L;
        }
    }

    /**
     * Proportional verification for time-based blind injection.
     *
     * <p>
     * Extracts the separator prefix from the confirmed sleep payload and probes
     * with sleep 1 and sleep 3. Both deltas must fall within 30 % of their expected
     * values to confirm that the delay is proportional (i.e., genuinely caused by
     * command execution rather than a slow network or flapping server).
     *
     * @param baselineMs
     *            median baseline RTT in milliseconds
     * @param separator
     *            the payload that triggered the initial spike (e.g. "; sleep 5")
     * @return true if the proportional check passes
     */
    private boolean verifyProportionalDelay(ScanContext ctx, HttpClient hc, long baselineMs, String base, String path,
            String param, String separator) {
        String sep = extractSeparatorPrefix(separator);
        if (sep == null) {
            // Cannot extract separator -- skip proportional check, treat as unconfirmed
            return false;
        }

        try {
            // Probe sleep 1 -- expect delta ~ 1000 ms (700 - 1700 ms window, 30 %
            // tolerance)
            long d1 = measureElapsedRaw(ctx, hc, base, path, param, sep + "sleep 1");
            long delta1 = d1 - baselineMs;
            if (delta1 < 700L || delta1 > 1700L) {
                return false;
            }

            // Probe sleep 3 -- expect delta ~ 3000 ms (2100 - 3900 ms window, 30 %
            // tolerance)
            long d3 = measureElapsedRaw(ctx, hc, base, path, param, sep + "sleep 3");
            long delta3 = d3 - baselineMs;
            return delta3 >= 2100L && delta3 <= 3900L;

        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Sends a raw (not URL-encoded-from-scratch) timed probe and returns the
     * elapsed time in milliseconds. Used exclusively by
     * {@link #verifyProportionalDelay}.
     */
    private long measureElapsedRaw(ScanContext ctx, HttpClient hc, String base, String path, String param,
            String payload) throws Exception {
        String encoded = URLEncoder.encode("testvalue" + WafEvasion.evasionPayload(ctx, payload), "UTF-8");
        String url = base + path + "?" + param + "=" + encoded;
        HttpRequest req = HttpRequest.newBuilder().uri(URI.create(url)).timeout(Duration.ofSeconds(10)).GET().build();
        long t0 = System.currentTimeMillis();
        try {
            Http.send(ctx, hc, req, HttpResponse.BodyHandlers.ofString(), id());
        } catch (Exception e) {
            // Timeout counts as elapsed time
        }
        return System.currentTimeMillis() - t0;
    }

    /**
     * Extracts the command-separator prefix from a sleep payload so that the
     * proportional verification can construct "sep + sleep N" probes.
     *
     * <p>
     * Examples: "; sleep 5" -> "; " "| sleep 5" -> "| " "&& sleep 5" -> "&& "
     * "$(sleep 5)" -> null (subshell -- skip proportional test) "; ping -c 5 ..."
     * -> "; "
     */
    private String extractSeparatorPrefix(String payload) {
        if (payload.startsWith("; ")) {
            return "; ";
        }
        if (payload.startsWith("| ")) {
            return "| ";
        }
        if (payload.startsWith("&& ")) {
            return "&& ";
        }
        return null;
    }
}
