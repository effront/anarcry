package gg.effront.anarcry.scanner.web.sqli;

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
import java.util.LinkedHashSet;
import java.util.List;
import java.util.function.Consumer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class SqlInjectionModule implements Scanner {

    private static final List<String> PATHS = List.of("/search", "/api/search", "/login", "/api/users", "/api/items",
            "/api/", "/api/v1/");

    private static final List<String> PARAMS = List.of("q", "query", "id", "user", "username", "email", "search",
            "sort", "order", "filter", "page");

    // Phase 1 — error-based payloads
    private static final List<String> ERROR_PAYLOADS = List.of("'", "\"", "')", "' AND 1=1--", "' AND 1=2--");

    // Phase 2 — time-based payloads (each should induce ~5s delay on a vulnerable
    // DB)
    private record TimePayload(String payload, String dbHint) {
    }

    private static final List<TimePayload> TIME_PAYLOADS = List.of(new TimePayload("' AND SLEEP(5)--", "MySQL"),
            new TimePayload("'; SELECT pg_sleep(5)--", "PostgreSQL"),
            new TimePayload("'; WAITFOR DELAY '0:0:5'--", "MSSQL"));

    // Multi-vendor SQL error signature — requires at least one specific token to
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
        log.accept("[~] SQLi: iniciando error-based e time-based em " + base + " (" + PATHS.size() + " paths × "
                + PARAMS.size() + " params, " + errorPayloads.size() + " error payloads)");

        outer : for (int pi = 0; pi < PATHS.size(); pi++) {
            String path = PATHS.get(pi);
            log.accept("[~] SQLi: [" + (pi + 1) + "/" + PATHS.size() + "] " + path);
            for (String param : PARAMS) {

                // ─── Phase 1: Error-Based ───────────────────────────────────────
                String baselineBody = fetchBody(ctx, hc, base + path + "?" + param + "=test", log);
                // Anti-FP: skip if baseline itself already contains SQL error tokens
                if (SQL_ERROR.matcher(baselineBody).find()) {
                    log.accept("[~] SQLi: baseline já contém SQL error em " + path + " — pulando param " + param);
                    continue;
                }

                for (String payload : errorPayloads) {
                    String encoded = URLEncoder.encode(payload, "UTF-8");
                    String url = base + path + "?" + param + "=" + encoded;
                    try {
                        HttpRequest req = HttpRequest.newBuilder().uri(URI.create(url)).timeout(Duration.ofSeconds(6))
                                .GET().build();
                        HttpResponse<String> resp = Http.send(ctx, hc, req, HttpResponse.BodyHandlers.ofString(), id());
                        String body = resp.body() != null ? resp.body() : "";

                        Matcher m = SQL_ERROR.matcher(body);
                        if (m.find() && resp.statusCode() != 400) {
                            String match = m.group();
                            String endpoint = path + "?" + param + "=" + encoded;
                            log.accept("[!!] SQLi error-based CRITICAL em " + endpoint + " — match: " + match);

                            findings.add(Finding.of(id(), endpoint, "SQL Injection — Error-Based confirmado",
                                    Severity.CRITICAL,
                                    "Payload: " + payload + " | Match: " + match + " | Status: " + resp.statusCode()
                                            + " | URL: " + base + endpoint,
                                    "SQL Injection error-based expõe mensagem de erro interno do banco de dados, "
                                            + "permitindo enumeração de estrutura e extração de dados.",
                                    "curl -G '" + base + path + "' \\\n" + "  --data-urlencode '" + param + "="
                                            + payload + "'",
                                    "Use prepared statements / parameterized queries em todos os pontos de entrada. "
                                            + "Nunca concatene input do usuário em queries SQL. "
                                            + "Desabilite mensagens de erro detalhadas do banco em produção.",
                                    cweId, cweTitle, cvssVec, cvssScore));
                            break outer;
                        }
                    } catch (Exception ignored) {
                    }
                }

                // ─── Phase 2: Time-Based Blind ─────────────────────────────────
                // Measure baseline RTT using 2 samples (median of small set)
                long b1 = measureRtt(ctx, hc, base + path + "?" + param + "=1", log);
                long b2 = measureRtt(ctx, hc, base + path + "?" + param + "=2", log);
                if (b1 < 0 || b2 < 0) {
                    // Target unreachable on this path — skip to next
                    continue;
                }
                long baselineAvg = (b1 + b2) / 2;

                for (TimePayload tp : TIME_PAYLOADS) {
                    String encoded = URLEncoder.encode(tp.payload(), "UTF-8");
                    String url = base + path + "?" + param + "=" + encoded;
                    try {
                        HttpRequest req = HttpRequest.newBuilder().uri(URI.create(url))
                                // Allow up to 10s to accommodate SLEEP(5) + normal RTT
                                .timeout(Duration.ofSeconds(10)).GET().build();
                        long start = System.currentTimeMillis();
                        Http.send(ctx, hc, req, HttpResponse.BodyHandlers.ofString(), id());
                        long elapsed = System.currentTimeMillis() - start;

                        if (elapsed > baselineAvg + 4000) {
                            String endpoint = path + "?" + param + "=" + encoded;
                            log.accept("[!!] SQLi time-based CRITICAL — " + tp.dbHint() + " em " + endpoint
                                    + " baseline=" + baselineAvg + "ms attack=" + elapsed + "ms");

                            findings.add(Finding.of(id(), endpoint,
                                    "SQL Injection — Time-Based Blind confirmado (" + tp.dbHint() + ")",
                                    Severity.CRITICAL,
                                    "baseline=" + baselineAvg + "ms attack=" + elapsed + "ms" + " delta="
                                            + (elapsed - baselineAvg) + "ms" + " | DB hint: " + tp.dbHint()
                                            + " | Payload: " + tp.payload(),
                                    "Blind SQL Injection confirmado por delay de " + (elapsed - baselineAvg)
                                            + "ms acima do baseline. Permite extração de dados via inferência booleana"
                                            + " / temporal mesmo sem mensagens de erro visíveis.",
                                    "curl -G '" + base + path + "' \\\n" + "  --data-urlencode '" + param + "="
                                            + tp.payload() + "'",
                                    "Use prepared statements / parameterized queries. Implemente WAF com detecção"
                                            + " de time-based blind SQLi. Limite o timeout de queries no banco.",
                                    cweId, cweTitle, cvssVec, cvssScore));
                            break outer;
                        }
                    } catch (java.net.http.HttpTimeoutException toe) {
                        // Timeout on the attack request itself can be a positive signal only when
                        // baseline was fast — treat as a candidate but require delta > 4s.
                        long elapsed = 10_000L; // timeout = full window consumed
                        if (elapsed > baselineAvg + 4000) {
                            String endpoint = path + "?" + param + "=" + encoded;
                            log.accept("[!!] SQLi time-based (timeout) CRITICAL — " + tp.dbHint() + " em " + endpoint);
                            findings.add(Finding.of(id(), endpoint,
                                    "SQL Injection — Time-Based Blind (timeout) confirmado (" + tp.dbHint() + ")",
                                    Severity.CRITICAL,
                                    "baseline=" + baselineAvg + "ms attack=timeout(10000ms)" + " | DB hint: "
                                            + tp.dbHint() + " | Payload: " + tp.payload(),
                                    "Request timeout sob payload de sleep sugere Blind SQLi temporal.",
                                    "curl -G '" + base + path + "' \\\n" + "  --data-urlencode '" + param + "="
                                            + tp.payload() + "'",
                                    "Use prepared statements / parameterized queries.", cweId, cweTitle, cvssVec,
                                    cvssScore));
                            break outer;
                        }
                    } catch (Exception ignored) {
                    }
                }
            }
        }

        if (findings.isEmpty()) {
            log.accept("[+] SQLi: nenhuma injeção SQL detectada");
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

    /** Returns elapsed ms, or -1 on connection error (not timeout). */
    private long measureRtt(ScanContext ctx, HttpClient hc, String url, Consumer<String> log) {
        try {
            HttpRequest req = HttpRequest.newBuilder().uri(URI.create(url)).timeout(Duration.ofSeconds(6)).GET()
                    .build();
            long t0 = System.currentTimeMillis();
            Http.send(ctx, hc, req, HttpResponse.BodyHandlers.ofString(), id());
            return System.currentTimeMillis() - t0;
        } catch (java.net.http.HttpTimeoutException e) {
            return 6_000L; // count a timeout as a full-window RTT sample
        } catch (Exception e) {
            return -1L;
        }
    }
}
