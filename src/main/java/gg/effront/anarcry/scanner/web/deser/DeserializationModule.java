package gg.effront.anarcry.scanner.web.deser;

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
import java.util.Base64;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Consumer;
import java.util.regex.Pattern;

public class DeserializationModule implements Scanner {

    // -- Probe paths for general scanning --
    private static final List<String> PROBE_PATHS = List.of("/", "/api/", "/api/v1/", "/login", "/search", "/api/users",
            "/api/items");

    // -- Parameters likely to carry serialized data --
    private static final List<String> DESER_PARAMS = List.of("data", "object", "state", "token", "session", "payload",
            "viewstate", "input");

    // -- Known vulnerable framework endpoints --
    private static final List<String> FRAMEWORK_ENDPOINTS = List.of("/invoker/JMXInvokerServlet",
            "/wls-wsat/CoordinatorPortType", "/console/", "/jenkins/script", "/jenkins/",
            "/_async/AsyncResponseService");

    // -- Java deserialization error patterns --
    private static final Pattern JAVA_DESER_ERROR = Pattern
            .compile("java\\.io\\.InvalidClassException|ClassNotFoundException|java\\.io\\.StreamCorruptedException"
                    + "|ObjectInputStream|java\\.io\\.NotSerializableException|java\\.io\\.EOFException"
                    + "|cannot be cast to|ClassCastException.*deserializ", Pattern.CASE_INSENSITIVE);

    // -- PHP deserialization error patterns --
    private static final Pattern PHP_DESER_ERROR = Pattern.compile(
            "unserialize\\(\\)|__wakeup|__destruct|__toString.*error|" + "allowed classes|O:\\d+:\"[^\"]+\":\\d+:\\{",
            Pattern.CASE_INSENSITIVE);

    // -- Python pickle error patterns --
    private static final Pattern PYTHON_PICKLE_ERROR = Pattern.compile(
            "pickle\\.UnpicklingError|_pickle\\.UnpicklingError|"
                    + "ImportError.*No module|ModuleNotFoundError|unpickling stack underflow",
            Pattern.CASE_INSENSITIVE);

    // -- .NET deserialization error patterns --
    private static final Pattern DOTNET_DESER_ERROR = Pattern
            .compile("BinaryFormatter|ObjectStateFormatter|LosFormatter|"
                    + "System\\.Runtime\\.Serialization|TypeInitializationException.*Serializ|"
                    + "ViewState MAC validation", Pattern.CASE_INSENSITIVE);

    // -- ViewState parameters (ASP.NET deserialization) --
    private static final Pattern VIEWSTATE_PARAM = Pattern.compile("__VIEWSTATE|__EVENTVALIDATION|__VIEWSTATEGENERATOR",
            Pattern.CASE_INSENSITIVE);

    // -- Base64 Java serialized object magic: 0xACED0005 -> rO0AB --
    private static final String JAVA_SERIAL_B64_PREFIX = "rO0AB";

    // -- Framework fingerprint headers --
    private static final Pattern VULN_FRAMEWORK_HEADER = Pattern.compile(
            "Apache-Coyote|JBoss|WebLogic|WildFly|GlassFish|Jenkins|" + "Struts|Oracle.*Application Server",
            Pattern.CASE_INSENSITIVE);

    // -- Malformed Java serialized payload (triggers error on deser endpoints) --
    // This is a truncated Java serialized stream header (magic + version only)
    private static final byte[] MALFORMED_JAVA_BYTES = new byte[]{(byte) 0xAC, (byte) 0xED, 0x00, 0x05, 0x73, 0x72,
            0x00, 0x01, 0x41};

    private static final String MALFORMED_JAVA_B64 = Base64.getEncoder().encodeToString(MALFORMED_JAVA_BYTES);

    // -- Malformed PHP serialized payload --
    private static final String MALFORMED_PHP = "O:1:\"a\":0:{}";

    // -- Malformed Python pickle payload (protocol 4 header, truncated) --
    private static final byte[] MALFORMED_PICKLE_BYTES = new byte[]{(byte) 0x80, 0x04, (byte) 0x95, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00};

    private static final String MALFORMED_PICKLE_B64 = Base64.getEncoder().encodeToString(MALFORMED_PICKLE_BYTES);

    @Override
    public String id() {
        return "Deserialization";
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

        log.accept("[~] " + id() + ": iniciando deteccao de desserializacao insegura em " + base);

        AtomicBoolean cancel = new AtomicBoolean(false);
        List<Callable<List<Finding>>> tasks = new ArrayList<>();

        // -- Phase 1: Framework fingerprinting (known vulnerable endpoints) --
        tasks.add(() -> {
            List<Finding> local = new ArrayList<>();
            log.accept("[~] " + id() + ": Phase 1 -- verificando endpoints de framework vulneraveis");
            for (String endpoint : FRAMEWORK_ENDPOINTS) {
                if (cancel.get()) {
                    return local;
                }
                try {
                    String url = base + endpoint;
                    HttpRequest req = HttpRequest.newBuilder().uri(URI.create(url)).timeout(Duration.ofSeconds(6)).GET()
                            .build();
                    HttpResponse<String> resp = Http.send(ctx, hc, req, HttpResponse.BodyHandlers.ofString(), id());
                    int status = resp.statusCode();
                    String body = resp.body() != null ? resp.body() : "";

                    // A 200 or 500 (not 404) on these paths is significant
                    if (status != 404 && status != 0) {
                        String serverHdr = resp.headers().firstValue("Server").orElse("");
                        String contentType = resp.headers().firstValue("Content-Type").orElse("");

                        if (status == 200 || status == 500
                                || contentType.contains("application/x-java-serialized-object")
                                || JAVA_DESER_ERROR.matcher(body).find()) {
                            log.accept("[!!] " + id() + ": endpoint de framework acessivel -- " + endpoint + " (HTTP "
                                    + status + ")");
                            local.add(Finding.of(id(), endpoint,
                                    "Deserialization -- Endpoint de framework vulneravel acessivel", Severity.CRITICAL,
                                    "Endpoint: " + url + " | HTTP " + status + " | Server: " + serverHdr
                                            + " | Content-Type: " + contentType,
                                    "Endpoint de framework com desserializacao nativa exposto. "
                                            + "Endpoints como JMXInvokerServlet (JBoss), "
                                            + "CoordinatorPortType (WebLogic), e /jenkins/script "
                                            + "permitem RCE via gadget chains em classes do classpath.",
                                    "curl -v '" + url + "'",
                                    "Remover ou restringir acesso a endpoints de gerenciamento. "
                                            + "Usar allowlist de IP para consoles administrativos. "
                                            + "Atualizar frameworks para versoes com desserializacao segura.",
                                    cweId, cweTitle, cvssVec, cvssScore));
                        }
                    }
                } catch (CircuitBreakerException cbe) {
                    throw cbe;
                } catch (Exception ignored) {
                }
            }
            return local;
        });

        // -- Phase 2: Response analysis + ViewState detection --
        tasks.add(() -> {
            List<Finding> local = new ArrayList<>();
            log.accept("[~] " + id() + ": Phase 2 -- analise de respostas e ViewState");

            // Check base URL response for framework headers and serialized content
            try {
                HttpRequest req = HttpRequest.newBuilder().uri(URI.create(base + "/")).timeout(Duration.ofSeconds(6))
                        .GET().build();
                HttpResponse<String> resp = Http.send(ctx, hc, req, HttpResponse.BodyHandlers.ofString(), id());
                String body = resp.body() != null ? resp.body() : "";

                // Check X-Powered-By / Server headers for vulnerable frameworks
                String poweredBy = resp.headers().firstValue("X-Powered-By").orElse("");
                String server = resp.headers().firstValue("Server").orElse("");
                String combined = poweredBy + " " + server;
                if (VULN_FRAMEWORK_HEADER.matcher(combined).find()) {
                    log.accept("[~] " + id() + ": framework com desserializacao conhecida detectado -- "
                            + combined.trim());
                }

                // Check for ViewState in response body
                if (VIEWSTATE_PARAM.matcher(body).find()) {
                    log.accept("[!!] " + id() + ": ViewState detectado em " + base + "/");
                    // Verify if ViewState has MAC validation
                    boolean macEnabled = body.contains("__VIEWSTATEGENERATOR") || body.contains("__VIEWSTATEENCRYPTED");
                    Severity sev = macEnabled ? Severity.MEDIUM : Severity.HIGH;
                    String macNote = macEnabled
                            ? "ViewState com MAC/encryption detectado -- exploitacao requer key leak"
                            : "ViewState sem indicacao de MAC -- potencialmente exploravel";
                    local.add(Finding.of(id(), "/", "Deserialization -- ASP.NET ViewState detectado", sev,
                            "ViewState encontrado no HTML | " + macNote + " | URL: " + base + "/",
                            "ASP.NET ViewState usa BinaryFormatter/ObjectStateFormatter "
                                    + "para serializar estado do lado do servidor. Sem MAC ou com key "
                                    + "vazada (machineKey), permite RCE via ysoserial.net.",
                            "curl -s '" + base + "/' | grep -i '__VIEWSTATE'",
                            "Habilitar ViewState MAC validation (enableViewStateMac=true). "
                                    + "Usar ViewState encryption. Nunca expor machineKey "
                                    + "em web.config ou error pages.",
                            cweId, cweTitle, cvssVec, cvssScore));
                }

                // Check Content-Type for Java serialized objects
                String ct = resp.headers().firstValue("Content-Type").orElse("");
                if (ct.contains("application/x-java-serialized-object")) {
                    log.accept("[!!] " + id() + ": Content-Type java-serialized-object em " + base + "/");
                    local.add(Finding.of(id(), "/", "Deserialization -- Java serialized object no Content-Type",
                            Severity.CRITICAL, "Content-Type: " + ct + " | URL: " + base + "/",
                            "Servidor retorna objetos Java serializados via HTTP. "
                                    + "Clientes que desserializam a resposta estao vulneraveis "
                                    + "a gadget chain attacks (ysoserial).",
                            "curl -v '" + base + "/'",
                            "Migrar para formatos seguros (JSON, Protocol Buffers). "
                                    + "Nunca usar ObjectInputStream em dados de rede sem filtro de tipos.",
                            cweId, cweTitle, cvssVec, cvssScore));
                }
            } catch (CircuitBreakerException cbe) {
                throw cbe;
            } catch (Exception ignored) {
            }
            return local;
        });

        // -- Phase 3: Parameter injection with malformed serialized payloads --
        List<String> probePaths = mergeWithDiscoveredPaths(ctx);
        for (int pi = 0; pi < probePaths.size(); pi++) {
            final String path = probePaths.get(pi);
            final int pathIdx = pi;
            tasks.add(() -> {
                List<Finding> local = new ArrayList<>();
                if (cancel.get()) {
                    return local;
                }
                log.accept("[~] " + id() + ": Phase 3 [" + (pathIdx + 1) + "/" + probePaths.size() + "] " + path);

                for (String param : DESER_PARAMS) {
                    if (cancel.get()) {
                        return local;
                    }

                    // Baseline: normal value
                    String baselineBody = fetchBody(ctx, hc, base + path + "?" + param + "=test", log);

                    // Skip if baseline already contains deser error tokens (anti-FP)
                    if (JAVA_DESER_ERROR.matcher(baselineBody).find() || PHP_DESER_ERROR.matcher(baselineBody).find()
                            || PYTHON_PICKLE_ERROR.matcher(baselineBody).find()) {
                        log.accept("[~] " + id() + ": baseline contem erro de desserializacao em " + path
                                + " -- pulando param " + param);
                        continue;
                    }

                    // -- Java: inject malformed serialized object (Base64) --
                    Finding javaFinding = probeJavaDeser(ctx, hc, base, path, param, baselineBody, log, cweId, cweTitle,
                            cvssVec, cvssScore);
                    if (javaFinding != null) {
                        local.add(javaFinding);
                        cancel.set(true);
                        return local;
                    }

                    // -- PHP: inject malformed serialized object --
                    Finding phpFinding = probePhpDeser(ctx, hc, base, path, param, baselineBody, log, cweId, cweTitle,
                            cvssVec, cvssScore);
                    if (phpFinding != null) {
                        local.add(phpFinding);
                        cancel.set(true);
                        return local;
                    }

                    // -- Python pickle: inject malformed pickle --
                    Finding pickleFinding = probePickleDeser(ctx, hc, base, path, param, baselineBody, log, cweId,
                            cweTitle, cvssVec, cvssScore);
                    if (pickleFinding != null) {
                        local.add(pickleFinding);
                        cancel.set(true);
                        return local;
                    }
                }
                return local;
            });
        }

        // -- Phase 4: Check crawled endpoints for serialized data markers --
        tasks.add(() -> {
            List<Finding> local = new ArrayList<>();
            if (cancel.get()) {
                return local;
            }
            log.accept("[~] " + id() + ": Phase 4 -- verificando dados serializados em cookies e params");

            for (String crawledPath : ctx.discoveredPaths().paths()) {
                if (cancel.get()) {
                    return local;
                }
                try {
                    String url = base + crawledPath;
                    HttpRequest req = HttpRequest.newBuilder().uri(URI.create(url)).timeout(Duration.ofSeconds(6)).GET()
                            .build();
                    HttpResponse<String> resp = Http.send(ctx, hc, req, HttpResponse.BodyHandlers.ofString(), id());

                    // Check Set-Cookie headers for serialized data
                    List<String> cookies = resp.headers().allValues("Set-Cookie");
                    for (String cookie : cookies) {
                        String cookieValue = extractCookieValue(cookie);
                        if (looksLikeSerializedJava(cookieValue)) {
                            log.accept("[!!] " + id() + ": cookie contendo objeto Java serializado em " + crawledPath);
                            local.add(Finding.of(id(), crawledPath,
                                    "Deserialization -- Cookie com objeto Java serializado", Severity.HIGH,
                                    "Cookie: " + cookie.substring(0, Math.min(cookie.length(), 80)) + "... | Path: "
                                            + crawledPath,
                                    "Cookie contem dados serializados em Java (prefixo rO0AB). "
                                            + "Se o servidor desserializa o cookie, atacantes podem "
                                            + "injetar gadget chains para RCE.",
                                    "curl -v '" + url + "' | grep -i 'Set-Cookie'",
                                    "Nunca armazenar objetos Java serializados em cookies. "
                                            + "Usar JSON com HMAC para integridade de sessao. "
                                            + "Implementar filtro de tipos em ObjectInputStream.",
                                    cweId, cweTitle, cvssVec, cvssScore));
                            cancel.set(true);
                            return local;
                        }
                        if (looksLikeSerializedPhp(cookieValue)) {
                            log.accept("[!!] " + id() + ": cookie contendo dados PHP serializados em " + crawledPath);
                            local.add(Finding.of(id(), crawledPath,
                                    "Deserialization -- Cookie com dados PHP serializados", Severity.HIGH,
                                    "Cookie: " + cookie.substring(0, Math.min(cookie.length(), 80)) + "... | Path: "
                                            + crawledPath,
                                    "Cookie contem dados serializados em PHP (prefixo O: ou a:). "
                                            + "Se o servidor usa unserialize() no cookie, atacantes "
                                            + "podem explorar __wakeup/__destruct gadgets para RCE.",
                                    "curl -v '" + url + "' | grep -i 'Set-Cookie'",
                                    "Nunca usar serialize/unserialize em dados de cookie. "
                                            + "Usar JSON com assinatura HMAC. "
                                            + "Se necessario, usar allowed_classes em unserialize().",
                                    cweId, cweTitle, cvssVec, cvssScore));
                            cancel.set(true);
                            return local;
                        }
                    }
                } catch (CircuitBreakerException cbe) {
                    throw cbe;
                } catch (Exception ignored) {
                }
            }
            return local;
        });

        findings.addAll(ProbeExecutor.run(tasks, ctx.config().probeConcurrency(), cancel));

        if (findings.isEmpty()) {
            log.accept("[+] " + id() + ": nenhuma vulnerabilidade de desserializacao detectada");
        }
        return findings;
    }

    // -- Probe helpers --

    private Finding probeJavaDeser(ScanContext ctx, HttpClient hc, String base, String path, String param,
            String baseline, Consumer<String> log, String cweId, String cweTitle, String cvssVec, double cvssScore) {
        try {
            String encoded = URLEncoder.encode(MALFORMED_JAVA_B64, "UTF-8");
            String url = base + path + "?" + param + "=" + encoded;
            HttpRequest req = HttpRequest.newBuilder().uri(URI.create(url)).timeout(Duration.ofSeconds(6)).GET()
                    .build();
            HttpResponse<String> resp = Http.send(ctx, hc, req, HttpResponse.BodyHandlers.ofString(), id());
            String body = resp.body() != null ? resp.body() : "";

            if (JAVA_DESER_ERROR.matcher(body).find() && !JAVA_DESER_ERROR.matcher(baseline).find()) {
                String endpoint = path + "?" + param + "=" + encoded;
                log.accept("[!!] " + id() + ": Java deserialization error em " + endpoint);
                return Finding.of(id(), endpoint, "Deserialization -- Java ObjectInputStream detectado",
                        Severity.CRITICAL,
                        "Payload: malformed Java serialized object (Base64) | Erro de "
                                + "desserializacao na resposta | URL: " + base + endpoint,
                        "Servidor tenta desserializar input via ObjectInputStream. "
                                + "Atacante pode usar ysoserial para gerar gadget chains "
                                + "(CommonsCollections, Spring, JNDI) para RCE.",
                        "echo '" + MALFORMED_JAVA_B64 + "' | base64 -d > payload.bin\n" + "curl -G '" + base + path
                                + "' \\\n" + "  --data-urlencode '" + param + "=" + MALFORMED_JAVA_B64 + "'",
                        "Nunca usar ObjectInputStream em dados de usuario. "
                                + "Implementar ValidatingObjectInputStream com allowlist de classes. "
                                + "Migrar para JSON/Protocol Buffers.",
                        cweId, cweTitle, cvssVec, cvssScore);
            }
        } catch (CircuitBreakerException cbe) {
            throw cbe;
        } catch (Exception ignored) {
        }
        return null;
    }

    private Finding probePhpDeser(ScanContext ctx, HttpClient hc, String base, String path, String param,
            String baseline, Consumer<String> log, String cweId, String cweTitle, String cvssVec, double cvssScore) {
        try {
            String encoded = URLEncoder.encode(MALFORMED_PHP, "UTF-8");
            String url = base + path + "?" + param + "=" + encoded;
            HttpRequest req = HttpRequest.newBuilder().uri(URI.create(url)).timeout(Duration.ofSeconds(6)).GET()
                    .build();
            HttpResponse<String> resp = Http.send(ctx, hc, req, HttpResponse.BodyHandlers.ofString(), id());
            String body = resp.body() != null ? resp.body() : "";

            if (PHP_DESER_ERROR.matcher(body).find() && !PHP_DESER_ERROR.matcher(baseline).find()) {
                String endpoint = path + "?" + param + "=" + encoded;
                log.accept("[!!] " + id() + ": PHP deserialization error em " + endpoint);
                return Finding.of(id(), endpoint, "Deserialization -- PHP unserialize() detectado", Severity.CRITICAL,
                        "Payload: " + MALFORMED_PHP + " | Erro de unserialize() na resposta" + " | URL: " + base
                                + endpoint,
                        "Servidor processa input via unserialize(). "
                                + "Atacante pode criar POP chains usando classes do framework "
                                + "(Monolog, Guzzle, Laravel) para execucao de codigo arbitrario.",
                        "curl -G '" + base + path + "' \\\n" + "  --data-urlencode '" + param + "=" + MALFORMED_PHP
                                + "'",
                        "Nunca usar unserialize() em dados de usuario. "
                                + "Usar json_decode() para dados estruturados. "
                                + "Se necessario, usar allowed_classes parameter.",
                        cweId, cweTitle, cvssVec, cvssScore);
            }
        } catch (CircuitBreakerException cbe) {
            throw cbe;
        } catch (Exception ignored) {
        }
        return null;
    }

    private Finding probePickleDeser(ScanContext ctx, HttpClient hc, String base, String path, String param,
            String baseline, Consumer<String> log, String cweId, String cweTitle, String cvssVec, double cvssScore) {
        try {
            String encoded = URLEncoder.encode(MALFORMED_PICKLE_B64, "UTF-8");
            String url = base + path + "?" + param + "=" + encoded;
            HttpRequest req = HttpRequest.newBuilder().uri(URI.create(url)).timeout(Duration.ofSeconds(6)).GET()
                    .build();
            HttpResponse<String> resp = Http.send(ctx, hc, req, HttpResponse.BodyHandlers.ofString(), id());
            String body = resp.body() != null ? resp.body() : "";

            if (PYTHON_PICKLE_ERROR.matcher(body).find() && !PYTHON_PICKLE_ERROR.matcher(baseline).find()) {
                String endpoint = path + "?" + param + "=" + encoded;
                log.accept("[!!] " + id() + ": Python pickle error em " + endpoint);
                return Finding.of(id(), endpoint, "Deserialization -- Python pickle.loads() detectado",
                        Severity.CRITICAL,
                        "Payload: malformed pickle (Base64) | Erro de unpickling na resposta" + " | URL: " + base
                                + endpoint,
                        "Servidor processa input via pickle.loads(). "
                                + "pickle.loads() executa codigo arbitrario durante "
                                + "desserializacao via __reduce__. Nao existe uso seguro de "
                                + "pickle com dados nao confiaveis.",
                        "echo '" + MALFORMED_PICKLE_B64 + "' | base64 -d > payload.pkl\n" + "curl -G '" + base + path
                                + "' \\\n" + "  --data-urlencode '" + param + "=" + MALFORMED_PICKLE_B64 + "'",
                        "Nunca usar pickle.loads() em dados de usuario. " + "Migrar para JSON ou MessagePack. "
                                + "Se necessario, usar hmac para validar integridade antes de carregar.",
                        cweId, cweTitle, cvssVec, cvssScore);
            }
        } catch (CircuitBreakerException cbe) {
            throw cbe;
        } catch (Exception ignored) {
        }
        return null;
    }

    // -- Utility methods --

    private List<String> mergeWithDiscoveredPaths(ScanContext ctx) {
        List<String> merged = new ArrayList<>(PROBE_PATHS);
        for (String discovered : ctx.discoveredPaths().paths()) {
            if (!merged.contains(discovered)) {
                merged.add(discovered);
            }
        }
        return merged;
    }

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

    private static boolean looksLikeSerializedJava(String value) {
        if (value == null || value.length() < 8) {
            return false;
        }
        // Check for Base64-encoded Java serialized object (rO0AB prefix)
        return value.startsWith(JAVA_SERIAL_B64_PREFIX);
    }

    private static boolean looksLikeSerializedPhp(String value) {
        if (value == null || value.length() < 4) {
            return false;
        }
        // PHP serialized object: O:<num>:"<class>":<num>:{...}
        // PHP serialized array: a:<num>:{...}
        return (value.startsWith("O:") || value.startsWith("a:")) && value.contains(":{");
    }

    private static String extractCookieValue(String setCookieHeader) {
        if (setCookieHeader == null || setCookieHeader.isEmpty()) {
            return "";
        }
        // Extract value before first semicolon, after first equals
        int eq = setCookieHeader.indexOf('=');
        if (eq < 0) {
            return "";
        }
        String afterEq = setCookieHeader.substring(eq + 1);
        int semi = afterEq.indexOf(';');
        return semi >= 0 ? afterEq.substring(0, semi).trim() : afterEq.trim();
    }
}
