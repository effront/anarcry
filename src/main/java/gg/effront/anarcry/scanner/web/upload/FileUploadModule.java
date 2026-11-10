package gg.effront.anarcry.scanner.web.upload;

import gg.effront.anarcry.model.CvssCalculator;
import gg.effront.anarcry.model.CweRegistry;
import gg.effront.anarcry.model.Finding;
import gg.effront.anarcry.model.Severity;
import gg.effront.anarcry.scanner.ScanContext;
import gg.effront.anarcry.scanner.Scanner;
import gg.effront.anarcry.scanner.util.CircuitBreakerException;
import gg.effront.anarcry.scanner.util.Http;
import gg.effront.anarcry.scanner.util.HttpClientFactory;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.function.Consumer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * FileUploadModule -- detects unrestricted file upload vulnerabilities
 * (CWE-434).
 *
 * <p>
 * Detection phases:
 * <ol>
 * <li>Discover upload endpoints via crawled paths and common upload paths.</li>
 * <li>Extension bypass tests (double extension, null byte, case variation,
 * alternative extensions, dot trick).</li>
 * <li>Content-type spoofing (script content with image MIME types).</li>
 * <li>Magic byte manipulation (GIF89a, PNG, JPEG headers prepended to
 * script).</li>
 * <li>Upload verification -- check if uploaded file is accessible and
 * executable.</li>
 * </ol>
 *
 * <p>
 * This module is DISABLED by default because it sends actual files to the
 * target.
 *
 * <p>
 * Anti-FP: every upload response is checked for concrete evidence of acceptance
 * before reporting. Code execution is only flagged when the test marker string
 * appears in the response from fetching the uploaded file.
 */
public class FileUploadModule implements Scanner {

    // -------------------------------------------------------------------------
    // Constants
    // -------------------------------------------------------------------------

    private static final String MARKER = "ANARCRY_UPLOAD_TEST";
    private static final String PHP_PAYLOAD = "<?php echo \"" + MARKER + "\"; ?>";
    private static final String JSP_PAYLOAD = "<%= new String(new char[]{'" + String.join("','", MARKER.split(""))
            + "'}) %>";
    private static final String SAFE_PAYLOAD = PHP_PAYLOAD;

    /** GIF89a magic bytes. */
    private static final String GIF_MAGIC = "GIF89a";

    /** PNG magic bytes as a string (binary). */
    private static final String PNG_MAGIC = "\u0089PNG\r\n\u001a\n";

    /** JPEG magic bytes as a string (binary). */
    private static final String JPEG_MAGIC = "\u00FF\u00D8\u00FF\u00E0";

    private static final List<String> COMMON_UPLOAD_PATHS = List.of("/upload", "/api/upload", "/files", "/attachments",
            "/media", "/images", "/api/files", "/api/attachments", "/api/images", "/api/media", "/avatar",
            "/api/avatar");

    private static final List<String> FORM_FIELD_NAMES = List.of("file", "upload", "attachment", "image", "document",
            "avatar", "media", "data");

    /** Pattern to detect a URL or path in an upload response body. */
    private static final Pattern URL_PATTERN = Pattern.compile(
            "(?:\"(?:url|path|location|file|link|src|href)\"\\s*:\\s*\"([^\"]+)\")"
                    + "|(?:(?:url|path|location|file|link|src|href)\\s*[:=]\\s*([^\\s,;\"'<>]+))",
            Pattern.CASE_INSENSITIVE);

    /** Pattern for forms with file upload capability. */
    private static final Pattern UPLOAD_FORM_PATTERN = Pattern.compile(
            "(?:enctype\\s*=\\s*[\"']multipart/form-data[\"'])" + "|(?:<input[^>]+type\\s*=\\s*[\"']file[\"'])",
            Pattern.CASE_INSENSITIVE);

    // -------------------------------------------------------------------------
    // Extension bypass payloads
    // -------------------------------------------------------------------------

    private record UploadProbe(String filename, String contentType, String content, String label) {
    }

    private static List<UploadProbe> extensionBypassProbes() {
        List<UploadProbe> probes = new ArrayList<>();

        // Double extensions
        probes.add(new UploadProbe("test.php.jpg", "image/jpeg", SAFE_PAYLOAD, "double ext php.jpg"));
        probes.add(new UploadProbe("test.jsp.png", "image/png", SAFE_PAYLOAD, "double ext jsp.png"));
        probes.add(new UploadProbe("test.aspx.gif", "image/gif", SAFE_PAYLOAD, "double ext aspx.gif"));

        // Null byte (URL-encoded)
        probes.add(new UploadProbe("test.php%00.jpg", "image/jpeg", SAFE_PAYLOAD, "null byte php%00.jpg"));

        // Case variations
        probes.add(new UploadProbe("test.PhP", "application/octet-stream", SAFE_PAYLOAD, "case PhP"));
        probes.add(new UploadProbe("test.pHp", "application/octet-stream", SAFE_PAYLOAD, "case pHp"));
        probes.add(new UploadProbe("test.PHP", "application/octet-stream", SAFE_PAYLOAD, "case PHP"));

        // Alternative extensions
        for (String ext : List.of(".phtml", ".php5", ".php7", ".shtml", ".asa", ".cer")) {
            probes.add(new UploadProbe("test" + ext, "application/octet-stream", SAFE_PAYLOAD, ext));
        }

        // Dot trick
        probes.add(new UploadProbe("test.php.", "application/octet-stream", SAFE_PAYLOAD, "dot php."));
        probes.add(new UploadProbe("test.php...", "application/octet-stream", SAFE_PAYLOAD, "dot php..."));

        return probes;
    }

    private static List<UploadProbe> contentTypeSpoofProbes() {
        List<UploadProbe> probes = new ArrayList<>();
        probes.add(new UploadProbe("test.php", "image/jpeg", SAFE_PAYLOAD, "content-type spoof image/jpeg"));
        probes.add(new UploadProbe("test.php", "image/png", SAFE_PAYLOAD, "content-type spoof image/png"));
        probes.add(new UploadProbe("test.php", "image/gif", SAFE_PAYLOAD, "content-type spoof image/gif"));
        return probes;
    }

    private static List<UploadProbe> magicByteProbes() {
        List<UploadProbe> probes = new ArrayList<>();
        probes.add(new UploadProbe("test.php", "image/gif", GIF_MAGIC + SAFE_PAYLOAD, "magic GIF89a + PHP"));
        probes.add(new UploadProbe("test.php", "image/png", PNG_MAGIC + SAFE_PAYLOAD, "magic PNG header + PHP"));
        probes.add(new UploadProbe("test.php", "image/jpeg", JPEG_MAGIC + SAFE_PAYLOAD, "magic JPEG header + PHP"));
        return probes;
    }

    // -------------------------------------------------------------------------
    // Scanner contract
    // -------------------------------------------------------------------------

    @Override
    public String id() {
        return "FileUpload";
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

        log.accept("[~] FileUpload: iniciando scan em " + base);

        // Phase 1: Discover upload endpoints
        Set<String> uploadEndpoints = discoverUploadEndpoints(ctx, hc, base, log);

        if (uploadEndpoints.isEmpty()) {
            log.accept("[+] FileUpload: nenhum endpoint de upload detectado");
            return findings;
        }

        log.accept("[~] FileUpload: " + uploadEndpoints.size() + " endpoint(s) de upload encontrado(s)");

        // Phase 2-4: Test each endpoint
        for (String endpoint : uploadEndpoints) {
            String uploadUrl = base + endpoint;

            // Phase 2: Extension bypass
            log.accept("[~] FileUpload: testando extension bypass em " + endpoint);
            for (UploadProbe probe : extensionBypassProbes()) {
                Finding f = testUpload(ctx, hc, base, uploadUrl, endpoint, probe, cweId, cweTitle, cvssVec, score, log);
                if (f != null) {
                    findings.add(f);
                    // One finding per endpoint per phase is enough
                    break;
                }
            }

            // Phase 3: Content-type spoofing
            log.accept("[~] FileUpload: testando content-type spoofing em " + endpoint);
            for (UploadProbe probe : contentTypeSpoofProbes()) {
                Finding f = testUpload(ctx, hc, base, uploadUrl, endpoint, probe, cweId, cweTitle, cvssVec, score, log);
                if (f != null) {
                    findings.add(f);
                    break;
                }
            }

            // Phase 4: Magic byte manipulation
            log.accept("[~] FileUpload: testando magic byte manipulation em " + endpoint);
            for (UploadProbe probe : magicByteProbes()) {
                Finding f = testUpload(ctx, hc, base, uploadUrl, endpoint, probe, cweId, cweTitle, cvssVec, score, log);
                if (f != null) {
                    findings.add(f);
                    break;
                }
            }
        }

        if (findings.isEmpty()) {
            log.accept("[+] FileUpload: nenhuma vulnerabilidade de upload detectada");
        }
        return findings;
    }

    // -------------------------------------------------------------------------
    // Phase 1: Endpoint discovery
    // -------------------------------------------------------------------------

    private Set<String> discoverUploadEndpoints(ScanContext ctx, HttpClient hc, String base, Consumer<String> log) {
        Set<String> endpoints = new LinkedHashSet<>();

        // Check crawled paths for forms with file upload
        for (String path : ctx.discoveredPaths().paths()) {
            try {
                HttpRequest req = HttpRequest.newBuilder().uri(URI.create(base + path)).timeout(Duration.ofSeconds(6))
                        .GET().build();
                HttpResponse<String> resp = Http.send(ctx, hc, req, HttpResponse.BodyHandlers.ofString(), id());
                String body = resp.body() != null ? resp.body() : "";

                if (UPLOAD_FORM_PATTERN.matcher(body).find()) {
                    endpoints.add(path);
                    log.accept("[~] FileUpload: form com upload encontrado em " + path);
                }
            } catch (CircuitBreakerException cbe) {
                throw cbe;
            } catch (Exception ignored) {
                // Connection errors are not findings
            }
        }

        // Probe common upload paths
        for (String path : COMMON_UPLOAD_PATHS) {
            try {
                HttpRequest req = HttpRequest.newBuilder().uri(URI.create(base + path)).timeout(Duration.ofSeconds(6))
                        .GET().build();
                HttpResponse<String> resp = Http.send(ctx, hc, req, HttpResponse.BodyHandlers.ofString(), id());

                // Accept endpoints that return 200, 301, 302, 401, 403, 405 (exists but may
                // require auth or different method)
                int status = resp.statusCode();
                if (status == 200 || status == 301 || status == 302 || status == 401 || status == 403
                        || status == 405) {
                    endpoints.add(path);
                    log.accept("[~] FileUpload: endpoint ativo em " + path + " (HTTP " + status + ")");
                }
            } catch (CircuitBreakerException cbe) {
                throw cbe;
            } catch (Exception ignored) {
                // Connection errors are not findings
            }
        }

        return endpoints;
    }

    // -------------------------------------------------------------------------
    // Upload testing
    // -------------------------------------------------------------------------

    private Finding testUpload(ScanContext ctx, HttpClient hc, String base, String uploadUrl, String endpoint,
            UploadProbe probe, String cweId, String cweTitle, String cvssVec, double score, Consumer<String> log) {

        for (String fieldName : FORM_FIELD_NAMES) {
            try {
                String boundary = "----AnarCryBoundary" + System.currentTimeMillis();
                String body = buildMultipartBody(boundary, fieldName, probe.filename(), probe.contentType(),
                        probe.content());

                HttpRequest req = HttpRequest.newBuilder().uri(URI.create(uploadUrl))
                        .header("Content-Type", "multipart/form-data; boundary=" + boundary)
                        .timeout(Duration.ofSeconds(8)).POST(HttpRequest.BodyPublishers.ofString(body)).build();

                HttpResponse<String> resp = Http.send(ctx, hc, req, HttpResponse.BodyHandlers.ofString(), id());
                String respBody = resp.body() != null ? resp.body() : "";

                // Skip 404/400 responses -- endpoint did not accept upload with this field
                if (resp.statusCode() == 404 || resp.statusCode() == 400) {
                    continue;
                }

                // Check for code execution in the upload response itself
                if (respBody.contains(MARKER) && !respBody.contains("<?php")) {
                    log.accept("[!!!] FileUpload: EXECUCAO DE CODIGO REMOTO via " + probe.label() + " em " + endpoint
                            + " (campo: " + fieldName + ")");

                    String rceVec = "AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H";
                    double rceScore = CvssCalculator.calculate(rceVec);

                    return Finding.of(id(), endpoint, "File Upload RCE -- execucao de codigo via " + probe.label(),
                            Severity.CRITICAL,
                            "Upload de " + probe.filename() + " com Content-Type: " + probe.contentType()
                                    + " resultou em execucao de codigo no servidor. " + "Marker '" + MARKER
                                    + "' detectado na resposta.",
                            "Execucao remota de codigo (RCE) confirmada via upload de arquivo. "
                                    + "Atacante pode executar comandos arbitrarios no servidor, "
                                    + "comprometendo completamente o sistema.",
                            buildCurlCommand(uploadUrl, fieldName, probe),
                            "Validar tipos de arquivo server-side com allowlist de extensoes. "
                                    + "Renomear uploads para nomes aleatorios. "
                                    + "Armazenar uploads fora do web root. "
                                    + "Desabilitar execucao de scripts no diretorio de uploads.",
                            cweId, cweTitle, rceVec, rceScore);
                }

                // Check if response contains a path to the uploaded file
                if (resp.statusCode() >= 200 && resp.statusCode() < 300) {
                    String uploadedPath = extractUploadedPath(respBody);
                    if (uploadedPath != null) {
                        // Phase 5: Verify if the uploaded file is accessible
                        Finding verifyResult = verifyUploadedFile(ctx, hc, base, uploadUrl, endpoint, uploadedPath,
                                probe, cweId, cweTitle, cvssVec, score, fieldName, log);
                        if (verifyResult != null) {
                            return verifyResult;
                        }
                    }

                    // Upload was accepted (2xx) even with a dangerous extension/content
                    if (resp.statusCode() == 200 || resp.statusCode() == 201) {
                        log.accept("[+] FileUpload: upload aceito via " + probe.label() + " em " + endpoint
                                + " (campo: " + fieldName + ", HTTP " + resp.statusCode() + ")");

                        return Finding.of(id(), endpoint, "Unrestricted File Upload -- bypass via " + probe.label(),
                                Severity.HIGH,
                                "Upload de " + probe.filename() + " com Content-Type: " + probe.contentType()
                                        + " aceito pelo servidor (HTTP " + resp.statusCode() + "). Resposta: "
                                        + truncate(respBody, 200),
                                "Servidor aceita upload de arquivos com extensoes perigosas. "
                                        + "Dependendo da configuracao do servidor, isso pode levar a "
                                        + "execucao remota de codigo (RCE) ao acessar o arquivo enviado.",
                                buildCurlCommand(uploadUrl, fieldName, probe),
                                "Validar tipos de arquivo server-side com allowlist de extensoes. "
                                        + "Renomear uploads para nomes aleatorios com extensao fixa. "
                                        + "Armazenar uploads fora do web root ou servir via handler "
                                        + "que previne execucao. "
                                        + "Usar Content-Disposition: attachment nos downloads.",
                                cweId, cweTitle, cvssVec, score);
                    }
                }
            } catch (CircuitBreakerException cbe) {
                throw cbe;
            } catch (Exception ignored) {
                // Connection errors are not findings
            }
        }
        return null;
    }

    // -------------------------------------------------------------------------
    // Phase 5: Verify uploaded file
    // -------------------------------------------------------------------------

    private Finding verifyUploadedFile(ScanContext ctx, HttpClient hc, String base, String uploadUrl, String endpoint,
            String uploadedPath, UploadProbe probe, String cweId, String cweTitle, String cvssVec, double score,
            String fieldName, Consumer<String> log) {

        String fileUrl;
        if (uploadedPath.startsWith("http://") || uploadedPath.startsWith("https://")) {
            fileUrl = uploadedPath;
        } else if (uploadedPath.startsWith("/")) {
            fileUrl = base + uploadedPath;
        } else {
            fileUrl = base + "/" + uploadedPath;
        }

        try {
            HttpRequest req = HttpRequest.newBuilder().uri(URI.create(fileUrl)).timeout(Duration.ofSeconds(6)).GET()
                    .build();
            HttpResponse<String> resp = Http.send(ctx, hc, req, HttpResponse.BodyHandlers.ofString(), id());
            String fileBody = resp.body() != null ? resp.body() : "";

            if (resp.statusCode() == 200) {
                // Check for code execution -- marker appears but PHP tags don't
                if (fileBody.contains(MARKER) && !fileBody.contains("<?php")) {
                    log.accept("[!!!] FileUpload: RCE CONFIRMADO -- arquivo executado em " + fileUrl);

                    String rceVec = "AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H";
                    double rceScore = CvssCalculator.calculate(rceVec);

                    return Finding.of(id(), endpoint,
                            "File Upload RCE -- codigo executado no servidor via " + probe.label(), Severity.CRITICAL,
                            "Upload via " + probe.label() + " em " + endpoint + " resultou em arquivo "
                                    + "acessivel em " + fileUrl + ". O servidor executou o conteudo PHP, "
                                    + "retornando '" + MARKER + "' sem as tags PHP -- confirmando RCE.",
                            "Execucao remota de codigo (RCE) confirmada. Atacante pode executar "
                                    + "comandos arbitrarios, ler arquivos sensiveis, acessar bancos de "
                                    + "dados, e comprometer completamente o sistema.",
                            buildCurlCommand(uploadUrl, fieldName, probe) + "\n\n# Verificar execucao:\ncurl '"
                                    + fileUrl + "'",
                            "Validar tipos de arquivo server-side. Armazenar uploads fora do web root. "
                                    + "Desabilitar execucao de scripts no diretorio de uploads. "
                                    + "Servir uploads em dominio separado com Content-Disposition: attachment.",
                            cweId, cweTitle, rceVec, rceScore);
                }

                // File served but script not executed -- still a finding (extension bypass
                // confirmed)
                if (fileBody.contains("<?php") || fileBody.contains(MARKER)) {
                    log.accept("[+] FileUpload: arquivo acessivel em " + fileUrl + " (sem execucao)");

                    return Finding.of(id(), endpoint,
                            "File Upload Bypass -- arquivo perigoso acessivel via " + probe.label(), Severity.MEDIUM,
                            "Upload via " + probe.label() + " aceito e arquivo acessivel em " + fileUrl
                                    + ". Conteudo script servido sem execucao -- bypass de validacao "
                                    + "confirmado mas sem RCE.",
                            "Arquivo com conteudo perigoso foi aceito e armazenado no servidor. "
                                    + "Embora o servidor nao execute o script, um atacante pode usar "
                                    + "isso para armazenar conteudo malicioso (XSS via SVG/HTML) "
                                    + "ou tentar outras tecnicas de bypass.",
                            buildCurlCommand(uploadUrl, fieldName, probe) + "\n\n# Verificar arquivo:\ncurl '" + fileUrl
                                    + "'",
                            "Validar tipos de arquivo server-side com allowlist. "
                                    + "Renomear uploads para nomes aleatorios com extensao fixa. "
                                    + "Servir uploads com Content-Disposition: attachment e em dominio " + "separado.",
                            cweId, cweTitle, cvssVec, score);
                }
            }
        } catch (CircuitBreakerException cbe) {
            throw cbe;
        } catch (Exception ignored) {
            // Could not verify -- not a finding
        }
        return null;
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private static String buildMultipartBody(String boundary, String fieldName, String filename, String contentType,
            String content) {
        return "--" + boundary + "\r\n" + "Content-Disposition: form-data; name=\"" + fieldName + "\"; filename=\""
                + filename + "\"\r\n" + "Content-Type: " + contentType + "\r\n\r\n" + content + "\r\n" + "--" + boundary
                + "--\r\n";
    }

    private static String extractUploadedPath(String responseBody) {
        Matcher m = URL_PATTERN.matcher(responseBody);
        if (m.find()) {
            String path = m.group(1) != null ? m.group(1) : m.group(2);
            if (path != null && !path.isBlank()) {
                return path.trim();
            }
        }
        return null;
    }

    private static String buildCurlCommand(String uploadUrl, String fieldName, UploadProbe probe) {
        return "curl -X POST '" + uploadUrl + "' \\\n" + "  -F '" + fieldName + "=@" + probe.filename() + ";type="
                + probe.contentType() + "'";
    }

    private static String truncate(String s, int maxLen) {
        if (s == null) {
            return "";
        }
        return s.length() <= maxLen ? s : s.substring(0, maxLen) + "...";
    }
}
