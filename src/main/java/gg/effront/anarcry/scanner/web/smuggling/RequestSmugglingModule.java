package gg.effront.anarcry.scanner.web.smuggling;

import gg.effront.anarcry.model.CvssCalculator;
import gg.effront.anarcry.model.CweRegistry;
import gg.effront.anarcry.model.Finding;
import gg.effront.anarcry.model.Severity;
import gg.effront.anarcry.scanner.ScanContext;
import gg.effront.anarcry.scanner.Scanner;
import gg.effront.anarcry.scanner.util.Http;
import gg.effront.anarcry.scanner.util.HttpClientFactory;
import gg.effront.anarcry.scanner.util.TlsUtil;

import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;

public class RequestSmugglingModule implements Scanner {

    // Baseline timeout -- expect any normal server to respond within 2s
    private static final int BASELINE_TIMEOUT_MS = 2_000;
    // Probe timeout -- if server takes longer than this, it's holding the
    // connection
    private static final int PROBE_TIMEOUT_MS = 3_000;

    @Override
    public String id() {
        return "ReqSmuggling";
    }

    @Override
    public List<Finding> scan(ScanContext ctx, Consumer<String> log) throws Exception {
        String _cweId = CweRegistry.cweId(id());
        String _cweTitle = CweRegistry.cweTitle(id());
        String _cveVector = CweRegistry.cvssVector(id());
        double _score = CvssCalculator.calculate(_cveVector);
        List<Finding> findings = new ArrayList<>();
        String host = ctx.host();
        int port = ctx.port();

        log.accept("[~] ReqSmuggling: testando CL.TE e TE.CL em " + host + ":" + port);

        // Verify baseline -- server must respond to a normal request in <
        // BASELINE_TIMEOUT_MS
        boolean baseline = sendBaseline(ctx, host, port, BASELINE_TIMEOUT_MS);
        if (!baseline) {
            log.accept("[~] ReqSmuggling: servidor nao respondeu ao baseline -- pulando");
            return findings;
        }

        // -- Phase 1: CL.TE --
        boolean clTeTimeout = sendProbeAndCheckTimeout(ctx, host, port, buildClTeProbe(host), PROBE_TIMEOUT_MS);
        if (clTeTimeout) {
            log.accept("[!!] ReqSmuggling: CRITICAL -- CL.TE desync confirmado (probe excedeu " + PROBE_TIMEOUT_MS
                    + "ms vs baseline < " + BASELINE_TIMEOUT_MS + "ms)");
            findings.add(Finding.of("ReqSmuggling", ctx.targetUrl(), "HTTP Request Smuggling -- CL.TE desync",
                    Severity.CRITICAL,
                    "CL.TE timing probe: POST com Content-Length=4 e Transfer-Encoding=chunked (corpo de 8 bytes) "
                            + "causou timeout de " + PROBE_TIMEOUT_MS + "ms -- backend usa TE e ficou aguardando "
                            + "bytes de chunk que o frontend (usa CL) nao repassou",
                    "Frontend e backend discordam sobre como interpretar Content-Length vs Transfer-Encoding. "
                            + "Um atacante pode 'contrabandear' requests parciais no buffer do backend, "
                            + "causando request hijacking, bypass de controles de acesso, e Account Takeover.",
                    "# Probe CL.TE -- envia via socket raw (nc/openssl):\n" + "printf 'POST / HTTP/1.1\\r\\nHost: "
                            + host + "\\r\\n" + "Content-Length: 4\\r\\nTransfer-Encoding: chunked\\r\\n\\r\\n"
                            + "1\\r\\nA\\r\\n0\\r\\n\\r\\n' | nc " + host + " " + port,
                    "Normalizar requests ambiguos no proxy/load-balancer: rejeitar com 400 qualquer request "
                            + "que contenha tanto Content-Length quanto Transfer-Encoding; "
                            + "ou reescrever para usar apenas um dos dois",
                    _cweId, _cweTitle, _cveVector, _score));
        }

        // -- Phase 2: TE.CL --
        boolean teCLTimeout = sendProbeAndCheckTimeout(ctx, host, port, buildTeCLProbe(host), PROBE_TIMEOUT_MS);
        if (teCLTimeout) {
            log.accept("[!!] ReqSmuggling: CRITICAL -- TE.CL desync confirmado");
            findings.add(Finding.of("ReqSmuggling", ctx.targetUrl(), "HTTP Request Smuggling -- TE.CL desync",
                    Severity.CRITICAL,
                    "TE.CL timing probe: POST com Transfer-Encoding=chunked e Content-Length=1 " + "causou timeout de "
                            + PROBE_TIMEOUT_MS + "ms -- backend usa CL e ficou aguardando "
                            + "dados que o frontend (usa TE) nao repassou completamente",
                    "Frontend e backend discordam sobre como interpretar Transfer-Encoding vs Content-Length. "
                            + "Permite HTTP request smuggling com impacto equivalente ao CL.TE.",
                    "# Probe TE.CL -- envia via socket raw:\n" + "printf 'POST / HTTP/1.1\\r\\nHost: " + host + "\\r\\n"
                            + "Content-Length: 1\\r\\nTransfer-Encoding: chunked\\r\\n\\r\\n"
                            + "1\\r\\nA\\r\\n0\\r\\n\\r\\n' | nc " + host + " " + port,
                    "Normalizar requests ambiguos no proxy: rejeitar 400 para Content-Length + Transfer-Encoding",
                    _cweId, _cweTitle, _cveVector, _score));
        }

        // -- Phase 3: TE.TE obfuscation --
        TeTeResult teTeResult = probeTeTeObfuscation(ctx, host, port, log);
        if (teTeResult != null) {
            String variant = teTeResult.variant();
            if (teTeResult.desyncConfirmed()) {
                log.accept("[!!] ReqSmuggling: HIGH -- TE.TE desync confirmado com obfuscation: " + variant);
                findings.add(Finding.of("ReqSmuggling", ctx.targetUrl(),
                        "HTTP Request Smuggling -- TE.TE desync (" + variant + ")", Severity.HIGH,
                        "Probe com Transfer-Encoding obfuscado '" + variant + "' confirmou desync: "
                                + "request smuggled foi processado como request separado "
                                + "(duas respostas HTTP na mesma conexao)",
                        "Frontend ou backend aceitou Transfer-Encoding com valor nao-padrao "
                                + "e interpretou o body de forma divergente -- desync confirmado com "
                                + "request smuggling real.",
                        "printf 'POST / HTTP/1.1\\r\\nHost: " + host + "\\r\\n"
                                + "Content-Length: 8\\r\\nTransfer-Encoding: " + variant + "\\r\\n\\r\\n"
                                + "5\\r\\nHELLO' | openssl s_client -connect " + host + ":" + port + " -quiet",
                        "Rejeitar Transfer-Encoding com valores nao-padrao (xchunked, identity com TE duplo etc.)",
                        _cweId, _cweTitle, _cveVector, _score));
            } else {
                log.accept("[~] ReqSmuggling: LOW -- TE parsing tolerance detectada (sem desync): " + variant);
                findings.add(Finding.of("ReqSmuggling", ctx.targetUrl(),
                        "TE parsing tolerance -- " + variant + " aceito (sem desync)", Severity.LOW,
                        "Servidor aceitou Transfer-Encoding obfuscado '" + variant + "' como chunked valido "
                                + "(timeout de " + PROBE_TIMEOUT_MS + "ms vs baseline < " + BASELINE_TIMEOUT_MS
                                + "ms), mas teste de desync nao confirmou request smuggling -- "
                                + "proxy e backend concordam na interpretacao",
                        "Servidor tolera valores nao-padrao de Transfer-Encoding. "
                                + "Sem desync confirmado, risco limitado a violacao de RFC 7230; "
                                + "pode se tornar exploravel se a arquitetura de proxy mudar.",
                        "printf 'POST / HTTP/1.1\\r\\nHost: " + host + "\\r\\n"
                                + "Content-Length: 8\\r\\nTransfer-Encoding: " + variant + "\\r\\n\\r\\n"
                                + "5\\r\\nHELLO' | openssl s_client -connect " + host + ":" + port + " -quiet",
                        "Rejeitar Transfer-Encoding com valores nao-padrao (xchunked, identity com TE duplo etc.)",
                        _cweId, _cweTitle, _cveVector, _score));
            }
        }

        // -- Phase 4: Duplicate Content-Length --
        log.accept("[~] ReqSmuggling: testando Duplicate Content-Length em " + host + ":" + port);
        boolean duplCl = probeDuplicateContentLength(ctx, host, port);
        if (duplCl) {
            log.accept("[!] ReqSmuggling: HIGH -- servidor aceita Content-Length duplicado");
            findings.add(Finding.of("ReqSmuggling", ctx.targetUrl(),
                    "HTTP Request Smuggling -- Duplicate Content-Length aceito", Severity.HIGH,
                    "Servidor aceitou request com dois headers Content-Length divergentes (0 e 42) "
                            + "sem rejeitar com 400 -- indica parser que escolhe um dos valores, "
                            + "criando discrepancia exploravel entre proxy e backend",
                    "Parser que aceita Content-Length duplicado pode permitir smuggling quando "
                            + "proxy e backend escolhem valores diferentes. " + "Ref: HAProxy CVE-2021-40346.",
                    "printf 'GET / HTTP/1.1\\r\\nHost: " + host + "\\r\\n"
                            + "Content-Length: 0\\r\\nContent-Length: 42\\r\\n" + "Connection: close\\r\\n\\r\\n' | nc "
                            + host + " " + port,
                    "Rejeitar com 400 qualquer request contendo headers Content-Length duplicados "
                            + "com valores divergentes (RFC 9112 Section 6.3)",
                    _cweId, _cweTitle, _cveVector, _score));
        }

        // -- Phase 5: CL.0 desync --
        log.accept("[~] ReqSmuggling: testando CL.0 desync em " + host + ":" + port);
        boolean cl0 = probeCl0(ctx, host, port);
        if (cl0) {
            log.accept("[!!] ReqSmuggling: CRITICAL -- CL.0 desync confirmado (duas respostas para um send)");
            findings.add(Finding.of("ReqSmuggling", ctx.targetUrl(), "HTTP Request Smuggling -- CL.0 desync",
                    Severity.CRITICAL,
                    "CL.0 probe: POST com Content-Length contendo request smuggled no body "
                            + "gerou duas respostas HTTP na mesma conexao -- backend ignorou o body "
                            + "e os bytes restantes foram interpretados como nova requisicao",
                    "Backend ignora Content-Length e responde antes de consumir o body. "
                            + "Bytes nao consumidos viram o inicio da proxima requisicao na mesma conexao, "
                            + "permitindo request hijacking, bypass de ACL e cache poisoning. "
                            + "Nao requer Content-Length + Transfer-Encoding -- funciona com CL sozinho.",
                    "# Probe CL.0 -- envia via socket raw (keep-alive):\n" + "printf 'POST / HTTP/1.1\\r\\nHost: "
                            + host + "\\r\\n" + "Content-Length: <N>\\r\\nConnection: keep-alive\\r\\n\\r\\n"
                            + "GET /admin HTTP/1.1\\r\\nHost: " + host + "\\r\\n\\r\\n' | nc " + host + " " + port,
                    "Garantir que o backend consome o body completo antes de responder; "
                            + "nao reutilizar conexoes quando o body nao foi totalmente lido; "
                            + "configurar proxy para fechar conexao apos early response",
                    _cweId, _cweTitle, _cveVector, _score));
        }

        // -- Phase 6: Hop-by-hop TE confusion --
        log.accept("[~] ReqSmuggling: testando hop-by-hop TE confusion em " + host + ":" + port);
        boolean hopByHop = probeHopByHopTe(ctx, host, port);
        if (hopByHop) {
            log.accept("[!] ReqSmuggling: HIGH -- hop-by-hop TE stripping detectado");
            findings.add(Finding.of("ReqSmuggling", ctx.targetUrl(),
                    "HTTP Request Smuggling -- Hop-by-hop TE stripping", Severity.HIGH,
                    "Probe com Connection: Transfer-Encoding respondeu normalmente, enquanto "
                            + "a mesma probe sem o header Connection causou timeout -- "
                            + "proxy removeu Transfer-Encoding como hop-by-hop header, "
                            + "backend processou body apenas via Content-Length",
                    "Proxy trata Transfer-Encoding como hop-by-hop e o remove antes de repassar. "
                            + "Backend recebe request sem TE e usa CL, criando parser differential exploravel. "
                            + "Ref: Akamai CVE-2026-26365.",
                    "# Probe hop-by-hop TE:\n" + "printf 'POST / HTTP/1.1\\r\\nHost: " + host + "\\r\\n"
                            + "Content-Length: 8\\r\\nConnection: Transfer-Encoding\\r\\n"
                            + "Transfer-Encoding: chunked\\r\\n\\r\\n" + "5\\r\\nHELLO' | nc " + host + " " + port,
                    "Nao tratar Transfer-Encoding como hop-by-hop header; "
                            + "rejeitar requests onde Connection lista Transfer-Encoding",
                    _cweId, _cweTitle, _cveVector, _score));
        }

        // -- Phase 7: H2.CL smuggling --
        probeH2ClSmuggling(ctx, host, port, findings, log, _cweId, _cweTitle, _cveVector, _score);

        // -- Phase 8: H2.TE smuggling --
        probeH2TeSmuggling(ctx, host, port, findings, log, _cweId, _cweTitle, _cveVector, _score);

        // -- Phase 9: H2 header manipulation --
        probeH2HeaderManipulation(ctx, host, port, findings, log, _cweId, _cweTitle, _cveVector, _score);

        // -- Phase 10: CRLF in HTTP/2 headers --
        probeH2CrlfInjection(ctx, host, port, findings, log, _cweId, _cweTitle, _cveVector, _score);

        if (findings.isEmpty()) {
            log.accept("[+] ReqSmuggling: nenhum desync detectado");
        }
        return findings;
    }

    // ========================================================================
    // Phase 7: H2.CL smuggling
    // HTTP/2 request with Content-Length that mismatches actual body length.
    // If a frontend proxy downgrades H2 to H1 and preserves CL, the backend
    // may interpret excess body bytes as a second request.
    // ========================================================================
    private void probeH2ClSmuggling(ScanContext ctx, String host, int port, List<Finding> findings,
            Consumer<String> log, String cweId, String cweTitle, String cveVector, double score) {
        log.accept("[~] ReqSmuggling: testando H2.CL smuggling em " + host + ":" + port);
        try {
            HttpClient h2 = HttpClientFactory.http2();
            String scheme = ctx.isHttps() ? "https" : "http";
            int defPort = ctx.isHttps() ? 443 : 80;
            String baseUrl = scheme + "://" + host + (port != defPort ? ":" + port : "");

            // First, confirm H2 is actually negotiated by sending a normal request
            HttpRequest baseReq = HttpRequest.newBuilder().uri(URI.create(baseUrl + "/")).header("Host", host)
                    .timeout(Duration.ofSeconds(6)).GET().build();
            HttpResponse<String> baseResp = Http.send(ctx, h2, baseReq, HttpResponse.BodyHandlers.ofString(), id());
            if (baseResp.version() != HttpClient.Version.HTTP_2) {
                log.accept("[~] ReqSmuggling: H2 nao negociado -- pulando probes H2");
                return;
            }

            // H2.CL probe: send POST with body containing a smuggled request prefix.
            // Set Content-Length shorter than actual body. If proxy downgrades to H1
            // using our CL header, backend reads only CL bytes and the rest becomes
            // the start of a new request.
            String smuggledReq = "GET /h2cl-smuggle-probe HTTP/1.1\r\nHost: " + host + "\r\n\r\n";
            String fullBody = "X" + smuggledReq;

            // Try to set Content-Length to 1 (only "X") while body has more data
            HttpRequest probe = HttpRequest.newBuilder().uri(URI.create(baseUrl + "/"))
                    .header("Content-Type", "application/x-www-form-urlencoded").header("Content-Length", "1")
                    .timeout(Duration.ofSeconds(6)).POST(HttpRequest.BodyPublishers.ofString(fullBody)).build();
            HttpResponse<String> probeResp = Http.send(ctx, h2, probe, HttpResponse.BodyHandlers.ofString(), id());
            String probeBody = probeResp.body() != null ? probeResp.body() : "";
            int probeStatus = probeResp.statusCode();

            // Detection: if the server returns indicators that the smuggled request
            // was processed (e.g., 404 for /h2cl-smuggle-probe in body, or two
            // HTTP status lines), that confirms desync
            if (probeBody.contains("h2cl-smuggle-probe") || probeBody.contains("HTTP/1.1")
                    || probeBody.contains("HTTP/2")) {
                log.accept("[!!] ReqSmuggling: HIGH -- H2.CL desync indicador detectado");
                findings.add(Finding.of("ReqSmuggling", ctx.targetUrl(), "HTTP/2 Request Smuggling -- H2.CL desync",
                        Severity.HIGH,
                        "H2.CL probe: POST via HTTP/2 com Content-Length=1 e body de " + fullBody.length()
                                + " bytes retornou indicadores de desync: HTTP " + probeStatus + " | "
                                + "Resposta contem referencia ao request smuggled",
                        "Frontend aceita HTTP/2 e faz downgrade para HTTP/1.1 ao backend preservando "
                                + "o Content-Length do request H2. Como H2 usa frame length (nao CL), "
                                + "o CL do header pode nao corresponder ao body real, criando desync "
                                + "no backend que interpreta o excesso como novo request.",
                        "# H2.CL probe (via curl HTTP/2):\ncurl -v --http2 -X POST " + baseUrl + "/ \\\n"
                                + "  -H 'Content-Length: 1' \\\n" + "  -d 'XGET /smuggled HTTP/1.1\\r\\nHost: " + host
                                + "\\r\\n\\r\\n'",
                        "Nao preservar Content-Length do request H2 durante downgrade para H1; "
                                + "recalcular CL baseado no body real; rejeitar requests com CL "
                                + "inconsistente; considerar end-to-end HTTP/2",
                        cweId, cweTitle, cveVector, score));
            }

            // Secondary check: send paired requests via H2 to detect connection-level
            // desync. First request has CL mismatch, second is a canary. If the
            // canary response is different from expected, desync occurred.
            HttpRequest canary = HttpRequest.newBuilder().uri(URI.create(baseUrl + "/")).header("Host", host)
                    .timeout(Duration.ofSeconds(6)).GET().build();
            HttpResponse<String> canaryResp = Http.send(ctx, h2, canary, HttpResponse.BodyHandlers.ofString(), id());
            int canaryStatus = canaryResp.statusCode();

            // If canary gets a 404 (routed to /h2cl-smuggle-probe) instead of the
            // expected status, the smuggled request poisoned the connection
            if (canaryStatus == 404 && probeStatus != 404) {
                log.accept("[!!] ReqSmuggling: CRITICAL -- H2.CL desync confirmado via canary (esperava " + probeStatus
                        + ", recebeu 404)");
                findings.add(Finding.of("ReqSmuggling", ctx.targetUrl(),
                        "HTTP/2 Request Smuggling -- H2.CL desync confirmado", Severity.CRITICAL,
                        "H2.CL desync confirmado: request canary (GET /) retornou HTTP 404 "
                                + "apos probe com CL mismatch -- request smuggled envenenou a conexao",
                        "Frontend aceita HTTP/2 e faz downgrade para H1 preservando CL incorreto. "
                                + "Dados excedentes no body sao interpretados como novo request, "
                                + "comprometendo requests de outros usuarios na mesma conexao.",
                        "# Confirma H2.CL com canary:\ncurl --http2 -X POST " + baseUrl + "/ \\\n"
                                + "  -H 'Content-Length: 1' -d 'XGET /probe HTTP/1.1\\r\\n\\r\\n'\n"
                                + "# Seguido imediatamente por:\ncurl --http2 " + baseUrl + "/",
                        "Nao preservar Content-Length do H2 durante downgrade; recalcular CL "
                                + "com base no body real; usar HTTP/2 end-to-end",
                        cweId, cweTitle, cveVector, score));
            }
        } catch (Exception e) {
            log.accept("[~] ReqSmuggling: erro no probe H2.CL -- " + e.getMessage());
        }
    }

    // ========================================================================
    // Phase 8: H2.TE smuggling
    // HTTP/2 request with Transfer-Encoding header (forbidden in H2 spec).
    // If proxy passes it through during H1 downgrade, backend may process
    // chunked encoding, creating desync.
    // ========================================================================
    private void probeH2TeSmuggling(ScanContext ctx, String host, int port, List<Finding> findings,
            Consumer<String> log, String cweId, String cweTitle, String cveVector, double score) {
        log.accept("[~] ReqSmuggling: testando H2.TE smuggling em " + host + ":" + port);
        try {
            HttpClient h2 = HttpClientFactory.http2();
            String scheme = ctx.isHttps() ? "https" : "http";
            int defPort = ctx.isHttps() ? 443 : 80;
            String baseUrl = scheme + "://" + host + (port != defPort ? ":" + port : "");

            // Verify H2 is negotiated
            HttpRequest checkReq = HttpRequest.newBuilder().uri(URI.create(baseUrl + "/"))
                    .timeout(Duration.ofSeconds(6)).GET().build();
            HttpResponse<String> checkResp = Http.send(ctx, h2, checkReq, HttpResponse.BodyHandlers.ofString(), id());
            if (checkResp.version() != HttpClient.Version.HTTP_2) {
                return; // Already logged in H2.CL phase
            }

            // H2.TE probe: send HTTP/2 request with Transfer-Encoding: chunked header.
            // H2 spec (RFC 9113 sec 8.2.2) forbids TE except TE: trailers.
            // If the proxy/server does not reject this, it may pass TE through to backend.
            String smuggled = "0\r\n\r\nGET /h2te-smuggle-probe HTTP/1.1\r\nHost: " + host + "\r\n\r\n";
            String chunkedBody = "5\r\nHELLO\r\n" + smuggled;

            HttpRequest probe = HttpRequest.newBuilder().uri(URI.create(baseUrl + "/"))
                    .header("Content-Type", "application/x-www-form-urlencoded").header("Transfer-Encoding", "chunked")
                    .timeout(Duration.ofSeconds(6)).POST(HttpRequest.BodyPublishers.ofString(chunkedBody)).build();
            HttpResponse<String> probeResp = Http.send(ctx, h2, probe, HttpResponse.BodyHandlers.ofString(), id());
            int probeStatus = probeResp.statusCode();
            String probeBody = probeResp.body() != null ? probeResp.body() : "";

            // If server did NOT reject with 400/500, TE was accepted in H2 context
            if (probeStatus >= 200 && probeStatus < 400) {
                // Check for desync indicators
                boolean desyncIndicator = probeBody.contains("h2te-smuggle-probe") || probeBody.contains("HTTP/1.1")
                        || probeBody.contains("HTTP/2");

                if (desyncIndicator) {
                    log.accept("[!!] ReqSmuggling: HIGH -- H2.TE desync detectado");
                    findings.add(Finding.of("ReqSmuggling", ctx.targetUrl(), "HTTP/2 Request Smuggling -- H2.TE desync",
                            Severity.HIGH,
                            "H2.TE probe: Transfer-Encoding: chunked aceito via HTTP/2 (HTTP " + probeStatus
                                    + ") e resposta contem indicadores de desync",
                            "Proxy aceita Transfer-Encoding em HTTP/2 (violacao RFC 9113) e o "
                                    + "propaga ao backend durante downgrade. Backend processa chunked "
                                    + "encoding, terminando o body no primeiro 0\\r\\n\\r\\n -- bytes "
                                    + "restantes viram novo request.",
                            "# H2.TE probe:\ncurl --http2 -X POST " + baseUrl + "/ \\\n"
                                    + "  -H 'Transfer-Encoding: chunked' \\\n"
                                    + "  -d '5\\r\\nHELLO\\r\\n0\\r\\n\\r\\nGET /probe HTTP/1.1\\r\\n\\r\\n'",
                            "Rejeitar requests HTTP/2 com Transfer-Encoding header (exceto TE: trailers); "
                                    + "nao propagar TE durante H2->H1 downgrade; usar HTTP/2 end-to-end",
                            cweId, cweTitle, cveVector, score));
                } else {
                    log.accept("[!] ReqSmuggling: MEDIUM -- Transfer-Encoding aceito em HTTP/2 (sem desync)");
                    findings.add(Finding.of("ReqSmuggling", ctx.targetUrl(),
                            "HTTP/2 Transfer-Encoding aceito (violacao RFC 9113)", Severity.MEDIUM,
                            "Transfer-Encoding: chunked aceito em HTTP/2 request sem rejeicao " + "(HTTP " + probeStatus
                                    + ") -- violacao de RFC 9113 sec 8.2.2",
                            "Servidor ou proxy aceita Transfer-Encoding em HTTP/2, violando a spec. "
                                    + "Em uma arquitetura com H2-to-H1 downgrade, isso habilita H2.TE "
                                    + "smuggling. Risco depende da topologia de proxy.",
                            "curl --http2 -X POST " + baseUrl + "/ \\\n"
                                    + "  -H 'Transfer-Encoding: chunked' -d 'test'",
                            "Rejeitar Transfer-Encoding em requests HTTP/2; configurar proxy "
                                    + "para strip TE antes de downgrade; atualizar software de proxy",
                            cweId, cweTitle, cveVector, score));
                }
            }
        } catch (IllegalArgumentException iae) {
            // Java's HttpClient rejected the Transfer-Encoding header in H2 mode --
            // this is expected and means the client-side enforces the spec
            log.accept("[~] ReqSmuggling: H2.TE -- cliente Java rejeitou TE em H2 (spec-compliant)");
        } catch (Exception e) {
            log.accept("[~] ReqSmuggling: erro no probe H2.TE -- " + e.getMessage());
        }
    }

    // ========================================================================
    // Phase 9: H2 header manipulation
    // Test for pseudo-header injection, duplicate Host, and header name
    // anomalies in HTTP/2 requests that may exploit H2-to-H1 downgrade.
    // ========================================================================
    private void probeH2HeaderManipulation(ScanContext ctx, String host, int port, List<Finding> findings,
            Consumer<String> log, String cweId, String cweTitle, String cveVector, double score) {
        log.accept("[~] ReqSmuggling: testando H2 header manipulation em " + host + ":" + port);
        try {
            HttpClient h2 = HttpClientFactory.http2();
            String scheme = ctx.isHttps() ? "https" : "http";
            int defPort = ctx.isHttps() ? 443 : 80;
            String baseUrl = scheme + "://" + host + (port != defPort ? ":" + port : "");

            // Test 1: Duplicate Host header
            // If proxy combines both Host values or picks the wrong one during
            // downgrade, it can cause routing confusion (cache poisoning, SSRF)
            try {
                HttpRequest dualHost = HttpRequest.newBuilder().uri(URI.create(baseUrl + "/")).header("Host", host)
                        .header("Host", "evil.example.com").timeout(Duration.ofSeconds(6)).GET().build();
                HttpResponse<String> dualResp = Http.send(ctx, h2, dualHost, HttpResponse.BodyHandlers.ofString(),
                        id());
                String dualBody = dualResp.body() != null ? dualResp.body() : "";
                int dualStatus = dualResp.statusCode();

                // If server responded 200 (not 400) and the response contains
                // references to evil.example.com, the duplicate Host was processed
                if (dualStatus >= 200 && dualStatus < 400 && dualBody.contains("evil.example.com")) {
                    log.accept("[!] ReqSmuggling: MEDIUM -- duplicate Host aceito em H2");
                    findings.add(Finding.of("ReqSmuggling", ctx.targetUrl(), "HTTP/2 duplicate Host header aceito",
                            Severity.MEDIUM,
                            "HTTP/2 request com dois Host headers ('" + host + "' e 'evil.example.com') "
                                    + "retornou HTTP " + dualStatus + " com referencia ao host injetado",
                            "Servidor aceita Host duplicado em HTTP/2 -- durante H2-to-H1 downgrade, "
                                    + "proxy pode gerar request H1 com Host ambiguo, habilitando cache "
                                    + "poisoning, SSRF ou routing manipulation.",
                            "curl --http2 -H 'Host: " + host + "' -H 'Host: evil.example.com' " + baseUrl + "/",
                            "Rejeitar requests com Host duplicado; normalizar Host "
                                    + "antes de processar; usar :authority como canonico em H2",
                            cweId, cweTitle, cveVector, score));
                }
            } catch (IllegalArgumentException ignored) {
                // Java's HttpClient may reject duplicate Host -- that's fine
            }

            // Test 2: Space in header name (header name injection)
            // Some servers/proxies accept "X Method: GET" which could cause
            // confusion during H2->H1 conversion
            try {
                HttpRequest spaceHeader = HttpRequest.newBuilder().uri(URI.create(baseUrl + "/"))
                        .header("X-Custom Header", "test-value").timeout(Duration.ofSeconds(6)).GET().build();
                HttpResponse<String> spaceResp = Http.send(ctx, h2, spaceHeader, HttpResponse.BodyHandlers.ofString(),
                        id());

                if (spaceResp.statusCode() >= 200 && spaceResp.statusCode() < 400) {
                    log.accept("[~] ReqSmuggling: servidor aceitou header com espaco no nome via H2");
                    // This is informational -- header name with space accepted
                }
            } catch (IllegalArgumentException ignored) {
                // Expected -- Java validates header names
            }

            // Test 3: Pseudo-header as regular header
            // Try to include :method, :path as regular headers. In H2 these are
            // pseudo-headers; if a proxy passes them as H1 headers, backend
            // may misroute the request.
            try {
                HttpRequest pseudoHeader = HttpRequest.newBuilder().uri(URI.create(baseUrl + "/"))
                        .header("x-http2-method", "DELETE").header("x-http2-path", "/admin")
                        .header("x-http2-scheme", "https").timeout(Duration.ofSeconds(6)).GET().build();
                HttpResponse<String> pseudoResp = Http.send(ctx, h2, pseudoHeader, HttpResponse.BodyHandlers.ofString(),
                        id());
                String pseudoBody = pseudoResp.body() != null ? pseudoResp.body() : "";

                // Some reverse proxies (like Envoy) use X-Forwarded-Method or similar
                // to override the actual method. Check if the response indicates
                // the server treated this as a DELETE or routed to /admin
                if (pseudoResp.statusCode() == 405 || pseudoBody.contains("DELETE") || pseudoBody.contains("/admin")) {
                    log.accept("[!] ReqSmuggling: MEDIUM -- pseudo-header override detectado via H2");
                    findings.add(Finding.of("ReqSmuggling", ctx.targetUrl(),
                            "HTTP/2 pseudo-header override via custom headers", Severity.MEDIUM,
                            "HTTP/2 request com x-http2-method: DELETE e x-http2-path: /admin " + "retornou HTTP "
                                    + pseudoResp.statusCode() + " indicando que o header influenciou o roteamento",
                            "Proxy ou backend aceita headers custom que sobrescrevem metodo ou path "
                                    + "do request -- atacante pode acessar endpoints restritos "
                                    + "ou executar metodos nao permitidos.",
                            "curl --http2 -H 'x-http2-method: DELETE' -H 'x-http2-path: /admin' " + baseUrl + "/",
                            "Ignorar headers que tentam sobrescrever pseudo-headers H2; "
                                    + "usar apenas :method e :path do frame HEADERS como autoritativos",
                            cweId, cweTitle, cveVector, score));
                }
            } catch (IllegalArgumentException ignored) {
                // Header name rejected
            }
        } catch (Exception e) {
            log.accept("[~] ReqSmuggling: erro nos probes de header manipulation -- " + e.getMessage());
        }
    }

    // ========================================================================
    // Phase 10: CRLF in HTTP/2 headers
    // In HTTP/2, headers are binary-safe. If a proxy downgrades to HTTP/1.1
    // without sanitizing, CRLF in header values becomes header injection.
    // ========================================================================
    private void probeH2CrlfInjection(ScanContext ctx, String host, int port, List<Finding> findings,
            Consumer<String> log, String cweId, String cweTitle, String cveVector, double score) {
        log.accept("[~] ReqSmuggling: testando CRLF injection em HTTP/2 headers em " + host + ":" + port);
        try {
            HttpClient h2 = HttpClientFactory.http2();
            String scheme = ctx.isHttps() ? "https" : "http";
            int defPort = ctx.isHttps() ? 443 : 80;
            String baseUrl = scheme + "://" + host + (port != defPort ? ":" + port : "");

            // Try CRLF injection via header value
            // If Java's HttpClient allows \r\n in header values (unlikely in modern JDK),
            // and the proxy downgrades to H1 without sanitizing, the injected CRLF
            // becomes a header line break, creating a new header.
            String[] crlfPayloads = {"bar\r\nX-Injected: h2crlf-probe",
                    "bar\r\n\r\nGET /h2crlf-smuggle HTTP/1.1\r\nHost: " + host + "\r\n\r\n",
                    "bar\nX-Injected: h2crlf-lf-probe"};

            for (String payload : crlfPayloads) {
                try {
                    HttpRequest crlfReq = HttpRequest.newBuilder().uri(URI.create(baseUrl + "/"))
                            .header("X-Test", payload).timeout(Duration.ofSeconds(6)).GET().build();
                    HttpResponse<String> crlfResp = Http.send(ctx, h2, crlfReq, HttpResponse.BodyHandlers.ofString(),
                            id());
                    String crlfBody = crlfResp.body() != null ? crlfResp.body() : "";

                    // Check if the injection affected the response
                    if (crlfBody.contains("h2crlf-probe") || crlfBody.contains("h2crlf-lf-probe")
                            || crlfBody.contains("h2crlf-smuggle") || crlfBody.contains("X-Injected")) {
                        log.accept("[!!] ReqSmuggling: HIGH -- CRLF injection em H2 headers confirmada");
                        findings.add(Finding.of("ReqSmuggling", ctx.targetUrl(),
                                "HTTP/2 CRLF header injection -- H2-to-H1 downgrade", Severity.HIGH,
                                "CRLF em header value HTTP/2 foi preservado durante downgrade para H1: " + "payload '"
                                        + payload.replace("\r", "\\r").replace("\n", "\\n")
                                        + "' resultou em header injection na resposta",
                                "Headers HTTP/2 sao binary-safe (sem delimitadores CRLF). Quando "
                                        + "proxy faz downgrade para HTTP/1.1 sem sanitizar, caracteres "
                                        + "\\r\\n em header values se tornam quebras de header no H1, "
                                        + "permitindo header injection e potencialmente response splitting.",
                                "curl --http2 -H 'X-Test: bar\\r\\nX-Injected: probe' " + baseUrl + "/",
                                "Sanitizar header values durante H2-to-H1 downgrade: strip ou rejeitar "
                                        + "\\r e \\n em valores; usar proxy que valida headers durante conversao",
                                cweId, cweTitle, cveVector, score));
                        return;
                    }

                    // Also check response headers for injected header
                    if (crlfResp.headers().firstValue("X-Injected").isPresent()) {
                        log.accept("[!!] ReqSmuggling: HIGH -- CRLF injection confirmada via response headers");
                        findings.add(Finding.of("ReqSmuggling", ctx.targetUrl(),
                                "HTTP/2 CRLF header injection -- header refletido", Severity.HIGH,
                                "CRLF injection em HTTP/2 header value criou header X-Injected na resposta "
                                        + "-- proxy fez downgrade sem sanitizar header values",
                                "Proxy nao sanitiza CRLF em header values durante H2->H1 downgrade, "
                                        + "permitindo injecao de headers arbitrarios e response splitting.",
                                "curl --http2 -H 'X-Test: bar\\r\\nX-Injected: probe' " + baseUrl + "/",
                                "Sanitizar header values durante H2->H1 downgrade; atualizar proxy", cweId, cweTitle,
                                cveVector, score));
                        return;
                    }
                } catch (IllegalArgumentException iae) {
                    // Java's HttpClient rejected the header value containing CRLF --
                    // this is expected behavior for modern JDKs
                    log.accept("[~] ReqSmuggling: CRLF em header rejeitado pelo cliente Java (spec-compliant)");
                    break; // All payloads will be rejected
                }
            }
        } catch (Exception e) {
            log.accept("[~] ReqSmuggling: erro no probe H2 CRLF -- " + e.getMessage());
        }
    }

    // CL.TE: CL says 4 bytes, TE body is 8 bytes ("1\r\nA\r\n0\r\n\r\n")
    // Frontend (uses CL) forwards 4 bytes: "1\r\n" -- backend (uses TE) sees
    // incomplete chunk, hangs
    private String buildClTeProbe(String host) {
        return "POST / HTTP/1.1\r\n" + "Host: " + host + "\r\n" + "Content-Type: application/x-www-form-urlencoded\r\n"
                + "Content-Length: 4\r\n" + "Transfer-Encoding: chunked\r\n" + "\r\n" + "1\r\n" + "A\r\n" + "0\r\n"
                + "\r\n";
    }

    // TE.CL: TE=chunked body complete (8 bytes), CL=1 (says only 1 byte)
    // Frontend (uses TE) processes full chunked body -> backend (uses CL) expects 1
    // byte, gets incomplete first line, hangs
    private String buildTeCLProbe(String host) {
        return "POST / HTTP/1.1\r\n" + "Host: " + host + "\r\n" + "Content-Type: application/x-www-form-urlencoded\r\n"
                + "Content-Length: 1\r\n" + "Transfer-Encoding: chunked\r\n" + "\r\n" + "1\r\n" + "A\r\n" + "0\r\n"
                + "\r\n";
    }

    private boolean sendBaseline(ScanContext ctx, String host, int port, int timeoutMs) {
        String req = "GET / HTTP/1.1\r\nHost: " + host + "\r\nConnection: close\r\n\r\n";
        try {
            String resp = rawSend(ctx, host, port, req, timeoutMs);
            return resp != null && resp.startsWith("HTTP/");
        } catch (Exception e) {
            return false;
        }
    }

    private boolean sendProbeAndCheckTimeout(ScanContext ctx, String host, int port, String probe, int timeoutMs) {
        try {
            String resp = rawSend(ctx, host, port, probe, timeoutMs);
            return false; // Got a response -- no timeout
        } catch (java.net.SocketTimeoutException e) {
            return true; // Timed out -- server was hanging
        } catch (Exception e) {
            return false;
        }
    }

    private static final int TETE_CONFIRM_THRESHOLD = 2;
    private static final int TETE_ATTEMPTS = 3;

    private record TeTeResult(String variant, boolean desyncConfirmed) {
    }

    private TeTeResult probeTeTeObfuscation(ScanContext ctx, String host, int port, Consumer<String> log) {
        List<String> variants = List.of("xchunked", "chunked, chunked", "chunked\t");
        for (String variant : variants) {
            String probe = "POST / HTTP/1.1\r\n" + "Host: " + host + "\r\n"
                    + "Content-Type: application/x-www-form-urlencoded\r\n" + "Content-Length: 8\r\n"
                    + "Transfer-Encoding: " + variant + "\r\n" + "\r\n" + "5\r\nHELLO";
            int timeouts = 0;
            for (int attempt = 0; attempt < TETE_ATTEMPTS; attempt++) {
                try {
                    rawSend(ctx, host, port, probe, PROBE_TIMEOUT_MS);
                } catch (java.net.SocketTimeoutException e) {
                    timeouts++;
                } catch (Exception e) {
                    // Connection error -- skip attempt
                }
            }
            if (timeouts >= TETE_CONFIRM_THRESHOLD) {
                boolean desync = confirmTeTeDesync(ctx, host, port, variant);
                return new TeTeResult(variant, desync);
            }
        }
        return null;
    }

    private boolean confirmTeTeDesync(ScanContext ctx, String host, int port, String variant) {
        String smuggled = "GET /smuggle-probe HTTP/1.1\r\nHost: " + host + "\r\n\r\n";
        String hexLen = Integer.toHexString(smuggled.length());
        String probe = "POST / HTTP/1.1\r\n" + "Host: " + host + "\r\n" + "Content-Length: 0\r\n"
                + "Transfer-Encoding: " + variant + "\r\n" + "\r\n" + hexLen + "\r\n" + smuggled + "0\r\n\r\n";
        try (Socket socket = createSocket(ctx, host, port, PROBE_TIMEOUT_MS)) {
            OutputStream out = socket.getOutputStream();
            out.write(probe.getBytes(StandardCharsets.US_ASCII));
            out.flush();
            InputStream in = socket.getInputStream();
            byte[] buf = new byte[8192];
            int totalRead = 0;
            long deadline = System.currentTimeMillis() + PROBE_TIMEOUT_MS;
            while (totalRead < buf.length && System.currentTimeMillis() < deadline) {
                int remaining = (int) (deadline - System.currentTimeMillis());
                if (remaining <= 0) {
                    break;
                }
                socket.setSoTimeout(remaining);
                try {
                    int n = in.read(buf, totalRead, buf.length - totalRead);
                    if (n <= 0) {
                        break;
                    }
                    totalRead += n;
                } catch (java.net.SocketTimeoutException e) {
                    break;
                }
            }
            if (totalRead == 0) {
                return false;
            }
            String resp = new String(buf, 0, totalRead, StandardCharsets.US_ASCII);
            int count = 0;
            int idx = 0;
            while ((idx = resp.indexOf("HTTP/", idx)) != -1) {
                count++;
                idx += 5;
            }
            return count >= 2;
        } catch (Exception e) {
            return false;
        }
    }

    private String rawSend(ScanContext ctx, String host, int port, String request, int timeoutMs) throws Exception {
        try (Socket socket = createSocket(ctx, host, port, timeoutMs)) {
            OutputStream out = socket.getOutputStream();
            out.write(request.getBytes(StandardCharsets.US_ASCII));
            out.flush();

            InputStream in = socket.getInputStream();
            byte[] buf = new byte[4096];
            int read = in.read(buf); // blocks until data arrives or timeout
            if (read <= 0) {
                return null;
            }
            return new String(buf, 0, read, StandardCharsets.US_ASCII);
        }
    }

    private boolean probeDuplicateContentLength(ScanContext ctx, String host, int port) {
        String probe = "GET / HTTP/1.1\r\n" + "Host: " + host + "\r\n" + "Content-Length: 0\r\n"
                + "Content-Length: 42\r\n" + "Connection: close\r\n" + "\r\n";
        try {
            String resp = rawSend(ctx, host, port, probe, BASELINE_TIMEOUT_MS);
            if (resp == null) {
                return false;
            }
            // RFC 9112: server MUST reject duplicate CL with different values (400).
            // Only flag on 2xx -- server successfully processed the ambiguous request.
            // 3xx/4xx/5xx are not reliable indicators of parser acceptance.
            if (!resp.startsWith("HTTP/")) {
                return false;
            }
            int sp = resp.indexOf(' ');
            if (sp < 0 || sp + 4 > resp.length()) {
                return false;
            }
            char c1 = resp.charAt(sp + 1);
            char c2 = resp.charAt(sp + 2);
            char c3 = resp.charAt(sp + 3);
            return c1 == '2' && c2 >= '0' && c2 <= '9' && c3 >= '0' && c3 <= '9';
        } catch (Exception e) {
            return false;
        }
    }

    private boolean probeCl0(ScanContext ctx, String host, int port) {
        // Smuggled GET baked into the POST body; if backend ignores CL
        // and does not consume the body, leftover bytes become a second request
        String smuggled = "GET /cl0-probe HTTP/1.1\r\nHost: " + host + "\r\n\r\n";
        String probe = "POST / HTTP/1.1\r\n" + "Host: " + host + "\r\n" + "Content-Length: " + smuggled.length()
                + "\r\n" + "Connection: keep-alive\r\n" + "\r\n" + smuggled;
        try (Socket socket = createSocket(ctx, host, port, PROBE_TIMEOUT_MS)) {
            OutputStream out = socket.getOutputStream();
            out.write(probe.getBytes(StandardCharsets.US_ASCII));
            out.flush();

            InputStream in = socket.getInputStream();
            byte[] buf = new byte[8192];
            int totalRead = 0;
            long deadline = System.currentTimeMillis() + PROBE_TIMEOUT_MS;
            while (totalRead < buf.length && System.currentTimeMillis() < deadline) {
                int remaining = (int) (deadline - System.currentTimeMillis());
                if (remaining <= 0) {
                    break;
                }
                socket.setSoTimeout(remaining);
                try {
                    int n = in.read(buf, totalRead, buf.length - totalRead);
                    if (n <= 0) {
                        break;
                    }
                    totalRead += n;
                } catch (java.net.SocketTimeoutException e) {
                    break;
                }
            }
            if (totalRead == 0) {
                return false;
            }
            String resp = new String(buf, 0, totalRead, StandardCharsets.US_ASCII);
            // Count HTTP response start lines -- two means desync
            int count = 0;
            int idx = 0;
            while ((idx = resp.indexOf("HTTP/", idx)) != -1) {
                count++;
                idx += 5;
            }
            return count >= 2;
        } catch (Exception e) {
            return false;
        }
    }

    private boolean probeHopByHopTe(ScanContext ctx, String host, int port) {
        // Incomplete chunked body -- server that processes TE will hang
        String bodyWithTe = "POST / HTTP/1.1\r\n" + "Host: " + host + "\r\n" + "Content-Length: 8\r\n"
                + "Transfer-Encoding: chunked\r\n" + "\r\n" + "5\r\nHELLO";
        // Same probe but with Connection: Transfer-Encoding
        // If proxy strips TE as hop-by-hop, backend uses CL=8, gets "5\r\nHELLO"
        // (8 bytes), responds normally instead of hanging
        String bodyWithHopByHop = "POST / HTTP/1.1\r\n" + "Host: " + host + "\r\n" + "Content-Length: 8\r\n"
                + "Connection: Transfer-Encoding\r\n" + "Transfer-Encoding: chunked\r\n" + "\r\n" + "5\r\nHELLO";

        boolean teTimeout = sendProbeAndCheckTimeout(ctx, host, port, bodyWithTe, PROBE_TIMEOUT_MS);
        boolean hopTimeout = sendProbeAndCheckTimeout(ctx, host, port, bodyWithHopByHop, PROBE_TIMEOUT_MS);
        // TE alone hangs (server processes chunked) but hop-by-hop version responds
        // normally -- proxy stripped TE
        return teTimeout && !hopTimeout;
    }

    private Socket createSocket(ScanContext ctx, String host, int port, int timeoutMs) throws Exception {
        if (ctx.isHttps()) {
            SSLContext sslCtx = TlsUtil.sslContext(TlsUtil.trustAll());
            SSLSocket sslSocket = TlsUtil.connectSocket(host, port, sslCtx, timeoutMs);
            sslSocket.setSoTimeout(timeoutMs);
            sslSocket.startHandshake();
            return sslSocket;
        } else {
            Socket socket = new Socket(); // nosemgrep: unencrypted-socket
            socket.setSoTimeout(timeoutMs);
            socket.connect(new InetSocketAddress(host, port), timeoutMs);
            return socket;
        }
    }
}
