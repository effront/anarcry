package gg.effront.anarcry.scanner.web.crlf;

import gg.effront.anarcry.model.Finding;
import gg.effront.anarcry.model.Severity;
import gg.effront.anarcry.scanner.ScanContext;
import gg.effront.anarcry.scanner.Scanner;
import gg.effront.anarcry.scanner.util.Http;
import gg.effront.anarcry.scanner.util.HttpClientFactory;
import gg.effront.anarcry.scanner.util.TlsUtil;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
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
import gg.effront.anarcry.model.CweRegistry;
import gg.effront.anarcry.model.CvssCalculator;

public class CrlfModule implements Scanner {

    // All 17 payloads from Payloads4All-master/CRLF Injection/crlfinjection.txt
    private static final List<String> PAYLOADS = List.of("/%0aSet-Cookie:crlf=injection",
            "/%0d%0aSet-Cookie:crlf=injection", "/%0dSet-Cookie:crlf=injection", "/%23%0aSet-Cookie:crlf=injection",
            "/%23%0d%0aSet-Cookie:crlf=injection", "/%23%0dSet-Cookie:crlf=injection",
            "/%25%30%61Set-Cookie:crlf=injection", "/%25%30aSet-Cookie:crlf=injection",
            "/%250aSet-Cookie:crlf=injection", "/%25250aSet-Cookie:crlf=injection",
            "/%2e%2e%2f%0d%0aSet-Cookie:crlf=injection", "/%2f%2e%2e%0d%0aSet-Cookie:crlf=injection",
            "/%2F..%0d%0aSet-Cookie:crlf=injection", "/%3f%0d%0aSet-Cookie:crlf=injection",
            "/%3f%0dSet-Cookie:crlf=injection"
    // /%u000a and /%%0a0a skipped — %u and %% are non-standard URI encoding
    // rejected by URI parser
    );

    // Sprint 28: headers whose values are reflected in response headers by
    // vulnerable servers.
    // Java HttpClient rejects CRLF in header values — must use raw socket.
    private static final List<String> INJECTABLE_HEADERS = List.of("User-Agent", "Referer", "Accept-Language");

    // Injected value: a recognizable marker after CRLF — we look for this in the
    // response
    private static final String INJECTED_HEADER_NAME = "X-Crlf-Injected";
    private static final String INJECTED_HEADER_VALUE = "anarcry-crlf-probe";

    @Override
    public String id() {
        return "CRLF";
    }

    @Override
    public List<Finding> scan(ScanContext ctx, Consumer<String> log) throws Exception {
        String _cweId = CweRegistry.cweId(id());
        String _cweTitle = CweRegistry.cweTitle(id());
        String _cveVector = CweRegistry.cvssVector(id());
        double _score = CvssCalculator.calculate(_cveVector);
        List<Finding> findings = new ArrayList<>();

        String scheme = ctx.isHttps() ? "https" : "http";
        int defPort = ctx.isHttps() ? 443 : 80;
        String baseUrl = scheme + "://" + ctx.host() + (ctx.port() != defPort ? ":" + ctx.port() : "");

        HttpClient hc = HttpClientFactory.noRedirect();
        log.accept("[~] CRLF: testando " + PAYLOADS.size() + " payloads de path em " + baseUrl);

        // Phase 1: path-based CRLF (existing payloads)
        for (String payload : PAYLOADS) {
            String url = baseUrl + payload;
            try {
                HttpRequest req = HttpRequest.newBuilder().uri(new URI(url)).timeout(Duration.ofSeconds(5)).GET()
                        .build();
                HttpResponse<Void> resp = Http.send(ctx, hc, req, HttpResponse.BodyHandlers.discarding(), id());

                boolean injected = resp.headers().map().entrySet().stream()
                        .anyMatch(e -> e.getKey().equalsIgnoreCase("set-cookie")
                                && e.getValue().stream().anyMatch(v -> v.contains("crlf=injection")));

                if (injected) {
                    log.accept("[!!] CRLF: CRÍTICO — injeção via path confirmada: " + payload);
                    findings.add(Finding.of("CRLF", url,
                            "CRLF Injection via path — cabeçalho HTTP arbitrário injetável", Severity.CRITICAL,
                            "Payload: " + payload + " | Set-Cookie: crlf=injection presente na resposta",
                            "Servidor não neutraliza CR (\\r / %0d) e LF (\\n / %0a) em paths refletidos "
                                    + "em cabeçalhos de resposta — permite injeção de cabeçalhos arbitrários, "
                                    + "cookies de sessão falsos, content-type spoofing e HTTP Response Splitting",
                            "curl -v '" + url + "'",
                            "Strip \\r (0x0d) e \\n (0x0a) de toda input usada em cabeçalhos HTTP; "
                                    + "usar encoding correto antes de incluir valores externos em cabeçalhos de"
                                    + "resposta",
                            _cweId, _cweTitle, _cveVector, _score));
                    return findings;
                }
            } catch (Exception e) {
                // URI parsing may reject some payloads — continue
            }
        }

        // Phase 2: Sprint 28 — CRLF via HTTP request headers (raw socket)
        // Java HttpClient rejects CRLF in header values, so we send raw bytes
        log.accept("[~] CRLF: testando injeção via " + INJECTABLE_HEADERS.size() + " request headers (raw socket)");
        Finding headerFinding = scanHeaderInjection(ctx, log);
        if (headerFinding != null) {
            findings.add(headerFinding);
        }

        if (findings.isEmpty()) {
            log.accept("[+] CRLF: nenhuma injeção detectada (path e headers)");
        }
        return findings;
    }

    // Sends raw HTTP request with CRLF injected into each of INJECTABLE_HEADERS.
    // Checks if the injected header name appears in the response headers.
    private Finding scanHeaderInjection(ScanContext ctx, Consumer<String> log) {
        String _cweId = CweRegistry.cweId(id());
        String _cweTitle = CweRegistry.cweTitle(id());
        String _cveVector = CweRegistry.cvssVector(id());
        double _score = CvssCalculator.calculate(_cveVector);
        String host = ctx.host();
        int port = ctx.port();
        // Value to inject: ends the current header and starts a new one
        String injected = "\r\n" + INJECTED_HEADER_NAME + ": " + INJECTED_HEADER_VALUE;

        for (String headerName : INJECTABLE_HEADERS) {
            try {
                String rawRequest = "GET / HTTP/1.1\r\n" + "Host: " + host + "\r\n" + headerName + ": Mozilla/5.0"
                        + injected + "\r\n" + "Connection: close\r\n" + "\r\n";

                String response = rawSocketSend(ctx, host, port, rawRequest, 5_000);
                if (response == null) {
                    continue;
                }

                // Check if our injected header name appears in response headers
                // (some servers echo request headers like User-Agent into response headers)
                String responseHeaders = response.contains("\r\n\r\n")
                        ? response.substring(0, response.indexOf("\r\n\r\n"))
                        : response;
                if (responseHeaders.toLowerCase().contains(INJECTED_HEADER_NAME.toLowerCase())) {
                    log.accept("[!!] CRLF: CRÍTICO — injeção via " + headerName + " refletida em response header");
                    return Finding.of("CRLF", ctx.targetUrl(),
                            "CRLF Injection via " + headerName + " — header injetado refletido na resposta",
                            Severity.CRITICAL,
                            "Header: " + headerName + " | CRLF + '" + INJECTED_HEADER_NAME + ": "
                                    + INJECTED_HEADER_VALUE + "' refletido nos cabeçalhos da resposta",
                            "Servidor reflete o valor do header " + headerName
                                    + " em cabeçalhos de resposta sem sanitização de CRLF — "
                                    + "permite injeção de cabeçalhos arbitrários: Set-Cookie malicioso, "
                                    + "content-type spoofing, HTTP Response Splitting",
                            "printf 'GET / HTTP/1.1\\r\\nHost: " + host + "\\r\\n" + headerName + ": Mozilla/5.0\\r\\n"
                                    + INJECTED_HEADER_NAME + ": " + INJECTED_HEADER_VALUE
                                    + "\\r\\nConnection: close\\r\\n\\r\\n' " + "| nc " + host + " " + port,
                            "Strip \\r e \\n de qualquer input usada para construir cabeçalhos HTTP de resposta",
                            _cweId, _cweTitle, _cveVector, _score);
                }
            } catch (Exception e) {
                // Continue with next header
            }
        }
        return null;
    }

    private String rawSocketSend(ScanContext ctx, String host, int port, String request, int timeoutMs)
            throws Exception {
        try (Socket socket = createSocket(ctx, host, port, timeoutMs)) {
            OutputStream out = socket.getOutputStream();
            out.write(request.getBytes(StandardCharsets.ISO_8859_1));
            out.flush();

            InputStream in = socket.getInputStream();
            byte[] buf = new byte[8192];
            int read = in.read(buf);
            if (read <= 0) {
                return null;
            }
            return new String(buf, 0, read, StandardCharsets.ISO_8859_1);
        }
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
