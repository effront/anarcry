package gg.effront.anarcry.scanner.web.smuggling;

import gg.effront.anarcry.model.Finding;
import gg.effront.anarcry.model.Severity;
import gg.effront.anarcry.scanner.ScanContext;
import gg.effront.anarcry.scanner.Scanner;
import gg.effront.anarcry.scanner.util.TlsUtil;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;
import gg.effront.anarcry.model.CweRegistry;
import gg.effront.anarcry.model.CvssCalculator;

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
            log.accept("[~] ReqSmuggling: servidor não respondeu ao baseline -- pulando");
            return findings;
        }

        // CL.TE probe -- CL says 4 bytes, TE body is 8 bytes (complete chunked)
        // If frontend uses CL: forwards 4 bytes → backend (TE) gets "1\r\nA" →
        // incomplete chunk → hangs
        boolean clTeTimeout = sendProbeAndCheckTimeout(ctx, host, port, buildClTeProbe(host), PROBE_TIMEOUT_MS);
        if (clTeTimeout) {
            log.accept("[!!] ReqSmuggling: CRITICAL -- CL.TE desync confirmado (probe excedeu " + PROBE_TIMEOUT_MS
                    + "ms vs baseline < " + BASELINE_TIMEOUT_MS + "ms)");
            findings.add(Finding.of("ReqSmuggling", ctx.targetUrl(), "HTTP Request Smuggling -- CL.TE desync",
                    Severity.CRITICAL,
                    "CL.TE timing probe: POST com Content-Length=4 e Transfer-Encoding=chunked (corpo de 8 bytes) "
                            + "causou timeout de " + PROBE_TIMEOUT_MS + "ms -- backend usa TE e ficou aguardando "
                            + "bytes de chunk que o frontend (usa CL) não repassou",
                    "Frontend e backend discordam sobre como interpretar Content-Length vs Transfer-Encoding. "
                            + "Um atacante pode 'contrabandear' requests parciais no buffer do backend, "
                            + "causando request hijacking, bypass de controles de acesso, e Account Takeover.",
                    "# Probe CL.TE -- envia via socket raw (nc/openssl):\n" + "printf 'POST / HTTP/1.1\\r\\nHost: "
                            + host + "\\r\\n" + "Content-Length: 4\\r\\nTransfer-Encoding: chunked\\r\\n\\r\\n"
                            + "1\\r\\nA\\r\\n0\\r\\n\\r\\n' | nc " + host + " " + port,
                    "Normalizar requests ambíguos no proxy/load-balancer: rejeitar com 400 qualquer request "
                            + "que contenha tanto Content-Length quanto Transfer-Encoding; "
                            + "ou reescrever para usar apenas um dos dois",
                    _cweId, _cweTitle, _cveVector, _score));
            return findings;
        }

        // TE.CL probe -- TE body completa, CL diz 1 byte
        // Se frontend usa TE: processa chunked completo → backend (usa CL) lê 1 byte →
        // resto vaza
        boolean teCLTimeout = sendProbeAndCheckTimeout(ctx, host, port, buildTeCLProbe(host), PROBE_TIMEOUT_MS);
        if (teCLTimeout) {
            log.accept("[!!] ReqSmuggling: CRITICAL -- TE.CL desync confirmado");
            findings.add(Finding.of("ReqSmuggling", ctx.targetUrl(), "HTTP Request Smuggling -- TE.CL desync",
                    Severity.CRITICAL,
                    "TE.CL timing probe: POST com Transfer-Encoding=chunked e Content-Length=1 " + "causou timeout de "
                            + PROBE_TIMEOUT_MS + "ms -- backend usa CL e ficou aguardando "
                            + "dados que o frontend (usa TE) não repassou completamente",
                    "Frontend e backend discordam sobre como interpretar Transfer-Encoding vs Content-Length. "
                            + "Permite HTTP request smuggling com impacto equivalente ao CL.TE.",
                    "# Probe TE.CL -- envia via socket raw:\n" + "printf 'POST / HTTP/1.1\\r\\nHost: " + host + "\\r\\n"
                            + "Content-Length: 1\\r\\nTransfer-Encoding: chunked\\r\\n\\r\\n"
                            + "1\\r\\nA\\r\\n0\\r\\n\\r\\n' | nc " + host + " " + port,
                    "Normalizar requests ambíguos no proxy: rejeitar 400 para Content-Length + Transfer-Encoding",
                    _cweId, _cweTitle, _cveVector, _score));
            return findings;
        }

        // TE.TE obfuscation -- se ambos processam TE mas um fica confuso com
        // obfuscation
        String verdict = probeTeTeObfuscation(ctx, host, port, log);
        if (verdict != null) {
            log.accept("[!!] ReqSmuggling: HIGH -- TE.TE obfuscation aceito pelo servidor: " + verdict);
            findings.add(Finding.of("ReqSmuggling", ctx.targetUrl(),
                    "HTTP Request Smuggling -- TE.TE obfuscation (" + verdict + ")", Severity.HIGH,
                    "Probe com Transfer-Encoding obfuscado '" + verdict + "' causou timeout de " + PROBE_TIMEOUT_MS
                            + "ms -- servidor processou TE obfuscado como chunked e ficou "
                            + "aguardando chunk terminal (baseline respondeu em < " + BASELINE_TIMEOUT_MS + "ms)",
                    "Frontend ou backend aceitou Transfer-Encoding com valor não-padrão -- "
                            + "atacante pode usar a ambiguidade para smuggling de requests.",
                    "printf 'POST / HTTP/1.1\\r\\nHost: " + host + "\\r\\n"
                            + "Content-Length: 8\\r\\nTransfer-Encoding: " + verdict + "\\r\\n\\r\\n"
                            + "5\\r\\nHELLO' | openssl s_client -connect " + host + ":" + port + " -quiet",
                    "Rejeitar Transfer-Encoding com valores não-padrão (xchunked, identity com TE duplo etc.)", _cweId,
                    _cweTitle, _cveVector, _score));
        }

        if (findings.isEmpty()) {
            log.accept("[+] ReqSmuggling: nenhum desync detectado");
        }
        return findings;
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
    // Frontend (uses TE) processes full chunked body → backend (uses CL) expects 1
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

    private String probeTeTeObfuscation(ScanContext ctx, String host, int port, Consumer<String> log) {
        List<String> variants = List.of("xchunked", "chunked, chunked", "chunked\t");
        for (String variant : variants) {
            // Body is "5\r\nHELLO" = 8 bytes. CL matches the raw body length so servers
            // that ignore the obfuscated TE and use CL get a complete request and respond.
            // Servers that treat the obfuscated TE as chunked see an incomplete chunk
            // (missing terminating 0\r\n\r\n) and hang.
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
                return variant;
            }
        }
        return null;
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
