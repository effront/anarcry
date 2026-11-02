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

        // ── Phase 1: CL.TE ──
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
        }

        // ── Phase 2: TE.CL ──
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
        }

        // ── Phase 3: TE.TE obfuscation ──
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

        // ── Phase 4: Duplicate Content-Length ──
        log.accept("[~] ReqSmuggling: testando Duplicate Content-Length em " + host + ":" + port);
        boolean duplCl = probeDuplicateContentLength(ctx, host, port);
        if (duplCl) {
            log.accept("[!] ReqSmuggling: HIGH -- servidor aceita Content-Length duplicado");
            findings.add(Finding.of("ReqSmuggling", ctx.targetUrl(),
                    "HTTP Request Smuggling -- Duplicate Content-Length aceito", Severity.HIGH,
                    "Servidor aceitou request com dois headers Content-Length divergentes (0 e 42) "
                            + "sem rejeitar com 400 -- indica parser que escolhe um dos valores, "
                            + "criando discrepância explorável entre proxy e backend",
                    "Parser que aceita Content-Length duplicado pode permitir smuggling quando "
                            + "proxy e backend escolhem valores diferentes. " + "Ref: HAProxy CVE-2021-40346.",
                    "printf 'GET / HTTP/1.1\\r\\nHost: " + host + "\\r\\n"
                            + "Content-Length: 0\\r\\nContent-Length: 42\\r\\n" + "Connection: close\\r\\n\\r\\n' | nc "
                            + host + " " + port,
                    "Rejeitar com 400 qualquer request contendo headers Content-Length duplicados "
                            + "com valores divergentes (RFC 9112 Section 6.3)",
                    _cweId, _cweTitle, _cveVector, _score));
        }

        // ── Phase 5: CL.0 desync ──
        log.accept("[~] ReqSmuggling: testando CL.0 desync em " + host + ":" + port);
        boolean cl0 = probeCl0(ctx, host, port);
        if (cl0) {
            log.accept("[!!] ReqSmuggling: CRITICAL -- CL.0 desync confirmado (duas respostas para um send)");
            findings.add(Finding.of("ReqSmuggling", ctx.targetUrl(), "HTTP Request Smuggling -- CL.0 desync",
                    Severity.CRITICAL,
                    "CL.0 probe: POST com Content-Length contendo request smuggled no body "
                            + "gerou duas respostas HTTP na mesma conexão -- backend ignorou o body "
                            + "e os bytes restantes foram interpretados como nova requisição",
                    "Backend ignora Content-Length e responde antes de consumir o body. "
                            + "Bytes não consumidos viram o início da próxima requisição na mesma conexão, "
                            + "permitindo request hijacking, bypass de ACL e cache poisoning. "
                            + "Não requer Content-Length + Transfer-Encoding -- funciona com CL sozinho.",
                    "# Probe CL.0 -- envia via socket raw (keep-alive):\n" + "printf 'POST / HTTP/1.1\\r\\nHost: "
                            + host + "\\r\\n" + "Content-Length: <N>\\r\\nConnection: keep-alive\\r\\n\\r\\n"
                            + "GET /admin HTTP/1.1\\r\\nHost: " + host + "\\r\\n\\r\\n' | nc " + host + " " + port,
                    "Garantir que o backend consome o body completo antes de responder; "
                            + "não reutilizar conexões quando o body não foi totalmente lido; "
                            + "configurar proxy para fechar conexão após early response",
                    _cweId, _cweTitle, _cveVector, _score));
        }

        // ── Phase 6: Hop-by-hop TE confusion ──
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
                            + "Backend recebe request sem TE e usa CL, criando parser differential explorável. "
                            + "Ref: Akamai CVE-2026-26365.",
                    "# Probe hop-by-hop TE:\n" + "printf 'POST / HTTP/1.1\\r\\nHost: " + host + "\\r\\n"
                            + "Content-Length: 8\\r\\nConnection: Transfer-Encoding\\r\\n"
                            + "Transfer-Encoding: chunked\\r\\n\\r\\n" + "5\\r\\nHELLO' | nc " + host + " " + port,
                    "Não tratar Transfer-Encoding como hop-by-hop header; "
                            + "rejeitar requests onde Connection lista Transfer-Encoding",
                    _cweId, _cweTitle, _cveVector, _score));
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
            if (sp < 0 || sp + 3 > resp.length()) {
                return false;
            }
            return resp.charAt(sp + 1) == '2';
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
