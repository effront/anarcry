package gg.effront.anarcry.scanner.crypto.tls;

import gg.effront.anarcry.model.CvssCalculator;
import gg.effront.anarcry.model.CweRegistry;
import gg.effront.anarcry.model.Finding;
import gg.effront.anarcry.model.Severity;
import gg.effront.anarcry.scanner.ScanContext;
import gg.effront.anarcry.scanner.util.TlsUtil;

import javax.net.ssl.SSLException;
import javax.net.ssl.SSLSocket;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;

public class TlsVersionProbe {

    private static final int TIMEOUT_MS = 5000;

    private String id() {
        return "TLS";
    }

    public List<Finding> probe(ScanContext ctx, Consumer<String> log) {
        String _cweId = CweRegistry.cweId(id());
        String _cweTitle = CweRegistry.cweTitle(id());
        String _cveVector = CweRegistry.cvssVector(id());
        double _score = CvssCalculator.calculate(_cveVector);
        List<Finding> findings = new ArrayList<>();
        String host = ctx.host();
        int port = ctx.port();

        String[][] tests = {{"TLSv1", "HIGH", "-tls1"}, {"TLSv1.1", "MEDIUM", "-tls1_1"},};

        for (String[] test : tests) {
            String protocol = test[0];
            Severity severity = Severity.valueOf(test[1]);
            String flag = test[2];

            log.accept("[~] TLS: testando " + protocol + " em " + host + ":" + port);

            synchronized (TlsUtil.PROP_LOCK) {
                Runnable restore = TlsUtil.removeDisabled(protocol);
                try {
                    try (SSLSocket socket = TlsUtil.connectSocket(host, port, TlsUtil.sslContext(TlsUtil.trustAll()),
                            TIMEOUT_MS)) {
                        socket.setEnabledProtocols(new String[]{protocol});
                        socket.startHandshake();
                        // Confirm the server actually used the weak protocol, not a fallback
                        String actual = socket.getSession().getProtocol();
                        if (!actual.equals(protocol)) {
                            log.accept("[+] TLS: " + protocol + " -- servidor negociou " + actual + " (ok)");
                            continue;
                        }
                    }
                    log.accept("[!] TLS: " + protocol + " aceito pelo servidor");
                    findings.add(Finding.of("TLS", host + ":" + port, protocol + " habilitado no servidor", severity,
                            "Handshake bem-sucedido com " + protocol + " em " + host + ":" + port,
                            "Protocolo obsoleto sujeito a ataques BEAST/POODLE/downgrade",
                            "openssl s_client -connect " + host + ":" + port + " " + flag,
                            "Desabilitar TLS 1.0 e TLS 1.1 na configuração do servidor", _cweId, _cweTitle, _cveVector,
                            _score));
                } catch (SSLException e) {
                    log.accept("[+] TLS: " + protocol + " rejeitado (ok)");
                } catch (IOException e) {
                    log.accept("[?] TLS: " + protocol + " erro de conexão: " + e.getMessage());
                } catch (Exception e) {
                    log.accept("[?] TLS: " + protocol + " erro: " + e.getMessage());
                } finally {
                    restore.run();
                }
            }
        }
        return findings;
    }
}
