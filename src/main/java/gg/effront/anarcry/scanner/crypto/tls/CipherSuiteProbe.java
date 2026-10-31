package gg.effront.anarcry.scanner.crypto.tls;

import gg.effront.anarcry.model.CvssCalculator;
import gg.effront.anarcry.model.CweRegistry;
import gg.effront.anarcry.model.Finding;
import gg.effront.anarcry.model.Severity;
import gg.effront.anarcry.scanner.ScanContext;
import gg.effront.anarcry.scanner.util.TlsUtil;

import javax.net.ssl.SSLSocket;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.function.Consumer;
import java.util.function.Predicate;

public class CipherSuiteProbe {

    private static final int TIMEOUT_MS = 5000;

    private String id() {
        return "TLS";
    }

    private record CipherGroup(String name, String disabledTerm, Predicate<String> matcher, Severity severity,
            String title, String impact, String opensslFlag) {
    }

    private static final List<CipherGroup> GROUPS = List.of(
            new CipherGroup("RC4", "RC4", c -> c.contains("RC4"), Severity.HIGH, "Cipher suite RC4 aceito",
                    "RC4 é criptograficamente quebrado -- vulnerável a ataques de desvio estatístico", "-cipher RC4"),
            new CipherGroup("NULL", "NULL", c -> c.contains("_NULL_") || c.contains("WITH_NULL"), Severity.CRITICAL,
                    "Cipher suite NULL aceito",
                    "Cipher NULL não fornece confidencialidade -- dados transmitidos em claro", "-cipher NULL"),
            new CipherGroup("ANON", "anon", c -> c.contains("_anon_") || c.contains("_DHE_anon"), Severity.CRITICAL,
                    "Cipher suite anônimo aceito", "Cipher anônimo não autentica o servidor -- vulnerável a MITM",
                    "-cipher aNULL"),
            new CipherGroup("3DES", "3DES_EDE_CBC", c -> c.contains("_3DES_"), Severity.HIGH,
                    "Cipher suite 3DES aceito",
                    "3DES vulnerável ao SWEET32 (CVE-2016-2183) -- colisão de bloco após ~768GB de dados",
                    "-cipher 3DES"),
            new CipherGroup("EXPORT", "EXPORT", c -> c.contains("EXPORT") || c.contains("_40_"), Severity.HIGH,
                    "Cipher suite EXPORT aceito",
                    "Ciphers EXPORT foram deliberadamente enfraquecidos (40-56 bits) -- FREAK/DROWN/LOGJAM",
                    "-cipher EXPORT"));

    public static List<String> groupNames() {
        return GROUPS.stream().map(CipherGroup::name).toList();
    }

    public List<Finding> probe(ScanContext ctx, Consumer<String> log) {
        String _cweId = CweRegistry.cweId(id());
        String _cweTitle = CweRegistry.cweTitle(id());
        String _cveVector = CweRegistry.cvssVector(id());
        double _score = CvssCalculator.calculate(_cveVector);
        List<Finding> findings = new ArrayList<>();
        String host = ctx.host();
        int port = ctx.port();

        for (CipherGroup group : GROUPS) {
            log.accept("[~] CIPHER: testando " + group.name() + " em " + host + ":" + port);

            synchronized (TlsUtil.PROP_LOCK) {
                Runnable restore = TlsUtil.removeDisabled(group.disabledTerm());
                try {
                    String[] supported;
                    try (SSLSocket probe = TlsUtil.connectSocket(host, port, TlsUtil.sslContext(TlsUtil.trustAll()),
                            TIMEOUT_MS)) {
                        supported = probe.getSupportedCipherSuites();
                    }

                    String[] weak = Arrays.stream(supported).filter(group.matcher()).toArray(String[]::new);

                    if (weak.length == 0) {
                        log.accept("[+] CIPHER: " + group.name() + " -- nenhum cipher disponível localmente");
                        continue;
                    }

                    String negotiated;
                    try (SSLSocket socket = TlsUtil.connectSocket(host, port, TlsUtil.sslContext(TlsUtil.trustAll()),
                            TIMEOUT_MS)) {
                        socket.setEnabledCipherSuites(weak);
                        socket.startHandshake();
                        negotiated = socket.getSession().getCipherSuite();
                    }

                    log.accept("[!] CIPHER: " + group.name() + " aceito -- " + negotiated);
                    findings.add(Finding.of("TLS", host + ":" + port, group.title(), group.severity(),
                            "Negociação bem-sucedida: " + negotiated + " em " + host + ":" + port, group.impact(),
                            "openssl s_client -connect " + host + ":" + port + " " + group.opensslFlag(),
                            "Desabilitar cipher suites " + group.name() + " na configuração TLS do servidor", _cweId,
                            _cweTitle, _cveVector, _score));
                } catch (Exception e) {
                    log.accept("[+] CIPHER: " + group.name() + " rejeitado (ok): " + e.getMessage());
                } finally {
                    restore.run();
                }
            }
        }
        return findings;
    }
}
