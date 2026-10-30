package gg.effront.anarcry.scanner.crypto.pqc;

import gg.effront.anarcry.model.CvssCalculator;
import gg.effront.anarcry.model.CweRegistry;
import gg.effront.anarcry.model.Finding;
import gg.effront.anarcry.model.Severity;
import gg.effront.anarcry.scanner.ScanContext;
import gg.effront.anarcry.scanner.Scanner;
import gg.effront.anarcry.scanner.util.TlsUtil;

import javax.net.ssl.SSLSocket;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;

public class PqcModule implements Scanner {

    private static final int TIMEOUT_MS = 8000;

    @Override
    public String id() {
        return "PQC";
    }

    @Override
    public List<Finding> scan(ScanContext ctx, Consumer<String> log) throws Exception {
        String _cweId = CweRegistry.cweId(id());
        String _cweTitle = CweRegistry.cweTitle(id());
        String _cveVector = CweRegistry.cvssVector(id());
        double _score = CvssCalculator.calculate(_cveVector);
        String _infoVector = CvssCalculator.defaultVector(Severity.INFO);
        double _infoScore = 0.0;
        List<Finding> findings = new ArrayList<>();

        if (!ctx.isHttps()) {
            log.accept("[~] PQC: alvo não é HTTPS -- módulo ignorado");
            return findings;
        }

        String host = ctx.host();
        int port = ctx.port();
        String evidence = host + ":" + port;

        // Step 1: TLS 1.3 support (prerequisite for PQC)
        log.accept("[~] PQC: verificando suporte a TLS 1.3 em " + evidence);
        boolean tls13ok = false;
        try {
            String proto;
            String cipher;
            try (SSLSocket socket = TlsUtil.connectSocket(host, port, TlsUtil.sslContext(TlsUtil.trustAll()),
                    TIMEOUT_MS)) {
                socket.setEnabledProtocols(new String[]{"TLSv1.3"});
                socket.startHandshake();
                proto = socket.getSession().getProtocol();
                cipher = socket.getSession().getCipherSuite();
            }
            tls13ok = true;
            log.accept("[+] PQC: TLS 1.3 suportado -- cipher: " + cipher);
            findings.add(Finding.of("PQC", host + ":" + port, "TLS 1.3 suportado -- base para PQC", Severity.INFO,
                    "Protocolo: " + proto + " | Cipher: " + cipher + " | Host: " + evidence,
                    "TLS 1.3 é prerequisito para negociação de grupos pós-quânticos",
                    "openssl s_client -connect " + host + ":" + port + " -tls1_3",
                    "Habilitar grupos pós-quânticos (ex: X25519MLKEM768) para proteção futura", _cweId, _cweTitle,
                    _infoVector, _infoScore));
        } catch (Exception e) {
            log.accept("[!] PQC: TLS 1.3 não suportado: " + e.getMessage());
            findings.add(Finding.of("PQC", host + ":" + port, "TLS 1.3 não suportado -- PQC indisponível", Severity.LOW,
                    "Erro: " + e.getMessage() + " | Host: " + evidence,
                    "Sem TLS 1.3, não é possível negociar grupos de chaves pós-quânticas",
                    "openssl s_client -connect " + host + ":" + port + " -tls1_3",
                    "Habilitar TLS 1.3 no servidor como prerequisito para PQC", _cweId, _cweTitle, _cveVector, _score));
        }

        // Step 2: X25519MLKEM768 probe (Java 27 PQC -- JEP 496)
        if (tls13ok) {
            log.accept("[~] PQC: testando X25519MLKEM768 (ML-KEM-768 híbrido)");
            String namedGroupsProp = "jdk.tls.namedGroups";
            String original = System.getProperty(namedGroupsProp, "");
            try {
                System.setProperty(namedGroupsProp, "X25519MLKEM768, x25519, secp256r1");
                try (SSLSocket socket = TlsUtil.connectSocket(host, port, TlsUtil.sslContext(TlsUtil.trustAll()),
                        TIMEOUT_MS)) {
                    socket.setEnabledProtocols(new String[]{"TLSv1.3"});
                    socket.startHandshake();
                }
                log.accept("[+] PQC: X25519MLKEM768 aceito pelo servidor");
                findings.add(Finding.of("PQC", host + ":" + port, "X25519MLKEM768 (PQC híbrido) suportado",
                        Severity.INFO, "Grupo de chave X25519MLKEM768 negociado com " + evidence,
                        "O servidor suporta troca de chaves resistente a computadores quânticos",
                        "openssl s_client -connect " + host + ":" + port + " -groups X25519MLKEM768",
                        "Manter suporte a X25519MLKEM768 e acompanhar padronização NIST PQC", _cweId, _cweTitle,
                        _infoVector, _infoScore));
            } catch (Exception e) {
                log.accept("[~] PQC: X25519MLKEM768 não suportado: " + e.getMessage());
                findings.add(
                        Finding.of("PQC", host + ":" + port, "X25519MLKEM768 não suportado -- considerar migração PQC",
                                Severity.INFO, "X25519MLKEM768 rejeitado ou não suportado em " + evidence,
                                "O servidor não suporta troca de chaves híbrida pós-quântica",
                                "Verificar suporte: openssl s_client -connect " + host + ":" + port
                                        + " -groups X25519MLKEM768",
                                "Avaliar migração para grupos pós-quânticos (NIST ML-KEM) para proteção a longo prazo",
                                _cweId, _cweTitle, _cveVector, _score));
            } finally {
                if (original.isBlank()) {
                    System.clearProperty(namedGroupsProp);
                } else {
                    System.setProperty(namedGroupsProp, original);
                }
            }
        }

        return findings;
    }
}
