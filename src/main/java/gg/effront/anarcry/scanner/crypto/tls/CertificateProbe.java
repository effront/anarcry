package gg.effront.anarcry.scanner.crypto.tls;

import gg.effront.anarcry.model.CvssCalculator;
import gg.effront.anarcry.model.CweRegistry;
import gg.effront.anarcry.model.Finding;
import gg.effront.anarcry.model.Severity;
import gg.effront.anarcry.scanner.ScanContext;
import gg.effront.anarcry.scanner.util.TlsUtil;

import javax.net.ssl.SSLSocket;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.function.Consumer;

public class CertificateProbe {

    private static final int TIMEOUT_MS = 8000;

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

        log.accept("[~] CERT: inspecionando certificado de " + host + ":" + port);

        try {
            SSLSocket socket = TlsUtil.connectSocket(host, port, TlsUtil.sslContext(TlsUtil.trustAll()), TIMEOUT_MS);
            socket.startHandshake();

            Certificate[] certs = socket.getSession().getPeerCertificates();
            socket.close();

            if (certs.length == 0) {
                log.accept("[?] CERT: nenhum certificado retornado");
                return findings;
            }

            X509Certificate cert = (X509Certificate) certs[0];
            Date now = new Date();
            Date expiry = cert.getNotAfter();
            String subject = cert.getSubjectX500Principal().getName();
            String issuer = cert.getIssuerX500Principal().getName();
            String evidence = "Subject: " + subject + " | Issuer: " + issuer + " | Expira: " + expiry + " | Alg: "
                    + cert.getSigAlgName();

            if (expiry.before(now)) {
                log.accept("[!] CERT: certificado expirado em " + expiry);
                findings.add(Finding.of("TLS", host + ":" + port, "Certificado SSL expirado", Severity.CRITICAL,
                        evidence, "Conexões serão rejeitadas por clientes que validam certificados",
                        "Verificar data de expiração: openssl s_client -connect " + host + ":" + port
                                + " | openssl x509 -noout -dates",
                        "Renovar o certificado imediatamente", _cweId, _cweTitle, _cveVector, _score));
            } else {
                long thirtyDays = 30L * 24 * 3600 * 1000;
                if (expiry.before(new Date(now.getTime() + thirtyDays))) {
                    log.accept("[!] CERT: certificado expira em breve: " + expiry);
                    findings.add(
                            Finding.of("TLS", host + ":" + port, "Certificado SSL expirando em breve", Severity.HIGH,
                                    evidence, "Certificado expira em menos de 30 dias — risco de indisponibilidade",
                                    "openssl s_client -connect " + host + ":" + port + " | openssl x509 -noout -dates",
                                    "Renovar o certificado antes da expiração", _cweId, _cweTitle, _cveVector, _score));
                }
            }

            if (issuer.equals(subject)) {
                log.accept("[!] CERT: certificado auto-assinado");
                findings.add(Finding.of("TLS", host + ":" + port, "Certificado auto-assinado", Severity.MEDIUM,
                        evidence, "Não validado por CA confiável — usuários receberão aviso de segurança",
                        "openssl s_client -connect " + host + ":" + port + " -showcerts",
                        "Emitir certificado por CA reconhecida (ex: Let's Encrypt)", _cweId, _cweTitle, _cveVector,
                        _score));
            }

            if (cert.getPublicKey() instanceof RSAPublicKey rsa) {
                int bits = rsa.getModulus().bitLength();
                if (bits < 2048) {
                    log.accept("[!] CERT: chave RSA fraca — " + bits + " bits");
                    findings.add(Finding.of("TLS", host + ":" + port, "Chave RSA fraca (< 2048 bits)", Severity.HIGH,
                            evidence + " | Tamanho chave: " + bits + " bits",
                            "Chave RSA < 2048 bits é vulnerável a fatoração",
                            "openssl s_client -connect " + host + ":" + port
                                    + " | openssl x509 -noout -text | grep 'Public-Key'",
                            "Gerar nova chave RSA de 2048 ou 4096 bits (ou usar EC)", _cweId, _cweTitle, _cveVector,
                            _score));
                }
            }

            if (cert.getSigAlgName().toUpperCase().contains("SHA1")) {
                log.accept("[!] CERT: algoritmo de assinatura SHA-1 detectado");
                findings.add(Finding.of("TLS", host + ":" + port, "Certificado assinado com SHA-1", Severity.MEDIUM,
                        evidence, "SHA-1 é considerado criptograficamente fraco desde 2017",
                        "openssl s_client -connect " + host + ":" + port
                                + " | openssl x509 -noout -text | grep 'Signature Algorithm'",
                        "Reemitir certificado com SHA-256 ou superior", _cweId, _cweTitle, _cveVector, _score));
            }

            if (findings.isEmpty()) {
                log.accept("[+] CERT: sem problemas encontrados no certificado");
            }
        } catch (Exception e) {
            log.accept("[!] CERT: erro ao inspecionar certificado: " + e.getMessage());
        }
        return findings;
    }
}
