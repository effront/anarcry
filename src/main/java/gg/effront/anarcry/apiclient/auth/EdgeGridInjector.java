package gg.effront.anarcry.apiclient.auth;

import gg.effront.anarcry.apiclient.model.AuthConfig;
import gg.effront.anarcry.apiclient.model.HttpRequestDef;
import gg.effront.anarcry.apiclient.vars.VariableStore;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.Base64;
import java.util.UUID;

public class EdgeGridInjector implements AuthInjector {

    private static final DateTimeFormatter TS_FMT = DateTimeFormatter.ofPattern("yyyyMMdd'T'HH:mm:ss+0000")
            .withZone(ZoneOffset.UTC);

    @Override
    public String mode() {
        return "akamai-edgegrid";
    }

    @Override
    public HttpRequestDef inject(HttpRequestDef request, AuthConfig auth, VariableStore vars) {
        if (!(auth instanceof AuthConfig.EdgeGrid eg)) {
            return request;
        }

        String timestamp = TS_FMT.format(Instant.now());
        String nonce = UUID.randomUUID().toString();

        URI uri = URI.create(request.url());
        String path = uri.getRawPath() != null ? uri.getRawPath() : "/";
        if (uri.getRawQuery() != null) {
            path = path + "?" + uri.getRawQuery();
        }

        String authHeader = "EG1-HMAC-SHA256 client_token=" + eg.clientToken() + ";access_token=" + eg.accessToken()
                + ";timestamp=" + timestamp + ";nonce=" + nonce + ";";

        String contentHash = sha256Base64("");
        String dataToSign = request.method().toUpperCase() + "\thttps\t" + uri.getHost() + "\t" + path + "\t\t"
                + contentHash + "\t" + authHeader;

        byte[] signingKey = hmacSha256(Base64.getDecoder().decode(eg.clientSecret()),
                timestamp.getBytes(StandardCharsets.UTF_8));
        String signature = Base64.getEncoder()
                .encodeToString(hmacSha256(signingKey, dataToSign.getBytes(StandardCharsets.UTF_8)));

        return AuthInjectorRegistry.addHeader(request, "Authorization", authHeader + "signature=" + signature);
    }

    private static String sha256Base64(String data) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(data.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 not available", e);
        }
    }

    private static byte[] hmacSha256(byte[] key, byte[] data) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            return mac.doFinal(data);
        } catch (Exception e) {
            throw new RuntimeException("HMAC-SHA256 failed", e);
        }
    }
}
