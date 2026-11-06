package gg.effront.anarcry.apiclient.auth;

import gg.effront.anarcry.apiclient.model.AuthConfig;
import gg.effront.anarcry.apiclient.model.HttpRequestDef;
import gg.effront.anarcry.apiclient.vars.VariableStore;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.Base64;

public class WsseInjector implements AuthInjector {

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final DateTimeFormatter ISO_FMT = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss'Z'")
            .withZone(ZoneOffset.UTC);

    @Override
    public String mode() {
        return "wsse";
    }

    @Override
    public HttpRequestDef inject(HttpRequestDef request, AuthConfig auth, VariableStore vars) {
        if (!(auth instanceof AuthConfig.Wsse wsse)) {
            return request;
        }

        byte[] nonceBytes = new byte[16];
        RANDOM.nextBytes(nonceBytes);
        String nonceB64 = Base64.getEncoder().encodeToString(nonceBytes);
        String created = ISO_FMT.format(Instant.now());

        byte[] digestInput = concat(nonceBytes, created.getBytes(StandardCharsets.UTF_8),
                wsse.password().getBytes(StandardCharsets.UTF_8));
        String passwordDigest = Base64.getEncoder().encodeToString(sha1(digestInput));

        String header = "UsernameToken Username=\"" + wsse.username() + "\", PasswordDigest=\"" + passwordDigest
                + "\", Nonce=\"" + nonceB64 + "\", Created=\"" + created + "\"";

        HttpRequestDef withWsse = AuthInjectorRegistry.addHeader(request, "X-WSSE", header);
        return AuthInjectorRegistry.addHeader(withWsse, "Authorization", "WSSE profile=\"UsernameToken\"");
    }

    private static byte[] concat(byte[]... arrays) {
        int total = 0;
        for (byte[] a : arrays) {
            total += a.length;
        }
        byte[] result = new byte[total];
        int pos = 0;
        for (byte[] a : arrays) {
            System.arraycopy(a, 0, result, pos, a.length);
            pos += a.length;
        }
        return result;
    }

    @SuppressWarnings("java:S4790")
    private static byte[] sha1(byte[] input) {
        try {
            return MessageDigest.getInstance("SHA-1").digest(input);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-1 not available", e);
        }
    }
}
