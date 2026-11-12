package gg.effront.anarcry.apiclient.auth;

import gg.effront.anarcry.apiclient.model.AuthConfig;
import gg.effront.anarcry.apiclient.model.HttpRequestDef;
import gg.effront.anarcry.apiclient.vars.VariableStore;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.TreeMap;
import java.util.stream.Collectors;

public class OAuth1Injector implements AuthInjector {

    private static final SecureRandom RNG = new SecureRandom();

    @Override
    public String mode() {
        return "oauth1";
    }

    @Override
    public HttpRequestDef inject(HttpRequestDef request, AuthConfig auth, VariableStore vars) {
        if (!(auth instanceof AuthConfig.OAuth1 o1)) {
            return request;
        }

        Map<String, String> oauthParams = new LinkedHashMap<>();
        oauthParams.put("oauth_consumer_key", o1.consumerKey());
        oauthParams.put("oauth_nonce", generateNonce());
        oauthParams.put("oauth_signature_method", "HMAC-SHA1");
        oauthParams.put("oauth_timestamp", String.valueOf(System.currentTimeMillis() / 1000));
        oauthParams.put("oauth_version", "1.0");
        if (o1.accessToken() != null && !o1.accessToken().isEmpty()) {
            oauthParams.put("oauth_token", o1.accessToken());
        }

        String baseUrl = request.url().split("\\?")[0];
        TreeMap<String, String> allParams = new TreeMap<>(oauthParams);
        for (var p : request.params().query()) {
            if (p.enabled()) {
                allParams.put(p.name(), p.value());
            }
        }

        String paramString = allParams.entrySet().stream().map(e -> encode(e.getKey()) + "=" + encode(e.getValue()))
                .collect(Collectors.joining("&"));

        String baseString = request.method().toUpperCase() + "&" + encode(baseUrl) + "&" + encode(paramString);

        String signingKey = encode(o1.consumerSecret()) + "&"
                + encode(o1.tokenSecret() != null ? o1.tokenSecret() : "");

        String signature = hmacSha1(signingKey, baseString);
        oauthParams.put("oauth_signature", signature);

        String header = "OAuth " + oauthParams.entrySet().stream()
                .map(e -> encode(e.getKey()) + "=\"" + encode(e.getValue()) + "\"").collect(Collectors.joining(", "));

        return AuthInjectorRegistry.addHeader(request, "Authorization", header);
    }

    private String generateNonce() {
        byte[] bytes = new byte[16];
        RNG.nextBytes(bytes);
        return HexFormat.of().formatHex(bytes);
    }

    private static String encode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8).replace("+", "%20").replace("*", "%2A").replace("%7E",
                "~");
    }

    private static String hmacSha1(String key, String data) {
        try {
            Mac mac = Mac.getInstance("HmacSHA1");
            mac.init(new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), "HmacSHA1"));
            byte[] raw = mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(raw);
        } catch (Exception e) {
            throw new RuntimeException("HMAC-SHA1 failed", e);
        }
    }
}
