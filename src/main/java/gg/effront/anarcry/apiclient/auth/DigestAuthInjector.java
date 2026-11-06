package gg.effront.anarcry.apiclient.auth;

import gg.effront.anarcry.apiclient.model.AuthConfig;
import gg.effront.anarcry.apiclient.model.HttpRequestDef;
import gg.effront.anarcry.apiclient.vars.VariableStore;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.HexFormat;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class DigestAuthInjector implements AuthInjector {

    private static final Pattern PARAM_PATTERN = Pattern.compile("(\\w+)=\"([^\"]*)\"");
    private static final SecureRandom RANDOM = new SecureRandom();
    private final AtomicInteger nonceCount = new AtomicInteger(1);
    private volatile DigestChallenge lastChallenge;

    public record DigestChallenge(String realm, String nonce, String qop, String opaque, String algorithm) {
    }

    @Override
    public String mode() {
        return "digest";
    }

    @Override
    public HttpRequestDef inject(HttpRequestDef request, AuthConfig auth, VariableStore vars) {
        if (!(auth instanceof AuthConfig.Digest digest)) {
            return request;
        }
        if (lastChallenge == null) {
            return request;
        }
        String header = computeDigestHeader(request.method(), extractUri(request.url()), digest.username(),
                digest.password(), lastChallenge);
        return AuthInjectorRegistry.addHeader(request, "Authorization", header);
    }

    public void setChallenge(DigestChallenge challenge) {
        this.lastChallenge = challenge;
        this.nonceCount.set(1);
    }

    public DigestChallenge challenge() {
        return lastChallenge;
    }

    public static DigestChallenge parseChallenge(String wwwAuthenticate) {
        if (wwwAuthenticate == null || !wwwAuthenticate.toLowerCase().startsWith("digest")) {
            return null;
        }
        String realm = null;
        String nonce = null;
        String qop = null;
        String opaque = null;
        String algorithm = "MD5";

        Matcher m = PARAM_PATTERN.matcher(wwwAuthenticate);
        while (m.find()) {
            switch (m.group(1).toLowerCase()) {
                case "realm" -> realm = m.group(2);
                case "nonce" -> nonce = m.group(2);
                case "qop" -> qop = m.group(2);
                case "opaque" -> opaque = m.group(2);
                case "algorithm" -> algorithm = m.group(2);
            }
        }
        if (realm == null || nonce == null) {
            return null;
        }
        return new DigestChallenge(realm, nonce, qop, opaque, algorithm);
    }

    public String computeDigestHeader(String method, String uri, String username, String password,
            DigestChallenge challenge) {
        String ha1 = md5(username + ":" + challenge.realm() + ":" + password);
        String ha2 = md5(method + ":" + uri);

        int nc = nonceCount.getAndIncrement();
        String ncHex = String.format("%08x", nc);
        byte[] cnonceBytes = new byte[8];
        RANDOM.nextBytes(cnonceBytes);
        String cnonce = HexFormat.of().formatHex(cnonceBytes);

        String response;
        if (challenge.qop() != null && challenge.qop().contains("auth")) {
            response = md5(ha1 + ":" + challenge.nonce() + ":" + ncHex + ":" + cnonce + ":auth:" + ha2);
        } else {
            response = md5(ha1 + ":" + challenge.nonce() + ":" + ha2);
        }

        StringBuilder sb = new StringBuilder("Digest ");
        sb.append("username=\"").append(username).append("\"");
        sb.append(", realm=\"").append(challenge.realm()).append("\"");
        sb.append(", nonce=\"").append(challenge.nonce()).append("\"");
        sb.append(", uri=\"").append(uri).append("\"");
        if (challenge.qop() != null) {
            sb.append(", qop=auth");
            sb.append(", nc=").append(ncHex);
            sb.append(", cnonce=\"").append(cnonce).append("\"");
        }
        sb.append(", response=\"").append(response).append("\"");
        if (challenge.opaque() != null) {
            sb.append(", opaque=\"").append(challenge.opaque()).append("\"");
        }
        sb.append(", algorithm=").append(challenge.algorithm());
        return sb.toString();
    }

    private static String extractUri(String url) {
        int schemeEnd = url.indexOf("://");
        if (schemeEnd < 0) {
            return url;
        }
        int pathStart = url.indexOf('/', schemeEnd + 3);
        return pathStart < 0 ? "/" : url.substring(pathStart);
    }

    @SuppressWarnings("java:S4790")
    private static String md5(String input) {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] digest = md.digest(input.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(digest);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("MD5 not available", e);
        }
    }
}
