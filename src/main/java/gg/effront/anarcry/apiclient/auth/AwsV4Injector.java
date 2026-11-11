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
import java.util.HexFormat;
import java.util.TreeMap;
import java.util.stream.Collectors;

public class AwsV4Injector implements AuthInjector {

    private static final DateTimeFormatter AMZ_DATE_FMT = DateTimeFormatter.ofPattern("yyyyMMdd'T'HHmmss'Z'")
            .withZone(ZoneOffset.UTC);
    private static final DateTimeFormatter DATE_FMT = DateTimeFormatter.ofPattern("yyyyMMdd").withZone(ZoneOffset.UTC);

    @Override
    public String mode() {
        return "awsv4";
    }

    @Override
    public HttpRequestDef inject(HttpRequestDef request, AuthConfig auth, VariableStore vars) {
        if (!(auth instanceof AuthConfig.AwsV4 aws)) {
            return request;
        }

        Instant now = Instant.now();
        String amzDate = AMZ_DATE_FMT.format(now);
        String dateStamp = DATE_FMT.format(now);

        URI uri = URI.create(request.url());
        String host = uri.getHost();
        if (uri.getPort() > 0 && uri.getPort() != 443 && uri.getPort() != 80) {
            host = host + ":" + uri.getPort();
        }
        String path = uri.getRawPath() != null && !uri.getRawPath().isEmpty() ? uri.getRawPath() : "/";
        String query = uri.getRawQuery() != null ? uri.getRawQuery() : "";

        String service = aws.service() != null && !aws.service().isEmpty() ? aws.service() : "execute-api";
        String region = aws.region() != null && !aws.region().isEmpty() ? aws.region() : "us-east-1";

        TreeMap<String, String> headers = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        headers.put("host", host);
        headers.put("x-amz-date", amzDate);
        if (aws.sessionToken() != null && !aws.sessionToken().isEmpty()) {
            headers.put("x-amz-security-token", aws.sessionToken());
        }

        String signedHeaders = headers.keySet().stream().map(String::toLowerCase).sorted()
                .collect(Collectors.joining(";"));
        String canonicalHeaders = headers.entrySet().stream().sorted(java.util.Map.Entry.comparingByKey())
                .map(e -> e.getKey().toLowerCase() + ":" + e.getValue().trim()).collect(Collectors.joining("\n"))
                + "\n";

        String payloadHash = sha256Hex("");
        String canonicalRequest = request.method().toUpperCase() + "\n" + path + "\n" + query + "\n" + canonicalHeaders
                + "\n" + signedHeaders + "\n" + payloadHash;

        String credentialScope = dateStamp + "/" + region + "/" + service + "/aws4_request";
        String stringToSign = "AWS4-HMAC-SHA256\n" + amzDate + "\n" + credentialScope + "\n"
                + sha256Hex(canonicalRequest);

        byte[] signingKey = getSignatureKey(aws.secretAccessKey(), dateStamp, region, service);
        String signature = HexFormat.of().formatHex(hmacSha256(signingKey, stringToSign));

        String authorization = "AWS4-HMAC-SHA256 Credential=" + aws.accessKeyId() + "/" + credentialScope
                + ", SignedHeaders=" + signedHeaders + ", Signature=" + signature;

        HttpRequestDef result = AuthInjectorRegistry.addHeader(request, "Authorization", authorization);
        result = AuthInjectorRegistry.addHeader(result, "X-Amz-Date", amzDate);
        if (aws.sessionToken() != null && !aws.sessionToken().isEmpty()) {
            result = AuthInjectorRegistry.addHeader(result, "X-Amz-Security-Token", aws.sessionToken());
        }
        return result;
    }

    private byte[] getSignatureKey(String key, String dateStamp, String region, String service) {
        byte[] kDate = hmacSha256(("AWS4" + key).getBytes(StandardCharsets.UTF_8), dateStamp);
        byte[] kRegion = hmacSha256(kDate, region);
        byte[] kService = hmacSha256(kRegion, service);
        return hmacSha256(kService, "aws4_request");
    }

    private static byte[] hmacSha256(byte[] key, String data) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            return mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            throw new RuntimeException("HMAC-SHA256 failed", e);
        }
    }

    private static String sha256Hex(String data) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(data.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 not available", e);
        }
    }
}
