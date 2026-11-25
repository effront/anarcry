package gg.effront.anarcry.fuzzer;

import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.regex.Pattern;

public final class PayloadProcessors {

    private PayloadProcessors() {
    }

    public static PayloadProcessor prefix(String prefix) {
        return input -> prefix + input;
    }

    public static PayloadProcessor suffix(String suffix) {
        return input -> input + suffix;
    }

    public static PayloadProcessor urlEncode() {
        return input -> URLEncoder.encode(input, StandardCharsets.UTF_8);
    }

    public static PayloadProcessor urlDecode() {
        return input -> {
            try {
                return URLDecoder.decode(input, StandardCharsets.UTF_8);
            } catch (Exception e) {
                return input;
            }
        };
    }

    public static PayloadProcessor base64Encode() {
        return input -> Base64.getEncoder().encodeToString(input.getBytes(StandardCharsets.UTF_8));
    }

    public static PayloadProcessor base64Decode() {
        return input -> {
            try {
                return new String(Base64.getDecoder().decode(input), StandardCharsets.UTF_8);
            } catch (Exception e) {
                return input;
            }
        };
    }

    public static PayloadProcessor htmlEncode() {
        return input -> input.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
                .replace("'", "&#x27;");
    }

    public static PayloadProcessor htmlDecode() {
        return input -> input.replace("&amp;", "&").replace("&lt;", "<").replace("&gt;", ">").replace("&quot;", "\"")
                .replace("&#x27;", "'");
    }

    public static PayloadProcessor hash(String algorithm) {
        return input -> {
            try {
                MessageDigest md = MessageDigest.getInstance(algorithm);
                byte[] digest = md.digest(input.getBytes(StandardCharsets.UTF_8));
                return HexFormat.of().formatHex(digest);
            } catch (Exception e) {
                return input;
            }
        };
    }

    public static PayloadProcessor matchReplace(String regex, String replacement) {
        Pattern p = Pattern.compile(regex);
        return input -> p.matcher(input).replaceAll(replacement);
    }

    public static PayloadProcessor skipIfMatches(String regex) {
        Pattern p = Pattern.compile(regex);
        return input -> p.matcher(input).find() ? null : input;
    }

    public static String applyPipeline(String payload, List<PayloadProcessor> processors) {
        String result = payload;
        for (PayloadProcessor proc : processors) {
            result = proc.process(result);
            if (result == null) {
                return null;
            }
        }
        return result;
    }

    public static final String[] AVAILABLE = {"Add prefix", "Add suffix", "URL encode", "URL decode", "Base64 encode",
            "Base64 decode", "HTML encode", "HTML decode", "Hash MD5", "Hash SHA-1", "Hash SHA-256", "Hash SHA-512",
            "Match/replace", "Skip if matches"};
}
