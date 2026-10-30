package gg.effront.anarcry.scanner.util;

import gg.effront.anarcry.scanner.ScanContext;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
import java.util.regex.Pattern;

public final class WafEvasion {

    public enum Strategy {
        DOUBLE_ENCODE, CASE_MUTATION, UNICODE_NORMALIZE, CHARSET_EBCDIC, HPP
    }

    public static final List<Strategy> PROBE_ORDER = List.of(Strategy.DOUBLE_ENCODE, Strategy.CASE_MUTATION,
            Strategy.UNICODE_NORMALIZE, Strategy.CHARSET_EBCDIC, Strategy.HPP);

    private static final Pattern WAF_SERVER = Pattern
            .compile("(?i)(cloudflare|akamai|incapsula|sucuri|ddos-guard|awselb|imperva|f5|barracuda)");

    private static final Pattern WAF_BODY = Pattern
            .compile("(?i)(blocked|access denied|attention required|request blocked|"
                    + "web application firewall|security policy|not acceptable)");

    private WafEvasion() {
    }

    // -- Strategy implementations (GET-compatible: transform payload string) --

    public static String doubleEncode(String payload) {
        return URLEncoder.encode(payload, StandardCharsets.UTF_8);
    }

    public static String mutateCase(String payload) {
        StringBuilder sb = new StringBuilder(payload.length());
        boolean upper = true;
        for (char c : payload.toCharArray()) {
            if (Character.isLetter(c)) {
                sb.append(upper ? Character.toUpperCase(c) : Character.toLowerCase(c));
                upper = !upper;
            } else {
                sb.append(c);
            }
        }
        return sb.toString();
    }

    public static String toFullwidth(String payload) {
        StringBuilder sb = new StringBuilder(payload.length());
        for (char c : payload.toCharArray()) {
            if (c >= 0x21 && c <= 0x7E) {
                sb.append((char) (c + 0xFEE0));
            } else {
                sb.append(c);
            }
        }
        return sb.toString();
    }

    public static byte[] encodeEbcdic(String formBody) {
        return formBody.getBytes(Charset.forName("ibm500"));
    }

    // -- Apply a GET-compatible strategy to a payload string --

    public static String applyGetStrategy(Strategy s, String payload) {
        return switch (s) {
            case DOUBLE_ENCODE -> doubleEncode(payload);
            case CASE_MUTATION -> mutateCase(payload);
            case UNICODE_NORMALIZE -> toFullwidth(payload);
            default -> payload;
        };
    }

    // -- Convenience: return evasion-transformed payload if WAF detected --

    public static String evasionPayload(ScanContext ctx, String payload) {
        if (!ctx.wafState().isWafDetected()) {
            return payload;
        }
        Strategy s = ctx.wafState().effectiveStrategy();
        if (s == null) {
            return payload;
        }
        return applyGetStrategy(s, payload);
    }

    // -- POST-based EBCDIC request builder --

    public static HttpRequest buildEbcdicPost(String url, String param, String payload) {
        String formBody = param + "=" + payload;
        byte[] encoded = encodeEbcdic(formBody);
        return HttpRequest.newBuilder().uri(URI.create(url))
                .header("Content-Type", "application/x-www-form-urlencoded; charset=ibm500")
                .POST(HttpRequest.BodyPublishers.ofByteArray(encoded)).timeout(Duration.ofSeconds(8)).build();
    }

    // -- HPP URL builder --

    public static String buildHppUrl(String baseUrl, String param, String payload) {
        return baseUrl + "?" + param + "=safe&" + param + "=" + URLEncoder.encode(payload, StandardCharsets.UTF_8);
    }

    // -- WAF detection helpers --

    public static boolean isWafBlocked(int statusCode, String serverHeader, String body) {
        if (statusCode != 403 && statusCode != 406 && statusCode != 429) {
            return false;
        }
        if (serverHeader != null && WAF_SERVER.matcher(serverHeader).find()) {
            return true;
        }
        return body != null && WAF_BODY.matcher(body).find();
    }

    public static String detectWafProduct(String serverHeader) {
        if (serverHeader == null) {
            return "";
        }
        var m = WAF_SERVER.matcher(serverHeader);
        return m.find() ? m.group(1) : "";
    }

    // -- JS Challenge detection (Vercel / Cloudflare managed challenge) --

    public static boolean isJsChallenge(int statusCode, Map<String, List<String>> headers, String body) {
        return !detectChallengeType(statusCode, headers, body).isEmpty();
    }

    public static String detectChallengeType(int statusCode, Map<String, List<String>> headers, String body) {
        if (statusCode != 403 && statusCode != 503) {
            return "";
        }
        if ("challenge".equalsIgnoreCase(firstHeader(headers, "x-vercel-mitigated"))
                || (body != null && body.contains("Vercel Security Checkpoint"))) {
            return "Vercel Security Checkpoint";
        }
        if ("challenge".equalsIgnoreCase(firstHeader(headers, "cf-mitigated"))
                || (body != null && (body.contains("cf_chl_opt") || body.contains("cf-challenge-")))) {
            return "Cloudflare Managed Challenge";
        }
        return "";
    }

    private static String firstHeader(Map<String, List<String>> headers, String name) {
        for (var entry : headers.entrySet()) {
            if (name.equalsIgnoreCase(entry.getKey()) && !entry.getValue().isEmpty()) {
                return entry.getValue().getFirst();
            }
        }
        return "";
    }

    // -- Probe: try each strategy against target to find effective one --

    public static Strategy probeStrategies(ScanContext ctx, HttpClient hc, String targetUrl, String moduleId,
            Consumer<String> log) {
        String canary = "<script>alert(1)</script>";

        for (Strategy s : PROBE_ORDER) {
            try {
                HttpRequest req;
                if (s == Strategy.CHARSET_EBCDIC) {
                    req = buildEbcdicPost(targetUrl, "q", canary);
                } else if (s == Strategy.HPP) {
                    String url = buildHppUrl(targetUrl, "q", canary);
                    req = HttpRequest.newBuilder().uri(URI.create(url)).timeout(Duration.ofSeconds(6)).GET().build();
                } else {
                    String transformed = applyGetStrategy(s, canary);
                    String encoded = URLEncoder.encode(transformed, StandardCharsets.UTF_8);
                    String url = targetUrl + "?q=" + encoded;
                    req = HttpRequest.newBuilder().uri(URI.create(url)).timeout(Duration.ofSeconds(6)).GET().build();
                }
                HttpResponse<String> resp = Http.send(ctx, hc, req, HttpResponse.BodyHandlers.ofString(), moduleId);
                String server = resp.headers().firstValue("Server").orElse("");
                String body = resp.body() != null ? resp.body() : "";
                if (!isWafBlocked(resp.statusCode(), server, body)) {
                    if (s == Strategy.CHARSET_EBCDIC || s == Strategy.HPP) {
                        log.accept("[+] WAF bypass: " + s + " efetiva mas incompativel com GET inline"
                                + " -- requer construcao de request especifica");
                        continue;
                    }
                    log.accept("[+] WAF bypass: estrategia " + s + " efetiva (HTTP " + resp.statusCode() + ")");
                    return s;
                }
            } catch (Exception e) {
                log.accept("[-] WAF probe " + s + " falhou: " + e.getMessage());
            }
        }
        log.accept("[-] WAF bypass: nenhuma estrategia efetiva");
        return null;
    }
}
