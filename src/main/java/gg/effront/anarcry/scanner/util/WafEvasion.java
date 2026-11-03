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
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.function.Consumer;
import java.util.regex.Pattern;

public final class WafEvasion {

    public enum Strategy {
        DOUBLE_ENCODE, CASE_MUTATION, UNICODE_NORMALIZE, CHARSET_EBCDIC, HPP
    }

    public static final List<Strategy> PROBE_ORDER = List.of(Strategy.DOUBLE_ENCODE, Strategy.CASE_MUTATION,
            Strategy.UNICODE_NORMALIZE, Strategy.CHARSET_EBCDIC, Strategy.HPP);

    public enum SignalType {
        COOKIE, HEADER, URL, CONTENT
    }

    public record WafSignal(SignalType type, String pattern, int confidence) {
    }

    public record WafSignature(String id, String name, String category, List<WafSignal> signals) {
    }

    public record WafDetection(String id, String name, String category, int confidence, List<String> hits) {
    }

    private static final Pattern WAF_SERVER = Pattern
            .compile("(?i)(cloudflare|akamai|incapsula|sucuri|ddos-guard|awselb|imperva|f5|barracuda)");

    private static final Pattern WAF_BODY = Pattern
            .compile("(?i)(blocked|access denied|attention required|request blocked|"
                    + "web application firewall|security policy|not acceptable)");

    private static final Pattern CF_WAF_BODY = Pattern.compile("(?i)(attention required|just a moment|cf-error-details|"
            + "cf-challenge-|cloudflare ray id|enable javascript.*cookies|"
            + "cf_chl_opt|challenge-platform|why have i been blocked)");

    @SuppressWarnings("checkstyle:LineLengthCheck")
    private static final List<WafSignature> SIGNATURES = List.of(new WafSignature("akamai", "Akamai", "waf",
            List.of(new WafSignal(SignalType.COOKIE, "_abck", 100), new WafSignal(SignalType.COOKIE, "ak_bmsc", 90),
                    new WafSignal(SignalType.URL, "/akam/", 80), new WafSignal(SignalType.CONTENT, "sensor_data", 70))),
            new WafSignature("aws-waf", "AWS WAF", "waf",
                    List.of(new WafSignal(SignalType.COOKIE, "aws-waf-token", 100),
                            new WafSignal(SignalType.URL, "/challenge.js", 80),
                            new WafSignal(SignalType.CONTENT, "awswaf", 90))),
            new WafSignature("cloudflare", "Cloudflare", "waf",
                    List.of(new WafSignal(SignalType.COOKIE, "__cf_bm", 90),
                            new WafSignal(SignalType.COOKIE, "cf_clearance", 100),
                            new WafSignal(SignalType.URL, "cdn-cgi/challenge-platform", 95),
                            new WafSignal(SignalType.HEADER, "cf-mitigated", 100),
                            new WafSignal(SignalType.HEADER, "cf-ray", 80))),
            new WafSignature("datadome", "DataDome", "waf",
                    List.of(new WafSignal(SignalType.COOKIE, "datadome", 100),
                            new WafSignal(SignalType.HEADER, "x-datadome-cid", 100))),
            new WafSignature("imperva", "Imperva", "waf",
                    List.of(new WafSignal(SignalType.COOKIE, "incap_ses_", 100),
                            new WafSignal(SignalType.COOKIE, "reese84", 90),
                            new WafSignal(SignalType.COOKIE, "visid_incap_", 90),
                            new WafSignal(SignalType.URL, "/_Incapsula_Resource", 80))),
            new WafSignature("perimeterx", "PerimeterX", "waf", List.of(new WafSignal(SignalType.COOKIE, "_px2", 100),
                    new WafSignal(SignalType.COOKIE, "_px3", 100), new WafSignal(SignalType.COOKIE, "_pxhd", 90),
                    new WafSignal(SignalType.CONTENT, "_pxAction", 80))),
            new WafSignature("kasada", "Kasada", "waf",
                    List.of(new WafSignal(SignalType.URL, "ips.js", 80),
                            new WafSignal(SignalType.CONTENT, "kasada", 95))),
            new WafSignature("reblaze", "Reblaze", "waf",
                    List.of(new WafSignal(SignalType.COOKIE, "rbzid", 100),
                            new WafSignal(SignalType.COOKIE, "rbzsessionid", 90))),
            new WafSignature("hcaptcha", "hCaptcha", "captcha",
                    List.of(new WafSignal(SignalType.URL, "hcaptcha.com", 100),
                            new WafSignal(SignalType.CONTENT, "h-captcha", 90))),
            new WafSignature("recaptcha", "reCAPTCHA", "captcha",
                    List.of(new WafSignal(SignalType.URL, "recaptcha/api", 100),
                            new WafSignal(SignalType.CONTENT, "grecaptcha", 90))),
            new WafSignature("funcaptcha", "FunCaptcha", "captcha",
                    List.of(new WafSignal(SignalType.URL, "arkoselabs.com", 100),
                            new WafSignal(SignalType.CONTENT, "ArkoseEnforce", 90))),
            new WafSignature("geetest", "GeeTest", "captcha",
                    List.of(new WafSignal(SignalType.URL, "api.geetest.com", 100),
                            new WafSignal(SignalType.CONTENT, "initGeetest", 90))),
            new WafSignature("shape", "Shape Security", "waf",
                    List.of(new WafSignal(SignalType.CONTENT, "shapesecurity", 50))),
            new WafSignature("sucuri", "Sucuri", "waf", List.of(new WafSignal(SignalType.CONTENT, "sucuri", 50))));

    private static final Pattern CF_CTYPE_PATTERN = Pattern.compile("cType['\"]?\\s*[:=]\\s*['\"]([A-Za-z_-]+)['\"]");

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
        if (!ctx.wafState().isWafDetected() || ctx.wafState().isManaged()) {
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
            // CF sets Server: cloudflare on ALL responses, not just WAF blocks.
            // Require body evidence to distinguish WAF block from app-level 403.
            if (serverHeader.toLowerCase().contains("cloudflare")) {
                return body != null && CF_WAF_BODY.matcher(body).find();
            }
            return true;
        }
        return body != null && WAF_BODY.matcher(body).find();
    }

    public static boolean isCloudflarePresent(Map<String, List<String>> headers) {
        String server = firstHeader(headers, "Server");
        if (server.toLowerCase().contains("cloudflare")) {
            return true;
        }
        return !firstHeader(headers, "cf-ray").isEmpty();
    }

    public static String detectWafProduct(String serverHeader) {
        if (serverHeader == null) {
            return "";
        }
        var m = WAF_SERVER.matcher(serverHeader);
        return m.find() ? m.group(1) : "";
    }

    // -- Multi-vendor WAF/captcha signature detection --

    public static List<WafDetection> detectProviders(int status, Map<String, List<String>> headers, String body,
            String url) {
        List<WafDetection> detections = new ArrayList<>();

        // Collect Set-Cookie values for cookie signal matching
        List<String> setCookies = new ArrayList<>();
        for (var entry : headers.entrySet()) {
            if ("set-cookie".equalsIgnoreCase(entry.getKey())) {
                setCookies.addAll(entry.getValue());
            }
        }

        String bodyLower = (body != null) ? body.toLowerCase(Locale.ROOT) : "";
        String urlSafe = (url != null) ? url : "";

        for (WafSignature sig : SIGNATURES) {
            int maxConfidence = 0;
            List<String> hits = new ArrayList<>();

            for (WafSignal signal : sig.signals()) {
                boolean matched = switch (signal.type()) {
                    case COOKIE -> matchesCookie(setCookies, signal.pattern());
                    case HEADER -> !firstHeader(headers, signal.pattern()).isEmpty();
                    case URL -> urlSafe.contains(signal.pattern());
                    case CONTENT -> bodyLower.contains(signal.pattern().toLowerCase(Locale.ROOT));
                };

                if (matched) {
                    hits.add(signal.type() + ":" + signal.pattern());
                    maxConfidence = Math.max(maxConfidence, signal.confidence());
                }
            }

            if (!hits.isEmpty()) {
                detections
                        .add(new WafDetection(sig.id(), sig.name(), sig.category(), maxConfidence, List.copyOf(hits)));
            }
        }
        return detections;
    }

    private static boolean matchesCookie(List<String> setCookies, String cookieName) {
        for (String sc : setCookies) {
            if (sc.startsWith(cookieName)) {
                return true;
            }
        }
        return false;
    }

    // -- Cloudflare challenge type classification --

    public static String parseCfChallengeType(String body, Map<String, List<String>> headers, String url) {
        // 1. cf-mitigated header -- strongest signal
        String cfMitigated = firstHeader(headers, "cf-mitigated");
        if ("challenge".equalsIgnoreCase(cfMitigated)) {
            return "managed";
        }

        // 2. _cf_chl_opt block in body -- extract cType value
        if (body != null && body.contains("_cf_chl_opt")) {
            var matcher = CF_CTYPE_PATTERN.matcher(body);
            if (matcher.find()) {
                return matcher.group(1);
            }
        }

        // 3. Challenge platform URL path
        if (url != null && url.contains("cdn-cgi/challenge-platform")) {
            return "managed";
        }

        // 4. Turnstile markers in body
        if (body != null && (body.contains("turnstile.js") || body.contains("cf-turnstile"))) {
            return "turnstile";
        }

        return "";
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
