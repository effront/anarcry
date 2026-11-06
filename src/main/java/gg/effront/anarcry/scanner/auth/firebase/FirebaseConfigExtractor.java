package gg.effront.anarcry.scanner.auth.firebase;

import gg.effront.anarcry.scanner.util.HttpClientFactory;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class FirebaseConfigExtractor {

    private static final Pattern API_KEY = Pattern.compile("apiKey\\s*[:=]\\s*[\"']([A-Za-z0-9_-]{39})[\"']");
    private static final Pattern AUTH_DOMAIN = Pattern.compile("authDomain\\s*[:=]\\s*[\"']([^\"']+)[\"']");
    private static final Pattern PROJECT_ID = Pattern.compile("projectId\\s*[:=]\\s*[\"']([^\"']+)[\"']");
    private static final Pattern STORAGE_BUCKET = Pattern.compile("storageBucket\\s*[:=]\\s*[\"']([^\"']+)[\"']");
    private static final Pattern MESSAGING_SENDER_ID = Pattern
            .compile("messagingSenderId\\s*[:=]\\s*[\"']([0-9]+)[\"']");
    private static final Pattern APP_ID = Pattern.compile("appId\\s*[:=]\\s*[\"']([0-9:a-f]+)[\"']");

    private static final Pattern SCRIPT_SRC = Pattern.compile("<script[^>]+src=[\"']([^\"']+)[\"']",
            Pattern.CASE_INSENSITIVE);

    private FirebaseConfigExtractor() {
    }

    public static FirebaseConfig extract(String html) {
        String apiKey = match(API_KEY, html);
        if (apiKey == null) {
            return null;
        }
        return new FirebaseConfig(apiKey, match(AUTH_DOMAIN, html), match(PROJECT_ID, html),
                match(STORAGE_BUCKET, html), match(MESSAGING_SENDER_ID, html), match(APP_ID, html));
    }

    public static FirebaseConfig extractFromUrl(String targetUrl) {
        try {
            HttpClient hc = HttpClientFactory.http2();
            HttpRequest req = HttpRequest.newBuilder().uri(URI.create(targetUrl)).timeout(Duration.ofSeconds(15)).GET()
                    .build();
            HttpResponse<String> resp = hc.send(req, HttpResponse.BodyHandlers.ofString());
            String body = resp.body() != null ? resp.body() : "";

            FirebaseConfig config = extract(body);
            if (config != null) {
                return config;
            }

            Matcher srcMatcher = SCRIPT_SRC.matcher(body);
            while (srcMatcher.find()) {
                String src = srcMatcher.group(1);
                if (src.contains("cdn") || src.contains("googleapis") || src.contains("gstatic")) {
                    continue;
                }
                String scriptUrl = resolveUrl(targetUrl, src);
                if (scriptUrl == null) {
                    continue;
                }
                try {
                    HttpRequest jsReq = HttpRequest.newBuilder().uri(URI.create(scriptUrl))
                            .timeout(Duration.ofSeconds(10)).GET().build();
                    HttpResponse<String> jsResp = hc.send(jsReq, HttpResponse.BodyHandlers.ofString());
                    String jsBody = jsResp.body() != null ? jsResp.body() : "";
                    config = extract(jsBody);
                    if (config != null) {
                        return config;
                    }
                } catch (Exception ignored) {
                }
            }
            return null;
        } catch (Exception e) {
            return null;
        }
    }

    public static boolean looksLikeFirebase(String html) {
        if (html == null) {
            return false;
        }
        String lower = html.toLowerCase();
        return lower.contains("firebaseapp.com") || lower.contains("firebase") || lower.contains("/__/auth/")
                || match(API_KEY, html) != null;
    }

    private static String match(Pattern p, String text) {
        Matcher m = p.matcher(text);
        return m.find() ? m.group(1) : null;
    }

    private static String resolveUrl(String base, String src) {
        try {
            if (src.startsWith("http://") || src.startsWith("https://")) {
                return src;
            }
            URI baseUri = URI.create(base);
            if (src.startsWith("//")) {
                return baseUri.getScheme() + ":" + src;
            }
            if (src.startsWith("/")) {
                return baseUri.getScheme() + "://" + baseUri.getHost()
                        + (baseUri.getPort() > 0 ? ":" + baseUri.getPort() : "") + src;
            }
            String basePath = baseUri.getPath();
            int lastSlash = basePath.lastIndexOf('/');
            String dir = lastSlash >= 0 ? basePath.substring(0, lastSlash + 1) : "/";
            return baseUri.getScheme() + "://" + baseUri.getHost()
                    + (baseUri.getPort() > 0 ? ":" + baseUri.getPort() : "") + dir + src;
        } catch (Exception e) {
            return null;
        }
    }
}
