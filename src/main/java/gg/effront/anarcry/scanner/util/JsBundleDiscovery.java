package gg.effront.anarcry.scanner.util;

import gg.effront.anarcry.scanner.ScanContext;

import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.function.Consumer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class JsBundleDiscovery {

    private static final Pattern SCRIPT_SRC = Pattern.compile("<script[^>]+src=[\"']([^\"']+)[\"']",
            Pattern.CASE_INSENSITIVE);

    // Chunk references inside JS: dynamic import("/_nuxt/Abc123.js") or
    // e("ChunkName")
    private static final Pattern JS_CHUNK_REF = Pattern
            .compile("(?:import|_import|__vitePreload)\\s*\\(\\s*[\"']([^\"']+\\.js)[\"']", Pattern.CASE_INSENSITIVE);

    // Nuxt 3 builds: path references like "/_nuxt/AbcDef12.js" in manifest or entry
    private static final Pattern NUXT_CHUNK_PATH = Pattern.compile("\"(/_nuxt/[A-Za-z0-9_-]+\\.js)\"");

    // Next.js chunk references: "static/chunks/xxx-hash.js"
    private static final Pattern NEXT_CHUNK_PATH = Pattern
            .compile("\"((?:static/chunks|_next/static/chunks)/[A-Za-z0-9_/.()-]+\\.js)\"");

    // Webpack/Vite manifest: chunk map entries
    private static final Pattern MANIFEST_ENTRY = Pattern.compile("\"([^\"]+\\.js)\"\\s*:");

    private static final int MAX_JS_SIZE = 5_000_000;
    private static final int MAX_DEPTH = 2;

    private JsBundleDiscovery() {
    }

    public static Set<String> discover(ScanContext ctx, HttpClient hc, String base, Consumer<String> log) {
        Set<String> jsUrls = new LinkedHashSet<>();
        Set<String> visited = new LinkedHashSet<>();

        // Phase 1: extract <script src> from crawled HTML pages
        Set<String> paths = ctx.discoveredPaths().paths();
        if (paths.isEmpty()) {
            paths = Set.of("/");
        }
        for (String path : paths) {
            String url = resolveUrl(base, path);
            if (!visited.add(url) || looksLikeAsset(path)) {
                continue;
            }
            String body = fetchQuietly(hc, url, log);
            if (body == null) {
                continue;
            }
            extractScriptSrcs(body, base, url, jsUrls);
        }

        // Phase 2: framework manifest probes
        probeManifests(hc, base, jsUrls, log);

        int initialCount = jsUrls.size();
        log.accept("[~] JsBundleDiscovery: " + initialCount + " bundle(s) from HTML + manifests");

        // Phase 3: recursive chunk discovery inside JS files (depth-limited)
        Set<String> frontier = new LinkedHashSet<>(jsUrls);
        for (int depth = 0; depth < MAX_DEPTH && !frontier.isEmpty(); depth++) {
            Set<String> nextFrontier = new LinkedHashSet<>();
            for (String jsUrl : frontier) {
                if (!visited.add(jsUrl)) {
                    continue;
                }
                String body = fetchQuietly(hc, jsUrl, log);
                if (body == null) {
                    continue;
                }
                Set<String> refs = extractChunkRefs(body, base, jsUrl);
                for (String ref : refs) {
                    if (jsUrls.add(ref)) {
                        nextFrontier.add(ref);
                    }
                }
            }
            frontier = nextFrontier;
        }

        if (jsUrls.size() > initialCount) {
            log.accept("[~] JsBundleDiscovery: +" + (jsUrls.size() - initialCount)
                    + " chunk(s) from cross-reference (total: " + jsUrls.size() + ")");
        }

        return jsUrls;
    }

    public static void extractScriptSrcs(String html, String base, String pageUrl, Set<String> jsUrls) {
        Matcher matcher = SCRIPT_SRC.matcher(html);
        while (matcher.find()) {
            String src = matcher.group(1);
            if (!src.endsWith(".js") && !src.contains(".js?")) {
                continue;
            }
            jsUrls.add(resolveRef(src, base, pageUrl));
        }
    }

    private static Set<String> extractChunkRefs(String jsBody, String base, String jsUrl) {
        Set<String> refs = new LinkedHashSet<>();
        extractPattern(JS_CHUNK_REF, jsBody, base, jsUrl, refs);
        extractPattern(NUXT_CHUNK_PATH, jsBody, base, jsUrl, refs);
        extractPattern(NEXT_CHUNK_PATH, jsBody, base, jsUrl, refs);
        return refs;
    }

    private static void extractPattern(Pattern p, String body, String base, String contextUrl, Set<String> out) {
        Matcher m = p.matcher(body);
        while (m.find()) {
            String ref = m.group(1);
            if (ref.length() > 200 || ref.contains("..") || ref.contains("node_modules")) {
                continue;
            }
            out.add(resolveRef(ref, base, contextUrl));
        }
    }

    private static void probeManifests(HttpClient hc, String base, Set<String> jsUrls, Consumer<String> log) {
        String[] manifests = {"/_nuxt/builds/latest.json", "/_next/static/buildManifest.js",
                "/_next/static/_buildManifest.js", "/asset-manifest.json", "/manifest.json",};
        for (String path : manifests) {
            String url = base + path;
            String body = fetchQuietly(hc, url, null);
            if (body == null || body.length() < 10) {
                continue;
            }
            if (log != null) {
                log.accept("[~] JsBundleDiscovery: manifest found at " + path);
            }
            Matcher m = MANIFEST_ENTRY.matcher(body);
            while (m.find()) {
                String ref = m.group(1);
                if (ref.endsWith(".js") && ref.length() < 200) {
                    jsUrls.add(resolveRef(ref, base, url));
                }
            }
            // Nuxt latest.json contains a build id; try to fetch its meta
            if (path.contains("latest.json")) {
                Matcher idMatcher = Pattern.compile("\"id\"\\s*:\\s*\"([^\"]+)\"").matcher(body);
                if (idMatcher.find()) {
                    String buildId = idMatcher.group(1);
                    String metaUrl = base + "/_nuxt/builds/meta/" + buildId + ".json";
                    String meta = fetchQuietly(hc, metaUrl, null);
                    if (meta != null) {
                        Matcher em = NUXT_CHUNK_PATH.matcher(meta);
                        while (em.find()) {
                            jsUrls.add(resolveRef(em.group(1), base, metaUrl));
                        }
                    }
                }
            }
        }
    }

    private static String resolveRef(String src, String base, String contextUrl) {
        if (src.startsWith("//")) {
            return "https:" + src;
        }
        if (src.startsWith("http://") || src.startsWith("https://")) {
            return src;
        }
        if (src.startsWith("/")) {
            return base + src;
        }
        String parent = contextUrl.substring(0, contextUrl.lastIndexOf('/') + 1);
        return parent + src;
    }

    private static String resolveUrl(String base, String path) {
        if (path.startsWith("http://") || path.startsWith("https://")) {
            return path;
        }
        if (!path.startsWith("/")) {
            path = "/" + path;
        }
        return base + path;
    }

    private static boolean looksLikeAsset(String path) {
        return path.endsWith(".js") || path.endsWith(".css") || path.endsWith(".map") || path.endsWith(".png")
                || path.endsWith(".jpg") || path.endsWith(".svg") || path.endsWith(".woff2") || path.endsWith(".ico");
    }

    private static String fetchQuietly(HttpClient hc, String url, Consumer<String> log) {
        try {
            HttpRequest req = HttpRequest.newBuilder().uri(java.net.URI.create(url)).timeout(Duration.ofSeconds(15))
                    .GET().build();
            HttpResponse<String> resp = hc.send(req, HttpResponse.BodyHandlers.ofString());
            if (resp.statusCode() >= 400) {
                return null;
            }
            String body = resp.body();
            if (body != null && body.length() > MAX_JS_SIZE) {
                body = body.substring(0, MAX_JS_SIZE);
            }
            return body;
        } catch (Exception e) {
            return null;
        }
    }
}
