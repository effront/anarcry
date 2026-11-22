package gg.effront.anarcry.scanner.web.secrets;

import gg.effront.anarcry.model.Finding;
import gg.effront.anarcry.model.Severity;
import gg.effront.anarcry.scanner.ScanContext;
import gg.effront.anarcry.scanner.Scanner;
import gg.effront.anarcry.scanner.util.Http;
import gg.effront.anarcry.scanner.util.HttpClientFactory;
import gg.effront.anarcry.scanner.util.JsBundleDiscovery;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.function.Consumer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class SecretsModule implements Scanner {

    // -- Secret patterns --

    private static final Pattern AWS_ACCESS_KEY = Pattern.compile("AKIA[0-9A-Z]{16}");
    private static final Pattern AWS_SECRET_KEY = Pattern
            .compile("(?i)aws_secret_access_key\\s*[=:]\\s*[A-Za-z0-9/+=]{40}");
    private static final Pattern GITHUB_TOKEN = Pattern.compile("gh[ps]_[A-Za-z0-9_]{36,255}");
    private static final Pattern GITHUB_OAUTH = Pattern.compile("gho_[A-Za-z0-9_]{36,255}");
    private static final Pattern GITLAB_TOKEN = Pattern.compile("glpat-[A-Za-z0-9\\-_]{20,}");
    private static final Pattern SLACK_BOT_TOKEN = Pattern.compile("xoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,34}");
    private static final Pattern SLACK_USER_TOKEN = Pattern
            .compile("xoxp-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,34}");
    private static final Pattern GOOGLE_API_KEY = Pattern.compile("AIza[0-9A-Za-z\\-_]{35}");
    private static final Pattern STRIPE_SECRET_KEY = Pattern.compile("sk_live_[0-9a-zA-Z]{24,99}");
    private static final Pattern STRIPE_PUBLISHABLE_KEY = Pattern.compile("pk_live_[0-9a-zA-Z]{24,99}");
    private static final Pattern PRIVATE_KEY = Pattern.compile("-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----");
    private static final Pattern JWT_LONG = Pattern
            .compile("eyJ[A-Za-z0-9_-]{10,}\\.eyJ[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}");
    private static final Pattern GENERIC_API_KEY = Pattern
            .compile("(?i)(api[_-]?key|apikey|api[_-]?secret)\\s*[=:]\\s*['\"][A-Za-z0-9\\-_]{16,}['\"]");
    private static final Pattern GENERIC_PASSWORD = Pattern
            .compile("(?i)(password|passwd|pwd)\\s*[=:]\\s*['\"][^'\"]{8,}['\"]");
    private static final Pattern HEROKU_API_KEY = Pattern
            .compile("[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}");
    private static final Pattern HEROKU_CONTEXT = Pattern.compile("(?i)heroku");
    private static final Pattern TWILIO_KEY = Pattern.compile("SK[0-9a-fA-F]{32}");
    private static final Pattern SENDGRID_KEY = Pattern.compile("SG\\.[A-Za-z0-9\\-_]{22,}\\.[A-Za-z0-9\\-_]{22,}");
    private static final Pattern MAILGUN_KEY = Pattern.compile("key-[0-9a-zA-Z]{32}");

    // -- Crypto / fintech-specific patterns --

    // Catches Meld-style key:secret pairs in minified JS variable assignments.
    // Both sides of the colon must be 16+ chars of [A-Za-z0-9_-].
    private static final Pattern KEY_SECRET_PAIR_JS = Pattern
            .compile("[A-Za-z_$]\\w{0,30}=[\"']([A-Za-z0-9_-]{16,}:[A-Za-z0-9_-]{16,})[\"']");
    private static final Pattern ALCHEMY_API_KEY = Pattern.compile("alch_[A-Za-z0-9_-]{32,}");
    private static final Pattern INFURA_PROJECT_ID = Pattern.compile("(?i)infura[^\"'{]*[\"']([a-f0-9]{32})[\"']");
    private static final Pattern DIGITALOCEAN_API_TOKEN = Pattern.compile("dop_v1_[a-f0-9]{64}");
    private static final Pattern FIREBASE_API_KEY = Pattern.compile("AIzaSy[A-Za-z0-9_-]{33}");
    private static final Pattern SUPABASE_SERVICE_KEY = Pattern
            .compile("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\\.[A-Za-z0-9_-]{50,}");
    private static final Pattern CLOUDFLARE_API_TOKEN = Pattern
            .compile("(?i)cloudflare[^\"']*[\"']([A-Za-z0-9_-]{40})[\"']");
    private static final Pattern MOONPAY_API_KEY = Pattern
            .compile("(?i)moonpay[^\"']*(?:key|publishable)[^\"']*[\"']([a-z]{2}_[a-z]+_[A-Za-z0-9]+)[\"']");
    private static final Pattern TRANSAK_API_KEY = Pattern
            .compile("(?i)transak[^\"']*(?:key|api)[^\"']*[\"']([a-f0-9-]{36})[\"']");

    // Pattern to detect source map URLs in JS bundles
    private static final Pattern SOURCE_MAP_URL = Pattern.compile("//[#@]\\s*sourceMappingURL=([^\\s]+)");

    // Well-known JS bundle paths to probe
    private static final List<String> JS_BUNDLE_PATHS = List.of("/static/js/main.js", "/static/js/bundle.js",
            "/static/js/app.js", "/_next/static/chunks/main.js", "/_next/static/chunks/app.js", "/assets/js/app.js",
            "/assets/js/bundle.js", "/build/bundle.js", "/dist/bundle.js", "/dist/app.js", "/config.js", "/config.json",
            "/.env");

    private record SecretPattern(String type, Pattern pattern, Severity severity) {
    }

    // Patterns that are matched directly (no context needed)
    private static final List<SecretPattern> DIRECT_PATTERNS = List.of(
            new SecretPattern("AWS Access Key", AWS_ACCESS_KEY, Severity.CRITICAL),
            new SecretPattern("AWS Secret Key", AWS_SECRET_KEY, Severity.CRITICAL),
            new SecretPattern("GitHub Token", GITHUB_TOKEN, Severity.HIGH),
            new SecretPattern("GitHub OAuth Token", GITHUB_OAUTH, Severity.HIGH),
            new SecretPattern("GitLab Token", GITLAB_TOKEN, Severity.HIGH),
            new SecretPattern("Slack Bot Token", SLACK_BOT_TOKEN, Severity.HIGH),
            new SecretPattern("Slack User Token", SLACK_USER_TOKEN, Severity.HIGH),
            new SecretPattern("Google API Key", GOOGLE_API_KEY, Severity.MEDIUM),
            new SecretPattern("Stripe Secret Key", STRIPE_SECRET_KEY, Severity.CRITICAL),
            new SecretPattern("Stripe Publishable Key", STRIPE_PUBLISHABLE_KEY, Severity.LOW),
            new SecretPattern("Private Key", PRIVATE_KEY, Severity.CRITICAL),
            new SecretPattern("JWT Token", JWT_LONG, Severity.MEDIUM),
            new SecretPattern("Generic API Key", GENERIC_API_KEY, Severity.MEDIUM),
            new SecretPattern("Generic Password", GENERIC_PASSWORD, Severity.HIGH),
            new SecretPattern("Twilio API Key", TWILIO_KEY, Severity.HIGH),
            new SecretPattern("SendGrid API Key", SENDGRID_KEY, Severity.HIGH),
            new SecretPattern("Mailgun API Key", MAILGUN_KEY, Severity.MEDIUM),
            new SecretPattern("API Key:Secret Pair", KEY_SECRET_PAIR_JS, Severity.HIGH),
            new SecretPattern("Alchemy API Key", ALCHEMY_API_KEY, Severity.HIGH),
            new SecretPattern("Infura Project ID", INFURA_PROJECT_ID, Severity.MEDIUM),
            new SecretPattern("DigitalOcean API Token", DIGITALOCEAN_API_TOKEN, Severity.CRITICAL),
            new SecretPattern("Firebase API Key", FIREBASE_API_KEY, Severity.MEDIUM),
            new SecretPattern("Supabase Service Key", SUPABASE_SERVICE_KEY, Severity.HIGH),
            new SecretPattern("Cloudflare API Token", CLOUDFLARE_API_TOKEN, Severity.HIGH),
            new SecretPattern("MoonPay API Key", MOONPAY_API_KEY, Severity.MEDIUM),
            new SecretPattern("Transak API Key", TRANSAK_API_KEY, Severity.MEDIUM));

    @Override
    public String id() {
        return "Secrets";
    }

    @Override
    public List<Finding> scan(ScanContext ctx, Consumer<String> log) throws Exception {
        List<Finding> findings = new ArrayList<>();
        HttpClient hc = HttpClientFactory.http2();
        Set<String> seenSecrets = new HashSet<>();
        Set<String> scannedUrls = new HashSet<>();
        Set<String> jsUrls = new LinkedHashSet<>();

        String base = ctx.targetUrl().replaceAll("/+$", "");

        // Phase 1: Crawled pages scan
        log.accept("[~] " + id() + ": scanning crawled pages for exposed secrets");
        Set<String> paths = ctx.discoveredPaths().paths();
        if (paths.isEmpty()) {
            // Always scan at least the root page
            paths = Set.of("/");
        }
        for (String path : paths) {
            String url = resolveUrl(base, path);
            if (!scannedUrls.add(url)) {
                continue;
            }
            String body = fetchBody(ctx, hc, url, log);
            if (body == null || body.isBlank()) {
                continue;
            }
            scanContent(body, url, findings, seenSecrets, log);
        }

        // Phase 2: JavaScript bundle scan (with chunk discovery)
        jsUrls.addAll(JsBundleDiscovery.discover(ctx, hc, base, log));
        for (String bundlePath : JS_BUNDLE_PATHS) {
            jsUrls.add(base + bundlePath);
        }
        log.accept("[~] " + id() + ": scanning " + jsUrls.size() + " JavaScript bundles");
        Set<String> sourceMapUrls = new LinkedHashSet<>();
        for (String jsUrl : jsUrls) {
            if (!scannedUrls.add(jsUrl)) {
                continue;
            }
            String body = fetchBody(ctx, hc, jsUrl, log);
            if (body == null || body.isBlank()) {
                continue;
            }
            scanContent(body, jsUrl, findings, seenSecrets, log);
            // Check for source maps
            Matcher smMatcher = SOURCE_MAP_URL.matcher(body);
            if (smMatcher.find()) {
                String smUrl = smMatcher.group(1);
                sourceMapUrls.add(resolveRelativeUrl(jsUrl, smUrl));
            }
        }

        // Phase 3: Source map scan
        if (!sourceMapUrls.isEmpty()) {
            log.accept("[~] " + id() + ": scanning " + sourceMapUrls.size() + " source map(s)");
        }
        for (String smUrl : sourceMapUrls) {
            if (!scannedUrls.add(smUrl)) {
                continue;
            }
            String body = fetchBody(ctx, hc, smUrl, log);
            if (body == null || body.isBlank()) {
                continue;
            }
            log.accept("[+] " + id() + ": accessible source map at " + smUrl);
            scanContent(body, smUrl, findings, seenSecrets, log);
        }

        if (findings.isEmpty()) {
            log.accept("[+] " + id() + ": no exposed secrets detected");
        } else {
            log.accept("[!!] " + id() + ": " + findings.size() + " exposed secret(s) detected");
        }
        return findings;
    }

    private String fetchBody(ScanContext ctx, HttpClient hc, String url, Consumer<String> log) {
        try {
            HttpRequest req = HttpRequest.newBuilder().uri(URI.create(url)).timeout(Duration.ofSeconds(6)).GET()
                    .build();
            HttpResponse<String> resp = Http.send(ctx, hc, req, HttpResponse.BodyHandlers.ofString(), id());
            if (resp.statusCode() >= 200 && resp.statusCode() < 400) {
                return resp.body();
            }
        } catch (Exception e) {
            // Connection errors, timeouts, etc. -- skip silently
        }
        return null;
    }

    private void scanContent(String content, String url, List<Finding> findings, Set<String> seenSecrets,
            Consumer<String> log) {
        // Direct pattern matching
        for (SecretPattern sp : DIRECT_PATTERNS) {
            Matcher matcher = sp.pattern.matcher(content);
            while (matcher.find()) {
                String matched = matcher.group();
                if (seenSecrets.add(matched)) {
                    String masked = maskSecret(matched);
                    log.accept("[!!] " + id() + ": " + sp.type + " found in " + url);
                    findings.add(buildFinding(sp.type, url, masked, matched, sp.severity));
                }
            }
        }
        // Heroku API Key (requires context match)
        if (HEROKU_CONTEXT.matcher(content).find()) {
            Matcher herokuMatcher = HEROKU_API_KEY.matcher(content);
            while (herokuMatcher.find()) {
                String matched = herokuMatcher.group();
                String herokuKey = "heroku:" + matched;
                if (seenSecrets.add(herokuKey)) {
                    String masked = maskSecret(matched);
                    log.accept("[!!] " + id() + ": Heroku API Key found in " + url);
                    findings.add(buildFinding("Heroku API Key", url, masked, matched, Severity.HIGH));
                }
            }
        }
    }

    private Finding buildFinding(String secretType, String url, String maskedValue, String rawValue,
            Severity severity) {
        String grepPrefix = rawValue.length() > 20 ? rawValue.substring(0, 20) : rawValue;
        String jsGrepPrefix = grepPrefix.replace("\\", "\\\\").replace("\"", "\\\"");
        grepPrefix = grepPrefix.replace("'", "'\\''").replace("[", "\\[").replace("]", "\\]").replace("(", "\\(")
                .replace(")", "\\)").replace("{", "\\{").replace("}", "\\}").replace(".", "\\.").replace("*", "\\*")
                .replace("+", "\\+").replace("?", "\\?").replace("|", "\\|").replace("^", "\\^").replace("$", "\\$");
        String urlPath = url.replaceFirst("^https?://[^/]+", "");
        return Finding.of(id(), url, "Exposed " + secretType, severity,
                "[" + secretType + "] Found in " + url + ": " + maskedValue,
                "Exposed credentials allow unauthorized access to external services, "
                        + "APIs, or infrastructure. Depending on the key type, this can lead "
                        + "to data theft, account takeover, or resource abuse.",
                "# Option 1 - Browser Console (open target site first, then F12):\n" + "fetch('" + urlPath
                        + "').then(r=>r.text()).then(t=>console.log(t.match(/" + jsGrepPrefix + "[^\"]*/))" + ")\n\n"
                        + "# Option 2 - curl (if no WAF, or with cookies from browser):\n" + "curl -s '" + url
                        + "' | grep -oP '" + grepPrefix + "[^\"]*'\n\n"
                        + "# Option 3 - curl with WAF bypass (paste cookies from browser console: document.cookie):\n"
                        + "curl -b 'PASTE_COOKIES' -s '" + url + "' | grep -oP '" + grepPrefix + "[^\"]*'",
                "Remove all secrets from client-side code. Use environment variables "
                        + "loaded server-side only. Rotate the exposed credential immediately. "
                        + "Implement secret scanning in CI/CD pipelines.");
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

    private static String resolveRelativeUrl(String parentUrl, String relative) {
        if (relative.startsWith("http://") || relative.startsWith("https://")) {
            return relative;
        }
        if (relative.startsWith("//")) {
            return "https:" + relative;
        }
        if (relative.startsWith("/")) {
            try {
                URI uri = URI.create(parentUrl);
                return uri.getScheme() + "://" + uri.getAuthority() + relative;
            } catch (Exception e) {
                return parentUrl.substring(0, parentUrl.lastIndexOf('/') + 1) + relative;
            }
        }
        return parentUrl.substring(0, parentUrl.lastIndexOf('/') + 1) + relative;
    }

    private static String maskSecret(String secret) {
        if (secret.length() <= 12) {
            return secret.substring(0, Math.min(4, secret.length())) + "****";
        }
        return secret.substring(0, 8) + "..." + secret.substring(secret.length() - 4);
    }
}
