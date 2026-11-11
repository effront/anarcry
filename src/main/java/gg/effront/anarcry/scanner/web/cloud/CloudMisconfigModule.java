package gg.effront.anarcry.scanner.web.cloud;

import gg.effront.anarcry.model.Finding;
import gg.effront.anarcry.model.Severity;
import gg.effront.anarcry.scanner.ScanContext;
import gg.effront.anarcry.scanner.Scanner;
import gg.effront.anarcry.scanner.util.CircuitBreakerException;
import gg.effront.anarcry.scanner.util.Http;
import gg.effront.anarcry.scanner.util.HttpClientFactory;
import gg.effront.anarcry.scanner.util.ProbeExecutor;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Consumer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class CloudMisconfigModule implements Scanner {

    // S3 bucket URL patterns
    private static final Pattern S3_PATTERN = Pattern
            .compile("(?:https?://)?(" + "([a-z0-9][a-z0-9.\\-]{1,61})\\.s3[.\\-][a-z0-9\\-]+\\.amazonaws\\.com"
                    + "|s3[.\\-][a-z0-9\\-]+\\.amazonaws\\.com/([a-z0-9][a-z0-9.\\-]{1,61})"
                    + "|([a-z0-9][a-z0-9.\\-]{1,61})\\.s3\\.amazonaws\\.com"
                    + "|s3\\.amazonaws\\.com/([a-z0-9][a-z0-9.\\-]{1,61})" + ")", Pattern.CASE_INSENSITIVE);

    // Azure Blob Storage pattern
    private static final Pattern AZURE_BLOB_PATTERN = Pattern.compile(
            "https?://([a-z0-9]{3,24})\\.blob\\.core\\.windows\\.net/([a-z0-9][a-z0-9\\-]{2,62})",
            Pattern.CASE_INSENSITIVE);

    // Google Cloud Storage pattern
    private static final Pattern GCS_PATTERN = Pattern.compile(
            "https?://storage\\.googleapis\\.com/([a-z0-9][a-z0-9._\\-]{1,61}[a-z0-9])", Pattern.CASE_INSENSITIVE);

    // Firebase pattern
    private static final Pattern FIREBASE_PATTERN = Pattern.compile("https?://([a-z0-9\\-]+)\\.firebaseio\\.com",
            Pattern.CASE_INSENSITIVE);

    // Cloud headers that indicate cloud provider
    private static final List<String> CLOUD_HEADERS = List.of("x-amz-request-id", "x-amz-id-2", "x-amz-cf-id",
            "x-amz-cf-pop", "x-amzn-requestid", "x-goog-hash", "x-goog-generation", "x-goog-stored-content-length",
            "x-ms-request-id", "x-ms-version", "x-azure-ref");

    // S3 bucket suffixes to enumerate
    private static final List<String> BUCKET_SUFFIXES = List.of("", "-assets", "-backup", "-backups", "-dev",
            "-staging", "-prod", "-static", "-media", "-uploads", "-public", "-data", "-files", "-logs", "-images",
            "-cdn");

    private static final List<String> FALLBACK_PATHS = List.of("/", "/index.html", "/api/", "/assets/", "/static/");

    @Override
    public String id() {
        return "CloudMisconfig";
    }

    @Override
    public List<Finding> scan(ScanContext ctx, Consumer<String> log) throws Exception {
        List<Finding> findings = new ArrayList<>();
        HttpClient hc = HttpClientFactory.http2();

        String scheme = ctx.isHttps() ? "https" : "http";
        int defPort = ctx.isHttps() ? 443 : 80;
        String base = scheme + "://" + ctx.host() + (ctx.port() != defPort ? ":" + ctx.port() : "");
        String domain = stripSubdomain(ctx.host());

        log.accept("[~] " + id() + ": scanning cloud misconfigurations for " + ctx.host());

        int concurrency = ctx.config().probeConcurrency();
        AtomicBoolean cancel = new AtomicBoolean(false);
        List<Callable<List<Finding>>> tasks = new ArrayList<>();

        // Phase 5: Check response headers for cloud-specific indicators
        tasks.add(() -> {
            List<Finding> local = new ArrayList<>();
            if (cancel.get()) {
                return local;
            }
            Finding hdrFinding = checkCloudHeaders(ctx, hc, base, log);
            if (hdrFinding != null) {
                local.add(hdrFinding);
            }
            return local;
        });

        // Scan responses for cloud URLs
        Set<String> crawledPaths = ctx.discoveredPaths().paths();
        List<String> scanPaths = crawledPaths.isEmpty() ? FALLBACK_PATHS : new ArrayList<>(crawledPaths);

        tasks.add(() -> {
            if (cancel.get()) {
                return List.of();
            }
            return scanResponsesForCloudUrls(ctx, hc, base, scanPaths, log);
        });

        // Phase 1: S3 bucket enumeration from domain
        tasks.add(() -> {
            if (cancel.get()) {
                return List.of();
            }
            return enumerateS3Buckets(ctx, hc, domain, log);
        });

        // Phase 4: Firebase detection
        tasks.add(() -> {
            if (cancel.get()) {
                return List.of();
            }
            return checkFirebase(ctx, hc, domain, log);
        });

        findings.addAll(ProbeExecutor.run(tasks, concurrency, cancel));

        if (findings.isEmpty()) {
            log.accept("[+] " + id() + ": nenhuma cloud misconfiguration detectada");
        }
        return findings;
    }

    // -------------------------------------------------------------------------
    // Phase 5: Cloud header detection
    // -------------------------------------------------------------------------

    private Finding checkCloudHeaders(ScanContext ctx, HttpClient hc, String base, Consumer<String> log) {
        try {
            HttpRequest req = HttpRequest.newBuilder().uri(URI.create(base + "/")).timeout(Duration.ofSeconds(6)).GET()
                    .build();
            HttpResponse<String> resp = Http.send(ctx, hc, req, HttpResponse.BodyHandlers.ofString(), id());

            List<String> detected = new ArrayList<>();
            for (String header : CLOUD_HEADERS) {
                if (resp.headers().firstValue(header).isPresent()) {
                    detected.add(header + ": " + resp.headers().firstValue(header).orElse(""));
                }
            }

            if (!detected.isEmpty()) {
                String provider = detectProvider(detected);
                log.accept("[~] " + id() + ": cloud headers detected (" + provider + ") -- " + detected.size()
                        + " header(s)");
                return Finding.of(id(), base + "/", "Cloud Provider Headers Exposed -- " + provider, Severity.INFO,
                        "Headers: " + String.join(", ", detected),
                        "Cloud-specific response headers reveal the cloud provider and infrastructure"
                                + " details. This information assists attackers in targeting"
                                + " provider-specific misconfigurations",
                        "curl -sI '" + base + "/' | grep -iE '" + String.join("|", CLOUD_HEADERS) + "'",
                        "Configure the reverse proxy or CDN to strip cloud-specific headers from"
                                + " responses. Use custom headers instead of exposing provider defaults.");
            }
        } catch (CircuitBreakerException cbe) {
            throw cbe;
        } catch (Exception ignored) {
            // Target may be unreachable
        }
        return null;
    }

    // -------------------------------------------------------------------------
    // Scan responses for cloud storage URLs and test them
    // -------------------------------------------------------------------------

    private List<Finding> scanResponsesForCloudUrls(ScanContext ctx, HttpClient hc, String base, List<String> paths,
            Consumer<String> log) {
        List<Finding> findings = new ArrayList<>();
        Set<String> testedBuckets = new HashSet<>();

        for (String path : paths) {
            try {
                String url = base + path;
                HttpRequest req = HttpRequest.newBuilder().uri(URI.create(url)).timeout(Duration.ofSeconds(6)).GET()
                        .build();
                HttpResponse<String> resp = Http.send(ctx, hc, req, HttpResponse.BodyHandlers.ofString(), id());
                String body = resp.body() != null ? resp.body() : "";

                // S3 URLs
                Matcher s3m = S3_PATTERN.matcher(body);
                while (s3m.find()) {
                    String bucket = extractS3Bucket(s3m);
                    if (bucket != null && testedBuckets.add(bucket)) {
                        Finding f = testS3Bucket(ctx, hc, bucket, url, log);
                        if (f != null) {
                            findings.add(f);
                        }
                    }
                }

                // Azure Blob URLs
                Matcher azm = AZURE_BLOB_PATTERN.matcher(body);
                while (azm.find()) {
                    String account = azm.group(1);
                    String container = azm.group(2);
                    String key = account + "/" + container;
                    if (testedBuckets.add(key)) {
                        Finding f = testAzureBlob(ctx, hc, account, container, url, log);
                        if (f != null) {
                            findings.add(f);
                        }
                    }
                }

                // GCS URLs
                Matcher gcsm = GCS_PATTERN.matcher(body);
                while (gcsm.find()) {
                    String bucket = gcsm.group(1);
                    if (testedBuckets.add("gcs:" + bucket)) {
                        Finding f = testGcsBucket(ctx, hc, bucket, url, log);
                        if (f != null) {
                            findings.add(f);
                        }
                    }
                }

                // Firebase URLs
                Matcher fbm = FIREBASE_PATTERN.matcher(body);
                while (fbm.find()) {
                    String project = fbm.group(1);
                    if (testedBuckets.add("firebase:" + project)) {
                        Finding f = testFirebaseProject(ctx, hc, project, url, log);
                        if (f != null) {
                            findings.add(f);
                        }
                    }
                }
            } catch (CircuitBreakerException cbe) {
                throw cbe;
            } catch (Exception ignored) {
                // Skip unreachable paths
            }
        }
        return findings;
    }

    // -------------------------------------------------------------------------
    // Phase 1: S3 bucket enumeration and testing
    // -------------------------------------------------------------------------

    private List<Finding> enumerateS3Buckets(ScanContext ctx, HttpClient hc, String domain, Consumer<String> log) {
        List<Finding> findings = new ArrayList<>();
        log.accept("[~] " + id() + ": enumerating S3 buckets for domain " + domain);

        for (String suffix : BUCKET_SUFFIXES) {
            String bucket = domain + suffix;
            try {
                Finding f = testS3Bucket(ctx, hc, bucket, "enumeration:" + bucket, log);
                if (f != null) {
                    findings.add(f);
                }
            } catch (CircuitBreakerException cbe) {
                throw cbe;
            } catch (Exception ignored) {
                // Expected for non-existent buckets
            }
        }
        return findings;
    }

    private Finding testS3Bucket(ScanContext ctx, HttpClient hc, String bucket, String sourceUrl,
            Consumer<String> log) {
        String bucketUrl = "https://" + bucket + ".s3.amazonaws.com";
        try {
            HttpRequest req = HttpRequest.newBuilder().uri(URI.create(bucketUrl + "/")).timeout(Duration.ofSeconds(6))
                    .GET().build();
            HttpResponse<String> resp = Http.send(ctx, hc, req, HttpResponse.BodyHandlers.ofString(), id());
            String body = resp.body() != null ? resp.body() : "";

            // Public listing
            if (resp.statusCode() == 200 && body.contains("<ListBucketResult")) {
                log.accept("[!!] " + id() + ": S3 bucket listing enabled -- " + bucket);
                return Finding.of(id(), bucketUrl, "S3 Bucket Public Listing -- " + bucket, Severity.HIGH,
                        "Bucket: " + bucket + " | Status: 200 | Response contains <ListBucketResult>" + " | Found via: "
                                + sourceUrl,
                        "The S3 bucket allows public listing of all objects. An attacker can"
                                + " enumerate and download all files, potentially exposing sensitive"
                                + " data, backups, credentials, and source code",
                        "curl -s '" + bucketUrl + "/' | head -50",
                        "Set the bucket policy to deny public ListBucket. Use S3 Block Public"
                                + " Access at the account level. Review and remove overly permissive"
                                + " ACLs. Enable S3 server access logging.");
            }

            // Bucket exists but is restricted (AccessDenied)
            if (resp.statusCode() == 403 && body.contains("AccessDenied")) {
                log.accept("[~] " + id() + ": S3 bucket exists but is restricted -- " + bucket);
                // Informational only -- bucket exists
                return Finding.of(id(), bucketUrl, "S3 Bucket Detected (Restricted) -- " + bucket, Severity.INFO,
                        "Bucket: " + bucket + " | Status: 403 AccessDenied | Found via: " + sourceUrl,
                        "The S3 bucket exists and is associated with the target. While listing is"
                                + " denied, individual objects may still be accessible if their ACLs"
                                + " are misconfigured",
                        "curl -s -o /dev/null -w '%{http_code}' '" + bucketUrl + "/'",
                        "Ensure all objects in the bucket have appropriate ACLs. Enable S3 Block"
                                + " Public Access. Review bucket policies regularly.");
            }
        } catch (CircuitBreakerException cbe) {
            throw cbe;
        } catch (Exception ignored) {
            // DNS resolution failure means bucket does not exist
        }
        return null;
    }

    // -------------------------------------------------------------------------
    // Phase 2: Azure Blob Storage testing
    // -------------------------------------------------------------------------

    private Finding testAzureBlob(ScanContext ctx, HttpClient hc, String account, String container, String sourceUrl,
            Consumer<String> log) {
        String listUrl = "https://" + account + ".blob.core.windows.net/" + container + "?restype=container&comp=list";
        try {
            HttpRequest req = HttpRequest.newBuilder().uri(URI.create(listUrl)).timeout(Duration.ofSeconds(6)).GET()
                    .build();
            HttpResponse<String> resp = Http.send(ctx, hc, req, HttpResponse.BodyHandlers.ofString(), id());
            String body = resp.body() != null ? resp.body() : "";

            if (resp.statusCode() == 200 && body.contains("<EnumerationResults")) {
                log.accept("[!!] " + id() + ": Azure Blob container listing enabled -- " + account + "/" + container);
                return Finding
                        .of(id(), listUrl, "Azure Blob Container Public Listing -- " + account + "/" + container,
                                Severity.HIGH,
                                "Account: " + account + " | Container: " + container + " | Status: 200"
                                        + " | Response contains <EnumerationResults> | Found via: " + sourceUrl,
                                "The Azure Blob Storage container allows public listing of all blobs."
                                        + " An attacker can enumerate and download files, potentially exposing"
                                        + " sensitive data, backups, and credentials",
                                "curl -s '" + listUrl + "' | head -50",
                                "Set the container access level to Private. Use Azure Storage firewalls"
                                        + " and virtual network rules. Enable Azure Storage analytics logging."
                                        + " Use Shared Access Signatures (SAS) with minimal permissions.");
            }
        } catch (CircuitBreakerException cbe) {
            throw cbe;
        } catch (Exception ignored) {
            // Container may not exist
        }
        return null;
    }

    // -------------------------------------------------------------------------
    // Phase 3: Google Cloud Storage testing
    // -------------------------------------------------------------------------

    private Finding testGcsBucket(ScanContext ctx, HttpClient hc, String bucket, String sourceUrl,
            Consumer<String> log) {
        String bucketUrl = "https://storage.googleapis.com/" + bucket;
        try {
            HttpRequest req = HttpRequest.newBuilder().uri(URI.create(bucketUrl + "/")).timeout(Duration.ofSeconds(6))
                    .GET().build();
            HttpResponse<String> resp = Http.send(ctx, hc, req, HttpResponse.BodyHandlers.ofString(), id());
            String body = resp.body() != null ? resp.body() : "";

            if (resp.statusCode() == 200 && body.contains("<ListBucketResult")) {
                log.accept("[!!] " + id() + ": GCS bucket listing enabled -- " + bucket);
                return Finding.of(id(), bucketUrl, "GCS Bucket Public Listing -- " + bucket, Severity.HIGH,
                        "Bucket: " + bucket + " | Status: 200 | Response contains <ListBucketResult>" + " | Found via: "
                                + sourceUrl,
                        "The Google Cloud Storage bucket allows public listing of all objects."
                                + " An attacker can enumerate and download files, potentially exposing"
                                + " sensitive data and credentials",
                        "curl -s '" + bucketUrl + "/' | head -50",
                        "Set the bucket IAM policy to deny allUsers and allAuthenticatedUsers"
                                + " access. Use Uniform bucket-level access. Enable Cloud Audit Logs."
                                + " Review and remove legacy ACLs.");
            }
        } catch (CircuitBreakerException cbe) {
            throw cbe;
        } catch (Exception ignored) {
            // Bucket may not exist
        }
        return null;
    }

    // -------------------------------------------------------------------------
    // Phase 4: Firebase detection and testing
    // -------------------------------------------------------------------------

    private List<Finding> checkFirebase(ScanContext ctx, HttpClient hc, String domain, Consumer<String> log) {
        List<Finding> findings = new ArrayList<>();
        // Try common Firebase project names derived from the domain
        String baseName = domain.replace(".", "-");
        List<String> projectNames = List.of(baseName, domain.split("\\.")[0]);

        for (String project : projectNames) {
            Finding f = testFirebaseProject(ctx, hc, project, "enumeration:" + project, log);
            if (f != null) {
                findings.add(f);
            }
        }
        return findings;
    }

    private Finding testFirebaseProject(ScanContext ctx, HttpClient hc, String project, String sourceUrl,
            Consumer<String> log) {
        String firebaseUrl = "https://" + project + ".firebaseio.com";
        try {
            // Check /.json endpoint -- if Firebase rules allow unauthenticated read, this
            // returns data
            HttpRequest req = HttpRequest.newBuilder().uri(URI.create(firebaseUrl + "/.json?shallow=true"))
                    .timeout(Duration.ofSeconds(6)).GET().build();
            HttpResponse<String> resp = Http.send(ctx, hc, req, HttpResponse.BodyHandlers.ofString(), id());
            String body = resp.body() != null ? resp.body() : "";

            if (resp.statusCode() == 200 && !body.equals("null") && !body.isBlank()) {
                // Firebase returned data -- rules are wide open
                log.accept("[!!] " + id() + ": Firebase database publicly readable -- " + project);
                return Finding.of(id(), firebaseUrl + "/.json", "Firebase Database Publicly Readable -- " + project,
                        Severity.CRITICAL,
                        "Project: " + project + " | Status: 200 | Response: " + truncate(body, 200) + " | Found via: "
                                + sourceUrl,
                        "The Firebase Realtime Database allows unauthenticated read access."
                                + " All data stored in the database is publicly accessible, which"
                                + " typically includes user data, credentials, PII, and application" + " configuration",
                        "curl -s '" + firebaseUrl + "/.json?shallow=true'",
                        "Set Firebase Security Rules to require authentication for all read and"
                                + " write operations. Migrate from default open rules to restrictive"
                                + " rules. Audit existing data for exposed PII and credentials." + " Example rules:\n"
                                + "{\n" + "  \"rules\": {\n" + "    \".read\": \"auth != null\",\n"
                                + "    \".write\": \"auth != null\"\n" + "  }\n" + "}");
            }

            // Check if the project exists but is restricted
            if (resp.statusCode() == 401 || (body.contains("Permission denied"))) {
                log.accept("[~] " + id() + ": Firebase project exists but is restricted -- " + project);
                return Finding.of(id(), firebaseUrl, "Firebase Project Detected (Restricted) -- " + project,
                        Severity.INFO,
                        "Project: " + project + " | Status: " + resp.statusCode() + " | Found via: " + sourceUrl,
                        "The Firebase project exists and is associated with the target. While"
                                + " unauthenticated access is denied, misconfigurations in specific"
                                + " paths or rules may still expose data",
                        "curl -s -o /dev/null -w '%{http_code}' '" + firebaseUrl + "/.json'",
                        "Review Firebase Security Rules for all paths. Ensure rules do not"
                                + " allow unauthenticated access to any subtree. Use Firebase"
                                + " Emulator Suite to test rules before deployment.");
            }
        } catch (CircuitBreakerException cbe) {
            throw cbe;
        } catch (Exception ignored) {
            // Project may not exist
        }
        return null;
    }

    // -------------------------------------------------------------------------
    // Utility
    // -------------------------------------------------------------------------

    private static String extractS3Bucket(Matcher m) {
        // Groups: 2=subdomain style, 3=path style, 4=subdomain .s3., 5=path s3.
        for (int i = 2; i <= 5; i++) {
            String g = m.group(i);
            if (g != null && !g.isBlank()) {
                return g;
            }
        }
        return null;
    }

    private static String detectProvider(List<String> headers) {
        for (String h : headers) {
            if (h.startsWith("x-amz") || h.startsWith("x-amzn")) {
                return "AWS";
            }
            if (h.startsWith("x-goog")) {
                return "GCP";
            }
            if (h.startsWith("x-ms-") || h.startsWith("x-azure")) {
                return "Azure";
            }
        }
        return "Unknown Cloud Provider";
    }

    private static String stripSubdomain(String host) {
        // Remove www. and similar prefixes, keep the registrable domain
        String[] parts = host.split("\\.");
        if (parts.length > 2) {
            return parts[parts.length - 2] + "." + parts[parts.length - 1];
        }
        return host;
    }

    private static String truncate(String s, int maxLen) {
        if (s.length() <= maxLen) {
            return s;
        }
        return s.substring(0, maxLen) + "...";
    }
}
