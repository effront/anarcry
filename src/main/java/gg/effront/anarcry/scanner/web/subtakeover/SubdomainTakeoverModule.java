package gg.effront.anarcry.scanner.web.subtakeover;

import gg.effront.anarcry.model.Finding;
import gg.effront.anarcry.model.Severity;
import gg.effront.anarcry.scanner.ScanContext;
import gg.effront.anarcry.scanner.Scanner;
import gg.effront.anarcry.scanner.util.Http;
import gg.effront.anarcry.scanner.util.HttpClientFactory;

import java.net.InetAddress;
import java.net.URI;
import java.net.UnknownHostException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;
import java.util.regex.Pattern;

import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;

public class SubdomainTakeoverModule implements Scanner {

    private static final List<String> COMMON_SUBDOMAINS = List.of("www", "api", "app", "dev", "staging", "admin",
            "mail", "cdn", "assets", "static", "beta", "test");

    private record ServiceFingerprint(Pattern cnamePattern, String serviceName, Pattern bodyPattern) {
    }

    private static final List<ServiceFingerprint> FINGERPRINTS = List.of(
            new ServiceFingerprint(Pattern.compile(".*\\.github\\.io$", Pattern.CASE_INSENSITIVE), "GitHub Pages",
                    Pattern.compile("There isn't a GitHub Pages site here", Pattern.CASE_INSENSITIVE)),
            new ServiceFingerprint(Pattern.compile(".*\\.herokuapp\\.com$", Pattern.CASE_INSENSITIVE), "Heroku",
                    Pattern.compile("No such app|no-such-app", Pattern.CASE_INSENSITIVE)),
            new ServiceFingerprint(
                    Pattern.compile(".*\\.s3[.-].*\\.amazonaws\\.com$|.*\\.s3\\.amazonaws\\.com$",
                            Pattern.CASE_INSENSITIVE),
                    "AWS S3",
                    Pattern.compile("NoSuchBucket|The specified bucket does not exist", Pattern.CASE_INSENSITIVE)),
            new ServiceFingerprint(
                    Pattern.compile(".*\\.azurewebsites\\.net$|.*\\.cloudapp\\.azure\\.com$", Pattern.CASE_INSENSITIVE),
                    "Azure", Pattern.compile("not found|404 Web Site not found", Pattern.CASE_INSENSITIVE)),
            new ServiceFingerprint(Pattern.compile("shops\\.myshopify\\.com$", Pattern.CASE_INSENSITIVE), "Shopify",
                    Pattern.compile("Sorry, this shop is currently unavailable", Pattern.CASE_INSENSITIVE)),
            new ServiceFingerprint(Pattern.compile(".*\\.fastly\\.net$", Pattern.CASE_INSENSITIVE), "Fastly",
                    Pattern.compile("Fastly error: unknown domain", Pattern.CASE_INSENSITIVE)),
            new ServiceFingerprint(Pattern.compile(".*\\.pantheonsite\\.io$", Pattern.CASE_INSENSITIVE), "Pantheon",
                    Pattern.compile("404 error unknown site|The gods are displeased", Pattern.CASE_INSENSITIVE)),
            new ServiceFingerprint(Pattern.compile(".*\\.tumblr\\.com$", Pattern.CASE_INSENSITIVE), "Tumblr",
                    Pattern.compile("There's nothing here|Whatever you were looking for doesn't currently exist",
                            Pattern.CASE_INSENSITIVE)),
            new ServiceFingerprint(Pattern.compile(".*\\.wordpress\\.com$", Pattern.CASE_INSENSITIVE), "WordPress",
                    Pattern.compile("Do you want to register .* this", Pattern.CASE_INSENSITIVE)),
            new ServiceFingerprint(Pattern.compile(".*\\.surge\\.sh$", Pattern.CASE_INSENSITIVE), "Surge.sh",
                    Pattern.compile("project not found|surge\\.sh", Pattern.CASE_INSENSITIVE)));

    @Override
    public String id() {
        return "SubTakeover";
    }

    @Override
    public List<Finding> scan(ScanContext ctx, Consumer<String> log) throws Exception {
        List<Finding> findings = new ArrayList<>();
        HttpClient hc = HttpClientFactory.noRedirect();

        // Collect hosts to check: primary host + common subdomains
        String primaryHost = ctx.host();
        List<String> hostsToCheck = new ArrayList<>();
        hostsToCheck.add(primaryHost);

        // Extract base domain for subdomain enumeration
        String baseDomain = extractBaseDomain(primaryHost);
        for (String sub : COMMON_SUBDOMAINS) {
            String candidate = sub + "." + baseDomain;
            if (!candidate.equals(primaryHost)) {
                hostsToCheck.add(candidate);
            }
        }

        log.accept("[~] " + id() + ": checking " + hostsToCheck.size() + " hosts for dangling CNAMEs");

        for (String host : hostsToCheck) {
            try {
                checkHost(ctx, hc, host, findings, log);
            } catch (Exception e) {
                // DNS resolution or connection failures are expected for non-existent
                // subdomains
            }
        }

        if (findings.isEmpty()) {
            log.accept("[+] " + id() + ": nenhuma vulnerabilidade detectada");
        }
        return findings;
    }

    private void checkHost(ScanContext ctx, HttpClient hc, String host, List<Finding> findings, Consumer<String> log)
            throws Exception {
        // Phase 1: DNS CNAME resolution
        List<String> cnameChain = resolveCnameChain(host, log);
        if (cnameChain.isEmpty()) {
            return;
        }

        String finalCname = cnameChain.get(cnameChain.size() - 1);
        String chainStr = host + " -> " + String.join(" -> ", cnameChain);
        log.accept("[~] " + id() + ": CNAME chain for " + host + ": " + chainStr);

        // Phase 2: Match CNAME against known vulnerable services
        for (ServiceFingerprint fp : FINGERPRINTS) {
            if (fp.cnamePattern().matcher(finalCname).matches()) {
                log.accept("[~] " + id() + ": " + host + " points to " + fp.serviceName() + " (" + finalCname + ")");

                // Check if the CNAME target resolves (NXDOMAIN = dangling)
                boolean resolves = dnsResolves(finalCname);
                if (!resolves) {
                    log.accept("[!!] " + id() + ": NXDOMAIN on " + finalCname + " -- dangling CNAME for " + host);
                    findings.add(buildFinding(host, chainStr, fp.serviceName(),
                            "NXDOMAIN on CNAME target " + finalCname, Severity.HIGH));
                    return;
                }

                // CNAME resolves -- check HTTP response for takeover fingerprint
                String body = fetchBody(ctx, hc, host, log);
                if (body != null && fp.bodyPattern().matcher(body).find()) {
                    log.accept("[!!] " + id() + ": takeover fingerprint matched for " + host + " (" + fp.serviceName()
                            + ")");
                    String evidence = "CNAME chain: " + chainStr + " | HTTP body matched: "
                            + fp.bodyPattern().pattern();
                    findings.add(buildFinding(host, chainStr, fp.serviceName(), evidence, Severity.HIGH));
                    return;
                }

                // CNAME matches a service pattern but no fingerprint -- suspicious
                log.accept("[~] " + id() + ": " + host + " CNAME matches " + fp.serviceName()
                        + " but no takeover fingerprint in response");
                return;
            }
        }

        // Phase 3: Generic dangling CNAME check (CNAME points to something that does
        // not resolve)
        if (!dnsResolves(finalCname)) {
            log.accept("[!] " + id() + ": dangling CNAME detected for " + host + " -> " + finalCname
                    + " (unknown service)");
            findings.add(buildFinding(host, chainStr, "Unknown service",
                    "CNAME target " + finalCname + " does not resolve (NXDOMAIN)", Severity.MEDIUM));
        }
    }

    private List<String> resolveCnameChain(String host, Consumer<String> log) {
        List<String> chain = new ArrayList<>();
        try {
            java.util.Hashtable<String, String> env = new java.util.Hashtable<>();
            env.put("java.naming.factory.initial", "com.sun.jndi.dns.DnsContextFactory");
            DirContext dnsCtx = new InitialDirContext(env);

            String current = host;
            int maxDepth = 10;
            while (maxDepth-- > 0) {
                try {
                    Attributes attrs = dnsCtx.getAttributes(current, new String[]{"CNAME"});
                    Attribute cnameAttr = attrs.get("CNAME");
                    if (cnameAttr == null) {
                        break;
                    }
                    NamingEnumeration<?> values = cnameAttr.getAll();
                    if (values.hasMore()) {
                        String cname = values.next().toString();
                        // Strip trailing dot from DNS names
                        if (cname.endsWith(".")) {
                            cname = cname.substring(0, cname.length() - 1);
                        }
                        chain.add(cname);
                        current = cname;
                    } else {
                        break;
                    }
                } catch (NamingException e) {
                    break;
                }
            }
            dnsCtx.close();
        } catch (NamingException e) {
            log.accept("[~] " + id() + ": DNS lookup failed for " + host + ": " + e.getMessage());
        }
        return chain;
    }

    private boolean dnsResolves(String host) {
        try {
            InetAddress.getByName(host);
            return true;
        } catch (UnknownHostException e) {
            return false;
        }
    }

    private String fetchBody(ScanContext ctx, HttpClient hc, String host, Consumer<String> log) {
        try {
            String scheme = ctx.isHttps() ? "https" : "http";
            String url = scheme + "://" + host + "/";
            HttpRequest req = HttpRequest.newBuilder().uri(URI.create(url)).timeout(Duration.ofSeconds(6)).GET()
                    .build();
            HttpResponse<String> resp = Http.send(ctx, hc, req, HttpResponse.BodyHandlers.ofString(), id());
            return resp.body() != null ? resp.body() : "";
        } catch (Exception e) {
            log.accept("[~] " + id() + ": HTTP fetch failed for " + host + ": " + e.getMessage());
            return null;
        }
    }

    private Finding buildFinding(String host, String cnameChain, String service, String evidence, Severity severity) {
        return Finding.of(id(), host, "Subdomain Takeover -- " + service + " (" + host + ")", severity, evidence,
                "Dangling CNAME allows an attacker to claim the target subdomain on " + service
                        + ", serving arbitrary content under the organization's domain. "
                        + "This enables phishing, cookie theft, and bypassing same-origin protections.",
                "# Verify:\ndig CNAME " + host + "\ncurl -sI https://" + host + "/\n\n# CNAME chain: " + cnameChain,
                "Remove the orphaned DNS record or reclaim the resource on " + service
                        + ". Audit all CNAME records regularly for dangling references. "
                        + "Use monitoring tools to detect subdomain takeover conditions.");
    }

    private static String extractBaseDomain(String host) {
        // Simple extraction: take the last two labels (e.g., example.com from
        // sub.example.com)
        // For known two-part TLDs (co.uk, com.br), take last three labels
        String[] parts = host.split("\\.");
        if (parts.length <= 2) {
            return host;
        }
        // Check for common two-part TLDs
        String lastTwo = parts[parts.length - 2] + "." + parts[parts.length - 1];
        if (isTwoPartTld(lastTwo)) {
            if (parts.length >= 3) {
                return parts[parts.length - 3] + "." + lastTwo;
            }
            return host;
        }
        return parts[parts.length - 2] + "." + parts[parts.length - 1];
    }

    private static boolean isTwoPartTld(String tld) {
        return switch (tld) {
            case "co.uk", "co.jp", "co.kr", "co.nz", "co.za", "com.br", "com.au", "com.cn", "com.mx", "com.ar",
                    "com.tw", "org.uk", "org.au", "net.au", "ac.uk", "gov.uk", "gov.br" ->
                true;
            default -> false;
        };
    }
}
