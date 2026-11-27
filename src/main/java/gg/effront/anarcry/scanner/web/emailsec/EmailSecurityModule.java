package gg.effront.anarcry.scanner.web.emailsec;

import gg.effront.anarcry.model.CvssCalculator;
import gg.effront.anarcry.model.Finding;
import gg.effront.anarcry.model.Severity;
import gg.effront.anarcry.scanner.ScanContext;
import gg.effront.anarcry.scanner.Scanner;

import java.util.ArrayList;
import java.util.Hashtable;
import java.util.List;
import java.util.Locale;
import java.util.function.Consumer;

import javax.naming.NameNotFoundException;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;

public class EmailSecurityModule implements Scanner {

    private static final String CWE_ID = "CWE-183";
    private static final String CWE_TITLE = "Permissive List of Allowed Inputs";
    private static final String CVSS_MEDIUM = "AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N";
    private static final String CVSS_HIGH = "AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N";
    private static final String CVSS_LOW = "AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:N";
    private static final String CVSS_INFO = "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N";

    private static final String[] DKIM_SELECTORS = {"default", "google", "selector1"};

    @Override
    public String id() {
        return "EmailSec";
    }

    @Override
    public List<Finding> scan(ScanContext ctx, Consumer<String> log) throws Exception {
        List<Finding> findings = new ArrayList<>();
        String domain = extractDomain(ctx.host());
        log.accept("[~] " + id() + ": checking email security records for " + domain);

        DirContext dnsCtx = null;
        try {
            Hashtable<String, String> env = new Hashtable<>();
            env.put("java.naming.factory.initial", "com.sun.jndi.dns.DnsContextFactory");
            dnsCtx = new InitialDirContext(env);

            checkSpf(dnsCtx, domain, findings, log);
            checkDmarc(dnsCtx, domain, findings, log);
            checkDkim(dnsCtx, domain, findings, log);
        } catch (NamingException e) {
            log.accept("[!] " + id() + ": DNS context initialization failed -- " + e.getMessage());
        } finally {
            if (dnsCtx != null) {
                try {
                    dnsCtx.close();
                } catch (NamingException ignored) {
                    // best-effort close
                }
            }
        }

        if (findings.isEmpty()) {
            log.accept("[+] " + id() + ": no email security issues detected for " + domain);
        }
        return findings;
    }

    private void checkSpf(DirContext dnsCtx, String domain, List<Finding> findings, Consumer<String> log) {
        log.accept("[~] " + id() + ": looking up SPF record for " + domain);
        List<String> txtRecords = lookupTxt(dnsCtx, domain, log);
        String spfRecord = null;
        for (String txt : txtRecords) {
            if (txt.toLowerCase(Locale.ROOT).startsWith("v=spf1")) {
                spfRecord = txt;
                break;
            }
        }

        if (spfRecord == null) {
            log.accept("[!!] " + id() + ": no SPF record found for " + domain);
            findings.add(Finding.of(id(), domain, "Missing SPF Record", Severity.MEDIUM,
                    "No TXT record containing v=spf1 found for " + domain,
                    "Without SPF, any mail server can send emails pretending to be from " + domain
                            + ". This enables phishing and email spoofing attacks against the"
                            + " organization and its contacts.",
                    "dig TXT " + domain + " +short",
                    "Publish an SPF TXT record for " + domain
                            + " that lists authorized mail servers and ends with -all to reject"
                            + " unauthorized senders. Example: v=spf1 include:_spf.google.com -all",
                    CWE_ID, CWE_TITLE, CVSS_MEDIUM, CvssCalculator.calculate(CVSS_MEDIUM)));
            return;
        }

        log.accept("[~] " + id() + ": SPF record found -- " + spfRecord);
        String lower = spfRecord.toLowerCase(Locale.ROOT);

        if (lower.contains("+all")) {
            log.accept("[!!] " + id() + ": SPF record uses +all -- permits any sender");
            findings.add(Finding.of(id(), domain, "SPF Record Permits Any Sender (+all)", Severity.HIGH,
                    "SPF record: " + spfRecord,
                    "The +all mechanism explicitly authorizes every mail server on the"
                            + " internet to send email on behalf of " + domain
                            + ". This completely negates SPF protection and allows unrestricted" + " email spoofing.",
                    "dig TXT " + domain + " +short",
                    "Replace +all with -all to reject unauthorized senders, or use ~all as"
                            + " a transitional step during deployment.",
                    CWE_ID, CWE_TITLE, CVSS_HIGH, CvssCalculator.calculate(CVSS_HIGH)));
        } else if (lower.contains("~all")) {
            log.accept("[~] " + id() + ": SPF record uses ~all (softfail) -- not enforcing");
            findings.add(Finding.of(id(), domain, "SPF Record Uses Softfail (~all)", Severity.LOW,
                    "SPF record: " + spfRecord,
                    "The ~all mechanism marks unauthorized senders as softfail but does not"
                            + " reject them. Most receivers still deliver these emails, reducing"
                            + " SPF effectiveness against spoofing.",
                    "dig TXT " + domain + " +short",
                    "Change ~all to -all once all legitimate senders are listed in the SPF"
                            + " record. Use DMARC reporting (p=none with rua/ruf) to identify"
                            + " missed sources before switching.",
                    CWE_ID, CWE_TITLE, CVSS_LOW, CvssCalculator.calculate(CVSS_LOW)));
        } else {
            log.accept("[+] " + id() + ": SPF record is properly configured");
        }
    }

    private void checkDmarc(DirContext dnsCtx, String domain, List<Finding> findings, Consumer<String> log) {
        String dmarcDomain = "_dmarc." + domain;
        log.accept("[~] " + id() + ": looking up DMARC record for " + dmarcDomain);
        List<String> txtRecords = lookupTxt(dnsCtx, dmarcDomain, log);
        String dmarcRecord = null;
        for (String txt : txtRecords) {
            if (txt.toLowerCase(Locale.ROOT).startsWith("v=dmarc1")) {
                dmarcRecord = txt;
                break;
            }
        }

        if (dmarcRecord == null) {
            log.accept("[!!] " + id() + ": no DMARC record found for " + dmarcDomain);
            findings.add(Finding.of(id(), domain, "Missing DMARC Record", Severity.MEDIUM,
                    "No TXT record containing v=DMARC1 found at " + dmarcDomain,
                    "Without DMARC, receiving mail servers have no policy for handling"
                            + " emails that fail SPF/DKIM checks. Attackers can spoof " + domain
                            + " with no consequences, enabling phishing campaigns.",
                    "dig TXT " + dmarcDomain + " +short",
                    "Publish a DMARC TXT record at " + dmarcDomain
                            + ". Start with p=none and rua/ruf reporting to monitor, then"
                            + " escalate to p=quarantine or p=reject. Example:"
                            + " v=DMARC1; p=reject; rua=mailto:dmarc@" + domain,
                    CWE_ID, CWE_TITLE, CVSS_MEDIUM, CvssCalculator.calculate(CVSS_MEDIUM)));
            return;
        }

        log.accept("[~] " + id() + ": DMARC record found -- " + dmarcRecord);
        String lower = dmarcRecord.toLowerCase(Locale.ROOT);

        if (extractDmarcPolicy(lower).equals("none")) {
            log.accept("[~] " + id() + ": DMARC policy is p=none -- monitoring only");
            findings.add(Finding.of(id(), domain, "DMARC Policy Set to None (No Enforcement)", Severity.LOW,
                    "DMARC record: " + dmarcRecord,
                    "The p=none policy only monitors email authentication failures without"
                            + " taking action. Spoofed emails will still be delivered to"
                            + " recipients, making phishing attacks possible.",
                    "dig TXT " + dmarcDomain + " +short",
                    "Upgrade the DMARC policy to p=quarantine or p=reject after reviewing"
                            + " aggregate reports to ensure legitimate senders are properly" + " authenticated.",
                    CWE_ID, CWE_TITLE, CVSS_LOW, CvssCalculator.calculate(CVSS_LOW)));
        } else {
            log.accept("[+] " + id() + ": DMARC policy is enforcing");
        }
    }

    private void checkDkim(DirContext dnsCtx, String domain, List<Finding> findings, Consumer<String> log) {
        log.accept("[~] " + id() + ": checking common DKIM selectors for " + domain);
        boolean anyFound = false;

        for (String selector : DKIM_SELECTORS) {
            String dkimDomain = selector + "._domainkey." + domain;
            List<String> txtRecords = lookupTxt(dnsCtx, dkimDomain, log);

            for (String txt : txtRecords) {
                if (txt.toLowerCase(Locale.ROOT).contains("v=dkim1")) {
                    anyFound = true;
                    log.accept("[+] " + id() + ": DKIM record found at " + dkimDomain);

                    int keyBits = estimateDkimKeyBits(txt);
                    if (keyBits > 0 && keyBits < 1024) {
                        log.accept("[!!] " + id() + ": DKIM key at " + dkimDomain + " is weak (" + keyBits + " bits)");
                        findings.add(Finding.of(id(), domain, "Weak DKIM Key (" + keyBits + " bits) at " + selector,
                                Severity.LOW,
                                "DKIM record at " + dkimDomain + " has an estimated key size of " + keyBits + " bits",
                                "DKIM keys shorter than 1024 bits can be factored with moderate"
                                        + " computational resources, allowing an attacker to forge DKIM"
                                        + " signatures and bypass email authentication.",
                                "dig TXT " + dkimDomain + " +short",
                                "Rotate the DKIM key to at least 2048 bits. Update the DNS TXT"
                                        + " record and the mail server signing configuration" + " simultaneously.",
                                CWE_ID, CWE_TITLE, CVSS_LOW, CvssCalculator.calculate(CVSS_LOW)));
                    }
                    break;
                }
            }
        }

        if (!anyFound) {
            log.accept("[~] " + id() + ": no DKIM records found for common selectors");
            findings.add(Finding.of(id(), domain, "No DKIM Records Found (Common Selectors)", Severity.INFO,
                    "No DKIM TXT records found at " + String.join(", ",
                            java.util.Arrays.stream(DKIM_SELECTORS).map(s -> s + "._domainkey." + domain).toList()),
                    "Without DKIM, recipients cannot verify that emails from " + domain
                            + " were authorized and unmodified. Note: the domain may use DKIM"
                            + " selectors not covered by this check.",
                    "dig TXT default._domainkey." + domain + " +short",
                    "Configure DKIM signing on the mail server with a 2048-bit RSA key (or"
                            + " Ed25519) and publish the public key as a TXT record at" + " <selector>._domainkey."
                            + domain,
                    CWE_ID, CWE_TITLE, CVSS_INFO, CvssCalculator.calculate(CVSS_INFO)));
        }
    }

    private List<String> lookupTxt(DirContext dnsCtx, String name, Consumer<String> log) {
        List<String> results = new ArrayList<>();
        try {
            Attributes attrs = dnsCtx.getAttributes(name, new String[]{"TXT"});
            Attribute txtAttr = attrs.get("TXT");
            if (txtAttr != null) {
                for (int i = 0; i < txtAttr.size(); i++) {
                    String val = txtAttr.get(i).toString().trim();
                    // DNS TXT records may be quoted; strip surrounding quotes
                    if (val.startsWith("\"") && val.endsWith("\"")) {
                        val = val.substring(1, val.length() - 1);
                    }
                    results.add(val);
                }
            }
        } catch (NameNotFoundException e) {
            // No record -- not an error, caller handles absence
        } catch (NamingException e) {
            log.accept("[!] " + id() + ": DNS lookup failed for " + name + " -- " + e.getMessage());
        }
        return results;
    }

    private static String extractDmarcPolicy(String dmarcLower) {
        // Parse p=<policy> from DMARC record
        int idx = dmarcLower.indexOf("p=");
        if (idx < 0) {
            return "";
        }
        int start = idx + 2;
        int end = dmarcLower.indexOf(';', start);
        if (end < 0) {
            end = dmarcLower.length();
        }
        return dmarcLower.substring(start, end).trim();
    }

    /**
     * Estimates the DKIM RSA key size from the base64-encoded public key in the TXT
     * record. Returns the estimated bit count, or -1 if the key cannot be parsed.
     */
    private static int estimateDkimKeyBits(String txt) {
        // Extract p= value from the DKIM record
        String lower = txt.toLowerCase(Locale.ROOT);
        int idx = lower.indexOf("p=");
        if (idx < 0) {
            return -1;
        }
        int start = idx + 2;
        int end = txt.indexOf(';', start);
        if (end < 0) {
            end = txt.length();
        }
        String b64Key = txt.substring(start, end).replaceAll("\\s+", "").trim();
        if (b64Key.isEmpty()) {
            return -1;
        }
        try {
            byte[] decoded = java.util.Base64.getDecoder().decode(b64Key);
            // RSA public key DER: rough estimate from byte count
            // SubjectPublicKeyInfo overhead is ~38 bytes for 2048-bit, ~24 for 1024-bit
            // The modulus is the dominant component; approximate key size from decoded
            // length
            return (decoded.length - 30) * 8;
        } catch (IllegalArgumentException e) {
            return -1;
        }
    }

    private static String extractDomain(String host) {
        if (host == null || host.isBlank()) {
            return "";
        }
        // Strip port if present
        int colonIdx = host.indexOf(':');
        if (colonIdx > 0) {
            host = host.substring(0, colonIdx);
        }
        // Strip www. prefix
        if (host.toLowerCase(Locale.ROOT).startsWith("www.")) {
            host = host.substring(4);
        }
        return host;
    }
}
