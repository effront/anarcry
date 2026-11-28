package gg.effront.anarcry.artex;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import gg.effront.anarcry.model.CvssCalculator;
import gg.effront.anarcry.model.CweRegistry;
import gg.effront.anarcry.model.Finding;
import gg.effront.anarcry.model.Severity;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Converts ARTEX finding JSON into AnarCry {@link Finding} records. Handles
 * missing fields gracefully -- every field has a sensible default so a partial
 * ARTEX response never causes an exception.
 */
public final class ArtexFindingConverter {

    /**
     * Maps ARTEX vulnclass identifiers to AnarCry module IDs. ARTEX uses
     * lowercase-hyphenated names while AnarCry uses short PascalCase/acronym IDs.
     */
    private static final Map<String, String> VULNCLASS_TO_MODULE = Map.ofEntries(Map.entry("sql-injection", "SQLi"),
            Map.entry("sqli", "SQLi"), Map.entry("xss", "XSS"), Map.entry("cross-site-scripting", "XSS"),
            Map.entry("ssrf", "SSRF"), Map.entry("server-side-request-forgery", "SSRF"), Map.entry("ssti", "SSTI"),
            Map.entry("server-side-template-injection", "SSTI"), Map.entry("lfi", "LFI"),
            Map.entry("local-file-inclusion", "LFI"), Map.entry("command-injection", "CmdInjection"),
            Map.entry("cmd-injection", "CmdInjection"), Map.entry("os-command-injection", "CmdInjection"),
            Map.entry("cors", "CORS"), Map.entry("cors-misconfiguration", "CORS"),
            Map.entry("open-redirect", "OpenRedirect"), Map.entry("open-redirection", "OpenRedirect"),
            Map.entry("xxe", "XXE"), Map.entry("xml-external-entity", "XXE"), Map.entry("idor", "IDOR"),
            Map.entry("insecure-direct-object-reference", "IDOR"), Map.entry("jwt", "JWT"),
            Map.entry("jwt-attack", "JWT"), Map.entry("tls", "TLS"), Map.entry("tls-misconfiguration", "TLS"),
            Map.entry("headers", "Headers"), Map.entry("security-headers", "Headers"), Map.entry("hsts", "HSTS"),
            Map.entry("graphql", "GraphQL"), Map.entry("graphql-introspection", "GraphQL"), Map.entry("crlf", "CRLF"),
            Map.entry("crlf-injection", "CRLF"), Map.entry("host-header", "HostHeader"),
            Map.entry("host-header-injection", "HostHeader"), Map.entry("mass-assignment", "MassAssign"),
            Map.entry("cache-poisoning", "CachePoisoning"), Map.entry("request-smuggling", "ReqSmuggling"),
            Map.entry("http-request-smuggling", "ReqSmuggling"), Map.entry("csrf", "CSRF"),
            Map.entry("cross-site-request-forgery", "CSRF"), Map.entry("nosql-injection", "NoSQLi"),
            Map.entry("nosqli", "NoSQLi"), Map.entry("deserialization", "Deserialization"),
            Map.entry("insecure-deserialization", "Deserialization"), Map.entry("file-upload", "FileUpload"),
            Map.entry("subdomain-takeover", "SubTakeover"), Map.entry("websocket", "WebSocket"),
            Map.entry("prototype-pollution", "ProtoPollution"), Map.entry("cloud-misconfiguration", "CloudMisconfig"),
            Map.entry("oauth", "OAuth"), Map.entry("oauth-misconfiguration", "OAuth"),
            Map.entry("actuator", "Actuator"), Map.entry("spring-actuator", "Actuator"),
            Map.entry("secrets", "Secrets"), Map.entry("secret-exposure", "Secrets"),
            Map.entry("race-condition", "RaceCondition"), Map.entry("clickjacking", "Clickjacking"),
            Map.entry("pqc", "PQC"));

    private ArtexFindingConverter() {
    }

    /**
     * Converts a JSON array of ARTEX findings into AnarCry Finding records.
     *
     * <p>
     * Expected ARTEX finding JSON shape:
     *
     * <pre>{@code
     * {
     *   "vulnclass": "sql-injection",
     *   "endpoint": "https://target.com/api/users?id=1",
     *   "title": "SQL Injection in id parameter",
     *   "severity": "critical",
     *   "evidence": "...",
     *   "impact": "...",
     *   "reproduction": "...",
     *   "recommendation": "...",
     *   "cwe_id": "CWE-89",
     *   "cwe_title": "SQL Injection",
     *   "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
     *   "cvss_score": 9.8
     * }
     * }</pre>
     *
     * <p>
     * All fields except {@code vulnclass} are optional. Missing fields fall back to
     * defaults.
     *
     * @param artexFindings
     *            the ARTEX findings JSON array
     * @return list of AnarCry Finding records (never null, may be empty)
     */
    public static List<Finding> convert(JsonArray artexFindings) {
        if (artexFindings == null || artexFindings.isEmpty()) {
            return List.of();
        }
        List<Finding> results = new ArrayList<>(artexFindings.size());
        for (JsonElement elem : artexFindings) {
            if (!elem.isJsonObject()) {
                continue;
            }
            Finding f = convertSingle(elem.getAsJsonObject());
            if (f != null) {
                results.add(f);
            }
        }
        return results;
    }

    /**
     * Converts a single ARTEX finding JSON object to an AnarCry Finding.
     *
     * @param obj
     *            the ARTEX finding JSON
     * @return a Finding, or null if the object is unusable
     */
    public static Finding convertSingle(JsonObject obj) {
        if (obj == null) {
            return null;
        }

        String vulnclass = str(obj, "vulnclass", "");
        String module = mapVulnClass(vulnclass);
        String endpoint = str(obj, "endpoint", "unknown");
        String title = str(obj, "title", "ARTEX Finding -- " + vulnclass);
        Severity severity = mapSeverity(str(obj, "severity", "info"));
        String evidence = str(obj, "evidence", "Detected by ARTEX remote engine");
        String impact = str(obj, "impact", "");
        String reproduction = str(obj, "reproduction", "");
        String recommendation = str(obj, "recommendation", "");

        // CWE/CVSS: prefer ARTEX-provided values, fall back to CweRegistry
        String cweId = str(obj, "cwe_id", "");
        String cweTitle = str(obj, "cwe_title", "");
        String cvssVector = str(obj, "cvss_vector", "");
        double cvssScore = dbl(obj, "cvss_score", -1.0);

        if (cweId.isEmpty()) {
            cweId = CweRegistry.cweId(module);
        }
        if (cweTitle.isEmpty()) {
            cweTitle = CweRegistry.cweTitle(module);
        }
        if (cvssVector.isEmpty()) {
            cvssVector = CweRegistry.cvssVector(module);
        }
        if (cvssScore < 0) {
            cvssScore = CvssCalculator.calculate(cvssVector);
        }

        return Finding.of(module, endpoint, title, severity, evidence, impact, reproduction, recommendation, cweId,
                cweTitle, cvssVector, cvssScore);
    }

    /**
     * Maps an ARTEX vulnclass string to an AnarCry module ID. Falls back to "ARTEX"
     * prefixed module name for unknown classes.
     */
    static String mapVulnClass(String vulnclass) {
        if (vulnclass == null || vulnclass.isBlank()) {
            return "ARTEX";
        }
        String normalized = vulnclass.toLowerCase().strip();
        String mapped = VULNCLASS_TO_MODULE.get(normalized);
        return mapped != null ? mapped : "ARTEX-" + normalized;
    }

    /** Maps an ARTEX severity string to the AnarCry Severity enum. */
    static Severity mapSeverity(String severity) {
        if (severity == null || severity.isBlank()) {
            return Severity.INFO;
        }
        return switch (severity.toLowerCase().strip()) {
            case "critical", "crit" -> Severity.CRITICAL;
            case "high" -> Severity.HIGH;
            case "medium", "med" -> Severity.MEDIUM;
            case "low" -> Severity.LOW;
            default -> Severity.INFO;
        };
    }

    private static String str(JsonObject obj, String key, String fallback) {
        if (obj.has(key) && obj.get(key).isJsonPrimitive()) {
            String val = obj.get(key).getAsString();
            return val != null ? val : fallback;
        }
        return fallback;
    }

    private static double dbl(JsonObject obj, String key, double fallback) {
        if (obj.has(key) && obj.get(key).isJsonPrimitive()) {
            try {
                return obj.get(key).getAsDouble();
            } catch (NumberFormatException e) {
                return fallback;
            }
        }
        return fallback;
    }
}
