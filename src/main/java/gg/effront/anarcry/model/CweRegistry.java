package gg.effront.anarcry.model;

import java.util.Map;

public class CweRegistry {

    private static final Map<String, String[]> REGISTRY = Map
            .ofEntries(
                    Map.entry("TLS",
                            new String[]{"CWE-326", "Inadequate Encryption Strength",
                                    "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N"}),
                    Map.entry("Headers",
                            new String[]{"CWE-693", "Protection Mechanism Failure",
                                    "AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N"}),
                    Map.entry("JWT",
                            new String[]{"CWE-347", "Improper Verification of Cryptographic Signature",
                                    "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"}),
                    Map.entry("PQC",
                            new String[]{"CWE-311", "Missing Encryption of Sensitive Data",
                                    "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"}),
                    Map.entry("CORS",
                            new String[]{"CWE-942", "Permissive Cross-domain Policy with Untrusted Domains",
                                    "AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N"}),
                    Map.entry("OAuth",
                            new String[]{"CWE-352", "Cross-Site Request Forgery",
                                    "AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N"}),
                    Map.entry("OpenRedirect",
                            new String[]{"CWE-601", "URL Redirection to Untrusted Site",
                                    "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"}),
                    Map.entry("SSRF",
                            new String[]{"CWE-918", "Server-Side Request Forgery (SSRF)",
                                    "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N"}),
                    Map.entry("GraphQL",
                            new String[]{"CWE-200", "Exposure of Sensitive Information to an Unauthorized Actor",
                                    "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"}),
                    Map.entry("CRLF",
                            new String[]{"CWE-113", "Improper Neutralization of CRLF Sequences in HTTP Headers",
                                    "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"}),
                    Map.entry("XXE",
                            new String[]{"CWE-611", "Improper Restriction of XML External Entity Reference",
                                    "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"}),
                    Map.entry("SSTI",
                            new String[]{"CWE-94", "Improper Control of Generation of Code (Code Injection)",
                                    "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"}),
                    Map.entry("IDOR",
                            new String[]{"CWE-639", "Authorization Bypass Through User-Controlled Key",
                                    "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"}),
                    Map.entry("HostHeader",
                            new String[]{"CWE-20", "Improper Input Validation", "AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N"}),
                    Map.entry("Actuator",
                            new String[]{"CWE-200", "Exposure of Sensitive Information to an Unauthorized Actor",
                                    "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"}),
                    Map.entry("MassAssign",
                            new String[]{"CWE-915",
                                    "Improperly Controlled Modification of Dynamically-Determined Object Attributes",
                                    "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N"}),
                    Map.entry("CachePoisoning",
                            new String[]{"CWE-524", "Use of Cache Containing Sensitive Information",
                                    "AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:N"}),
                    Map.entry("ReqSmuggling",
                            new String[]{"CWE-444",
                                    "Inconsistent Interpretation of HTTP Requests (HTTP Request Smuggling)",
                                    "AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H"}));

    private static final String[] FALLBACK = new String[]{"CWE-200", "Exposure of Sensitive Information",
            CvssCalculator.defaultVector(Severity.MEDIUM)};

    // Retorna {cweId, cweTitle, cvssVector} para o módulo.
    // O vector é o pior caso típico do módulo.
    public static String[] forModule(String moduleId) {
        return REGISTRY.getOrDefault(moduleId, FALLBACK);
    }

    // Conveniência: só o cweId
    public static String cweId(String moduleId) {
        return forModule(moduleId)[0];
    }

    // Conveniência: só o cweTitle
    public static String cweTitle(String moduleId) {
        return forModule(moduleId)[1];
    }

    // Conveniência: só o vector base do módulo
    public static String cvssVector(String moduleId) {
        return forModule(moduleId)[2];
    }
}
