package gg.effront.anarcry.model;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

class KnowledgeBaseTest {

    private final KnowledgeBase kb = KnowledgeBase.getInstance();

    @Test
    void loadsAll25Entries() {
        assertEquals(25, kb.size());
    }

    @Test
    void byIdReturnsAllEntries() {
        List<String> expectedIds = List.of("xss", "sql_injection", "ssrf", "csrf", "idor", "lfi", "command_injection",
                "ssti", "xxe", "cors_misconfiguration", "crlf_injection", "host_header_injection",
                "jwt_signature_bypass", "oauth_misconfiguration", "mass_assignment", "graphql_misconfiguration",
                "request_smuggling", "cache_poisoning", "security_headers_missing", "hsts_missing",
                "infrastructure_exposure", "spring_actuator_exposure", "tls_weak_configuration", "open_redirect",
                "post_quantum_readiness");

        for (String id : expectedIds) {
            assertTrue(kb.byId(id).isPresent(), "Missing entry for id: " + id);
        }
    }

    @Test
    void byModuleCaseInsensitive() {
        assertTrue(kb.byModule("XSS").isPresent());
        assertTrue(kb.byModule("xss").isPresent());
        assertTrue(kb.byModule("Xss").isPresent());

        assertTrue(kb.byModule("SQLi").isPresent());
        assertTrue(kb.byModule("sqli").isPresent());

        assertTrue(kb.byModule("CachePoisoning").isPresent());
        assertTrue(kb.byModule("cachepoisoning").isPresent());

        assertTrue(kb.byModule("CmdInjection").isPresent());
        assertTrue(kb.byModule("cmdinjection").isPresent());
    }

    @Test
    void byModuleReturnsEmptyForUnknown() {
        assertTrue(kb.byModule("NonExistentModule").isEmpty());
        assertTrue(kb.byModule(null).isEmpty());
    }

    @Test
    void byIdReturnsEmptyForUnknown() {
        assertTrue(kb.byId("not_a_real_vuln").isEmpty());
        assertTrue(kb.byId(null).isEmpty());
    }

    @Test
    void entryHasAllFields() {
        KnowledgeEntry xss = kb.byModule("XSS").orElseThrow();

        assertEquals("Cross-Site Scripting", xss.title());
        assertEquals("XSS", xss.module());
        assertEquals("CRITICAL", xss.severity());
        assertEquals("CWE-79", xss.cweId());
        assertFalse(xss.cweTitle().isBlank());
        assertEquals("AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N", xss.cvssVector());
        assertFalse(xss.vrtId().isBlank());
        assertFalse(xss.summary().isBlank());
        assertFalse(xss.description().isBlank());
        assertFalse(xss.impact().isBlank());
        assertFalse(xss.payloads().isEmpty());
        assertNotNull(xss.crawlerHints());
        assertFalse(xss.crawlerHints().parameters().isEmpty());
        assertFalse(xss.crawlerHints().paths().isEmpty());
        assertFalse(xss.recommendation().isBlank());
    }

    @Test
    void payloadsNotEmpty() {
        for (var entry : kb.all().entrySet()) {
            assertFalse(entry.getValue().payloads().isEmpty(), "Payloads empty for: " + entry.getKey());
        }
    }

    @Test
    void hstsCuratedVector() {
        KnowledgeEntry hsts = kb.byModule("HSTS").orElseThrow();
        assertEquals("AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N", hsts.cvssVector());
        double score = CvssCalculator.calculate(hsts.cvssVector());
        assertTrue(score > 0 && score < 5.0, "HSTS curated score should be LOW range, got: " + score);
    }

    @Test
    void pqcCuratedVector() {
        KnowledgeEntry pqc = kb.byModule("PQC").orElseThrow();
        assertEquals("AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N", pqc.cvssVector());
        double score = CvssCalculator.calculate(pqc.cvssVector());
        assertTrue(score > 0 && score < 5.0, "PQC curated score should be LOW range, got: " + score);
    }

    @Test
    void cweRegistryDelegatesCorrectly() {
        String[] xssInfo = CweRegistry.forModule("XSS");
        assertEquals("CWE-79", xssInfo[0]);
        assertFalse(xssInfo[1].isBlank());
        assertFalse(xssInfo[2].isBlank());

        String[] sqliInfo = CweRegistry.forModule("SQLi");
        assertEquals("CWE-89", sqliInfo[0]);
    }

    @Test
    void cweRegistryFallback() {
        String[] unknown = CweRegistry.forModule("TotallyFakeModule");
        assertEquals("CWE-200", unknown[0]);
        assertEquals("Exposure of Sensitive Information", unknown[1]);
    }

    @Test
    void allModulesMatchCweRegistryKeys() {
        List<String> scannerKeys = List.of("TLS", "Headers", "JWT", "PQC", "CORS", "OAuth", "OpenRedirect", "SSRF",
                "GraphQL", "CRLF", "XXE", "SSTI", "IDOR", "HostHeader", "Actuator", "MassAssign", "CachePoisoning",
                "ReqSmuggling", "XSS", "SQLi", "LFI", "CmdInjection", "HSTS", "CSRF", "Infra");

        for (String key : scannerKeys) {
            Optional<KnowledgeEntry> entry = kb.byModule(key);
            assertTrue(entry.isPresent(), "KB missing module for scanner key: " + key);

            String[] cweInfo = CweRegistry.forModule(key);
            assertEquals(entry.get().cweId(), cweInfo[0], "CweRegistry mismatch for key: " + key);
        }
    }

    @Test
    void infrastructureExposureEdgeCase() {
        KnowledgeEntry infra = kb.byModule("Infra").orElseThrow();
        assertTrue(infra.crawlerHints().parameters().isEmpty());
        assertTrue(infra.crawlerHints().paths().isEmpty());
        assertFalse(infra.payloads().isEmpty());
    }

    @Test
    void vrtIdsPresentForAll() {
        for (var entry : kb.all().entrySet()) {
            assertFalse(entry.getValue().vrtId().isBlank(), "VRT ID blank for: " + entry.getKey());
        }
    }
}
