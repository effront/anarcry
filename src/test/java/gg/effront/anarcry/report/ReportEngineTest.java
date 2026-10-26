package gg.effront.anarcry.report;

import gg.effront.anarcry.model.Finding;
import gg.effront.anarcry.model.Severity;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class ReportEngineTest {

    private final ReportEngine engine = new ReportEngine();
    private final List<Path> cleanupPaths = new ArrayList<>();

    @AfterEach
    void cleanup() {
        for (Path p : cleanupPaths) {
            try {
                Files.deleteIfExists(p);
            } catch (IOException ignored) {
            }
        }
    }

    private Finding xssFinding() {
        return Finding.of("XSS", "https://target.com/search?q=test", "Reflected XSS in search", Severity.CRITICAL,
                "<script>alert(1)</script> reflected in response", "Session hijacking possible",
                "curl 'https://target.com/search?q=<script>alert(1)</script>'", "Encode output");
    }

    private Finding unknownModuleFinding() {
        return Finding.of("UnknownModule", "https://target.com/api", "Unknown finding", Severity.LOW, "Some evidence",
                "Low impact", "curl https://target.com/api", "Fix it");
    }

    @Test
    void h1ExportContainsKBSections() throws IOException {
        String file = engine.exportH1(List.of(xssFinding()), "https://target.com", "TestProgram");
        cleanupPaths.add(Path.of(file));

        String content = Files.readString(Path.of(file));

        assertTrue(content.contains("# [CRITICAL]"), "Missing severity header");
        assertTrue(content.contains("**Program:** TestProgram"), "Missing program name");
        assertTrue(content.contains("**Asset:** https://target.com"), "Missing asset");
        assertTrue(content.contains("**Weakness:** CWE-79"), "Missing CWE");
        assertTrue(content.contains("## Summary"), "Missing Summary section");
        assertTrue(content.contains("## Description"), "Missing Description section");
        assertTrue(content.contains("## Steps to Reproduce"), "Missing Steps section");
        assertTrue(content.contains("## Impact"), "Missing Impact section");
        assertTrue(content.contains("## Mitigation"), "Missing Mitigation section");
        assertTrue(content.contains("## Supporting Material"), "Missing Supporting Material");
        assertTrue(content.contains("Scanner: AnarCry"), "Missing scanner attribution");
        assertFalse(content.contains("null"), "Null value leaked into report");
    }

    @Test
    void h1ExportInjectsEvidence() throws IOException {
        String file = engine.exportH1(List.of(xssFinding()), "https://target.com", "TestProgram");
        cleanupPaths.add(Path.of(file));

        String content = Files.readString(Path.of(file));
        assertTrue(content.contains("### Observed Evidence"), "Missing evidence subsection");
        assertTrue(content.contains("<script>alert(1)</script>"), "Missing actual evidence");
    }

    @Test
    void bugcrowdExportContainsVRT() throws IOException {
        String file = engine.exportBugcrowd(List.of(xssFinding()), "https://target.com");
        cleanupPaths.add(Path.of(file));

        String content = Files.readString(Path.of(file));

        assertTrue(content.contains("**Classification (VRT):** `cross_site_scripting_xss"),
                "Missing VRT classification");
        assertTrue(content.contains("### Proof of Concept"), "Missing PoC section");
        assertTrue(content.contains("### Replication Steps"), "Missing Replication Steps");
        assertTrue(content.contains("### Impact"), "Missing Impact section");
        assertTrue(content.contains("### Remediation"), "Missing Remediation section");
        assertFalse(content.contains("null"), "Null value leaked into report");
    }

    @Test
    void bugcrowdExportSeparatesEvidenceAndReproduction() throws IOException {
        String file = engine.exportBugcrowd(List.of(xssFinding()), "https://target.com");
        cleanupPaths.add(Path.of(file));

        String content = Files.readString(Path.of(file));
        int pocIdx = content.indexOf("### Proof of Concept");
        int stepsIdx = content.indexOf("### Replication Steps");
        assertTrue(pocIdx < stepsIdx, "PoC should come before Replication Steps");
        assertTrue(content.indexOf("**Evidence:**") < content.indexOf("**Reproduction:**"),
                "Evidence should come before Reproduction in PoC");
    }

    @Test
    void unknownModuleFallsBackGracefully() throws IOException {
        String h1File = engine.exportH1(List.of(unknownModuleFinding()), "https://target.com", "Test");
        cleanupPaths.add(Path.of(h1File));
        String h1Content = Files.readString(Path.of(h1File));
        assertFalse(h1Content.contains("null"), "Null leaked in H1 fallback");
        assertTrue(h1Content.contains("## Summary"), "H1 fallback missing Summary");

        String bcFile = engine.exportBugcrowd(List.of(unknownModuleFinding()), "https://target.com");
        cleanupPaths.add(Path.of(bcFile));
        String bcContent = Files.readString(Path.of(bcFile));
        assertTrue(bcContent.contains("`other`"), "Bugcrowd fallback should use 'other' VRT");
        assertFalse(bcContent.contains("null"), "Null leaked in Bugcrowd fallback");
    }

    @Test
    void multipleFindings() throws IOException {
        List<Finding> findings = List.of(xssFinding(), unknownModuleFinding());

        String h1File = engine.exportH1(findings, "https://target.com", "Multi");
        cleanupPaths.add(Path.of(h1File));
        String h1 = Files.readString(Path.of(h1File));
        assertEquals(2, countOccurrences(h1, "## Summary"), "H1 should have 2 findings");

        String bcFile = engine.exportBugcrowd(findings, "https://target.com");
        cleanupPaths.add(Path.of(bcFile));
        String bc = Files.readString(Path.of(bcFile));
        assertEquals(2, countOccurrences(bc, "### Proof of Concept"), "Bugcrowd should have 2 findings");
    }

    private static int countOccurrences(String text, String sub) {
        int count = 0;
        int idx = 0;
        while ((idx = text.indexOf(sub, idx)) != -1) {
            count++;
            idx += sub.length();
        }
        return count;
    }
}
