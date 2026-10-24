package gg.effront.anarcry.harness;

import gg.effront.anarcry.model.Finding;
import gg.effront.anarcry.report.ReportEngine;
import gg.effront.anarcry.scanner.ScanContext;
import gg.effront.anarcry.scanner.ScanRunner;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

/**
 * One-shot integration scan — run with: ./gradlew test --tests
 * "gg.effront.anarcry.harness.CliScanRunner.scanProstaff" --rerun ./gradlew
 * test --tests "gg.effront.anarcry.harness.CliScanRunner.scanScraper" --rerun
 * ./gradlew test --tests
 * "gg.effront.anarcry.harness.CliScanRunner.scanProstaffAllModules" --rerun
 *
 * Reads credentials from .env.local in the project root (target:, jwt1:, jwt2:)
 */
public class CliScanRunner {

    // ──────────────────────────────────────────────────────
    // Utility: load .env.local
    // ──────────────────────────────────────────────────────

    private static Map<String, String> loadEnv() throws IOException {
        Path envFile = Paths.get(System.getProperty("user.dir"), ".env.local");
        Map<String, String> env = new LinkedHashMap<>();
        if (!Files.exists(envFile))
            return env;
        for (String line : Files.readAllLines(envFile)) {
            int colon = line.indexOf(':');
            if (colon > 0) {
                env.put(line.substring(0, colon).trim(), line.substring(colon + 1).trim());
            }
        }
        return env;
    }

    // ──────────────────────────────────────────────────────
    // All enabled modules — includes new Sprint 25/26/28
    // ──────────────────────────────────────────────────────

    private static final Set<String> ALL_MODULES = Set.of("TLS", "Headers", "JWT", "PQC", "CORS", "OAuth",
            "OpenRedirect", "SSRF", "GraphQL", "CRLF", "XXE", "SSTI", "IDOR", "HostHeader", "Actuator", "MassAssign",
            "CachePoisoning", "ReqSmuggling");

    // ──────────────────────────────────────────────────────
    // Legacy test: prostaff.gg frontend (no JWT)
    // ──────────────────────────────────────────────────────

    @Test
    void scanProstaff() throws Exception {
        Map<String, String> env = loadEnv();
        String target = env.getOrDefault("target", "prostaff.gg");
        if (!target.startsWith("http"))
            target = "https://" + target;
        String jwt1 = env.getOrDefault("jwt1", "");

        runScan(target, jwt1, "", Set.of("TLS", "Headers", "JWT", "PQC", "CORS", "OAuth", "OpenRedirect", "SSRF",
                "GraphQL", "CRLF", "CachePoisoning", "ReqSmuggling"), 5);
    }

    // ──────────────────────────────────────────────────────
    // scraper.prostaff.gg — API backend, rich attack surface
    // ──────────────────────────────────────────────────────

    @Test
    void scanScraper() throws Exception {
        Map<String, String> env = loadEnv();
        String jwt1 = env.getOrDefault("jwt1", "");
        String jwt2 = env.getOrDefault("jwt2", "");

        runScan("https://scraper.prostaff.gg", jwt1, jwt2, ALL_MODULES, 10);
    }

    // ──────────────────────────────────────────────────────
    // prostaff.gg frontend + all modules + both JWTs
    // ──────────────────────────────────────────────────────

    @Test
    void scanProstaffAllModules() throws Exception {
        Map<String, String> env = loadEnv();
        String target = env.getOrDefault("target", "prostaff.gg");
        if (!target.startsWith("http"))
            target = "https://" + target;
        String jwt1 = env.getOrDefault("jwt1", "");
        String jwt2 = env.getOrDefault("jwt2", "");

        runScan(target, jwt1, jwt2, ALL_MODULES, 10);
    }

    // ──────────────────────────────────────────────────────
    // Shared runner
    // ──────────────────────────────────────────────────────

    private void runScan(String target, String jwt1, String jwt2, Set<String> modules, int timeoutMinutes)
            throws Exception {
        List<String> logs = Collections.synchronizedList(new ArrayList<>());
        List<Finding> findings = Collections.synchronizedList(new ArrayList<>());
        CountDownLatch done = new CountDownLatch(1);

        ScanRunner runner = new ScanRunner(msg -> {
            logs.add(msg);
            System.out.println(msg);
        }, f -> {
            findings.add(f);
            System.out.printf("[FINDING] %-8s %-16s %s%n", f.severity(), f.module(), f.title());
        });
        runner.setOnScanFinish(done::countDown);

        ScanContext ctx = new ScanContext(target, jwt1, modules, jwt2);

        System.out.println("\n╔═══════════════════════════════════════╗");
        System.out.println("║  AnarCry scan: " + target);
        System.out.println("║  Módulos: " + modules.size());
        System.out.println(
                "║  JWT1: " + (jwt1.isEmpty() ? "none" : jwt1.substring(0, Math.min(20, jwt1.length())) + "…"));
        System.out.println(
                "║  JWT2: " + (jwt2.isEmpty() ? "none" : jwt2.substring(0, Math.min(20, jwt2.length())) + "…"));
        System.out.println("╚═══════════════════════════════════════╝\n");

        runner.run(ctx);
        boolean finished = done.await(timeoutMinutes, TimeUnit.MINUTES);
        runner.shutdown();

        if (!finished) {
            System.out.println("[!] Scan timeout após " + timeoutMinutes + " minutos");
        }

        System.out.println("\n═══ " + findings.size() + " finding(s) ═══");
        findings.stream().sorted(Comparator.comparing(f -> f.severity().ordinal()))
                .forEach(f -> System.out.printf("  %-8s [%s] %s%n", f.severity(), f.module(), f.title()));

        if (!findings.isEmpty()) {
            String report = new ReportEngine().export(findings, target);
            System.out.println("\nReport: " + report);
        }
    }
}
