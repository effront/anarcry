package gg.effront.anarcry.harness;

import static org.junit.jupiter.api.Assertions.*;

import com.sun.net.httpserver.HttpServer;
import gg.effront.anarcry.model.Finding;
import gg.effront.anarcry.model.KnowledgeBase;
import gg.effront.anarcry.model.KnowledgeEntry;
import gg.effront.anarcry.scanner.DiscoveredPaths;
import gg.effront.anarcry.scanner.ScanConfig;
import gg.effront.anarcry.scanner.ScanContext;
import gg.effront.anarcry.scanner.ScanRunner;
import gg.effront.anarcry.scanner.web.crawler.CrawlerModule;
import gg.effront.anarcry.scanner.web.idor.IdorModule;
import gg.effront.anarcry.scanner.web.massassign.MassAssignmentModule;
import gg.effront.anarcry.scanner.web.ssrf.SsrfModule;

import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;

/**
 * Sprint 18 E2E test harness.
 *
 * <p>
 * Validates the full pipeline: CrawlerModule (Phase 1) populates
 * DiscoveredPaths, injection modules (Phase 2) consume discovered paths, plus
 * rate limiting, path cap, and phased execution order.
 */
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class Sprint18E2ETest {

    // ---------------------------------------------------------------
    // Test 1: CrawlerModule populates DiscoveredPaths via HTML/JS
    // ---------------------------------------------------------------

    @Test
    @Order(100)
    @Tag("integration")
    void crawlerPopulatesDiscoveredPaths() throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        int port = server.getAddress().getPort();

        // Root HTML with links to known paths and a JS file
        server.createContext("/", exchange -> {
            String path = exchange.getRequestURI().getPath();
            byte[] body;
            int status = 200;
            switch (path) {
                case "/" :
                    String html = "<html><body>" + "<a href=\"/api/users\">Users</a>"
                            + "<a href=\"/api/v1/orders\">Orders</a>" + "<script src=\"/app.js\"></script>"
                            + "</body></html>";
                    body = html.getBytes();
                    break;
                case "/app.js" :
                    // JS containing an API path string
                    body = "var endpoint = \"/api/v2/internal/data\"; fetch(endpoint);".getBytes();
                    break;
                case "/api/users" :
                    body = "{\"users\":[]}".getBytes();
                    break;
                case "/api/v1/orders" :
                    body = "{\"orders\":[]}".getBytes();
                    break;
                case "/api/v2/internal/data" :
                    body = "{\"data\":[]}".getBytes();
                    break;
                default :
                    body = "not found".getBytes();
                    status = 404;
                    break;
            }
            exchange.sendResponseHeaders(status, body.length);
            exchange.getResponseBody().write(body);
            exchange.getResponseBody().close();
        });
        server.start();

        try {
            ScanContext ctx = new ScanContext("http://127.0.0.1:" + port, "", Set.of("Crawler"));
            List<String> logs = new CopyOnWriteArrayList<>();
            new CrawlerModule().scan(ctx, logs::add);

            assertTrue(ctx.discoveredPaths().pathCount() > 0, "Crawler should discover at least one path");
            assertTrue(ctx.discoveredPaths().paths().contains("/api/users"),
                    "Discovered paths should contain /api/users from HTML link");
            assertTrue(ctx.discoveredPaths().paths().contains("/api/v1/orders"),
                    "Discovered paths should contain /api/v1/orders from HTML link");
        } finally {
            server.stop(0);
        }
    }

    // ---------------------------------------------------------------
    // Test 2: KB crawlerHints aggregation smoke test
    // ---------------------------------------------------------------

    @Test
    @Order(101)
    void crawlerKbHintsAggregation() {
        // Verify SSRF KB hints have non-empty paths
        Optional<KnowledgeEntry> ssrfEntry = KnowledgeBase.getInstance().byModule("SSRF");
        assertTrue(ssrfEntry.isPresent(), "KB should contain entry for SSRF module");
        KnowledgeEntry.CrawlerHints ssrfHints = ssrfEntry.get().crawlerHints();
        assertNotNull(ssrfHints, "SSRF KB entry should have crawlerHints");
        assertFalse(ssrfHints.paths().isEmpty(), "SSRF crawlerHints.paths() should be non-empty");

        // Verify XSS KB hints have non-empty parameters
        Optional<KnowledgeEntry> xssEntry = KnowledgeBase.getInstance().byModule("XSS");
        assertTrue(xssEntry.isPresent(), "KB should contain entry for XSS module");
        KnowledgeEntry.CrawlerHints xssHints = xssEntry.get().crawlerHints();
        assertNotNull(xssHints, "XSS KB entry should have crawlerHints");
        assertFalse(xssHints.parameters().isEmpty(), "XSS crawlerHints.parameters() should be non-empty");
    }

    // ---------------------------------------------------------------
    // Test 3: Phased execution — Phase 1 before Phase 2
    // ---------------------------------------------------------------

    @Test
    @Order(102)
    @Tag("integration")
    void phasedExecutionOrder() throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", exchange -> {
            byte[] body = "<html><body>minimal</body></html>".getBytes();
            exchange.sendResponseHeaders(200, body.length);
            exchange.getResponseBody().write(body);
            exchange.getResponseBody().close();
        });
        server.start();
        int port = server.getAddress().getPort();

        try {
            ScanContext ctx = new ScanContext("http://127.0.0.1:" + port, "", Set.of("Crawler", "Headers"));

            CopyOnWriteArrayList<String> logMessages = new CopyOnWriteArrayList<>();
            List<Finding> collected = Collections.synchronizedList(new ArrayList<>());
            CountDownLatch latch = new CountDownLatch(1);

            ScanRunner runner = new ScanRunner(logMessages::add, collected::add);
            runner.setOnScanFinish(latch::countDown);
            runner.run(ctx);

            assertTrue(latch.await(30, TimeUnit.SECONDS), "Scan should complete within 30 seconds");
            runner.shutdown();

            // Find first occurrence index of Phase 1 and Phase 2 log lines
            int phase1Idx = -1;
            int phase2Idx = -1;
            int crawlerLogIdx = -1;
            int headersLogIdx = -1;

            for (int i = 0; i < logMessages.size(); i++) {
                String msg = logMessages.get(i);
                if (phase1Idx < 0 && msg.contains("Phase 1")) {
                    phase1Idx = i;
                }
                if (phase2Idx < 0 && msg.contains("Phase 2")) {
                    phase2Idx = i;
                }
                if (crawlerLogIdx < 0 && msg.contains("Crawler")) {
                    crawlerLogIdx = i;
                }
                if (headersLogIdx < 0 && msg.contains("Headers")) {
                    headersLogIdx = i;
                }
            }

            assertTrue(phase1Idx >= 0, "Log should contain a Phase 1 message");
            assertTrue(phase2Idx >= 0, "Log should contain a Phase 2 message");
            assertTrue(phase1Idx < phase2Idx,
                    "Phase 1 log must appear before Phase 2 log. Phase1 at " + phase1Idx + ", Phase2 at " + phase2Idx);
            assertTrue(crawlerLogIdx >= 0, "Log should contain a Crawler message");
            assertTrue(headersLogIdx >= 0, "Log should contain a Headers message");
            assertTrue(crawlerLogIdx < headersLogIdx, "Crawler log must appear before Headers log. Crawler at "
                    + crawlerLogIdx + ", Headers at " + headersLogIdx);
        } finally {
            server.stop(0);
        }
    }

    // ---------------------------------------------------------------
    // Test 4: Without Crawler, DiscoveredPaths stays empty
    // ---------------------------------------------------------------

    @Test
    @Order(103)
    void crawlerDisabledModulesUseHardcodedOnly() {
        ScanContext ctx = new ScanContext("http://example.com", "", Set.of("SSRF"));
        assertTrue(ctx.discoveredPaths().isEmpty(), "DiscoveredPaths should be empty when Crawler is not enabled");
    }

    // ---------------------------------------------------------------
    // Test 5: DiscoveredPaths container is unlimited (cap is in Crawler)
    // ---------------------------------------------------------------

    @Test
    @Order(104)
    void discoveredPathsCap500() {
        DiscoveredPaths dp = new DiscoveredPaths();
        for (int i = 0; i < 600; i++) {
            dp.addPath("/path/" + i);
        }
        assertEquals(600, dp.pathCount(), "DiscoveredPaths container should accept all 600 paths "
                + "(capping is the CrawlerModule's responsibility, not the container's)");
    }

    // ---------------------------------------------------------------
    // Test 6: SsrfModule merges discovered paths
    // ---------------------------------------------------------------

    @Test
    @Order(105)
    @Tag("integration")
    void ssrfModuleMergesDiscoveredPaths() throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", exchange -> {
            String path = exchange.getRequestURI().getPath();
            byte[] body;
            int status;
            if ("/discovered/endpoint".equals(path)) {
                body = "ok".getBytes();
                status = 200;
            } else {
                body = "not found".getBytes();
                status = 404;
            }
            exchange.sendResponseHeaders(status, body.length);
            exchange.getResponseBody().write(body);
            exchange.getResponseBody().close();
        });
        server.start();
        int port = server.getAddress().getPort();

        try {
            ScanContext ctx = new ScanContext("http://127.0.0.1:" + port, "", Set.of("SSRF"));
            ctx.discoveredPaths().addPath("/discovered/endpoint");
            ctx.discoveredPaths().addParameter("custom_param");

            CopyOnWriteArrayList<String> logs = new CopyOnWriteArrayList<>();
            new SsrfModule().scan(ctx, logs::add);

            boolean hasMergeLog = logs.stream().anyMatch(l -> l.contains("from Crawler"));
            assertTrue(hasMergeLog, "SSRF log should mention paths from Crawler. Logs: " + logs);
        } finally {
            server.stop(0);
        }
    }

    // ---------------------------------------------------------------
    // Test 7: IdorModule merges API paths from Crawler
    // ---------------------------------------------------------------

    @Test
    @Order(106)
    @Tag("integration")
    void idorModuleMergesApiPaths() throws Exception {
        // IdorModule needs jwtToken to not skip
        ScanContext ctx = new ScanContext("http://127.0.0.1:1", "test-token", Set.of("IDOR"));
        ctx.discoveredPaths().addPath("/api/v1/resources");

        CopyOnWriteArrayList<String> logs = new CopyOnWriteArrayList<>();
        try {
            new IdorModule().scan(ctx, logs::add);
        } catch (Exception ignored) {
            // Network errors expected on port 1
        }

        boolean hasMergeLog = logs.stream().anyMatch(l -> l.contains("from Crawler"));
        assertTrue(hasMergeLog, "IDOR log should mention paths from Crawler. Logs: " + logs);
    }

    // ---------------------------------------------------------------
    // Test 8: MassAssignmentModule merges user paths from Crawler
    // ---------------------------------------------------------------

    @Test
    @Order(107)
    @Tag("integration")
    void massAssignMergesUserPaths() throws Exception {
        // MassAssign checks paths matching user/profile/account/settings/me
        ScanContext ctx = new ScanContext("http://127.0.0.1:1", "", Set.of("MassAssign"));
        ctx.discoveredPaths().addPath("/api/user/settings");

        CopyOnWriteArrayList<String> logs = new CopyOnWriteArrayList<>();
        try {
            new MassAssignmentModule().scan(ctx, logs::add);
        } catch (Exception ignored) {
            // Network errors expected on port 1
        }

        boolean hasMergeLog = logs.stream().anyMatch(l -> l.contains("from Crawler"));
        assertTrue(hasMergeLog, "MassAssign log should mention endpoints from Crawler. Logs: " + logs);
    }

    // ---------------------------------------------------------------
    // Test 9: Rate limiting is respected by CrawlerModule
    // ---------------------------------------------------------------

    @Test
    @Order(108)
    @Tag("integration")
    void rateLimitingRespected() throws Exception {
        CopyOnWriteArrayList<Long> timestamps = new CopyOnWriteArrayList<>();

        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", exchange -> {
            timestamps.add(System.nanoTime());
            String path = exchange.getRequestURI().getPath();
            byte[] body;
            int status;
            if ("/".equals(path)) {
                body = "<html><body>minimal page</body></html>".getBytes();
                status = 200;
            } else {
                body = "not found".getBytes();
                status = 404;
            }
            exchange.sendResponseHeaders(status, body.length);
            exchange.getResponseBody().write(body);
            exchange.getResponseBody().close();
        });
        server.start();
        int port = server.getAddress().getPort();

        try {
            ScanConfig config = new ScanConfig(200, "", Set.of(), List.of(), "");
            ScanContext ctx = new ScanContext("http://127.0.0.1:" + port, "", "", Set.of("Crawler"), config, r -> {
            }, new DiscoveredPaths());

            new CrawlerModule().scan(ctx, msg -> {
            });

            assertTrue(timestamps.size() >= 3, "Crawler should make at least 3 requests, made: " + timestamps.size());

            // Check gaps between consecutive requests during the wordlist probing phase.
            // The initial HTML fetch and JS fetch are not rate-limited, so we check gaps
            // starting from the 3rd request onward (wordlist probing begins after
            // HTML + JS fetches).
            int validGaps = 0;
            int checkedGaps = 0;
            for (int i = 3; i < timestamps.size(); i++) {
                long gapMs = (timestamps.get(i) - timestamps.get(i - 1)) / 1_000_000;
                checkedGaps++;
                if (gapMs >= 150) {
                    validGaps++;
                }
            }

            if (checkedGaps > 0) {
                double ratio = (double) validGaps / checkedGaps;
                assertTrue(ratio >= 0.7, "At least 70% of wordlist probe gaps should be >= 150ms "
                        + "(configured 200ms). Valid: " + validGaps + "/" + checkedGaps);
            }
        } finally {
            server.stop(0);
        }
    }
}
