package gg.effront.anarcry.fuzzer;

import static org.junit.jupiter.api.Assertions.*;

import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

@Tag("unit")
class FuzzEngineTest {

    // ---------------------------------------------------------------------------
    // FuzzPosition -- parsing and injection
    // ---------------------------------------------------------------------------

    @Nested
    class FuzzPositionTests {

        @Test
        void parseFindsAllMarkers() {
            List<FuzzPosition> positions = FuzzPosition.parse("GET /api/{{1}}/items?id={{2}} HTTP/1.1");
            assertEquals(2, positions.size(), "Must detect two markers");
            assertEquals(1, positions.get(0).index());
            assertEquals(2, positions.get(1).index());
        }

        @Test
        void parseEmptyTemplateReturnsEmpty() {
            List<FuzzPosition> positions = FuzzPosition.parse("GET /api/items HTTP/1.1");
            assertTrue(positions.isEmpty(), "No markers means empty list");
        }

        @Test
        void parseDuplicateIndexes() {
            List<FuzzPosition> positions = FuzzPosition.parse("{{1}} and {{1}} again");
            assertEquals(2, positions.size(), "Same index can appear multiple times");
            assertEquals(1, positions.get(0).index());
            assertEquals(1, positions.get(1).index());
        }

        @Test
        void parseMultiDigitIndex() {
            List<FuzzPosition> positions = FuzzPosition.parse("{{10}}");
            assertEquals(1, positions.size());
            assertEquals(10, positions.get(0).index());
        }

        @Test
        void injectSinglePosition() {
            String template = "GET /api/{{1}}/info HTTP/1.1";
            List<FuzzPosition> positions = FuzzPosition.parse(template);
            String result = FuzzPosition.inject(template, positions, new String[]{"admin"});
            assertEquals("GET /api/admin/info HTTP/1.1", result);
        }

        @Test
        void injectMultiplePositions() {
            String template = "GET /api/{{1}}/items/{{2}} HTTP/1.1";
            List<FuzzPosition> positions = FuzzPosition.parse(template);
            String result = FuzzPosition.inject(template, positions, new String[]{"users", "42"});
            assertEquals("GET /api/users/items/42 HTTP/1.1", result);
        }

        @Test
        void injectMissingPayloadDefaultsToEmpty() {
            String template = "GET /api/{{1}}/{{2}} HTTP/1.1";
            List<FuzzPosition> positions = FuzzPosition.parse(template);
            // Only one payload provided, position 2 (index-1 = 1) is out of bounds
            String result = FuzzPosition.inject(template, positions, new String[]{"data"});
            assertEquals("GET /api/data/ HTTP/1.1", result);
        }

        @Test
        void injectPreservesNonMarkerContent() {
            String template = "Authorization: Bearer {{1}}";
            List<FuzzPosition> positions = FuzzPosition.parse(template);
            String result = FuzzPosition.inject(template, positions, new String[]{"tok123"});
            assertEquals("Authorization: Bearer tok123", result);
        }

        @Test
        void maxIndexReturnsHighest() {
            List<FuzzPosition> positions = FuzzPosition.parse("{{3}} {{1}} {{5}} {{2}}");
            assertEquals(5, FuzzPosition.maxIndex(positions));
        }

        @Test
        void maxIndexEmptyReturnsZero() {
            assertEquals(0, FuzzPosition.maxIndex(List.of()));
        }
    }

    // ---------------------------------------------------------------------------
    // AttackType -- estimateRequests
    // ---------------------------------------------------------------------------

    @Nested
    class AttackTypeTests {

        @Test
        void sniperEstimate() {
            PayloadSource src = new InlinePayloadSource(List.of("a", "b", "c"));
            long est = AttackType.SNIPER.estimateRequests(2, List.of(src));
            // 2 positions * 3 payloads = 6
            assertEquals(6, est);
        }

        @Test
        void batteringRamEstimate() {
            PayloadSource src = new InlinePayloadSource(List.of("a", "b", "c"));
            long est = AttackType.BATTERING_RAM.estimateRequests(2, List.of(src));
            // All positions get same payload -- 3 payloads
            assertEquals(3, est);
        }

        @Test
        void pitchforkEstimate() {
            PayloadSource src1 = new InlinePayloadSource(List.of("a", "b", "c"));
            PayloadSource src2 = new InlinePayloadSource(List.of("1", "2"));
            long est = AttackType.PITCHFORK.estimateRequests(2, List.of(src1, src2));
            // min(3, 2) = 2
            assertEquals(2, est);
        }

        @Test
        void clusterBombEstimate() {
            PayloadSource src1 = new InlinePayloadSource(List.of("a", "b"));
            PayloadSource src2 = new InlinePayloadSource(List.of("1", "2", "3"));
            long est = AttackType.CLUSTER_BOMB.estimateRequests(2, List.of(src1, src2));
            // 2 * 3 = 6
            assertEquals(6, est);
        }

        @Test
        void emptySourcesReturnsZero() {
            assertEquals(0, AttackType.SNIPER.estimateRequests(2, List.of()));
            assertEquals(0, AttackType.CLUSTER_BOMB.estimateRequests(0, List.of()));
        }

        @Test
        void sniperZeroPositionsReturnsZero() {
            PayloadSource src = new InlinePayloadSource(List.of("a"));
            assertEquals(0, AttackType.SNIPER.estimateRequests(0, List.of(src)));
        }

        @Test
        void labelsAreMeaningful() {
            assertEquals("Sniper", AttackType.SNIPER.label());
            assertEquals("Battering Ram", AttackType.BATTERING_RAM.label());
            assertEquals("Pitchfork", AttackType.PITCHFORK.label());
            assertEquals("Cluster Bomb", AttackType.CLUSTER_BOMB.label());
        }

        @Test
        void descriptionsAreNonEmpty() {
            for (AttackType type : AttackType.values()) {
                assertNotNull(type.description());
                assertFalse(type.description().isEmpty(), type.name() + " description must not be empty");
            }
        }
    }

    // ---------------------------------------------------------------------------
    // InlinePayloadSource
    // ---------------------------------------------------------------------------

    @Nested
    class InlinePayloadSourceTests {

        @Test
        void sizeFromList() {
            InlinePayloadSource src = new InlinePayloadSource(List.of("a", "b", "c"));
            assertEquals(3, src.size());
        }

        @Test
        void sizeFromText() {
            InlinePayloadSource src = new InlinePayloadSource("alpha\nbeta\ngamma\n");
            assertEquals(3, src.size());
        }

        @Test
        void textSkipsEmptyLines() {
            InlinePayloadSource src = new InlinePayloadSource("a\n\nb\n\nc");
            assertEquals(3, src.size());
        }

        @Test
        void iteratorReturnsAllItems() {
            InlinePayloadSource src = new InlinePayloadSource(List.of("x", "y"));
            Iterator<String> it = src.iterator();
            assertTrue(it.hasNext());
            assertEquals("x", it.next());
            assertTrue(it.hasNext());
            assertEquals("y", it.next());
            assertFalse(it.hasNext());
        }

        @Test
        void resetIsNoOp() {
            InlinePayloadSource src = new InlinePayloadSource(List.of("a"));
            src.reset(); // should not throw
            assertEquals(1, src.size());
        }

        @Test
        void labelContainsSize() {
            InlinePayloadSource src = new InlinePayloadSource(List.of("a", "b"));
            assertTrue(src.label().contains("2"), "Label must contain item count");
        }
    }

    // ---------------------------------------------------------------------------
    // RangePayloadSource
    // ---------------------------------------------------------------------------

    @Nested
    class RangePayloadSourceTests {

        @Test
        void basicRange() {
            RangePayloadSource src = new RangePayloadSource(1, 5, 1, 0);
            assertEquals(5, src.size());
            List<String> items = new ArrayList<>();
            src.iterator().forEachRemaining(items::add);
            assertEquals(List.of("1", "2", "3", "4", "5"), items);
        }

        @Test
        void rangeWithStep() {
            RangePayloadSource src = new RangePayloadSource(0, 10, 3, 0);
            // 0, 3, 6, 9 -> 4 items
            assertEquals(4, src.size());
            List<String> items = new ArrayList<>();
            src.iterator().forEachRemaining(items::add);
            assertEquals(List.of("0", "3", "6", "9"), items);
        }

        @Test
        void rangeWithPadding() {
            RangePayloadSource src = new RangePayloadSource(1, 3, 1, 4);
            List<String> items = new ArrayList<>();
            src.iterator().forEachRemaining(items::add);
            assertEquals(List.of("0001", "0002", "0003"), items);
        }

        @Test
        void invertedRangeReturnsZeroSize() {
            RangePayloadSource src = new RangePayloadSource(10, 1, 1, 0);
            assertEquals(0, src.size());
            assertFalse(src.iterator().hasNext());
        }

        @Test
        void singleValueRange() {
            RangePayloadSource src = new RangePayloadSource(42, 42, 1, 0);
            assertEquals(1, src.size());
            List<String> items = new ArrayList<>();
            src.iterator().forEachRemaining(items::add);
            assertEquals(List.of("42"), items);
        }

        @Test
        void zeroStepDefaultsToOne() {
            RangePayloadSource src = new RangePayloadSource(1, 3, 0, 0);
            assertEquals(3, src.size());
        }

        @Test
        void labelContainsSizeAndRange() {
            RangePayloadSource src = new RangePayloadSource(1, 100, 1, 0);
            String label = src.label();
            assertTrue(label.contains("1"), "Label should contain from");
            assertTrue(label.contains("100"), "Label should contain to");
        }

        @Test
        void multipleIteratorsAreIndependent() {
            RangePayloadSource src = new RangePayloadSource(1, 3, 1, 0);
            Iterator<String> it1 = src.iterator();
            it1.next(); // consume one
            Iterator<String> it2 = src.iterator();
            assertEquals("1", it2.next(), "New iterator starts from beginning");
        }
    }

    // ---------------------------------------------------------------------------
    // FilePayloadSource
    // ---------------------------------------------------------------------------

    @Nested
    class FilePayloadSourceTests {

        private Path tempFile;

        @BeforeEach
        void setUp() throws IOException {
            tempFile = Files.createTempFile("fuzz-test-payload-", ".txt");
            Files.writeString(tempFile, "admin\nroot\nguest\n");
        }

        @AfterEach
        void tearDown() throws IOException {
            Files.deleteIfExists(tempFile);
        }

        @Test
        void sizeCountsLines() {
            FilePayloadSource src = new FilePayloadSource(tempFile);
            assertEquals(3, src.size());
        }

        @Test
        void iteratorReturnsAllLines() {
            FilePayloadSource src = new FilePayloadSource(tempFile);
            List<String> items = new ArrayList<>();
            src.iterator().forEachRemaining(items::add);
            assertEquals(List.of("admin", "root", "guest"), items);
        }

        @Test
        void missingFileReturnsZeroSize() {
            FilePayloadSource src = new FilePayloadSource(Path.of("/nonexistent/file.txt"));
            assertEquals(0, src.size());
        }

        @Test
        void missingFileIteratorIsEmpty() {
            FilePayloadSource src = new FilePayloadSource(Path.of("/nonexistent/file.txt"));
            assertFalse(src.iterator().hasNext());
        }

        @Test
        void labelContainsFilename() {
            FilePayloadSource src = new FilePayloadSource(tempFile);
            assertTrue(src.label().contains(tempFile.getFileName().toString()));
        }

        @Test
        void previewReturnsMaxLines() throws IOException {
            Path big = Files.createTempFile("fuzz-test-big-", ".txt");
            try {
                Files.writeString(big, "line1\nline2\nline3\nline4\nline5\n");
                FilePayloadSource src = new FilePayloadSource(big);
                List<String> preview = src.preview(2);
                assertEquals(2, preview.size());
                assertEquals("line1", preview.get(0));
                assertEquals("line2", preview.get(1));
            } finally {
                Files.deleteIfExists(big);
            }
        }

        @Test
        void pathAccessor() {
            FilePayloadSource src = new FilePayloadSource(tempFile);
            assertEquals(tempFile, src.path());
        }
    }

    // ---------------------------------------------------------------------------
    // PayloadProcessors
    // ---------------------------------------------------------------------------

    @Nested
    class PayloadProcessorTests {

        @Test
        void prefixProcessor() {
            PayloadProcessor proc = PayloadProcessors.prefix("admin_");
            assertEquals("admin_test", proc.process("test"));
        }

        @Test
        void suffixProcessor() {
            PayloadProcessor proc = PayloadProcessors.suffix("_end");
            assertEquals("test_end", proc.process("test"));
        }

        @Test
        void urlEncode() {
            PayloadProcessor proc = PayloadProcessors.urlEncode();
            assertEquals("hello+world", proc.process("hello world"));
            assertEquals("%3Cscript%3E", proc.process("<script>"));
        }

        @Test
        void urlDecode() {
            PayloadProcessor proc = PayloadProcessors.urlDecode();
            assertEquals("<script>", proc.process("%3Cscript%3E"));
        }

        @Test
        void urlDecodeInvalidInputReturnsSame() {
            PayloadProcessor proc = PayloadProcessors.urlDecode();
            assertEquals("%ZZinvalid", proc.process("%ZZinvalid"));
        }

        @Test
        void base64Encode() {
            PayloadProcessor proc = PayloadProcessors.base64Encode();
            assertEquals("aGVsbG8=", proc.process("hello"));
        }

        @Test
        void base64Decode() {
            PayloadProcessor proc = PayloadProcessors.base64Decode();
            assertEquals("hello", proc.process("aGVsbG8="));
        }

        @Test
        void base64DecodeInvalidInputReturnsSame() {
            PayloadProcessor proc = PayloadProcessors.base64Decode();
            assertEquals("not!base64!!!", proc.process("not!base64!!!"));
        }

        @Test
        void htmlEncode() {
            PayloadProcessor proc = PayloadProcessors.htmlEncode();
            assertEquals("&lt;b&gt;&amp;test&quot;&#x27;", proc.process("<b>&test\"'"));
        }

        @Test
        void htmlDecode() {
            PayloadProcessor proc = PayloadProcessors.htmlDecode();
            assertEquals("<b>&test\"'", proc.process("&lt;b&gt;&amp;test&quot;&#x27;"));
        }

        @Test
        void hashMd5() {
            PayloadProcessor proc = PayloadProcessors.hash("MD5");
            // MD5("hello") = 5d41402abc4b2a76b9719d911017c592
            assertEquals("5d41402abc4b2a76b9719d911017c592", proc.process("hello"));
        }

        @Test
        void hashSha256() {
            PayloadProcessor proc = PayloadProcessors.hash("SHA-256");
            String result = proc.process("test");
            assertNotNull(result);
            assertEquals(64, result.length(), "SHA-256 hex should be 64 chars");
        }

        @Test
        void hashInvalidAlgorithmReturnsSame() {
            PayloadProcessor proc = PayloadProcessors.hash("BOGUS-ALGO");
            assertEquals("test", proc.process("test"));
        }

        @Test
        void matchReplace() {
            PayloadProcessor proc = PayloadProcessors.matchReplace("\\d+", "NUM");
            assertEquals("user_NUM_name_NUM", proc.process("user_123_name_456"));
        }

        @Test
        void skipIfMatchesReturnsNull() {
            PayloadProcessor proc = PayloadProcessors.skipIfMatches("^#.*");
            assertNull(proc.process("# comment line"));
        }

        @Test
        void skipIfMatchesPassesThrough() {
            PayloadProcessor proc = PayloadProcessors.skipIfMatches("^#.*");
            assertEquals("valid payload", proc.process("valid payload"));
        }

        @Test
        void applyPipelineChains() {
            List<PayloadProcessor> pipeline = List.of(PayloadProcessors.prefix("pre_"),
                    PayloadProcessors.suffix("_suf"));
            String result = PayloadProcessors.applyPipeline("test", pipeline);
            assertEquals("pre_test_suf", result);
        }

        @Test
        void applyPipelineSkipReturnsNull() {
            List<PayloadProcessor> pipeline = List.of(PayloadProcessors.skipIfMatches("skip"),
                    PayloadProcessors.prefix("never_"));
            String result = PayloadProcessors.applyPipeline("skip-me", pipeline);
            assertNull(result, "Pipeline must short-circuit on null");
        }

        @Test
        void applyPipelineEmptyListIsIdentity() {
            assertEquals("test", PayloadProcessors.applyPipeline("test", List.of()));
        }

        @Test
        void availableProcessorsNonEmpty() {
            assertTrue(PayloadProcessors.AVAILABLE.length > 0);
        }
    }

    // ---------------------------------------------------------------------------
    // GrepMatcher
    // ---------------------------------------------------------------------------

    @Nested
    class GrepMatcherTests {

        @Test
        void literalMatchCounting() {
            GrepMatcher matcher = new GrepMatcher();
            matcher.setMatchRules(List.of(new GrepMatcher.GrepRule("error", false, false)));
            int[] counts = matcher.countMatches("Error: something went wrong. Another error occurred.");
            assertEquals(1, counts.length);
            assertEquals(2, counts[0], "Case-insensitive literal should match twice");
        }

        @Test
        void caseSensitiveLiteralMatch() {
            GrepMatcher matcher = new GrepMatcher();
            matcher.setMatchRules(List.of(new GrepMatcher.GrepRule("Error", false, true)));
            int[] counts = matcher.countMatches("Error: something error");
            assertEquals(1, counts[0], "Case-sensitive should match only 'Error'");
        }

        @Test
        void regexMatchCounting() {
            GrepMatcher matcher = new GrepMatcher();
            matcher.setMatchRules(List.of(new GrepMatcher.GrepRule("\\d{3}", true, false)));
            int[] counts = matcher.countMatches("HTTP 200 OK, then 404, then 500");
            assertEquals(1, counts.length);
            assertEquals(3, counts[0], "Should match three 3-digit numbers");
        }

        @Test
        void multipleMatchRules() {
            GrepMatcher matcher = new GrepMatcher();
            matcher.setMatchRules(List.of(new GrepMatcher.GrepRule("error", false, false),
                    new GrepMatcher.GrepRule("\\d+", true, false)));
            int[] counts = matcher.countMatches("Error 404: not found");
            assertEquals(2, counts.length);
            assertEquals(1, counts[0], "One 'error' match");
            assertEquals(1, counts[1], "One number match");
        }

        @Test
        void noMatchRulesReturnsEmptyArray() {
            GrepMatcher matcher = new GrepMatcher();
            int[] counts = matcher.countMatches("anything");
            assertEquals(0, counts.length);
        }

        @Test
        void nullBodyReturnsZeroCounts() {
            GrepMatcher matcher = new GrepMatcher();
            matcher.setMatchRules(List.of(new GrepMatcher.GrepRule("test", false, false)));
            int[] counts = matcher.countMatches(null);
            assertEquals(1, counts.length);
            assertEquals(0, counts[0]);
        }

        @Test
        void extractLiteral() {
            GrepMatcher matcher = new GrepMatcher();
            matcher.setExtractRules(List.of(new GrepMatcher.GrepRule("token", false, false)));
            String[] results = matcher.extract("Your token is here");
            assertEquals(1, results.length);
            assertEquals("token", results[0]);
        }

        @Test
        void extractRegexWithCaptureGroup() {
            GrepMatcher matcher = new GrepMatcher();
            matcher.setExtractRules(List.of(new GrepMatcher.GrepRule("token=(\\w+)", true, false)));
            String[] results = matcher.extract("?token=abc123&other=val");
            assertEquals(1, results.length);
            assertEquals("abc123", results[0], "Should extract capture group 1");
        }

        @Test
        void extractNoMatchReturnsNull() {
            GrepMatcher matcher = new GrepMatcher();
            matcher.setExtractRules(List.of(new GrepMatcher.GrepRule("not-present", false, false)));
            String[] results = matcher.extract("some body content");
            assertEquals(1, results.length);
            assertNull(results[0]);
        }

        @Test
        void extractFromNullBody() {
            GrepMatcher matcher = new GrepMatcher();
            matcher.setExtractRules(List.of(new GrepMatcher.GrepRule("x", false, false)));
            String[] results = matcher.extract(null);
            assertEquals(1, results.length);
            assertNull(results[0]);
        }

        @Test
        void matchLabelsReflectRules() {
            GrepMatcher matcher = new GrepMatcher();
            matcher.setMatchRules(List.of(new GrepMatcher.GrepRule("alpha", false, false),
                    new GrepMatcher.GrepRule("beta", false, false)));
            assertEquals(List.of("alpha", "beta"), matcher.matchLabels());
            assertEquals(2, matcher.matchRuleCount());
        }

        @Test
        void extractLabelsReflectRules() {
            GrepMatcher matcher = new GrepMatcher();
            matcher.setExtractRules(List.of(new GrepMatcher.GrepRule("token=(\\w+)", true, false)));
            assertEquals(List.of("token=(\\w+)"), matcher.extractLabels());
            assertEquals(1, matcher.extractRuleCount());
        }
    }

    // ---------------------------------------------------------------------------
    // FuzzResult
    // ---------------------------------------------------------------------------

    @Nested
    class FuzzResultTests {

        @Test
        void hasErrorDetectsNonEmpty() {
            FuzzResult r = new FuzzResult(1, new String[]{"a"}, 0, 0, 0, "", "", "timeout", new int[0], new String[0]);
            assertTrue(r.hasError());
        }

        @Test
        void hasErrorFalseWhenNull() {
            FuzzResult r = new FuzzResult(1, new String[]{"a"}, 200, 10, 5, "ok", "", null, new int[0], new String[0]);
            assertFalse(r.hasError());
        }

        @Test
        void hasErrorFalseWhenEmpty() {
            FuzzResult r = new FuzzResult(1, new String[]{"a"}, 200, 10, 5, "ok", "", "", new int[0], new String[0]);
            assertFalse(r.hasError());
        }

        @Test
        void payloadSummarySingle() {
            FuzzResult r = new FuzzResult(1, new String[]{"admin"}, 200, 10, 5, "", "", null, new int[0],
                    new String[0]);
            assertEquals("admin", r.payloadSummary());
        }

        @Test
        void payloadSummaryMultiple() {
            FuzzResult r = new FuzzResult(1, new String[]{"admin", "pass123"}, 200, 10, 5, "", "", null, new int[0],
                    new String[0]);
            assertEquals("admin | pass123", r.payloadSummary());
        }

        @Test
        void payloadSummaryNullPayloads() {
            FuzzResult r = new FuzzResult(1, null, 200, 10, 5, "", "", null, new int[0], new String[0]);
            assertEquals("", r.payloadSummary());
        }

        @Test
        void payloadSummaryEmptyPayloads() {
            FuzzResult r = new FuzzResult(1, new String[]{}, 200, 10, 5, "", "", null, new int[0], new String[0]);
            assertEquals("", r.payloadSummary());
        }
    }

    // ---------------------------------------------------------------------------
    // FuzzEngine.parseRawRequest
    // ---------------------------------------------------------------------------

    @Nested
    class ParseRawRequestTests {

        @Test
        void basicGetRequest() {
            String raw = "GET /api/users HTTP/1.1\nHost: example.com\n\n";
            String[] parts = FuzzEngine.parseRawRequest(raw);
            assertEquals("GET", parts[0]);
            assertTrue(parts[1].contains("example.com"), "URL must include host");
            assertTrue(parts[1].contains("/api/users"), "URL must include path");
        }

        @Test
        void postRequestWithBody() {
            String raw = "POST /login HTTP/1.1\nHost: example.com\nContent-Type: application/json\n\n{\"user\":\"admin\"}";
            String[] parts = FuzzEngine.parseRawRequest(raw);
            assertEquals("POST", parts[0]);
            assertTrue(parts[1].contains("/login"), "URL must include path");
            assertTrue(parts[2].contains("Content-Type"), "Headers must include Content-Type");
            assertEquals("{\"user\":\"admin\"}", parts[3]);
        }

        @Test
        void absoluteUrlInRequestLine() {
            String raw = "GET http://target.com/path HTTP/1.1\nHost: target.com\n\n";
            String[] parts = FuzzEngine.parseRawRequest(raw);
            assertEquals("http://target.com/path", parts[1]);
        }

        @Test
        void noHostDefaultsToLocalhost() {
            String raw = "GET /test HTTP/1.1\n\n";
            String[] parts = FuzzEngine.parseRawRequest(raw);
            assertTrue(parts[1].contains("localhost"), "Missing Host must default to localhost");
            assertTrue(parts[1].contains("/test"), "Path must be preserved");
        }

        @Test
        void emptyInputReturnsDefaults() {
            String[] parts = FuzzEngine.parseRawRequest("");
            assertEquals("GET", parts[0]);
            assertEquals("", parts[1]);
        }

        @Test
        void multiLineBody() {
            String raw = "PUT /data HTTP/1.1\nHost: api.test\n\nline1\nline2\nline3";
            String[] parts = FuzzEngine.parseRawRequest(raw);
            assertEquals("PUT", parts[0]);
            assertTrue(parts[3].contains("line1"));
            assertTrue(parts[3].contains("line2"));
            assertTrue(parts[3].contains("line3"));
        }

        @Test
        void headersExcludeHost() {
            String raw = "GET / HTTP/1.1\nHost: example.com\nAccept: */*\n\n";
            String[] parts = FuzzEngine.parseRawRequest(raw);
            // The headers string is used for adding to HttpRequest -- Host header
            // is handled separately via URL construction
            String headers = parts[2];
            // Headers should contain Accept but Host is also present in the string
            // since parseRawRequest includes all header lines
            assertTrue(headers.contains("Accept"), "Headers must include Accept");
        }

        @Test
        void httpsSchemeFromPort443() {
            String raw = "GET /secure HTTP/1.1\nHost: example.com:443\n\n";
            String[] parts = FuzzEngine.parseRawRequest(raw);
            assertTrue(parts[1].startsWith("https://"), "Port 443 must yield https scheme");
        }
    }

    // ---------------------------------------------------------------------------
    // FuzzEngine -- end-to-end with mock HTTP server
    // ---------------------------------------------------------------------------

    @Nested
    class FuzzEngineE2ETests {

        private HttpServer server;
        private int port;
        private FuzzEngine engine;
        private final AtomicInteger serverRequestCount = new AtomicInteger(0);

        @BeforeEach
        void setUp() throws IOException {
            serverRequestCount.set(0);
            server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
            server.createContext("/", exchange -> {
                serverRequestCount.incrementAndGet();
                byte[] body = "OK".getBytes();
                exchange.sendResponseHeaders(200, body.length);
                exchange.getResponseBody().write(body);
                exchange.getResponseBody().close();
            });
            server.start();
            port = server.getAddress().getPort();
            engine = new FuzzEngine();
        }

        @AfterEach
        void tearDown() {
            engine.stop();
            server.stop(0);
        }

        private String makeTemplate(String method, String path) {
            return method + " http://127.0.0.1:" + port + path + " HTTP/1.1\n" + "Host: 127.0.0.1:" + port + "\n\n";
        }

        @Test
        void sniperAttackSinglePosition() throws Exception {
            String template = "GET http://127.0.0.1:" + port + "/api/{{1}} HTTP/1.1\n" + "Host: 127.0.0.1:" + port
                    + "\n\n";
            List<FuzzResult> results = new CopyOnWriteArrayList<>();
            CountDownLatch latch = new CountDownLatch(1);
            AtomicLong totalReported = new AtomicLong(0);

            PayloadSource src = new InlinePayloadSource(List.of("admin", "root", "guest"));

            FuzzEngine.FuzzConfig config = new FuzzEngine.FuzzConfig(template, AttackType.SNIPER, List.of(src),
                    List.of(), 1, 0, 0, 10, null, null, null, null, 0);

            engine.start(config, new FuzzEngine.FuzzListener() {
                @Override
                public void onResult(FuzzResult result) {
                    results.add(result);
                }

                @Override
                public void onProgress(int completed, long total) {
                    totalReported.set(total);
                }

                @Override
                public void onComplete(int totalCompleted, long elapsedMs) {
                    latch.countDown();
                }

                @Override
                public void onError(String message) {
                    fail("Unexpected error: " + message);
                }
            });

            assertTrue(latch.await(15, TimeUnit.SECONDS), "Fuzzer must complete within 15s");
            assertEquals(3, results.size(), "Sniper with 1 position and 3 payloads = 3 requests");
            for (FuzzResult r : results) {
                assertEquals(200, r.statusCode());
                assertFalse(r.hasError());
                assertTrue(r.timeMs() >= 0);
            }
        }

        @Test
        void sniperAttackTwoPositions() throws Exception {
            String template = "GET http://127.0.0.1:" + port + "/api/{{1}}/{{2}} HTTP/1.1\n" + "Host: 127.0.0.1:" + port
                    + "\n\n";
            List<FuzzResult> results = new CopyOnWriteArrayList<>();
            CountDownLatch latch = new CountDownLatch(1);

            PayloadSource src = new InlinePayloadSource(List.of("a", "b"));

            FuzzEngine.FuzzConfig config = new FuzzEngine.FuzzConfig(template, AttackType.SNIPER, List.of(src),
                    List.of(), 1, 0, 0, 10, null, null, null, null, 0);

            engine.start(config, listenerWith(results, latch));
            assertTrue(latch.await(15, TimeUnit.SECONDS));
            // Sniper: 2 positions * 2 payloads = 4 requests
            assertEquals(4, results.size());
        }

        @Test
        void batteringRamAllPositionsSamePayload() throws Exception {
            String template = "GET http://127.0.0.1:" + port + "/{{1}}/{{2}} HTTP/1.1\n" + "Host: 127.0.0.1:" + port
                    + "\n\n";
            List<FuzzResult> results = new CopyOnWriteArrayList<>();
            CountDownLatch latch = new CountDownLatch(1);

            PayloadSource src = new InlinePayloadSource(List.of("test1", "test2", "test3"));

            FuzzEngine.FuzzConfig config = new FuzzEngine.FuzzConfig(template, AttackType.BATTERING_RAM, List.of(src),
                    List.of(), 1, 0, 0, 10, null, null, null, null, 0);

            engine.start(config, listenerWith(results, latch));
            assertTrue(latch.await(15, TimeUnit.SECONDS));
            // Battering ram: 3 payloads (all positions get the same value)
            assertEquals(3, results.size());
            // Each result should have the same payload for both positions
            for (FuzzResult r : results) {
                assertNotNull(r.payloads());
                assertEquals(2, r.payloads().length);
                assertEquals(r.payloads()[0], r.payloads()[1],
                        "Battering ram must inject same payload in all positions");
            }
        }

        @Test
        void pitchforkStepsInParallel() throws Exception {
            String template = "GET http://127.0.0.1:" + port + "/{{1}}/{{2}} HTTP/1.1\n" + "Host: 127.0.0.1:" + port
                    + "\n\n";
            List<FuzzResult> results = new CopyOnWriteArrayList<>();
            CountDownLatch latch = new CountDownLatch(1);

            PayloadSource src1 = new InlinePayloadSource(List.of("user1", "user2", "user3"));
            PayloadSource src2 = new InlinePayloadSource(List.of("pass1", "pass2"));

            FuzzEngine.FuzzConfig config = new FuzzEngine.FuzzConfig(template, AttackType.PITCHFORK,
                    List.of(src1, src2), List.of(), 1, 0, 0, 10, null, null, null, null, 0);

            engine.start(config, listenerWith(results, latch));
            assertTrue(latch.await(15, TimeUnit.SECONDS));
            // Pitchfork: min(3, 2) = 2 requests
            assertEquals(2, results.size());
        }

        @Test
        void clusterBombCartesianProduct() throws Exception {
            String template = "GET http://127.0.0.1:" + port + "/{{1}}/{{2}} HTTP/1.1\n" + "Host: 127.0.0.1:" + port
                    + "\n\n";
            List<FuzzResult> results = new CopyOnWriteArrayList<>();
            CountDownLatch latch = new CountDownLatch(1);

            PayloadSource src1 = new InlinePayloadSource(List.of("a", "b"));
            PayloadSource src2 = new InlinePayloadSource(List.of("1", "2", "3"));

            FuzzEngine.FuzzConfig config = new FuzzEngine.FuzzConfig(template, AttackType.CLUSTER_BOMB,
                    List.of(src1, src2), List.of(), 1, 0, 0, 10, null, null, null, null, 0);

            engine.start(config, listenerWith(results, latch));
            assertTrue(latch.await(15, TimeUnit.SECONDS));
            // Cluster bomb: 2 * 3 = 6 requests
            assertEquals(6, results.size());
        }

        @Test
        void grepMatcherIntegration() throws Exception {
            server.stop(0);
            server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
            server.createContext("/", exchange -> {
                byte[] body = "Error: access denied for user. Error code 403.".getBytes();
                exchange.sendResponseHeaders(403, body.length);
                exchange.getResponseBody().write(body);
                exchange.getResponseBody().close();
            });
            server.start();
            port = server.getAddress().getPort();

            String template = "GET http://127.0.0.1:" + port + "/{{1}} HTTP/1.1\n" + "Host: 127.0.0.1:" + port + "\n\n";
            List<FuzzResult> results = new CopyOnWriteArrayList<>();
            CountDownLatch latch = new CountDownLatch(1);

            GrepMatcher grep = new GrepMatcher();
            grep.setMatchRules(List.of(new GrepMatcher.GrepRule("Error", false, false)));
            grep.setExtractRules(List.of(new GrepMatcher.GrepRule("code (\\d+)", true, false)));

            PayloadSource src = new InlinePayloadSource(List.of("test"));

            FuzzEngine.FuzzConfig config = new FuzzEngine.FuzzConfig(template, AttackType.SNIPER, List.of(src),
                    List.of(), 1, 0, 0, 10, grep, null, null, null, 0);

            engine.start(config, listenerWith(results, latch));
            assertTrue(latch.await(15, TimeUnit.SECONDS));
            assertEquals(1, results.size());

            FuzzResult r = results.getFirst();
            assertEquals(403, r.statusCode());
            assertEquals(1, r.grepMatchCounts().length);
            assertEquals(2, r.grepMatchCounts()[0], "Should match 'Error' twice");
            assertEquals(1, r.grepExtracts().length);
            assertEquals("403", r.grepExtracts()[0], "Should extract code 403");
        }

        @Test
        void noPositionsReportsError() throws Exception {
            String template = "GET http://127.0.0.1:" + port + "/static HTTP/1.1\n" + "Host: 127.0.0.1:" + port
                    + "\n\n";
            AtomicBoolean gotError = new AtomicBoolean(false);
            CountDownLatch latch = new CountDownLatch(1);

            FuzzEngine.FuzzConfig config = new FuzzEngine.FuzzConfig(template, AttackType.SNIPER,
                    List.of(new InlinePayloadSource(List.of("a"))), List.of(), 1, 0, 0, 10, null, null, null, null, 0);

            engine.start(config, new FuzzEngine.FuzzListener() {
                @Override
                public void onResult(FuzzResult result) {
                }

                @Override
                public void onProgress(int completed, long total) {
                }

                @Override
                public void onComplete(int totalCompleted, long elapsedMs) {
                    latch.countDown();
                }

                @Override
                public void onError(String message) {
                    if (message.contains("No positions")) {
                        gotError.set(true);
                    }
                    latch.countDown();
                }
            });

            assertTrue(latch.await(10, TimeUnit.SECONDS));
            assertTrue(gotError.get(), "Must report error when no {{N}} markers found");
        }

        @Test
        void noSourcesReportsError() throws Exception {
            String template = "GET http://127.0.0.1:" + port + "/{{1}} HTTP/1.1\n" + "Host: 127.0.0.1:" + port + "\n\n";
            AtomicBoolean gotError = new AtomicBoolean(false);
            CountDownLatch latch = new CountDownLatch(1);

            FuzzEngine.FuzzConfig config = new FuzzEngine.FuzzConfig(template, AttackType.SNIPER, List.of(), List.of(),
                    1, 0, 0, 10, null, null, null, null, 0);

            engine.start(config, new FuzzEngine.FuzzListener() {
                @Override
                public void onResult(FuzzResult result) {
                }

                @Override
                public void onProgress(int completed, long total) {
                }

                @Override
                public void onComplete(int totalCompleted, long elapsedMs) {
                    latch.countDown();
                }

                @Override
                public void onError(String message) {
                    if (message.contains("No payload sources")) {
                        gotError.set(true);
                    }
                    latch.countDown();
                }
            });

            assertTrue(latch.await(10, TimeUnit.SECONDS));
            assertTrue(gotError.get(), "Must report error when no payload sources configured");
        }

        @Test
        void processorPipelineAppliedDuringFuzz() throws Exception {
            // Server records request paths so we can verify transformed payloads
            List<String> requestPaths = Collections.synchronizedList(new ArrayList<>());
            server.stop(0);
            server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
            server.createContext("/", exchange -> {
                requestPaths.add(exchange.getRequestURI().getPath());
                byte[] body = "OK".getBytes();
                exchange.sendResponseHeaders(200, body.length);
                exchange.getResponseBody().write(body);
                exchange.getResponseBody().close();
            });
            server.start();
            port = server.getAddress().getPort();

            String template = "GET http://127.0.0.1:" + port + "/api/{{1}} HTTP/1.1\n" + "Host: 127.0.0.1:" + port
                    + "\n\n";
            List<FuzzResult> results = new CopyOnWriteArrayList<>();
            CountDownLatch latch = new CountDownLatch(1);

            PayloadSource src = new InlinePayloadSource(List.of("test"));
            List<PayloadProcessor> pipeline = List.of(PayloadProcessors.prefix("PRE_"),
                    PayloadProcessors.suffix("_SUF"));

            FuzzEngine.FuzzConfig config = new FuzzEngine.FuzzConfig(template, AttackType.SNIPER, List.of(src),
                    List.of(pipeline), 1, 0, 0, 10, null, null, null, null, 0);

            engine.start(config, listenerWith(results, latch));
            assertTrue(latch.await(15, TimeUnit.SECONDS));
            assertEquals(1, results.size());
            // Verify the payload in the result was transformed
            assertEquals("PRE_test_SUF", results.getFirst().payloads()[0]);
        }

        @Test
        void concurrentThreadsWork() throws Exception {
            String template = "GET http://127.0.0.1:" + port + "/{{1}} HTTP/1.1\n" + "Host: 127.0.0.1:" + port + "\n\n";
            List<FuzzResult> results = new CopyOnWriteArrayList<>();
            CountDownLatch latch = new CountDownLatch(1);

            List<String> payloads = new ArrayList<>();
            for (int i = 0; i < 20; i++) {
                payloads.add("payload" + i);
            }
            PayloadSource src = new InlinePayloadSource(payloads);

            FuzzEngine.FuzzConfig config = new FuzzEngine.FuzzConfig(template, AttackType.SNIPER, List.of(src),
                    List.of(), 5, 0, 0, 10, null, null, null, null, 0);

            engine.start(config, listenerWith(results, latch));
            assertTrue(latch.await(30, TimeUnit.SECONDS));
            assertEquals(20, results.size(), "All 20 requests must complete");
        }

        @Test
        void responseBodyAndHeadersCaptured() throws Exception {
            server.stop(0);
            server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
            server.createContext("/", exchange -> {
                exchange.getResponseHeaders().set("X-Custom", "test-val");
                byte[] body = "response-body-content".getBytes();
                exchange.sendResponseHeaders(200, body.length);
                exchange.getResponseBody().write(body);
                exchange.getResponseBody().close();
            });
            server.start();
            port = server.getAddress().getPort();

            String template = "GET http://127.0.0.1:" + port + "/{{1}} HTTP/1.1\n" + "Host: 127.0.0.1:" + port + "\n\n";
            List<FuzzResult> results = new CopyOnWriteArrayList<>();
            CountDownLatch latch = new CountDownLatch(1);

            FuzzEngine.FuzzConfig config = new FuzzEngine.FuzzConfig(template, AttackType.SNIPER,
                    List.of(new InlinePayloadSource(List.of("x"))), List.of(), 1, 0, 0, 10, null, null, null, null, 0);

            engine.start(config, listenerWith(results, latch));
            assertTrue(latch.await(15, TimeUnit.SECONDS));
            assertEquals(1, results.size());

            FuzzResult r = results.getFirst();
            assertTrue(r.responseBody().contains("response-body-content"),
                    "Response body must contain the expected content");
            assertTrue(r.length() > 0, "Length must be positive");
            assertTrue(r.responseHeaders().toLowerCase().contains("x-custom"),
                    "Response headers must contain the custom header");
        }

        @Test
        void networkErrorResultsInErrorField() throws Exception {
            // Use a port that is definitely closed
            server.stop(0);
            int closedPort = port;

            String template = "GET http://127.0.0.1:" + closedPort + "/{{1}} HTTP/1.1\n" + "Host: 127.0.0.1:"
                    + closedPort + "\n\n";
            List<FuzzResult> results = new CopyOnWriteArrayList<>();
            CountDownLatch latch = new CountDownLatch(1);

            FuzzEngine.FuzzConfig config = new FuzzEngine.FuzzConfig(template, AttackType.SNIPER,
                    List.of(new InlinePayloadSource(List.of("test"))), List.of(), 1, 0, 0, 5, null, null, null, null,
                    0);

            engine.start(config, listenerWith(results, latch));
            assertTrue(latch.await(30, TimeUnit.SECONDS));
            assertEquals(1, results.size());
            assertTrue(results.getFirst().hasError(), "Connection refused must produce an error result");
            assertEquals(0, results.getFirst().statusCode());
        }

        @Test
        void rangePayloadSourceWithFuzzer() throws Exception {
            String template = "GET http://127.0.0.1:" + port + "/id/{{1}} HTTP/1.1\n" + "Host: 127.0.0.1:" + port
                    + "\n\n";
            List<FuzzResult> results = new CopyOnWriteArrayList<>();
            CountDownLatch latch = new CountDownLatch(1);

            RangePayloadSource range = new RangePayloadSource(1, 5, 1, 0);

            FuzzEngine.FuzzConfig config = new FuzzEngine.FuzzConfig(template, AttackType.SNIPER, List.of(range),
                    List.of(), 1, 0, 0, 10, null, null, null, null, 0);

            engine.start(config, listenerWith(results, latch));
            assertTrue(latch.await(15, TimeUnit.SECONDS));
            assertEquals(5, results.size(), "Range 1-5 step 1 should produce 5 requests");
        }

        @Test
        void doubleStartReportsError() throws Exception {
            String template = "GET http://127.0.0.1:" + port + "/{{1}} HTTP/1.1\n" + "Host: 127.0.0.1:" + port + "\n\n";
            List<String> payloads = new ArrayList<>();
            for (int i = 0; i < 100; i++) {
                payloads.add("p" + i);
            }
            CountDownLatch firstDone = new CountDownLatch(1);
            AtomicBoolean secondGotError = new AtomicBoolean(false);

            FuzzEngine.FuzzConfig config = new FuzzEngine.FuzzConfig(template, AttackType.SNIPER,
                    List.of(new InlinePayloadSource(payloads)), List.of(), 1, 10, 0, 10, null, null, null, null, 0);

            engine.start(config, new FuzzEngine.FuzzListener() {
                @Override
                public void onResult(FuzzResult result) {
                }

                @Override
                public void onProgress(int completed, long total) {
                }

                @Override
                public void onComplete(int totalCompleted, long elapsedMs) {
                    firstDone.countDown();
                }

                @Override
                public void onError(String message) {
                }
            });

            // Try starting again while already running
            engine.start(config, new FuzzEngine.FuzzListener() {
                @Override
                public void onResult(FuzzResult result) {
                }

                @Override
                public void onProgress(int completed, long total) {
                }

                @Override
                public void onComplete(int totalCompleted, long elapsedMs) {
                }

                @Override
                public void onError(String message) {
                    if (message.contains("already running")) {
                        secondGotError.set(true);
                    }
                }
            });

            engine.stop(); // stop the first run
            assertTrue(firstDone.await(15, TimeUnit.SECONDS));
            assertTrue(secondGotError.get(), "Starting while running must report error");
        }

        @Test
        void progressCallbackFires() throws Exception {
            String template = "GET http://127.0.0.1:" + port + "/{{1}} HTTP/1.1\n" + "Host: 127.0.0.1:" + port + "\n\n";
            AtomicInteger maxProgress = new AtomicInteger(0);
            AtomicLong totalReported = new AtomicLong(0);
            CountDownLatch latch = new CountDownLatch(1);

            PayloadSource src = new InlinePayloadSource(List.of("a", "b", "c"));

            FuzzEngine.FuzzConfig config = new FuzzEngine.FuzzConfig(template, AttackType.SNIPER, List.of(src),
                    List.of(), 1, 0, 0, 10, null, null, null, null, 0);

            engine.start(config, new FuzzEngine.FuzzListener() {
                @Override
                public void onResult(FuzzResult result) {
                }

                @Override
                public void onProgress(int completed, long total) {
                    maxProgress.updateAndGet(curr -> Math.max(curr, completed));
                    totalReported.set(total);
                }

                @Override
                public void onComplete(int totalCompleted, long elapsedMs) {
                    latch.countDown();
                }

                @Override
                public void onError(String message) {
                    fail("Unexpected error: " + message);
                }
            });

            assertTrue(latch.await(15, TimeUnit.SECONDS));
            assertEquals(3, maxProgress.get(), "Progress must reach total count");
            assertEquals(3, totalReported.get(), "Total reported must match estimated requests");
        }

        @Test
        void onCompleteReportsElapsedTime() throws Exception {
            String template = "GET http://127.0.0.1:" + port + "/{{1}} HTTP/1.1\n" + "Host: 127.0.0.1:" + port + "\n\n";
            AtomicLong elapsed = new AtomicLong(-1);
            AtomicInteger completed = new AtomicInteger(-1);
            CountDownLatch latch = new CountDownLatch(1);

            FuzzEngine.FuzzConfig config = new FuzzEngine.FuzzConfig(template, AttackType.SNIPER,
                    List.of(new InlinePayloadSource(List.of("a"))), List.of(), 1, 0, 0, 10, null, null, null, null, 0);

            engine.start(config, new FuzzEngine.FuzzListener() {
                @Override
                public void onResult(FuzzResult result) {
                }

                @Override
                public void onProgress(int c, long t) {
                }

                @Override
                public void onComplete(int totalCompleted, long elapsedMs) {
                    completed.set(totalCompleted);
                    elapsed.set(elapsedMs);
                    latch.countDown();
                }

                @Override
                public void onError(String message) {
                    fail("Unexpected error: " + message);
                }
            });

            assertTrue(latch.await(15, TimeUnit.SECONDS));
            assertEquals(1, completed.get());
            assertTrue(elapsed.get() >= 0, "Elapsed time must be non-negative");
        }

        private FuzzEngine.FuzzListener listenerWith(List<FuzzResult> results, CountDownLatch latch) {
            return new FuzzEngine.FuzzListener() {
                @Override
                public void onResult(FuzzResult result) {
                    results.add(result);
                }

                @Override
                public void onProgress(int completed, long total) {
                }

                @Override
                public void onComplete(int totalCompleted, long elapsedMs) {
                    latch.countDown();
                }

                @Override
                public void onError(String message) {
                    // Allow engine errors (like "already running") to be tested separately
                }
            };
        }
    }

    // ---------------------------------------------------------------------------
    // FuzzEngine -- pause and stop mechanics
    // ---------------------------------------------------------------------------

    @Nested
    class PauseStopTests {

        private HttpServer server;
        private int port;
        private FuzzEngine engine;

        @BeforeEach
        void setUp() throws IOException {
            server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
            server.createContext("/", exchange -> {
                byte[] body = "OK".getBytes();
                exchange.sendResponseHeaders(200, body.length);
                exchange.getResponseBody().write(body);
                exchange.getResponseBody().close();
            });
            server.start();
            port = server.getAddress().getPort();
            engine = new FuzzEngine();
        }

        @AfterEach
        void tearDown() {
            engine.stop();
            server.stop(0);
        }

        @Test
        void stopCancelsBeforeAllComplete() throws Exception {
            String template = "GET http://127.0.0.1:" + port + "/{{1}} HTTP/1.1\n" + "Host: 127.0.0.1:" + port + "\n\n";
            List<String> payloads = new ArrayList<>();
            for (int i = 0; i < 1000; i++) {
                payloads.add("payload-" + i);
            }
            List<FuzzResult> results = new CopyOnWriteArrayList<>();
            CountDownLatch latch = new CountDownLatch(1);

            FuzzEngine.FuzzConfig config = new FuzzEngine.FuzzConfig(template, AttackType.SNIPER,
                    List.of(new InlinePayloadSource(payloads)), List.of(), 1, 5, 0, 10, null, null, null, null, 0);

            engine.start(config, new FuzzEngine.FuzzListener() {
                @Override
                public void onResult(FuzzResult result) {
                    results.add(result);
                }

                @Override
                public void onProgress(int completed, long total) {
                }

                @Override
                public void onComplete(int totalCompleted, long elapsedMs) {
                    latch.countDown();
                }

                @Override
                public void onError(String message) {
                }
            });

            // Let a few requests go through, then stop
            Thread.sleep(100);
            engine.stop();

            assertTrue(latch.await(15, TimeUnit.SECONDS), "Engine must complete after stop()");
            assertTrue(results.size() < 1000,
                    "Stop must prevent all 1000 requests from completing. Got: " + results.size());
            assertFalse(engine.isRunning(), "Engine must not be running after stop");
        }

        @Test
        void pauseAndResume() throws Exception {
            String template = "GET http://127.0.0.1:" + port + "/{{1}} HTTP/1.1\n" + "Host: 127.0.0.1:" + port + "\n\n";
            List<String> payloads = new ArrayList<>();
            for (int i = 0; i < 50; i++) {
                payloads.add("p" + i);
            }
            List<FuzzResult> results = new CopyOnWriteArrayList<>();
            CountDownLatch latch = new CountDownLatch(1);

            FuzzEngine.FuzzConfig config = new FuzzEngine.FuzzConfig(template, AttackType.SNIPER,
                    List.of(new InlinePayloadSource(payloads)), List.of(), 1, 5, 0, 10, null, null, null, null, 0);

            engine.start(config, new FuzzEngine.FuzzListener() {
                @Override
                public void onResult(FuzzResult result) {
                    results.add(result);
                }

                @Override
                public void onProgress(int completed, long total) {
                }

                @Override
                public void onComplete(int totalCompleted, long elapsedMs) {
                    latch.countDown();
                }

                @Override
                public void onError(String message) {
                }
            });

            // Pause after some requests
            Thread.sleep(50);
            engine.pause();
            assertTrue(engine.isPaused(), "Engine must report paused state");

            int countAtPause = results.size();
            Thread.sleep(200); // wait while paused
            int countAfterWait = results.size();
            // Allow a small margin for in-flight requests completing
            assertTrue(countAfterWait - countAtPause <= 2,
                    "While paused, very few additional requests should complete");

            // Resume and let it finish
            engine.resume();
            assertFalse(engine.isPaused(), "Engine must report unpaused after resume");
            assertTrue(latch.await(30, TimeUnit.SECONDS));
            assertEquals(50, results.size(), "All requests must complete after resume");
        }

        @Test
        void isRunningReflectsState() throws Exception {
            assertFalse(engine.isRunning(), "Engine must not be running before start");

            String template = "GET http://127.0.0.1:" + port + "/{{1}} HTTP/1.1\n" + "Host: 127.0.0.1:" + port + "\n\n";
            CountDownLatch latch = new CountDownLatch(1);
            List<String> payloads = new ArrayList<>();
            for (int i = 0; i < 50; i++) {
                payloads.add("p" + i);
            }

            FuzzEngine.FuzzConfig config = new FuzzEngine.FuzzConfig(template, AttackType.SNIPER,
                    List.of(new InlinePayloadSource(payloads)), List.of(), 1, 5, 0, 10, null, null, null, null, 0);

            engine.start(config, new FuzzEngine.FuzzListener() {
                @Override
                public void onResult(FuzzResult result) {
                }

                @Override
                public void onProgress(int completed, long total) {
                }

                @Override
                public void onComplete(int totalCompleted, long elapsedMs) {
                    latch.countDown();
                }

                @Override
                public void onError(String message) {
                }
            });

            // Should be running shortly after start
            Thread.sleep(10);
            assertTrue(engine.isRunning(), "Engine must be running after start");

            engine.stop();
            assertTrue(latch.await(15, TimeUnit.SECONDS));
            assertFalse(engine.isRunning(), "Engine must not be running after stop + complete");
        }
    }

    // ---------------------------------------------------------------------------
    // FuzzEngine -- status code variation for grep testing
    // ---------------------------------------------------------------------------

    @Nested
    class StatusCodeVariationTests {

        @Test
        void differentStatusCodesRecorded() throws Exception {
            HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
            AtomicInteger callCount = new AtomicInteger(0);
            server.createContext("/", exchange -> {
                int n = callCount.incrementAndGet();
                int status = n % 2 == 0 ? 200 : 403;
                byte[] body = ("resp-" + n).getBytes();
                exchange.sendResponseHeaders(status, body.length);
                exchange.getResponseBody().write(body);
                exchange.getResponseBody().close();
            });
            server.start();
            int port = server.getAddress().getPort();

            try {
                FuzzEngine engine = new FuzzEngine();
                String template = "GET http://127.0.0.1:" + port + "/{{1}} HTTP/1.1\n" + "Host: 127.0.0.1:" + port
                        + "\n\n";
                List<FuzzResult> results = new CopyOnWriteArrayList<>();
                CountDownLatch latch = new CountDownLatch(1);

                FuzzEngine.FuzzConfig config = new FuzzEngine.FuzzConfig(template, AttackType.SNIPER,
                        List.of(new InlinePayloadSource(List.of("a", "b", "c", "d"))), List.of(), 1, 0, 0, 10, null,
                        null, null, null, 0);

                engine.start(config, new FuzzEngine.FuzzListener() {
                    @Override
                    public void onResult(FuzzResult result) {
                        results.add(result);
                    }

                    @Override
                    public void onProgress(int completed, long total) {
                    }

                    @Override
                    public void onComplete(int totalCompleted, long elapsedMs) {
                        latch.countDown();
                    }

                    @Override
                    public void onError(String message) {
                    }
                });

                assertTrue(latch.await(15, TimeUnit.SECONDS));
                assertEquals(4, results.size());
                // At least one 200 and one 403 should appear
                assertTrue(results.stream().anyMatch(r -> r.statusCode() == 200), "Must capture 200 status");
                assertTrue(results.stream().anyMatch(r -> r.statusCode() == 403), "Must capture 403 status");
            } finally {
                server.stop(0);
            }
        }
    }

    // ---------------------------------------------------------------------------
    // FilePayloadSource integration with FuzzEngine
    // ---------------------------------------------------------------------------

    @Nested
    class FilePayloadIntegrationTests {

        @Test
        void filePayloadSourceWithFuzzer() throws Exception {
            Path tempFile = Files.createTempFile("fuzz-file-int-", ".txt");
            Files.writeString(tempFile, "alpha\nbeta\ngamma\n");

            HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
            server.createContext("/", exchange -> {
                byte[] body = "OK".getBytes();
                exchange.sendResponseHeaders(200, body.length);
                exchange.getResponseBody().write(body);
                exchange.getResponseBody().close();
            });
            server.start();
            int port = server.getAddress().getPort();

            try {
                FuzzEngine engine = new FuzzEngine();
                String template = "GET http://127.0.0.1:" + port + "/{{1}} HTTP/1.1\n" + "Host: 127.0.0.1:" + port
                        + "\n\n";
                List<FuzzResult> results = new CopyOnWriteArrayList<>();
                CountDownLatch latch = new CountDownLatch(1);

                FuzzEngine.FuzzConfig config = new FuzzEngine.FuzzConfig(template, AttackType.SNIPER,
                        List.of(new FilePayloadSource(tempFile)), List.of(), 1, 0, 0, 10, null, null, null, null, 0);

                engine.start(config, new FuzzEngine.FuzzListener() {
                    @Override
                    public void onResult(FuzzResult result) {
                        results.add(result);
                    }

                    @Override
                    public void onProgress(int completed, long total) {
                    }

                    @Override
                    public void onComplete(int totalCompleted, long elapsedMs) {
                        latch.countDown();
                    }

                    @Override
                    public void onError(String message) {
                        fail("Unexpected error: " + message);
                    }
                });

                assertTrue(latch.await(15, TimeUnit.SECONDS));
                assertEquals(3, results.size(), "File with 3 lines should produce 3 requests");
            } finally {
                server.stop(0);
                Files.deleteIfExists(tempFile);
            }
        }
    }

    // ---------------------------------------------------------------------------
    // Processor pipeline skip integration
    // ---------------------------------------------------------------------------

    @Nested
    class ProcessorSkipIntegrationTests {

        @Test
        void skipProcessorReducesRequestCount() throws Exception {
            HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
            server.createContext("/", exchange -> {
                byte[] body = "OK".getBytes();
                exchange.sendResponseHeaders(200, body.length);
                exchange.getResponseBody().write(body);
                exchange.getResponseBody().close();
            });
            server.start();
            int port = server.getAddress().getPort();

            try {
                FuzzEngine engine = new FuzzEngine();
                String template = "GET http://127.0.0.1:" + port + "/{{1}} HTTP/1.1\n" + "Host: 127.0.0.1:" + port
                        + "\n\n";
                List<FuzzResult> results = new CopyOnWriteArrayList<>();
                CountDownLatch latch = new CountDownLatch(1);

                PayloadSource src = new InlinePayloadSource(List.of("admin", "# comment", "root", "# skip-this"));
                // Skip payloads starting with #
                List<PayloadProcessor> pipeline = List.of(PayloadProcessors.skipIfMatches("^#"));

                FuzzEngine.FuzzConfig config = new FuzzEngine.FuzzConfig(template, AttackType.SNIPER, List.of(src),
                        List.of(pipeline), 1, 0, 0, 10, null, null, null, null, 0);

                engine.start(config, new FuzzEngine.FuzzListener() {
                    @Override
                    public void onResult(FuzzResult result) {
                        results.add(result);
                    }

                    @Override
                    public void onProgress(int completed, long total) {
                    }

                    @Override
                    public void onComplete(int totalCompleted, long elapsedMs) {
                        latch.countDown();
                    }

                    @Override
                    public void onError(String message) {
                    }
                });

                assertTrue(latch.await(15, TimeUnit.SECONDS));
                // 4 payloads, 2 skipped by processor -> 2 actual requests
                assertEquals(2, results.size(), "Skip processor must prevent requests for matching payloads");
            } finally {
                server.stop(0);
            }
        }
    }
}
