package gg.effront.anarcry.scanner;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.Test;

class DiscoveredPathsTest {

    @Test
    void startsEmpty() {
        DiscoveredPaths dp = new DiscoveredPaths();
        assertTrue(dp.isEmpty());
        assertEquals(0, dp.pathCount());
        assertEquals(0, dp.parameterCount());
        assertTrue(dp.paths().isEmpty());
        assertTrue(dp.parameters().isEmpty());
    }

    @Test
    void addPathAndParameter() {
        DiscoveredPaths dp = new DiscoveredPaths();
        dp.addPath("/api/users");
        dp.addParameter("id");
        assertFalse(dp.isEmpty());
        assertEquals(1, dp.pathCount());
        assertEquals(1, dp.parameterCount());
        assertTrue(dp.paths().contains("/api/users"));
        assertTrue(dp.parameters().contains("id"));
    }

    @Test
    void addPathsAndParametersBulk() {
        DiscoveredPaths dp = new DiscoveredPaths();
        dp.addPaths(List.of("/a", "/b", "/c"));
        dp.addParameters(List.of("x", "y"));
        assertEquals(3, dp.pathCount());
        assertEquals(2, dp.parameterCount());
    }

    @Test
    void deduplication() {
        DiscoveredPaths dp = new DiscoveredPaths();
        dp.addPath("/api/users");
        dp.addPath("/api/users");
        dp.addParameter("id");
        dp.addParameter("id");
        assertEquals(1, dp.pathCount());
        assertEquals(1, dp.parameterCount());
    }

    @Test
    void nullAndBlankRejected() {
        DiscoveredPaths dp = new DiscoveredPaths();
        dp.addPath(null);
        dp.addPath("");
        dp.addPath("   ");
        dp.addParameter(null);
        dp.addParameter("");
        dp.addParameter("  ");
        assertTrue(dp.isEmpty());
    }

    @Test
    void unmodifiableViews() {
        DiscoveredPaths dp = new DiscoveredPaths();
        dp.addPath("/test");
        dp.addParameter("q");
        Set<String> paths = dp.paths();
        Set<String> params = dp.parameters();
        assertThrows(UnsupportedOperationException.class, () -> paths.add("/hack"));
        assertThrows(UnsupportedOperationException.class, () -> params.add("hack"));
    }

    @Test
    void threadSafety() throws Exception {
        DiscoveredPaths dp = new DiscoveredPaths();
        int threads = 4;
        int perThread = 250;
        CountDownLatch latch = new CountDownLatch(threads);
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CopyOnWriteArrayList<Throwable> errors = new CopyOnWriteArrayList<>();

        for (int t = 0; t < threads; t++) {
            final int offset = t * perThread;
            pool.submit(() -> {
                try {
                    for (int i = 0; i < perThread; i++) {
                        dp.addPath("/path/" + (offset + i));
                        dp.addParameter("param" + (offset + i));
                    }
                } catch (Throwable e) {
                    errors.add(e);
                } finally {
                    latch.countDown();
                }
            });
        }

        assertTrue(latch.await(10, TimeUnit.SECONDS));
        pool.shutdown();
        assertTrue(errors.isEmpty(), "Concurrent writes threw: " + errors);
        assertEquals(threads * perThread, dp.pathCount());
        assertEquals(threads * perThread, dp.parameterCount());
    }
}
