package gg.effront.anarcry.scanner;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import gg.effront.anarcry.model.Finding;
import gg.effront.anarcry.model.Severity;

import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

class BatchFindingListenerTest {

    private static Finding stubFinding(String title) {
        return Finding.of("TestModule", "https://example.com/test", title, Severity.LOW, "evidence", "impact",
                "reproduction", "recommendation", "CWE-0", "Test", "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0);
    }

    @Test
    void flushesOnBatchSizeReached() {
        List<List<Finding>> flushed = Collections.synchronizedList(new ArrayList<>());

        try (BatchFindingListener listener = new BatchFindingListener(batch -> flushed.add(new ArrayList<>(batch)), 3,
                60_000)) {
            listener.onFinding(stubFinding("A"));
            listener.onFinding(stubFinding("B"));
            // Not yet flushed
            assertEquals(0, flushed.size(), "Should not flush before batch size reached");

            listener.onFinding(stubFinding("C"));
            // Now flushed -- batch of 3
            assertEquals(1, flushed.size(), "Should flush when batch size reached");
            assertEquals(3, flushed.get(0).size());
        }
    }

    @Test
    void flushesOnTimerExpiry() throws Exception {
        CountDownLatch flushedLatch = new CountDownLatch(1);
        List<List<Finding>> flushed = Collections.synchronizedList(new ArrayList<>());

        try (BatchFindingListener listener = new BatchFindingListener(batch -> {
            flushed.add(new ArrayList<>(batch));
            flushedLatch.countDown();
        }, 100, 200)) {
            listener.onFinding(stubFinding("Timer"));

            // Wait for the timer-based flush
            assertTrue(flushedLatch.await(3, TimeUnit.SECONDS), "Timer flush must trigger within 3s");
            assertEquals(1, flushed.size());
            assertEquals(1, flushed.get(0).size());
            assertEquals("Timer", flushed.get(0).get(0).title());
        }
    }

    @Test
    void closeFlushesRemaining() {
        List<List<Finding>> flushed = Collections.synchronizedList(new ArrayList<>());

        BatchFindingListener listener = new BatchFindingListener(batch -> flushed.add(new ArrayList<>(batch)), 10,
                60_000);
        listener.onFinding(stubFinding("Remaining1"));
        listener.onFinding(stubFinding("Remaining2"));
        assertEquals(0, flushed.size(), "Should not flush before close");

        listener.close();
        assertEquals(1, flushed.size(), "close() must flush remaining findings");
        assertEquals(2, flushed.get(0).size());
    }

    @Test
    void closeIsIdempotent() {
        List<List<Finding>> flushed = Collections.synchronizedList(new ArrayList<>());

        BatchFindingListener listener = new BatchFindingListener(batch -> flushed.add(new ArrayList<>(batch)), 10,
                60_000);
        listener.onFinding(stubFinding("Once"));

        listener.close();
        listener.close(); // second close should be safe
        assertEquals(1, flushed.size(), "Double close must not double-flush");
    }

    @Test
    void onFindingAfterCloseIsIgnored() {
        List<List<Finding>> flushed = Collections.synchronizedList(new ArrayList<>());

        BatchFindingListener listener = new BatchFindingListener(batch -> flushed.add(new ArrayList<>(batch)), 10,
                60_000);
        listener.close();

        listener.onFinding(stubFinding("Late"));
        assertEquals(0, flushed.size(), "Findings after close must be ignored");
    }

    @Test
    void manualFlushDrainsCurrent() {
        List<List<Finding>> flushed = Collections.synchronizedList(new ArrayList<>());

        try (BatchFindingListener listener = new BatchFindingListener(batch -> flushed.add(new ArrayList<>(batch)), 10,
                60_000)) {
            listener.onFinding(stubFinding("Manual1"));
            listener.onFinding(stubFinding("Manual2"));
            assertEquals(0, flushed.size());

            listener.flush();
            assertEquals(1, flushed.size());
            assertEquals(2, flushed.get(0).size());

            // Flush on empty buffer is a no-op
            listener.flush();
            assertEquals(1, flushed.size());
        }
    }

    @Test
    void concurrentOnFindingIsSafe() throws Exception {
        List<List<Finding>> flushed = Collections.synchronizedList(new ArrayList<>());

        try (BatchFindingListener listener = new BatchFindingListener(batch -> flushed.add(new ArrayList<>(batch)), 5,
                60_000)) {
            int threadCount = 10;
            int findingsPerThread = 5;
            CountDownLatch startGate = new CountDownLatch(1);
            CountDownLatch done = new CountDownLatch(threadCount);

            for (int t = 0; t < threadCount; t++) {
                final int threadId = t;
                Thread thread = new Thread(() -> {
                    try {
                        startGate.await();
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                    }
                    for (int f = 0; f < findingsPerThread; f++) {
                        listener.onFinding(stubFinding("T" + threadId + "-F" + f));
                    }
                    done.countDown();
                });
                thread.setDaemon(true);
                thread.start();
            }

            startGate.countDown();
            assertTrue(done.await(5, TimeUnit.SECONDS), "All threads must complete");

            // Flush any remaining
            listener.flush();

            int totalFlushed = flushed.stream().mapToInt(List::size).sum();
            assertEquals(threadCount * findingsPerThread, totalFlushed, "All findings must be flushed without loss");
        }
    }
}
