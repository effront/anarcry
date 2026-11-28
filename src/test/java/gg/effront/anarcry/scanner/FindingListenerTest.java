package gg.effront.anarcry.scanner;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import gg.effront.anarcry.model.Finding;
import gg.effront.anarcry.model.Severity;

import org.junit.jupiter.api.Test;

import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.ArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

class FindingListenerTest {

    private static Finding stubFinding(String title) {
        return Finding.of("TestModule", "https://example.com/test", title, Severity.LOW, "evidence", "impact",
                "reproduction", "recommendation", "CWE-0", "Test", "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0);
    }

    @Test
    void listenerReceivesFindingsBeforeDedup() throws Exception {
        List<Finding> listenerFindings = Collections.synchronizedList(new ArrayList<>());
        List<Finding> callbackFindings = Collections.synchronizedList(new ArrayList<>());
        CountDownLatch latch = new CountDownLatch(1);

        ScanRunner runner = new ScanRunner(msg -> {
        }, callbackFindings::add);
        runner.addFindingListener(listenerFindings::add);

        // Add a custom module that returns two findings with the same dedup key
        runner.addModule(new Scanner() {
            @Override
            public String id() {
                return "StubDup";
            }

            @Override
            public List<Finding> scan(ScanContext ctx, java.util.function.Consumer<String> log) {
                Finding f1 = stubFinding("Same Title");
                Finding f2 = stubFinding("Same Title");
                return List.of(f1, f2);
            }
        });

        runner.setOnScanFinish(latch::countDown);
        runner.run(new ScanContext("http://127.0.0.1", "", Set.of()));

        assertTrue(latch.await(10, TimeUnit.SECONDS), "Scan must complete in 10s");
        runner.shutdown();

        // Listener sees both findings (before dedup)
        assertEquals(2, listenerFindings.size(), "Listener must see all findings before dedup");
        // findingCb only sees the first (after dedup)
        assertEquals(1, callbackFindings.size(), "findingCb must see only deduplicated findings");
    }

    @Test
    void multipleListenersAllNotified() throws Exception {
        List<Finding> listener1 = Collections.synchronizedList(new ArrayList<>());
        List<Finding> listener2 = Collections.synchronizedList(new ArrayList<>());
        CountDownLatch latch = new CountDownLatch(1);

        ScanRunner runner = new ScanRunner(msg -> {
        }, f -> {
        });
        runner.addFindingListener(listener1::add);
        runner.addFindingListener(listener2::add);

        runner.addModule(new Scanner() {
            @Override
            public String id() {
                return "StubMulti";
            }

            @Override
            public List<Finding> scan(ScanContext ctx, java.util.function.Consumer<String> log) {
                return List.of(stubFinding("Finding A"), stubFinding("Finding B"));
            }
        });

        runner.setOnScanFinish(latch::countDown);
        runner.run(new ScanContext("http://127.0.0.1", "", Set.of()));

        assertTrue(latch.await(10, TimeUnit.SECONDS));
        runner.shutdown();

        assertEquals(2, listener1.size());
        assertEquals(2, listener2.size());
    }

    @Test
    void listenerExceptionDoesNotBreakScan() throws Exception {
        List<Finding> safeListener = Collections.synchronizedList(new ArrayList<>());
        CountDownLatch latch = new CountDownLatch(1);

        ScanRunner runner = new ScanRunner(msg -> {
        }, f -> {
        });
        // First listener throws, second should still receive findings
        runner.addFindingListener(f -> {
            throw new RuntimeException("boom");
        });
        runner.addFindingListener(safeListener::add);

        runner.addModule(new Scanner() {
            @Override
            public String id() {
                return "StubErr";
            }

            @Override
            public List<Finding> scan(ScanContext ctx, java.util.function.Consumer<String> log) {
                return List.of(stubFinding("Survives Error"));
            }
        });

        runner.setOnScanFinish(latch::countDown);
        runner.run(new ScanContext("http://127.0.0.1", "", Set.of()));

        assertTrue(latch.await(10, TimeUnit.SECONDS));
        runner.shutdown();

        assertEquals(1, safeListener.size(), "Second listener must still receive findings");
    }

    @Test
    void findingDiscoveredEventFired() throws Exception {
        List<ScanEvent> events = Collections.synchronizedList(new ArrayList<>());
        CountDownLatch latch = new CountDownLatch(1);

        ScanRunner runner = new ScanRunner(msg -> {
        }, f -> {
        });
        runner.setOnScanEvent(events::add);

        runner.addModule(new Scanner() {
            @Override
            public String id() {
                return "StubEvent";
            }

            @Override
            public List<Finding> scan(ScanContext ctx, java.util.function.Consumer<String> log) {
                return List.of(stubFinding("Event Test"));
            }
        });

        runner.setOnScanFinish(latch::countDown);
        runner.run(new ScanContext("http://127.0.0.1", "", Set.of()));

        assertTrue(latch.await(10, TimeUnit.SECONDS));
        runner.shutdown();

        long discoveredCount = events.stream().filter(e -> e.type() == ScanEvent.Type.FINDING_DISCOVERED).count();
        assertTrue(discoveredCount > 0, "At least one FINDING_DISCOVERED event must fire");

        ScanEvent discovered = events.stream().filter(e -> e.type() == ScanEvent.Type.FINDING_DISCOVERED).findFirst()
                .orElseThrow();
        assertEquals("StubEvent", discovered.moduleId());
        assertTrue(discovered.findingCount() > 0, "findingCount must be positive");
    }
}
