package gg.effront.anarcry.scanner.util;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.Semaphore;
import java.util.concurrent.atomic.AtomicBoolean;

public final class ProbeExecutor {

    private ProbeExecutor() {
    }

    /**
     * Runs probe tasks with bounded concurrency using virtual threads. Each task
     * returns a list of results. The caller controls early termination via the
     * cancel flag -- set it to true inside a task lambda to signal other tasks to
     * bail out.
     *
     * @param tasks
     *            probe tasks, each returning a list of results
     * @param maxConcurrency
     *            max in-flight requests (semaphore permits)
     * @param cancel
     *            shared cancellation flag -- checked before acquiring a permit and
     *            after; tasks should also check it in inner loops
     * @return aggregated results from all tasks
     */
    public static <T> List<T> run(List<Callable<List<T>>> tasks, int maxConcurrency, AtomicBoolean cancel) {
        if (tasks.isEmpty()) {
            return List.of();
        }
        if (maxConcurrency <= 1) {
            List<T> results = new ArrayList<>();
            for (Callable<List<T>> task : tasks) {
                if (cancel.get()) {
                    break;
                }
                try {
                    results.addAll(task.call());
                } catch (Exception ignored) {
                    // Module-level exceptions are swallowed (consistent with current behavior)
                }
            }
            return results;
        }

        Semaphore sem = new Semaphore(maxConcurrency);
        List<T> results = Collections.synchronizedList(new ArrayList<>());

        try (ExecutorService vte = Executors.newVirtualThreadPerTaskExecutor()) {
            List<Future<?>> futures = new ArrayList<>();
            for (Callable<List<T>> task : tasks) {
                futures.add(vte.submit(() -> {
                    try {
                        if (cancel.get()) {
                            return;
                        }
                        sem.acquire();
                        try {
                            if (cancel.get()) {
                                return;
                            }
                            List<T> r = task.call();
                            if (!r.isEmpty()) {
                                results.addAll(r);
                            }
                        } finally {
                            sem.release();
                        }
                    } catch (Exception ignored) {
                        // Task-level exceptions are swallowed (timeouts, connection errors)
                    }
                }));
            }
            for (Future<?> f : futures) {
                try {
                    f.get();
                } catch (Exception ignored) {
                    // Individual task failures are expected (timeouts, connection errors)
                }
            }
        }

        return new ArrayList<>(results);
    }
}
