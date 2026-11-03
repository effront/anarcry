package gg.effront.anarcry.scanner.util;

import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;

public final class CircuitBreaker {

    private static final int DEFAULT_THRESHOLD = 8;

    private final int threshold;
    private final AtomicInteger consecutiveBlocks = new AtomicInteger(0);
    private final AtomicBoolean tripped = new AtomicBoolean(false);
    private final AtomicBoolean logged = new AtomicBoolean(false);
    private final String moduleId;

    public CircuitBreaker(String moduleId) {
        this(moduleId, DEFAULT_THRESHOLD);
    }

    public CircuitBreaker(String moduleId, int threshold) {
        this.moduleId = moduleId;
        this.threshold = threshold;
    }

    public void recordSuccess() {
        consecutiveBlocks.set(0);
    }

    public void recordBlock(Consumer<String> log) {
        int count = consecutiveBlocks.incrementAndGet();
        if (count >= threshold && tripped.compareAndSet(false, true)) {
            if (logged.compareAndSet(false, true) && log != null) {
                log.accept("[!] " + moduleId + " circuit breaker: " + count
                        + " bloqueios WAF consecutivos -- abortando modulo");
            }
        }
    }

    public boolean isTripped() {
        return tripped.get();
    }

    public int consecutiveBlocks() {
        return consecutiveBlocks.get();
    }

    public String moduleId() {
        return moduleId;
    }

    public void checkAndThrow() {
        if (tripped.get()) {
            throw new CircuitBreakerException(moduleId, consecutiveBlocks.get());
        }
    }
}
