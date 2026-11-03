package gg.effront.anarcry.scanner.util;

public class CircuitBreakerException extends RuntimeException {

    private final String moduleId;
    private final int consecutiveBlocks;

    public CircuitBreakerException(String moduleId, int consecutiveBlocks) {
        super(moduleId + " abortado -- " + consecutiveBlocks + " bloqueios consecutivos (WAF circuit breaker)");
        this.moduleId = moduleId;
        this.consecutiveBlocks = consecutiveBlocks;
    }

    public String moduleId() {
        return moduleId;
    }

    public int consecutiveBlocks() {
        return consecutiveBlocks;
    }
}
