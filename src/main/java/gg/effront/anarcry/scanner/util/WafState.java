package gg.effront.anarcry.scanner.util;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;

public final class WafState {

    /** Classifies the type of WAF block observed during scanning. */
    public enum WafBlockType {
        /** No block detected -- scan proceeds normally. */
        NONE,
        /** WAF blocked a specific payload -- stealth + evasion strategies may help. */
        RULE_BLOCK,
        /** Cloudflare managed challenge -- browser required, evasion is useless. */
        MANAGED_CHALLENGE,
        /** Pure JS challenge -- BrowserTransport may solve it. */
        JS_CHALLENGE,
        /** Vercel Security Checkpoint -- solvable via headless (WASM + mouse sim). */
        VERCEL_CHALLENGE,
        /** Interactive captcha (Turnstile) -- out of scope for automated bypass. */
        TURNSTILE
    }

    private static final int DEFAULT_THRESHOLD = 8;
    private static final int WAF_RULE_THRESHOLD = 25;
    private static final int MANAGED_CHALLENGE_THRESHOLD = 3;
    private static final int VERCEL_CHALLENGE_THRESHOLD = 5;

    private final AtomicBoolean wafDetected = new AtomicBoolean(false);
    private final AtomicReference<String> wafProduct = new AtomicReference<>("");
    private final AtomicReference<String> cdnProduct = new AtomicReference<>("");
    private final AtomicReference<WafEvasion.Strategy> effectiveStrategy = new AtomicReference<>();
    private final AtomicBoolean stealthActive = new AtomicBoolean(false);
    private final AtomicBoolean jsChallenge = new AtomicBoolean(false);
    private final AtomicReference<String> challengeType = new AtomicReference<>("");
    private final AtomicReference<String> challengeCookies = new AtomicReference<>("");
    private final AtomicReference<WafBlockType> blockType = new AtomicReference<>(WafBlockType.NONE);
    private volatile BrowserTransport browserTransport;
    private final ConcurrentHashMap<String, CircuitBreaker> circuitBreakers = new ConcurrentHashMap<>();
    private volatile Consumer<String> runtimeLog;
    private volatile boolean debugMode;
    private volatile int wafDelayMs;

    public void setDebugMode(boolean enabled) {
        this.debugMode = enabled;
    }

    public boolean isDebugMode() {
        return debugMode;
    }

    public void debugLog(String msg) {
        if (debugMode && runtimeLog != null) {
            runtimeLog.accept("[DBG] " + msg);
        }
    }

    public void markWafDetected(String product) {
        wafDetected.set(true);
        if (product != null && !product.isBlank()) {
            wafProduct.set(product);
        }
    }

    public boolean isWafDetected() {
        return wafDetected.get();
    }

    public String wafProduct() {
        return wafProduct.get();
    }

    public void markCdnPresent(String product) {
        if (product != null && !product.isBlank()) {
            cdnProduct.set(product);
        }
    }

    public String cdnProduct() {
        return cdnProduct.get();
    }

    public void markEffectiveStrategy(WafEvasion.Strategy strategy) {
        effectiveStrategy.set(strategy);
    }

    public WafEvasion.Strategy effectiveStrategy() {
        return effectiveStrategy.get();
    }

    public void markStealthActive() {
        stealthActive.set(true);
    }

    public boolean isStealthActive() {
        return stealthActive.get();
    }

    public void markJsChallenge(String type) {
        jsChallenge.set(true);
        if (type != null && !type.isBlank()) {
            challengeType.set(type);
        }
    }

    public boolean isJsChallenge() {
        return jsChallenge.get();
    }

    public String challengeType() {
        return challengeType.get();
    }

    public void setChallengeCookies(String cookies) {
        if (cookies != null) {
            challengeCookies.set(cookies);
        }
    }

    public String challengeCookies() {
        return challengeCookies.get();
    }

    public boolean hasChallengeCookies() {
        return !challengeCookies.get().isEmpty();
    }

    public void setBrowserTransport(BrowserTransport transport) {
        this.browserTransport = transport;
    }

    public BrowserTransport browserTransport() {
        return browserTransport;
    }

    public void closeBrowserTransport() {
        BrowserTransport bt = browserTransport;
        if (bt != null) {
            browserTransport = null;
            bt.close();
        }
    }

    public void setRuntimeLog(Consumer<String> log) {
        this.runtimeLog = log;
    }

    public Consumer<String> runtimeLog() {
        return runtimeLog;
    }

    public void markBlockType(WafBlockType type) {
        if (type != null) {
            blockType.set(type);
        }
    }

    public WafBlockType blockType() {
        return blockType.get();
    }

    /** Returns true if blockType is MANAGED_CHALLENGE or TURNSTILE. */
    public boolean isManaged() {
        WafBlockType current = blockType.get();
        return current == WafBlockType.MANAGED_CHALLENGE || current == WafBlockType.TURNSTILE;
    }

    /** Returns true if blockType is RULE_BLOCK. */
    public boolean isRuleBlock() {
        return blockType.get() == WafBlockType.RULE_BLOCK;
    }

    /** Returns true if blockType is VERCEL_CHALLENGE. */
    public boolean isVercelChallenge() {
        return blockType.get() == WafBlockType.VERCEL_CHALLENGE;
    }

    /**
     * Returns the effective circuit breaker threshold based on the current block
     * type. Managed challenges get a lower threshold (3) since every request will
     * be blocked -- no point insisting.
     */
    public int effectiveThreshold() {
        if (isManaged()) {
            return MANAGED_CHALLENGE_THRESHOLD;
        }
        if (isVercelChallenge()) {
            return VERCEL_CHALLENGE_THRESHOLD;
        }
        return isRuleBlock() ? WAF_RULE_THRESHOLD : DEFAULT_THRESHOLD;
    }

    public CircuitBreaker circuitBreaker(String moduleId) {
        return circuitBreakers.computeIfAbsent(moduleId, id -> new CircuitBreaker(id, effectiveThreshold()));
    }

    public boolean isCircuitOpen(String moduleId) {
        CircuitBreaker cb = circuitBreakers.get(moduleId);
        return cb != null && cb.isTripped();
    }

    public void setWafDelay(int ms) {
        this.wafDelayMs = Math.max(0, ms);
    }

    public int wafDelayMs() {
        return wafDelayMs;
    }
}
