package gg.effront.anarcry.scanner.util;

import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

public final class WafState {

    private final AtomicBoolean wafDetected = new AtomicBoolean(false);
    private final AtomicReference<String> wafProduct = new AtomicReference<>("");
    private final AtomicReference<WafEvasion.Strategy> effectiveStrategy = new AtomicReference<>();
    private final AtomicBoolean stealthActive = new AtomicBoolean(false);
    private final AtomicBoolean jsChallenge = new AtomicBoolean(false);
    private final AtomicReference<String> challengeType = new AtomicReference<>("");
    private final AtomicReference<String> challengeCookies = new AtomicReference<>("");
    private volatile BrowserTransport browserTransport;

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
}
