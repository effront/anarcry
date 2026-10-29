package gg.effront.anarcry.scanner.util;

import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

public final class WafState {

    private final AtomicBoolean wafDetected = new AtomicBoolean(false);
    private final AtomicReference<String> wafProduct = new AtomicReference<>("");
    private final AtomicReference<WafEvasion.Strategy> effectiveStrategy = new AtomicReference<>();

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
}
