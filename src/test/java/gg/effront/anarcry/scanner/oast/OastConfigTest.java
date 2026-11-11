package gg.effront.anarcry.scanner.oast;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;

class OastConfigTest {

    @Test
    void disabledConfigIsNotEnabled() {
        OastConfig cfg = OastConfig.disabled();
        assertFalse(cfg.enabled());
        assertEquals("", cfg.externalUrl());
        assertEquals(30, cfg.callbackWaitSeconds());
    }

    @Test
    void withDefaultsIsEnabled() {
        OastConfig cfg = OastConfig.withDefaults();
        assertTrue(cfg.enabled());
        assertEquals("", cfg.externalUrl());
        assertEquals(30, cfg.callbackWaitSeconds());
    }

    @Test
    void nullExternalUrlNormalized() {
        OastConfig cfg = new OastConfig(true, null, 30);
        assertEquals("", cfg.externalUrl());
    }

    @Test
    void zeroWaitSecondsNormalizedToDefault() {
        OastConfig cfg = new OastConfig(true, "", 0);
        assertEquals(30, cfg.callbackWaitSeconds());
    }

    @Test
    void negativeWaitSecondsNormalizedToDefault() {
        OastConfig cfg = new OastConfig(true, "", -5);
        assertEquals(30, cfg.callbackWaitSeconds());
    }

    @Test
    void customValuesPreserved() {
        OastConfig cfg = new OastConfig(true, "http://custom:8080", 60);
        assertTrue(cfg.enabled());
        assertEquals("http://custom:8080", cfg.externalUrl());
        assertEquals(60, cfg.callbackWaitSeconds());
    }
}
