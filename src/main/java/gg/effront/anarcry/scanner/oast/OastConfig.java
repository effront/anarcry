package gg.effront.anarcry.scanner.oast;

/**
 * Configuration for the OAST (Out-of-Band Application Security Testing)
 * subsystem.
 *
 * @param enabled
 *            whether OAST callback listening is active
 * @param externalUrl
 *            user-provided external URL for the callback server (e.g. when
 *            behind NAT); empty string means auto-detect
 * @param callbackWaitSeconds
 *            how long to wait after Phase 2 for OOB callbacks to arrive
 */
public record OastConfig(boolean enabled, String externalUrl, int callbackWaitSeconds) {

    private static final int DEFAULT_WAIT_SECONDS = 30;

    public OastConfig {
        if (externalUrl == null) {
            externalUrl = "";
        }
        if (callbackWaitSeconds <= 0) {
            callbackWaitSeconds = DEFAULT_WAIT_SECONDS;
        }
    }

    public static OastConfig disabled() {
        return new OastConfig(false, "", DEFAULT_WAIT_SECONDS);
    }

    public static OastConfig withDefaults() {
        return new OastConfig(true, "", DEFAULT_WAIT_SECONDS);
    }
}
