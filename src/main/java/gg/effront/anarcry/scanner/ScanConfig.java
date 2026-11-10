package gg.effront.anarcry.scanner;

import gg.effront.anarcry.model.Suppression;
import gg.effront.anarcry.scanner.oast.OastConfig;

import java.util.List;
import java.util.Set;

public record ScanConfig(int delayMs, String sessionCookie, String sessionCookie2, Set<String> inScopeHosts,
        List<Suppression> suppressions, String redirectRelayUrl, int probeConcurrency, boolean exploitationEnabled,
        OastConfig oastConfig) {

    public static final int DEFAULT_PROBE_CONCURRENCY = 12;

    public ScanConfig {
        if (delayMs < 0) {
            delayMs = 0;
        }
        if (sessionCookie == null) {
            sessionCookie = "";
        }
        if (sessionCookie2 == null) {
            sessionCookie2 = "";
        }
        if (inScopeHosts == null) {
            inScopeHosts = Set.of();
        }
        if (suppressions == null) {
            suppressions = List.of();
        }
        if (redirectRelayUrl == null) {
            redirectRelayUrl = "";
        }
        if (probeConcurrency <= 0) {
            probeConcurrency = DEFAULT_PROBE_CONCURRENCY;
        }
        if (oastConfig == null) {
            oastConfig = OastConfig.disabled();
        }
    }

    public ScanConfig(int delayMs, String sessionCookie, String sessionCookie2, Set<String> inScopeHosts,
            List<Suppression> suppressions, String redirectRelayUrl, int probeConcurrency,
            boolean exploitationEnabled) {
        this(delayMs, sessionCookie, sessionCookie2, inScopeHosts, suppressions, redirectRelayUrl, probeConcurrency,
                exploitationEnabled, OastConfig.disabled());
    }

    public ScanConfig(int delayMs, String sessionCookie, String sessionCookie2, Set<String> inScopeHosts,
            List<Suppression> suppressions, String redirectRelayUrl, int probeConcurrency) {
        this(delayMs, sessionCookie, sessionCookie2, inScopeHosts, suppressions, redirectRelayUrl, probeConcurrency,
                false, OastConfig.disabled());
    }

    public ScanConfig(int delayMs, String sessionCookie, Set<String> inScopeHosts, List<Suppression> suppressions,
            String redirectRelayUrl) {
        this(delayMs, sessionCookie, "", inScopeHosts, suppressions, redirectRelayUrl, DEFAULT_PROBE_CONCURRENCY, false,
                OastConfig.disabled());
    }

    public static ScanConfig defaults() {
        return new ScanConfig(0, "", "", Set.of(), List.of(), "", DEFAULT_PROBE_CONCURRENCY, false,
                OastConfig.disabled());
    }

    public boolean oastEnabled() {
        return oastConfig != null && oastConfig.enabled();
    }

    public boolean isInScope(String host) {
        return inScopeHosts.isEmpty() || inScopeHosts.contains(host);
    }

    public boolean isSuppressed(String module, String title, String host) {
        return suppressions.stream().anyMatch(s -> s.matches(module, title, host));
    }
}
