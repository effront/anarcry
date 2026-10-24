package gg.effront.anarcry.scanner;

import gg.effront.anarcry.model.Suppression;

import java.util.List;
import java.util.Set;

public record ScanConfig(
        int delayMs,
        String sessionCookie,
        Set<String> inScopeHosts,
        List<Suppression> suppressions,
        String redirectRelayUrl) {
    public ScanConfig {
        if (delayMs < 0) {
            delayMs = 0;
        }
        if (sessionCookie == null) {
            sessionCookie = "";
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
    }

    public static ScanConfig defaults() {
        return new ScanConfig(0, "", Set.of(), List.of(), "");
    }

    public boolean isInScope(String host) {
        return inScopeHosts.isEmpty() || inScopeHosts.contains(host);
    }

    public boolean isSuppressed(String module, String title, String host) {
        return suppressions.stream().anyMatch(s -> s.matches(module, title, host));
    }
}
