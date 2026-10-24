package gg.effront.anarcry.scanner;

import java.util.Set;

public record ScanConfig(int delayMs, // delay entre requisições em ms (default 0)
        String sessionCookie, // valor do header Cookie a injetar (default "")
        Set<String> inScopeHosts // hosts permitidos; vazio = qualquer host
) {
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
    }

    public static ScanConfig defaults() {
        return new ScanConfig(0, "", Set.of());
    }

    public boolean isInScope(String host) {
        return inScopeHosts.isEmpty() || inScopeHosts.contains(host);
    }
}
