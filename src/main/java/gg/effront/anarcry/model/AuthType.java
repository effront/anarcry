package gg.effront.anarcry.model;

import gg.effront.anarcry.scanner.DiscoveredPaths;
import gg.effront.anarcry.scanner.ScanConfig;
import gg.effront.anarcry.scanner.ScanContext;
import gg.effront.anarcry.scanner.util.WafState;
import java.util.List;
import java.util.Set;
import java.util.function.Consumer;

public enum AuthType {
    NONE, JWT, COOKIE, BEARER;

    public boolean usesBearer() {
        return this == JWT || this == BEARER;
    }

    public boolean usesCookie() {
        return this == COOKIE;
    }

    public boolean requiresJwtParsing() {
        return this == JWT;
    }

    public boolean hasAuth() {
        return this != NONE;
    }

    public ScanContext buildContext(String target, Set<String> modules, String credential, String credential2,
            Consumer<RequestRecord> requestLog) {
        return switch (this) {
            case NONE -> new ScanContext(target, "", modules);
            case JWT, BEARER -> {
                String token1 = credential != null ? credential : "";
                String token2 = credential2 != null ? credential2 : "";
                yield new ScanContext(target, token1, token2, modules);
            }
            case COOKIE -> {
                String cookie = credential != null ? credential : "";
                ScanConfig cfg = new ScanConfig(0, cookie, Set.of(), List.of(), "");
                yield new ScanContext(target, "", "", modules, cfg, requestLog, new DiscoveredPaths(), new WafState());
            }
        };
    }

    public ScanContext buildContext(String target, Set<String> modules, String credential, String credential2) {
        return buildContext(target, modules, credential, credential2, r -> {
        });
    }
}
