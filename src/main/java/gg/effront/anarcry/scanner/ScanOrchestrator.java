package gg.effront.anarcry.scanner;

import gg.effront.anarcry.model.RequestRecord;
import gg.effront.anarcry.scanner.util.WafState;

import java.util.LinkedHashSet;
import java.util.Set;
import java.util.function.Consumer;

public final class ScanOrchestrator {

    public static final Set<String> ALL_MODULES = Set.of("TLS", "Headers", "HSTS", "JWT", "PQC", "CORS", "OAuth",
            "OpenRedirect", "SSRF", "GraphQL", "CRLF", "XXE", "SSTI", "IDOR", "HostHeader", "Actuator", "MassAssign",
            "CachePoisoning", "ReqSmuggling", "Crawler", "Infra");

    private ScanOrchestrator() {
    }

    public static ScanContext buildContext(String target, String jwt, String jwt2, Set<String> modules,
            Consumer<RequestRecord> requestLogCb) {
        ScanConfig cfg = new ScanConfig(0, "", Set.of(), SuppressionLoader.loadFromCwd(), "");
        return new ScanContext(target, jwt, jwt2, modules, cfg, requestLogCb, new DiscoveredPaths(), new WafState());
    }

    public static ScanContext buildContext(String target, String jwt, String jwt2, Set<String> modules) {
        return buildContext(target, jwt, jwt2, modules, r -> {
        });
    }

    public static Set<String> defaultModules() {
        Set<String> modules = new LinkedHashSet<>(ALL_MODULES);
        modules.remove("IDOR");
        modules.remove("Infra");
        return modules;
    }
}
