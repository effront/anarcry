package gg.effront.anarcry.assistant.tools;

import com.google.gson.Gson;
import gg.effront.anarcry.scanner.ScanContext;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;
import java.util.stream.Collectors;

public final class GetScanConfigTool implements AssistantTool {

    private static final Gson GSON = new Gson();

    private final Supplier<ScanContext> contextSupplier;

    public GetScanConfigTool(Supplier<ScanContext> contextSupplier) {
        this.contextSupplier = contextSupplier;
    }

    @Override
    public String name() {
        return "get_scan_config";
    }

    @Override
    public String description() {
        return "Returns current scan configuration: target URL, auth type, enabled modules, scope";
    }

    @Override
    public String paramsSchema() {
        return """
                {
                  "type": "object",
                  "properties": {}
                }""";
    }

    @Override
    public String call(String paramsJson) {
        ScanContext ctx = contextSupplier.get();
        if (ctx == null) {
            return GSON.toJson(Map.of("status", "no_scan_running"));
        }

        Map<String, Object> response = new LinkedHashMap<>();
        response.put("target", ctx.targetUrl());
        response.put("host", ctx.host());
        response.put("https", ctx.isHttps());

        String authType = "NONE";
        if (!ctx.jwtToken().isEmpty()) {
            authType = "JWT/BEARER";
        } else if (!ctx.config().sessionCookie().isEmpty()) {
            authType = "COOKIE";
        }
        response.put("authType", authType);
        response.put("hasAuth", !ctx.jwtToken().isEmpty() || !ctx.config().sessionCookie().isEmpty());

        List<String> modules = ctx.enabledModules().stream().sorted().collect(Collectors.toList());
        response.put("enabledModules", modules);
        response.put("moduleCount", modules.size());

        if (!ctx.config().inScopeHosts().isEmpty()) {
            response.put("scopeHosts", ctx.config().inScopeHosts());
        }

        response.put("discoveredPaths", ctx.discoveredPaths().pathCount());
        response.put("discoveredParams", ctx.discoveredPaths().parameterCount());
        response.put("probeConcurrency", ctx.config().probeConcurrency());

        return GSON.toJson(response);
    }
}
