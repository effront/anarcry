package gg.effront.anarcry.scanner;

import gg.effront.anarcry.model.RequestRecord;

import java.net.URI;
import java.util.Set;
import java.util.function.Consumer;

public record ScanContext(String targetUrl, String jwtToken, String jwtToken2, Set<String> enabledModules,
        ScanConfig config, Consumer<RequestRecord> requestLog, DiscoveredPaths discoveredPaths) {

    public ScanContext(String targetUrl, String jwtToken, Set<String> enabledModules) {
        this(targetUrl, jwtToken, "", enabledModules, ScanConfig.defaults(), r -> {
        }, new DiscoveredPaths());
    }

    public ScanContext(String targetUrl, String jwtToken, String jwtToken2, Set<String> enabledModules) {
        this(targetUrl, jwtToken, jwtToken2, enabledModules, ScanConfig.defaults(), r -> {
        }, new DiscoveredPaths());
    }

    public ScanContext(String targetUrl, String jwtToken, Set<String> enabledModules, String jwtToken2) {
        this(targetUrl, jwtToken, jwtToken2, enabledModules, ScanConfig.defaults(), r -> {
        }, new DiscoveredPaths());
    }

    public ScanContext(String targetUrl, String jwtToken, Set<String> enabledModules, String jwtToken2,
            Consumer<RequestRecord> requestLog) {
        this(targetUrl, jwtToken, jwtToken2, enabledModules, ScanConfig.defaults(), requestLog, new DiscoveredPaths());
    }

    public ScanContext(String targetUrl, String jwtToken, Set<String> enabledModules, String jwtToken2,
            ScanConfig config, Consumer<RequestRecord> requestLog) {
        this(targetUrl, jwtToken, jwtToken2, enabledModules, config, requestLog, new DiscoveredPaths());
    }

    public String host() {
        return URI.create(targetUrl).getHost();
    }

    public int port() {
        URI uri = URI.create(targetUrl);
        int p = uri.getPort();
        if (p > 0) {
            return p;
        }
        return uri.getScheme().equalsIgnoreCase("https") ? 443 : 80;
    }

    public boolean isHttps() {
        return targetUrl.toLowerCase().startsWith("https://");
    }

    public boolean has(String module) {
        return enabledModules.contains(module);
    }
}
