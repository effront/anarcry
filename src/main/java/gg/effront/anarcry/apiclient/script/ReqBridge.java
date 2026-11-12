package gg.effront.anarcry.apiclient.script;

import gg.effront.anarcry.apiclient.model.BodyConfig;
import gg.effront.anarcry.apiclient.model.Header;
import gg.effront.anarcry.apiclient.model.HttpRequestDef;

import org.graalvm.polyglot.HostAccess;

import java.util.LinkedHashMap;
import java.util.Map;

public class ReqBridge {

    private HttpRequestDef request;
    private final Map<String, String> headerOverrides = new LinkedHashMap<>();

    public ReqBridge(HttpRequestDef request) {
        this.request = request;
    }

    public void update(HttpRequestDef request) {
        this.request = request;
    }

    @HostAccess.Export
    public String getUrl() {
        return request.url();
    }

    @HostAccess.Export
    public String getMethod() {
        return request.method();
    }

    @HostAccess.Export
    public String getHeader(String name) {
        String override = headerOverrides.get(name.toLowerCase());
        if (override != null) {
            return override;
        }
        for (Header h : request.headers()) {
            if (h.name().equalsIgnoreCase(name)) {
                return h.value();
            }
        }
        return "";
    }

    @HostAccess.Export
    public void setHeader(String name, String value) {
        headerOverrides.put(name.toLowerCase(), value);
    }

    @HostAccess.Export
    public String getBody() {
        return switch (request.body()) {
            case BodyConfig.Json j -> j.content();
            case BodyConfig.Text t -> t.content();
            case BodyConfig.Xml x -> x.content();
            case BodyConfig.GraphQL g -> g.query();
            default -> "";
        };
    }

    @HostAccess.Export
    public String getAuthType() {
        return request.auth().mode();
    }

    public Map<String, String> headerOverrides() {
        return Map.copyOf(headerOverrides);
    }
}
