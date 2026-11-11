package gg.effront.anarcry.apiclient.script;

import gg.effront.anarcry.apiclient.model.ResponseData;

import org.graalvm.polyglot.HostAccess;

import java.util.List;
import java.util.Map;

public class ResBridge {

    private ResponseData response;

    public ResBridge() {
    }

    public void setResponse(ResponseData response) {
        this.response = response;
    }

    @HostAccess.Export
    public int getStatus() {
        return response != null ? response.status() : 0;
    }

    @HostAccess.Export
    public String getBody() {
        return response != null ? response.body() : "";
    }

    @HostAccess.Export
    public String getHeader(String name) {
        if (response == null) {
            return "";
        }
        return response.header(name);
    }

    @HostAccess.Export
    public long getResponseTime() {
        return response != null ? response.responseTimeMs() : 0;
    }

    @HostAccess.Export
    public long getSize() {
        return response != null ? response.size() : 0;
    }

    @HostAccess.Export
    public String getStatusText() {
        return response != null ? response.statusText() : "";
    }

    @HostAccess.Export
    public Map<String, List<String>> getHeaders() {
        return response != null ? response.headers() : Map.of();
    }
}
