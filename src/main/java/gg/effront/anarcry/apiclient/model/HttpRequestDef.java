package gg.effront.anarcry.apiclient.model;

import java.util.List;

public record HttpRequestDef(String method, String url, ParamsDef params, List<Header> headers, AuthConfig auth,
        BodyConfig body, RequestSettings settings) {

    public HttpRequestDef {
        if (method == null) {
            method = "GET";
        }
        if (url == null) {
            url = "";
        }
        if (params == null) {
            params = ParamsDef.empty();
        }
        if (headers == null) {
            headers = List.of();
        }
        if (auth == null) {
            auth = new AuthConfig.None();
        }
        if (body == null) {
            body = new BodyConfig.None();
        }
        if (settings == null) {
            settings = RequestSettings.defaults();
        }
    }

    public static HttpRequestDef get(String url) {
        return new HttpRequestDef("GET", url, null, null, null, null, null);
    }

    public static HttpRequestDef post(String url, BodyConfig body) {
        return new HttpRequestDef("POST", url, null, null, null, body, null);
    }
}
