package gg.effront.anarcry.apiclient.model;

public record RequestMeta(String name, String type, int seq) {

    public RequestMeta {
        if (name == null) {
            name = "";
        }
        if (type == null) {
            type = "http";
        }
    }

    public static RequestMeta http(String name, int seq) {
        return new RequestMeta(name, "http", seq);
    }
}
