package gg.effront.anarcry.apiclient.model;

import java.util.List;

public record RequestItem(String uid, String name, RequestMeta meta, HttpRequestDef request, VarsDef vars,
        List<Assertion> assertions, String docs) implements CollectionItem {

    public RequestItem {
        if (uid == null) {
            uid = java.util.UUID.randomUUID().toString();
        }
        if (name == null) {
            name = "";
        }
        if (meta == null) {
            meta = RequestMeta.http(name, 0);
        }
        if (vars == null) {
            vars = VarsDef.empty();
        }
        if (assertions == null) {
            assertions = List.of();
        }
    }
}
