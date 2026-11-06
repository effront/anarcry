package gg.effront.anarcry.apiclient.model;

import java.util.List;

public record ParamsDef(List<Param> query, List<Param> path) {

    public ParamsDef {
        if (query == null) {
            query = List.of();
        }
        if (path == null) {
            path = List.of();
        }
    }

    public static ParamsDef empty() {
        return new ParamsDef(List.of(), List.of());
    }
}
