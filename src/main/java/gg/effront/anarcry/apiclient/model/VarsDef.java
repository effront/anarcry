package gg.effront.anarcry.apiclient.model;

import java.util.List;

public record VarsDef(List<VarEntry> pre, List<VarEntry> post) {

    public record VarEntry(String name, String value) {

        public VarEntry {
            if (name == null) {
                name = "";
            }
            if (value == null) {
                value = "";
            }
        }
    }

    public VarsDef {
        if (pre == null) {
            pre = List.of();
        }
        if (post == null) {
            post = List.of();
        }
    }

    public static VarsDef empty() {
        return new VarsDef(List.of(), List.of());
    }
}
