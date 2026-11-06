package gg.effront.anarcry.apiclient.model;

public record Param(String name, String value, ParamType type, boolean enabled) {

    public enum ParamType {
        QUERY, PATH
    }

    public Param {
        if (name == null) {
            name = "";
        }
        if (value == null) {
            value = "";
        }
        if (type == null) {
            type = ParamType.QUERY;
        }
    }

    public static Param query(String name, String value) {
        return new Param(name, value, ParamType.QUERY, true);
    }

    public static Param path(String name, String value) {
        return new Param(name, value, ParamType.PATH, true);
    }
}
