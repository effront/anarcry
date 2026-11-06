package gg.effront.anarcry.apiclient.model;

public record EnvVariable(String name, String value, boolean secret, boolean enabled) {

    public EnvVariable {
        if (name == null) {
            name = "";
        }
        if (value == null) {
            value = "";
        }
    }

    public static EnvVariable of(String name, String value) {
        return new EnvVariable(name, value, false, true);
    }

    public static EnvVariable secret(String name, String value) {
        return new EnvVariable(name, value, true, true);
    }
}
