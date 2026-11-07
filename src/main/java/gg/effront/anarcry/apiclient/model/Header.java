package gg.effront.anarcry.apiclient.model;

public record Header(String name, String value, boolean enabled) {

    public Header {
        if (name == null) {
            name = "";
        }
        if (value == null) {
            value = "";
        }
    }

    public static Header of(String name, String value) {
        return new Header(name, value, true);
    }
}
