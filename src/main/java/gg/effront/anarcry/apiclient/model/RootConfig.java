package gg.effront.anarcry.apiclient.model;

import java.util.List;

public record RootConfig(List<Header> headers, AuthConfig auth, List<EnvVariable> vars) {

    public RootConfig {
        if (headers == null) {
            headers = List.of();
        }
        if (auth == null) {
            auth = new AuthConfig.None();
        }
        if (vars == null) {
            vars = List.of();
        }
    }

    public static RootConfig empty() {
        return new RootConfig(List.of(), new AuthConfig.None(), List.of());
    }
}
