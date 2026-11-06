package gg.effront.anarcry.apiclient.auth;

import gg.effront.anarcry.apiclient.model.AuthConfig;
import gg.effront.anarcry.apiclient.model.HttpRequestDef;
import gg.effront.anarcry.apiclient.vars.VariableStore;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class BasicAuthInjector implements AuthInjector {

    @Override
    public String mode() {
        return "basic";
    }

    @Override
    public HttpRequestDef inject(HttpRequestDef request, AuthConfig auth, VariableStore vars) {
        if (!(auth instanceof AuthConfig.Basic basic)) {
            return request;
        }
        String credentials = basic.username() + ":" + basic.password();
        String encoded = Base64.getEncoder().encodeToString(credentials.getBytes(StandardCharsets.UTF_8));
        return AuthInjectorRegistry.addHeader(request, "Authorization", "Basic " + encoded);
    }
}
