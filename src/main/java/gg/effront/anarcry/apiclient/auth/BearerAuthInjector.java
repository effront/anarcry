package gg.effront.anarcry.apiclient.auth;

import gg.effront.anarcry.apiclient.model.AuthConfig;
import gg.effront.anarcry.apiclient.model.HttpRequestDef;
import gg.effront.anarcry.apiclient.vars.VariableStore;

public class BearerAuthInjector implements AuthInjector {

    @Override
    public String mode() {
        return "bearer";
    }

    @Override
    public HttpRequestDef inject(HttpRequestDef request, AuthConfig auth, VariableStore vars) {
        if (!(auth instanceof AuthConfig.Bearer bearer)) {
            return request;
        }
        return AuthInjectorRegistry.addHeader(request, "Authorization", "Bearer " + bearer.token());
    }
}
