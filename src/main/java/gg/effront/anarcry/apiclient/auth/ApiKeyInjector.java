package gg.effront.anarcry.apiclient.auth;

import gg.effront.anarcry.apiclient.model.AuthConfig;
import gg.effront.anarcry.apiclient.model.HttpRequestDef;
import gg.effront.anarcry.apiclient.vars.VariableStore;

public class ApiKeyInjector implements AuthInjector {

    @Override
    public String mode() {
        return "apikey";
    }

    @Override
    public HttpRequestDef inject(HttpRequestDef request, AuthConfig auth, VariableStore vars) {
        if (!(auth instanceof AuthConfig.ApiKey apiKey)) {
            return request;
        }
        if ("queryparams".equalsIgnoreCase(apiKey.placement())) {
            return AuthInjectorRegistry.addQueryParam(request, apiKey.key(), apiKey.value());
        }
        return AuthInjectorRegistry.addHeader(request, apiKey.key(), apiKey.value());
    }
}
