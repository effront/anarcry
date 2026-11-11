package gg.effront.anarcry.apiclient.auth;

import gg.effront.anarcry.apiclient.model.AuthConfig;
import gg.effront.anarcry.apiclient.model.Header;
import gg.effront.anarcry.apiclient.model.HttpRequestDef;
import gg.effront.anarcry.apiclient.model.Param;
import gg.effront.anarcry.apiclient.model.ParamsDef;
import gg.effront.anarcry.apiclient.vars.VariableStore;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

public class AuthInjectorRegistry {

    private final Map<String, AuthInjector> injectors = new LinkedHashMap<>();

    public AuthInjectorRegistry() {
        register(new BasicAuthInjector());
        register(new BearerAuthInjector());
        register(new ApiKeyInjector());
        register(new DigestAuthInjector());
        register(new OAuth2Injector());
        register(new WsseInjector());
        register(new NtlmInjector());
        register(new OAuth1Injector());
        register(new AwsV4Injector());
        register(new EdgeGridInjector());
    }

    public void register(AuthInjector injector) {
        injectors.put(injector.mode(), injector);
    }

    public Optional<AuthInjector> forMode(String mode) {
        return Optional.ofNullable(injectors.get(mode));
    }

    public HttpRequestDef inject(HttpRequestDef request, AuthConfig auth, VariableStore vars) {
        if (auth == null || auth instanceof AuthConfig.None || auth instanceof AuthConfig.Inherit) {
            return request;
        }
        AuthInjector injector = injectors.get(auth.mode());
        if (injector == null) {
            return request;
        }
        return injector.inject(request, auth, vars);
    }

    public static HttpRequestDef addHeader(HttpRequestDef request, String name, String value) {
        List<Header> headers = new ArrayList<>(request.headers());
        headers.removeIf(h -> h.name().equalsIgnoreCase(name));
        headers.add(Header.of(name, value));
        return new HttpRequestDef(request.method(), request.url(), request.params(), headers, request.auth(),
                request.body(), request.settings());
    }

    public static HttpRequestDef addQueryParam(HttpRequestDef request, String name, String value) {
        List<Param> query = new ArrayList<>(request.params().query());
        query.add(Param.query(name, value));
        ParamsDef params = new ParamsDef(query, request.params().path());
        return new HttpRequestDef(request.method(), request.url(), params, request.headers(), request.auth(),
                request.body(), request.settings());
    }
}
