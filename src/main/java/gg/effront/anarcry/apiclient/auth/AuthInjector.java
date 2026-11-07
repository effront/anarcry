package gg.effront.anarcry.apiclient.auth;

import gg.effront.anarcry.apiclient.model.AuthConfig;
import gg.effront.anarcry.apiclient.model.HttpRequestDef;
import gg.effront.anarcry.apiclient.vars.VariableStore;

public interface AuthInjector {

    String mode();

    HttpRequestDef inject(HttpRequestDef request, AuthConfig auth, VariableStore vars);
}
