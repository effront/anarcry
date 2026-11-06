package gg.effront.anarcry.scanner.auth.harvester;

import gg.effront.anarcry.scanner.auth.AuthException;
import gg.effront.anarcry.scanner.auth.AuthProvider;
import gg.effront.anarcry.scanner.auth.CredentialStore;

import java.util.Map;

public interface Harvester {
    AuthProvider provider();
    boolean canHandle(String targetUrl, String pageSource);
    CredentialStore harvest(String targetUrl, String username, String password,
                           Map<String, String> extra) throws AuthException;
}
