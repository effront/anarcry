package gg.effront.anarcry.apiclient.model;

import java.util.Map;

public sealed interface AuthConfig {

    String mode();

    record None() implements AuthConfig {

        @Override
        public String mode() {
            return "none";
        }
    }

    record Inherit() implements AuthConfig {

        @Override
        public String mode() {
            return "inherit";
        }
    }

    record Basic(String username, String password) implements AuthConfig {

        @Override
        public String mode() {
            return "basic";
        }
    }

    record Bearer(String token) implements AuthConfig {

        @Override
        public String mode() {
            return "bearer";
        }
    }

    record Digest(String username, String password) implements AuthConfig {

        @Override
        public String mode() {
            return "digest";
        }
    }

    record Ntlm(String username, String password, String domain) implements AuthConfig {

        @Override
        public String mode() {
            return "ntlm";
        }
    }

    record ApiKey(String key, String value, String placement) implements AuthConfig {

        @Override
        public String mode() {
            return "apikey";
        }
    }

    record OAuth2(String grantType, String accessTokenUrl, String refreshTokenUrl, String clientId, String clientSecret,
            String scope, String callbackUrl, String authorizationUrl, boolean pkce, String credPlacement,
            String tokenPlacement, boolean autoRefresh, boolean autoFetch,
            Map<String, String> additionalParams) implements AuthConfig {

        @Override
        public String mode() {
            return "oauth2";
        }
    }

    record AwsV4(String accessKeyId, String secretAccessKey, String sessionToken, String service,
            String region) implements AuthConfig {

        @Override
        public String mode() {
            return "awsv4";
        }
    }

    record OAuth1(String consumerKey, String consumerSecret, String accessToken, String tokenSecret,
            String signatureMethod, String placement) implements AuthConfig {

        @Override
        public String mode() {
            return "oauth1";
        }
    }

    record Wsse(String username, String password) implements AuthConfig {

        @Override
        public String mode() {
            return "wsse";
        }
    }

    record EdgeGrid(String accessToken, String clientToken, String clientSecret) implements AuthConfig {

        @Override
        public String mode() {
            return "akamai-edgegrid";
        }
    }
}
