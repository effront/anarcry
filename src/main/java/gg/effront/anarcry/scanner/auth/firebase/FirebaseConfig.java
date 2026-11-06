package gg.effront.anarcry.scanner.auth.firebase;

public record FirebaseConfig(String apiKey, String authDomain, String projectId, String storageBucket,
        String messagingSenderId, String appId, String identityToolkitBaseUrl, String secureTokenBaseUrl) {

    private static final String DEFAULT_IDENTITY_URL = "https://identitytoolkit.googleapis.com/v1";
    private static final String DEFAULT_TOKEN_URL = "https://securetoken.googleapis.com/v1";

    public FirebaseConfig(String apiKey, String authDomain, String projectId, String storageBucket,
            String messagingSenderId, String appId) {
        this(apiKey, authDomain, projectId, storageBucket, messagingSenderId, appId, DEFAULT_IDENTITY_URL,
                DEFAULT_TOKEN_URL);
    }

    public String identityToolkitUrl() {
        return identityToolkitBaseUrl;
    }

    public String secureTokenUrl() {
        return secureTokenBaseUrl;
    }
}
