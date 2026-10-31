package gg.effront.anarcry.model;

public enum AuthType {
    NONE, JWT, COOKIE, BEARER;

    public boolean usesBearer() {
        return this == JWT || this == BEARER;
    }

    public boolean usesCookie() {
        return this == COOKIE;
    }

    public boolean requiresJwtParsing() {
        return this == JWT;
    }

    public boolean hasAuth() {
        return this != NONE;
    }
}
