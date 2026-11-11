package gg.effront.anarcry.apiclient.model;

public record ScriptDef(String preRequest, String postResponse, String tests) {

    public ScriptDef {
        if (preRequest == null) {
            preRequest = "";
        }
        if (postResponse == null) {
            postResponse = "";
        }
        if (tests == null) {
            tests = "";
        }
    }

    public static ScriptDef empty() {
        return new ScriptDef("", "", "");
    }

    public boolean hasPreRequest() {
        return !preRequest.isBlank();
    }

    public boolean hasPostResponse() {
        return !postResponse.isBlank();
    }

    public boolean hasTests() {
        return !tests.isBlank();
    }

    public boolean isEmpty() {
        return !hasPreRequest() && !hasPostResponse() && !hasTests();
    }
}
