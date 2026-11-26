package gg.effront.anarcry.assistant.providers;

public final class OpenRouterProvider extends OpenAiProvider {

    private static final String API_URL = "https://openrouter.ai/api/v1/chat/completions";

    @Override
    public String id() {
        return "openrouter";
    }

    @Override
    protected String apiUrl() {
        return API_URL;
    }
}
