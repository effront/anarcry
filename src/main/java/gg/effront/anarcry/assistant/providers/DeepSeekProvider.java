package gg.effront.anarcry.assistant.providers;

public final class DeepSeekProvider extends OpenAiProvider {

    private static final String API_URL = "https://api.deepseek.com/v1/chat/completions";

    @Override
    public String id() {
        return "deepseek";
    }

    @Override
    protected String apiUrl() {
        return API_URL;
    }
}
