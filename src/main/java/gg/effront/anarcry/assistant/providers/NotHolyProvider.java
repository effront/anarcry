package gg.effront.anarcry.assistant.providers;

public final class NotHolyProvider extends OpenAiProvider {

    private static final String API_URL = "https://api.notholy.com/v1/chat/completions";

    @Override
    public String id() {
        return "notholy";
    }

    @Override
    protected String apiUrl() {
        return API_URL;
    }
}
