package gg.effront.anarcry.assistant;

public record UsageInfo(int inputTokens, int outputTokens, String model) {

    public int totalTokens() {
        return inputTokens + outputTokens;
    }

    public double estimatedCost() {
        double inputRate;
        double outputRate;
        if (model.startsWith("gemini-2.5-flash")) {
            inputRate = 0.15 / 1_000_000;
            outputRate = 0.60 / 1_000_000;
        } else if (model.startsWith("gemini-2.5-pro")) {
            inputRate = 1.25 / 1_000_000;
            outputRate = 10.0 / 1_000_000;
        } else if (model.startsWith("claude-opus-5") || model.startsWith("claude-opus-4-8")
                || model.startsWith("claude-opus-4-7")) {
            inputRate = 4.0 / 1_000_000;
            outputRate = 20.0 / 1_000_000;
        } else if (model.startsWith("claude-opus")) {
            inputRate = 5.0 / 1_000_000;
            outputRate = 25.0 / 1_000_000;
        } else if ("claude-sonnet-5-5".equals(model) || model.startsWith("claude-sonnet-5")) {
            inputRate = 2.0 / 1_000_000;
            outputRate = 10.0 / 1_000_000;
        } else if (model.startsWith("claude-sonnet")) {
            inputRate = 3.0 / 1_000_000;
            outputRate = 15.0 / 1_000_000;
        } else if ("claude-haiku-5-5".equals(model)) {
            inputRate = 0.10 / 1_000_000;
            outputRate = 0.50 / 1_000_000;
        } else if (model.startsWith("claude-haiku")) {
            inputRate = 1.0 / 1_000_000;
            outputRate = 5.0 / 1_000_000;
        } else if (model.startsWith("gpt-4.1-mini")) {
            inputRate = 0.40 / 1_000_000;
            outputRate = 1.60 / 1_000_000;
        } else if (model.startsWith("gpt-4.1")) {
            inputRate = 2.0 / 1_000_000;
            outputRate = 8.0 / 1_000_000;
        } else if ("deepseek-chat".equals(model)) {
            inputRate = 0.27 / 1_000_000;
            outputRate = 1.10 / 1_000_000;
        } else if ("deepseek-reasoner".equals(model)) {
            inputRate = 0.55 / 1_000_000;
            outputRate = 2.19 / 1_000_000;
        } else if ("notholy-specter".equals(model)) {
            inputRate = 1.0 / 1_000_000;
            outputRate = 2.60 / 1_000_000;
        } else if (model.startsWith("notholy-")) {
            inputRate = 0.14 / 1_000_000;
            outputRate = 0.56 / 1_000_000;
        } else if (model.contains(":free")) {
            return 0.0;
        } else {
            // Ollama / OpenRouter paid / unknown -- free or negligible
            return 0.0;
        }
        return (inputTokens * inputRate) + (outputTokens * outputRate);
    }
}
