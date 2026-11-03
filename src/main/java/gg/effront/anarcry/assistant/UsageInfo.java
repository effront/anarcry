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
        } else if (model.startsWith("claude-sonnet")) {
            inputRate = 3.0 / 1_000_000;
            outputRate = 15.0 / 1_000_000;
        } else if (model.startsWith("claude-haiku")) {
            inputRate = 0.25 / 1_000_000;
            outputRate = 1.25 / 1_000_000;
        } else if (model.startsWith("gpt-4.1-mini")) {
            inputRate = 0.40 / 1_000_000;
            outputRate = 1.60 / 1_000_000;
        } else if (model.startsWith("gpt-4.1")) {
            inputRate = 2.0 / 1_000_000;
            outputRate = 8.0 / 1_000_000;
        } else {
            // Ollama / unknown -- free or negligible
            return 0.0;
        }
        return (inputTokens * inputRate) + (outputTokens * outputRate);
    }
}
