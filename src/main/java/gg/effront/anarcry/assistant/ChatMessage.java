package gg.effront.anarcry.assistant;

import java.time.Instant;

public record ChatMessage(String role, String content, Instant timestamp) {

    public static ChatMessage system(String content) {
        return new ChatMessage("system", content, Instant.now());
    }

    public static ChatMessage user(String content) {
        return new ChatMessage("user", content, Instant.now());
    }

    public static ChatMessage assistant(String content) {
        return new ChatMessage("assistant", content, Instant.now());
    }

    public static ChatMessage tool(String content) {
        return new ChatMessage("tool", content, Instant.now());
    }
}
