package gg.effront.anarcry.assistant;

import java.time.Instant;

public record ChatMessage(String role, String content, Instant timestamp, String toolCallId, String toolCallPayload) {

    public ChatMessage(String role, String content, Instant timestamp) {
        this(role, content, timestamp, null, null);
    }

    public static ChatMessage system(String content) {
        return new ChatMessage("system", content, Instant.now(), null, null);
    }

    public static ChatMessage user(String content) {
        return new ChatMessage("user", content, Instant.now(), null, null);
    }

    public static ChatMessage assistant(String content) {
        return new ChatMessage("assistant", content, Instant.now(), null, null);
    }

    public static ChatMessage assistantToolCall(String toolCallPayload) {
        return new ChatMessage("assistant", "", Instant.now(), null, toolCallPayload);
    }

    public static ChatMessage tool(String content) {
        return new ChatMessage("tool", content, Instant.now(), null, null);
    }

    public static ChatMessage toolResult(String content, String toolCallId) {
        return new ChatMessage("tool", content, Instant.now(), toolCallId, null);
    }
}
