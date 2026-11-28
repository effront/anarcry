package gg.effront.anarcry.artex;

/**
 * Represents a single Server-Sent Event parsed from the ARTEX activity stream.
 * Fields follow the SSE specification: event type, JSON data payload, and
 * optional event id.
 */
public record SseEvent(String eventType, String data, String id) {

    /** Default event type per SSE spec when no "event:" field is present. */
    private static final String DEFAULT_EVENT = "message";

    /**
     * Parses a complete SSE block (accumulated lines between blank-line delimiters)
     * into an SseEvent. Returns null if no data field was present in the block.
     *
     * @param block
     *            concatenated lines of a single SSE event (separated by newlines)
     * @return parsed SseEvent or null if the block contains no data
     */
    public static SseEvent parse(String block) {
        if (block == null || block.isBlank()) {
            return null;
        }

        String eventType = DEFAULT_EVENT;
        StringBuilder dataBuilder = new StringBuilder();
        String id = "";
        boolean hasData = false;

        for (String line : block.split("\n")) {
            if (line.startsWith(":")) {
                // Comment line -- ignored per SSE spec
                continue;
            }

            int colonIdx = line.indexOf(':');
            String field;
            String value;
            if (colonIdx >= 0) {
                field = line.substring(0, colonIdx);
                // Per SSE spec: if the character after colon is a space, skip it
                value = (colonIdx + 1 < line.length() && line.charAt(colonIdx + 1) == ' ')
                        ? line.substring(colonIdx + 2)
                        : line.substring(colonIdx + 1);
            } else {
                field = line;
                value = "";
            }

            switch (field) {
                case "event" -> eventType = value;
                case "data" -> {
                    if (hasData) {
                        dataBuilder.append('\n');
                    }
                    dataBuilder.append(value);
                    hasData = true;
                }
                case "id" -> id = value;
                case "retry" -> {
                    // retry field is handled by SseActivityListener, not stored in the event
                }
                default -> {
                    // Unknown fields are ignored per SSE spec
                }
            }
        }

        if (!hasData) {
            return null;
        }

        return new SseEvent(eventType, dataBuilder.toString(), id);
    }

    /**
     * Returns the retry interval in milliseconds if present in the block, or -1 if
     * absent.
     */
    public static long parseRetry(String block) {
        if (block == null || block.isBlank()) {
            return -1;
        }
        for (String line : block.split("\n")) {
            if (line.startsWith("retry:")) {
                String value = line.substring(6).trim();
                try {
                    return Long.parseLong(value);
                } catch (NumberFormatException e) {
                    return -1;
                }
            }
        }
        return -1;
    }
}
