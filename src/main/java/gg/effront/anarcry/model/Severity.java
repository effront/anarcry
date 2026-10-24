package gg.effront.anarcry.model;

import com.googlecode.lanterna.TextColor;

public enum Severity {
    CRITICAL(TextColor.ANSI.RED_BRIGHT),
    HIGH(TextColor.ANSI.YELLOW_BRIGHT),
    MEDIUM(TextColor.ANSI.YELLOW),
    LOW(TextColor.ANSI.CYAN),
    INFO(TextColor.ANSI.WHITE);

    public final TextColor color;

    Severity(TextColor color) {
        this.color = color;
    }
}
