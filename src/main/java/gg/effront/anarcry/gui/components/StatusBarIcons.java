package gg.effront.anarcry.gui.components;

import java.net.URL;

import javax.swing.Icon;
import javax.swing.ImageIcon;

public final class StatusBarIcons {

    private StatusBarIcons() {
    }

    public static Icon settings() {
        return load("settings.png");
    }

    public static Icon palette() {
        return load("palette.png");
    }

    public static Icon github() {
        return load("brand-github.png");
    }

    public static Icon search() {
        return load("search.png");
    }

    public static Icon cookie() {
        return load("cookie.png");
    }

    public static Icon keyboard() {
        return load("keyboard.png");
    }

    public static Icon license() {
        return load("license.png");
    }

    public static Icon proxy() {
        return load("arrows-right-left.png");
    }

    public static Icon privacy() {
        return load("shield-lock.png");
    }

    private static Icon load(String name) {
        URL url = StatusBarIcons.class.getResource("/icons/" + name);
        if (url != null) {
            return new ImageIcon(url);
        }
        return new ImageIcon();
    }
}
