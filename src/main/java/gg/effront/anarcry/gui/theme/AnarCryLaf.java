package gg.effront.anarcry.gui.theme;

import com.formdev.flatlaf.FlatDarkLaf;
import com.formdev.flatlaf.FlatIntelliJLaf;
import com.formdev.flatlaf.FlatLaf;

import java.awt.Color;
import java.awt.Dimension;
import java.awt.Insets;

import javax.swing.UIManager;

/** FlatLaf theme setup utility for the AnarCry GUI. */
public final class AnarCryLaf {

    // Burp-inspired palette
    static final Color BG = new Color(0x32, 0x33, 0x34);
    static final Color BG_DARK = new Color(0x2B, 0x2B, 0x2B);
    static final Color TOOL_BG = new Color(0x30, 0x31, 0x32);
    static final Color HEADING_BG = new Color(0x36, 0x38, 0x3A);
    static final Color ACCENT = new Color(0xD8, 0x66, 0x33);
    static final Color SELECTION = new Color(0x2C, 0x51, 0x75);
    static final Color BLUE = new Color(0x26, 0x64, 0x9D);
    static final Color FOCUS = new Color(0x3D, 0x61, 0x85);
    static final Color BORDER = new Color(0x60, 0x60, 0x60);
    static final Color HEADER_BG = new Color(0x3D, 0x3C, 0x3C);
    static final Color GRID = new Color(0x36, 0x36, 0x36);
    static final Color SEPARATOR = new Color(0x51, 0x51, 0x51);

    private AnarCryLaf() {
    }

    /** Installs the dark theme (FlatDarkLaf) with AnarCry UI customizations. */
    public static void install() {
        FlatDarkLaf.setup();
        applyDarkCustomizations();
    }

    /**
     * Installs the light theme (FlatIntelliJLaf) with AnarCry UI customizations.
     */
    public static void installLight() {
        FlatIntelliJLaf.setup();
        applySharedCustomizations();
    }

    /** Returns {@code true} if the current Look and Feel is a dark theme. */
    public static boolean isDark() {
        return FlatLaf.isLafDark();
    }

    /** Toggles between dark and light themes. */
    public static void toggle() {
        if (isDark()) {
            installLight();
        } else {
            install();
        }
    }

    private static void applyDarkCustomizations() {
        applySharedCustomizations();

        // TabbedPane -- orange underline like Burp, taller tabs
        UIManager.put("TabbedPane.underlineColor", ACCENT);
        UIManager.put("TabbedPane.selectedBackground", BG);
        UIManager.put("TabbedPane.hoverColor", HEADING_BG);
        UIManager.put("TabbedPane.focusColor", BG);
        UIManager.put("TabbedPane.tabHeight", 28);
        UIManager.put("TabbedPane.tabInsets", new Insets(2, 12, 4, 12));
        UIManager.put("TabbedPane.tabSelectionHeight", 2);
        UIManager.put("TabbedPane.showTabSeparators", false);
        UIManager.put("TabbedPane.contentSeparatorHeight", 1);

        // Table -- dark rows with alternation
        UIManager.put("Table.background", BG_DARK);
        UIManager.put("Table.alternateRowColor", BG);
        UIManager.put("Table.selectionBackground", SELECTION);
        UIManager.put("Table.gridColor", GRID);

        // TableHeader
        UIManager.put("TableHeader.background", HEADER_BG);
        UIManager.put("TableHeader.separatorColor", new Color(0x4D, 0x4D, 0x4D));
        UIManager.put("TableHeader.bottomSeparatorColor", new Color(0x4D, 0x4D, 0x4D));

        // CheckBox -- blue selected like Burp
        UIManager.put("CheckBox.icon.selectedBorderColor", BLUE);
        UIManager.put("CheckBox.icon.selectedBackground", BLUE);
        UIManager.put("CheckBox.icon.focusedBorderColor", BLUE);
        UIManager.put("CheckBox.icon.focusedSelectedBackground", BLUE);

        // Component borders
        UIManager.put("Component.borderColor", BORDER);
        UIManager.put("Component.focusedBorderColor", new Color(0x00, 0x66, 0xCC));
        UIManager.put("Component.focusColor", FOCUS);

        // ProgressBar -- orange like Burp
        UIManager.put("ProgressBar.foreground", ACCENT);
        UIManager.put("ProgressBar.arc", 999);

        // Buttons
        UIManager.put("Button.background", new Color(0x4C, 0x50, 0x52));

        // Separator
        UIManager.put("Separator.foreground", SEPARATOR);

        // MenuBar
        UIManager.put("MenuBar.borderColor", SEPARATOR);
        UIManager.put("PopupMenu.borderColor", new Color(0x5E, 0x5E, 0x5E));

        // Tooltip
        UIManager.put("ToolTip.background", new Color(0x1E, 0x21, 0x23));

        // Tree
        UIManager.put("Tree.hash", new Color(0x50, 0x53, 0x55));
        UIManager.put("Tree.selectionBackground", SELECTION);

        // SplitPane
        UIManager.put("SplitPaneDivider.draggingColor", new Color(0x64, 0x64, 0x64));
    }

    private static void applySharedCustomizations() {
        UIManager.put("Component.focusWidth", 1);
        UIManager.put("Component.arc", 8);
        UIManager.put("Button.arc", 8);
        UIManager.put("ScrollBar.thumbArc", 999);
        UIManager.put("ScrollBar.thumbInsets", new Insets(2, 2, 2, 2));
        UIManager.put("TitlePane.unifiedBackground", true);
        UIManager.put("Table.showHorizontalLines", true);
        UIManager.put("Table.showVerticalLines", true);
        UIManager.put("Table.intercellSpacing", new Dimension(0, 1));
    }
}
