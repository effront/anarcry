package gg.effront.anarcry.tui.chrome;

import com.googlecode.lanterna.TextColor;
import com.googlecode.lanterna.gui2.*;
import gg.effront.anarcry.tui.modes.Mode;

public class ModeBar extends Panel {

    private static final Mode[]   MODES = Mode.values();
    private static final String[] KEYS  = {"F1","F2","F3","F4","F5","F6","F7"};
    private static final String[] NAMES = {"Dashboard","Scan","Target","Findings","Repeater","Relatório","Site Map"};

    private final Label[] tabs = new Label[7];

    private Mode    activeMode    = Mode.SCAN;
    private boolean scanning      = false;
    private int     findingsCount = 0;

    public ModeBar() {
        super(new LinearLayout(Direction.HORIZONTAL));
        for (int i = 0; i < 7; i++) {
            tabs[i] = new Label(" ");
            addComponent(tabs[i]);
        }
        refresh();
    }

    public void setMode(Mode mode) {
        this.activeMode = mode;
        refresh();
    }

    public void setScanning(boolean scanning) {
        this.scanning = scanning;
        refresh();
    }

    public void setFindingsCount(int count) {
        this.findingsCount = count;
        refresh();
    }

    private void refresh() {
        for (int i = 0; i < MODES.length; i++) {
            Mode m = MODES[i];
            tabs[i].setText(buildTabText(i, m));
            if (m == activeMode) {
                tabs[i].setForegroundColor(TextColor.ANSI.BLACK);
                tabs[i].setBackgroundColor(TextColor.ANSI.YELLOW_BRIGHT);
            } else {
                tabs[i].setForegroundColor(TextColor.ANSI.RED_BRIGHT);
                tabs[i].setBackgroundColor(TextColor.ANSI.BLACK);
            }
        }
    }

    private String buildTabText(int idx, Mode mode) {
        String badge = "";
        if (mode == Mode.SCAN && scanning) {
            badge = " ▶";
        } else if (mode == Mode.FINDINGS && findingsCount > 0) {
            badge = "(" + findingsCount + ")";
        }
        return " " + KEYS[idx] + " " + NAMES[idx] + badge + " ";
    }
}
