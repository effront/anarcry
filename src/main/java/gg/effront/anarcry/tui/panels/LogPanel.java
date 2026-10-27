package gg.effront.anarcry.tui.panels;

import com.googlecode.lanterna.TextColor;
import com.googlecode.lanterna.gui2.Direction;
import com.googlecode.lanterna.gui2.Label;
import com.googlecode.lanterna.gui2.LinearLayout;
import com.googlecode.lanterna.gui2.Panel;

import java.util.ArrayList;
import java.util.List;

public class LogPanel extends Panel {

    private static final int MAX_LINES = 500;

    private final int height;
    private final Panel linesPanel;
    private final List<ColoredLine> lines = new ArrayList<>();
    private int viewStart = 0;

    private record ColoredLine(String text, TextColor color) {
    }

    public LogPanel(int height) {
        super(new LinearLayout(Direction.VERTICAL));
        this.height = height;
        this.linesPanel = new Panel(new LinearLayout(Direction.VERTICAL));
        addComponent(linesPanel, LinearLayout.createLayoutData(LinearLayout.Alignment.Fill));
    }

    public synchronized void log(String message) {
        boolean wasAtBottom = isAtBottom();
        lines.add(new ColoredLine(message, colorFor(message)));
        if (lines.size() > MAX_LINES) {
            lines.remove(0);
            viewStart = Math.max(0, viewStart - 1);
        }
        if (wasAtBottom) {
            viewStart = Math.max(0, lines.size() - height);
        }
        repaint();
    }

    public synchronized void scrollUp(int n) {
        viewStart = Math.max(0, viewStart - n);
        repaint();
    }

    public synchronized void scrollDown(int n) {
        viewStart = Math.min(Math.max(0, lines.size() - height), viewStart + n);
        repaint();
    }

    private boolean isAtBottom() {
        return viewStart >= Math.max(0, lines.size() - height);
    }

    private void repaint() {
        linesPanel.removeAllComponents();
        int end = Math.min(lines.size(), viewStart + height);
        for (int i = viewStart; i < end; i++) {
            ColoredLine cl = lines.get(i);
            Label lbl = new Label(cl.text());
            lbl.setForegroundColor(cl.color());
            linesPanel.addComponent(lbl);
        }
        linesPanel.invalidate();
        invalidate();
    }

    private static TextColor colorFor(String msg) {
        if (msg.startsWith("[!!]")) {
            return TextColor.ANSI.RED;
        }
        if (msg.startsWith("[!]")) {
            return TextColor.ANSI.YELLOW;
        }
        if (msg.startsWith("[+]")) {
            return TextColor.ANSI.GREEN;
        }
        if (msg.startsWith("[*]") || msg.startsWith("[~]")) {
            return TextColor.ANSI.BLUE;
        }
        return TextColor.ANSI.WHITE;
    }
}
