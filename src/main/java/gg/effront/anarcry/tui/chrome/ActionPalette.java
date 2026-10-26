package gg.effront.anarcry.tui.chrome;

import com.googlecode.lanterna.TextColor;
import com.googlecode.lanterna.gui2.BasicWindow;
import com.googlecode.lanterna.gui2.Borders;
import com.googlecode.lanterna.gui2.Button;
import com.googlecode.lanterna.gui2.EmptySpace;
import com.googlecode.lanterna.gui2.GridLayout;
import com.googlecode.lanterna.gui2.Label;
import com.googlecode.lanterna.gui2.Panel;
import com.googlecode.lanterna.gui2.Window;
import com.googlecode.lanterna.gui2.WindowBasedTextGUI;

import java.util.List;
import java.util.Set;

public class ActionPalette {

    private static final List<String[]> ACTIONS = List.of(new String[]{"F1", "SCAN mode — modules and log"},
            new String[]{"F2", "FINDINGS mode — findings table"},
            new String[]{"F3", "DASHBOARD mode — session summary"},
            new String[]{"F4", "REPEATER mode — request/response"}, new String[]{"F5", "NOTES mode — scratchpad"},
            new String[]{"F6", "REPORT mode — export panel"},
            new String[]{"E", "Export menu (AnarCry / H1 / Bugcrowd / JSON)"},
            new String[]{"?", "Open this action palette"}, new String[]{"q", "Quit application"});

    public static void show(WindowBasedTextGUI gui) {
        BasicWindow dialog = new BasicWindow("Ações — AnarCry");
        dialog.setHints(Set.of(Window.Hint.CENTERED, Window.Hint.MODAL));

        Panel panel = new Panel(new GridLayout(2));
        GridLayout gl = (GridLayout) panel.getLayoutManager();
        gl.setHorizontalSpacing(3);

        for (String[] row : ACTIONS) {
            panel.addComponent(new Label(row[0]).setForegroundColor(TextColor.ANSI.YELLOW));
            panel.addComponent(new Label(row[1]));
        }

        panel.addComponent(new EmptySpace());
        panel.addComponent(new Button("Close", dialog::close)
                .setLayoutData(GridLayout.createLayoutData(GridLayout.Alignment.END, GridLayout.Alignment.CENTER)));

        dialog.setComponent(panel.withBorder(Borders.singleLine()));
        gui.addWindowAndWait(dialog);
    }
}
