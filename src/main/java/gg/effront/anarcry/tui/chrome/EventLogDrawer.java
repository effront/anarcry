package gg.effront.anarcry.tui.chrome;

import com.googlecode.lanterna.TextColor;
import com.googlecode.lanterna.gui2.ActionListBox;
import com.googlecode.lanterna.gui2.BasicWindow;
import com.googlecode.lanterna.gui2.Borders;
import com.googlecode.lanterna.gui2.Direction;
import com.googlecode.lanterna.gui2.Label;
import com.googlecode.lanterna.gui2.LinearLayout;
import com.googlecode.lanterna.gui2.MultiWindowTextGUI;
import com.googlecode.lanterna.gui2.Panel;
import com.googlecode.lanterna.gui2.Window;
import com.googlecode.lanterna.gui2.WindowListenerAdapter;
import com.googlecode.lanterna.input.KeyStroke;
import com.googlecode.lanterna.input.KeyType;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

public class EventLogDrawer {

    private static final String F_ALL = "all";
    private static final String F_WARN = "warn";
    private static final String F_OK = "ok";

    public static void show(MultiWindowTextGUI gui, List<String> logHistory) {
        var dialog = new BasicWindow();
        dialog.setHints(Set.of(Window.Hint.CENTERED, Window.Hint.MODAL, Window.Hint.FIT_TERMINAL_WINDOW));

        AtomicReference<String> activeFilter = new AtomicReference<>(F_ALL);

        var panel = new Panel(new LinearLayout(Direction.VERTICAL));

        // filter bar
        Label filterLabel = new Label("");
        filterLabel.setForegroundColor(TextColor.ANSI.BLACK);
        filterLabel.setBackgroundColor(TextColor.ANSI.WHITE_BRIGHT);
        panel.addComponent(filterLabel);

        // log list -- height bounded so it doesn't overflow the terminal
        int termH = gui.getScreen().getTerminalSize().getRows();
        ActionListBox listBox = new ActionListBox(new com.googlecode.lanterna.TerminalSize(0, Math.max(5, termH - 6)));
        panel.addComponent(listBox, LinearLayout.createLayoutData(LinearLayout.Alignment.Fill));

        // hint bar
        Label hint = new Label(" [1] Todos  [2] Avisos [!]  [3] Sucessos [+]  [Esc/F8] Fechar ");
        hint.setForegroundColor(TextColor.ANSI.WHITE);
        panel.addComponent(hint);

        dialog.setComponent(panel.withBorder(Borders.singleLine("F8 Log")));

        // initial fill
        rebuild(listBox, filterLabel, logHistory, F_ALL);

        dialog.addWindowListener(new WindowListenerAdapter() {
            @Override
            public void onInput(Window w, KeyStroke ks, AtomicBoolean deliver) {
                KeyType kt = ks.getKeyType();
                if (kt == KeyType.Escape || kt == KeyType.F8) {
                    dialog.close();
                    deliver.set(false);
                    return;
                }
                if (kt == KeyType.Character) {
                    char ch = ks.getCharacter();
                    if (ch == '1') {
                        rebuild(listBox, filterLabel, logHistory, F_ALL);
                        deliver.set(false);
                    }
                    if (ch == '2') {
                        rebuild(listBox, filterLabel, logHistory, F_WARN);
                        deliver.set(false);
                    }
                    if (ch == '3') {
                        rebuild(listBox, filterLabel, logHistory, F_OK);
                        deliver.set(false);
                    }
                }
            }
        });

        gui.addWindow(dialog);
        gui.setActiveWindow(dialog);
    }

    private static void rebuild(ActionListBox box, Label bar, List<String> src, String filter) {
        List<String> lines = applyFilter(src, filter);
        box.clearItems();
        for (String line : lines) {
            box.addItem(line, () -> {
            });
        }
        // scroll to last entry
        if (!lines.isEmpty()) {
            box.setSelectedIndex(lines.size() - 1);
        }
        bar.setText(buildBarText(filter, src.size(), lines.size()));
    }

    private static List<String> applyFilter(List<String> src, String filter) {
        synchronized (src) {
            return switch (filter) {
                case F_WARN -> src.stream().filter(l -> l.startsWith("[!]") || l.startsWith("[!!]")).toList();
                case F_OK -> src.stream().filter(l -> l.startsWith("[+]")).toList();
                default -> new ArrayList<>(src);
            };
        }
    }

    private static String buildBarText(String filter, int total, int shown) {
        String label = switch (filter) {
            case F_WARN -> "Avisos";
            case F_OK -> "Sucessos";
            default -> "Todos";
        };
        return String.format(" Filtro: %-9s %d/%d linhas ", label, shown, total);
    }
}
