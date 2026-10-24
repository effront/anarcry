package gg.effront.anarcry.tui.panels;

import com.googlecode.lanterna.TerminalSize;
import com.googlecode.lanterna.TextColor;
import com.googlecode.lanterna.gui2.*;
import gg.effront.anarcry.model.Finding;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.function.Consumer;

public class FindingsPanel extends Panel {

    private final ActionListBox      list;
    private final Label              hintLabel;
    private final Consumer<Finding>  onSelect;
    private final List<Finding>      sortedFindings = new ArrayList<>();
    private String                   severityFilter = null; // null = show all

    public FindingsPanel(int height, Consumer<Finding> onSelect) {
        super(new LinearLayout(Direction.VERTICAL));
        setPreferredSize(new TerminalSize(0, height));
        this.onSelect = onSelect;

        list = new ActionListBox();
        addComponent(list, LinearLayout.createLayoutData(LinearLayout.Alignment.Fill));
        hintLabel = new Label(buildHint());
        addComponent(hintLabel);
    }

    public void addFinding(Finding finding) {
        sortedFindings.add(finding);
        // CRITICAL first (ordinal 0) → INFO last (ordinal 4)
        sortedFindings.sort(Comparator.comparingInt(f -> f.severity().ordinal()));
        rebuildList();
    }

    public void setFilter(String filter) {
        this.severityFilter = filter;
        hintLabel.setText(buildHint());
        rebuildList();
    }

    private void rebuildList() {
        list.clearItems();
        for (Finding f : sortedFindings) {
            if (severityFilter != null && !f.severity().name().equals(severityFilter)) continue;
            String label = String.format("  %-8s  %-20s  %-12s  %s",
                    f.severity().name(), truncate(f.endpoint(), 20),
                    f.module().toUpperCase(), f.title());
            Finding captured = f;
            list.addItem(label, () -> onSelect.accept(captured));
        }
    }

    private String truncate(String s, int max) {
        if (s == null) return "";
        return s.length() <= max ? s : s.substring(0, max - 1) + "…";
    }

    private String buildHint() {
        String active = severityFilter != null ? severityFilter : "ALL";
        return " [Enter] Detalhes  [C] Curl  │ Filtro: [1]" + mark("ALL", active)
                + " [2]" + mark("CRITICAL", active)
                + " [3]" + mark("HIGH",     active)
                + " [4]" + mark("MEDIUM",   active)
                + " [5]" + mark("LOW",      active)
                + " [6]" + mark("INFO",     active);
    }

    private static String mark(String label, String active) {
        return label.equals(active) ? "*" + label + "*" : label;
    }
}
