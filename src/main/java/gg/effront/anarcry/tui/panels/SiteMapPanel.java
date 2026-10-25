package gg.effront.anarcry.tui.panels;

import com.googlecode.lanterna.TextColor;
import com.googlecode.lanterna.gui2.ActionListBox;
import com.googlecode.lanterna.gui2.Direction;
import com.googlecode.lanterna.gui2.Label;
import com.googlecode.lanterna.gui2.LinearLayout;
import com.googlecode.lanterna.gui2.Panel;
import gg.effront.anarcry.model.RequestRecord;

import java.net.URI;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class SiteMapPanel extends Panel {

    private final ActionListBox listBox;
    private final Label counter;
    private final List<RequestRecord> records = new ArrayList<>();

    public SiteMapPanel(int listHeight) {
        super(new LinearLayout(Direction.VERTICAL));

        counter = new Label("  0 requisições | 0 hosts ");
        counter.setForegroundColor(TextColor.ANSI.BLUE);
        addComponent(counter);

        listBox = new ActionListBox(new com.googlecode.lanterna.TerminalSize(0, Math.max(4, listHeight)));
        addComponent(listBox, LinearLayout.createLayoutData(LinearLayout.Alignment.Fill));

        Label hint = new Label("  Método  URL                                      Cód  Tam     Módulo");
        hint.setForegroundColor(TextColor.ANSI.WHITE);
        addComponent(hint);
    }

    public synchronized void addRecord(RequestRecord r) {
        records.add(r);
        rebuild();
    }

    public synchronized void clear() {
        records.clear();
        rebuild();
    }

    private void rebuild() {
        listBox.clearItems();

        Map<String, List<RequestRecord>> byHost = new LinkedHashMap<>();
        for (RequestRecord r : records) {
            String host = extractHost(r.url());
            byHost.computeIfAbsent(host, k -> new ArrayList<>()).add(r);
        }

        for (Map.Entry<String, List<RequestRecord>> entry : byHost.entrySet()) {
            String host = entry.getKey();
            List<RequestRecord> hostRecords = entry.getValue();
            listBox.addItem("  ─ " + host + " (" + hostRecords.size() + ")", () -> {
            });
            for (RequestRecord r : hostRecords) {
                String path = extractPath(r.url());
                String label = String.format("    %-6s %-38s %3d  %-6s  %s", r.method(), truncate(path, 38),
                        r.statusCode(), humanSize(r.responseBodySize()), r.moduleId());
                listBox.addItem(label, () -> {
                });
            }
        }

        counter.setText(String.format("  %d requisições | %d hosts ", records.size(), byHost.size()));
    }

    private static String extractHost(String url) {
        try {
            return URI.create(url).getHost();
        } catch (Exception e) {
            return url;
        }
    }

    private static String extractPath(String url) {
        try {
            URI uri = URI.create(url);
            String path = uri.getPath();
            String query = uri.getQuery();
            return (path == null ? "/" : path) + (query != null ? "?" + query : "");
        } catch (Exception e) {
            return url;
        }
    }

    private static String truncate(String s, int max) {
        if (s == null) {
            return "";
        }
        return s.length() <= max ? s : s.substring(0, max - 1) + "…";
    }

    private static String humanSize(long bytes) {
        if (bytes <= 0) {
            return "—";
        }
        if (bytes < 1024) {
            return bytes + "B";
        }
        return (bytes / 1024) + "KB";
    }
}
