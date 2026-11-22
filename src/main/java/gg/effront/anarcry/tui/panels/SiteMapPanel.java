package gg.effront.anarcry.tui.panels;

import com.googlecode.lanterna.TerminalSize;
import com.googlecode.lanterna.TextColor;
import com.googlecode.lanterna.gui2.ActionListBox;
import com.googlecode.lanterna.gui2.Borders;
import com.googlecode.lanterna.gui2.Direction;
import com.googlecode.lanterna.gui2.Label;
import com.googlecode.lanterna.gui2.LinearLayout;
import com.googlecode.lanterna.gui2.Panel;
import com.googlecode.lanterna.gui2.TextBox;
import gg.effront.anarcry.model.RequestRecord;

import java.net.URI;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class SiteMapPanel extends Panel {

    private final ActionListBox listBox;
    private final TextBox detailBox;
    private final Label counter;
    private final List<RequestRecord> records = new ArrayList<>();
    private final int listHeight;

    public SiteMapPanel(int listHeight) {
        super(new LinearLayout(Direction.HORIZONTAL));
        this.listHeight = Math.max(4, listHeight);

        Panel leftPanel = new Panel(new LinearLayout(Direction.VERTICAL));

        counter = new Label("  0 requests | 0 hosts ");
        counter.setForegroundColor(TextColor.ANSI.BLUE);
        leftPanel.addComponent(counter);

        listBox = new ActionListBox(new TerminalSize(72, this.listHeight));
        leftPanel.addComponent(listBox, LinearLayout.createLayoutData(LinearLayout.Alignment.Fill));

        Label hint = new Label("  Met  URL                                      Cod  Tam     Mod");
        hint.setForegroundColor(TextColor.ANSI.WHITE);
        leftPanel.addComponent(hint);

        addComponent(leftPanel.withBorder(Borders.singleLine("Tree")));

        detailBox = new TextBox(new TerminalSize(60, this.listHeight + 3), TextBox.Style.MULTI_LINE);
        detailBox.setReadOnly(true);
        detailBox.setText("Selecione uma requisicao na tree para ver o conteudo.");
        addComponent(detailBox.withBorder(Borders.singleLine("Response")));
    }

    public synchronized void addRecord(RequestRecord r) {
        records.add(r);
        rebuild();
    }

    public synchronized void clear() {
        records.clear();
        detailBox.setText("");
        rebuild();
    }

    private void rebuild() {
        listBox.clearItems();

        Map<String, List<RequestRecord>> byHost = new LinkedHashMap<>();
        for (RequestRecord r : records) {
            if (r.statusCode() >= 400) {
                continue;
            }
            String host = extractHost(r.url());
            byHost.computeIfAbsent(host, k -> new ArrayList<>()).add(r);
        }

        for (Map.Entry<String, List<RequestRecord>> entry : byHost.entrySet()) {
            String host = entry.getKey();
            List<RequestRecord> hostRecords = entry.getValue();
            listBox.addItem("-- " + host + " (" + hostRecords.size() + ")", () -> {
            });
            for (RequestRecord r : hostRecords) {
                String path = extractPath(r.url());
                String label = String.format("  %-5s %-36s %3d  %-6s  %s", r.method(), truncate(path, 36),
                        r.statusCode(), humanSize(r.responseBodySize()), r.moduleId());
                listBox.addItem(label, () -> showDetail(r));
            }
        }

        counter.setText(String.format("  %d requests | %d hosts ", records.size(), byHost.size()));
    }

    private void showDetail(RequestRecord r) {
        StringBuilder sb = new StringBuilder();
        sb.append(r.method()).append(" ").append(r.url()).append("\n");
        sb.append("Status: ").append(r.statusCode()).append("  Size: ").append(humanSize(r.responseBodySize()));
        sb.append("  Module: ").append(r.moduleId()).append("\n");
        sb.append("\n");

        if (!r.responseHeaders().isEmpty()) {
            sb.append("--- Response Headers ---\n");
            for (var entry : r.responseHeaders().entrySet()) {
                sb.append(entry.getKey()).append(": ").append(entry.getValue()).append("\n");
            }
            sb.append("\n");
        }

        if (r.hasBody()) {
            sb.append("--- Response Body ---\n");
            sb.append(r.responseBodySnippet());
            if (r.responseBodySize() > r.responseBodySnippet().length()) {
                sb.append("\n\n[truncated -- ").append(humanSize(r.responseBodySize())).append(" total]");
            }
        } else {
            sb.append("[sem body capturado]");
        }

        detailBox.setText(sb.toString());
        detailBox.setCaretPosition(0, 0);
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
        return s.length() <= max ? s : s.substring(0, max - 1) + "~";
    }

    private static String humanSize(long bytes) {
        if (bytes <= 0) {
            return "--";
        }
        if (bytes < 1024) {
            return bytes + "B";
        }
        return (bytes / 1024) + "KB";
    }
}
