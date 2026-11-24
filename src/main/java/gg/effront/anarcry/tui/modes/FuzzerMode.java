package gg.effront.anarcry.tui.modes;

import com.googlecode.lanterna.TerminalSize;
import com.googlecode.lanterna.TextColor;
import com.googlecode.lanterna.gui2.ActionListBox;
import com.googlecode.lanterna.gui2.BorderLayout;
import com.googlecode.lanterna.gui2.Borders;
import com.googlecode.lanterna.gui2.Button;
import com.googlecode.lanterna.gui2.ComboBox;
import com.googlecode.lanterna.gui2.Component;
import com.googlecode.lanterna.gui2.Direction;
import com.googlecode.lanterna.gui2.Label;
import com.googlecode.lanterna.gui2.LinearLayout;
import com.googlecode.lanterna.gui2.MultiWindowTextGUI;
import com.googlecode.lanterna.gui2.Panel;
import com.googlecode.lanterna.gui2.TextBox;
import gg.effront.anarcry.fuzzer.AttackType;
import gg.effront.anarcry.fuzzer.FuzzEngine;
import gg.effront.anarcry.fuzzer.FuzzPosition;
import gg.effront.anarcry.fuzzer.FuzzResult;
import gg.effront.anarcry.fuzzer.InlinePayloadSource;
import gg.effront.anarcry.fuzzer.PayloadSource;
import gg.effront.anarcry.tui.PasteableTextBox;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public final class FuzzerMode {

    private static final int MAX_RESULTS = 10_000;

    private final FuzzEngine engine = new FuzzEngine();

    // -- UI components --
    private PasteableTextBox templateBox;
    private PasteableTextBox payloadBox;
    private ComboBox<String> attackTypeCombo;
    private PasteableTextBox threadsBox;
    private PasteableTextBox delayBox;
    private ActionListBox resultsList;
    private Label statusLabel;
    private Label positionLabel;
    private Button startButton;
    private Button pauseButton;
    private Button stopButton;

    // -- State --
    private final List<FuzzResult> allResults = Collections.synchronizedList(new ArrayList<>());
    private MultiWindowTextGUI gui;

    public Component build(MultiWindowTextGUI textGui) {
        this.gui = textGui;
        var root = new Panel(new BorderLayout());

        // -- TOP: config + template + payloads --
        var topPanel = new Panel(new BorderLayout());
        topPanel.addComponent(buildConfigBar(), BorderLayout.Location.TOP);

        var editorPanel = new Panel(new BorderLayout());
        editorPanel.addComponent(buildTemplatePanel(), BorderLayout.Location.CENTER);
        editorPanel.addComponent(buildPayloadPanel(), BorderLayout.Location.RIGHT);
        topPanel.addComponent(editorPanel, BorderLayout.Location.CENTER);

        topPanel.addComponent(buildControlBar(), BorderLayout.Location.BOTTOM);

        root.addComponent(topPanel, BorderLayout.Location.TOP);

        // -- BOTTOM: results list + status --
        var bottomPanel = new Panel(new BorderLayout());
        bottomPanel.addComponent(buildResultsPanel(), BorderLayout.Location.CENTER);

        statusLabel = new Label("  Ready");
        statusLabel.setForegroundColor(TextColor.ANSI.WHITE);
        bottomPanel.addComponent(statusLabel, BorderLayout.Location.BOTTOM);

        root.addComponent(bottomPanel, BorderLayout.Location.CENTER);

        return root;
    }

    private Component buildConfigBar() {
        var bar = new Panel(new LinearLayout(Direction.HORIZONTAL));

        Label attackLabel = new Label("  Attack:");
        attackLabel.setForegroundColor(TextColor.ANSI.BLUE);
        bar.addComponent(attackLabel);

        attackTypeCombo = new ComboBox<>();
        for (AttackType type : AttackType.values()) {
            attackTypeCombo.addItem(type.label());
        }
        attackTypeCombo.setSelectedIndex(0);
        bar.addComponent(attackTypeCombo);

        bar.addComponent(new Label("  "));

        Label threadsLabel = new Label("Threads:");
        threadsLabel.setForegroundColor(TextColor.ANSI.BLUE);
        bar.addComponent(threadsLabel);
        threadsBox = new PasteableTextBox(new TerminalSize(4, 1));
        threadsBox.setText("10");
        bar.addComponent(threadsBox);

        bar.addComponent(new Label("  "));

        Label delayLabel = new Label("Delay(ms):");
        delayLabel.setForegroundColor(TextColor.ANSI.BLUE);
        bar.addComponent(delayLabel);
        delayBox = new PasteableTextBox(new TerminalSize(5, 1));
        delayBox.setText("0");
        bar.addComponent(delayBox);

        bar.addComponent(new Label("  "));

        positionLabel = new Label("0 positions");
        positionLabel.setForegroundColor(TextColor.ANSI.WHITE);
        bar.addComponent(positionLabel);

        return bar;
    }

    private Component buildTemplatePanel() {
        var panel = new Panel(new LinearLayout(Direction.VERTICAL));

        templateBox = new PasteableTextBox(new TerminalSize(50, 10), TextBox.Style.MULTI_LINE);
        templateBox.setText("GET /path?param={{1}} HTTP/1.1\nHost: target.com\nUser-Agent: AnarCry\nAccept: */*");
        panel.addComponent(templateBox, LinearLayout.createLayoutData(LinearLayout.Alignment.Fill));

        return panel.withBorder(Borders.singleLine("Template (use {{N}} markers)"));
    }

    private Component buildPayloadPanel() {
        var panel = new Panel(new LinearLayout(Direction.VERTICAL));

        payloadBox = new PasteableTextBox(new TerminalSize(28, 10), TextBox.Style.MULTI_LINE);
        payloadBox.setText("admin\ntest\nroot\n' OR 1=1--\n<script>alert(1)</script>");
        panel.addComponent(payloadBox, LinearLayout.createLayoutData(LinearLayout.Alignment.Fill));

        return panel.withBorder(Borders.singleLine("Payloads (one per line)"));
    }

    private Component buildControlBar() {
        var bar = new Panel(new LinearLayout(Direction.HORIZONTAL));

        bar.addComponent(new Label("  "));

        startButton = new Button("Start Attack", this::startAttack);
        bar.addComponent(startButton);

        bar.addComponent(new Label(" "));

        pauseButton = new Button("Pause", this::togglePause);
        bar.addComponent(pauseButton);

        bar.addComponent(new Label(" "));

        stopButton = new Button("Stop", this::stopAttack);
        bar.addComponent(stopButton);

        bar.addComponent(new Label("  "));

        Label hint = new Label("Ctrl+Enter: start  |  Esc: stop");
        hint.setForegroundColor(TextColor.ANSI.WHITE);
        bar.addComponent(hint);

        return bar;
    }

    private Component buildResultsPanel() {
        var panel = new Panel(new LinearLayout(Direction.VERTICAL));

        Label header = new Label(formatResultHeader());
        header.setForegroundColor(TextColor.ANSI.BLUE);
        panel.addComponent(header);

        resultsList = new ActionListBox(new TerminalSize(0, 12));
        panel.addComponent(resultsList, LinearLayout.createLayoutData(LinearLayout.Alignment.Fill));

        return panel.withBorder(Borders.singleLine("Results"));
    }

    private static String formatResultHeader() {
        return String.format("  %-6s %-30s %-8s %-10s %-10s %s", "#", "Payload", "Status", "Length", "Time(ms)",
                "Error");
    }

    private static String formatResultRow(FuzzResult r) {
        String payload = r.payloadSummary();
        if (payload.length() > 28) {
            payload = payload.substring(0, 26) + "..";
        }
        String error = r.hasError() ? r.error() : "";
        if (error.length() > 30) {
            error = error.substring(0, 28) + "..";
        }
        return String.format("  %-6d %-30s %-8d %-10d %-10d %s", r.requestNum(), payload, r.statusCode(), r.length(),
                r.timeMs(), error);
    }

    // -- Attack control --

    private void startAttack() {
        if (engine.isRunning()) {
            return;
        }

        String template = templateBox.getText();
        var positions = FuzzPosition.parse(template);
        if (positions.isEmpty()) {
            updateStatus("[!] No positions marked. Use {{1}}, {{2}} etc.");
            return;
        }

        String payloadText = payloadBox.getText();
        if (payloadText == null || payloadText.isBlank()) {
            updateStatus("[!] No payloads configured.");
            return;
        }

        List<PayloadSource> sources = new ArrayList<>();
        sources.add(new InlinePayloadSource(payloadText));

        AttackType attackType = AttackType.values()[attackTypeCombo.getSelectedIndex()];
        int threads = parseIntSafe(threadsBox.getText(), 10);
        int delay = parseIntSafe(delayBox.getText(), 0);

        int posCount = FuzzPosition.maxIndex(positions);
        long est = attackType.estimateRequests(posCount, sources);

        // Clear previous results
        allResults.clear();
        if (gui != null) {
            gui.getGUIThread().invokeLater(() -> resultsList.clearItems());
        }

        FuzzEngine.FuzzConfig config = new FuzzEngine.FuzzConfig(template, attackType, sources, List.of(), threads,
                delay, 0, 30, null, null, null, null, 0);

        updateStatus("Starting -- ~" + String.format("%,d", est) + " requests...");

        engine.start(config, new FuzzEngine.FuzzListener() {
            @Override
            public void onResult(FuzzResult result) {
                if (gui == null) {
                    return;
                }
                gui.getGUIThread().invokeLater(() -> {
                    if (allResults.size() < MAX_RESULTS) {
                        allResults.add(result);
                        resultsList.addItem(formatResultRow(result), () -> {
                        });
                    }
                });
            }

            @Override
            public void onProgress(int completed, long total) {
                if (gui == null) {
                    return;
                }
                gui.getGUIThread().invokeLater(() -> {
                    int pct = total > 0 ? (int) (completed * 100 / total) : 0;
                    updateStatus(String.format("  %,d / %,d (%d%%)  |  %d results", completed, total, pct,
                            allResults.size()));
                });
            }

            @Override
            public void onComplete(int totalCompleted, long elapsedMs) {
                if (gui == null) {
                    return;
                }
                gui.getGUIThread().invokeLater(() -> {
                    double secs = elapsedMs / 1000.0;
                    double rps = secs > 0 ? totalCompleted / secs : 0;
                    updateStatus(String.format("  Done: %,d requests in %.1fs (%.1f req/s)  |  %d results",
                            totalCompleted, secs, rps, allResults.size()));
                });
            }

            @Override
            public void onError(String message) {
                if (gui == null) {
                    return;
                }
                gui.getGUIThread().invokeLater(() -> updateStatus("  [!] Error: " + message));
            }
        });
    }

    private void togglePause() {
        if (!engine.isRunning()) {
            return;
        }
        if (engine.isPaused()) {
            engine.resume();
            updateStatus("  Resumed");
        } else {
            engine.pause();
            updateStatus("  Paused");
        }
    }

    private void stopAttack() {
        if (engine.isRunning()) {
            engine.stop();
            updateStatus("  Stopped by user");
        }
    }

    public void shutdown() {
        if (engine.isRunning()) {
            engine.stop();
        }
    }

    public boolean isRunning() {
        return engine.isRunning();
    }

    // -- Utilities --

    private void updateStatus(String text) {
        if (statusLabel != null) {
            statusLabel.setText(text);
        }
    }

    private void updatePositionCount() {
        if (templateBox != null && positionLabel != null) {
            int count = FuzzPosition.parse(templateBox.getText()).size();
            positionLabel.setText(count + " positions");
        }
    }

    private static int parseIntSafe(String text, int fallback) {
        if (text == null || text.isBlank()) {
            return fallback;
        }
        try {
            return Integer.parseInt(text.trim());
        } catch (NumberFormatException e) {
            return fallback;
        }
    }
}
