package gg.effront.anarcry.gui.views;

import gg.effront.anarcry.fuzzer.AttackType;
import gg.effront.anarcry.fuzzer.FuzzEngine;
import gg.effront.anarcry.fuzzer.FuzzResult;
import gg.effront.anarcry.fuzzer.GrepMatcher;
import gg.effront.anarcry.fuzzer.PayloadProcessor;
import gg.effront.anarcry.fuzzer.PayloadProcessors;
import gg.effront.anarcry.fuzzer.PayloadSource;
import gg.effront.anarcry.gui.theme.AnarCryLaf;

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.util.ArrayList;
import java.util.List;

import javax.swing.BorderFactory;
import javax.swing.DefaultListModel;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSpinner;
import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;
import javax.swing.JTextArea;
import javax.swing.JToolBar;
import javax.swing.KeyStroke;
import javax.swing.SpinnerNumberModel;
import javax.swing.SwingUtilities;

import org.fife.ui.rsyntaxtextarea.RSyntaxTextArea;
import org.fife.ui.rsyntaxtextarea.SyntaxConstants;
import org.fife.ui.rsyntaxtextarea.Theme;
import org.fife.ui.rtextarea.RTextScrollPane;

public class FuzzerView extends JPanel implements FuzzEngine.FuzzListener {

    private final FuzzEngine engine = new FuzzEngine();

    // -- Template panel --
    private RSyntaxTextArea templateEditor;
    private JLabel positionCountLabel;

    // -- Config --
    private JComboBox<AttackType> attackTypeCombo;
    private JSpinner threadsSpinner;
    private JSpinner delaySpinner;
    private JSpinner jitterSpinner;
    private JLabel estimateLabel;

    // -- Payload tabs --
    private JTabbedPane payloadTabs;
    private final List<FuzzerPayloadPanel> payloadPanels = new ArrayList<>();

    // -- Processor list --
    private DefaultListModel<String> processorListModel;
    private JList<String> processorList;
    private final List<PayloadProcessor> processors = new ArrayList<>();

    // -- Grep --
    private JTextArea grepMatchArea;
    private JCheckBox grepCaseSensitive;
    private JCheckBox grepRegex;
    private JTextArea grepExtractArea;

    // -- Results --
    private final FuzzerResultsPanel resultsPanel = new FuzzerResultsPanel();

    // -- Control --
    private JButton startButton;
    private JButton pauseButton;
    private JButton stopButton;
    private JLabel progressLabel;
    private JLabel rpsLabel;

    // -- State --
    private long attackStartTime;
    private final GrepMatcher grepMatcher = new GrepMatcher();

    // -- Callback for "Send to Repeater" --
    private java.util.function.BiConsumer<String, String> sendToRepeaterCallback;

    public FuzzerView() {
        super(new BorderLayout());
        buildUi();
        AnarCryLaf.addThemeListener(this::onThemeChanged);
    }

    public void setSendToRepeaterCallback(java.util.function.BiConsumer<String, String> callback) {
        this.sendToRepeaterCallback = callback;
        resultsPanel.setSendToRepeaterAction(() -> {
            FuzzResult r = resultsPanel.getSelectedResult();
            if (r != null && sendToRepeaterCallback != null) {
                String template = templateEditor.getText();
                var positions = gg.effront.anarcry.fuzzer.FuzzPosition.parse(template);
                String injected = gg.effront.anarcry.fuzzer.FuzzPosition.inject(template, positions, r.payloads());
                String[] parts = FuzzEngine.parseRawRequest(injected);
                sendToRepeaterCallback.accept(parts[1], injected);
            }
        });
    }

    public void loadRequest(String method, String url, String headers, String body) {
        StringBuilder sb = new StringBuilder();
        sb.append(method).append(" ").append(url).append(" HTTP/1.1\n");
        if (headers != null && !headers.isBlank()) {
            sb.append(headers.trim()).append("\n");
        }
        if (body != null && !body.isBlank()) {
            sb.append("\n").append(body);
        }
        templateEditor.setText(sb.toString());
        updatePositionCount();
    }

    // -------------------------------------------------------------------------
    // UI Construction
    // -------------------------------------------------------------------------

    private void buildUi() {
        JToolBar toolbar = buildToolbar();
        JSplitPane mainSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT, buildTopPanel(), resultsPanel);
        mainSplit.setResizeWeight(0.45);
        add(toolbar, BorderLayout.NORTH);
        add(mainSplit, BorderLayout.CENTER);
        add(buildStatusBar(), BorderLayout.SOUTH);
    }

    private JToolBar buildToolbar() {
        JToolBar bar = new JToolBar();
        bar.setFloatable(false);
        bar.setBorder(BorderFactory.createEmptyBorder(4, 4, 4, 4));

        bar.add(new JLabel("Attack: "));
        attackTypeCombo = new JComboBox<>(AttackType.values());
        attackTypeCombo.setToolTipText("How payloads combine across positions");
        attackTypeCombo.addActionListener(e -> updateEstimate());
        bar.add(attackTypeCombo);
        bar.addSeparator();

        bar.add(new JLabel(" Threads: "));
        threadsSpinner = new JSpinner(new SpinnerNumberModel(10, 1, 100, 1));
        threadsSpinner.setMaximumSize(new Dimension(60, 28));
        bar.add(threadsSpinner);

        bar.add(new JLabel(" Delay(ms): "));
        delaySpinner = new JSpinner(new SpinnerNumberModel(0, 0, 5000, 50));
        delaySpinner.setMaximumSize(new Dimension(70, 28));
        bar.add(delaySpinner);

        bar.add(new JLabel(" Jitter(%): "));
        jitterSpinner = new JSpinner(new SpinnerNumberModel(0, 0, 50, 5));
        jitterSpinner.setMaximumSize(new Dimension(60, 28));
        bar.add(jitterSpinner);

        bar.addSeparator();
        estimateLabel = new JLabel("  ~0 requests");
        bar.add(estimateLabel);

        bar.add(javax.swing.Box.createHorizontalGlue());

        startButton = new JButton("Start Attack");
        startButton.addActionListener(e -> startAttack());
        bar.add(startButton);

        pauseButton = new JButton("Pause");
        pauseButton.setEnabled(false);
        pauseButton.addActionListener(e -> togglePause());
        bar.add(pauseButton);

        stopButton = new JButton("Stop");
        stopButton.setEnabled(false);
        stopButton.addActionListener(e -> stopAttack());
        bar.add(stopButton);

        return bar;
    }

    private JPanel buildTopPanel() {
        JSplitPane split = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, buildTemplatePanel(), buildPayloadPanel());
        split.setResizeWeight(0.55);
        JPanel panel = new JPanel(new BorderLayout());
        panel.add(split, BorderLayout.CENTER);
        return panel;
    }

    private JPanel buildTemplatePanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(BorderFactory.createTitledBorder("Request Template"));

        templateEditor = new RSyntaxTextArea(20, 60);
        templateEditor.setSyntaxEditingStyle(SyntaxConstants.SYNTAX_STYLE_NONE);
        templateEditor.setCodeFoldingEnabled(false);
        templateEditor.setAntiAliasingEnabled(true);
        templateEditor.setTabSize(2);
        templateEditor.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 13));
        templateEditor
                .setText("GET /path?param={{1}} HTTP/1.1\nHost: target.com\nUser-Agent: AnarCry/2.4.0\nAccept: */*");
        applySyntaxTheme(templateEditor);

        RTextScrollPane scroll = new RTextScrollPane(templateEditor);
        panel.add(scroll, BorderLayout.CENTER);

        JPanel buttonBar = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 2));
        JButton addPosBtn = new JButton("Add Position");
        addPosBtn.setToolTipText("Wrap selected text with {{N}} marker");
        addPosBtn.addActionListener(e -> addPosition());
        buttonBar.add(addPosBtn);

        JButton clearPosBtn = new JButton("Clear Positions");
        clearPosBtn.addActionListener(e -> clearPositions());
        buttonBar.add(clearPosBtn);

        JButton autoBtn = new JButton("Auto");
        autoBtn.setToolTipText("Auto-detect injection positions in query params, headers, and body");
        autoBtn.addActionListener(e -> autoDetectPositions());
        buttonBar.add(autoBtn);

        positionCountLabel = new JLabel("  0 positions");
        buttonBar.add(positionCountLabel);

        panel.add(buttonBar, BorderLayout.SOUTH);

        templateEditor.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
            @Override
            public void insertUpdate(javax.swing.event.DocumentEvent e) {
                updatePositionCount();
            }

            @Override
            public void removeUpdate(javax.swing.event.DocumentEvent e) {
                updatePositionCount();
            }

            @Override
            public void changedUpdate(javax.swing.event.DocumentEvent e) {
                updatePositionCount();
            }
        });

        registerKeyShortcuts(panel);

        return panel;
    }

    private JPanel buildPayloadPanel() {
        JPanel panel = new JPanel(new BorderLayout());

        JTabbedPane configTabs = new JTabbedPane();

        JPanel payloadsPanel = new JPanel(new BorderLayout());
        payloadTabs = new JTabbedPane();
        addPayloadTab();
        JButton addTabBtn = new JButton("+");
        addTabBtn.setToolTipText("Add payload set for another position");
        addTabBtn.addActionListener(e -> addPayloadTab());
        JPanel payloadTopBar = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 2));
        payloadTopBar.add(addTabBtn);
        payloadsPanel.add(payloadTopBar, BorderLayout.NORTH);
        payloadsPanel.add(payloadTabs, BorderLayout.CENTER);
        configTabs.addTab("Payloads", payloadsPanel);

        configTabs.addTab("Processing", buildProcessorPanel());
        configTabs.addTab("Grep", buildGrepPanel());

        panel.add(configTabs, BorderLayout.CENTER);
        return panel;
    }

    private void addPayloadTab() {
        FuzzerPayloadPanel pp = new FuzzerPayloadPanel();
        pp.setOnSourceChanged(this::updateEstimate);
        payloadPanels.add(pp);
        int idx = payloadPanels.size();
        payloadTabs.addTab("Position " + idx, pp);
        payloadTabs.setSelectedComponent(pp);
        updateEstimate();
    }

    private JPanel buildProcessorPanel() {
        JPanel panel = new JPanel(new BorderLayout(4, 4));
        panel.setBorder(BorderFactory.createEmptyBorder(4, 4, 4, 4));

        processorListModel = new DefaultListModel<>();
        processorList = new JList<>(processorListModel);
        JScrollPane listScroll = new JScrollPane(processorList);
        listScroll.setPreferredSize(new Dimension(200, 150));

        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 2));
        JComboBox<String> procCombo = new JComboBox<>(PayloadProcessors.AVAILABLE);
        buttons.add(procCombo);

        JButton addBtn = new JButton("Add");
        addBtn.addActionListener(e -> {
            String selected = (String) procCombo.getSelectedItem();
            if (selected != null) {
                addProcessor(selected);
            }
        });
        buttons.add(addBtn);

        JButton removeBtn = new JButton("Remove");
        removeBtn.addActionListener(e -> {
            int idx = processorList.getSelectedIndex();
            if (idx >= 0) {
                processorListModel.remove(idx);
                processors.remove(idx);
            }
        });
        buttons.add(removeBtn);

        panel.add(new JLabel("Payload processing pipeline (applied in order):"), BorderLayout.NORTH);
        panel.add(listScroll, BorderLayout.CENTER);
        panel.add(buttons, BorderLayout.SOUTH);

        return panel;
    }

    private void addProcessor(String name) {
        PayloadProcessor proc = switch (name) {
            case "URL encode" -> PayloadProcessors.urlEncode();
            case "URL decode" -> PayloadProcessors.urlDecode();
            case "Base64 encode" -> PayloadProcessors.base64Encode();
            case "Base64 decode" -> PayloadProcessors.base64Decode();
            case "HTML encode" -> PayloadProcessors.htmlEncode();
            case "HTML decode" -> PayloadProcessors.htmlDecode();
            case "Hash MD5" -> PayloadProcessors.hash("MD5");
            case "Hash SHA-1" -> PayloadProcessors.hash("SHA-1");
            case "Hash SHA-256" -> PayloadProcessors.hash("SHA-256");
            case "Hash SHA-512" -> PayloadProcessors.hash("SHA-512");
            case "Add prefix" -> {
                String val = JOptionPane.showInputDialog(this, "Prefix:");
                yield val != null ? PayloadProcessors.prefix(val) : null;
            }
            case "Add suffix" -> {
                String val = JOptionPane.showInputDialog(this, "Suffix:");
                yield val != null ? PayloadProcessors.suffix(val) : null;
            }
            case "Match/replace" -> {
                String pattern = JOptionPane.showInputDialog(this, "Regex pattern:");
                if (pattern != null) {
                    String repl = JOptionPane.showInputDialog(this, "Replacement:");
                    yield repl != null ? PayloadProcessors.matchReplace(pattern, repl) : null;
                }
                yield null;
            }
            case "Skip if matches" -> {
                String pattern = JOptionPane.showInputDialog(this, "Skip regex:");
                yield pattern != null ? PayloadProcessors.skipIfMatches(pattern) : null;
            }
            default -> null;
        };
        if (proc != null) {
            processors.add(proc);
            processorListModel.addElement(name);
        }
    }

    private JPanel buildGrepPanel() {
        JPanel panel = new JPanel(new BorderLayout(4, 4));
        panel.setBorder(BorderFactory.createEmptyBorder(4, 4, 4, 4));

        JPanel matchPanel = new JPanel(new BorderLayout(4, 4));
        matchPanel.setBorder(BorderFactory.createTitledBorder("Grep -- Match (one per line)"));
        grepMatchArea = new JTextArea(5, 30);
        grepMatchArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        grepMatchArea.setText("error\nexception\nSQL syntax\nstack trace\npassword\ntoken\nadmin\nflag{");
        matchPanel.add(new JScrollPane(grepMatchArea), BorderLayout.CENTER);

        JPanel matchOpts = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 2));
        grepCaseSensitive = new JCheckBox("Case sensitive");
        grepRegex = new JCheckBox("Regex");
        matchOpts.add(grepCaseSensitive);
        matchOpts.add(grepRegex);
        matchPanel.add(matchOpts, BorderLayout.SOUTH);

        JPanel extractPanel = new JPanel(new BorderLayout(4, 4));
        extractPanel.setBorder(
                BorderFactory.createTitledBorder("Grep -- Extract (regex with capture group, one per line)"));
        grepExtractArea = new JTextArea(3, 30);
        grepExtractArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        extractPanel.add(new JScrollPane(grepExtractArea), BorderLayout.CENTER);

        JSplitPane split = new JSplitPane(JSplitPane.VERTICAL_SPLIT, matchPanel, extractPanel);
        split.setResizeWeight(0.6);
        panel.add(split, BorderLayout.CENTER);

        return panel;
    }

    private JPanel buildStatusBar() {
        JPanel bar = new JPanel(new BorderLayout());
        bar.setBorder(BorderFactory.createEmptyBorder(2, 8, 2, 8));
        progressLabel = new JLabel("Ready");
        rpsLabel = new JLabel("");
        bar.add(progressLabel, BorderLayout.WEST);
        bar.add(rpsLabel, BorderLayout.EAST);
        return bar;
    }

    // -------------------------------------------------------------------------
    // Position management
    // -------------------------------------------------------------------------

    private void addPosition() {
        int start = templateEditor.getSelectionStart();
        int end = templateEditor.getSelectionEnd();
        if (start == end) {
            JOptionPane.showMessageDialog(this, "Select text to mark as a fuzz position.");
            return;
        }
        String text = templateEditor.getText();
        int nextIdx = gg.effront.anarcry.fuzzer.FuzzPosition
                .maxIndex(gg.effront.anarcry.fuzzer.FuzzPosition.parse(text)) + 1;
        String marker = "{{" + nextIdx + "}}";
        templateEditor.replaceRange(marker, start, end);
        updatePositionCount();
    }

    private void clearPositions() {
        String text = templateEditor.getText();
        text = text.replaceAll("\\{\\{\\d+\\}\\}", "");
        templateEditor.setText(text);
        updatePositionCount();
    }

    private void autoDetectPositions() {
        String text = templateEditor.getText();
        text = text.replaceAll("\\{\\{\\d+\\}\\}", "");

        int idx = 1;
        StringBuilder result = new StringBuilder();
        String[] lines = text.split("\n", -1);

        for (int i = 0; i < lines.length; i++) {
            String line = lines[i];
            if (i == 0) {
                int qIdx = line.indexOf('?');
                if (qIdx >= 0) {
                    int spaceIdx = line.indexOf(' ', qIdx);
                    String beforeQuery = line.substring(0, qIdx + 1);
                    String query = spaceIdx > 0 ? line.substring(qIdx + 1, spaceIdx) : line.substring(qIdx + 1);
                    String after = spaceIdx > 0 ? line.substring(spaceIdx) : "";

                    StringBuilder queryResult = new StringBuilder();
                    for (String param : query.split("&")) {
                        if (queryResult.length() > 0) {
                            queryResult.append("&");
                        }
                        int eq = param.indexOf('=');
                        if (eq >= 0) {
                            queryResult.append(param, 0, eq + 1).append("{{").append(idx++).append("}}");
                        } else {
                            queryResult.append(param);
                        }
                    }
                    result.append(beforeQuery).append(queryResult).append(after);
                } else {
                    result.append(line);
                }
            } else if (line.trim().isEmpty()) {
                result.append(line);
                for (int j = i + 1; j < lines.length; j++) {
                    result.append("\n");
                    String bodyLine = lines[j];
                    if (bodyLine.trim().startsWith("{")) {
                        bodyLine = bodyLine.replaceAll(":\\s*\"([^\"]+)\"", ": \"{{" + idx + "}}\"");
                        if (bodyLine.contains("{{" + idx + "}}")) {
                            idx++;
                        }
                    } else if (bodyLine.contains("=")) {
                        StringBuilder formResult = new StringBuilder();
                        for (String param : bodyLine.split("&")) {
                            if (formResult.length() > 0) {
                                formResult.append("&");
                            }
                            int eq = param.indexOf('=');
                            if (eq >= 0) {
                                formResult.append(param, 0, eq + 1).append("{{").append(idx++).append("}}");
                            } else {
                                formResult.append(param);
                            }
                        }
                        bodyLine = formResult.toString();
                    }
                    result.append(bodyLine);
                }
                break;
            } else {
                result.append(line);
            }
            if (i < lines.length - 1 && !lines[i].trim().isEmpty()) {
                result.append("\n");
            }
        }
        templateEditor.setText(result.toString());
        updatePositionCount();
    }

    private void updatePositionCount() {
        int count = gg.effront.anarcry.fuzzer.FuzzPosition.parse(templateEditor.getText()).size();
        positionCountLabel.setText("  " + count + " positions");
        updateEstimate();
    }

    private void updateEstimate() {
        AttackType type = (AttackType) attackTypeCombo.getSelectedItem();
        if (type == null) {
            return;
        }
        List<PayloadSource> sources = collectSources();
        int posCount = gg.effront.anarcry.fuzzer.FuzzPosition
                .maxIndex(gg.effront.anarcry.fuzzer.FuzzPosition.parse(templateEditor.getText()));
        long est = type.estimateRequests(posCount, sources);
        estimateLabel.setText("  ~" + String.format("%,d", est) + " requests");
    }

    // -------------------------------------------------------------------------
    // Attack control
    // -------------------------------------------------------------------------

    private void startAttack() {
        if (engine.isRunning()) {
            return;
        }

        String template = templateEditor.getText();
        var positions = gg.effront.anarcry.fuzzer.FuzzPosition.parse(template);
        if (positions.isEmpty()) {
            JOptionPane.showMessageDialog(this, "No positions marked. Use {{1}}, {{2}} etc.");
            return;
        }

        List<PayloadSource> sources = collectSources();
        if (sources.isEmpty() || sources.stream().allMatch(s -> s.size() == 0)) {
            JOptionPane.showMessageDialog(this, "No payloads configured.");
            return;
        }

        AttackType type = (AttackType) attackTypeCombo.getSelectedItem();
        long est = type.estimateRequests(gg.effront.anarcry.fuzzer.FuzzPosition.maxIndex(positions), sources);
        if (est > 100_000) {
            int confirm = JOptionPane.showConfirmDialog(this,
                    "This will generate ~" + String.format("%,d", est) + " requests. Continue?", "Large Attack",
                    JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE);
            if (confirm != JOptionPane.YES_OPTION) {
                return;
            }
        }

        setupGrepMatcher();

        resultsPanel.clearResults();
        resultsPanel.rebuildColumns(grepMatcher);

        List<List<PayloadProcessor>> pipelines = new ArrayList<>();
        pipelines.add(new ArrayList<>(processors));

        int threads = (int) threadsSpinner.getValue();
        int delay = (int) delaySpinner.getValue();
        int jitter = (int) jitterSpinner.getValue();

        FuzzEngine.FuzzConfig config = new FuzzEngine.FuzzConfig(template, type, sources, pipelines, threads, delay,
                jitter, 30, grepMatcher, null, null, null, 0);

        attackStartTime = System.currentTimeMillis();
        startButton.setEnabled(false);
        pauseButton.setEnabled(true);
        stopButton.setEnabled(true);
        progressLabel.setText("Starting...");

        engine.start(config, this);
    }

    private void togglePause() {
        if (engine.isPaused()) {
            engine.resume();
            pauseButton.setText("Pause");
        } else {
            engine.pause();
            pauseButton.setText("Resume");
        }
    }

    private void stopAttack() {
        engine.stop();
    }

    private List<PayloadSource> collectSources() {
        List<PayloadSource> sources = new ArrayList<>();
        for (FuzzerPayloadPanel pp : payloadPanels) {
            PayloadSource src = pp.getSource();
            if (src != null) {
                sources.add(src);
            }
        }
        return sources;
    }

    // -------------------------------------------------------------------------
    // Grep setup
    // -------------------------------------------------------------------------

    private void setupGrepMatcher() {
        List<GrepMatcher.GrepRule> matchRules = new ArrayList<>();
        String matchText = grepMatchArea.getText();
        if (matchText != null && !matchText.isBlank()) {
            boolean isRegex = grepRegex.isSelected();
            boolean caseSens = grepCaseSensitive.isSelected();
            for (String line : matchText.lines().filter(l -> !l.isBlank()).toList()) {
                matchRules.add(new GrepMatcher.GrepRule(line.trim(), isRegex, caseSens));
            }
        }
        grepMatcher.setMatchRules(matchRules);

        List<GrepMatcher.GrepRule> extractRules = new ArrayList<>();
        String extractText = grepExtractArea.getText();
        if (extractText != null && !extractText.isBlank()) {
            for (String line : extractText.lines().filter(l -> !l.isBlank()).toList()) {
                extractRules.add(new GrepMatcher.GrepRule(line.trim(), true, false));
            }
        }
        grepMatcher.setExtractRules(extractRules);
    }

    // -------------------------------------------------------------------------
    // FuzzListener callbacks
    // -------------------------------------------------------------------------

    @Override
    public void onResult(FuzzResult result) {
        SwingUtilities.invokeLater(() -> resultsPanel.addResult(result));
    }

    @Override
    public void onProgress(int completed, long total) {
        SwingUtilities.invokeLater(() -> {
            progressLabel.setText(String.format("%,d / %,d requests (%d%%)", completed, total,
                    total > 0 ? (completed * 100 / total) : 0));
            long elapsed = System.currentTimeMillis() - attackStartTime;
            if (elapsed > 0) {
                double rps = completed * 1000.0 / elapsed;
                rpsLabel.setText(String.format("%.1f req/s", rps));
            }
        });
    }

    @Override
    public void onComplete(int totalCompleted, long elapsedMs) {
        SwingUtilities.invokeLater(() -> {
            startButton.setEnabled(true);
            pauseButton.setEnabled(false);
            pauseButton.setText("Pause");
            stopButton.setEnabled(false);
            progressLabel.setText(String.format("Done: %,d requests in %,.1fs", totalCompleted, elapsedMs / 1000.0));
        });
    }

    @Override
    public void onError(String message) {
        SwingUtilities.invokeLater(
                () -> JOptionPane.showMessageDialog(this, message, "Fuzzer Error", JOptionPane.ERROR_MESSAGE));
    }

    // -------------------------------------------------------------------------
    // Keyboard shortcuts
    // -------------------------------------------------------------------------

    private void registerKeyShortcuts(JComponent component) {
        component.getInputMap(JComponent.WHEN_ANCESTOR_OF_FOCUSED_COMPONENT).put(KeyStroke.getKeyStroke("ctrl ENTER"),
                "startAttack");
        component.getActionMap().put("startAttack", new javax.swing.AbstractAction() {
            @Override
            public void actionPerformed(java.awt.event.ActionEvent e) {
                startAttack();
            }
        });

        component.getInputMap(JComponent.WHEN_ANCESTOR_OF_FOCUSED_COMPONENT).put(KeyStroke.getKeyStroke("ESCAPE"),
                "stopAttack");
        component.getActionMap().put("stopAttack", new javax.swing.AbstractAction() {
            @Override
            public void actionPerformed(java.awt.event.ActionEvent e) {
                stopAttack();
            }
        });
    }

    // -------------------------------------------------------------------------
    // Utilities
    // -------------------------------------------------------------------------

    private void applySyntaxTheme(RSyntaxTextArea area) {
        try {
            String themePath = AnarCryLaf.isDark()
                    ? "/org/fife/ui/rsyntaxtextarea/themes/dark.xml"
                    : "/org/fife/ui/rsyntaxtextarea/themes/default.xml";
            Theme theme = Theme.load(getClass().getResourceAsStream(themePath));
            theme.apply(area);
        } catch (Exception ignored) {
        }
    }

    private void onThemeChanged() {
        applySyntaxTheme(templateEditor);
    }
}
