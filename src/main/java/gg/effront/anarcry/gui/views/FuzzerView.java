package gg.effront.anarcry.gui.views;

import gg.effront.anarcry.fuzzer.AttackType;
import gg.effront.anarcry.fuzzer.FilePayloadSource;
import gg.effront.anarcry.fuzzer.FuzzEngine;
import gg.effront.anarcry.fuzzer.FuzzResult;
import gg.effront.anarcry.fuzzer.GrepMatcher;
import gg.effront.anarcry.fuzzer.InlinePayloadSource;
import gg.effront.anarcry.fuzzer.PayloadProcessor;
import gg.effront.anarcry.fuzzer.PayloadProcessors;
import gg.effront.anarcry.fuzzer.PayloadSource;
import gg.effront.anarcry.fuzzer.RangePayloadSource;
import gg.effront.anarcry.gui.theme.AnarCryLaf;
import gg.effront.anarcry.util.HttpRequestUtil;

import java.awt.BorderLayout;
import java.awt.CardLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.Toolkit;
import java.awt.datatransfer.StringSelection;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import javax.swing.BorderFactory;
import javax.swing.DefaultListModel;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPopupMenu;
import javax.swing.JMenuItem;
import javax.swing.JScrollPane;
import javax.swing.JSpinner;
import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.JToolBar;
import javax.swing.KeyStroke;
import javax.swing.RowFilter;
import javax.swing.SpinnerNumberModel;
import javax.swing.SwingUtilities;
import javax.swing.filechooser.FileNameExtensionFilter;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableRowSorter;

import org.fife.ui.rsyntaxtextarea.RSyntaxTextArea;
import org.fife.ui.rsyntaxtextarea.SyntaxConstants;
import org.fife.ui.rsyntaxtextarea.Theme;
import org.fife.ui.rtextarea.RTextScrollPane;

public class FuzzerView extends JPanel implements FuzzEngine.FuzzListener {

    private static final int MAX_RESULTS_IN_MEMORY = 50_000;

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
    private final List<PayloadPanel> payloadPanels = new ArrayList<>();

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
    private DefaultTableModel resultsModel;
    private JTable resultsTable;
    private TableRowSorter<DefaultTableModel> resultsSorter;
    private JTextField statusFilterField;
    private JTextField lengthFilterField;
    private RSyntaxTextArea responseViewer;

    // -- Control --
    private JButton startButton;
    private JButton pauseButton;
    private JButton stopButton;
    private JLabel progressLabel;
    private JLabel rpsLabel;

    // -- State --
    private long attackStartTime;
    private int lastReportedCount;
    private final GrepMatcher grepMatcher = new GrepMatcher();
    private final List<FuzzResult> allResults = new ArrayList<>();

    // -- Callback for "Send to Repeater" --
    private java.util.function.BiConsumer<String, String> sendToRepeaterCallback;

    public FuzzerView() {
        super(new BorderLayout());
        buildUi();
        AnarCryLaf.addThemeListener(this::onThemeChanged);
    }

    public void setSendToRepeaterCallback(java.util.function.BiConsumer<String, String> callback) {
        this.sendToRepeaterCallback = callback;
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
        JSplitPane mainSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT, buildTopPanel(), buildBottomPanel());
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
        attackTypeCombo.addActionListener(e -> onAttackTypeChanged());
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

        // Payloads tab
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

        // Processors tab
        configTabs.addTab("Processing", buildProcessorPanel());

        // Grep tab
        configTabs.addTab("Grep", buildGrepPanel());

        panel.add(configTabs, BorderLayout.CENTER);
        return panel;
    }

    private void addPayloadTab() {
        PayloadPanel pp = new PayloadPanel();
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

    private JPanel buildBottomPanel() {
        JPanel panel = new JPanel(new BorderLayout());

        // Filter bar
        JPanel filterBar = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 2));
        filterBar.add(new JLabel("Status:"));
        statusFilterField = new JTextField(8);
        statusFilterField.setToolTipText("Filter: 200, 4xx, !200");
        statusFilterField.addActionListener(e -> applyFilters());
        filterBar.add(statusFilterField);

        filterBar.add(new JLabel("Length:"));
        lengthFilterField = new JTextField(10);
        lengthFilterField.setToolTipText("Filter: min-max (e.g. 100-5000)");
        lengthFilterField.addActionListener(e -> applyFilters());
        filterBar.add(lengthFilterField);

        JButton filterBtn = new JButton("Filter");
        filterBtn.addActionListener(e -> applyFilters());
        filterBar.add(filterBtn);

        JButton clearFilterBtn = new JButton("Clear");
        clearFilterBtn.addActionListener(e -> {
            statusFilterField.setText("");
            lengthFilterField.setText("");
            resultsSorter.setRowFilter(null);
        });
        filterBar.add(clearFilterBtn);

        JButton exportBtn = new JButton("Export CSV");
        exportBtn.addActionListener(e -> exportResults());
        filterBar.add(exportBtn);

        JButton exportJsonBtn = new JButton("Export JSON");
        exportJsonBtn.addActionListener(e -> exportResultsJson());
        filterBar.add(exportJsonBtn);

        panel.add(filterBar, BorderLayout.NORTH);

        // Results table
        resultsModel = new DefaultTableModel(new String[]{"#", "Payload", "Status", "Length", "Time(ms)", "Error"}, 0) {
            @Override
            public Class<?> getColumnClass(int col) {
                return switch (col) {
                    case 0, 2, 3, 4 -> Integer.class;
                    default -> String.class;
                };
            }

            @Override
            public boolean isCellEditable(int row, int col) {
                return false;
            }
        };
        resultsTable = new JTable(resultsModel);
        resultsTable.setAutoCreateRowSorter(false);
        resultsSorter = new TableRowSorter<>(resultsModel);
        resultsTable.setRowSorter(resultsSorter);
        resultsTable.setDefaultRenderer(Object.class, new StatusCodeRenderer());
        resultsTable.setDefaultRenderer(Integer.class, new StatusCodeRenderer());
        resultsTable.setRowHeight(22);
        resultsTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                showSelectedResponse();
            }
        });
        addResultsContextMenu();

        JScrollPane tableScroll = new JScrollPane(resultsTable);

        // Response viewer
        responseViewer = new RSyntaxTextArea(10, 60);
        responseViewer.setEditable(false);
        responseViewer.setSyntaxEditingStyle(SyntaxConstants.SYNTAX_STYLE_NONE);
        responseViewer.setCodeFoldingEnabled(true);
        responseViewer.setAntiAliasingEnabled(true);
        responseViewer.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        applySyntaxTheme(responseViewer);
        RTextScrollPane responseScroll = new RTextScrollPane(responseViewer);

        JSplitPane resultsSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT, tableScroll, responseScroll);
        resultsSplit.setResizeWeight(0.6);
        panel.add(resultsSplit, BorderLayout.CENTER);

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
                // request line -- mark query param values
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
                // mark body values in remaining lines
                for (int j = i + 1; j < lines.length; j++) {
                    result.append("\n");
                    String bodyLine = lines[j];
                    if (bodyLine.trim().startsWith("{")) {
                        // JSON: mark string values
                        bodyLine = bodyLine.replaceAll(":\\s*\"([^\"]+)\"", ": \"{{" + idx + "}}\"");
                        if (bodyLine.contains("{{" + idx + "}}")) {
                            idx++;
                        }
                    } else if (bodyLine.contains("=")) {
                        // Form encoded
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

    private void onAttackTypeChanged() {
        updateEstimate();
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

        // Setup grep matcher
        setupGrepMatcher();

        // Reset results
        resultsModel.setRowCount(0);
        allResults.clear();
        rebuildResultColumns();

        List<List<PayloadProcessor>> pipelines = new ArrayList<>();
        pipelines.add(new ArrayList<>(processors));

        int threads = (int) threadsSpinner.getValue();
        int delay = (int) delaySpinner.getValue();
        int jitter = (int) jitterSpinner.getValue();

        FuzzEngine.FuzzConfig config = new FuzzEngine.FuzzConfig(template, type, sources, pipelines, threads, delay,
                jitter, 30, grepMatcher, null, null, null, 0);

        attackStartTime = System.currentTimeMillis();
        lastReportedCount = 0;
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
        for (PayloadPanel pp : payloadPanels) {
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

    private void rebuildResultColumns() {
        List<String> cols = new ArrayList<>(List.of("#", "Payload", "Status", "Length", "Time(ms)", "Error"));
        for (String label : grepMatcher.matchLabels()) {
            cols.add("M:" + truncate(label, 15));
        }
        for (String label : grepMatcher.extractLabels()) {
            cols.add("E:" + truncate(label, 15));
        }
        resultsModel.setColumnIdentifiers(cols.toArray());
    }

    // -------------------------------------------------------------------------
    // FuzzListener callbacks
    // -------------------------------------------------------------------------

    @Override
    public void onResult(FuzzResult result) {
        SwingUtilities.invokeLater(() -> {
            if (allResults.size() < MAX_RESULTS_IN_MEMORY) {
                allResults.add(result);
            }
            Object[] row = buildResultRow(result);
            resultsModel.addRow(row);
        });
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
    // Results table
    // -------------------------------------------------------------------------

    private Object[] buildResultRow(FuzzResult result) {
        List<Object> row = new ArrayList<>();
        row.add(result.requestNum());
        row.add(result.payloadSummary());
        row.add(result.statusCode());
        row.add((int) result.length());
        row.add((int) result.timeMs());
        row.add(result.error() != null ? result.error() : "");

        int[] matches = result.grepMatchCounts();
        if (matches != null) {
            for (int count : matches) {
                row.add(count > 0 ? String.valueOf(count) : "");
            }
        }
        String[] extracts = result.grepExtracts();
        if (extracts != null) {
            for (String val : extracts) {
                row.add(val != null ? val : "");
            }
        }
        return row.toArray();
    }

    private void showSelectedResponse() {
        int viewRow = resultsTable.getSelectedRow();
        if (viewRow < 0) {
            return;
        }
        int modelRow = resultsTable.convertRowIndexToModel(viewRow);
        if (modelRow < 0 || modelRow >= allResults.size()) {
            return;
        }
        FuzzResult result = allResults.get(modelRow);
        String body = result.responseBody();
        responseViewer.setText(body != null ? body : "");
        responseViewer.setCaretPosition(0);

        if (body != null) {
            String lower = body.trim().toLowerCase();
            if (lower.startsWith("{") || lower.startsWith("[")) {
                responseViewer.setSyntaxEditingStyle(SyntaxConstants.SYNTAX_STYLE_JSON);
            } else if (lower.startsWith("<!doctype") || lower.startsWith("<html")) {
                responseViewer.setSyntaxEditingStyle(SyntaxConstants.SYNTAX_STYLE_HTML);
            } else if (lower.startsWith("<?xml")) {
                responseViewer.setSyntaxEditingStyle(SyntaxConstants.SYNTAX_STYLE_XML);
            } else {
                responseViewer.setSyntaxEditingStyle(SyntaxConstants.SYNTAX_STYLE_NONE);
            }
        }
    }

    private void addResultsContextMenu() {
        JPopupMenu menu = new JPopupMenu();

        JMenuItem copyPayload = new JMenuItem("Copy Payload");
        copyPayload.addActionListener(e -> {
            int row = resultsTable.getSelectedRow();
            if (row >= 0) {
                Object val = resultsTable.getValueAt(row, 1);
                copyToClipboard(val != null ? val.toString() : "");
            }
        });
        menu.add(copyPayload);

        JMenuItem copyResponse = new JMenuItem("Copy Response");
        copyResponse.addActionListener(e -> {
            int viewRow = resultsTable.getSelectedRow();
            if (viewRow >= 0) {
                int modelRow = resultsTable.convertRowIndexToModel(viewRow);
                if (modelRow < allResults.size()) {
                    copyToClipboard(allResults.get(modelRow).responseBody());
                }
            }
        });
        menu.add(copyResponse);

        JMenuItem sendToRepeater = new JMenuItem("Send to Repeater");
        sendToRepeater.addActionListener(e -> {
            int viewRow = resultsTable.getSelectedRow();
            if (viewRow >= 0 && sendToRepeaterCallback != null) {
                int modelRow = resultsTable.convertRowIndexToModel(viewRow);
                if (modelRow < allResults.size()) {
                    FuzzResult r = allResults.get(modelRow);
                    String template = templateEditor.getText();
                    var positions = gg.effront.anarcry.fuzzer.FuzzPosition.parse(template);
                    String injected = gg.effront.anarcry.fuzzer.FuzzPosition.inject(template, positions, r.payloads());
                    String[] parts = FuzzEngine.parseRawRequest(injected);
                    sendToRepeaterCallback.accept(parts[1], injected);
                }
            }
        });
        menu.add(sendToRepeater);

        resultsTable.addMouseListener(new MouseAdapter() {
            @Override
            public void mousePressed(MouseEvent e) {
                showPopup(e);
            }

            @Override
            public void mouseReleased(MouseEvent e) {
                showPopup(e);
            }

            private void showPopup(MouseEvent e) {
                if (!e.isPopupTrigger()) {
                    return;
                }
                int row = resultsTable.rowAtPoint(e.getPoint());
                if (row >= 0) {
                    resultsTable.setRowSelectionInterval(row, row);
                }
                menu.show(resultsTable, e.getX(), e.getY());
            }
        });
    }

    // -------------------------------------------------------------------------
    // Filters
    // -------------------------------------------------------------------------

    private void applyFilters() {
        List<RowFilter<Object, Object>> filters = new ArrayList<>();
        String statusText = statusFilterField.getText().trim();
        if (!statusText.isEmpty()) {
            filters.add(createStatusFilter(statusText));
        }
        String lengthText = lengthFilterField.getText().trim();
        if (!lengthText.isEmpty()) {
            filters.add(createLengthFilter(lengthText));
        }
        if (filters.isEmpty()) {
            resultsSorter.setRowFilter(null);
        } else {
            resultsSorter.setRowFilter(RowFilter.andFilter(filters));
        }
    }

    private RowFilter<Object, Object> createStatusFilter(String text) {
        boolean negate = text.startsWith("!");
        String val = negate ? text.substring(1) : text;
        return new RowFilter<>() {
            @Override
            public boolean include(Entry<?, ?> entry) {
                Object statusObj = entry.getValue(2);
                if (statusObj == null) {
                    return false;
                }
                int status = (Integer) statusObj;
                boolean match;
                if (val.endsWith("xx")) {
                    int prefix = Integer.parseInt(val.substring(0, 1));
                    match = status / 100 == prefix;
                } else {
                    match = status == Integer.parseInt(val);
                }
                return negate != match;
            }
        };
    }

    private RowFilter<Object, Object> createLengthFilter(String text) {
        String[] parts = text.split("-");
        long min = parts.length > 0 ? Long.parseLong(parts[0].trim()) : 0;
        long max = parts.length > 1 ? Long.parseLong(parts[1].trim()) : Long.MAX_VALUE;
        return new RowFilter<>() {
            @Override
            public boolean include(Entry<?, ?> entry) {
                Object lenObj = entry.getValue(3);
                if (lenObj == null) {
                    return false;
                }
                int len = (Integer) lenObj;
                return len >= min && len <= max;
            }
        };
    }

    // -------------------------------------------------------------------------
    // Export
    // -------------------------------------------------------------------------

    private void exportResults() {
        JFileChooser fc = new JFileChooser();
        fc.setSelectedFile(new java.io.File("fuzz-results-" + System.currentTimeMillis() + ".csv"));
        fc.setFileFilter(new FileNameExtensionFilter("CSV files", "csv"));
        if (fc.showSaveDialog(this) != JFileChooser.APPROVE_OPTION) {
            return;
        }
        try (PrintWriter pw = new PrintWriter(new FileWriter(fc.getSelectedFile()))) {
            // header
            StringBuilder hdr = new StringBuilder();
            for (int i = 0; i < resultsModel.getColumnCount(); i++) {
                if (i > 0) {
                    hdr.append(",");
                }
                hdr.append(HttpRequestUtil.csvEscape(resultsModel.getColumnName(i)));
            }
            pw.println(hdr);
            // rows (filtered)
            for (int viewRow = 0; viewRow < resultsTable.getRowCount(); viewRow++) {
                StringBuilder row = new StringBuilder();
                for (int col = 0; col < resultsModel.getColumnCount(); col++) {
                    if (col > 0) {
                        row.append(",");
                    }
                    Object val = resultsTable.getValueAt(viewRow, col);
                    row.append(HttpRequestUtil.csvEscape(val != null ? val.toString() : ""));
                }
                pw.println(row);
            }
            JOptionPane.showMessageDialog(this,
                    "Exported " + resultsTable.getRowCount() + " rows to " + fc.getSelectedFile().getName());
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(this, "Export failed: " + ex.getMessage());
        }
    }

    private void exportResultsJson() {
        JFileChooser fc = new JFileChooser();
        fc.setSelectedFile(new java.io.File("fuzz-results-" + System.currentTimeMillis() + ".json"));
        fc.setFileFilter(new FileNameExtensionFilter("JSON files", "json"));
        if (fc.showSaveDialog(this) != JFileChooser.APPROVE_OPTION) {
            return;
        }
        try (PrintWriter pw = new PrintWriter(new FileWriter(fc.getSelectedFile()))) {
            com.google.gson.GsonBuilder gb = new com.google.gson.GsonBuilder().setPrettyPrinting();
            pw.print(gb.create().toJson(allResults));
            JOptionPane.showMessageDialog(this,
                    "Exported " + allResults.size() + " results to " + fc.getSelectedFile().getName());
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(this, "Export failed: " + ex.getMessage());
        }
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

    private static String truncate(String s, int max) {
        return s.length() <= max ? s : s.substring(0, max - 2) + "..";
    }

    private static void copyToClipboard(String text) {
        if (text != null) {
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(text), null);
        }
    }

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
        applySyntaxTheme(responseViewer);
    }

    // -------------------------------------------------------------------------
    // Status code renderer
    // -------------------------------------------------------------------------

    private static class StatusCodeRenderer extends DefaultTableCellRenderer {
        @Override
        public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus,
                int row, int column) {
            Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
            if (!isSelected && column == 2 && value instanceof Integer status) {
                if (status >= 500) {
                    c.setForeground(new Color(0xDC, 0x38, 0x2D));
                } else if (status >= 400) {
                    c.setForeground(new Color(0xCC, 0x66, 0x00));
                } else if (status >= 300) {
                    c.setForeground(new Color(0x33, 0x87, 0xC5));
                } else if (status >= 200) {
                    c.setForeground(new Color(0x4D, 0xA5, 0x3C));
                } else {
                    c.setForeground(table.getForeground());
                }
            } else if (!isSelected) {
                c.setForeground(table.getForeground());
            }
            // alternating rows
            if (!isSelected) {
                c.setBackground(row % 2 == 0 ? table.getBackground() : stripeColor(table));
            }
            return c;
        }

        private static Color stripeColor(JTable table) {
            Color bg = table.getBackground();
            int r = bg.getRed();
            int g = bg.getGreen();
            int b = bg.getBlue();
            boolean dark = (r + g + b) / 3 < 128;
            int delta = dark ? 12 : -12;
            return new Color(clamp(r + delta), clamp(g + delta), clamp(b + delta));
        }

        private static int clamp(int v) {
            return Math.max(0, Math.min(255, v));
        }
    }

    // -------------------------------------------------------------------------
    // Payload panel (inner component)
    // -------------------------------------------------------------------------

    private class PayloadPanel extends JPanel {

        private final JComboBox<String> sourceTypeCombo;
        private final CardLayout cardLayout;
        private final JPanel cardPanel;

        // File source
        private JTextField filePathField;
        private JLabel fileInfoLabel;
        private JTextArea filePreview;
        private Path selectedFilePath;

        // Inline source
        private JTextArea inlineArea;

        // Range source
        private JSpinner rangeFrom;
        private JSpinner rangeTo;
        private JSpinner rangeStep;
        private JSpinner rangePadding;

        PayloadPanel() {
            super(new BorderLayout(4, 4));
            setBorder(BorderFactory.createEmptyBorder(4, 4, 4, 4));

            sourceTypeCombo = new JComboBox<>(new String[]{"File", "Inline", "Range"});
            sourceTypeCombo.addActionListener(e -> showSourceCard());
            add(sourceTypeCombo, BorderLayout.NORTH);

            cardLayout = new CardLayout();
            cardPanel = new JPanel(cardLayout);
            cardPanel.add(buildFileCard(), "File");
            cardPanel.add(buildInlineCard(), "Inline");
            cardPanel.add(buildRangeCard(), "Range");
            add(cardPanel, BorderLayout.CENTER);
        }

        private JPanel buildFileCard() {
            JPanel panel = new JPanel(new BorderLayout(4, 4));

            JPanel pathBar = new JPanel(new BorderLayout(4, 0));
            filePathField = new JTextField();
            filePathField.setEditable(false);
            JButton browseBtn = new JButton("Browse");
            browseBtn.addActionListener(e -> browseFile());
            pathBar.add(filePathField, BorderLayout.CENTER);
            pathBar.add(browseBtn, BorderLayout.EAST);
            panel.add(pathBar, BorderLayout.NORTH);

            fileInfoLabel = new JLabel("No file selected");
            filePreview = new JTextArea(8, 30);
            filePreview.setEditable(false);
            filePreview.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 11));

            JPanel infoPanel = new JPanel(new BorderLayout());
            infoPanel.add(fileInfoLabel, BorderLayout.NORTH);
            infoPanel.add(new JScrollPane(filePreview), BorderLayout.CENTER);
            panel.add(infoPanel, BorderLayout.CENTER);

            return panel;
        }

        private JPanel buildInlineCard() {
            JPanel panel = new JPanel(new BorderLayout(4, 4));
            panel.add(new JLabel("One payload per line:"), BorderLayout.NORTH);
            inlineArea = new JTextArea(10, 30);
            inlineArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
            panel.add(new JScrollPane(inlineArea), BorderLayout.CENTER);
            return panel;
        }

        private JPanel buildRangeCard() {
            JPanel panel = new JPanel(new GridBagLayout());
            GridBagConstraints gbc = new GridBagConstraints();
            gbc.insets = new Insets(4, 4, 4, 4);
            gbc.anchor = GridBagConstraints.WEST;

            gbc.gridx = 0;
            gbc.gridy = 0;
            panel.add(new JLabel("From:"), gbc);
            gbc.gridx = 1;
            rangeFrom = new JSpinner(new SpinnerNumberModel(0L, 0L, (long) Integer.MAX_VALUE, 1L));
            panel.add(rangeFrom, gbc);

            gbc.gridx = 0;
            gbc.gridy = 1;
            panel.add(new JLabel("To:"), gbc);
            gbc.gridx = 1;
            rangeTo = new JSpinner(new SpinnerNumberModel(100L, 0L, (long) Integer.MAX_VALUE, 1L));
            panel.add(rangeTo, gbc);

            gbc.gridx = 0;
            gbc.gridy = 2;
            panel.add(new JLabel("Step:"), gbc);
            gbc.gridx = 1;
            rangeStep = new JSpinner(new SpinnerNumberModel(1L, 1L, (long) Integer.MAX_VALUE, 1L));
            panel.add(rangeStep, gbc);

            gbc.gridx = 0;
            gbc.gridy = 3;
            panel.add(new JLabel("Padding:"), gbc);
            gbc.gridx = 1;
            rangePadding = new JSpinner(new SpinnerNumberModel(0, 0, 20, 1));
            panel.add(rangePadding, gbc);

            return panel;
        }

        private void showSourceCard() {
            String selected = (String) sourceTypeCombo.getSelectedItem();
            if (selected != null) {
                cardLayout.show(cardPanel, selected);
            }
            updateEstimate();
        }

        private void browseFile() {
            JFileChooser fc = new JFileChooser();
            Path wordlistDir = Path.of(System.getProperty("user.home"), "wordlists");
            if (Files.isDirectory(wordlistDir)) {
                fc.setCurrentDirectory(wordlistDir.toFile());
            }
            fc.setFileFilter(new FileNameExtensionFilter("Text files", "txt", "lst", "csv"));
            if (fc.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
                selectedFilePath = fc.getSelectedFile().toPath();
                filePathField.setText(selectedFilePath.toString());

                Thread.ofVirtual().name("payload-file-load").start(() -> {
                    FilePayloadSource src = new FilePayloadSource(selectedFilePath);
                    long count = src.size();
                    List<String> preview = src.preview(10);
                    SwingUtilities.invokeLater(() -> {
                        fileInfoLabel.setText(
                                selectedFilePath.getFileName() + " (" + String.format("%,d", count) + " lines)");
                        filePreview.setText(String.join("\n", preview));
                        updateEstimate();
                    });
                });
            }
        }

        PayloadSource getSource() {
            String type = (String) sourceTypeCombo.getSelectedItem();
            return switch (type) {
                case "File" -> selectedFilePath != null ? new FilePayloadSource(selectedFilePath) : null;
                case "Inline" -> {
                    String text = inlineArea.getText();
                    yield text != null && !text.isBlank() ? new InlinePayloadSource(text) : null;
                }
                case "Range" -> new RangePayloadSource((long) rangeFrom.getValue(), (long) rangeTo.getValue(),
                        (long) rangeStep.getValue(), (int) rangePadding.getValue());
                default -> null;
            };
        }
    }
}
