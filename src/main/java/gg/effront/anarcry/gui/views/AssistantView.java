package gg.effront.anarcry.gui.views;

import gg.effront.anarcry.assistant.AiAssistant;
import gg.effront.anarcry.assistant.AssistantConfig;
import gg.effront.anarcry.assistant.ContextBuilder;
import gg.effront.anarcry.assistant.ProviderRegistry;
import gg.effront.anarcry.assistant.UsageTracker;
import gg.effront.anarcry.assistant.tools.AssistantTool;
import gg.effront.anarcry.assistant.tools.ExplainCweTool;
import gg.effront.anarcry.assistant.tools.GetFindingsTool;
import gg.effront.anarcry.assistant.tools.GetScanConfigTool;
import gg.effront.anarcry.assistant.tools.GetSitemapTool;
import gg.effront.anarcry.assistant.tools.QueryKbTool;
import gg.effront.anarcry.assistant.tools.SaveDocTool;
import gg.effront.anarcry.assistant.tools.ToolSchemaBuilder;
import gg.effront.anarcry.model.Finding;
import gg.effront.anarcry.model.KnowledgeBase;
import gg.effront.anarcry.scanner.DiscoveredPaths;
import gg.effront.anarcry.scanner.ScanContext;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.event.ItemEvent;
import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.function.Supplier;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollBar;
import javax.swing.JScrollPane;
import javax.swing.JTextField;
import javax.swing.JTextPane;
import javax.swing.SwingUtilities;
import javax.swing.text.BadLocationException;
import javax.swing.text.Style;
import javax.swing.text.StyleConstants;
import javax.swing.text.StyledDocument;

public class AssistantView extends JPanel {

    private static final Color DARK_BG = new Color(0x1E, 0x1E, 0x2E);
    private static final Color USER_COLOR = new Color(0x4E, 0xC9, 0xB0);
    private static final Color ASSISTANT_COLOR = new Color(0xD4, 0xD4, 0xD4);
    private static final Color SYSTEM_COLOR = new Color(0xE5, 0xC0, 0x7B);
    private static final Color INPUT_BG = new Color(0x2D, 0x2D, 0x3D);
    private static final Color LABEL_COLOR = new Color(0x88, 0x88, 0x99);
    private static final Font CHAT_FONT = new Font(Font.MONOSPACED, Font.PLAIN, 13);
    private static final Font INPUT_FONT = new Font(Font.MONOSPACED, Font.PLAIN, 14);

    private final JTextPane chatPane;
    private final JTextField inputField;
    private final JLabel usageLabel;
    private final JScrollPane scrollPane;
    private final JComboBox<String> providerCombo;
    private final JComboBox<String> modelCombo;

    private AiAssistant aiAssistant;
    private ContextBuilder contextBuilder;
    private final ExecutorService executor = Executors.newSingleThreadExecutor(r -> {
        Thread t = new Thread(r, "gui-assistant-worker");
        t.setDaemon(true);
        return t;
    });

    private Supplier<List<Finding>> findingsSupplier = List::of;
    private Supplier<ScanContext> contextSupplier = () -> null;
    private Supplier<DiscoveredPaths> discoveredPathsSupplier = DiscoveredPaths::new;

    private List<ProviderRegistry.ProviderInfo> availableProviders = List.of();
    private int maxTokens = 4096;
    private boolean suppressComboEvents;
    private int thinkingStart = -1;

    public AssistantView() {
        super(new BorderLayout(0, 4));
        setBackground(DARK_BG);

        providerCombo = new JComboBox<>();
        providerCombo.setBackground(INPUT_BG);
        providerCombo.setForeground(ASSISTANT_COLOR);
        providerCombo.setFont(CHAT_FONT);
        providerCombo.setPreferredSize(new Dimension(140, 26));
        providerCombo.addItemListener(e -> {
            if (!suppressComboEvents && e.getStateChange() == ItemEvent.SELECTED) {
                onProviderChanged();
            }
        });

        modelCombo = new JComboBox<>();
        modelCombo.setEditable(true);
        modelCombo.setBackground(INPUT_BG);
        modelCombo.setForeground(ASSISTANT_COLOR);
        modelCombo.setFont(CHAT_FONT);
        modelCombo.setPreferredSize(new Dimension(250, 26));
        modelCombo.getEditor().getEditorComponent().setBackground(INPUT_BG);
        modelCombo.getEditor().getEditorComponent().setForeground(ASSISTANT_COLOR);
        modelCombo.addItemListener(e -> {
            if (!suppressComboEvents && e.getStateChange() == ItemEvent.SELECTED) {
                onModelChanged();
            }
        });

        JLabel providerLabel = new JLabel(" Provider:");
        providerLabel.setForeground(LABEL_COLOR);
        providerLabel.setFont(CHAT_FONT);

        JLabel modelLabel = new JLabel("  Model:");
        modelLabel.setForeground(LABEL_COLOR);
        modelLabel.setFont(CHAT_FONT);

        JPanel selectorBar = new JPanel(new FlowLayout(FlowLayout.LEFT, 2, 4));
        selectorBar.setBackground(DARK_BG);
        selectorBar.add(providerLabel);
        selectorBar.add(providerCombo);
        selectorBar.add(modelLabel);
        selectorBar.add(modelCombo);

        chatPane = new JTextPane();
        chatPane.setEditable(false);
        chatPane.setBackground(DARK_BG);
        chatPane.setFont(CHAT_FONT);
        initStyles();

        scrollPane = new JScrollPane(chatPane);
        scrollPane.setBorder(null);

        JPanel centerPanel = new JPanel(new BorderLayout());
        centerPanel.setBackground(DARK_BG);
        centerPanel.add(selectorBar, BorderLayout.NORTH);
        centerPanel.add(scrollPane, BorderLayout.CENTER);
        add(centerPanel, BorderLayout.CENTER);

        JPanel bottomPanel = new JPanel(new BorderLayout(4, 0));
        bottomPanel.setBackground(DARK_BG);

        JLabel hintLabel = new JLabel(" /findings /explain /remediate /plan /kb /report /clear");
        hintLabel.setForeground(LABEL_COLOR);
        hintLabel.setFont(CHAT_FONT);

        inputField = new JTextField();
        inputField.setBackground(INPUT_BG);
        inputField.setForeground(ASSISTANT_COLOR);
        inputField.setCaretColor(ASSISTANT_COLOR);
        inputField.setFont(INPUT_FONT);
        inputField.setPreferredSize(new Dimension(0, 38));
        inputField.setBorder(
                BorderFactory.createCompoundBorder(BorderFactory.createLineBorder(new Color(0x44, 0x44, 0x55)),
                        BorderFactory.createEmptyBorder(8, 8, 8, 8)));

        inputField.addKeyListener(new KeyAdapter() {
            @Override
            public void keyPressed(KeyEvent e) {
                if (e.getKeyCode() == KeyEvent.VK_ENTER) {
                    handleSubmit();
                    e.consume();
                }
            }
        });

        JButton sendBtn = new JButton("Send");
        sendBtn.addActionListener(e -> handleSubmit());

        usageLabel = new JLabel("");
        usageLabel.setForeground(LABEL_COLOR);
        usageLabel.setFont(CHAT_FONT);

        JPanel inputRow = new JPanel(new BorderLayout(4, 0));
        inputRow.setBackground(DARK_BG);
        inputRow.add(inputField, BorderLayout.CENTER);
        inputRow.add(sendBtn, BorderLayout.EAST);

        JPanel usageRow = new JPanel(new BorderLayout());
        usageRow.setBackground(DARK_BG);
        usageRow.add(hintLabel, BorderLayout.WEST);
        usageRow.add(usageLabel, BorderLayout.EAST);

        bottomPanel.add(usageRow, BorderLayout.NORTH);
        bottomPanel.add(inputRow, BorderLayout.SOUTH);

        add(bottomPanel, BorderLayout.SOUTH);
    }

    public void configure(Map<String, String> envMap) {
        availableProviders = ProviderRegistry.detect(envMap);
        maxTokens = AssistantConfig.parseMaxTokens(envMap);

        suppressComboEvents = true;
        providerCombo.removeAllItems();
        for (ProviderRegistry.ProviderInfo info : availableProviders) {
            providerCombo.addItem(info.label());
        }

        int selectIndex = 0;
        String legacyProvider = envMap.getOrDefault("assistant_provider", "").toLowerCase();
        if (!legacyProvider.isEmpty()) {
            String resolvedId = "anthropic".equals(legacyProvider) ? "claude" : legacyProvider;
            for (int i = 0; i < availableProviders.size(); i++) {
                if (availableProviders.get(i).id().equals(resolvedId)) {
                    selectIndex = i;
                    break;
                }
            }
        }

        if (!availableProviders.isEmpty()) {
            providerCombo.setSelectedIndex(selectIndex);
            populateModels(availableProviders.get(selectIndex));
            String envModel = envMap.getOrDefault("assistant_model", "");
            if (!envModel.isEmpty()) {
                modelCombo.setSelectedItem(envModel);
            }
        }
        suppressComboEvents = false;

        if (!availableProviders.isEmpty()) {
            initAssistant(availableProviders.get(selectIndex), selectedModel());
        }
    }

    public void setFindingsSupplier(Supplier<List<Finding>> supplier) {
        this.findingsSupplier = supplier;
    }

    public void setContextSupplier(Supplier<ScanContext> supplier) {
        this.contextSupplier = supplier;
    }

    public void setDiscoveredPathsSupplier(Supplier<DiscoveredPaths> supplier) {
        this.discoveredPathsSupplier = supplier;
    }

    public JTextField getInputField() {
        return inputField;
    }

    private void onProviderChanged() {
        int idx = providerCombo.getSelectedIndex();
        if (idx < 0 || idx >= availableProviders.size()) {
            return;
        }
        ProviderRegistry.ProviderInfo info = availableProviders.get(idx);
        suppressComboEvents = true;
        populateModels(info);
        suppressComboEvents = false;
        switchProvider(info, info.defaultModel());
    }

    private void onModelChanged() {
        int idx = providerCombo.getSelectedIndex();
        if (idx < 0 || idx >= availableProviders.size()) {
            return;
        }
        switchProvider(availableProviders.get(idx), selectedModel());
    }

    private void populateModels(ProviderRegistry.ProviderInfo info) {
        modelCombo.removeAllItems();
        for (String model : info.models()) {
            modelCombo.addItem(model);
        }
        modelCombo.setSelectedItem(info.defaultModel());
    }

    private String selectedModel() {
        Object item = modelCombo.getSelectedItem();
        return item != null ? item.toString().strip() : "";
    }

    private void switchProvider(ProviderRegistry.ProviderInfo info, String model) {
        chatPane.setText("");
        initAssistant(info, model);
    }

    private void initAssistant(ProviderRegistry.ProviderInfo info, String model) {
        try {
            AssistantConfig config = AssistantConfig.forProvider(info, model, maxTokens);
            if (!config.isConfigured()) {
                appendSystem("No API key for " + info.label() + ". Set " + info.id().toUpperCase()
                        + "_API_KEY in .env.local");
                aiAssistant = null;
                contextBuilder = null;
                return;
            }

            aiAssistant = new AiAssistant(config);
            KnowledgeBase kb = KnowledgeBase.getInstance();
            contextBuilder = new ContextBuilder(findingsSupplier, contextSupplier, kb);

            GetFindingsTool findingsTool = new GetFindingsTool(findingsSupplier);
            QueryKbTool kbTool = new QueryKbTool(kb);
            ExplainCweTool cweTool = new ExplainCweTool(kb);
            GetSitemapTool sitemapTool = new GetSitemapTool(discoveredPathsSupplier);
            GetScanConfigTool configTool = new GetScanConfigTool(contextSupplier);
            SaveDocTool saveDocTool = new SaveDocTool();

            aiAssistant.registerTool(findingsTool.name(), findingsTool::call);
            aiAssistant.registerTool(kbTool.name(), kbTool::call);
            aiAssistant.registerTool(cweTool.name(), cweTool::call);
            aiAssistant.registerTool(sitemapTool.name(), sitemapTool::call);
            aiAssistant.registerTool(configTool.name(), configTool::call);
            aiAssistant.registerTool(saveDocTool.name(), saveDocTool::call);

            appendSystem("AI Assistant ready (" + config.provider() + "/" + config.model()
                    + "). Type your question or use a slash command.");
        } catch (Exception e) {
            appendSystem("Error initializing assistant: " + e.getMessage());
        }
    }

    private void handleSubmit() {
        String text = inputField.getText().strip();
        if (text.isEmpty()) {
            return;
        }
        inputField.setText("");

        if (text.startsWith("/")) {
            handleSlashCommand(text);
            return;
        }

        if (aiAssistant == null) {
            appendSystem("Assistant not configured. Select a provider with an API key.");
            return;
        }

        appendUser(text);
        sendToAssistant(text, contextBuilder.build());
    }

    private void handleSlashCommand(String input) {
        String cmd = input.toLowerCase();
        if ("/clear".equals(cmd)) {
            chatPane.setText("");
            appendSystem("Chat cleared.");
            return;
        }

        appendSystem("Command: " + input);

        if (contextBuilder == null) {
            appendSystem("Assistant not configured.");
            return;
        }

        String[] parts = input.split("\\s+", 2);
        String slashCmd = parts[0].toLowerCase();
        String arg = parts.length > 1 ? parts[1] : "";
        String enriched = contextBuilder.buildWithSlashCommand(slashCmd, arg);

        if (aiAssistant != null) {
            sendToAssistant(input, enriched);
        }
    }

    private void sendToAssistant(String userMessage, String systemPrompt) {
        executor.submit(() -> {
            try {
                String toolsJson = buildToolsJson();
                SwingUtilities.invokeLater(this::startStreaming);
                aiAssistant.sendStreaming(userMessage, systemPrompt, toolsJson, token -> {
                    SwingUtilities.invokeLater(() -> appendStreamToken(token));
                });
                SwingUtilities.invokeLater(this::finishStreaming);
                updateUsageLabel();
            } catch (Exception e) {
                SwingUtilities.invokeLater(() -> appendSystem("Error: " + e.getMessage()));
            }
        });
    }

    private void startStreaming() {
        StyledDocument doc = chatPane.getStyledDocument();
        thinkingStart = doc.getLength();
        appendStyled("Pensando...\n", "system");
    }

    private void appendStreamToken(String token) {
        StyledDocument doc = chatPane.getStyledDocument();
        if (thinkingStart >= 0) {
            try {
                doc.remove(thinkingStart, doc.getLength() - thinkingStart);
            } catch (BadLocationException ignored) {
            }
            thinkingStart = -1;
        }
        try {
            doc.insertString(doc.getLength(), token, doc.getStyle("assistant"));
        } catch (BadLocationException ignored) {
        }
        scrollToBottom();
    }

    private void finishStreaming() {
        StyledDocument doc = chatPane.getStyledDocument();
        try {
            doc.insertString(doc.getLength(), "\n\n", doc.getStyle("assistant"));
        } catch (BadLocationException ignored) {
        }
        scrollToBottom();
    }

    private void appendUser(String msg) {
        appendStyled("> " + msg + "\n", "user");
    }

    private void appendSystem(String msg) {
        appendStyled("[sys] " + msg + "\n", "system");
    }

    private void appendStyled(String text, String styleName) {
        StyledDocument doc = chatPane.getStyledDocument();
        try {
            doc.insertString(doc.getLength(), text, doc.getStyle(styleName));
        } catch (BadLocationException ignored) {
        }
        scrollToBottom();
    }

    private void scrollToBottom() {
        SwingUtilities.invokeLater(() -> {
            JScrollBar vertical = scrollPane.getVerticalScrollBar();
            vertical.setValue(vertical.getMaximum());
        });
    }

    private void updateUsageLabel() {
        if (aiAssistant != null) {
            UsageTracker tracker = aiAssistant.getUsageTracker();
            SwingUtilities.invokeLater(() -> usageLabel.setText(tracker.summary() + "  "));
        }
    }

    private void initStyles() {
        StyledDocument doc = chatPane.getStyledDocument();

        Style userStyle = doc.addStyle("user", null);
        StyleConstants.setForeground(userStyle, USER_COLOR);
        StyleConstants.setFontFamily(userStyle, Font.MONOSPACED);
        StyleConstants.setFontSize(userStyle, 13);

        Style assistantStyle = doc.addStyle("assistant", null);
        StyleConstants.setForeground(assistantStyle, ASSISTANT_COLOR);
        StyleConstants.setFontFamily(assistantStyle, Font.MONOSPACED);
        StyleConstants.setFontSize(assistantStyle, 13);

        Style systemStyle = doc.addStyle("system", null);
        StyleConstants.setForeground(systemStyle, SYSTEM_COLOR);
        StyleConstants.setFontFamily(systemStyle, Font.MONOSPACED);
        StyleConstants.setFontSize(systemStyle, 13);
        StyleConstants.setItalic(systemStyle, true);
    }

    private String buildToolsJson() {
        if (aiAssistant == null) {
            return "[]";
        }
        KnowledgeBase kb = KnowledgeBase.getInstance();
        List<AssistantTool> toolDefs = List.of(new GetFindingsTool(findingsSupplier), new QueryKbTool(kb),
                new ExplainCweTool(kb), new GetSitemapTool(discoveredPathsSupplier),
                new GetScanConfigTool(contextSupplier), new SaveDocTool());
        return ToolSchemaBuilder.buildJson(toolDefs);
    }
}
