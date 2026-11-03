package gg.effront.anarcry.gui.views;

import gg.effront.anarcry.assistant.AiAssistant;
import gg.effront.anarcry.assistant.AssistantConfig;
import gg.effront.anarcry.assistant.ContextBuilder;
import gg.effront.anarcry.assistant.UsageTracker;
import gg.effront.anarcry.assistant.tools.AssistantTool;
import gg.effront.anarcry.assistant.tools.ExplainCweTool;
import gg.effront.anarcry.assistant.tools.GetFindingsTool;
import gg.effront.anarcry.assistant.tools.GetScanConfigTool;
import gg.effront.anarcry.assistant.tools.GetSitemapTool;
import gg.effront.anarcry.assistant.tools.QueryKbTool;
import gg.effront.anarcry.model.Finding;
import gg.effront.anarcry.model.KnowledgeBase;
import gg.effront.anarcry.scanner.DiscoveredPaths;
import gg.effront.anarcry.scanner.ScanContext;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Font;
import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.function.Supplier;

import javax.swing.JButton;
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
    private static final Font CHAT_FONT = new Font(Font.MONOSPACED, Font.PLAIN, 13);
    private static final Font INPUT_FONT = new Font(Font.MONOSPACED, Font.PLAIN, 14);

    private final JTextPane chatPane;
    private final JTextField inputField;
    private final JLabel usageLabel;
    private final JScrollPane scrollPane;

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

    public AssistantView() {
        super(new BorderLayout(0, 4));
        setBackground(DARK_BG);

        chatPane = new JTextPane();
        chatPane.setEditable(false);
        chatPane.setBackground(DARK_BG);
        chatPane.setFont(CHAT_FONT);
        initStyles();

        scrollPane = new JScrollPane(chatPane);
        scrollPane.setBorder(null);
        add(scrollPane, BorderLayout.CENTER);

        JPanel bottomPanel = new JPanel(new BorderLayout(4, 0));
        bottomPanel.setBackground(DARK_BG);

        JLabel hintLabel = new JLabel(" /findings /explain /remediate /plan /kb /report /clear");
        hintLabel.setForeground(new Color(0x88, 0x88, 0x99));
        hintLabel.setFont(CHAT_FONT);

        inputField = new JTextField();
        inputField.setBackground(INPUT_BG);
        inputField.setForeground(ASSISTANT_COLOR);
        inputField.setCaretColor(ASSISTANT_COLOR);
        inputField.setFont(INPUT_FONT);
        inputField.setBorder(javax.swing.BorderFactory.createCompoundBorder(
                javax.swing.BorderFactory.createLineBorder(new Color(0x44, 0x44, 0x55)),
                javax.swing.BorderFactory.createEmptyBorder(6, 8, 6, 8)));

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
        usageLabel.setForeground(new Color(0x88, 0x88, 0x99));
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
        AssistantConfig config = AssistantConfig.fromEnv(envMap);
        if (!config.isConfigured()) {
            appendSystem(
                    "AI Assistant not configured. " + "Set ASSISTANT_PROVIDER and ASSISTANT_API_KEY in .env.local");
            return;
        }

        try {
            aiAssistant = new AiAssistant(config);
            KnowledgeBase kb = KnowledgeBase.getInstance();
            contextBuilder = new ContextBuilder(findingsSupplier, contextSupplier, kb);

            GetFindingsTool findingsTool = new GetFindingsTool(findingsSupplier);
            QueryKbTool kbTool = new QueryKbTool(kb);
            ExplainCweTool cweTool = new ExplainCweTool(kb);
            GetSitemapTool sitemapTool = new GetSitemapTool(discoveredPathsSupplier);
            GetScanConfigTool configTool = new GetScanConfigTool(contextSupplier);

            aiAssistant.registerTool(findingsTool.name(), findingsTool::call);
            aiAssistant.registerTool(kbTool.name(), kbTool::call);
            aiAssistant.registerTool(cweTool.name(), cweTool::call);
            aiAssistant.registerTool(sitemapTool.name(), sitemapTool::call);
            aiAssistant.registerTool(configTool.name(), configTool::call);

            appendSystem("AI Assistant ready (" + config.provider() + "/" + config.model()
                    + "). Type your question or use a slash command.");
        } catch (Exception e) {
            appendSystem("Error initializing assistant: " + e.getMessage());
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
            appendSystem("Assistant not configured. Set ASSISTANT_PROVIDER in .env.local");
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
        appendStyled("", "assistant");
    }

    private void appendStreamToken(String token) {
        StyledDocument doc = chatPane.getStyledDocument();
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
                new GetScanConfigTool(contextSupplier));
        var tools = new com.google.gson.JsonArray();
        for (AssistantTool tool : toolDefs) {
            var fn = new com.google.gson.JsonObject();
            fn.addProperty("name", tool.name());
            fn.addProperty("description", tool.description());
            fn.add("parameters", com.google.gson.JsonParser.parseString(tool.paramsSchema()));
            tools.add(fn);
        }
        return tools.toString();
    }
}
