package gg.effront.anarcry.tui.panels;

import com.googlecode.lanterna.TerminalSize;
import com.googlecode.lanterna.TextColor;
import com.googlecode.lanterna.gui2.BorderLayout;
import com.googlecode.lanterna.gui2.Borders;
import com.googlecode.lanterna.gui2.Direction;
import com.googlecode.lanterna.gui2.Label;
import com.googlecode.lanterna.gui2.LinearLayout;
import com.googlecode.lanterna.gui2.Panel;
import com.googlecode.lanterna.gui2.TextBox;
import gg.effront.anarcry.tui.PasteableTextBox;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;

public class AssistantPanel extends Panel {

    private static final int MAX_HISTORY = 500;
    private static final String USER_PREFIX = "> ";
    private static final String SYSTEM_PREFIX = "[sys] ";

    private final Panel chatArea;
    private final PasteableTextBox inputBox;
    private final Label hintLabel;
    private final Label usageLabel;
    private final List<ChatLine> chatLines = new ArrayList<>();
    private final boolean configured;

    private int viewHeight;
    private int viewStart = 0;
    private Consumer<String> onSend;
    private Consumer<String> onSlashCommand;
    private StringBuilder streamingBuffer;

    private record ChatLine(String text, Role role) {
    }

    public enum Role {
        USER, ASSISTANT, SYSTEM
    }

    public AssistantPanel(int height, boolean configured) {
        super(new BorderLayout());
        this.viewHeight = Math.max(3, height - 4);
        this.configured = configured;

        chatArea = new Panel(new LinearLayout(Direction.VERTICAL));
        inputBox = new PasteableTextBox(new TerminalSize(0, 1));
        hintLabel = new Label(" /findings /explain /plan /kb /clear /provider /model  |  Enter: send");
        hintLabel.setForegroundColor(TextColor.ANSI.WHITE);
        usageLabel = new Label("");
        usageLabel.setForegroundColor(TextColor.ANSI.CYAN);

        var centerPanel = new Panel(new BorderLayout());
        centerPanel.addComponent(chatArea.withBorder(Borders.singleLine("Chat")), BorderLayout.Location.CENTER);

        var hintRow = new Panel(new BorderLayout());
        hintRow.addComponent(hintLabel, BorderLayout.Location.LEFT);
        hintRow.addComponent(usageLabel, BorderLayout.Location.RIGHT);

        var bottomPanel = new Panel(new LinearLayout(Direction.VERTICAL));
        bottomPanel.addComponent(hintRow);
        bottomPanel.addComponent(inputBox);

        addComponent(centerPanel, BorderLayout.Location.CENTER);
        addComponent(bottomPanel, BorderLayout.Location.BOTTOM);

        if (!configured) {
            addSystemMessage(
                    "No API keys configured. Set GEMINI_API_KEY, ANTHROPIC_API_KEY, or OPENAI_API_KEY in .env.local");
        } else {
            addSystemMessage("AI Assistant ready. Type your question or use a slash command.");
        }
    }

    public void setOnSend(Consumer<String> onSend) {
        this.onSend = onSend;
    }

    public void setOnSlashCommand(Consumer<String> onSlashCommand) {
        this.onSlashCommand = onSlashCommand;
    }

    public TextBox getInputBox() {
        return inputBox;
    }

    public boolean handleEnter() {
        String text = inputBox.getText().strip();
        if (text.isEmpty()) {
            return false;
        }
        inputBox.setText("");

        if (text.startsWith("/")) {
            handleSlash(text);
            return true;
        }

        if (!configured) {
            addSystemMessage("No API keys configured. Use /provider to check available providers.");
            return true;
        }

        addUserMessage(text);
        if (onSend != null) {
            onSend.accept(text);
        }
        return true;
    }

    private void handleSlash(String input) {
        String cmd = input.toLowerCase();
        if (cmd.equals("/clear")) {
            chatLines.clear();
            viewStart = 0;
            repaintChat();
            addSystemMessage("Chat cleared.");
            return;
        }

        addSystemMessage("Command: " + input);
        if (onSlashCommand != null) {
            onSlashCommand.accept(input);
        }
    }

    public void addUserMessage(String msg) {
        for (String line : msg.split("\n")) {
            appendLine(new ChatLine(USER_PREFIX + line, Role.USER));
        }
        repaintChat();
    }

    public void addAssistantMessage(String msg) {
        for (String line : msg.split("\n")) {
            appendLine(new ChatLine(line, Role.ASSISTANT));
        }
        appendLine(new ChatLine("", Role.ASSISTANT));
        repaintChat();
    }

    public void addSystemMessage(String msg) {
        appendLine(new ChatLine(SYSTEM_PREFIX + msg, Role.SYSTEM));
        repaintChat();
    }

    public void startAssistantMessage() {
        streamingBuffer = new StringBuilder();
        appendLine(new ChatLine("...", Role.ASSISTANT));
        repaintChat();
    }

    public void appendToken(String token) {
        if (streamingBuffer == null) {
            streamingBuffer = new StringBuilder();
        }
        streamingBuffer.append(token);

        if (!chatLines.isEmpty()) {
            chatLines.remove(chatLines.size() - 1);
        }

        String current = streamingBuffer.toString();
        String[] lines = current.split("\n", -1);
        for (int i = 0; i < lines.length; i++) {
            appendLine(new ChatLine(lines[i], Role.ASSISTANT));
        }
        scrollToBottom();
        repaintChat();
    }

    public void finishAssistantMessage() {
        if (streamingBuffer != null && !chatLines.isEmpty()) {
            appendLine(new ChatLine("", Role.ASSISTANT));
        }
        streamingBuffer = null;
        repaintChat();
    }

    public void updateUsage(String summary) {
        usageLabel.setText(summary + "  ");
    }

    public void scrollUp(int n) {
        viewStart = Math.max(0, viewStart - n);
        repaintChat();
    }

    public void scrollDown(int n) {
        viewStart = Math.min(Math.max(0, chatLines.size() - viewHeight), viewStart + n);
        repaintChat();
    }

    private void appendLine(ChatLine line) {
        chatLines.add(line);
        if (chatLines.size() > MAX_HISTORY) {
            chatLines.remove(0);
            viewStart = Math.max(0, viewStart - 1);
        }
        scrollToBottom();
    }

    private void scrollToBottom() {
        viewStart = Math.max(0, chatLines.size() - viewHeight);
    }

    private void repaintChat() {
        chatArea.removeAllComponents();
        int end = Math.min(chatLines.size(), viewStart + viewHeight);
        for (int i = viewStart; i < end; i++) {
            ChatLine cl = chatLines.get(i);
            Label lbl = new Label(cl.text());
            lbl.setForegroundColor(colorFor(cl.role()));
            chatArea.addComponent(lbl);
        }
        chatArea.invalidate();
        invalidate();
    }

    private static TextColor colorFor(Role role) {
        return switch (role) {
            case USER -> TextColor.ANSI.GREEN;
            case ASSISTANT -> TextColor.ANSI.WHITE;
            case SYSTEM -> TextColor.ANSI.YELLOW;
        };
    }
}
