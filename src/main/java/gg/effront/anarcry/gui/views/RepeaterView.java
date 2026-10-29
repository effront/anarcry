package gg.effront.anarcry.gui.views;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.KeyStroke;
import javax.swing.SwingUtilities;

import org.fife.ui.rsyntaxtextarea.RSyntaxTextArea;
import org.fife.ui.rsyntaxtextarea.SyntaxConstants;
import org.fife.ui.rsyntaxtextarea.Theme;
import org.fife.ui.rtextarea.RTextScrollPane;

/**
 * HTTP repeater panel with request editor and response viewer using
 * RSyntaxTextArea for syntax highlighting.
 */
public class RepeaterView extends JPanel {

    private static final Color DARK_BG = new Color(0x1E, 0x1E, 0x2E);
    private static final int REQUEST_TIMEOUT_SECONDS = 30;

    private JComboBox<String> methodCombo;
    private JTextField urlField;
    private JButton sendButton;
    private JTextArea headersArea;
    private RSyntaxTextArea requestBody;
    private JLabel statusLabel;
    private RSyntaxTextArea responseBody;
    private JTextArea responseHeaders;

    private final HttpClient httpClient;

    public RepeaterView() {
        super(new BorderLayout());
        httpClient = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NORMAL)
                .connectTimeout(Duration.ofSeconds(REQUEST_TIMEOUT_SECONDS)).build();

        JSplitPane split = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, buildRequestPanel(), buildResponsePanel());
        split.setResizeWeight(0.5);
        add(split, BorderLayout.CENTER);
    }

    public void setTargetUrl(String url) {
        urlField.setText(url);
    }

    private JPanel buildRequestPanel() {
        JPanel panel = new JPanel(new BorderLayout());

        JPanel topBar = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 4));
        methodCombo = new JComboBox<>(new String[]{"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"});
        urlField = new JTextField(40);
        urlField.setText("https://");
        sendButton = new JButton("Send");
        sendButton.addActionListener(e -> sendRequest());

        topBar.add(methodCombo);
        topBar.add(urlField);
        topBar.add(sendButton);
        panel.add(topBar, BorderLayout.NORTH);

        JPanel centerPanel = new JPanel(new BorderLayout());

        JLabel headersLabel = new JLabel("  Headers (Key: Value, one per line):");
        headersArea = new JTextArea(5, 40);
        headersArea.setFont(monoFont());
        headersArea.setText("User-Agent: AnarCry/1.2\nAccept: */*");
        JScrollPane headersScroll = new JScrollPane(headersArea);
        headersScroll.setPreferredSize(new Dimension(0, 100));

        JPanel headersPanel = new JPanel(new BorderLayout());
        headersPanel.add(headersLabel, BorderLayout.NORTH);
        headersPanel.add(headersScroll, BorderLayout.CENTER);

        requestBody = createSyntaxArea(false);
        requestBody.setSyntaxEditingStyle(SyntaxConstants.SYNTAX_STYLE_NONE);
        RTextScrollPane bodyScroll = new RTextScrollPane(requestBody);

        JPanel bodyPanel = new JPanel(new BorderLayout());
        bodyPanel.add(new JLabel("  Body:"), BorderLayout.NORTH);
        bodyPanel.add(bodyScroll, BorderLayout.CENTER);

        JSplitPane reqSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT, headersPanel, bodyPanel);
        reqSplit.setResizeWeight(0.3);
        centerPanel.add(reqSplit, BorderLayout.CENTER);

        panel.add(centerPanel, BorderLayout.CENTER);

        registerSendShortcut(panel);

        return panel;
    }

    private JPanel buildResponsePanel() {
        JPanel panel = new JPanel(new BorderLayout());

        statusLabel = new JLabel("  No response yet");
        panel.add(statusLabel, BorderLayout.NORTH);

        responseBody = createSyntaxArea(true);
        responseBody.setSyntaxEditingStyle(SyntaxConstants.SYNTAX_STYLE_NONE);
        RTextScrollPane bodyScroll = new RTextScrollPane(responseBody);

        JLabel respHeadersLabel = new JLabel("  Response Headers:");
        responseHeaders = new JTextArea(5, 40);
        responseHeaders.setEditable(false);
        responseHeaders.setFont(monoFont());
        JScrollPane respHeadersScroll = new JScrollPane(responseHeaders);
        respHeadersScroll.setPreferredSize(new Dimension(0, 120));

        JPanel headersPanel = new JPanel(new BorderLayout());
        headersPanel.add(respHeadersLabel, BorderLayout.NORTH);
        headersPanel.add(respHeadersScroll, BorderLayout.CENTER);

        JSplitPane respSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT, bodyScroll, headersPanel);
        respSplit.setResizeWeight(0.7);
        panel.add(respSplit, BorderLayout.CENTER);

        return panel;
    }

    private void sendRequest() {
        String method = (String) methodCombo.getSelectedItem();
        String url = urlField.getText().trim();
        if (url.isBlank() || "https://".equals(url)) {
            statusLabel.setText("  URL required");
            return;
        }

        sendButton.setEnabled(false);
        statusLabel.setText("  Sending...");
        responseBody.setText("");
        responseHeaders.setText("");

        String body = requestBody.getText();
        String rawHeaders = headersArea.getText();

        Thread.ofVirtual().name("repeater-send").start(() -> {
            try {
                HttpRequest.Builder builder = HttpRequest.newBuilder().uri(URI.create(url))
                        .timeout(Duration.ofSeconds(REQUEST_TIMEOUT_SECONDS));

                applyHeaders(builder, rawHeaders);
                applyMethod(builder, method, body);

                long start = System.nanoTime();
                HttpResponse<String> resp = httpClient.send(builder.build(), HttpResponse.BodyHandlers.ofString());
                long elapsedMs = (System.nanoTime() - start) / 1_000_000;

                SwingUtilities.invokeLater(() -> displayResponse(resp, elapsedMs));
            } catch (IllegalArgumentException ex) {
                SwingUtilities.invokeLater(() -> statusLabel.setText("  Invalid URL: " + ex.getMessage()));
            } catch (Exception ex) {
                SwingUtilities.invokeLater(() -> statusLabel.setText("  Error: " + ex.getMessage()));
            } finally {
                SwingUtilities.invokeLater(() -> sendButton.setEnabled(true));
            }
        });
    }

    private void displayResponse(HttpResponse<String> resp, long elapsedMs) {
        int code = resp.statusCode();
        long contentLength = resp.body().length();
        statusLabel.setText(String.format("  %d - %dms - %d bytes", code, elapsedMs, contentLength));

        String respBodyText = resp.body();
        responseBody.setText(respBodyText);
        responseBody.setCaretPosition(0);
        responseBody.setSyntaxEditingStyle(detectSyntax(resp));

        StringBuilder hdr = new StringBuilder();
        resp.headers().map().forEach((k, values) -> {
            for (String v : values) {
                hdr.append(k).append(": ").append(v).append("\n");
            }
        });
        responseHeaders.setText(hdr.toString());

        sendButton.setEnabled(true);
    }

    private static String detectSyntax(HttpResponse<String> resp) {
        String ct = resp.headers().firstValue("content-type").orElse("").toLowerCase();
        if (ct.contains("json")) {
            return SyntaxConstants.SYNTAX_STYLE_JSON;
        }
        if (ct.contains("html")) {
            return SyntaxConstants.SYNTAX_STYLE_HTML;
        }
        if (ct.contains("xml")) {
            return SyntaxConstants.SYNTAX_STYLE_XML;
        }
        if (ct.contains("javascript")) {
            return SyntaxConstants.SYNTAX_STYLE_JAVASCRIPT;
        }
        if (ct.contains("css")) {
            return SyntaxConstants.SYNTAX_STYLE_CSS;
        }
        return SyntaxConstants.SYNTAX_STYLE_NONE;
    }

    private static void applyHeaders(HttpRequest.Builder builder, String rawHeaders) {
        for (String line : rawHeaders.split("\n")) {
            String trimmed = line.trim();
            if (trimmed.isBlank()) {
                continue;
            }
            int sep = trimmed.indexOf(':');
            if (sep > 0) {
                String key = trimmed.substring(0, sep).trim();
                String val = trimmed.substring(sep + 1).trim();
                builder.header(key, val);
            }
        }
    }

    private static void applyMethod(HttpRequest.Builder builder, String method, String body) {
        boolean hasBody = body != null && !body.isBlank();
        switch (method) {
            case "GET" -> builder.GET();
            case "DELETE" -> builder.DELETE();
            case "HEAD" -> builder.method("HEAD", HttpRequest.BodyPublishers.noBody());
            case "OPTIONS" -> builder.method("OPTIONS", HttpRequest.BodyPublishers.noBody());
            case "POST" -> builder.POST(HttpRequest.BodyPublishers.ofString(hasBody ? body : ""));
            case "PUT" -> builder.PUT(HttpRequest.BodyPublishers.ofString(hasBody ? body : ""));
            case "PATCH" -> builder.method("PATCH", HttpRequest.BodyPublishers.ofString(hasBody ? body : ""));
            default -> builder.GET();
        }
    }

    private RSyntaxTextArea createSyntaxArea(boolean readOnly) {
        RSyntaxTextArea area = new RSyntaxTextArea(20, 60);
        area.setEditable(!readOnly);
        area.setCodeFoldingEnabled(true);
        area.setAntiAliasingEnabled(true);
        area.setTabSize(2);
        applyDarkTheme(area);
        return area;
    }

    private void applyDarkTheme(RSyntaxTextArea area) {
        try {
            Theme theme = Theme.load(getClass().getResourceAsStream("/org/fife/ui/rsyntaxtextarea/themes/dark.xml"));
            theme.apply(area);
        } catch (Exception e) {
            area.setBackground(DARK_BG);
            area.setForeground(Color.WHITE);
            area.setCaretColor(Color.WHITE);
            area.setCurrentLineHighlightColor(new Color(0x2A, 0x2A, 0x3E));
        }
    }

    private void registerSendShortcut(JPanel panel) {
        KeyStroke ctrlEnter = KeyStroke.getKeyStroke(KeyEvent.VK_ENTER, InputEvent.CTRL_DOWN_MASK);
        panel.registerKeyboardAction(e -> sendRequest(), ctrlEnter, JComponent.WHEN_ANCESTOR_OF_FOCUSED_COMPONENT);
    }

    private static Font monoFont() {
        return new Font(Font.MONOSPACED, Font.PLAIN, 12);
    }
}
