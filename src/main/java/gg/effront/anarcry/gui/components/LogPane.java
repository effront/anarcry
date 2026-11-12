package gg.effront.anarcry.gui.components;

import gg.effront.anarcry.gui.PrivacyFilter;

import java.awt.BasicStroke;
import java.awt.Color;
import java.awt.Component;
import java.awt.Cursor;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.RenderingHints;
import java.awt.Toolkit;
import java.awt.datatransfer.StringSelection;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;

import javax.swing.BorderFactory;
import javax.swing.BoundedRangeModel;
import javax.swing.Icon;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPopupMenu;
import javax.swing.JScrollBar;
import javax.swing.JScrollPane;
import javax.swing.JTextPane;
import javax.swing.JToggleButton;
import javax.swing.SwingUtilities;
import javax.swing.text.AttributeSet;
import javax.swing.text.BadLocationException;
import javax.swing.text.DefaultCaret;
import javax.swing.text.Document;
import javax.swing.text.Element;
import javax.swing.text.SimpleAttributeSet;
import javax.swing.text.StyleConstants;

/**
 * Scrollable log pane with color-coded lines and a floating debug toggle.
 * Thread-safe: callers may invoke {@link #log} from any thread.
 */
public class LogPane extends JPanel {

    private static final int MAX_LINES = 5000;
    private static final int BTN_SIZE = 28;
    private static final int BTN_MARGIN = 8;
    private static final int ICON_SIZE = 16;

    private static final Color COLOR_RED = new Color(0xF8, 0x51, 0x49);
    private static final Color COLOR_GREEN = new Color(0x3F, 0xB9, 0x50);
    private static final Color COLOR_BLUE = new Color(0x58, 0xA6, 0xFF);
    private static final Color COLOR_GRAY = new Color(0x8B, 0x94, 0x9E);
    private static Color bgLog() {
        return gg.effront.anarcry.gui.theme.AnarCryLaf.bgDark();
    }

    private static Color btnBg() {
        return gg.effront.anarcry.gui.theme.AnarCryLaf.buttonBg();
    }

    private static Color btnBgOn() {
        return gg.effront.anarcry.gui.theme.AnarCryLaf.buttonBgOn();
    }

    private static Color btnBorder() {
        return gg.effront.anarcry.gui.theme.AnarCryLaf.border();
    }

    private final JScrollPane scrollPane;
    private final JTextPane textPane;
    private final JToggleButton debugToggle;
    private final List<String> rawMessages = new ArrayList<>();

    public LogPane() {
        super(null);

        textPane = new JTextPane();
        textPane.setEditable(false);
        ((DefaultCaret) textPane.getCaret()).setUpdatePolicy(DefaultCaret.NEVER_UPDATE);
        textPane.setFont(resolveMonoFont());
        textPane.setBackground(bgLog());
        textPane.setForeground(gg.effront.anarcry.gui.theme.AnarCryLaf.fg());

        scrollPane = new JScrollPane(textPane);
        scrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);
        scrollPane.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
        scrollPane.setBorder(BorderFactory.createEmptyBorder());
        add(scrollPane);

        debugToggle = createDebugToggle();
        add(debugToggle);
        setComponentZOrder(debugToggle, 0);

        PrivacyFilter.addListener(() -> SwingUtilities.invokeLater(this::rerender));
        installContextMenu();
    }

    @Override
    public boolean isOptimizedDrawingEnabled() {
        return false;
    }

    @Override
    public void doLayout() {
        int w = getWidth();
        int h = getHeight();
        scrollPane.setBounds(0, 0, w, h);
        debugToggle.setBounds(w - BTN_SIZE - BTN_MARGIN, BTN_MARGIN, BTN_SIZE, BTN_SIZE);
    }

    private JToggleButton createDebugToggle() {
        JToggleButton btn = new JToggleButton();
        btn.setIcon(bugIcon(ICON_SIZE, COLOR_GRAY));
        btn.setSelectedIcon(bugIcon(ICON_SIZE, COLOR_GREEN));
        btn.setToolTipText("Debug Logging -- verbose HTTP/WAF/challenge diagnostics");
        btn.setPreferredSize(new Dimension(BTN_SIZE, BTN_SIZE));
        btn.setFocusPainted(false);
        btn.setOpaque(true);
        btn.setBackground(btnBg());
        btn.setBorder(BorderFactory.createLineBorder(btnBorder()));
        btn.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        btn.addChangeListener(e -> btn.setBackground(btn.isSelected() ? btnBgOn() : btnBg()));
        return btn;
    }

    private static Icon bugIcon(int size, Color color) {
        return new Icon() {
            @Override
            public void paintIcon(Component c, Graphics g, int x, int y) {
                Graphics2D g2 = (Graphics2D) g.create();
                g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
                g2.setColor(color);

                int cx = x + size / 2;

                // Head
                int headR = size / 6;
                int headY = y + size / 5;
                g2.fillOval(cx - headR, headY - headR, headR * 2, headR * 2);

                // Antennae
                g2.setStroke(new BasicStroke(1.3f, BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND));
                g2.drawLine(cx - headR + 1, headY - headR + 1, cx - size / 3, y);
                g2.drawLine(cx + headR - 1, headY - headR + 1, cx + size / 3, y);

                // Body
                int bw = size * 5 / 12;
                int bTop = headY + headR;
                int bH = size - bTop + y - 1;
                g2.fillRoundRect(cx - bw, bTop, bw * 2, bH, 4, 4);

                // Wing seam
                g2.setColor(c != null && c.getBackground() != null ? c.getBackground() : btnBg());
                g2.setStroke(new BasicStroke(1.0f));
                g2.drawLine(cx, bTop + 1, cx, bTop + bH - 2);

                // Legs
                g2.setColor(color);
                g2.setStroke(new BasicStroke(1.2f, BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND));
                int legOut = size / 4;
                for (int i = 0; i < 3; i++) {
                    int ly = bTop + 2 + i * (bH - 4) / 2;
                    int angle = (i - 1) * size / 8;
                    g2.drawLine(cx - bw, ly, cx - bw - legOut, ly + angle);
                    g2.drawLine(cx + bw, ly, cx + bw + legOut, ly + angle);
                }

                g2.dispose();
            }

            @Override
            public int getIconWidth() {
                return size;
            }

            @Override
            public int getIconHeight() {
                return size;
            }
        };
    }

    // ---------------------------------------------------------------------------
    // Public API
    // ---------------------------------------------------------------------------

    public boolean isDebugEnabled() {
        return debugToggle.isSelected();
    }

    /**
     * Append a log line with automatic color coding. Safe to call from any thread.
     */
    public void log(String message) {
        SwingUtilities.invokeLater(() -> {
            boolean follow = isScrolledToBottom();
            rawMessages.add(message);
            while (rawMessages.size() > MAX_LINES) {
                rawMessages.removeFirst();
            }
            String display = PrivacyFilter.apply(message);
            AttributeSet attrs = attrsFor(message);
            Document doc = textPane.getDocument();
            try {
                if (doc.getLength() > 0) {
                    doc.insertString(doc.getLength(), "\n", attrs);
                }
                doc.insertString(doc.getLength(), display, attrs);
            } catch (BadLocationException ignored) {
                // should not happen
            }
            trimExcessLines(doc);
            if (follow) {
                textPane.setCaretPosition(doc.getLength());
            }
        });
    }

    /** Returns a snapshot of all raw (unfiltered) log messages. */
    public List<String> getRawMessages() {
        return List.copyOf(rawMessages);
    }

    /** Clear all log content. Safe to call from any thread. */
    public void clear() {
        SwingUtilities.invokeLater(() -> {
            rawMessages.clear();
            try {
                Document doc = textPane.getDocument();
                doc.remove(0, doc.getLength());
            } catch (BadLocationException ignored) {
                // should not happen
            }
        });
    }

    // ---------------------------------------------------------------------------
    // Internals
    // ---------------------------------------------------------------------------

    private boolean isScrolledToBottom() {
        JScrollBar vbar = scrollPane.getVerticalScrollBar();
        BoundedRangeModel model = vbar.getModel();
        return model.getValue() + model.getExtent() >= model.getMaximum() - 20;
    }

    private void installContextMenu() {
        JPopupMenu menu = new JPopupMenu();
        JMenuItem copyAll = new JMenuItem("Copy All");
        copyAll.addActionListener(e -> {
            String text = String.join("\n", rawMessages);
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(text), null);
        });
        JMenuItem exportLog = new JMenuItem("Export Log");
        exportLog.addActionListener(e -> exportToFile());
        menu.add(copyAll);
        menu.add(exportLog);
        textPane.addMouseListener(new MouseAdapter() {
            @Override
            public void mousePressed(MouseEvent ev) {
                showPopup(ev);
            }

            @Override
            public void mouseReleased(MouseEvent ev) {
                showPopup(ev);
            }

            private void showPopup(MouseEvent ev) {
                if (ev.isPopupTrigger()) {
                    menu.show(ev.getComponent(), ev.getX(), ev.getY());
                }
            }
        });
    }

    private void exportToFile() {
        if (rawMessages.isEmpty()) {
            return;
        }
        try {
            Path reportsDir = Path.of(System.getProperty("user.home"), ".anarcry", "reports");
            Files.createDirectories(reportsDir);
            String ts = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss"));
            Path outFile = reportsDir.resolve("scan-log-" + ts + ".txt");
            Files.write(outFile, rawMessages);
            JOptionPane.showMessageDialog(this, "Log exportado: " + outFile, "Export Log",
                    JOptionPane.INFORMATION_MESSAGE);
        } catch (IOException ex) {
            JOptionPane.showMessageDialog(this, "Erro ao exportar: " + ex.getMessage(), "Export Log",
                    JOptionPane.ERROR_MESSAGE);
        }
    }

    private AttributeSet attrsFor(String message) {
        SimpleAttributeSet attrs = new SimpleAttributeSet();
        Color fg;
        if (message.startsWith("[!]")) {
            fg = COLOR_RED;
        } else if (message.startsWith("[+]")) {
            fg = COLOR_GREEN;
        } else if (message.startsWith("[*]")) {
            fg = COLOR_BLUE;
        } else if (message.startsWith("[~]")) {
            fg = COLOR_GRAY;
        } else {
            fg = textPane.getForeground();
        }
        StyleConstants.setForeground(attrs, fg);
        return attrs;
    }

    private void rerender() {
        Document doc = textPane.getDocument();
        try {
            doc.remove(0, doc.getLength());
        } catch (BadLocationException ignored) {
            return;
        }
        for (String raw : rawMessages) {
            String display = PrivacyFilter.apply(raw);
            AttributeSet attrs = attrsFor(raw);
            try {
                if (doc.getLength() > 0) {
                    doc.insertString(doc.getLength(), "\n", attrs);
                }
                doc.insertString(doc.getLength(), display, attrs);
            } catch (BadLocationException ignored) {
                break;
            }
        }
        if (doc.getLength() > 0) {
            textPane.setCaretPosition(doc.getLength());
        }
    }

    private void trimExcessLines(Document doc) {
        int lineCount = doc.getDefaultRootElement().getElementCount();
        if (lineCount <= MAX_LINES) {
            return;
        }
        Element first = doc.getDefaultRootElement().getElement(0);
        try {
            doc.remove(first.getStartOffset(), first.getEndOffset());
        } catch (BadLocationException ignored) {
            // should not happen
        }
    }

    private static Font resolveMonoFont() {
        String[] candidates = {"JetBrains Mono", "Consolas", Font.MONOSPACED};
        for (String name : candidates) {
            Font f = new Font(name, Font.PLAIN, 12);
            if (f.getFamily().equalsIgnoreCase(name) || name.equals(Font.MONOSPACED)) {
                return f;
            }
        }
        return new Font(Font.MONOSPACED, Font.PLAIN, 12);
    }
}
