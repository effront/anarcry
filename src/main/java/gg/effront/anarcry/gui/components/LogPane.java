package gg.effront.anarcry.gui.components;

import gg.effront.anarcry.gui.PrivacyFilter;

import java.awt.Color;
import java.awt.Font;

import javax.swing.JScrollPane;
import javax.swing.JTextPane;
import javax.swing.SwingUtilities;
import javax.swing.text.AttributeSet;
import javax.swing.text.BadLocationException;
import javax.swing.text.Document;
import javax.swing.text.Element;
import javax.swing.text.SimpleAttributeSet;
import javax.swing.text.StyleConstants;

/**
 * Scrollable log pane with color-coded lines. Thread-safe: callers may invoke
 * {@link #log} from any thread.
 */
public class LogPane extends JScrollPane {

    private static final int MAX_LINES = 500;

    private static final Color COLOR_RED = new Color(0xF8, 0x51, 0x49);
    private static final Color COLOR_GREEN = new Color(0x3F, 0xB9, 0x50);
    private static final Color COLOR_BLUE = new Color(0x58, 0xA6, 0xFF);
    private static final Color COLOR_GRAY = new Color(0x8B, 0x94, 0x9E);

    private final JTextPane textPane;

    public LogPane() {
        textPane = new JTextPane();
        textPane.setEditable(false);
        textPane.setFont(resolveMonoFont());
        textPane.setBackground(new Color(0x2B, 0x2B, 0x2B));
        textPane.setForeground(new Color(0xCE, 0xCE, 0xCE));
        setViewportView(textPane);
        setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);
        setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
    }

    /**
     * Append a log line with automatic color coding. Safe to call from any thread.
     */
    public void log(String message) {
        SwingUtilities.invokeLater(() -> {
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
            textPane.setCaretPosition(doc.getLength());
        });
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

    /** Clear all log content. Safe to call from any thread. */
    public void clear() {
        SwingUtilities.invokeLater(() -> {
            try {
                Document doc = textPane.getDocument();
                doc.remove(0, doc.getLength());
            } catch (BadLocationException ignored) {
                // should not happen
            }
        });
    }

    private void trimExcessLines(Document doc) {
        Element root = doc.getDefaultRootElement();
        while (root.getElementCount() > MAX_LINES) {
            Element first = root.getElement(0);
            try {
                doc.remove(first.getStartOffset(), first.getEndOffset());
            } catch (BadLocationException ignored) {
                break;
            }
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
