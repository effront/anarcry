package gg.effront.anarcry.tui;

import com.googlecode.lanterna.TerminalSize;
import com.googlecode.lanterna.gui2.TextBox;
import com.googlecode.lanterna.input.KeyStroke;
import com.googlecode.lanterna.input.KeyType;

import java.io.IOException;

public class PasteableTextBox extends TextBox {

    public PasteableTextBox(TerminalSize size) {
        super(size);
    }

    public PasteableTextBox(TerminalSize size, Style style) {
        super(size, style);
    }

    @Override
    public synchronized Result handleKeyStroke(KeyStroke key) {
        // Ctrl+V (char \u0016) ou Ctrl+Shift+V
        if (key.getKeyType() == KeyType.Character && key.isCtrlDown()
                && (key.getCharacter() == '\u0016' || key.getCharacter() == 'v' || key.getCharacter() == 'V')) {
            String clip = readClipboard();
            if (clip != null && !clip.isBlank()) {
                setText(getText() + clip.stripTrailing());
            }
            return Result.HANDLED;
        }
        return super.handleKeyStroke(key);
    }

    private String readClipboard() {
        String[][] cmds = {
            {"xclip", "-selection", "clipboard", "-o"},
            {"xsel",  "--clipboard", "--output"},
            {"wl-paste", "--no-newline"}
        };
        for (String[] cmd : cmds) {
            try {
                Process p = Runtime.getRuntime().exec(cmd);
                String out = new String(p.getInputStream().readAllBytes());
                if (p.waitFor() == 0) return out;
            } catch (IOException | InterruptedException ignored) {}
        }
        return null;
    }
}
