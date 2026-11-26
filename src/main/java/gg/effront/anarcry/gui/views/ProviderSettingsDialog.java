package gg.effront.anarcry.gui.views;

import gg.effront.anarcry.assistant.ProviderConfigStore;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.Window;
import java.util.LinkedHashMap;
import java.util.Map;

import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextField;
import javax.swing.border.EmptyBorder;

/**
 * Dialog for configuring AI provider API keys. Auto-detects installed CLIs and
 * env vars, lets users add/edit keys, and persists to
 * ~/.anarcry/providers.json.
 */
public final class ProviderSettingsDialog extends JDialog {

    private static final ProviderEntry[] PROVIDERS = {
            new ProviderEntry("anthropic_api_key", "Claude (Anthropic)", "sk-ant-..."),
            new ProviderEntry("openai_api_key", "OpenAI", "sk-..."),
            new ProviderEntry("gemini_api_key", "Gemini (Google)", "AI..."),
            new ProviderEntry("deepseek_api_key", "DeepSeek", "sk-..."),
            new ProviderEntry("openrouter_api_key", "OpenRouter", "sk-or-..."),
            new ProviderEntry("notholy_api_key", "NotHoly", "nh_cli_... (auto-detected from CLI)"),
            new ProviderEntry("ollama_url", "Ollama (URL)", "http://localhost:11434"),};

    private final Map<String, JTextField> fields = new LinkedHashMap<>();
    private final Map<String, String> envLocal;
    private boolean saved;

    public ProviderSettingsDialog(Window owner, Map<String, String> envLocal) {
        super(owner, "AI Provider Settings", ModalityType.APPLICATION_MODAL);
        this.envLocal = envLocal != null ? envLocal : Map.of();
        setDefaultCloseOperation(DISPOSE_ON_CLOSE);
        setResizable(true);
        buildUi();
        pack();
        setMinimumSize(new Dimension(520, 400));
        setLocationRelativeTo(owner);
    }

    public boolean wasSaved() {
        return saved;
    }

    private void buildUi() {
        JPanel content = new JPanel(new BorderLayout(0, 12));
        content.setBorder(new EmptyBorder(16, 16, 16, 16));

        JLabel header = new JLabel("<html><b>Configure AI Providers</b><br>"
                + "<small>Add your API keys below. Keys from installed CLIs and env vars are auto-detected.</small>"
                + "</html>");
        content.add(header, BorderLayout.NORTH);

        // Load current state: auto-detected + saved
        Map<String, String> autoDetected = ProviderConfigStore.autoDetect();
        Map<String, String> savedKeys = ProviderConfigStore.loadSaved();

        JPanel grid = new JPanel(new GridBagLayout());
        GridBagConstraints lbl = new GridBagConstraints();
        lbl.anchor = GridBagConstraints.WEST;
        lbl.insets = new Insets(4, 0, 4, 8);
        lbl.gridx = 0;

        GridBagConstraints fld = new GridBagConstraints();
        fld.fill = GridBagConstraints.HORIZONTAL;
        fld.weightx = 1.0;
        fld.insets = new Insets(4, 0, 4, 0);
        fld.gridx = 1;

        GridBagConstraints tag = new GridBagConstraints();
        tag.anchor = GridBagConstraints.WEST;
        tag.insets = new Insets(4, 6, 4, 0);
        tag.gridx = 2;

        for (int i = 0; i < PROVIDERS.length; i++) {
            ProviderEntry pe = PROVIDERS[i];
            lbl.gridy = i;
            fld.gridy = i;
            tag.gridy = i;

            grid.add(new JLabel(pe.label()), lbl);

            JTextField tf = new JTextField(30);
            tf.putClientProperty("JTextField.placeholderText", pe.placeholder());

            // Prioritize: saved > env.local > auto-detected
            String envLocalVal = envLocal.getOrDefault(pe.key(), "");
            String val = savedKeys.getOrDefault(pe.key(),
                    !envLocalVal.isBlank() ? envLocalVal : autoDetected.getOrDefault(pe.key(), ""));
            if (!val.isBlank()) {
                tf.setText(val);
            }

            fields.put(pe.key(), tf);
            grid.add(tf, fld);

            // Show detection source
            String source = null;
            if (savedKeys.containsKey(pe.key()) && !savedKeys.get(pe.key()).isBlank()) {
                source = "saved";
            } else if (!envLocalVal.isBlank()) {
                source = ".env";
            } else if (autoDetected.containsKey(pe.key()) && !autoDetected.get(pe.key()).isBlank()) {
                source = pe.key().equals("notholy_api_key") ? "CLI" : "env";
            }
            if (source != null) {
                JLabel sourceLabel = new JLabel(source);
                sourceLabel.setFont(sourceLabel.getFont().deriveFont(Font.ITALIC, 10f));
                sourceLabel.setForeground(new Color(100, 180, 100));
                grid.add(sourceLabel, tag);
            }
        }

        JScrollPane scroll = new JScrollPane(grid);
        scroll.setBorder(null);
        content.add(scroll, BorderLayout.CENTER);

        // Buttons
        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 0));
        JButton cancelBtn = new JButton("Cancel");
        cancelBtn.addActionListener(e -> dispose());

        JButton saveBtn = new JButton("Save");
        saveBtn.addActionListener(e -> doSave());

        buttons.add(cancelBtn);
        buttons.add(saveBtn);
        content.add(buttons, BorderLayout.SOUTH);

        setContentPane(content);
    }

    private void doSave() {
        Map<String, String> keys = new LinkedHashMap<>();
        for (var entry : fields.entrySet()) {
            String val = entry.getValue().getText().strip();
            if (!val.isBlank()) {
                keys.put(entry.getKey(), val);
            }
        }
        try {
            ProviderConfigStore.save(keys);
            saved = true;
            dispose();
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(this, "Failed to save: " + ex.getMessage(), "Error",
                    JOptionPane.ERROR_MESSAGE);
        }
    }

    private record ProviderEntry(String key, String label, String placeholder) {
    }
}
