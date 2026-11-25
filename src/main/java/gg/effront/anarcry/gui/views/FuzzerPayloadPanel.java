package gg.effront.anarcry.gui.views;

import gg.effront.anarcry.fuzzer.FilePayloadSource;
import gg.effront.anarcry.fuzzer.InlinePayloadSource;
import gg.effront.anarcry.fuzzer.PayloadSource;
import gg.effront.anarcry.fuzzer.RangePayloadSource;

import java.awt.BorderLayout;
import java.awt.CardLayout;
import java.awt.Font;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSpinner;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.SpinnerNumberModel;
import javax.swing.SwingUtilities;
import javax.swing.filechooser.FileNameExtensionFilter;

final class FuzzerPayloadPanel extends JPanel {

    private final JComboBox<String> sourceTypeCombo;
    private final CardLayout cardLayout;
    private final JPanel cardPanel;

    private JTextField filePathField;
    private JLabel fileInfoLabel;
    private JTextArea filePreview;
    private Path selectedFilePath;

    private JTextArea inlineArea;

    private JSpinner rangeFrom;
    private JSpinner rangeTo;
    private JSpinner rangeStep;
    private JSpinner rangePadding;

    private Runnable onSourceChanged;

    FuzzerPayloadPanel() {
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

    void setOnSourceChanged(Runnable callback) {
        this.onSourceChanged = callback;
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
        if (onSourceChanged != null) {
            onSourceChanged.run();
        }
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
                    fileInfoLabel
                            .setText(selectedFilePath.getFileName() + " (" + String.format("%,d", count) + " lines)");
                    filePreview.setText(String.join("\n", preview));
                    if (onSourceChanged != null) {
                        onSourceChanged.run();
                    }
                });
            });
        }
    }
}
