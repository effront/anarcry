package gg.effront.anarcry.gui.views;

import gg.effront.anarcry.fuzzer.FuzzResult;
import gg.effront.anarcry.fuzzer.GrepMatcher;
import gg.effront.anarcry.gui.theme.AnarCryLaf;
import gg.effront.anarcry.util.HttpRequestUtil;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.Toolkit;
import java.awt.datatransfer.StringSelection;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;

import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPopupMenu;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTable;
import javax.swing.JTextField;
import javax.swing.RowFilter;
import javax.swing.filechooser.FileNameExtensionFilter;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableRowSorter;

import org.fife.ui.rsyntaxtextarea.RSyntaxTextArea;
import org.fife.ui.rsyntaxtextarea.SyntaxConstants;
import org.fife.ui.rsyntaxtextarea.Theme;
import org.fife.ui.rtextarea.RTextScrollPane;

final class FuzzerResultsPanel extends JPanel {

    private static final int MAX_RESULTS_IN_MEMORY = 50_000;

    private final DefaultTableModel resultsModel;
    private final JTable resultsTable;
    private final TableRowSorter<DefaultTableModel> resultsSorter;
    private final JTextField statusFilterField;
    private final JTextField lengthFilterField;
    private final RSyntaxTextArea responseViewer;

    private final List<FuzzResult> allResults = new ArrayList<>();

    private Runnable sendToRepeaterAction;

    FuzzerResultsPanel() {
        super(new BorderLayout());

        statusFilterField = new JTextField(8);
        statusFilterField.setToolTipText("Filter: 200, 4xx, !200");
        statusFilterField.addActionListener(e -> applyFilters());

        lengthFilterField = new JTextField(10);
        lengthFilterField.setToolTipText("Filter: min-max (e.g. 100-5000)");
        lengthFilterField.addActionListener(e -> applyFilters());

        add(buildFilterBar(), BorderLayout.NORTH);

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

        addContextMenu();

        responseViewer = new RSyntaxTextArea(10, 60);
        responseViewer.setEditable(false);
        responseViewer.setSyntaxEditingStyle(SyntaxConstants.SYNTAX_STYLE_NONE);
        responseViewer.setCodeFoldingEnabled(true);
        responseViewer.setAntiAliasingEnabled(true);
        responseViewer.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        applySyntaxTheme(responseViewer);

        JSplitPane resultsSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT, new JScrollPane(resultsTable),
                new RTextScrollPane(responseViewer));
        resultsSplit.setResizeWeight(0.6);
        add(resultsSplit, BorderLayout.CENTER);

        AnarCryLaf.addThemeListener(() -> applySyntaxTheme(responseViewer));
    }

    void setSendToRepeaterAction(Runnable action) {
        this.sendToRepeaterAction = action;
    }

    void addResult(FuzzResult result) {
        if (allResults.size() < MAX_RESULTS_IN_MEMORY) {
            allResults.add(result);
        }
        resultsModel.addRow(buildResultRow(result));
    }

    void clearResults() {
        resultsModel.setRowCount(0);
        allResults.clear();
    }

    FuzzResult getSelectedResult() {
        int viewRow = resultsTable.getSelectedRow();
        if (viewRow < 0) {
            return null;
        }
        int modelRow = resultsTable.convertRowIndexToModel(viewRow);
        if (modelRow < 0 || modelRow >= allResults.size()) {
            return null;
        }
        return allResults.get(modelRow);
    }

    void rebuildColumns(GrepMatcher grepMatcher) {
        List<String> cols = new ArrayList<>(List.of("#", "Payload", "Status", "Length", "Time(ms)", "Error"));
        for (String label : grepMatcher.matchLabels()) {
            cols.add("M:" + truncate(label, 15));
        }
        for (String label : grepMatcher.extractLabels()) {
            cols.add("E:" + truncate(label, 15));
        }
        resultsModel.setColumnIdentifiers(cols.toArray());
    }

    private JPanel buildFilterBar() {
        JPanel filterBar = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 2));
        filterBar.add(new JLabel("Status:"));
        filterBar.add(statusFilterField);

        filterBar.add(new JLabel("Length:"));
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
        exportBtn.addActionListener(e -> exportCsv());
        filterBar.add(exportBtn);

        JButton exportJsonBtn = new JButton("Export JSON");
        exportJsonBtn.addActionListener(e -> exportJson());
        filterBar.add(exportJsonBtn);

        return filterBar;
    }

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
        FuzzResult result = getSelectedResult();
        if (result == null) {
            return;
        }
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

    private void addContextMenu() {
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
            FuzzResult r = getSelectedResult();
            if (r != null) {
                copyToClipboard(r.responseBody());
            }
        });
        menu.add(copyResponse);

        JMenuItem sendToRepeater = new JMenuItem("Send to Repeater");
        sendToRepeater.addActionListener(e -> {
            if (sendToRepeaterAction != null) {
                sendToRepeaterAction.run();
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

    private void exportCsv() {
        JFileChooser fc = new JFileChooser();
        fc.setSelectedFile(new java.io.File("fuzz-results-" + System.currentTimeMillis() + ".csv"));
        fc.setFileFilter(new FileNameExtensionFilter("CSV files", "csv"));
        if (fc.showSaveDialog(this) != JFileChooser.APPROVE_OPTION) {
            return;
        }
        try (PrintWriter pw = new PrintWriter(new FileWriter(fc.getSelectedFile()))) {
            StringBuilder hdr = new StringBuilder();
            for (int i = 0; i < resultsModel.getColumnCount(); i++) {
                if (i > 0) {
                    hdr.append(",");
                }
                hdr.append(HttpRequestUtil.csvEscape(resultsModel.getColumnName(i)));
            }
            pw.println(hdr);
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

    private void exportJson() {
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
}
