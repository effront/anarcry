package gg.effront.anarcry.gui.components;

import gg.effront.anarcry.gui.PrivacyFilter;
import gg.effront.anarcry.model.Finding;
import gg.effront.anarcry.model.Severity;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.util.ArrayList;
import java.util.List;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.SwingConstants;
import javax.swing.SwingUtilities;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.TableRowSorter;

/**
 * Findings table with severity coloring and row sorting. Thread-safe for
 * {@link #addFinding}.
 */
public class FindingsTable extends JPanel {

    private static final Color COLOR_CRITICAL = new Color(0xF8, 0x51, 0x49);
    private static final Color COLOR_HIGH = new Color(0xD2, 0x99, 0x22);
    private static final Color COLOR_MEDIUM = new Color(0xE3, 0xB3, 0x41);
    private static final Color COLOR_LOW = new Color(0x58, 0xA6, 0xFF);
    private static final Color COLOR_INFO = new Color(0x8B, 0x94, 0x9E);

    private final FindingsTableModel model;
    private final JTable table;

    public FindingsTable() {
        super(new BorderLayout());
        model = new FindingsTableModel();
        table = new JTable(model);
        table.setRowSorter(new TableRowSorter<>(model));
        table.setFillsViewportHeight(true);
        table.setAutoResizeMode(JTable.AUTO_RESIZE_LAST_COLUMN);

        // Severity column renderer
        table.getColumnModel().getColumn(0).setCellRenderer(new SeverityCellRenderer());

        // CVSS column right-aligned
        DefaultTableCellRenderer rightRenderer = new DefaultTableCellRenderer();
        rightRenderer.setHorizontalAlignment(SwingConstants.RIGHT);
        table.getColumnModel().getColumn(1).setCellRenderer(rightRenderer);

        // Preferred column widths
        table.getColumnModel().getColumn(0).setPreferredWidth(80);
        table.getColumnModel().getColumn(1).setPreferredWidth(55);
        table.getColumnModel().getColumn(2).setPreferredWidth(90);
        table.getColumnModel().getColumn(3).setPreferredWidth(200);
        table.getColumnModel().getColumn(4).setPreferredWidth(300);

        add(new JScrollPane(table), BorderLayout.CENTER);

        PrivacyFilter.addListener(() -> SwingUtilities.invokeLater(model::fireTableDataChanged));
    }

    /** Add a finding row. Safe to call from any thread. */
    public void addFinding(Finding f) {
        SwingUtilities.invokeLater(() -> {
            model.findings.add(f);
            int row = model.findings.size() - 1;
            model.fireTableRowsInserted(row, row);
        });
    }

    /** Return a defensive copy of all findings. */
    public List<Finding> getFindings() {
        return new ArrayList<>(model.findings);
    }

    /** Remove all rows. */
    public void clear() {
        SwingUtilities.invokeLater(() -> {
            model.findings.clear();
            model.fireTableDataChanged();
        });
    }

    /**
     * Return the underlying JTable for selection listeners or further
     * customization.
     */
    public JTable getTable() {
        return table;
    }

    // ---------------------------------------------------------------------------
    // Table model
    // ---------------------------------------------------------------------------

    private static final String[] COLUMNS = {"Severity", "CVSS", "Module", "Endpoint", "Title"};

    private static class FindingsTableModel extends AbstractTableModel {

        private final List<Finding> findings = new ArrayList<>();

        @Override
        public int getRowCount() {
            return findings.size();
        }

        @Override
        public int getColumnCount() {
            return COLUMNS.length;
        }

        @Override
        public String getColumnName(int column) {
            return COLUMNS[column];
        }

        @Override
        public Class<?> getColumnClass(int columnIndex) {
            return switch (columnIndex) {
                case 0 -> Severity.class;
                case 1 -> Double.class;
                default -> String.class;
            };
        }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            Finding f = findings.get(rowIndex);
            return switch (columnIndex) {
                case 0 -> f.severity();
                case 1 -> f.cvssScore();
                case 2 -> f.module();
                case 3 -> PrivacyFilter.apply(f.endpoint());
                case 4 -> f.title();
                default -> "";
            };
        }
    }

    // ---------------------------------------------------------------------------
    // Cell renderer
    // ---------------------------------------------------------------------------

    private static class SeverityCellRenderer extends DefaultTableCellRenderer {

        @Override
        public Component getTableCellRendererComponent(JTable tbl, Object value, boolean isSelected, boolean hasFocus,
                int row, int column) {
            JLabel label = (JLabel) super.getTableCellRendererComponent(tbl, value, isSelected, hasFocus, row, column);
            if (value instanceof Severity sev) {
                label.setText(sev.name());
                if (!isSelected) {
                    label.setForeground(colorFor(sev));
                }
            }
            return label;
        }

        private static Color colorFor(Severity sev) {
            return switch (sev) {
                case CRITICAL -> COLOR_CRITICAL;
                case HIGH -> COLOR_HIGH;
                case MEDIUM -> COLOR_MEDIUM;
                case LOW -> COLOR_LOW;
                case INFO -> COLOR_INFO;
            };
        }
    }
}
