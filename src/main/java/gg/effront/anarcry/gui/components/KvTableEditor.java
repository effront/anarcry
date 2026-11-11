package gg.effront.anarcry.gui.components;

import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.FlowLayout;
import java.util.ArrayList;
import java.util.List;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.ListSelectionModel;
import javax.swing.UIManager;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableCellRenderer;

public class KvTableEditor extends JPanel {

    public record Entry(String key, String value, boolean enabled) {
    }

    private final DefaultTableModel model;
    private final JTable table;

    public KvTableEditor() {
        super(new BorderLayout());

        model = new DefaultTableModel(new String[]{"", "Key", "Value"}, 0) {
            @Override
            public Class<?> getColumnClass(int column) {
                if (column == 0) {
                    return Boolean.class;
                }
                return String.class;
            }

            @Override
            public boolean isCellEditable(int row, int column) {
                return true;
            }
        };

        table = new JTable(model);
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        table.setRowHeight(24);
        table.putClientProperty("terminateEditOnFocusLost", Boolean.TRUE);
        table.setShowGrid(true);
        table.setGridColor(UIManager.getColor("Separator.foreground") != null
                ? UIManager.getColor("Separator.foreground")
                : new java.awt.Color(0x30, 0x36, 0x3d));
        table.getTableHeader().setReorderingAllowed(false);

        table.getColumnModel().getColumn(0).setMaxWidth(32);
        table.getColumnModel().getColumn(0).setMinWidth(32);
        table.getColumnModel().getColumn(0).setPreferredWidth(32);
        table.getColumnModel().getColumn(1).setPreferredWidth(160);
        table.getColumnModel().getColumn(2).setPreferredWidth(300);

        table.getColumnModel().getColumn(0).setHeaderRenderer(new CheckHeaderRenderer());

        JScrollPane scroll = new JScrollPane(table);
        scroll.setBorder(BorderFactory.createEmptyBorder());
        add(scroll, BorderLayout.CENTER);

        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 2));
        JButton addBtn = new JButton("+");
        addBtn.setToolTipText("Add row");
        addBtn.addActionListener(e -> addRow("", "", true));

        JButton removeBtn = new JButton("-");
        removeBtn.setToolTipText("Remove selected row");
        removeBtn.addActionListener(e -> {
            int row = table.getSelectedRow();
            if (row >= 0) {
                if (table.isEditing()) {
                    table.getCellEditor().stopCellEditing();
                }
                model.removeRow(row);
            }
        });

        buttons.add(addBtn);
        buttons.add(removeBtn);
        add(buttons, BorderLayout.SOUTH);
    }

    public void addRow(String key, String value, boolean enabled) {
        model.addRow(new Object[]{enabled, key, value});
    }

    public List<Entry> getEntries() {
        if (table.isEditing()) {
            table.getCellEditor().stopCellEditing();
        }
        List<Entry> entries = new ArrayList<>();
        for (int i = 0; i < model.getRowCount(); i++) {
            boolean enabled = Boolean.TRUE.equals(model.getValueAt(i, 0));
            String key = String.valueOf(model.getValueAt(i, 1)).trim();
            String value = String.valueOf(model.getValueAt(i, 2)).trim();
            if (!key.isEmpty()) {
                entries.add(new Entry(key, value, enabled));
            }
        }
        return entries;
    }

    public void setEntries(List<Entry> entries) {
        model.setRowCount(0);
        for (Entry e : entries) {
            model.addRow(new Object[]{e.enabled(), e.key(), e.value()});
        }
    }

    public void clear() {
        model.setRowCount(0);
    }

    private static class CheckHeaderRenderer implements TableCellRenderer {
        @Override
        public Component getTableCellRendererComponent(JTable t, Object value, boolean isSel, boolean hasFocus, int row,
                int col) {
            javax.swing.JCheckBox cb = new javax.swing.JCheckBox();
            cb.setHorizontalAlignment(javax.swing.SwingConstants.CENTER);
            cb.setOpaque(true);
            cb.setBackground(t.getTableHeader().getBackground());
            return cb;
        }
    }
}
