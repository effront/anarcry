package gg.effront.anarcry.gui.views;

import gg.effront.anarcry.gui.components.FindingDetailPanel;
import gg.effront.anarcry.gui.components.FindingsTable;
import gg.effront.anarcry.model.Finding;
import gg.effront.anarcry.model.Severity;

import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.ArrayList;
import java.util.List;

import javax.swing.JComboBox;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JSplitPane;
import javax.swing.JTable;
import javax.swing.JTextField;
import javax.swing.RowFilter;
import javax.swing.SwingUtilities;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.table.TableModel;
import javax.swing.table.TableRowSorter;

/**
 * Findings view wrapping a {@link FindingsTable} with severity filter, text
 * search, count label, and double-click detail dialog.
 */
public class FindingsView extends JPanel {

    private final FindingsTable findingsTable;
    private final FindingDetailPanel detailPanel;
    private final JComboBox<String> severityFilter;
    private final JTextField searchField;
    private final JLabel countLabel;

    public FindingsView() {
        this(new FindingsTable());
    }

    public FindingsView(FindingsTable table) {
        super(new BorderLayout());
        this.findingsTable = table;

        // -- Toolbar --
        JPanel toolbar = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 4));

        toolbar.add(new JLabel("Severity:"));
        severityFilter = new JComboBox<>(new String[]{"All", "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"});
        severityFilter.addActionListener(e -> applyFilters());
        toolbar.add(severityFilter);

        toolbar.add(new JLabel("Search:"));
        searchField = new JTextField(20);
        searchField.getDocument().addDocumentListener(new DocumentListener() {

            @Override
            public void insertUpdate(DocumentEvent e) {
                applyFilters();
            }

            @Override
            public void removeUpdate(DocumentEvent e) {
                applyFilters();
            }

            @Override
            public void changedUpdate(DocumentEvent e) {
                applyFilters();
            }
        });
        toolbar.add(searchField);

        countLabel = new JLabel("0 findings");
        toolbar.add(countLabel);

        add(toolbar, BorderLayout.NORTH);

        detailPanel = new FindingDetailPanel();

        JSplitPane split = new JSplitPane(JSplitPane.VERTICAL_SPLIT, findingsTable, detailPanel);
        split.setResizeWeight(0.5);
        add(split, BorderLayout.CENTER);

        // Selection updates inline detail panel
        JTable jTable = findingsTable.getTable();
        jTable.getSelectionModel().addListSelectionListener(e -> {
            if (e.getValueIsAdjusting()) {
                return;
            }
            int viewRow = jTable.getSelectedRow();
            if (viewRow < 0) {
                detailPanel.clear();
                return;
            }
            int modelRow = jTable.convertRowIndexToModel(viewRow);
            List<Finding> all = findingsTable.getFindings();
            if (modelRow >= 0 && modelRow < all.size()) {
                detailPanel.show(all.get(modelRow));
            }
        });

        // Double-click opens full detail dialog
        jTable.addMouseListener(new MouseAdapter() {

            @Override
            public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() == 2) {
                    int viewRow = jTable.getSelectedRow();
                    if (viewRow < 0) {
                        return;
                    }
                    int modelRow = jTable.convertRowIndexToModel(viewRow);
                    List<Finding> all = findingsTable.getFindings();
                    if (modelRow >= 0 && modelRow < all.size()) {
                        Finding f = all.get(modelRow);
                        JFrame frame = (JFrame) SwingUtilities.getWindowAncestor(FindingsView.this);
                        new FindingDetailDialog(frame, f).setVisible(true);
                    }
                }
            }
        });
    }

    /** Add a finding row. Thread-safe. */
    public void addFinding(Finding f) {
        findingsTable.addFinding(f);
        SwingUtilities.invokeLater(this::updateCount);
    }

    /** Remove all rows. */
    public void clear() {
        findingsTable.clear();
        detailPanel.clear();
        SwingUtilities.invokeLater(this::updateCount);
    }

    /** Return all findings. */
    public List<Finding> getFindings() {
        return findingsTable.getFindings();
    }

    /** Return the wrapped table component. */
    public FindingsTable getFindingsTable() {
        return findingsTable;
    }

    @SuppressWarnings("unchecked")
    private void applyFilters() {
        JTable jTable = findingsTable.getTable();
        if (!(jTable.getRowSorter() instanceof TableRowSorter<?> sorter)) {
            return;
        }
        @SuppressWarnings("unchecked")
        TableRowSorter<TableModel> typedSorter = (TableRowSorter<TableModel>) sorter;

        List<RowFilter<TableModel, Object>> filters = new ArrayList<>();

        String selected = (String) severityFilter.getSelectedItem();
        if (selected != null && !"All".equals(selected)) {
            filters.add(new RowFilter<>() {

                @Override
                public boolean include(Entry<? extends TableModel, ? extends Object> entry) {
                    Object val = entry.getValue(0);
                    if (val instanceof Severity sev) {
                        return sev.name().equals(selected);
                    }
                    return String.valueOf(val).equals(selected);
                }
            });
        }

        String text = searchField.getText().trim().toLowerCase();
        if (!text.isEmpty()) {
            filters.add(new RowFilter<>() {

                @Override
                public boolean include(Entry<? extends TableModel, ? extends Object> entry) {
                    for (int i = 0; i < entry.getValueCount(); i++) {
                        String v = String.valueOf(entry.getValue(i)).toLowerCase();
                        if (v.contains(text)) {
                            return true;
                        }
                    }
                    return false;
                }
            });
        }

        if (filters.isEmpty()) {
            typedSorter.setRowFilter(null);
        } else {
            typedSorter.setRowFilter(RowFilter.andFilter(filters));
        }

        updateCount();
    }

    private void updateCount() {
        int visible = findingsTable.getTable().getRowCount();
        int total = findingsTable.getFindings().size();
        if (visible == total) {
            countLabel.setText(total + " findings");
        } else {
            countLabel.setText(visible + "/" + total + " findings");
        }
    }
}
