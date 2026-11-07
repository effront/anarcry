package gg.effront.anarcry.gui.views;

import gg.effront.anarcry.apiclient.model.Collection;
import gg.effront.anarcry.apiclient.model.EnvVariable;
import gg.effront.anarcry.apiclient.model.Environment;

import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.awt.Font;
import java.util.ArrayList;
import java.util.List;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JDialog;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.JTextField;
import javax.swing.table.DefaultTableModel;

public class EnvironmentEditorDialog extends JDialog {

    private final Collection collection;
    private final List<Environment> environments;
    private final JComboBox<String> envCombo;
    private final DefaultTableModel tableModel;
    private final JTable table;
    private final JTextField renameField;
    private boolean saved = false;

    public EnvironmentEditorDialog(JFrame parent, Collection collection) {
        super(parent, "Environment Editor", true);
        this.collection = collection;
        this.environments = new ArrayList<>(collection.environments());

        setSize(600, 450);
        setLocationRelativeTo(parent);
        setLayout(new BorderLayout(8, 8));

        JPanel topPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 4));
        topPanel.setBorder(BorderFactory.createEmptyBorder(8, 8, 0, 8));

        topPanel.add(new JLabel("Environment:"));
        envCombo = new JComboBox<>();
        envCombo.setPreferredSize(new java.awt.Dimension(180, 28));
        refreshEnvCombo();
        envCombo.addActionListener(e -> loadSelectedEnv());
        topPanel.add(envCombo);

        JButton newBtn = new JButton("New");
        newBtn.addActionListener(e -> addEnvironment());
        topPanel.add(newBtn);

        JButton deleteBtn = new JButton("Delete");
        deleteBtn.addActionListener(e -> deleteEnvironment());
        topPanel.add(deleteBtn);

        topPanel.add(new JLabel("Name:"));
        renameField = new JTextField(14);
        renameField.addActionListener(e -> renameEnvironment());
        topPanel.add(renameField);

        add(topPanel, BorderLayout.NORTH);

        tableModel = new DefaultTableModel(new Object[]{"Name", "Value", "Secret", "Enabled"}, 0) {

            @Override
            public Class<?> getColumnClass(int column) {
                return switch (column) {
                    case 2, 3 -> Boolean.class;
                    default -> String.class;
                };
            }
        };
        table = new JTable(tableModel);
        table.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        table.getColumnModel().getColumn(2).setMaxWidth(60);
        table.getColumnModel().getColumn(3).setMaxWidth(60);
        table.setRowHeight(24);

        JPanel tablePanel = new JPanel(new BorderLayout(4, 4));
        tablePanel.setBorder(BorderFactory.createEmptyBorder(4, 8, 4, 8));
        tablePanel.add(new JScrollPane(table), BorderLayout.CENTER);

        JPanel varButtons = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 2));
        JButton addVar = new JButton("Add Variable");
        addVar.addActionListener(e -> {
            tableModel.addRow(new Object[]{"", "", false, true});
        });
        varButtons.add(addVar);

        JButton removeVar = new JButton("Remove Variable");
        removeVar.addActionListener(e -> {
            int row = table.getSelectedRow();
            if (row >= 0) {
                tableModel.removeRow(row);
            }
        });
        varButtons.add(removeVar);
        tablePanel.add(varButtons, BorderLayout.SOUTH);

        add(tablePanel, BorderLayout.CENTER);

        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 8));
        JButton saveBtn = new JButton("Save");
        saveBtn.addActionListener(e -> {
            commitCurrentEnv();
            saved = true;
            dispose();
        });
        buttonPanel.add(saveBtn);

        JButton cancelBtn = new JButton("Cancel");
        cancelBtn.addActionListener(e -> dispose());
        buttonPanel.add(cancelBtn);

        add(buttonPanel, BorderLayout.SOUTH);

        if (!environments.isEmpty()) {
            envCombo.setSelectedIndex(0);
            loadSelectedEnv();
        }
    }

    public boolean isSaved() {
        return saved;
    }

    public Collection getUpdatedCollection() {
        return new Collection(collection.uid(), collection.name(), collection.version(), List.copyOf(environments),
                collection.items(), collection.root(), collection.settings());
    }

    private void refreshEnvCombo() {
        envCombo.removeAllItems();
        for (Environment env : environments) {
            envCombo.addItem(env.name());
        }
    }

    private void loadSelectedEnv() {
        int idx = envCombo.getSelectedIndex();
        if (idx < 0 || idx >= environments.size()) {
            tableModel.setRowCount(0);
            renameField.setText("");
            return;
        }
        Environment env = environments.get(idx);
        renameField.setText(env.name());
        tableModel.setRowCount(0);
        for (EnvVariable v : env.variables()) {
            tableModel.addRow(new Object[]{v.name(), v.secret() ? "****" : v.value(), v.secret(), v.enabled()});
        }
    }

    private void commitCurrentEnv() {
        int idx = envCombo.getSelectedIndex();
        if (idx < 0 || idx >= environments.size()) {
            return;
        }
        if (table.isEditing()) {
            table.getCellEditor().stopCellEditing();
        }
        Environment old = environments.get(idx);
        List<EnvVariable> vars = new ArrayList<>();
        for (int r = 0; r < tableModel.getRowCount(); r++) {
            String name = str(tableModel.getValueAt(r, 0));
            String value = str(tableModel.getValueAt(r, 1));
            boolean secret = bool(tableModel.getValueAt(r, 2));
            boolean enabled = bool(tableModel.getValueAt(r, 3));
            if (secret && "****".equals(value)) {
                EnvVariable original = r < old.variables().size() ? old.variables().get(r) : null;
                value = original != null ? original.value() : "";
            }
            if (!name.isBlank()) {
                vars.add(new EnvVariable(name, value, secret, enabled));
            }
        }
        String name = renameField.getText().isBlank() ? old.name() : renameField.getText().trim();
        environments.set(idx, new Environment(old.uid(), name, old.color(), List.copyOf(vars), old.extendsEnv()));
    }

    private void addEnvironment() {
        commitCurrentEnv();
        String base = "New Environment";
        String finalName = base;
        int count = 1;
        while (nameExists(finalName)) {
            count++;
            finalName = base + " " + count;
        }
        environments.add(Environment.of(finalName, List.of()));
        refreshEnvCombo();
        envCombo.setSelectedIndex(environments.size() - 1);
    }

    private void deleteEnvironment() {
        int idx = envCombo.getSelectedIndex();
        if (idx < 0 || idx >= environments.size()) {
            return;
        }
        int confirm = JOptionPane.showConfirmDialog(this, "Delete environment '" + environments.get(idx).name() + "'?",
                "Delete", JOptionPane.YES_NO_OPTION);
        if (confirm == JOptionPane.YES_OPTION) {
            environments.remove(idx);
            refreshEnvCombo();
            if (!environments.isEmpty()) {
                envCombo.setSelectedIndex(Math.min(idx, environments.size() - 1));
            } else {
                tableModel.setRowCount(0);
                renameField.setText("");
            }
        }
    }

    private void renameEnvironment() {
        int idx = envCombo.getSelectedIndex();
        if (idx < 0 || idx >= environments.size() || renameField.getText().isBlank()) {
            return;
        }
        commitCurrentEnv();
        refreshEnvCombo();
        envCombo.setSelectedIndex(idx);
    }

    private boolean nameExists(String name) {
        return environments.stream().anyMatch(e -> e.name().equals(name));
    }

    private static String str(Object o) {
        return o != null ? o.toString() : "";
    }

    private static boolean bool(Object o) {
        return o instanceof Boolean b && b;
    }
}
