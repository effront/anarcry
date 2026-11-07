package gg.effront.anarcry.gui.views;

import gg.effront.anarcry.model.Finding;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.List;
import java.util.function.Consumer;
import java.util.function.Supplier;

import javax.swing.BorderFactory;
import javax.swing.DefaultListCellRenderer;
import javax.swing.DefaultListModel;
import javax.swing.JDialog;
import javax.swing.JFrame;
import javax.swing.JList;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;

public class GlobalSearchDialog extends JDialog {

    private final JTextField searchField;
    private final JList<SearchResult> resultList;
    private final DefaultListModel<SearchResult> listModel;

    private Supplier<List<Finding>> findingsSupplier = List::of;
    private Supplier<List<String>> siteMapSupplier = List::of;
    private Supplier<List<String>> apiRequestsSupplier = List::of;
    private Consumer<SearchResult> onSelect;

    public GlobalSearchDialog(JFrame parent) {
        super(parent, false);
        setUndecorated(true);
        setSize(520, 400);
        setLocationRelativeTo(parent);

        JPanel root = new JPanel(new BorderLayout());
        root.setBorder(BorderFactory.createCompoundBorder(BorderFactory.createLineBorder(new Color(0x55, 0x55, 0x55)),
                BorderFactory.createEmptyBorder(8, 8, 8, 8)));

        searchField = new JTextField();
        searchField.setFont(searchField.getFont().deriveFont(14f));
        searchField.putClientProperty("JTextField.placeholderText", "Search findings, endpoints, requests...");
        searchField.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createMatteBorder(0, 0, 1, 0, new Color(0x55, 0x55, 0x55)),
                BorderFactory.createEmptyBorder(6, 6, 6, 6)));

        searchField.getDocument().addDocumentListener(new DocumentListener() {

            @Override
            public void insertUpdate(DocumentEvent e) {
                search();
            }

            @Override
            public void removeUpdate(DocumentEvent e) {
                search();
            }

            @Override
            public void changedUpdate(DocumentEvent e) {
                search();
            }
        });

        searchField.addKeyListener(new KeyAdapter() {

            @Override
            public void keyPressed(KeyEvent e) {
                if (e.getKeyCode() == KeyEvent.VK_ESCAPE) {
                    dispose();
                } else if (e.getKeyCode() == KeyEvent.VK_DOWN) {
                    int idx = resultList.getSelectedIndex();
                    if (idx < listModel.size() - 1) {
                        resultList.setSelectedIndex(idx + 1);
                        resultList.ensureIndexIsVisible(idx + 1);
                    }
                } else if (e.getKeyCode() == KeyEvent.VK_UP) {
                    int idx = resultList.getSelectedIndex();
                    if (idx > 0) {
                        resultList.setSelectedIndex(idx - 1);
                        resultList.ensureIndexIsVisible(idx - 1);
                    }
                } else if (e.getKeyCode() == KeyEvent.VK_ENTER) {
                    selectCurrent();
                }
            }
        });

        listModel = new DefaultListModel<>();
        resultList = new JList<>(listModel);
        resultList.setCellRenderer(new SearchResultRenderer());
        resultList.addMouseListener(new MouseAdapter() {

            @Override
            public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() == 2) {
                    selectCurrent();
                }
            }
        });

        root.add(searchField, BorderLayout.NORTH);
        root.add(new JScrollPane(resultList), BorderLayout.CENTER);

        setContentPane(root);
    }

    public void setFindingsSupplier(Supplier<List<Finding>> supplier) {
        this.findingsSupplier = supplier;
    }

    public void setSiteMapSupplier(Supplier<List<String>> supplier) {
        this.siteMapSupplier = supplier;
    }

    public void setApiRequestsSupplier(Supplier<List<String>> supplier) {
        this.apiRequestsSupplier = supplier;
    }

    public void setOnSelect(Consumer<SearchResult> consumer) {
        this.onSelect = consumer;
    }

    public void showSearch() {
        searchField.setText("");
        listModel.clear();
        setVisible(true);
        SwingUtilities.invokeLater(searchField::requestFocusInWindow);
    }

    private void search() {
        String query = searchField.getText().trim().toLowerCase();
        listModel.clear();

        if (query.isEmpty()) {
            return;
        }

        List<Finding> findings = findingsSupplier.get();
        for (Finding f : findings) {
            String text = f.title() + " " + f.severity() + " " + f.module();
            if (text.toLowerCase().contains(query)) {
                listModel.addElement(new SearchResult(Category.FINDING, f.severity() + " - " + f.title(), f.module()));
            }
            if (listModel.size() >= 50) {
                break;
            }
        }

        List<String> paths = siteMapSupplier.get();
        for (String path : paths) {
            if (path.toLowerCase().contains(query)) {
                listModel.addElement(new SearchResult(Category.SITEMAP, path, "SiteMap"));
            }
            if (listModel.size() >= 50) {
                break;
            }
        }

        List<String> requests = apiRequestsSupplier.get();
        for (String req : requests) {
            if (req.toLowerCase().contains(query)) {
                listModel.addElement(new SearchResult(Category.API_REQUEST, req, "API Client"));
            }
            if (listModel.size() >= 50) {
                break;
            }
        }

        if (!listModel.isEmpty()) {
            resultList.setSelectedIndex(0);
        }
    }

    private void selectCurrent() {
        SearchResult selected = resultList.getSelectedValue();
        if (selected != null && onSelect != null) {
            onSelect.accept(selected);
        }
        dispose();
    }

    public enum Category {
        FINDING, SITEMAP, API_REQUEST
    }

    public record SearchResult(Category category, String title, String source) {

        @Override
        public String toString() {
            return title;
        }
    }

    private static class SearchResultRenderer extends DefaultListCellRenderer {

        private static final Color COLOR_FINDING = new Color(0xF8, 0x51, 0x49);
        private static final Color COLOR_SITEMAP = new Color(0x58, 0xA6, 0xFF);
        private static final Color COLOR_API = new Color(0x3F, 0xB9, 0x50);

        @Override
        public Component getListCellRendererComponent(JList<?> list, Object value, int index, boolean isSelected,
                boolean cellHasFocus) {
            super.getListCellRendererComponent(list, value, index, isSelected, cellHasFocus);

            if (value instanceof SearchResult sr) {
                setText("<html><b>[" + sr.source() + "]</b> " + escapeHtml(sr.title()) + "</html>");
                setBorder(BorderFactory.createEmptyBorder(4, 8, 4, 8));
                if (!isSelected) {
                    setForeground(switch (sr.category()) {
                        case FINDING -> COLOR_FINDING;
                        case SITEMAP -> COLOR_SITEMAP;
                        case API_REQUEST -> COLOR_API;
                    });
                }
            }
            return this;
        }

        private static String escapeHtml(String s) {
            return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
        }
    }
}
