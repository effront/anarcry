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
        root.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(gg.effront.anarcry.gui.theme.AnarCryLaf.border()),
                BorderFactory.createEmptyBorder(8, 8, 8, 8)));

        searchField = new JTextField();
        searchField.setFont(searchField.getFont().deriveFont(14f));
        searchField.putClientProperty("JTextField.placeholderText", "Search findings, endpoints, requests...");
        searchField.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createMatteBorder(0, 0, 1, 0, gg.effront.anarcry.gui.theme.AnarCryLaf.border()),
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
                    int next = (idx + 1) % Math.max(1, listModel.size());
                    resultList.setSelectedIndex(next);
                    resultList.ensureIndexIsVisible(next);
                } else if (e.getKeyCode() == KeyEvent.VK_UP) {
                    int idx = resultList.getSelectedIndex();
                    int prev = idx <= 0 ? listModel.size() - 1 : idx - 1;
                    resultList.setSelectedIndex(prev);
                    resultList.ensureIndexIsVisible(prev);
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
                selectCurrent();
            }
        });

        root.add(searchField, BorderLayout.NORTH);
        root.add(new JScrollPane(resultList), BorderLayout.CENTER);

        setContentPane(root);

        addWindowFocusListener(new java.awt.event.WindowFocusListener() {

            @Override
            public void windowGainedFocus(java.awt.event.WindowEvent e) {
            }

            @Override
            public void windowLostFocus(java.awt.event.WindowEvent e) {
                dispose();
            }
        });
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
        setLocationRelativeTo(getOwner());
        setVisible(true);
        SwingUtilities.invokeLater(() -> {
            searchField.requestFocusInWindow();
            populateDefaults();
        });
    }

    private void populateDefaults() {
        listModel.clear();
        addApiRequests("");
        addFindings("");
        addSiteMapPaths("");
        if (!listModel.isEmpty()) {
            resultList.setSelectedIndex(0);
        }
    }

    private void search() {
        String query = searchField.getText().trim().toLowerCase();
        listModel.clear();

        if (query.isEmpty()) {
            populateDefaults();
            return;
        }

        addApiRequests(query);
        addFindings(query);
        addSiteMapPaths(query);

        if (!listModel.isEmpty()) {
            resultList.setSelectedIndex(0);
        }
    }

    private void addFindings(String query) {
        List<Finding> findings = findingsSupplier.get();
        for (Finding f : findings) {
            if (listModel.size() >= 50) {
                break;
            }
            String text = (f.title() + " " + f.severity() + " " + f.module() + " " + f.endpoint()).toLowerCase();
            if (query.isEmpty() || text.contains(query)) {
                listModel.addElement(new SearchResult(Category.FINDING, f.severity() + " - " + f.title(), f.module()));
            }
        }
    }

    private void addSiteMapPaths(String query) {
        List<String> paths = siteMapSupplier.get();
        for (String path : paths) {
            if (listModel.size() >= 50) {
                break;
            }
            if (query.isEmpty() || path.toLowerCase().contains(query)) {
                listModel.addElement(new SearchResult(Category.SITEMAP, path, "SiteMap"));
            }
        }
    }

    private void addApiRequests(String query) {
        List<String> requests = apiRequestsSupplier.get();
        for (String req : requests) {
            if (listModel.size() >= 50) {
                break;
            }
            if (query.isEmpty() || req.toLowerCase().contains(query)) {
                listModel.addElement(new SearchResult(Category.API_REQUEST, req, "API Client"));
            }
        }
    }

    private void selectCurrent() {
        SearchResult selected = resultList.getSelectedValue();
        if (selected != null && onSelect != null) {
            onSelect.accept(selected);
            dispose();
        }
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
