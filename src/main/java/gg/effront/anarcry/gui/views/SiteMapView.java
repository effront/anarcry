package gg.effront.anarcry.gui.views;

import gg.effront.anarcry.gui.PrivacyFilter;
import gg.effront.anarcry.model.RequestRecord;

import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.Font;
import java.awt.Toolkit;
import java.awt.datatransfer.StringSelection;
import java.net.URI;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import javax.swing.BorderFactory;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTextArea;
import javax.swing.JTree;
import javax.swing.SwingUtilities;
import javax.swing.UIManager;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.DefaultTreeCellRenderer;
import javax.swing.tree.DefaultTreeModel;
import javax.swing.tree.TreePath;

public class SiteMapView extends JPanel {

    private final DefaultMutableTreeNode rootNode;
    private final DefaultTreeModel treeModel;
    private final JTree tree;
    private final JLabel pathLabel;
    private final JTextArea detailArea;
    private String rootUrl = "";
    private final Map<String, RequestRecord> recordsByUrl = new LinkedHashMap<>();

    public SiteMapView() {
        super(new BorderLayout());
        rootNode = new DefaultMutableTreeNode("(no target)");
        treeModel = new DefaultTreeModel(rootNode);
        tree = new JTree(treeModel);
        tree.setRootVisible(true);
        tree.setShowsRootHandles(true);
        tree.setCellRenderer(new SiteMapCellRenderer());

        JPanel leftPanel = new JPanel(new BorderLayout());
        leftPanel.add(new JScrollPane(tree), BorderLayout.CENTER);

        pathLabel = new JLabel("  Select a path");
        pathLabel.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        pathLabel.setBorder(BorderFactory.createEmptyBorder(6, 6, 6, 6));
        pathLabel.setToolTipText("Click to copy full URL");
        pathLabel.addMouseListener(new java.awt.event.MouseAdapter() {
            @Override
            public void mouseClicked(java.awt.event.MouseEvent e) {
                String text = pathLabel.getText().trim();
                if (!text.isEmpty() && !text.equals("Select a path")) {
                    Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(text), null);
                    pathLabel.setText("  Copied!");
                    javax.swing.Timer t = new javax.swing.Timer(1200, ev -> pathLabel.setText("  " + text));
                    t.setRepeats(false);
                    t.start();
                }
            }
        });
        leftPanel.add(pathLabel, BorderLayout.SOUTH);

        detailArea = new JTextArea();
        detailArea.setEditable(false);
        detailArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        detailArea.setLineWrap(false);
        detailArea.setText("Selecione um path na tree para ver headers e body.");
        JScrollPane detailScroll = new JScrollPane(detailArea);
        detailScroll.setBorder(BorderFactory.createTitledBorder("Response"));

        JSplitPane split = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, leftPanel, detailScroll);
        split.setDividerLocation(400);
        split.setResizeWeight(0.4);
        add(split, BorderLayout.CENTER);

        tree.addTreeSelectionListener(e -> {
            TreePath sel = tree.getSelectionPath();
            if (sel == null) {
                pathLabel.setText("  Select a path");
                detailArea.setText("");
                return;
            }
            String fullPath = buildFullPath(sel);
            pathLabel.setText("  " + PrivacyFilter.apply(fullPath));
            showDetail(fullPath);
        });

        PrivacyFilter.addListener(() -> SwingUtilities.invokeLater(() -> {
            treeModel.reload();
            tree.expandPath(new TreePath(rootNode.getPath()));
            TreePath sel = tree.getSelectionPath();
            if (sel != null) {
                pathLabel.setText("  " + PrivacyFilter.apply(buildFullPath(sel)));
            }
        }));
    }

    private void showDetail(String url) {
        RequestRecord r = recordsByUrl.get(url);
        if (r == null) {
            detailArea.setText("[sem dados de response para " + url + "]");
            return;
        }
        detailArea.setText(RequestRecord.formatDetail(r));
        detailArea.setCaretPosition(0);
    }

    public void setRootUrl(String url) {
        rootUrl = url != null ? url.replaceAll("/+$", "") : "";
        SwingUtilities.invokeLater(() -> {
            rootNode.setUserObject(url != null ? url : "(no target)");
            treeModel.nodeChanged(rootNode);
        });
    }

    public void addRecord(RequestRecord r) {
        recordsByUrl.put(r.url(), r);
        if (r.statusCode() < 400) {
            addPath(r.url());
        }
    }

    public void addPath(String fullUrl) {
        SwingUtilities.invokeLater(() -> {
            String path;
            try {
                URI uri = URI.create(fullUrl);
                path = uri.getPath();
            } catch (Exception e) {
                path = fullUrl;
            }
            if (path == null || path.isEmpty() || "/".equals(path)) {
                return;
            }

            String[] segments = path.split("/");
            DefaultMutableTreeNode current = rootNode;

            for (String seg : segments) {
                if (seg.isEmpty()) {
                    continue;
                }
                DefaultMutableTreeNode child = findChild(current, seg);
                if (child == null) {
                    child = new DefaultMutableTreeNode(seg);
                    treeModel.insertNodeInto(child, current, current.getChildCount());
                }
                current = child;
            }

            tree.expandPath(new TreePath(rootNode.getPath()));
        });
    }

    public void clear() {
        SwingUtilities.invokeLater(() -> {
            rootNode.removeAllChildren();
            treeModel.reload();
            pathLabel.setText("  Select a path");
            detailArea.setText("");
            recordsByUrl.clear();
        });
    }

    public List<String> getPaths() {
        List<String> paths = new ArrayList<>();
        collectPaths(rootNode, "", paths);
        return paths;
    }

    private void collectPaths(DefaultMutableTreeNode node, String prefix, List<String> out) {
        Enumeration<?> children = node.children();
        while (children.hasMoreElements()) {
            DefaultMutableTreeNode child = (DefaultMutableTreeNode) children.nextElement();
            String path = prefix + "/" + child.getUserObject();
            out.add(rootUrl + path);
            collectPaths(child, path, out);
        }
    }

    private String buildFullPath(TreePath treePath) {
        Object[] nodes = treePath.getPath();
        if (nodes.length <= 1) {
            return rootUrl.isEmpty() ? "/" : rootUrl;
        }
        StringBuilder sb = new StringBuilder(rootUrl);
        for (int i = 1; i < nodes.length; i++) {
            sb.append('/');
            sb.append(((DefaultMutableTreeNode) nodes[i]).getUserObject());
        }
        return sb.toString();
    }

    public JTree getTree() {
        return tree;
    }

    private static DefaultMutableTreeNode findChild(DefaultMutableTreeNode parent, String name) {
        Enumeration<?> children = parent.children();
        while (children.hasMoreElements()) {
            DefaultMutableTreeNode child = (DefaultMutableTreeNode) children.nextElement();
            if (name.equals(child.getUserObject())) {
                return child;
            }
        }
        return null;
    }

    private static class SiteMapCellRenderer extends DefaultTreeCellRenderer {

        @Override
        public Component getTreeCellRendererComponent(JTree t, Object value, boolean sel, boolean expanded,
                boolean leaf, int row, boolean hasFocus) {
            Object display = value;
            if (value instanceof DefaultMutableTreeNode node && node.getParent() == null) {
                display = new DefaultMutableTreeNode(PrivacyFilter.apply(String.valueOf(node.getUserObject())));
            }
            super.getTreeCellRendererComponent(t, display, sel, expanded, leaf, row, hasFocus);
            if (leaf) {
                setIcon(UIManager.getIcon("FileView.fileIcon"));
            } else {
                setIcon(expanded
                        ? UIManager.getIcon("FileView.directoryIcon")
                        : UIManager.getIcon("FileView.directoryIcon"));
            }
            return this;
        }
    }
}
