package gg.effront.anarcry.gui.views;

import java.awt.BorderLayout;
import java.awt.Component;
import java.net.URI;
import java.util.Enumeration;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTree;
import javax.swing.SwingUtilities;
import javax.swing.UIManager;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.DefaultTreeCellRenderer;
import javax.swing.tree.DefaultTreeModel;
import javax.swing.tree.TreePath;

/**
 * Hierarchical JTree view of crawled URLs. Thread-safe for {@link #addPath}.
 */
public class SiteMapView extends JPanel {

    private final DefaultMutableTreeNode rootNode;
    private final DefaultTreeModel treeModel;
    private final JTree tree;

    public SiteMapView() {
        super(new BorderLayout());
        rootNode = new DefaultMutableTreeNode("(no target)");
        treeModel = new DefaultTreeModel(rootNode);
        tree = new JTree(treeModel);
        tree.setRootVisible(true);
        tree.setShowsRootHandles(true);
        tree.setCellRenderer(new SiteMapCellRenderer());
        add(new JScrollPane(tree), BorderLayout.CENTER);
    }

    /** Set the root node label to the target URL. */
    public void setRootUrl(String url) {
        SwingUtilities.invokeLater(() -> {
            rootNode.setUserObject(url != null ? url : "(no target)");
            treeModel.nodeChanged(rootNode);
        });
    }

    /**
     * Parse a full URL and insert its path segments into the tree hierarchy. Safe
     * to call from any thread.
     */
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

    /** Reset the tree to just the root node. */
    public void clear() {
        SwingUtilities.invokeLater(() -> {
            rootNode.removeAllChildren();
            treeModel.reload();
        });
    }

    /** Return the underlying JTree for further customization. */
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
            super.getTreeCellRendererComponent(t, value, sel, expanded, leaf, row, hasFocus);
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
