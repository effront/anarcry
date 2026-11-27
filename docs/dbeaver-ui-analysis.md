# DBeaver UI Analysis -- AnarCry DB Explorer Improvements

## Current State

AnarCry's DB Explorer has the core pieces: connection tree with schema browsing, RSyntaxTextArea SQL editor, JTable results grid, query history, export (CSV/JSON/SQL/Markdown), and a status label. But the visual polish and interaction quality fall short of DBeaver's standards. The screenshot shows truncated columns, no sorting, no context menu on results, no NULL highlighting, and a bare status bar.

## Top 10 UI Improvements

### 1. Auto-Resize Columns to Content (QUICK WIN)

**DBeaver**: Columns auto-size to fit the widest visible value, capped at a "max column %" of the grid width. Double-click on column header border to auto-fit.

**AnarCry now**: `JTable.AUTO_RESIZE_OFF` with no sizing logic -- all columns get equal default width, truncating everything.

**How to implement**:
After populating `resultsTableModel`, iterate visible rows (first 50-100) and measure each cell's preferred width using the cell renderer. Set each `TableColumn.preferredWidth` to `max(headerWidth, maxCellWidth)`, capped at 400px. Add a double-click listener on `JTableHeader` to resize the clicked column to fit all rows.

```java
private void autoResizeColumns(JTable table, int maxWidth) {
    for (int col = 0; col < table.getColumnCount(); col++) {
        TableColumn tc = table.getColumnModel().getColumn(col);
        int width = table.getTableHeader().getDefaultRenderer()
            .getTableCellRendererComponent(table, tc.getHeaderValue(), false, false, -1, col)
            .getPreferredSize().width + 12;
        for (int row = 0; row < Math.min(table.getRowCount(), 100); row++) {
            Component c = table.prepareRenderer(table.getCellRenderer(row, col), row, col);
            width = Math.max(width, c.getPreferredSize().width + 12);
        }
        tc.setPreferredWidth(Math.min(width, maxWidth));
    }
}
```

**Effort**: 1h | **Impact**: HIGH -- instantly fixes the truncated columns problem

---

### 2. NULL Cell Rendering (QUICK WIN)

**DBeaver**: NULL values are displayed as `[NULL]` in italic gray text, visually distinct from empty strings and actual values.

**AnarCry now**: NULLs render as empty cells -- indistinguishable from empty strings.

**How to implement**:
Create a custom `DefaultTableCellRenderer` that checks for null values and renders them as italic gray `[NULL]` text. Set it as the default renderer on `resultsTable`.

```java
private static class NullAwareRenderer extends DefaultTableCellRenderer {
    @Override
    public Component getTableCellRendererComponent(JTable table, Object value,
            boolean isSelected, boolean hasFocus, int row, int column) {
        super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
        if (value == null) {
            setText("[NULL]");
            setFont(getFont().deriveFont(Font.ITALIC));
            if (!isSelected) setForeground(Color.GRAY);
        } else {
            setFont(getFont().deriveFont(Font.PLAIN));
            if (!isSelected) setForeground(table.getForeground());
        }
        return this;
    }
}
```

**Effort**: 30min | **Impact**: HIGH -- critical for data analysis during pentesting

---

### 3. Alternating Row Colors (QUICK WIN)

**DBeaver**: Alternating row backgrounds (odd/even striping) for readability. Configurable colors.

**AnarCry now**: All rows have the same background -- hard to read wide result sets.

**How to implement**:
Override `prepareRenderer` on `resultsTable` to apply alternating backgrounds:

```java
resultsTable = new JTable(resultsTableModel) {
    @Override
    public Component prepareRenderer(TableCellRenderer renderer, int row, int column) {
        Component c = super.prepareRenderer(renderer, row, column);
        if (!isRowSelected(row)) {
            c.setBackground(row % 2 == 0 ? getBackground() : stripeColor());
        }
        return c;
    }
};
```

Where `stripeColor()` returns a slightly darker/lighter shade of the table background (works with FlatLaf themes).

**Effort**: 30min | **Impact**: MEDIUM -- visual readability improvement

---

### 4. Results Grid Context Menu (QUICK WIN)

**DBeaver**: Right-click on result grid offers: Copy Cell, Copy Row, Copy Column Name, Copy as SQL INSERT, Sort ASC/DESC, Filter by Value.

**AnarCry now**: No context menu at all on `resultsTable`.

**How to implement**:
Add a `MouseListener` on `resultsTable` for popup trigger. Build a `JPopupMenu` with:
- **Copy Cell** (Ctrl+C) -- selected cell value to clipboard
- **Copy Row** -- tab-delimited row to clipboard
- **Copy Column Name** -- header text to clipboard
- **Copy as INSERT** -- generate INSERT statement for selected row
- **Sort ASC / Sort DESC** -- use `TableRowSorter`
- Separator
- **Filter by Value** -- set filter field text to cell value (future)

```java
resultsTable.addMouseListener(new MouseAdapter() {
    @Override public void mousePressed(MouseEvent e) { showPopup(e); }
    @Override public void mouseReleased(MouseEvent e) { showPopup(e); }
    private void showPopup(MouseEvent e) {
        if (!e.isPopupTrigger()) return;
        int row = resultsTable.rowAtPoint(e.getPoint());
        int col = resultsTable.columnAtPoint(e.getPoint());
        if (row >= 0) resultsTable.setRowSelectionInterval(row, row);
        // build menu...
    }
});
```

**Effort**: 1.5h | **Impact**: HIGH -- essential interaction pattern for data exploration

---

### 5. Column Sorting (QUICK WIN)

**DBeaver**: Click column header to sort ASC, click again for DESC, third click removes sort. Sort indicator arrow in header.

**AnarCry now**: No sorting at all.

**How to implement**:
Enable JTable's built-in sorting with `TableRowSorter`:

```java
resultsTable.setAutoCreateRowSorter(true);
```

One line. For better UX, create a custom `TableRowSorter` that cycles through ASC -> DESC -> unsorted. The header automatically shows sort arrows with FlatLaf.

**Effort**: 15min (basic) / 1h (custom cycle) | **Impact**: HIGH -- critical for data analysis

---

### 6. Rich Status Bar with Row Count and Timing (MEDIUM EFFORT)

**DBeaver**: Bottom toolbar shows: row count ("2 rows fetched"), execution time ("12ms"), total row count button, fetch-all button. Separate from connection status.

**AnarCry now**: Single `JLabel` showing only connection name and status. Row count and timing go to Messages tab only.

**How to implement**:
Replace the single `statusLabel` with a `JPanel` (FlowLayout or BoxLayout) containing:
- Left: connection status label (existing)
- Center/Right: row count label ("2 rows"), execution time label ("12ms"), total rows button

Update `displaySqlResult` to populate these fields alongside the existing Messages log.

```java
JPanel statusBar = new JPanel(new BorderLayout());
statusBar.add(statusLabel, BorderLayout.WEST);
JPanel rightStatus = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 0));
rightStatus.add(rowCountLabel);    // "2 rows"
rightStatus.add(execTimeLabel);    // "12ms"
statusBar.add(rightStatus, BorderLayout.EAST);
```

**Effort**: 1.5h | **Impact**: HIGH -- immediate feedback without switching tabs

---

### 7. Tree Icons per Node Type (MEDIUM EFFORT)

**DBeaver**: Custom icons for each node type: database icon for connections, schema icon, table icon, column icons (with type indicators), key icon for PKs, index icon.

**AnarCry now**: Default JTree folder/leaf icons only. Only color-coding: green for connected sessions.

**How to implement**:
Extend `ConnectionTreeCellRenderer` to set icons based on `UserObject` type:
- `SessionNodeData`: database icon (connected=green, disconnected=gray)
- `SchemaNodeData`: schema/folder icon
- `TableNodeData`: table grid icon
- Column nodes: column icon (with PK badge if primary key)
- `MongoCollNodeData`: document icon
- `RedisKeyNodeData`: key icon

Use FlatLaf's built-in SVG icon support or simple 16x16 PNG icons. Can use Unicode symbols as a quick shortcut: database icon, table icon, column icon.

**Effort**: 2-3h | **Impact**: MEDIUM -- visual clarity for navigation

---

### 8. Value Viewer Panel (MEDIUM EFFORT)

**DBeaver**: Side panel (toggled with F7) showing the full content of the focused cell. Supports JSON syntax highlighting, text wrapping, hex view for BLOBs. Editable.

**AnarCry now**: Cell content only visible in truncated grid cells. No way to view full JSON, long text, or binary data.

**How to implement**:
Add a split pane below (or beside) the results table. When a cell is selected, display its full content in an RSyntaxTextArea with:
- Auto-detected syntax mode (JSON, XML, plain text)
- Read-only by default
- Toggle button on results toolbar ("Value Viewer" or F7 shortcut)

```java
RSyntaxTextArea valueViewer = new RSyntaxTextArea();
valueViewer.setEditable(false);
valueViewer.setSyntaxEditingStyle(SyntaxConstants.SYNTAX_STYLE_NONE);

resultsTable.getSelectionModel().addListSelectionListener(e -> {
    int row = resultsTable.getSelectedRow();
    int col = resultsTable.getSelectedColumn();
    if (row >= 0 && col >= 0) {
        Object val = resultsTable.getValueAt(row, col);
        valueViewer.setText(val != null ? val.toString() : "[NULL]");
        // auto-detect JSON
        if (val != null && val.toString().trim().startsWith("{")) {
            valueViewer.setSyntaxEditingStyle(SyntaxConstants.SYNTAX_STYLE_JSON);
        }
    }
});
```

**Effort**: 2-3h | **Impact**: HIGH -- essential for inspecting JSON columns, long text, UUIDs

---

### 9. Connection Tree Context Menu (MEDIUM EFFORT)

**DBeaver**: Right-click on tree nodes offers: Connect/Disconnect, Edit, Remove, Refresh, SQL Editor, Copy Name, Export Data, Generate DDL.

**AnarCry now**: Tree context menu exists for sessions (Connect, Disconnect, Edit, Remove) but not for schemas/tables/columns. No "Copy Name", no "SELECT * FROM", no "Export Table".

**How to implement**:
Extend the tree's `MouseListener` to show context menus for all node types:
- **Schema node**: Refresh, Copy Name
- **Table node**: SELECT * (opens in editor), Export Table (CSV/JSON/SQL), Copy Name, Copy Qualified Name, Row Count
- **Column node**: Copy Name, Copy "column = ?" (for WHERE clauses)

**Effort**: 2h | **Impact**: MEDIUM -- speeds up exploration workflow

---

### 10. Keyboard Shortcuts (QUICK WIN)

**DBeaver**: Ctrl+Enter (execute), Ctrl+Shift+C (advanced copy), Ctrl+D (copy cell down), F5 (refresh), F7 (value viewer), Ctrl+2 (sort by column).

**AnarCry now**: Only Ctrl+Enter for execute. No other shortcuts.

**How to implement**:
Register key bindings via `InputMap`/`ActionMap` on the results table and editor:
- **Ctrl+C on results table**: copy selected cells
- **Ctrl+Shift+C**: copy with headers
- **F5**: re-execute last query
- **F7**: toggle value viewer panel
- **Escape**: clear selection

```java
resultsTable.getInputMap().put(KeyStroke.getKeyStroke("ctrl C"), "copyCell");
resultsTable.getActionMap().put("copyCell", new AbstractAction() {
    @Override public void actionPerformed(ActionEvent e) { copyCellToClipboard(); }
});
```

**Effort**: 1h | **Impact**: MEDIUM -- power user productivity

---

## Priority Matrix

| # | Improvement | Effort | Impact | Priority |
|---|-------------|--------|--------|----------|
| 1 | Auto-Resize Columns | 1h | HIGH | P0 |
| 2 | NULL Cell Rendering | 30min | HIGH | P0 |
| 3 | Alternating Row Colors | 30min | MEDIUM | P0 |
| 5 | Column Sorting | 15min | HIGH | P0 |
| 4 | Results Context Menu | 1.5h | HIGH | P1 |
| 6 | Rich Status Bar | 1.5h | HIGH | P1 |
| 10 | Keyboard Shortcuts | 1h | MEDIUM | P1 |
| 8 | Value Viewer Panel | 2-3h | HIGH | P2 |
| 9 | Tree Context Menu | 2h | MEDIUM | P2 |
| 7 | Tree Icons | 2-3h | MEDIUM | P3 |

## Implementation Order

**Phase 1 -- Quick Wins (2h total, massive visual improvement)**:
1. Column sorting (`setAutoCreateRowSorter(true)`)
2. NULL cell renderer
3. Alternating row colors
4. Auto-resize columns after query

**Phase 2 -- Interaction (3h total)**:
5. Results grid context menu (copy cell/row/column, copy as INSERT, sort)
6. Rich status bar with row count + execution time
7. Keyboard shortcuts (Ctrl+C, Ctrl+Shift+C, F5)

**Phase 3 -- Advanced (5h total)**:
8. Value viewer panel (F7, JSON/text preview)
9. Extended tree context menus
10. Tree node icons

---
Generated: 2026-11-23

Sources:
- [DBeaver Data Editor](https://github.com/dbeaver/dbeaver/wiki/Data-Editor)
- [DBeaver Data Editor Preferences](https://dbeaver.com/docs/dbeaver/Data-Editor-preferences/)
- [DBeaver Data View and Format](https://dbeaver.com/docs/dbeaver/Data-View-and-Format/)
- [DBeaver Data Viewing and Editing](https://github.com/dbeaver/dbeaver/wiki/Data-Viewing-and-Editing)
- [DBeaver Panels (Value Viewer)](https://github.com/dbeaver/dbeaver/wiki/Panels)
- [DBeaver Database Navigator](https://github.com/dbeaver/dbeaver/wiki/Database-Navigator)
- [DBeaver Connection Types](https://dbeaver.com/docs/dbeaver/Connection-Types/)
- [DBeaver Data Filters](https://github.com/dbeaver/dbeaver/wiki/Data-Filters)
- [DBeaver Shortcuts](https://dbeaver.com/docs/dbeaver/25.3/Shortcuts/)
- [DBeaver ResultSetViewer.java](https://github.com/dbeaver/dbeaver/blob/devel/plugins/org.jkiss.dbeaver.ui.editors.data/src/org/jkiss/dbeaver/ui/controls/resultset/ResultSetViewer.java)
- [DBeaver Grid Colorization](https://dbeaver.com/?p=161177)
