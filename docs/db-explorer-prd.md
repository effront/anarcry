# DB Explorer PRD -- AnarCry v2.5.0

## Overview

The DB Explorer is AnarCry's post-exploitation database client, built for authorized
pentest engagements where the operator has gained database credentials and needs to
explore, query, and exfiltrate data efficiently. It supports SQL databases (PostgreSQL,
MySQL, MSSQL, SQLite, Oracle), MongoDB, and Redis, with optional SSH tunneling.

This PRD defines the next iteration of the DB Explorer UI/UX, closing the gap between
our current functional-but-rough interface and the polish level of tools like DBeaver.
The focus is on data grid quality, interaction patterns, and workflow speed -- the things
a pentester hits every time they open a result set.

**Reference documents**:
- `docs/dbeaver-ui-analysis.md` -- DBeaver UI deep dive (10 improvements with code snippets)
- `docs/dbeaver-gap-analysis.md` -- DBeaver feature gap analysis (10 feature gaps)

## Current State

### What exists today

| Component | Status | Notes |
|-----------|--------|-------|
| Connection tree | Done | Schema/table/column browsing with lazy load |
| Schema tree filter | Done | Type-ahead filter above connection tree |
| SQL editor | Done | RSyntaxTextArea with SQL syntax highlighting |
| Results grid | Done | Basic JTable, AUTO_RESIZE_OFF, no cell rendering |
| Query history | Done | History tab with timing, re-execute, copy SQL |
| Connection test | Done | Test button in connection dialog with server info |
| Export | Done | CSV, JSON, SQL INSERT, Markdown |
| Connection info | Done | Info tab populated on connect (server version, driver) |
| Status bar | Partial | Shows connection name only, no row count or timing |
| SSH tunneling | Done | Local port forwarding via MINA SSHD |
| Connection persistence | Done | JSON store in ~/.anarcry/ |

### What is broken or missing

The screenshot (2026-11-23) shows the core problems:
- All result columns are truncated to equal widths -- values like UUIDs, timestamps, and
  JSON are unreadable without manually resizing each column
- NULL values render as blank cells -- indistinguishable from empty strings
- No alternating row colors -- hard to track rows across wide result sets
- No column sorting -- clicking headers does nothing
- No context menu on the results grid -- no copy cell, copy row, or copy as SQL
- Status bar shows only "Active: prostaff -- Connected" -- no row count or query time
- No keyboard shortcuts beyond Ctrl+Enter for execute
- No value viewer for inspecting full cell content (JSON, long text)
- Tree nodes use default folder/leaf icons -- no visual distinction between schemas,
  tables, columns, and primary keys
- No right-click menu on tree nodes below the session level

---

## User Stories

### Phase 1 -- Data Grid Polish (P0)

---

#### DBX-001: Auto-Resize Columns to Content

**As a** pentester exploring a compromised database,
**I want** result columns to auto-size based on their content,
**so that** I can read UUIDs, timestamps, and other values without manually dragging
every column border.

**Acceptance Criteria**:
- [ ] After query execution, each column width is set to fit the widest value in the
  first 100 visible rows, plus 12px padding
- [ ] Column width is capped at 400px maximum to prevent a single column from consuming
  the entire grid
- [ ] Header text width is included in the calculation (column is never narrower than
  its header)
- [ ] Double-clicking a column header border auto-fits that column to all rows (not
  just the first 100)
- [ ] Works correctly after theme change (re-measures with new font metrics)
- [ ] `AUTO_RESIZE_OFF` is preserved -- horizontal scroll still works for wide result sets

**Priority**: P0
**Effort**: 1h
**Dependencies**: None

---

#### DBX-002: NULL Cell Rendering

**As a** pentester analyzing database contents,
**I want** NULL values to be visually distinct from empty strings,
**so that** I can tell whether a field is unset (NULL) or intentionally empty during
data exfiltration triage.

**Acceptance Criteria**:
- [ ] NULL cells display `[NULL]` in italic gray text
- [ ] Empty string cells display as empty (no text) -- visually distinct from NULL
- [ ] The `[NULL]` styling works in both light and dark themes
- [ ] When a row is selected, NULL cells use the selection foreground color (not gray)
- [ ] The renderer does not break column sorting or copy operations
- [ ] MongoDB and Redis results also render NULL/missing values consistently

**Priority**: P0
**Effort**: 30min
**Dependencies**: None

---

#### DBX-003: Alternating Row Colors

**As a** pentester reading wide result sets with many columns,
**I want** alternating row backgrounds (zebra striping),
**so that** I can visually track a row across the full width of the grid without losing
my place.

**Acceptance Criteria**:
- [ ] Even rows use the default table background
- [ ] Odd rows use a slightly darker/lighter shade (derived from the theme, not hardcoded)
- [ ] Selected rows override the stripe color with the selection background
- [ ] Stripe colors update correctly when switching between light and dark themes
- [ ] The stripe does not interfere with the NULL cell renderer (DBX-002)

**Priority**: P0
**Effort**: 30min
**Dependencies**: None

---

#### DBX-004: Column Sorting

**As a** pentester looking for specific data patterns,
**I want** to sort result columns by clicking the header,
**so that** I can quickly find the largest values, most recent timestamps, or
alphabetically locate specific entries.

**Acceptance Criteria**:
- [ ] Clicking a column header sorts ascending; clicking again sorts descending;
  third click removes the sort
- [ ] A sort direction arrow indicator appears in the column header (provided by FlatLaf)
- [ ] Sorting works correctly for string, numeric, and date values
- [ ] Row selection is preserved after sorting (selected data row stays selected)
- [ ] Sort state resets when a new query is executed
- [ ] Copy and export operations use the sorted order

**Priority**: P0
**Effort**: 15min (basic) / 1h (tri-state cycle)
**Dependencies**: None

---

### Phase 2 -- Interaction (P1)

---

#### DBX-005: Results Grid Context Menu

**As a** pentester extracting data from a compromised database,
**I want** a right-click context menu on result cells,
**so that** I can quickly copy individual values, full rows, or generate SQL statements
without manual text selection.

**Acceptance Criteria**:
- [ ] Right-clicking a cell selects that row and shows a popup menu
- [ ] Menu items:
  - **Copy Cell** -- copies the cell value (or `NULL` text for null) to clipboard
  - **Copy Row** -- copies all values in the row, tab-delimited, to clipboard
  - **Copy Row as INSERT** -- generates `INSERT INTO table (col1, col2) VALUES ('v1', 'v2');`
    for the selected row, using the current result column names
  - **Copy Column Name** -- copies the column header text to clipboard
  - Separator
  - **Sort Ascending** -- sorts by the clicked column ascending
  - **Sort Descending** -- sorts by the clicked column descending
- [ ] Ctrl+C on the results table copies the selected cell value
- [ ] Ctrl+Shift+C copies the selected row with column headers as first line
- [ ] The menu adapts when multiple rows are selected (Copy Rows, Copy as INSERT plural)

**Priority**: P1
**Effort**: 1.5h
**Dependencies**: DBX-004 (sorting)

---

#### DBX-006: Rich Status Bar

**As a** pentester running queries during an engagement,
**I want** to see the row count and execution time at a glance,
**so that** I get immediate feedback on query results without switching to the Messages tab.

**Acceptance Criteria**:
- [ ] The status bar is split into left and right sections
- [ ] Left section: connection status (existing -- "Active: prostaff -- Connected")
- [ ] Right section: row count label ("N rows") and execution time label ("Nms")
- [ ] Row count and execution time update after every query execution (SQL, MongoDB, Redis)
- [ ] For DML statements (INSERT/UPDATE/DELETE), show "N rows affected" instead
- [ ] Labels clear when switching to a disconnected session
- [ ] Execution time is measured in the same place as the History tab timing (consistency)

**Priority**: P1
**Effort**: 1.5h
**Dependencies**: None

---

#### DBX-007: Keyboard Shortcuts

**As a** pentester who works fast during time-limited engagements,
**I want** keyboard shortcuts for common DB Explorer actions,
**so that** I can navigate, copy, and re-execute without reaching for the mouse.

**Acceptance Criteria**:
- [ ] **Ctrl+C** on results table: copy selected cell(s) value to clipboard
- [ ] **Ctrl+Shift+C** on results table: copy selected row(s) with column headers
- [ ] **F5** anywhere in DB Explorer: re-execute the current query
- [ ] **Ctrl+Enter** in SQL editor: execute (already exists -- verify still works)
- [ ] **Escape** on results table: clear selection
- [ ] Shortcuts do not conflict with RSyntaxTextArea's built-in bindings
- [ ] Shortcuts work regardless of which sub-component has focus (editor vs. results vs. tree)

**Priority**: P1
**Effort**: 1h
**Dependencies**: DBX-005 (copy logic is shared)

---

### Phase 3 -- Advanced Data (P2)

---

#### DBX-008: Value Viewer Panel

**As a** pentester inspecting JSON API responses, long text fields, or binary data
stored in a database,
**I want** a panel that shows the full content of the selected cell with syntax
highlighting,
**so that** I can read and analyze values that are truncated in the grid without
manually copying them elsewhere.

**Acceptance Criteria**:
- [ ] A "Value Viewer" panel appears below (or beside) the results table
- [ ] Toggled with F7 key or a toolbar button; hidden by default
- [ ] When a cell is selected, its full value is displayed in an RSyntaxTextArea
- [ ] Syntax mode is auto-detected: JSON for values starting with `{` or `[`, XML for
  values starting with `<`, plain text otherwise
- [ ] NULL values display as `[NULL]` in the viewer
- [ ] The panel is read-only
- [ ] Panel state (open/closed) persists across query executions within the same session
- [ ] Panel updates on both cell click and keyboard navigation (arrow keys)
- [ ] Long values are displayed with word wrap enabled

**Priority**: P2
**Effort**: 2-3h
**Dependencies**: None

---

#### DBX-009: Extended Tree Context Menus

**As a** pentester exploring a database schema,
**I want** right-click context menus on schema, table, and column tree nodes,
**so that** I can quickly run common operations (SELECT *, copy names, export) without
typing SQL manually.

**Acceptance Criteria**:
- [ ] **Schema node** context menu:
  - Refresh -- reloads tables for this schema
  - Copy Name -- copies schema name to clipboard
- [ ] **Table node** context menu:
  - SELECT * FROM -- populates editor with `SELECT * FROM schema.table LIMIT 100` and
    executes
  - Copy Name -- copies table name to clipboard
  - Copy Qualified Name -- copies `schema.table` to clipboard
  - Export Table -- opens export dialog (CSV/JSON/SQL/Markdown) for this specific table
  - Row Count -- runs `SELECT COUNT(*) FROM schema.table` and shows result in Messages
- [ ] **Column node** context menu:
  - Copy Name -- copies column name to clipboard
  - Copy WHERE Clause -- copies `column_name = ''` to clipboard (for building queries)
- [ ] **MongoDB collection node** context menu:
  - Find All -- populates editor with `db.collection.find({}).limit(100)` and executes
  - Copy Name -- copies collection name to clipboard
- [ ] Existing session-level context menu (Connect, Disconnect, Edit, Remove) is preserved

**Priority**: P2
**Effort**: 2h
**Dependencies**: None

---

#### DBX-010: Tree Node Icons

**As a** pentester navigating complex database schemas with many node types,
**I want** distinct icons for each tree node type,
**so that** I can visually distinguish databases, schemas, tables, columns, and keys
at a glance without reading every label.

**Acceptance Criteria**:
- [ ] Icon assignments:
  - Session (connected): green database icon
  - Session (disconnected): gray database icon
  - Schema: folder/namespace icon
  - Table: grid/table icon
  - Column: generic column icon
  - Column (PK): column icon with key badge or distinct color
  - MongoDB database: document database icon
  - MongoDB collection: document icon
  - Redis key: key icon
- [ ] Icons are 16x16px, crisp on standard and HiDPI displays
- [ ] Icons respect dark/light theme (not washed out in either mode)
- [ ] Icons can be FlatLaf SVG icons, PNG resources, or Unicode symbols rendered as icons
- [ ] The existing green color for connected sessions is preserved alongside the icon

**Priority**: P2
**Effort**: 2-3h
**Dependencies**: None

---

### Phase 4 -- Feature Expansion (P2/P3)

---

#### DBX-011: SQL Auto-Completion

**As a** pentester writing queries against an unfamiliar database,
**I want** the SQL editor to suggest table names, column names, and SQL keywords as I type,
**so that** I can explore the schema without switching back and forth between the tree
and the editor.

**Acceptance Criteria**:
- [ ] `com.fifesoft:autocomplete` library is added to `build.gradle`
- [ ] After connecting, a `DefaultCompletionProvider` is populated with:
  - SQL keywords (SELECT, FROM, WHERE, INSERT, UPDATE, DELETE, JOIN, etc.)
  - All schema names from the connected database
  - All table names from all schemas
  - All column names from all tables (prefixed with table name for disambiguation)
- [ ] Completion triggers on Ctrl+Space (standard) or automatically after typing 2+ chars
- [ ] Completions update when the connection changes or schemas are refreshed
- [ ] Completions are case-insensitive
- [ ] The popup list shows the type (keyword, table, column) alongside each suggestion
- [ ] Works correctly with the existing RSyntaxTextArea SQL syntax highlighting

**Priority**: P2
**Effort**: 3-4h
**Dependencies**: None (new dependency: `com.fifesoft:autocomplete:3.3.1`)

---

#### DBX-012: Multiple Result Tabs

**As a** pentester comparing data across different tables or queries,
**I want** each query execution to open a new result tab instead of overwriting the
previous result,
**so that** I can compare results side by side without re-executing queries.

**Acceptance Criteria**:
- [ ] Each query execution creates a new closeable tab in the results area
- [ ] Tab title shows a truncated query snippet (first 30 chars) + timestamp (HH:mm:ss)
- [ ] Maximum of 5 result tabs are kept (oldest is closed when limit is exceeded)
- [ ] Each tab has its own independent JTable with its own data, sorting, and selection
- [ ] Closing a tab frees its data from memory
- [ ] The "Export Results" button exports from the currently visible result tab
- [ ] A "Close All Results" button or shortcut clears all result tabs
- [ ] The Messages, Info, and History tabs remain as global (not per-result) tabs

**Priority**: P2
**Effort**: 3-4h
**Dependencies**: DBX-001 (auto-resize applies to each new tab's table)

---

#### DBX-013: Connection Folders/Groups

**As a** pentester managing connections to multiple targets across different engagements,
**I want** to organize connections into named folders or groups,
**so that** I can keep credentials organized by engagement, environment, or target type.

**Acceptance Criteria**:
- [ ] An optional "Group" field is added to the connection dialog
- [ ] Connections with the same group are rendered under a parent folder node in the tree
- [ ] Ungrouped connections appear at the root level (backward compatible)
- [ ] Groups can be collapsed/expanded independently
- [ ] The group name is persisted in the connection store JSON
- [ ] The schema filter (DBX existing) also matches group names
- [ ] Groups can be renamed or removed (connections move to root)
- [ ] Groups are color-coded or visually distinct from session nodes

**Priority**: P3
**Effort**: 2-3h
**Dependencies**: None

---

#### DBX-014: Table Row Count in Tree

**As a** pentester triaging which tables to exfiltrate during a time-limited engagement,
**I want** to see estimated row counts next to table names in the connection tree,
**so that** I can prioritize large tables (user data, logs) over small reference tables.

**Acceptance Criteria**:
- [ ] After expanding a schema node, table nodes display estimated row count in
  parentheses: `users (12,345 rows)`
- [ ] Row counts are fetched from `information_schema.tables.TABLE_ROWS` (estimated, fast)
  for SQL databases
- [ ] Row counts are fetched lazily (not blocking tree expansion)
- [ ] Tables with 0 rows or no estimate show no count suffix
- [ ] MongoDB collections show `estimatedDocumentCount` in parentheses
- [ ] Row count display can be toggled off if it causes performance issues on large schemas

**Priority**: P3
**Effort**: 2h
**Dependencies**: None

---

#### DBX-015: EXPLAIN Viewer

**As a** pentester or developer analyzing query performance on a target database,
**I want** an "Explain" button that shows the query execution plan,
**so that** I can understand how the database processes a query and identify potential
performance issues or indexing gaps.

**Acceptance Criteria**:
- [ ] An "Explain" button is added to the SQL editor toolbar
- [ ] Clicking it prepends `EXPLAIN` (or `EXPLAIN ANALYZE` for PostgreSQL) to the current
  query and executes it
- [ ] The result is displayed in a dedicated "Plan" tab in the results area
- [ ] The `SqlDialect` enum provides the correct EXPLAIN syntax per database type:
  - PostgreSQL: `EXPLAIN (FORMAT TEXT)` or `EXPLAIN ANALYZE`
  - MySQL: `EXPLAIN`
  - MSSQL: `SET SHOWPLAN_TEXT ON` / `SET SHOWPLAN_TEXT OFF`
  - SQLite: `EXPLAIN QUERY PLAN`
  - Oracle: `EXPLAIN PLAN FOR` + `SELECT * FROM TABLE(DBMS_XPLAN.DISPLAY)`
- [ ] For databases that return structured output (PostgreSQL JSON format), the plan is
  rendered as an indented tree
- [ ] For databases that return text output, the raw text is displayed in a monospace area

**Priority**: P3
**Effort**: 3-4h
**Dependencies**: None

---

#### DBX-016: Saved Queries / Bookmarks

**As a** pentester who reuses the same reconnaissance queries across engagements,
**I want** to save frequently used queries as named bookmarks,
**so that** I can recall them instantly without retyping or searching my notes.

**Acceptance Criteria**:
- [ ] A "Save Query" button (or Ctrl+S when editor has focus) saves the current SQL
  with a user-provided name
- [ ] Saved queries are stored in `~/.anarcry/saved-queries.json`
- [ ] A "Saved Queries" dropdown or panel lists all saved queries alphabetically
- [ ] Clicking a saved query loads it into the SQL editor
- [ ] Right-click on a saved query allows: Load, Rename, Delete
- [ ] Saved queries are global (not per-connection) -- useful across engagements
- [ ] Import/export of saved queries is possible via the JSON file
- [ ] Duplicate names are prevented (prompt to overwrite)
- [ ] Maximum of 100 saved queries (oldest can be deleted manually)

**Priority**: P3
**Effort**: 2-3h
**Dependencies**: None

---

## Implementation Plan

### Phase Summary

| Phase | Stories | Total Effort | Focus |
|-------|---------|-------------|-------|
| Phase 1 | DBX-001, DBX-002, DBX-003, DBX-004 | ~2.5h | Data grid visual polish |
| Phase 2 | DBX-005, DBX-006, DBX-007 | ~4h | Interaction and feedback |
| Phase 3 | DBX-008, DBX-009, DBX-010 | ~7h | Advanced data inspection |
| Phase 4 | DBX-011, DBX-012, DBX-013, DBX-014, DBX-015, DBX-016 | ~16-20h | Feature expansion |

### Implementation Order

```
Phase 1 -- Data Grid Polish (P0, ~2.5h)
  |
  |-- DBX-004: Column Sorting .................. 15min  (one-liner, unblocks DBX-005)
  |-- DBX-002: NULL Cell Rendering ............. 30min  (custom DefaultTableCellRenderer)
  |-- DBX-003: Alternating Row Colors .......... 30min  (prepareRenderer override)
  |-- DBX-001: Auto-Resize Columns ............. 1h     (measure + cap + header dbl-click)
  |
Phase 2 -- Interaction (P1, ~4h)
  |
  |-- DBX-005: Results Context Menu ............ 1.5h   (copy cell/row/INSERT, sort items)
  |-- DBX-006: Rich Status Bar ................. 1.5h   (row count + timing labels)
  |-- DBX-007: Keyboard Shortcuts .............. 1h     (Ctrl+C, Ctrl+Shift+C, F5, Esc)
  |
Phase 3 -- Advanced Data (P2, ~7h)
  |
  |-- DBX-008: Value Viewer Panel .............. 2-3h   (RSyntaxTextArea, F7, auto-detect)
  |-- DBX-009: Extended Tree Context Menus ..... 2h     (schema/table/column right-click)
  |-- DBX-010: Tree Node Icons ................. 2-3h   (16x16 icons per node type)
  |
Phase 4 -- Feature Expansion (P2/P3, ~16-20h)
  |
  |-- DBX-011: SQL Auto-Completion ............. 3-4h   (com.fifesoft:autocomplete dep)
  |-- DBX-012: Multiple Result Tabs ............ 3-4h   (closeable tabs, max 5)
  |-- DBX-014: Table Row Count in Tree ......... 2h     (information_schema estimate)
  |-- DBX-016: Saved Queries ................... 2-3h   (JSON store, dropdown)
  |-- DBX-013: Connection Folders .............. 2-3h   (group field, tree parent nodes)
  |-- DBX-015: EXPLAIN Viewer .................. 3-4h   (per-dialect EXPLAIN, Plan tab)
```

### Already Shipped (v2.4.0)

These items from the original gap analysis are already implemented and are **not** in
scope for this PRD:

| Feature | Status | Shipped in |
|---------|--------|-----------|
| Query History (tab, timing, re-execute) | Done | v2.4.0 |
| Connection Test Button (server info, latency) | Done | v2.4.0 |
| Schema Tree Filter (type-ahead, recursive match) | Done | v2.4.0 |
| SQL INSERT + Markdown Export | Done | v2.4.0 |
| Connection Info on Connect (Info tab, Messages log) | Done | v2.4.0 |

---

## Technical Notes

### JTable Patterns

- **Custom renderer**: Subclass `DefaultTableCellRenderer`, set as default via
  `resultsTable.setDefaultRenderer(Object.class, renderer)`. The renderer handles NULL
  display, alternating rows, and type-specific formatting in one class.
- **Column auto-resize**: Use `table.prepareRenderer()` to measure cell widths without
  creating extra components. Measure only the first 100 rows for performance on large
  result sets.
- **Row sorting**: `setAutoCreateRowSorter(true)` gives basic sorting. For tri-state
  cycling (ASC -> DESC -> unsorted), create a custom `TableRowSorter` and override
  `toggleSortOrder`.
- **Context menu**: Use `MouseAdapter` with `isPopupTrigger()` on both `mousePressed`
  and `mouseReleased` (platform-dependent trigger). Select the row under the cursor
  before showing the menu.
- **Clipboard**: Use `java.awt.Toolkit.getDefaultToolkit().getSystemClipboard()` with
  `StringSelection` for plain text copy.

### FlatLaf Theming

- **Stripe color**: Derive from `UIManager.getColor("Table.background")` by adjusting
  brightness by 3-5% (darker in light theme, lighter in dark theme). Use
  `Color.brighter()` / `Color.darker()` or manual HSB adjustment.
- **Theme change**: Register `AnarCryLaf.addThemeListener()` to re-derive stripe color
  and re-apply renderers when the user switches themes.
- **Icons**: FlatLaf supports SVG icons via `FlatSVGIcon`. For quick implementation,
  Unicode symbols rendered as `JLabel` icons work but lack crispness. SVG is preferred
  for production quality.

### RSyntaxTextArea

- **Value viewer**: Create a second `RSyntaxTextArea` instance for the value panel.
  Set `setSyntaxEditingStyle()` dynamically based on detected content type.
- **Auto-completion**: The `com.fifesoft:autocomplete` library's `AutoCompletion` class
  wires directly to RSyntaxTextArea. Use `DefaultCompletionProvider` populated from
  `SchemaBrowser.listSchemas()`, `listTables()`, `listColumns()`.

### Data Model

- **Multiple result tabs**: Each tab needs its own `DefaultTableModel` and `JTable`
  instance. Wrap in a `record ResultTab(String title, JTable table, DefaultTableModel model,
  List<String> columns, List<List<String>> rows)` for clean lifecycle management.
- **Saved queries**: Store as JSON array in `~/.anarcry/saved-queries.json`:
  ```json
  [{"name": "Find admin users", "sql": "SELECT * FROM users WHERE role = 'admin'"}]
  ```
- **Connection groups**: Add `String group` field to `DbSession`. Persist in the
  connection store. Render as `DefaultMutableTreeNode` parent nodes above session nodes.

### Performance Considerations

- **Auto-resize**: Measuring all cells on a 10,000-row result set is expensive. Cap at
  first 100 rows. The double-click-to-fit feature can measure all rows since it is
  user-initiated.
- **Row count estimation**: Use `information_schema` estimated counts (fast) rather than
  `SELECT COUNT(*)` (slow on large tables without indexes). Make it async and update the
  tree label when the result arrives.
- **Auto-completion provider**: Populate the completion provider on a virtual thread
  after connecting. Large schemas (500+ tables) may take a moment -- show a "Loading
  schema..." indicator.

---

## Non-Goals

The following are explicitly **out of scope** for this PRD:

- **Data editing**: AnarCry is a read-only exploration tool for pentesting. DBeaver's
  inline cell editing, row insertion, and data modification features are not relevant.
  The operator queries and exfiltrates; they do not modify the target database.
- **ER diagrams**: DBeaver's visual entity-relationship diagrams are out of scope.
  Schema structure is navigable via the tree.
- **Data transfer / migration**: DBeaver's data pump, import wizards, and cross-database
  transfer tools are not needed. Export to files is sufficient.
- **Driver management**: AnarCry bundles all JDBC drivers. No driver download or
  management UI is needed.
- **SQL formatting / beautification**: The RSyntaxTextArea editor provides syntax
  highlighting. Automatic SQL formatting (like DBeaver's Ctrl+Shift+F) is nice-to-have
  but not in scope.
- **Stored procedure / function browsing**: The tree shows schemas, tables, and columns.
  Browsing stored procedures, views, triggers, and functions is not planned.
- **GIS / spatial data viewer**: DBeaver's map viewer for PostGIS data is not relevant
  to the pentesting use case.
- **Cloud database integrations**: DBeaver's AWS RDS, Azure SQL, and GCP Cloud SQL
  specific connection wizards are not needed. AnarCry connects via standard JDBC.

---

Generated: 2026-11-23
