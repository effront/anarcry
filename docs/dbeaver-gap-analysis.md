# DBeaver Gap Analysis -- AnarCry DB/FTP Explorer

## Top 10 Gaps

### 1. SQL Auto-Completion (HIGH IMPACT)
**DBeaver**: Full semantic auto-complete via `SQLCompletionProposal` -- suggests table/column/function names from connected schema. Context-aware (knows FROM clause tables).
**AnarCry**: Zero auto-complete. RSyntaxTextArea has syntax highlighting only. The companion `com.fifesoft:autocomplete` library supports `CompletionProvider` -- not in build.gradle yet.
**How to adopt**: Add `com.fifesoft:autocomplete` dep. After connect, populate `DefaultCompletionProvider` with schema/table/column names from `SchemaBrowser`. Wire `AutoCompletion` to RSyntaxTextArea.

### 2. Query History / Log (HIGH IMPACT, LOW EFFORT)
**DBeaver**: `QueryLogViewer` -- persistent log of every query with timestamp, duration, row count, error status. Searchable. Re-execute from history.
**AnarCry**: Raw `messagesArea` output, no structured history, no timing, no recall.
**How to adopt**: Add `QueryHistoryPanel` tab in `resultsTabs`. Store each execution as record (SQL, timestamp, duration, rowCount, error). JTable with columns. Double-click re-populates editor.

### 3. Connection Test Button (MEDIUM IMPACT, LOW EFFORT)
**DBeaver**: `ConnectionTestDialog` -- validates connectivity before saving. Shows server version, driver version, latency.
**AnarCry**: No test button. Must Save + Connect to discover bad credentials. Critical for pentest credential testing.
**How to adopt**: Add "Test" button in `showConnectionDialog()`. Attempt JDBC connect in virtual thread, show server version + latency or error.

### 4. Multiple Result Tabs (MEDIUM IMPACT, MEDIUM EFFORT)
**DBeaver**: `MultiTabsQueryResultsContainer` -- each execution creates a new result tab. Compare results side by side.
**AnarCry**: Single `resultsTable` -- each execution overwrites previous result.
**How to adopt**: Each `executeQuery` creates a new closeable tab (query snippet + timestamp). Keep last N results (default 5).

### 5. Schema Tree Filter/Search (MEDIUM IMPACT, LOW EFFORT)
**DBeaver**: `DatabaseNavigatorTreeFilter` -- type-ahead filter narrowing visible tree nodes. Filter by type (tables, views) or name pattern.
**AnarCry**: No filter. Large schemas (hundreds of tables) unusable.
**How to adopt**: Add `JTextField` above `connectionTree` with `DocumentListener` that filters tree nodes by name.

### 6. More Export Formats (MEDIUM IMPACT, LOW EFFORT)
**DBeaver**: 11 formats -- CSV, JSON, XML, HTML, SQL INSERT, Markdown, source code, DbUnit, TXT.
**AnarCry**: Only CSV and JSON via `DataExporter`.
**How to adopt**: Add `exportSql()` (INSERT statements -- critical for pentest exfil) and `exportMarkdown()` (paste into reports).

### 7. Connection Folders/Groups (LOW-MEDIUM IMPACT)
**DBeaver**: `DBPDataSourceFolder` -- connections organized in folders, color-coded by environment.
**AnarCry**: Flat session list.
**How to adopt**: Add optional `group` field to `DbSession`. Render as parent nodes in tree.

### 8. Table Row Count / Stats in Tree (LOW-MEDIUM IMPACT)
**DBeaver**: `StatisticsNavigatorNodeRenderer` -- row count, table size, proportional bar next to tables. Lazy loaded.
**AnarCry**: No stats. During data exfil assessment, table sizes help prioritize.
**How to adopt**: Fetch `information_schema.tables.TABLE_ROWS` estimate. Show count next to table name.

### 9. Execution Plan / EXPLAIN (LOW-MEDIUM IMPACT, MEDIUM EFFORT)
**DBeaver**: `ExplainPlanViewer` -- visual EXPLAIN tree per DB type.
**AnarCry**: No EXPLAIN support.
**How to adopt**: "Explain" button prepends EXPLAIN to query. Parse output into tree tab. `SqlDialect` already has per-DB knowledge.

### 10. Saved Queries / Bookmarks (LOW IMPACT, LOW EFFORT)
**DBeaver**: `BookmarkStorage` -- save queries as bookmarks in folders.
**AnarCry**: No saved queries.
**How to adopt**: Store in `~/.anarcry/saved-queries.json`. "Save Query" button + dropdown.

## Priority Matrix

| # | Gap | Impact | Effort | Pentest Value |
|---|-----|--------|--------|---------------|
| 1 | SQL Auto-Completion | High | Medium | High |
| 2 | Query History | High | Low | High |
| 3 | Connection Test | Medium | Low | High |
| 4 | Multiple Result Tabs | Medium | Medium | Medium |
| 5 | Schema Tree Filter | Medium | Low | High |
| 6 | More Export Formats | Medium | Low | High |
| 7 | Connection Groups | Low-Med | Low | Medium |
| 8 | Table Stats in Tree | Low-Med | Low | Medium |
| 9 | EXPLAIN viewer | Low-Med | Medium | Low |
| 10 | Saved Queries | Low | Low | Medium |

**Quick wins**: #2 Query History, #3 Connection Test, #5 Schema Filter, #6 SQL INSERT export
**High effort, high reward**: #1 SQL Auto-Completion, #4 Multiple Result Tabs

---
Generated: 2026-11-23
