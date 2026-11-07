# API Client - Gap Analysis vs Bruno

## P0 - Critical

- [x] Drag-and-drop reordering in collection tree (move requests between folders, reorder within folder)
- [x] Close button (X) on request tabs (click X or middle-click)
- [x] Search/filter bar in collection sidebar
- [x] Move Up/Move Down in context menu

## P1 - Missing request editor tabs (Bruno has 10, we have 4)

Have: Headers, Body, Params, Auth, Vars, Assert, Docs, Settings
Missing:
- [x] Vars - per-request variables (pre/post, loads from VarsDef model)
- [ ] Script - pre-request/post-response scripts (model exists)
- [x] Assert - assertion editor table (add/remove assertions, enabled toggle)
- [x] Docs - request documentation editor
- [x] Settings - per-request settings (follow redirects, timeout, encode URL)

## P2 - Response panel gaps

- [x] Prettify button (JSON)
- [x] Copy response button
- [ ] Timeline tab (request timing breakdown)
- [x] Status blank before first send (empty label)
- [x] Response header count badge (Headers N)

## P3 - Other gaps

- [x] Body type selector (JSON/XML/Text/FormUrlEncoded/GraphQL/None)
- [ ] Params as table (Name/Value/Enabled) instead of raw text
- [ ] Auth structured form fields per auth type
- [ ] Request history tab
- [ ] Overflow menu (...) on tree items on hover

## Notes

Backend model layer is solid (24 model classes covering vars, assertions, settings, docs).
Most gaps now covered in GUI. Remaining: Script tab, Timeline tab, params-as-table, auth forms, request history.
