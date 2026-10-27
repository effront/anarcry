# Sprint 18 — CrawlerModule & Dynamic Injection Engine

**Version:** 3.0 (consolidated)  
**Date:** 2026-10-26  
**Status:** REVIEW  
**Prerequisites:** Sprint 17 (KB integration + export engine) DONE

---

## 1. State Audit — Code Review Summary

### 1.1 ScanContext (`scanner/ScanContext.java`)

- Java `record` with 6 components: `targetUrl`, `jwtToken`, `jwtToken2`, `enabledModules`, `config`, `requestLog`
- 6 constructor overloads — all delegate to the canonical constructor
- Helper methods: `host()`, `port()`, `isHttps()`, `has(module)`
- **Key insight:** A record CAN hold a reference to a mutable object. The reference is final, but the object's internal state changes freely. Same pattern already used by `enabledModules` (a `Set<String>`). We exploit this for `DiscoveredPaths`.

### 1.2 ScanRunner (`scanner/ScanRunner.java`)

- All modules run in parallel via 4-thread `modulePool` (CompletableFuture)
- Module registration: `if (ctx.has("ModuleName"))` chain (lines 94-156), 21 modules total
- CrawlerModule already registered at line 151: `if (ctx.has("Crawler")) modules.add(new CrawlerModule())`
- **No phase ordering** — Crawler runs concurrently with all other modules
- **Problem:** For discovery to feed injection modules, Crawler must complete BEFORE them

### 1.3 CrawlerModule (`scanner/web/crawler/CrawlerModule.java`)

- ID: `"Crawler"`
- Existing: HTML link extraction, JS path extraction (regex), OpenAPI/Swagger discovery (8 paths), wordlist probing (~90 hardcoded paths), sensitive endpoint findings
- Local `Set<String> discovered` at line 57 — never shared externally
- **No KB integration:** Does not consume `crawlerHints.paths` or `crawlerHints.parameters`
- **No rate limiting:** No per-request throttling

### 1.4 ModulesPanel (`tui/panels/ModulesPanel.java`)

- **17 checkboxes** total (4 crypto + 13 web)
- **Missing from TUI** (but registered in ScanRunner): Crawler, HSTS, CSRF, CachePoisoning, ReqSmuggling
- `onStart()` builds `ScanContext` via 6-arg constructor at line 289

### 1.5 ScanConfig (`scanner/ScanConfig.java`)

- Record with `delayMs` field (int, default 0) — already exists for rate control
- We use this for crawler rate limiting: `delayMs > 0 ? delayMs : 100` (default 100ms = 10 req/s)

### 1.6 Injection Modules — Current Path Sources

| Module | Hardcoded Paths | Hardcoded Params | Benefits from Crawler |
|--------|----------------|------------------|-----------------------|
| SSRF | 13 `PROBE_PATHS` | 24 `URL_PARAMS` | Discovered paths + params |
| IDOR | 16 `ID_PATHS` + 8 `DELETE_PATHS` | - (uses JWT) | Discovered API endpoints |
| MassAssign | 10 `ENDPOINTS` (method+path) | - (fixed payload) | Discovered user/profile endpoints |

### 1.7 KnowledgeBase crawlerHints

Each of 25 KB entries has `crawlerHints: { parameters: [...], paths: [...] }`.
Exception: `infrastructure_exposure` has empty parameters and empty paths.

---

## 2. Architecture

```
┌──────────────────────────────────────────────────────┐
│                     ScanRunner                        │
│                                                       │
│  Phase 1 — ENRICHER (blocking)                        │
│  ┌─────────────────────────────────────────────┐      │
│  │  CrawlerModule.scan(ctx, log)               │      │
│  │  ├── HTML extraction (root page)            │      │
│  │  ├── JS path extraction                     │      │
│  │  ├── OpenAPI discovery                      │      │
│  │  ├── KB crawlerHints aggregation            │      │
│  │  ├── Wordlist + KB probing (rate-limited)   │      │
│  │  └── ctx.discoveredPaths().addPaths(...)    │      │
│  └─────────────────────────────────────────────┘      │
│                       │                               │
│                       ▼                               │
│  Phase 2 — SCANNERS (parallel, 4 threads)             │
│  ┌────────┐ ┌────────┐ ┌────────┐ ┌────────┐         │
│  │ SSRF   │ │ IDOR   │ │ Mass   │ │ TLS    │ ...     │
│  │ reads  │ │ reads  │ │ Assign │ │ (own)  │         │
│  │ ctx.   │ │ ctx.   │ │ reads  │ │        │         │
│  │ paths  │ │ paths  │ │ ctx.   │ │        │         │
│  └────────┘ └────────┘ └────────┘ └────────┘         │
└──────────────────────────────────────────────────────┘
```

### Design Decisions

1. **ScanContext stays a record.** Add `DiscoveredPaths` as the 7th component. A record holds a mutable reference — the reference is final, the container's state changes. All convenience constructors pass `new DiscoveredPaths()`. **Zero breaking changes.**

2. **DiscoveredPaths as a separate class.** Wraps `ConcurrentHashMap.newKeySet()` for paths and parameters. Unmodifiable views for readers. Thread-safe by design.

3. **No separate RateLimiter class.** `ScanConfig.delayMs()` already exists. CrawlerModule uses `Thread.sleep(ctx.config().delayMs() > 0 ? ctx.config().delayMs() : 100)` between probes. Simple, no new dependencies, 10 req/s default.

4. **Two-phase ScanRunner.** CrawlerModule identified by `id().equals("Crawler")` and extracted from module list. Phase 1 runs it blocking. Phase 2 runs everything else in parallel (existing behavior unchanged).

5. **KB hints aggregation in Crawler.** CrawlerModule loads `crawlerHints.paths` from ALL enabled modules' KB entries. Merged into probe set (union with WORDLIST, deduped). Parameters aggregated and pushed to `DiscoveredPaths`.

6. **Scope: only SSRF, IDOR, MassAssign for Sprint 18.** These 3 modules have the clearest path consumption patterns. XSS, SQLi, LFI, CmdInjection, SSTI, CRLF, XXE will be wired in Sprint 19+ (requires rethinking their param+payload injection loops — different architecture).

---

## 3. Tasks

### Task 1: Create `DiscoveredPaths` class

**File:** `src/main/java/gg/effront/anarcry/scanner/DiscoveredPaths.java` (NEW)

Thread-safe container for paths and parameters discovered during crawl phase.

```java
public final class DiscoveredPaths {
    private final Set<String> paths = ConcurrentHashMap.newKeySet();
    private final Set<String> parameters = ConcurrentHashMap.newKeySet();

    public void addPath(String path)                 { if (path != null && !path.isBlank()) paths.add(path); }
    public void addPaths(Collection<String> p)       { p.forEach(this::addPath); }
    public void addParameter(String param)           { if (param != null && !param.isBlank()) parameters.add(param); }
    public void addParameters(Collection<String> p)  { p.forEach(this::addParameter); }

    public Set<String> paths()      { return Collections.unmodifiableSet(paths); }
    public Set<String> parameters() { return Collections.unmodifiableSet(parameters); }
    public boolean isEmpty()        { return paths.isEmpty() && parameters.isEmpty(); }
    public int pathCount()          { return paths.size(); }
    public int parameterCount()     { return parameters.size(); }
}
```

~30 lines.

### Task 2: Extend ScanContext record

**File:** `src/main/java/gg/effront/anarcry/scanner/ScanContext.java`

Add `DiscoveredPaths discoveredPaths` as the 7th component:

```java
public record ScanContext(
    String targetUrl, String jwtToken, String jwtToken2,
    Set<String> enabledModules, ScanConfig config,
    Consumer<RequestRecord> requestLog,
    DiscoveredPaths discoveredPaths) { ... }
```

All 6 convenience constructors chain to canonical with `new DiscoveredPaths()`.

**Impact:** Only `ModulesPanel.onStart()` (line 289) uses a multi-arg call that needs the 7th arg added. All other callers use convenience constructors — unaffected.

~15 lines changed.

### Task 3: Enhance CrawlerModule with KB integration

**File:** `src/main/java/gg/effront/anarcry/scanner/web/crawler/CrawlerModule.java`

**Changes:**
1. Import `KnowledgeBase` and `KnowledgeEntry`
2. At scan start: aggregate `crawlerHints.paths` and `crawlerHints.parameters` from all enabled modules
3. Merge KB paths into probe set (union with WORDLIST, deduped via `LinkedHashSet`)
4. Rate limit: `Thread.sleep(delay)` between probes (default 100ms = 10 req/s)
5. After all discovery: push results to `ctx.discoveredPaths()`
6. Cap at 500 discovered paths (avoid combinatorial explosion in injection modules)

**Enhanced flow:**
```
1. HTML extraction (root page)              — existing
2. JS path extraction (from discovered .js) — existing
3. OpenAPI discovery                        — existing
4. Merge KB crawlerHints.paths              — NEW
5. Deduplicate merged set vs WORDLIST       — NEW
6. Wordlist + KB probing (rate-limited)     — enhanced
7. ctx.discoveredPaths().addPaths(all)      — NEW
8. ctx.discoveredPaths().addParameters(kb)  — NEW
```

~50 lines changed.

### Task 4: Split ScanRunner into two-phase execution

**File:** `src/main/java/gg/effront/anarcry/scanner/ScanRunner.java`

**Changes:**
- After building the module list, partition into:
  - `enrichers`: modules where `id().equals("Crawler")`
  - `scanners`: everything else
- Phase 1: Run enrichers sequentially (blocking). Emit `MODULE_START`/`MODULE_DONE` events.
- Phase 2: Run scanners in parallel via existing `modulePool` + CompletableFuture (current behavior).
- If Crawler is disabled or not in the list, skip Phase 1 entirely.
- Event flow: `SCAN_START` -> Phase 1 events -> Phase 2 events -> `SCAN_DONE`

**Log output:**
```
[*] Phase 1: Reconnaissance — Crawler
[~] Crawler: analyzing https://target.com
[~] Crawler: 42 paths from HTML, 18 KB hint paths merged
[+] Crawler: 67 paths, 31 params discovered
[*] Phase 2: 16 scanner modules (parallel)
[*] Module TLS started
[*] Module SSRF started (67 discovered paths available)
...
```

~35 lines changed.

### Task 5: Wire discovered paths into injection modules

Each module merges `ctx.discoveredPaths()` with its hardcoded lists when non-empty. Discovered paths are ADDITIVE — never remove hardcoded paths. Each module filters by relevance pattern.

#### 5a — SsrfModule (`scanner/web/ssrf/SsrfModule.java`)

Current: `PROBE_PATHS` (13 paths) + `URL_PARAMS` (24 params).

At scan start, merge discovered paths and params:
```java
List<String> probePaths = new ArrayList<>(PROBE_PATHS);
List<String> urlParams = new ArrayList<>(URL_PARAMS);
if (!ctx.discoveredPaths().isEmpty()) {
    for (String dp : ctx.discoveredPaths().paths()) {
        if (!probePaths.contains(dp)) probePaths.add(dp);
    }
    for (String p : ctx.discoveredPaths().parameters()) {
        if (!urlParams.contains(p)) urlParams.add(p);
    }
    log.accept("[~] SSRF: " + probePaths.size() + " paths ("
              + ctx.discoveredPaths().pathCount() + " from Crawler)");
}
```

Then use `probePaths` and `urlParams` in the existing probe loops instead of the static lists.

~15 lines.

#### 5b — IdorModule (`scanner/web/idor/IdorModule.java`)

Current: `ID_PATHS` (16 paths), `DELETE_PATHS` (8 paths), `extractUserId()` for dynamic paths.

Append discovered paths that look like resource endpoints:
```java
if (!ctx.discoveredPaths().isEmpty()) {
    for (String dp : ctx.discoveredPaths().paths()) {
        if (dp.matches(".*/(?:api|v[0-9])/.*") && !effectivePaths.contains(dp)) {
            effectivePaths.add(dp);
            effectivePaths.add(dp + "/1");
            effectivePaths.add(dp + "/2");
        }
    }
    log.accept("[~] IDOR: " + effectivePaths.size() + " paths (+" 
              + ctx.discoveredPaths().pathCount() + " from Crawler)");
}
```

~15 lines.

#### 5c — MassAssignmentModule (`scanner/web/massassign/MassAssignmentModule.java`)

Current: `ENDPOINTS` (10 method+path pairs).

Append discovered user/profile paths as PUT/PATCH candidates:
```java
List<Endpoint> endpoints = new ArrayList<>(ENDPOINTS);
if (!ctx.discoveredPaths().isEmpty()) {
    for (String dp : ctx.discoveredPaths().paths()) {
        if (dp.matches(".*/(user|profile|account|me|settings).*")) {
            if (endpoints.stream().noneMatch(e -> e.path().equals(dp))) {
                endpoints.add(new Endpoint("PUT", dp));
                endpoints.add(new Endpoint("PATCH", dp));
            }
        }
    }
    log.accept("[~] MassAssign: " + endpoints.size() + " endpoints (+"
              + (endpoints.size() - ENDPOINTS.size()) + " from Crawler)");
}
```

~15 lines.

### Task 6: Add missing TUI checkboxes to ModulesPanel

**File:** `src/main/java/gg/effront/anarcry/tui/panels/ModulesPanel.java`

**Changes:**
- Add new `RECON` section label (cyan) BEFORE the CRYPTO section
- Add `crawlerCheck` (`CheckBox("Crawler")`, checked by default)
- Add missing checkboxes for modules already in ScanRunner:
  - `hstsCheck` -> under CRYPTO (checked by default)
  - `cachePoisoningCheck` -> under WEB (checked by default)
  - `reqSmugglingCheck` -> under WEB (checked by default)
- Wire all new checkboxes in `onStart()` module set
- Update `onStart()` to pass 7th arg `new DiscoveredPaths()` to canonical ScanContext constructor

**TUI layout after:**
```
── RECON ───────────────
[x] Crawler

── CRYPTO ──────────────
[x] TLS
[x] Headers
[x] HSTS        <- NEW
[x] JWT
[x] PQC

── WEB ─────────────────
[x] CORS
[x] OAuth
[x] OpenRedirect
[x] SSRF
[x] GraphQL
[x] CRLF
[x] XXE
[x] SSTI
[x] HostHeader
[x] Actuator
[x] MassAssign
[x] CachePoisoning  <- NEW
[x] ReqSmuggling    <- NEW
[ ] IDOR
[ ] Infra
```

~60 lines.

### Task 7: Tests

**New:** `src/test/java/gg/effront/anarcry/scanner/DiscoveredPathsTest.java`
- Thread safety: populate from 4 threads, verify no lost entries
- Deduplication: add same path twice, verify size is 1
- Null/blank rejection: ignored gracefully
- Unmodifiable views: `paths()` throws on `add()`
- Path + parameter separation

**New:** `src/test/java/gg/effront/anarcry/scanner/ScanContextTest.java`
- `discoveredPaths()` starts empty on default constructors
- `addPaths()` populates and `discoveredPaths()` returns them
- Existing accessor methods still work (targetUrl, host, port, isHttps, has)

**Existing tests:** Run full suite to verify zero regressions from ScanContext 7th field change.

~90 lines across 2 files.

---

## 4. Execution Order

```
Task 1 (DiscoveredPaths)      <- foundational
    |
Task 2 (ScanContext)          <- add 7th component
    |
    +-- Task 3 (CrawlerModule KB)    <- depends on Task 2
    |
    +-- Task 4 (ScanRunner phases)   <- depends on Task 2
    |
    +-- Task 5 (Wire 3 modules)      <- depends on Task 2
    |
    +-- Task 6 (TUI checkboxes)      <- depends on Task 2
         |
         +-- Task 7 (Tests)          <- after all implementation
```

Tasks 3, 4, 5, and 6 can execute in parallel after Task 2 completes.

**Estimated effort:** ~325 lines across 10 files.

---

## 5. Risk Analysis

| Risk | Impact | Mitigation |
|------|--------|------------|
| ScanContext 7th field breaks callers | LOW | All 6 convenience constructors chain to canonical with default `new DiscoveredPaths()`. Only canonical call in `ModulesPanel.onStart()` needs 7th arg. |
| ScanRunner phase split breaks events | LOW | `SCAN_START`/`SCAN_DONE` preserved. MODULE events emitted per-module. TUI progress bar sees same stream. |
| Crawler rate limiter slows scan | LOW | 100ms default (10 req/s). ~150 paths = 15s max. Uses `ScanConfig.delayMs()` if set. |
| Discovered paths too noisy for modules | LOW | Each module filters by relevance pattern. Crawler caps at 500 paths. |
| Thread safety on DiscoveredPaths | NONE | `ConcurrentHashMap.newKeySet()` is lock-free. Phase 2 modules only read (Crawler finished in Phase 1). |
| KB crawlerHints overlap with WORDLIST | NONE | Merged into `LinkedHashSet` — automatic dedup. |
| Gradle Kryo test crash (pre-existing) | NONE | Unrelated to Sprint 18. Individual test classes pass. |

---

## 6. Files Changed

| File | Action | Lines (est.) |
|------|--------|-------------|
| `scanner/DiscoveredPaths.java` | **CREATE** | ~30 |
| `scanner/ScanContext.java` | Modify (add 7th component) | ~15 |
| `scanner/ScanRunner.java` | Modify (two-phase split) | ~35 |
| `scanner/web/crawler/CrawlerModule.java` | Modify (KB + ctx + rate limit) | ~50 |
| `scanner/web/ssrf/SsrfModule.java` | Modify (merge paths/params) | ~15 |
| `scanner/web/idor/IdorModule.java` | Modify (merge paths) | ~15 |
| `scanner/web/massassign/MassAssignmentModule.java` | Modify (merge paths) | ~15 |
| `tui/panels/ModulesPanel.java` | Modify (add 4 checkboxes + 7th arg) | ~60 |
| `test/.../DiscoveredPathsTest.java` | **CREATE** | ~50 |
| `test/.../ScanContextTest.java` | **CREATE** | ~40 |

**Total:** ~325 lines across 10 files

---

## 7. Non-Goals (Sprint 18)

- **Wiring XSS/SQLi/LFI/CmdInjection/SSTI/CRLF/XXE to DiscoveredPaths** — Sprint 19+. These modules need a different injection pattern (params x payloads loop), not just path merging.
- **Separate RateLimiter class** — `ScanConfig.delayMs()` + `Thread.sleep()` is sufficient. Guava/Semaphore overkill for single-threaded crawler.
- **Recursive crawling** — CrawlerModule crawls depth=1 (root page + linked JS). Recursive spidering is Sprint 20+.
- **Dynamic parameter detection** — Parsing HTML forms for `<input name="">` fields is Sprint 19+ (tied to XSS/SQLi).
- **CSRF checkbox** — CSRF module does not exist yet (only KB entry). Sprint 19+.
- **ScanEvent.Type.PHASE_START** — Not worth a new event type. Phase separation is logged via `[*] Phase 1: ...` / `[*] Phase 2: ...` text messages.
- **Running crypto modules in Phase 1** — Over-engineering. Crypto modules are fast (~2-5s) and don't benefit from parallel execution with Crawler. Keeping all non-Crawler modules in Phase 2 is simpler.

---

## 8. Validation Checklist

- [ ] `./gradlew test` — all tests pass (including KnowledgeBaseTest, ReportEngineTest)
- [ ] `./gradlew spotlessApply` + `./gradlew spotlessCheck` — formatting clean
- [ ] `./gradlew checkstyleMain` — zero violations
- [ ] Crawler enabled: scan discovers paths and SSRF/IDOR/MassAssign consume them
- [ ] Crawler disabled: injection modules use only hardcoded paths (zero regression)
- [ ] Rate limiting: crawler probes spaced by >= 100ms
- [ ] TUI: Crawler, HSTS, CachePoisoning, ReqSmuggling checkboxes visible
- [ ] Thread safety: DiscoveredPaths concurrent test passes
- [ ] Phased execution: log shows Phase 1 before Phase 2
- [ ] Discovered paths cap: <= 500 entries
