# AnarCry Recon & Wordlist Integration Analysis

## 1. Current State -- Hardcoded Payload Audit

Every AnarCry scanner module uses **hardcoded** `List.of(...)` constants for paths, parameters, and attack payloads. There is no external wordlist loading, no `src/main/resources/wordlists/` directory, and no SecLists integration. The knowledge base (`knowledge-base/*.md`) feeds a handful of extra payloads per module via `KnowledgeBase.getInstance().filteredPayloads(id())`, but coverage is thin.

### Module-by-Module Inventory

| Module | Category | Hardcoded Counts | Details |
|--------|----------|-----------------|---------|
| **CrawlerModule** | Discovery | ~90 paths, 8 OpenAPI paths, 1 regex | `WORDLIST` has ~90 entries covering `/api/*`, `/admin/*`, `/swagger*`, CMS, backup files, common dirs. `OPENAPI_PATHS` has 8 Swagger/OpenAPI endpoints. `PATH_PATTERN` regex extracts paths from JS. |
| **SQLi** | Injection | 7 paths, 11 params, 5 error payloads, 3 time-based | `ERROR_PAYLOADS`: `'`, `"`, `')`, `' AND 1=1--`, `' AND 1=2--`. `TIME_PAYLOADS`: MySQL SLEEP, PostgreSQL pg_sleep, MSSQL WAITFOR. WAF mode reduces to 5 params. |
| **XSS** | Injection | 8 paths, 10 params, 1 hardcoded + KB-enriched | Base payload: `<img src=x onerror=zz>`. `buildXssPayloads()` merges KB entries dynamically. Paths: `/`, `/search`, `/api/search`, `/q`, `/filter`, etc. |
| **LFI** | Traversal | 8 paths, 8 params, 11 Linux + 6 Windows payloads | Linux: `../../etc/passwd` with encoding variants (double-URL, null-byte, UTF-8 overlong). Windows: `../../windows/win.ini`, `../../boot.ini` + encoding variants. Log poisoning checks 3 log paths. |
| **CmdInjection** | Injection | 8 paths, 10 params, 5 active + 6 sleep | Active: `; id`, `\| id`, `\|\| id`, `&& id`, `$(id)`. Sleep: `; sleep 5`, `\| sleep 5`, etc. KB payloads merged. WAF mode reduces to 7 params. |
| **SSRF** | SSRF | 10 paths, 14 params, 14 probes + 4 WAF + 3 redirect | Probes cover localhost (7 encoding variants), AWS/Azure/GCP metadata (4 endpoints). Redirect bypass with 3 high-signal probes. 10+ redirect params. |
| **SSTI** | Injection | 8 paths, 10 params, 8 detection + 6 RCE | Detection: `${7*7*7*7}` (FreeMarker), `{{7*7}}` (Jinja2/Twig), `#{7*7}` (Thymeleaf), etc. RCE probes for FreeMarker Execute, Jinja2 subprocess, Velocity Runtime, Twig system, EL Runtime, Pebble Runtime. |
| **NoSQLi** | Injection | 7 paths, 9 params, 6 operator + 5 JSON | Operator: `[$ne]`, `[$gt]`, `[$regex]`, `[$exists]`, `[$nin]`. JSON: `{"$ne":""}`, `{"$gt":""}`, `{"$regex":".*"}`, constructor pollution, `$where`. |
| **OpenRedirect** | Redirect | 8 paths, 8 params, 6 payloads | Payloads: absolute, protocol-relative, encoded-slash, user-info (`@evil`), backslash, encoded-scheme. |
| **CRLF** | Injection | 15 path payloads, 3 header injections | Path: `%0a`, `%0d%0a`, `%0d`, `%23%0a`, double-encoded variants, path-traversal combos. Header injection via raw socket on User-Agent, Referer, Accept-Language. |
| **CORS** | Misc | 4 paths, 6 origin probes | Probes: reflection (`evil.com`), null origin, subdomain trust, scheme downgrade (HTTP from HTTPS), wildcard + credentials. |
| **XXE** | Injection | 10 XML endpoints, 3 payloads | Payloads: file read (`/etc/passwd`), SSRF (internal metadata), Billion Laughs (DoS). Endpoints: `/api/*`, `/upload`, `/import`, `/xmlrpc`, `/soap`, etc. |
| **Deserialization** | Injection | 8 probe paths, 10 params, 6+ framework endpoints | Framework detection: JMXInvokerServlet, ViewState, GatewayServlet, JNDIDetector, WebLogic T3, Jenkins. Param fuzzing for serialized object markers. |
| **GraphQL** | Discovery | 8 endpoints, 3 queries, typo queries | Introspection, __typename, mutation introspection. Typo squatting queries for suggestion-based schema extraction. |
| **Secrets** | Detection | 17 regex patterns | AWS (access + secret), GitHub (pat, oauth), GitLab, Slack (bot, user), Google API, Stripe (secret + pub), private keys, JWT, generic API key/password, Heroku, Twilio, SendGrid, Mailgun. |
| **CachePoisoning** | Misc | 3 paths, 8 unkeyed headers | Headers: X-Forwarded-Host, X-Forwarded-Scheme, X-Original-URL, X-Rewrite-URL, X-Forwarded-Port, X-Host, X-Forwarded-Server, X-HTTP-Method-Override. |
| **HostHeader** | Misc | 4 headers, 4 targets | Headers: Host, X-Forwarded-Host, X-Host, X-Original-Host. Targets: GET /, POST /login, GET /reset-password, POST /api/auth. |
| **IDOR** | AuthZ | 6 ID paths, 4 delete paths, 2 GQL mutations | Hardcoded `/api/user/1`, `/api/user/2`, etc. GQL mutations for deleteUser. Crawler-discovered UUIDs merged dynamically. |
| **CSRF** | Misc | 8 probe paths + crawler-discovered | Built-in: `/`, `/login`, `/account`, `/settings`, `/profile`, etc. Dynamically merges crawler-discovered form paths. |
| **SubTakeover** | Infra | 12 subdomains, 10 service fingerprints | Subdomains: www, api, app, dev, staging, admin, mail, cdn, assets, static, beta, test. Fingerprints: GitHub Pages, Heroku, S3, Azure, Shopify, Fastly, Pantheon, Tumblr, WordPress, Surge. |
| **CloudMisconfig** | Infra | 16 bucket suffixes, 5 fallback paths, 4 cloud patterns | Bucket suffix enumeration: -assets, -backup, -dev, -staging, -prod, -static, -media, etc. S3, Azure Blob, GCS, Firebase URL pattern detection. |
| **ProtoPollution** | Injection | 8 paths, 10 params, 4 client + 3 server payloads | Client: `__proto__[ppcanary]`, `constructor.prototype`, nested. Server JSON: `{"__proto__":{}}`, `{"constructor":{"prototype":{}}}`. |
| **WebSocket** | Misc | 11 WS paths | `/ws`, `/websocket`, `/socket.io`, `/sockjs`, `/hub`, `/signalr`, `/cable`, `/realtime`, `/stream`, `/events`, `/graphql`. |
| **FileUpload** | Bypass | 7 upload paths, 8 field names, 6 alt extensions, 3 magic bytes | Extensions: `.phtml`, `.php5`, `.php7`, `.shtml`, `.asa`, `.cer`. Magic bytes: GIF89a, PNG header, JPEG header. Multipart fuzzing. |
| **Smuggling** | Protocol | Raw socket probes, 3 TE variants | CL.TE, TE.CL, TE.TE mutation probes via raw TCP. H2 smuggling (CLEN, TE, method, path override). Variants: `xchunked`, `chunked, chunked`, `chunked\t`. |
| **RaceCondition** | Logic | Endpoint-targeted, 10 concurrent requests | Targets discovered endpoints from crawler. Sends concurrent POST requests and compares response consistency. |
| **InfraModule** | Infra | 20 probe ports, panel detection probes | SSH, Docker, etcd, Grafana, GlassFish, Kibana, Redis, Jenkins, Consul, Jupyter, Portainer, Prometheus, Elasticsearch, Kubelet, RabbitMQ, MongoDB, Hadoop. Uses nmap if available. |
| **SpringActuator** | Infra | ~15 actuator endpoints | `/actuator/env`, `/actuator/configprops`, `/actuator/mappings`, `/actuator/beans`, `/actuator/health`, `/actuator/info`, `/actuator/heapdump`, etc. |
| **OAuth** | AuthZ | 2 well-known paths, 4 authorize paths | Well-known: `/.well-known/openid-configuration`, `/.well-known/oauth-authorization-server`. Authorize: `/oauth/authorize`, `/oauth2/authorize`, `/authorize`, `/auth/authorize`. |

### Total Hardcoded Asset Count

| Asset Type | Count |
|-----------|-------|
| Discovery paths (Crawler) | ~90 |
| Scan endpoint paths (all modules) | ~140 |
| Parameter names | ~90 |
| Attack payloads | ~180 |
| Regex patterns (Secrets) | 17 |
| Subdomain names | 12 |
| Service fingerprints | 10 |
| **TOTAL embedded entries** | **~540** |

---

## 2. SecLists Mapping (Available at `/usr/share/seclists/`)

SecLists is installed locally. Below maps each AnarCry module to its corresponding SecLists wordlists.

### Discovery / Crawling

| SecLists Path | Lines | AnarCry Module | Purpose |
|---------------|-------|----------------|---------|
| `Discovery/Web-Content/common.txt` | 4,751 | CrawlerModule | General path discovery (vs 90 hardcoded) |
| `Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt` | 220,559 | CrawlerModule | Deep directory brute (too large for embedded, profile: "thorough") |
| `Discovery/Web-Content/raft-medium-directories.txt` | 29,999 | CrawlerModule | Raft medium -- good balance |
| `Discovery/Web-Content/api/api-endpoints.txt` | 295 | CrawlerModule | API endpoint discovery |
| `Discovery/Web-Content/api/api-seen-in-wild.txt` | 7,615 | CrawlerModule | Real-world API paths |
| `Discovery/Web-Content/common-api-endpoints-mazen160.txt` | 174 | CrawlerModule | Curated API endpoints |
| `Discovery/Web-Content/graphql.txt` | 106 | GraphQLModule | GraphQL endpoint discovery |
| `Discovery/Web-Content/common_pt-br.txt` | 2,921 | CrawlerModule | PT-BR specific paths |
| `Discovery/Web-Content/burp-parameter-names.txt` | 6,453 | All injection modules | Parameter name discovery |
| `Discovery/DNS/subdomains-top1million-5000.txt` | 5,000 | SubTakeoverModule | Subdomain enumeration (vs 12 hardcoded) |
| `Discovery/DNS/subdomains-top1million-20000.txt` | 20,000 | SubTakeoverModule | Extended subdomain enumeration |
| `Discovery/Infrastructure/nmap-ports-top1000.txt` | ~1,000 | InfraModule | Port scanning (vs 20 hardcoded) |
| `Discovery/Infrastructure/common-http-ports.txt` | ~50 | InfraModule | HTTP-specific ports |

### Injection / Fuzzing

| SecLists Path | Lines | AnarCry Module | Purpose |
|---------------|-------|----------------|---------|
| `Fuzzing/Databases/SQLi/Generic-SQLi.txt` | ~267 | SQLi | Generic SQLi payloads (vs 8 hardcoded) |
| `Fuzzing/Databases/SQLi/quick-SQLi.txt` | ~78 | SQLi | Quick SQLi payloads |
| `Fuzzing/Databases/SQLi/MySQL.fuzzdb.txt` | ~97 | SQLi | MySQL-specific payloads |
| `Fuzzing/Databases/SQLi/MSSQL.fuzzdb.txt` | ~40 | SQLi | MSSQL-specific payloads |
| `Fuzzing/Databases/SQLi/Oracle.fuzzdb.txt` | ~30 | SQLi | Oracle-specific payloads |
| `Fuzzing/Databases/SQLi/sqli.auth.bypass.txt` | ~50 | SQLi | Auth bypass payloads |
| `Fuzzing/Databases/SQLi/SQLi-Polyglots.txt` | ~10 | SQLi | Polyglot payloads |
| `Fuzzing/Databases/SQLi/NoSQL.txt` | 22 | NoSQLi | NoSQL injection payloads (vs 11 hardcoded) |
| `Fuzzing/XSS/robot-friendly/*.txt` | ~16,518 | XSS | XSS payloads (BruteLogic, PortSwigger, EnDe) |
| `Fuzzing/XSS/human-friendly/*.txt` | ~14,223 | XSS | XSS payloads (readable format) |
| `Fuzzing/LFI/LFI-Jhaddix.txt` | 930 | LFI | LFI traversal paths (vs 17 hardcoded) |
| `Fuzzing/LFI/LFI-LFISuite-pathtotest-huge.txt` | 9,550 | LFI | Comprehensive LFI (thorough profile) |
| `Fuzzing/LFI/Linux/*.txt` | ~9,235 | LFI | Linux-specific file paths |
| `Fuzzing/LFI/Windows/*.txt` | ~5,485 | LFI | Windows-specific file paths |
| `Fuzzing/command-injection-commix.txt` | 8,262 | CmdInjection | Command injection (vs 11 hardcoded) |
| `Fuzzing/template-engines-expression.txt` | 11 | SSTI | Template expression probes |
| `Fuzzing/template-engines-identification.txt` | 24 | SSTI | Template engine identification |
| `Fuzzing/template-engines-special-vars.txt` | 78 | SSTI | Template special variables |
| `Fuzzing/XXE-Fuzzing.txt` | 51 | XXE | XXE payload variants (vs 3 hardcoded) |
| `Pattern-Matching/errors.txt` | ~100 | SQLi, SSTI | Error pattern matching |
| `Discovery/Variables/secret-keywords.txt` | ~50 | Secrets | Secret keyword patterns |

### Coverage Gap Analysis

| Module | Hardcoded | SecLists Available | Gap Factor |
|--------|-----------|-------------------|------------|
| **Crawler (paths)** | 90 | 4,751+ (common.txt) | **53x** |
| **SQLi (payloads)** | 8 | ~570 (all SQLi files) | **71x** |
| **XSS (payloads)** | 1 + KB | ~30,000+ (all XSS files) | **massive** |
| **LFI (traversals)** | 17 | ~12,200 (all LFI files) | **718x** |
| **CmdInjection** | 11 | 8,262 (commix) | **751x** |
| **SSTI** | 14 | 113 (template files) | **8x** |
| **NoSQLi** | 11 | 22 | **2x** |
| **XXE** | 3 | 51 | **17x** |
| **Subdomains** | 12 | 5,000-20,000 | **417x-1667x** |
| **Infra (ports)** | 20 | 1,000+ | **50x** |
| **Parameters** | 90 | 6,453 (burp params) | **72x** |

---

## 3. Integration Architecture

### 3.1 WordlistLoader Utility

New class: `scanner/util/WordlistLoader.java`

```
WordlistLoader
  +-- load(String resourcePath) -> List<String>       // from src/main/resources/wordlists/
  +-- loadExternal(Path file) -> List<String>          // from filesystem (SecLists)
  +-- merge(List<String> base, List<String> extra) -> List<String>  // dedup + merge
  +-- loadForModule(String moduleId, String category) -> List<String>
```

**Loading priority** (highest wins):
1. `ScanConfig` custom wordlist path per module (user override)
2. External filesystem path (e.g., `/usr/share/seclists/...`)
3. Embedded `src/main/resources/wordlists/{module}/{category}.txt`
4. Hardcoded `List.of(...)` fallback (current behavior)

### 3.2 Embedded Minimal Wordlists

Directory: `src/main/resources/wordlists/`

These are **curated subsets** of SecLists -- small enough to ship in the fat JAR but significantly better than current hardcoded lists.

```
src/main/resources/wordlists/
  crawler/
    paths-common.txt          # 500 entries (curated from common.txt + api-endpoints)
    paths-api.txt             # 300 entries (from api-seen-in-wild, api-endpoints)
    paths-pt-br.txt           # 200 entries (from common_pt-br.txt)
  sqli/
    error-based.txt           # 50 entries (from Generic-SQLi.txt, curated)
    time-based.txt            # 30 entries (MySQL, PostgreSQL, MSSQL, Oracle, SQLite)
    auth-bypass.txt           # 30 entries (from sqli.auth.bypass.txt)
    polyglots.txt             # 10 entries (from SQLi-Polyglots.txt)
  xss/
    payloads.txt              # 100 entries (curated from BruteLogic + PortSwigger)
    bypass.txt                # 50 entries (WAF bypass variants)
  lfi/
    linux.txt                 # 100 entries (from LFI-Jhaddix.txt, curated)
    windows.txt               # 50 entries (from Windows-LFI-Payloads)
    log-poisoning.txt         # 20 entries
  cmdinject/
    payloads.txt              # 100 entries (curated from commix)
    blind.txt                 # 30 entries (sleep/ping-based)
  ssrf/
    probes.txt                # 30 entries (IP encoding + metadata endpoints)
    cloud-metadata.txt        # 20 entries (AWS/Azure/GCP/DigitalOcean/Oracle)
  ssti/
    detection.txt             # 30 entries (from template-engines-identification + expression)
    rce.txt                   # 20 entries (per-engine RCE gadgets)
  nosqli/
    payloads.txt              # 30 entries (from NoSQL.txt + curated)
  xxe/
    payloads.txt              # 30 entries (from XXE-Fuzzing.txt, curated)
  crlf/
    payloads.txt              # 30 entries (path + header injection variants)
  openredirect/
    payloads.txt              # 20 entries
  secrets/
    patterns.txt              # 30 entries (regex patterns, one per line)
  discovery/
    subdomains.txt            # 500 entries (from subdomains-top1million-5000.txt)
    parameters.txt            # 500 entries (from burp-parameter-names.txt)
    ports.txt                 # 100 entries (from common-http-ports + nmap-top1000)
```

**Estimated embedded size**: ~3,500 entries total, ~120KB uncompressed (negligible in shadow JAR).

### 3.3 ScanConfig Wordlist Settings

Add to `ScanConfig`:

```java
// Wordlist configuration
private final Path wordlistDir;           // e.g., /usr/share/seclists
private final WordlistProfile profile;    // MINIMAL, STANDARD, THOROUGH

enum WordlistProfile {
    MINIMAL,     // hardcoded only (current behavior, fastest)
    STANDARD,    // embedded wordlists (default, ~3,500 entries)
    THOROUGH     // external SecLists (largest, slowest)
}
```

TUI integration: add "Wordlist Profile" dropdown in TargetMode settings (Minimal / Standard / Thorough).

### 3.4 Per-Module Override

Each module calls `WordlistLoader.loadForModule(id(), category)` which resolves:

```
MINIMAL  -> List.of(...) hardcoded constant (current)
STANDARD -> src/main/resources/wordlists/{module}/{category}.txt
THOROUGH -> {wordlistDir}/Fuzzing/{mapped-path} or /Discovery/{mapped-path}
```

Module mapping table (THOROUGH profile):

| Module | Category | SecLists Mapping |
|--------|----------|-----------------|
| Crawler | paths | `Discovery/Web-Content/common.txt` |
| Crawler | api-paths | `Discovery/Web-Content/api/api-seen-in-wild.txt` |
| SQLi | error | `Fuzzing/Databases/SQLi/Generic-SQLi.txt` |
| SQLi | time | `Fuzzing/Databases/SQLi/quick-SQLi.txt` |
| SQLi | auth-bypass | `Fuzzing/Databases/SQLi/sqli.auth.bypass.txt` |
| XSS | payloads | `Fuzzing/XSS/human-friendly/XSS-BruteLogic.txt` |
| LFI | linux | `Fuzzing/LFI/LFI-Jhaddix.txt` |
| LFI | windows | `Fuzzing/LFI/Windows/Windows-LFI-Payloads_by-adeadfed.txt` |
| CmdInjection | payloads | `Fuzzing/command-injection-commix.txt` |
| SSTI | detection | `Fuzzing/template-engines-identification.txt` |
| SSTI | rce | `Fuzzing/template-engines-special-vars.txt` |
| NoSQLi | payloads | `Fuzzing/Databases/SQLi/NoSQL.txt` |
| XXE | payloads | `Fuzzing/XXE-Fuzzing.txt` |
| SubTakeover | subdomains | `Discovery/DNS/subdomains-top1million-5000.txt` |
| Infra | ports | `Discovery/Infrastructure/nmap-ports-top1000.txt` |

---

## 4. Implementation Plan

### Phase 1: WordlistLoader + Embedded Wordlists

1. Create `scanner/util/WordlistLoader.java`
   - `load(String)` reads from classpath resources
   - `loadExternal(Path)` reads from filesystem
   - `merge(List, List)` deduplicates preserving order
   - Comment-line stripping (`#` prefix)
   - Empty-line filtering
   - UTF-8 encoding

2. Create `src/main/resources/wordlists/` directory structure
   - Curate subsets from SecLists for each module
   - Keep total size under 200KB

3. Add `WordlistProfile` enum to ScanConfig

### Phase 2: Module Migration

4. Migrate each module to use `WordlistLoader`:
   - Keep `List.of(...)` as `FALLBACK` constant
   - Replace direct usage with `WordlistLoader.loadForModule()` call
   - Priority order: CrawlerModule, SQLi, XSS, LFI, CmdInjection (highest gap factor)

5. Register SecLists path mappings in `WordlistLoader.MODULE_MAPPING`

### Phase 3: TUI Integration

6. Add "Wordlist Profile" selector to TargetMode
7. Add "SecLists Path" text field (auto-detected from `/usr/share/seclists` or configurable)
8. Show wordlist stats in scan start log: "SQLi: 267 payloads (THOROUGH profile)"

### Phase 4: Custom Wordlist Support

9. Support per-module custom wordlist override in ScanConfig
10. Support `.anarcry-wordlists.json` config file for persistent custom mappings

---

## 5. Risk Assessment

| Risk | Mitigation |
|------|-----------|
| Large wordlists slow down scans | Profile system (MINIMAL/STANDARD/THOROUGH), circuit breaker already in place |
| WAF rate limiting with more requests | Existing WAF delay system (`wafDelayMs`), circuit breaker at 25 blocks |
| SecLists not installed on target system | STANDARD profile uses embedded wordlists, THOROUGH gracefully falls back |
| Payload dedup with KB payloads | `WordlistLoader.merge()` deduplicates, KB payloads always appended |
| Fat JAR size increase | Embedded wordlists ~120KB, negligible vs current JAR |
| Breaking existing module behavior | Hardcoded lists preserved as `FALLBACK`, MINIMAL profile uses them |

---

## 6. Quick Wins (No Architecture Changes)

These can be done immediately by expanding the hardcoded `List.of(...)` constants:

1. **CrawlerModule WORDLIST**: Add ~50 high-value paths from `common.txt` (total ~140)
2. **SubTakeover COMMON_SUBDOMAINS**: Expand from 12 to 50 (top subdomains from SecLists)
3. **Secrets patterns**: Add ~10 more regex (Firebase, Azure, Datadog, New Relic, npm tokens)
4. **SQLi TIME_PAYLOADS**: Add Oracle (`DBMS_LOCK.SLEEP(5)`) and SQLite (`randomblob(100000000)`)
5. **SSRF PROBES**: Add DigitalOcean metadata (`169.254.169.254/metadata/v1/`), Oracle Cloud
6. **InfraModule PROBE_PORTS**: Add 10 more high-value ports (5432 PostgreSQL, 3306 MySQL, 11211 Memcached, etc.)
7. **SubTakeover FINGERPRINTS**: Add Netlify, Vercel, Fly.io, Railway, Render

---

## 7. Comparison: AnarCry vs Manual Tooling

| Capability | AnarCry (Current) | ffuf + SecLists | gobuster + SecLists | Nuclei |
|-----------|-------------------|-----------------|--------------------|----|
| Path discovery | 90 paths | 220,000+ | 220,000+ | Templates |
| Parameter fuzzing | ~90 params | 6,453 | N/A | Templates |
| SQLi payloads | 8 | 570+ | N/A | ~50 templates |
| XSS payloads | 1 + KB | 30,000+ | N/A | ~100 templates |
| LFI traversals | 17 | 12,200+ | N/A | ~30 templates |
| Subdomain enum | 12 | N/A | N/A | N/A (subfinder) |
| Port scanning | 20 | N/A | N/A | N/A (nmap) |
| **Advantage** | Integrated, auto-exploit, TUI | Raw volume | Raw volume | Community templates |

**After integration (THOROUGH profile)**: AnarCry matches ffuf/gobuster payload volume while retaining its integrated scanning pipeline, auto-exploitation, and report generation advantages.
