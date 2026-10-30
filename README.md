```
 █████╗ ███╗   ██╗ █████╗ ██████╗  ██████╗██████╗ ██╗   ██╗
██╔══██╗████╗  ██║██╔══██╗██╔══██╗██╔════╝██╔══██╗╚██╗ ██╔╝
███████║██╔██╗ ██║███████║██████╔╝██║     ██████╔╝ ╚████╔╝
██╔══██║██║╚██╗██║██╔══██║██╔══██╗██║     ██╔══██╗  ╚██╔╝
██║  ██║██║ ╚████║██║  ██║██║  ██║╚██████╗██║  ██║   ██║
╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝   ╚═╝
              Bug Bounty Security Scanner — effront
```

<div align="center">

[![Java Version](https://img.shields.io/badge/java-27-ED8B00?logo=openjdk)](https://openjdk.org/projects/jdk/27/)
[![Gradle](https://img.shields.io/badge/gradle-9.x-02303A?logo=gradle)](https://gradle.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

[![Lint](https://github.com/effront/anarcry/actions/workflows/lint.yml/badge.svg)](https://github.com/effront/anarcry/actions/workflows/lint.yml)
[![Security Scan](https://github.com/effront/anarcry/actions/workflows/security-scan.yml/badge.svg)](https://github.com/effront/anarcry/actions/workflows/security-scan.yml)
[![Spotless](https://img.shields.io/badge/code%20style-eclipse%20JDT-4CAF50)](https://github.com/diffplug/spotless)
[![Checkstyle](https://img.shields.io/badge/checkstyle-10.21.4-blue)](https://checkstyle.org/)
[![PMD](https://img.shields.io/badge/PMD-7.13.0-orange)](https://pmd.github.io/)
[![SpotBugs](https://img.shields.io/badge/SpotBugs%20+%20FindSecBugs-4.9.3-red)](https://spotbugs.github.io/)

</div>

---

```
+===========================================================================+
|  ANARCRY -- Java 27 Security Scanner                                      |
+===========================================================================+
|  TUI scanner for bug bounty. 25 attack modules, parallel execution,       |
|  CVSS v3.1 auto-scoring, knowledge base with 25 entries, export to        |
|  HackerOne and Bugcrowd. Crypto-first + OWASP Top 10.                     |
+===========================================================================+
```

---

<details>
<summary><kbd>Modules (click to expand)</kbd></summary>

```
+---------------------------------------------------------------------------+
|  RECON                                                                    |
|  [x] Crawler         -- HTML/JS path extraction, wordlist, OpenAPI        |
|  [ ] Infra           -- port scan, SSH/Redis/Docker/panel fingerprint     |
|                                                                           |
|  CRYPTO / INFRASTRUCTURE                                                  |
|  [x] TLS             -- version, weak cipher suites, expired cert, SHA-1  |
|  [x] Headers         -- CSP, X-Frame-Options, cookies, CORP/CORB          |
|  [x] HSTS            -- missing HSTS, weak max-age, includeSubDomains     |
|  [x] JWT             -- alg:none, RS256->HS256, JWK injection, kid,       |
|                         null signature, signature disclosure              |
|  [x] PQC             -- X25519MLKEM768, TLS 1.3, post-quantum groups      |
|                                                                           |
|  WEB (OWASP TOP 10)                                                       |
|  [x] SQLi            -- error-based + time-based blind SQL injection      |
|  [x] XSS             -- DOM sink analysis, canary reflection, payload     |
|  [x] LFI             -- Linux/Windows traversal, PHP wrappers, log RCE    |
|  [x] CmdInject       -- output-based + time-based blind with confirm      |
|  [x] CORS            -- origin reflection + credentials, wildcard, null   |
|  [x] OAuth           -- state CSRF, redirect_uri bypass, .well-known      |
|  [x] OpenRedirect    -- url/redirect/next/return/dest parameters          |
|  [x] SSRF            -- internal URLs, IP bypass, metadata endpoint       |
|  [x] GraphQL         -- introspection, field suggestions, batching DoS    |
|  [x] CRLF            -- path injection + header injection (raw socket)    |
|  [x] XXE             -- external entity, SSRF via XXE, blind XXE          |
|  [x] SSTI            -- FreeMarker, Jinja2, Velocity, Thymeleaf           |
|  [x] IDOR            -- cross-user, DELETE/PATCH tampering, UUID probing  |
|  [x] HostHeader      -- Host injection, cache poisoning via XFH           |
|  [x] Actuator        -- Spring Boot /env /heapdump /mappings /beans       |
|  [x] MassAssign      -- JSON mass assignment on REST endpoints            |
|  [x] CachePoisoning  -- unkeyed headers reflected and cached              |
|  [x] ReqSmuggling    -- CL.TE and TE.CL HTTP request smuggling            |
+---------------------------------------------------------------------------+
```

</details>

---

## Table of Contents

```
+------------------------------------------------------+
|  01 - Quick Start                                    |
|  02 - Technology Stack                               |
|  03 - Export Formats                                 |
|  04 - Findings                                       |
|  05 - Interface TUI                                  |
|  06 - Testing                                        |
|  07 - Architecture                                   |
|  08 - Knowledge Base                                 |
|  09 - Changelog                                      |
|  10 - Ethical Use                                    |
+------------------------------------------------------+
```

---

## 01 - Quick Start

```bash
./gradlew shadowJar
java -jar build/libs/anarcry-1.5.0.jar
```

With `.env.local` for pre-configured targets:

```bash
java -jar build/libs/anarcry-1.5.0.jar --env .env.local
```

---

## 02 - Technology Stack

```
+======================+====================================================+
|  LAYER               |  TECHNOLOGY                                        |
+======================+====================================================+
|  Language            |  Java 27 (Azul Zulu 27+)                           |
|  PQC                 |  ML-KEM / ML-DSA native via JEP 496/497            |
|  Build               |  Gradle 9.x + Shadow plugin (fat JAR)              |
|  TUI                 |  Lanterna 3.1.3                                    |
|  Crypto              |  BouncyCastle 1.80 (TLS, JWT, cipher probes)       |
|  HTTP Client         |  java.net.http.HttpClient (HTTP/2 default)         |
|  JSON                |  Gson 2.11.0                                       |
|  CVSS                |  CvssCalculator.java (FIRST formula, zero deps)    |
|  Knowledge Base      |  knowledge_base.json (25 entries, CWE+CVSS+VRT)    |
|  Test                |  JUnit 5.11.3                                      |
+======================+====================================================+
```

---

## 03 - Export Formats

| Format | How to use | Output |
|---|---|---|
| Markdown + JSON | `[E]` in TUI -> option 1 | `docs/reports/anarcry-report-*.md` + `.json` |
| HackerOne | `[E]` in TUI -> option 2 | `docs/reports/h1-report-*.md` (KB-enriched) |
| Bugcrowd | `[E]` in TUI -> option 3 | `docs/reports/bugcrowd-report-*.md` (VRT mapped) |
| JSON only | `[E]` in TUI -> option 4 | `docs/reports/anarcry-findings-*.json` |

HackerOne and Bugcrowd exports are enriched from the Knowledge Base with detailed descriptions, impact statements, remediation guidance, and VRT classification.

---

## 04 - Findings

Each finding includes: CVSS v3.1 Base Score (FIRST formula, computed locally), CWE ID resolved from Knowledge Base per module, concrete evidence with body/header snippets, step-by-step reproduction, and actionable recommendation.

Findings are deduplicated by `module|endpoint|title` and can be suppressed via `.anarcry-ignore.json`:

```json
[{"module": "Headers", "title": "Missing X-Frame-Options", "host": "*.example.com"}]
```

Example HackerOne export:

```
# [CRITICAL] JWT -- Algorithm None Accepted

**Program:** acme-bounty
**Asset:** https://api.target.com
**Severity:** Critical (CVSS 9.1 -- AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N)
**Weakness:** CWE-347 -- Improper Verification of Cryptographic Signature

## Summary
Server accepts JWT tokens with alg:none, allowing full authentication bypass.

## Steps to Reproduce
1. Navigate to the target asset: `https://api.target.com`
2. Send request with forged token:
   curl -H "Authorization: Bearer eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIn0." \
        https://api.target.com/api/me

## Impact
Complete authentication bypass. Any user can impersonate any other user
without knowing their credentials.
```

---

## 05 - Interface TUI

Two operational modes: **Target** (main scan interface) and **Repeater** (HTTP request replay). Tab bar at the top, status bar at the bottom with severity counters and progress.

```
 [Target] [Repeater]                                                 [Ctrl+P]
+---------------+-------------------------------------------------------+
| MODULES       | LOG                                     scroll: Up/Dn |
|               |                                                       |
| [x] TLS       |  [*] Module JWT started                               |
| [x] Headers   |  [!!] alg:none accepted -- CRITICAL                   |
| [x] HSTS      |  [!!] RS256->HS256 confusion -- CRITICAL              |
| [x] JWT       |  [!] JWK injection -- HIGH                            |
| [x] PQC       |  [+] JWT: 3 finding(s)                                |
| [x] CORS      |  [*] Module CORS started                              |
| [x] SQLi      |  [!!] Origin reflection + credentials -- CRITICAL     |
| [x] XSS       |  [+] CORS: 1 finding(s)                               |
| [x] SSRF      |                                                       |
| ...           |                                                       |
|               |                                                       |
| Target:       |                                                       |
| target.com    |                                                       |
|               |                                                       |
| JWT:          |                                                       |
| eyJ...        |                                                       |
|               |                                                       |
| [Start]       |                                                       |
| [Stop]        |                                                       |
+---------------+---+---------------------------------------------------+
| FINDINGS          |  FINDING DETAIL                                   |
| >CRIT 10.0 SSRF   |  Module: SSRF                                     |
|  CRIT  9.1 JWT    |  Endpoint: /api/fetch?url=                        |
|  CRIT  9.1 CORS   |  Evidence: Response contains ami-id               |
|  HIGH  8.1 JWT    |  Impact: Internal network access                  |
|  [Enter] Detail   |  Reproduction: curl -X GET ...                    |
+-------------------+---------------------------------------------------+
| target: https://t.com | C:3 H:1 M:0 L:0 | [====----] 8/20 | [E]xport  |
+-----------------------------------------------------------------------+
```

**Key bindings:**

| Key | Action |
|---|---|
| `Tab` | Switch mode (Target / Repeater) |
| `Ctrl+P` | Action palette (command menu) |
| `E` | Export menu (4 formats) |
| `Q` | Quit |
| `Enter` | Finding detail (modal with evidence + curl) |
| `C` | Copy curl to clipboard |
| `PgUp/PgDn` | Scroll log |
| `S` | Expand module progress to log (during scan) |
| `F8` | Event log drawer |

---

## 06 - Testing

```bash
./gradlew test              # unit + harness (no network) -- 125 tests
./gradlew integrationTest   # tests with external hosts (badssl.com, etc.)
```

Test suite covers: JWT probes (alg:none, weak secret, RS256->HS256, JKU, null signature, signature disclosure), CORS (origin reflection, wildcard, null origin), OAuth (well-known discovery, redirect_uri bypass), CRLF (path + header injection), SSRF, GraphQL introspection, Open Redirect, Cache Poisoning, Request Smuggling (CL.TE), SQLi (error-based + time-based), PQC, Headers, HSTS, ScanRunner orchestration (callbacks, module isolation, dedup, omnibus E2E), ReportEngine (MD+JSON export, JSON serialization), KnowledgeBase (loading, lookups, CweRegistry delegation), CvssCalculator, and a false-positive regression test on a clean server.

---

## 07 - Architecture

```
src/main/java/gg/effront/anarcry/
+-- Main.java                        Entry point
+-- EnvLoader.java                   .env.local loader
+-- model/
|   +-- Finding.java                 Record: 12 fields (module, endpoint, title,
|   |                                severity, evidence, impact, reproduction,
|   |                                recommendation, cweId, cweTitle, cvssVector,
|   |                                cvssScore)
|   +-- Severity.java                CRITICAL / HIGH / MEDIUM / LOW / INFO
|   +-- CweRegistry.java            Delegates to KnowledgeBase (25 entries + fallback)
|   +-- CvssCalculator.java         CVSS v3.1 Base Score (FIRST formula)
|   +-- KnowledgeBase.java          Singleton: loads knowledge_base.json, lookup by
|   |                                module or ID
|   +-- KnowledgeEntry.java         Record: title, module, severity, cweId, cvssVector,
|   |                                vrtId, summary, description, impact, payloads,
|   |                                crawlerHints, recommendation
|   +-- RequestRecord.java          HTTP request/response log entry
|   +-- Suppression.java            Finding suppression config
+-- scanner/
|   +-- Scanner.java                Interface: id() + scan(ScanContext, Consumer<String>)
|   +-- ScanRunner.java             Orchestrator: parallel execution (thread pool,
|   |                                parallelism=4), dedup, suppression, callbacks
|   +-- DiscoveredPaths.java        Thread-safe container for Crawler-discovered paths
|   +-- ScanContext.java            Record: targetUrl, jwtToken(s), enabledModules, config
|   +-- ScanConfig.java            Scope rules, suppression list, delay, relay URL
|   +-- ScanEvent.java             Progress events
|   +-- SuppressionLoader.java     Loads .anarcry-ignore.json
|   +-- util/
|   |   +-- Http.java              HTTP send wrapper with request logging
|   |   +-- HttpClientFactory.java Shared HttpClient (HTTP/2, no-redirect, follow-one)
|   |   +-- TlsUtil.java           BouncyCastle TLS context setup
|   +-- crypto/                    5 modules: TLS, Headers, HSTS, JWT (5 probes), PQC
|   +-- web/                       20 modules: SQLi, XSS, LFI, CmdInject, CORS, OAuth,
|                                   OpenRedirect, SSRF, GraphQL, CRLF, XXE, SSTI, IDOR,
|                                   HostHeader, Actuator, MassAssign, CachePoisoning,
|                                   ReqSmuggling, Crawler, Infra
+-- report/
|   +-- ReportEngine.java          MD+JSON / HackerOne / Bugcrowd (KB-enriched)
|                                   All reports saved to docs/reports/
+-- tui/
    +-- AnarCryTui.java            Main TUI window (Lanterna)
    +-- PasteableTextBox.java      Custom text box with paste support
    +-- chrome/                    ModeBar, StatusBar, ActionPalette, EventLogDrawer
    +-- modes/                     Target mode, Repeater mode
    +-- panels/                    FindingsPanel, LogPanel, ModulesPanel, SiteMapPanel
```

**Scan execution flow:**

```
ScanRunner.run(ScanContext)
  -> Phase 1: run Crawler (blocking) to populate DiscoveredPaths
  -> Phase 2: submit remaining modules to thread pool (parallelism=4)
     -> modules consume Crawler-discovered paths for smarter probing
  -> each module: Scanner.scan() -> List<Finding>
  -> deduplicate by module|endpoint|title
  -> apply suppressions from ScanConfig
  -> fire onFinding callback for each result
  -> fire onScanFinish when all modules complete
```

---

## 08 - Knowledge Base

`src/main/resources/knowledge_base.json` contains 25 entries, one per vulnerability class. Each entry provides:

- CWE ID and title
- CVSS v3.1 vector (curated per module)
- VRT ID (Bugcrowd Vulnerability Rating Taxonomy)
- Summary, description, and impact text
- Payloads and crawler hints
- Remediation guidance

`CweRegistry` delegates to `KnowledgeBase` at runtime -- findings auto-resolve CWE and CVSS from the KB when created via `Finding.of()`.

---

## 09 - Changelog

### v1.5.0

- **WAF evasion engine**: WafState + WafEvasion in scanner/util/ -- 5 bypass strategies (DOUBLE_ENCODE, CASE_MUTATION, UNICODE_NORMALIZE, CHARSET_EBCDIC, HPP)
- **ScanRunner Phase 1.5**: automatic WAF probe between Crawler recon and scanner modules -- detects effective bypass strategy
- **Module integration**: SQLi, XSS, LFI, SSTI, CmdInjection, XXE apply evasion payloads transparently when WAF detected
- **HeadersModule WAF state**: marks shared WafState on 403 + WAF signature detection
- **Test harness**: 26 WAF tests (18 unit + 8 integration with mock WAF server)

<details>
<summary><kbd>Previous releases (click to expand)</kbd></summary>

### v1.4.2

- **CVE-enriched reports**: scan reports (MD, HackerOne, Bugcrowd) now include Known CVEs table per vulnerability class, sourced from the knowledge base
- **KnowledgeEntry.CveEntry**: new record type for structured CVE data in the KB JSON

### v1.4.1

- **Knowledge base CVE enrichment**: 71 real-world CVEs added across 7 vulnerability classes (JWT, SQLi, SSRF, XSS, XXE, SSTI, LFI) sourced from MITRE CVE List v5

### v1.4

- **Intra-module parallelism**: ProbeExecutor with virtual threads (bounded concurrency, default 12) -- SQLi, XSS, LFI, CmdInjection, SSRF, SSTI, OpenRedirect, Crawler refactored for parallel payload dispatch
- **Severity from CVSS**: `Severity.fromScore()` using NIST NVD ranges -- severity is now always derived from the CVSS score, not hardcoded per module
- **Per-finding CVSS vectors**: JWT (6 finding types, LOW to CRITICAL) and CORS (4 finding types, MEDIUM to CRITICAL) carry per-finding vectors instead of flat module-level severity
- **WAF/403 detection**: HeadersModule detects known WAFs (Cloudflare, Akamai, etc) on HTTP 403, emits single INFO finding instead of false positive header findings
- **Register orphaned modules**: SQLi, XSS, LFI, CmdInjection wired into ScanRunner + both UIs
- **GUI fixes**: RepeaterView catch-all error handling + button re-enable; SiteMapView selection with full URL + click-to-copy; FindingDetailDialog multi-step repro split

### v1.3

- **Swing GUI migration**: full Swing + FlatLaf GUI replacing Lanterna TUI (Dashboard, Scan, Target, Findings, Repeater, Report, SiteMap tabs)
- **Privacy Mode**: toggle to redact URLs, JWTs, and IPs across all views (Ctrl+Shift+P)
- **Inline FindingDetailPanel**: single-click finding row shows tabbed details (Impact/Evidence/Reproduction/Recommendation)
- **FindingDetailDialog**: double-click opens full detail dialog
- **Export dialog**: Markdown, JSON, SARIF, HackerOne, Bugcrowd export from GUI
- **Emdash cleanup**: all unicode dashes replaced with ASCII across codebase and knowledge-base
- **AGPL-3.0 license**, CODE_OF_CONDUCT.md, SECURITY.md added

### v1.2

- **Two-phase scan**: Crawler runs first (Phase 1), then all other modules execute in parallel consuming Crawler-discovered paths via `DiscoveredPaths`
- **Crawler-enriched modules**: SSRF, IDOR, and MassAssignment now merge Crawler-discovered paths and parameters for broader attack surface coverage
- **SSRF optimization**: static asset filtering, high-value path prioritization, and cap of 20 active paths to prevent probe explosion
- **Per-path progress logging**: SSTI, CmdInjection, SQLi, XSS, and LFI modules log `[X/N] path` progress per iteration
- **Animated status bar**: active module names with animated dots, expandable via `S` key or status bar click
- **LogPanel fix**: disappearing logs after scan resolved via Lanterna `invalidate()` calls
- **New TUI checkboxes**: Crawler, HSTS, CachePoisoning, ReqSmuggling added to ModulesPanel

### v1.1

- Initial public release with 25 attack modules, CVSS v3.1 auto-scoring, HackerOne/Bugcrowd export, and TUI

</details>

---

## 10 - Ethical Use

AnarCry is designed for **authorized security testing** only:

- Always obtain written authorization before scanning
- Respect scope boundaries configured in `ScanConfig`
- Never scan targets without explicit permission
- Findings are for defensive purposes -- helping teams fix vulnerabilities
