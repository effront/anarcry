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
[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL--3.0-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)

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
|  Security scanner for bug bounty. 38 attack modules, parallel execution,  |
|  CVSS v3.1 auto-scoring, knowledge base with 34 entries, WAF detection    |
|  (15 providers) + circuit breaker. OAST blind detection infra.            |
|  TUI + Swing GUI + AI Assistant.                                          |
|  Built-in API Client (Bruno-inspired) with collections, environments,     |
|  auth injectors, variable interpolation, scripting, runner + assertions.  |
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
|  [x] TLS             -- version, weak ciphers (raw TLS probe), cert, SHA-1|
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
|  [x] IDOR            -- cross-user GET/DELETE, COOKIE auth, UUID probing  |
|  [x] HostHeader      -- Host injection, cache poisoning via XFH           |
|  [x] Actuator        -- Spring Boot /env /heapdump /mappings /beans       |
|  [x] MassAssign      -- JSON mass assignment on REST endpoints            |
|  [x] CachePoisoning  -- unkeyed headers reflected and cached              |
|  [x] ReqSmuggling    -- CL.TE, TE.CL, TE.TE, Duplicate CL, CL.0,          |
|                         Hop-by-hop TE, H2.CL, H2.TE, HPACK manipulation   |
|  [x] CSRF           -- token validation, SameSite, referer/origin bypass  |
|  [x] Secrets        -- 17 patterns (AWS, GCP, GitHub, Slack, JWTs, etc.)  |
|  [x] NoSQLi        -- MongoDB operator injection, auth bypass             |
|  [x] Deserialization-- Java/PHP/Python/.NET gadget detection              |
|  [x] SubTakeover   -- dangling CNAME, service fingerprinting              |
|  [x] WebSocket     -- origin validation, unauth endpoint detection        |
|  [x] ProtoPollution-- __proto__, constructor.prototype injection          |
|  [x] CloudMisconfig-- S3/Azure/GCS public access, metadata endpoint       |
|  [ ] RaceCondition  -- concurrent request state inconsistency (opt-in)    |
|  [ ] FileUpload    -- extension/content-type/magic byte bypass (opt-in)   |
|                                                                           |
|  OAST (Out-of-Band Application Security Testing)                          |
|  [x] OastServer     -- HTTP/DNS callback server for blind detection       |
|  [x] OastCorrelator -- payload-to-callback correlation engine             |
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
|  05 - Interface (TUI + GUI)                          |
|  06 - Testing                                        |
|  07 - Architecture                                   |
|  08 - Knowledge Base                                 |
|  09 - AI Assistant                                   |
|  10 - API Client                                     |
|  11 - Changelog                                      |
|  12 - Ethical Use                                    |
+------------------------------------------------------+
```

---

## 01 - Quick Start

```bash
./gradlew shadowJar
java -jar build/libs/anarcry-2.2.1.jar
```

Or use the launcher (auto-builds if source changed):

```bash
./anarchrypto
```

With `.env.local` for pre-configured targets:

```bash
./anarchrypto --env .env.local
```

Launch in GUI mode (Swing + FlatLaf):

```bash
java -jar build/libs/anarcry-2.2.1.jar --gui
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
|  Knowledge Base      |  knowledge_base.json (34 entries, CWE+CVSS+VRT)    |
|                      |  knowledge-base/*.md (27 enriched entries)         |
|  AI Assistant        |  Multi-provider (Claude, OpenAI, Gemini, Ollama)   |
|  GUI                 |  Swing + FlatLaf (dark/light) + RSyntaxTextArea    |
|                      |  + JFreeChart                                      |
|  Test                |  JUnit 5.11.3                                      |
+======================+====================================================+
```

---

## 03 - Export Formats

| Format | How to use | Output |
|---|---|---|
| Markdown + JSON | `[E]` in TUI -> option 1 | `~/.anarcry/reports/anarcry-report-*.md` + `.json` |
| HackerOne | `[E]` in TUI -> option 2 | `~/.anarcry/reports/h1-report-*.md` (KB-enriched) |
| Bugcrowd | `[E]` in TUI -> option 3 | `~/.anarcry/reports/bugcrowd-report-*.md` (VRT mapped) |
| JSON only | `[E]` in TUI -> option 4 | `~/.anarcry/reports/anarcry-findings-*.json` |
| SARIF v2.1.0 | `[E]` in TUI -> option 5 | `~/.anarcry/reports/sarif-report-*.sarif.json` |

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

## 05 - Interface

Two interfaces: **TUI** (Lanterna, terminal-native) and **GUI** (Swing + FlatLaf, desktop). Both offer the same core functionality: Target scan, Repeater, Findings, SiteMap, Export. The GUI adds a Dashboard with severity chart (JFreeChart), Preferences dialog with persistent settings (`~/.anarcry/settings.json`), dark/light theme, and the AI Assistant chat view.

### TUI

Nine modes: Dashboard, Scan, Target, Findings, Repeater, Report, SiteMap, API Client, Assistant. Tab bar at the top, status bar at the bottom with severity counters and progress.

```
 [Dash] [Scan] [Target] [Findings] [Repeater] [Report] [SiteMap] [API] [Asst] [Ctrl+P]
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
| Auth Type:    |                                                       |
| [JWT v]       |                                                       |
| JWT Token:    |                                                       |
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

### GUI

Launch with `--gui` flag. Tabs: Dashboard, Scan, Target, Findings, Repeater, Report, SiteMap, API Client, Assistant.

```
+-----------------------------------------------------------------------------------+
| AnarCry                                            [Privacy] [Preferences]        |
+-----------------------------------------------------------------------------------+
| Dashboard | Scan | Target | Findings | Repeater | Report | SiteMap | API | Asst   |
+-----------------------------------------------------------------------------------+
|                                                                                   |
|  Severity Distribution (pie)               |   Recent Findings                    |
|  [CRIT: 3] [HIGH: 5]                       |   - JWT alg:none (CRITICAL)          |
|  [MED: 8]  [LOW: 2]                        |   - CORS origin reflect (CRITICAL)   |
|                                            |   - XSS reflected (HIGH)             |
|                                            |                                      |
+-----------------------------------------------------------------------------------+
|  Status: Scanning...                       | 8/25 modules | C:3 H:5 M:8 L:2 I:0   |
+-----------------------------------------------------------------------------------+
```

**AI Assistant tab:** chat interface with SSE streaming, tool-use indicators, and token usage display. Supports Claude, OpenAI, Gemini, and Ollama. Configure provider and API key in Preferences.

---

## 06 - Testing

```bash
./gradlew test              # unit + harness (no network)
./gradlew integrationTest   # tests with external hosts (badssl.com, etc.)
```

Test suite covers: JWT probes (alg:none, weak secret, RS256->HS256, JKU, null signature, signature disclosure, x5c, x5u, key confusion), CORS (origin reflection, wildcard, null origin), OAuth (well-known discovery, redirect_uri bypass), CRLF (path + header injection), SSRF, GraphQL (introspection, mutation, nested DoS, batching), Open Redirect, Cache Poisoning, Request Smuggling (CL.TE, TE.CL, Duplicate CL, CL.0, Hop-by-hop TE, H2.CL, H2.TE), SQLi (error-based + time-based), PQC, Headers, HSTS, IDOR (COOKIE auth, cross-user), OAST (server lifecycle, correlator matching, config validation), ScanRunner orchestration (callbacks, module isolation, dedup, omnibus E2E), ReportEngine (MD+JSON+SARIF export, JSON serialization), KnowledgeBase (34 entries, lookups, CweRegistry delegation), CvssCalculator, API Client (collections, importers, runner, assertions), and a false-positive regression suite on a clean server.

---

## 07 - Architecture



<details>
<summary><kbd> wanna see? (click to expand)</kbd></summary>

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
|   +-- CweRegistry.java            Delegates to KnowledgeBase (34 entries + fallback)
|   +-- CvssCalculator.java         CVSS v3.1 Base Score (FIRST formula)
|   +-- KnowledgeBase.java          Singleton: loads knowledge_base.json, lookup by
|   |                                module or ID
|   +-- KnowledgeEntry.java         Record: title, module, severity, cweId, cvssVector,
|   |                                vrtId, summary, description, impact, payloads,
|   |                                crawlerHints, recommendation
|   +-- RequestRecord.java          HTTP request/response log entry
|   +-- AuthType.java               Auth selector enum (NONE, JWT, COOKIE, BEARER)
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
|   |   +-- Http.java              HTTP send wrapper with request logging, WAF detection
|   |   +-- HttpClientFactory.java Shared HttpClient (HTTP/2, no-redirect, follow-one)
|   |   +-- TlsUtil.java           BouncyCastle TLS context setup
|   |   +-- WafState.java          WAF/CDN state: block type, circuit breakers, stealth
|   |   +-- WafEvasion.java        5 bypass strategies + 15-vendor signature detection
|   |   +-- CircuitBreaker.java    Per-module WAF block counter with dynamic threshold
|   +-- crypto/                    5 modules: TLS (+ RawTlsProbe), Headers, HSTS,
|   |                               JWT (8 probes incl. x5c, x5u, key confusion), PQC
|   +-- web/                       30 modules: SQLi, XSS, LFI, CmdInject, CORS, OAuth,
|   |                               OpenRedirect, SSRF, GraphQL, CRLF, XXE, SSTI, IDOR,
|   |                               HostHeader, Actuator, MassAssign, CachePoisoning,
|   |                               ReqSmuggling, Crawler, Infra, CSRF, Secrets,
|   |                               RaceCondition, NoSQLi, Deserialization, FileUpload,
|   |                               SubTakeover, WebSocket, ProtoPollution, CloudMisconfig
|   +-- oast/                      OAST infrastructure: OastServer, OastCorrelator,
|                                   OastPayload, OastCallback, OastConfig
+-- report/
|   +-- ReportEngine.java          MD+JSON / HackerOne / Bugcrowd (KB-enriched)
|                                   All reports saved to ~/.anarcry/reports/
+-- assistant/
|   +-- AiAssistant.java           SSE streaming, tool dispatch, conversation history
|   +-- ContextBuilder.java        System prompt with Finding Validation Protocol
|   +-- AssistantConfig.java       Provider/model/API key/temperature config
|   +-- ChatMessage.java           Conversation message record
|   +-- UsageTracker.java          Token usage tracking and cost estimation
|   +-- providers/
|   |   +-- ProviderAdapter.java   Interface: formatRequest, parseResponse, streaming
|   |   +-- AnthropicProvider      Claude API (content_block_start/input_json_delta)
|   |   +-- OpenAiProvider         OpenAI API (delta.tool_calls)
|   |   +-- GeminiProvider         Google Gemini API
|   |   +-- OllamaProvider         Local Ollama API
|   +-- tools/
|       +-- GetFindingsTool        Retrieve scan findings
|       +-- GetSitemapTool         Retrieve discovered sitemap
|       +-- GetScanConfigTool      Retrieve scan configuration
|       +-- QueryKbTool            Query knowledge base entries
|       +-- ExplainCweTool         Explain CWE IDs with context
|       +-- SaveDocTool            Save markdown documents to ~/.anarcry/reports/
+-- gui/
|   +-- AnarCryGui.java            Main Swing window (FlatLaf theme)
|   +-- AppSettings.java           Singleton: ~/.anarcry/settings.json persistence (Gson)
|   +-- GuiController.java         View orchestration and scan lifecycle
|   +-- PrivacyFilter.java         URL/JWT/IP redaction (Ctrl+Shift+P)
|   +-- views/
|   |   +-- DashboardView          Overview with severity chart (JFreeChart)
|   |   +-- TargetView             Target config + module selection
|   |   +-- FindingsView           Findings table with detail panel
|   |   +-- RepeaterView           HTTP request replay
|   |   +-- SiteMapView            Crawled sitemap tree
|   |   +-- ReportView             Report generation and export
|   |   +-- ApiClientView          API Client with collection tree + request tabs
|   |   +-- AssistantView          AI Assistant chat with streaming + tools
|   |   +-- PreferencesDialog      Settings dialog with persistence (10 categories)
|   |   +-- EnvironmentEditorDialog  API Client environment variable editor
|   |   +-- GlobalSearchDialog     Cross-tab search (Ctrl+K)
|   |   +-- ExportDialog           Multi-format export (MD, JSON, SARIF, H1, BC)
|   +-- components/                Reusable GUI components
|   |   +-- StatusBarIcons.java    Tabler Icons loader (PNG, 16x16)
|   +-- theme/                     FlatLaf theme customization
+-- tui/
    +-- AnarCryTui.java            Main TUI window (Lanterna)
    +-- PasteableTextBox.java      Custom text box with paste support
    +-- chrome/                    ModeBar, StatusBar, ActionPalette, EventLogDrawer
    +-- modes/                     Target mode, Repeater mode
    +-- panels/                    FindingsPanel, LogPanel, ModulesPanel, SiteMapPanel,
                                    ApiClientPanel, AssistantPanel
```

**Scan execution flow:**

```
ScanRunner.run(ScanContext)
  -> Phase 1: run Crawler (blocking) to populate DiscoveredPaths
  -> Phase 1.5: WAF detection -- baseline GET + canary probe
     -> multi-vendor signature detection (15 providers)
     -> classify block type: RULE_BLOCK / MANAGED_CHALLENGE / JS_CHALLENGE / VERCEL_CHALLENGE / TURNSTILE
     -> probe evasion strategies (skip for managed challenges)
  -> Phase 2: submit remaining modules to thread pool (parallelism=4)
     -> per-module timeout (180s via CompletableFuture.orTimeout)
     -> per-module circuit breaker (8 blocks, 3 for managed challenges)
     -> runtime WAF detection + stealth auto-activation in Http.send()
     -> modules consume Crawler-discovered paths for smarter probing
  -> each module: Scanner.scan() -> List<Finding>
  -> deduplicate by module|endpoint|title
  -> apply suppressions from ScanConfig
  -> fire onFinding callback for each result
  -> fire onScanFinish when all modules complete
```
</details>


---

## 08 - Knowledge Base

Two layers:

**Structured data** -- `src/main/resources/knowledge_base.json` contains 34 entries (one per vulnerability class). Each entry provides CWE ID, CVSS v3.1 vector, VRT ID, summary, payloads, crawler hints, and remediation. `CweRegistry` delegates to `KnowledgeBase` at runtime -- findings auto-resolve CWE and CVSS from the KB when created via `Finding.of()`.

**Enriched markdown** -- `knowledge-base/*.md` contains 27 entries with extended sections:

- Description, impact, payloads and bypasses
- Escalation Techniques (account takeover, data exfiltration, lateral movement)
- Hunting Methodology (step-by-step discovery procedure)
- False Positive Indicators (non-exploitable contexts, framework auto-escape)
- Notable CVEs (71 real-world CVEs across 7 classes from MITRE CVE List v5)
- WAF evasion strategies (Cloudflare, Akamai, Vercel-specific bypasses)

The AI Assistant uses the markdown KB via `QueryKbTool` for contextual vulnerability analysis.

---

## 09 - AI Assistant

Built-in LLM-powered security analyst available in both TUI and GUI. Supports four providers:

| Provider | Models | Streaming |
|----------|--------|-----------|
| Claude (Anthropic) | claude-sonnet-4-20250514, claude-opus-4-20250514 | SSE with tool fragments |
| OpenAI | gpt-4o, gpt-4o-mini | SSE with tool fragments |
| Gemini | gemini-2.0-flash, gemini-2.5-pro | SSE |
| Ollama | any local model | SSE |

**Tools:** The assistant has 7 tools it can call proactively during analysis:

| Tool | Purpose |
|------|---------|
| `get_findings` | Retrieve current scan findings with severity filter |
| `get_sitemap` | Retrieve Crawler-discovered paths and parameters |
| `get_scan_config` | Retrieve target, scope, and auth configuration |
| `query_kb` | Query knowledge base for vulnerability context |
| `explain_cwe` | Explain CWE IDs with impact and remediation |
| `save_document` | Save markdown reports to ~/.anarcry/reports/ |

**Slash commands:** `/findings`, `/explain <id>`, `/remediate`, `/plan`, `/kb <topic>`, `/report`

**Finding Validation Protocol:** The assistant follows a mandatory 6-step validation before confirming any finding -- verify attack surface, analyze reflection context, check defenses, confirm impact, honest severity assessment, report or discard. Based on Bug Bounty Bootcamp (Vickie Li) methodology.

---

## 10 - API Client

Built-in API client inspired by [Bruno](https://www.usebruno.com/) for manual API testing during pentests. Eliminates context-switching to external tools (Postman, curl) by sharing AnarCry's WAF-aware HTTP stack, credential store, and report engine.

```
+===========================================================================+
|  API CLIENT                                                               |
+===========================================================================+
|  Collections     -- tree of folders/requests in JSON (Git-friendly)       |
|  Environments    -- per-env variables (dev/staging/prod), secret masking  |
|  Auth Injectors  -- Bearer, Basic, Digest, API Key, OAuth2 (CC/PKCE/      |
|                     Password/Implicit), WSSE, AWS SigV4, NTLM, custom     |
|  Variables       -- {{var}} interpolation with 6-layer resolution         |
|                     (built-in > env > collection > folder > request >     |
|                     runtime) + circular reference detection               |
|  Request Builder -- method, URL, headers, body (JSON/form/multipart/      |
|                     XML/GraphQL/file), query/path params, descriptions    |
|  Scripting       -- pre-request + post-response + tests (GraalJS)         |
|  Runner          -- sequential execution with variable chaining           |
|  Assertions      -- declarative validation (status, JSON path, header,    |
|                     regex, timing, size)                                  |
|  Import          -- Postman v2.1, OpenAPI 3.0, Bruno .bru, Insomnia,      |
|                     cURL                                                  |
|  Export          -- cURL command, Markdown + JSON collection run reports  |
|  Proxy           -- HTTP/HTTPS/SOCKS5 with auth (via Preferences)         |
+===========================================================================+
```

**GUI (F8):** Collection tree, request tabs (color-coded by method), environment editor dialog, right-click context menu (new/duplicate/delete/rename), pre-request/post-response/test scripts (GraalJS), cURL export, keyboard shortcuts (Ctrl+Enter send, Ctrl+N new request), tab content badges, query/path param split, global search integration. Proxy and SSL configured via Preferences.

**TUI (F8):** Simplified collection list, request builder, environment selector, Send/Run All, response viewer.

---

## 11 - Changelog

### v2.2.1

**GUI + API Client bugfixes, Preferences persistence, light theme**

Preferences:
- **AppSettings persistence**: singleton saves all preferences to `~/.anarcry/settings.json` via Gson -- loads on startup, saves on Apply, survives restarts
- **Light theme**: AnarCryLaf.installLight() with theme-aware color helpers (fg(), bg(), border(), isDark()), saved theme applied on app launch
- **Preferences rework**: tab reorder (General, Themes, Display, Proxy, Certificates, Notifications, Keybindings, License, Support, About -- info tabs grouped at end)
- **Check for Updates**: dedicated sidebar button queries GitHub Releases API, compares with Version.get(), offers to open release page
- **Proxy centralized**: proxy config moved from API Client sidebar to Preferences -- single source of truth, ApiClientView receives ProxySelector/SSLContext via setNetworkConfig()
- **Certificates panel**: client cert table (Enable, Domain, Type PEM/PKCS12, Cert/PFX File, Key File, Passphrase) with Browse buttons, custom CA certificate with keep-default-CA toggle
- **SSL context builder**: PEM private key loading (RSA/EC/Ed25519), PKCS12 keystore, custom CA merge with JVM defaults, trust-all toggle for SSL verification off
- **Support panel**: support-art.png image, documentation and repository hyperlinks with Desktop.browse()
- **Display defaults**: resolution combo defaults to 1920x1080, saved resolution applied on app launch (including Maximized state)

API Client enhancements:
- **Auth interpolation**: `{{var}}` resolved in all 12 AuthConfig sealed interface variants (Bearer, Basic, Digest, API Key, OAuth2 CC/PKCE/Password/Implicit, WSSE, AWS SigV4, NTLM, custom)
- **GraalJS scripting**: pre-request, post-response, and test scripts with console output panel
- **cURL export**: generate cURL command from any request (CurlGenerator)
- **Insomnia import**: InsomniaImporter for Insomnia v4 JSON collections
- **Tab content badges**: "Headers 1", "Body *", "Script *" indicators on editor tabs
- **Query/Path params split**: separate KvTableEditors for query and path parameters
- **Keyboard shortcuts**: Ctrl+Enter send, Ctrl+N new request, Ctrl+E edit environment, empty state panel with shortcut hints
- **Description column**: KvTableEditor now has 4 columns (checkbox, Key, Value, Description)
- **Tab state cache**: per-tab editor state and response preserved when switching tabs
- **Auto-select editor tab**: first tab with content is auto-selected on request load
- **Sidebar width**: increased from 250px to 320px for longer request names
- **Method label fix**: full method names shown in tree (POST, DELETE, PATCH, OPTIONS) instead of 3-char truncation

GUI fixes:
- **Status bar icons**: Tabler Icons (MIT) replace Unicode/emoji text -- settings, theme, GitHub, search, cookie, license, proxy icons as 16x16 PNGs
- **Status bar actions**: Theme toggle, GitHub repo link, License info buttons with icon-only labels
- **Global search rewrite**: empty query shows all items (API requests, findings, sitemap), endpoint matching, wrap-around arrow navigation, single-click select, focus-loss dismissal
- **Global keyboard shortcuts**: Ctrl+K opens global search (works in text fields), Ctrl+, opens Preferences
- **Cookies status bar click**: opens PreferencesDialog
- **Search popup fix**: Enter no longer closes empty search dialog
- **API requests in search**: API Client request names wired into GlobalSearchDialog
- **Status reason phrase**: "401 Unauthorized" instead of "401 401"
- **Response status badges**: color-coded HTTP status in response panel

Other:
- **RequestExecutor**: auth variable interpolation in all auth config fields
- Version bump to 2.2.1

<details>
<summary><kbd>Previous releases (click to expand)</kbd></summary>

### v2.2.0

**Scanner Expansion -- 13 new modules, OAST, SARIF, FP reduction**

New scanner modules:
- **CSRF**: 6-phase detection (token presence, validation tests, SameSite cookie, referer/origin bypass, PoC generation)
- **Secrets**: 17 regex patterns (AWS AKIA, GCP, GitHub ghp_/gho_/ghs_, Slack xoxb/xoxp, JWTs, private keys, generic API keys) with JS bundle and source map scanning
- **Race Condition** (opt-in): concurrent request dispatch, state inconsistency detection for payment/coupon/vote endpoints
- **NoSQL Injection**: MongoDB operator injection ($gt, $ne, $regex, $where, $exists), JSON body injection, auth bypass
- **Insecure Deserialization**: Java/PHP/Python/.NET gadget detection, content-type analysis, error-based fingerprinting
- **File Upload Bypass** (opt-in): double extension, null byte, unicode, content-type spoofing, magic byte manipulation
- **Subdomain Takeover**: CNAME resolution, dangling record detection, service fingerprinting (GitHub Pages, Heroku, S3, Azure, Shopify)
- **WebSocket Security**: origin validation bypass, unauthenticated endpoint detection, protocol downgrade (ws:// vs wss://)
- **Prototype Pollution**: `__proto__` and `constructor.prototype` injection in JSON bodies and query params
- **Cloud Misconfiguration**: S3/Azure Blob/GCS public access checks, cloud metadata endpoint exposure

JWT++ probes:
- **x5c chain**: self-signed certificate chain injection
- **x5u cert**: attacker-controlled certificate URL (OAST-enabled)
- **Key confusion**: RSA public key as HMAC secret (RS256 -> HS256 variant)

OAST infrastructure (`scanner/oast/`):
- **OastServer**: lightweight HTTP/DNS callback server for blind vulnerability detection
- **OastCorrelator**: matches incoming callbacks to pending payloads with timestamp correlation
- Integrated into SSRF, XXE, SQLi, CmdInjection modules (conditional on `oastEnabled`)

Module enhancements:
- **GraphQL++**: mutation testing, nested query DoS (depth bombing), batching bypass, field suggestion leak
- **XXE++**: SVG upload XXE, SAML XXE, XInclude, content-type switching
- **HTTP/2 Smuggling**: H2.CL, H2.TE, HPACK header manipulation, CRLF injection

Other:
- **SARIF v2.1.0 export**: full CWE/CVSS mapping, available in TUI ([E] -> 5), GUI (Export dialog), CLI (--format sarif)
- **FP reduction**: echo detection in FindingValidator, module-specific validation hooks (SQLi/XSS/SSRF), structural HTML comparison in BaselineDiffer, statistical timing analysis in TimingAnalyzer
- **Knowledge base**: expanded from 25 to 34 entries with new module coverage
- Version bump to 2.2.0

### v2.1.0

**API Client Module - Bruno-inspired collections, environments, runner**
- **Collections**: tree of folders and requests persisted as JSON on filesystem (Git-friendly), load/save/import
- **Environments**: per-env variables with secret masking, create/edit/delete via Environment Editor dialog
- **Auth injectors**: 12 auth modes via sealed interfaces - Bearer, Basic, Digest, API Key, OAuth2 (CC/PKCE/Password/Implicit), WSSE, AWS SigV4, NTLM, custom headers
- **Variable interpolation**: `{{var}}` in URL, headers, body, auth fields with 6-layer resolution (built-in > env > collection > folder > request > runtime) and circular reference detection
- **RequestExecutor**: 7-phase pipeline (resolve vars > inject auth > build body > send > extract > assert > chain) using AnarCry's Http.send() for WAF stealth, cookie rotation, and circuit breaker
- **CollectionRunner**: sequential execution with variable chaining between requests, jump-to-request support
- **Assertions**: declarative response validation (status code, JSON path, header value, regex match, response time, body size)
- **Import**: Postman v2.1 collections, OpenAPI 3.0 specs, Bruno .bru directories, cURL command parsing
- **Report**: Markdown + JSON export of collection run results with assertion details

**GUI/TUI Integration**
- **API Client tab (F8)**: request tabs color-coded by method (GET=green, POST=yellow, DELETE=red), collection tree with right-click menu (new request/folder, duplicate, delete, rename), environment selector with "..." configure button
- **Environment Editor**: modal dialog for managing environments and variables (name, value, secret toggle, enabled toggle)
- **PreferencesDialog**: Bruno-style categorized settings (General, Themes, Display, Proxy, Certificates, Notifications, Keybindings, License, Support, About) - SSL/TLS toggle, proxy config for Burp/ZAP, client certificates table
- **StatusBar shortcuts**: Search (jumps to Findings search), Cookies count, Proxy status, Privacy toggle, version display
- **F-key shift**: API Client on F8, Assistant moved to F9

### v2.0.1

**Security Hardening + Static Analysis Cleanup**
- **FormLoginHarvester scope validation**: form action URLs and redirect destinations validated against target root domain before sending credentials - prevents credential leakage to external domains
- **FormLoginHarvester method handling**: honors parsed form method (GET/POST), rejects unsupported methods instead of silently forcing POST
- **Http.sendSimple()**: lightweight HTTP helper for pre-scan auth flows that don't have ScanContext (FormLoginHarvester now routes through Http instead of raw HttpClient)
- **Cookie rotation expiry**: Http.rotateCookie() parses max-age from Set-Cookie header instead of hardcoding 3600s default
- **CredentialStore**: removed hardcoded expiry default - callers must pass explicit expiry duration
- **FirebaseAuthClient**: URL-encode refresh tokens in form body, use UUID for probe credentials instead of predictable timestamps, log cleanup failures
- **FirebaseConfigExtractor**: use shared HttpClientFactory instead of raw HttpClient (prevents thread pool leak)
- **ProviderDetector**: precompiled regex patterns (was compiling per call), proper InterruptedException handling
- **Hooks hardening**: command injection fix in ac-filter.js (exec form instead of sh -c), prototype pollution guards, path validation with traversal depth limits, canonical path resolution
- **CI config**: exclude hooks/ from Codacy and Semgrep analysis (local CLI tooling, not application code)

### v2.0.0

**Credential Harvester - auto-auth pipeline**
- **AuthType.AUTO**: new auth mode that detects the target's auth provider from page source (Firebase, Auth0, Supabase, Keycloak, OIDC) and authenticates automatically -- user provides email/password, scanner handles token extraction, refresh, and injection
- **ProviderDetector**: passive fingerprinting of auth providers via JS bundle patterns (firebaseConfig, auth0 domain/clientId, supabase URL/key, Keycloak realm URLs, generic OIDC .well-known)
- **FirebaseHarvester**: full Firebase Identity Toolkit integration -- signInWithPassword, automatic token refresh via refreshToken endpoint, cleanup via deleteAccount
- **FormLoginHarvester**: generic form-based login for apps without a known auth provider -- parses login forms (FormParser), submits credentials, extracts JWT/session from response headers/cookies/body, supports CSRF token extraction and hidden field forwarding
- **CredentialStore**: centralized token lifecycle manager -- holds activeToken/refreshToken, tracks expiry, auto-refresh before dispatch in Http.send(), thread-safe refresh with double-check locking
- **Http.send() token refresh**: automatic pre-flight token refresh when CredentialStore reports expiring-soon (< 60s) -- scan sessions survive past token TTL without manual intervention
- **TUI/GUI integration**: Auth Type selector updated with AUTO option, shows username/password fields instead of JWT when selected, provider detection result shown before scan starts

**Exploitation Modules - post-scan validation (Phase 3)**
- **ExploitOrchestrator**: 2-pass pipeline -- (1) FindingValidator runs generic FP detection on all findings, (2) specific exploiters run on survivors. Parallel execution via ProbeExecutor
- **FindingValidator**: meta-exploiter that replays findings with baseline diffing (response with vs without payload), timing analysis, WAF FP detection, and error-based validation -- max 3 requests per finding
- **FirebaseExploiter**: probes Firebase misconfig (signUp abuse, Firestore/RTDB/Storage public read/write, rate limit absence) using shared FirebaseAuthClient -- creates temp account, probes, cleans up. Max 50 requests
- **AuthBypassExploiter**: JWT manipulation (alg:none, RS256-to-HS256, claim editing via TokenManipulator), privilege escalation probing (PrivEscProbe role/isAdmin injection), session fixation. Max 30 requests
- **IdorExploiter**: enhanced IDOR validation -- discovers real IDs from /api/me or listing endpoints, attempts cross-user access with UUID/numeric ID substitution, parameter tampering, BOLA/BFLA, HTTP method override. Baseline diffing eliminates FP from public endpoints. Max 40 requests
- **EndpointEnumExploiter**: framework detection (FrameworkDetector: Next.js, Nuxt, SvelteKit, Remix via headers/patterns), source map probing, API version enumeration, route fuzzing (RouteFuzzer with per-framework wordlists). Max 200 requests
- **ValidatedFinding + ExploitResult**: findings carry exploit evidence (PoC curl, response diff, impact proof, confidence score). Status: CONFIRMED, FALSE_POSITIVE, NEEDS_MANUAL, ERROR
- **ReportEngine validated exports**: exportValidated(), exportH1Validated(), exportBugcrowdValidated() -- confirmed findings with PoC sections, dismissed findings with FP justification
- **ScanConfig.exploitationEnabled**: opt-in flag (default false) -- ScanRunner Phase 3 runs ExploitOrchestrator only when enabled
- **ScanRunner Phase 3**: after all modules complete, findings collected into synchronized list, passed to ExploitOrchestrator for validation when exploitation is enabled

**FP Reduction + Scanner Fixes**
- **RequestSmugglingModule hardening**: multi-backend CL.TE/TE.CL/TE.TE detection with 4-stage pipeline (HTTP/1.0 downgrade, dual Content-Length, Transfer-Encoding obfuscation, H2 smuggling via CONNECT). Connection reuse detection and response correlation
- **OpenRedirectModule enhancement**: URL-encoded and double-encoded payload variants, dataURI and javascript: scheme detection
- **OAuthModule**: callback URL manipulation testing (open redirect via OAuth redirect_uri)
- **Cookie rotation in Http.send()**: Set-Cookie headers from responses automatically update session cookies in ScanContext -- critical for targets with rotating session tokens (Fernet, signed cookies)

**Known Gaps (identified during Duma Finance assessment)**
- No rate limit detection module (burst requests to detect 429 absence)
- No race condition / TOCTOU testing module
- No business logic validation (sensitive operations without password, phone change without SMS OTP)
- No financial precision testing (BigDecimal vs float, amount overflow/underflow)
- No CSV/export injection testing beyond formula prefixes (HTML tag passthrough)
- No actuator/admin endpoint enumeration beyond basic path check (Swagger UI, API docs, debug endpoints)

### v1.9.5

- **Headers/HSTS redirect fix**: migrated HeadersModule and HSTSModule HTTPS probe from `HttpURLConnection` to `HttpClient` via `Http.send()` -- follows 308 redirects to final response, injects session cookies, and uses shared WAF/circuit breaker pipeline (fixes false positives on naked domain 308 redirects)
- **JWT alg:none server-side validation**: passive alg:none detection downgraded to INFO; active probe now does 3-step baseline comparison (valid token 200, no-token != 200, alg:none 200) to confirm server actually accepts unsigned tokens -- eliminates false positives from unauthenticated endpoints
- **XSS non-executable reflection downgrade**: reflection-without-execution now reports INFO instead of MEDIUM when canary appears in non-executable context (Next.js RSC payload, JSON serialization, CSP with nonce/strict-dynamic)


### v1.9.4

- **Vercel WAF detection + bypass**: Vercel Security Checkpoint detected via `x-vercel-mitigated` header and body content, with dedicated `VERCEL_CHALLENGE` block type (threshold 5) and 4-signal WAF signature (x-vercel-mitigated, x-vercel-challenge-token, x-vercel-id, body content)
- **ChallengeSolver integration**: Phase 1.5 invokes `ChallengeSolver.solve()` for Vercel challenges (headless Chromium + WASM proof-of-work + mouse simulation) -- extracted cookies injected into all subsequent requests via `Http.send()`
- **Manual cookie fallback**: when ChallengeSolver fails (no Playwright, challenge changed), log instructs user to extract cookies from browser and paste into Session Cookie field
- **Vercel in isWafBlocked()**: header-aware overload recognizes Vercel 403 + `x-vercel-mitigated: challenge` -- circuit breaker now detects Vercel blocks at runtime instead of letting modules waste requests on the challenge page
- **Dynamic post-scan finding labels**: managed/Vercel challenge findings use `challengeType()` or block type name instead of hardcoded "Cloudflare" -- only emitted when challenge was NOT solved
- **Body-based detection hardened**: Vercel body check requires 403/503 status code to avoid false-positive challenge handling on normal pages containing "Vercel Security Checkpoint"

### v1.9.3

- **CF WAF bypass pipeline**: automatic 3-layer retry chain when Cloudflare WAF blocks a GET request -- (1) origin spoof headers (X-Forwarded-For, CF-Connecting-IP, True-Client-IP = 127.0.0.1), (2) X-Original-URL/X-Rewrite-URL header rewrite (WAF inspects clean /, backend reads payload from header), (3) POST JSON body delivery (CF applies weaker rulesets to JSON)
- **CF-specific evasion strategies**: 4 new strategies (NEWLINE_BREAK, TAB_BREAK, COMMENT_SPLIT, JSON_BODY) with dedicated CF probe order -- newline/tab injection breaks WAF regex patterns, SQL comment splitting (/*!50000SELECT*/), HTML null byte splitting
- **CF-aware probe canaries**: probeStrategies uses less obvious XSS vectors for CF targets (`<details/open/ontoggle>`, `<img onerror>`, MySQL version comments) instead of `<script>alert(1)</script>` which CF catches in any encoding
- **Spray mode** (`bypassPayloads()`): returns multiple obfuscated variants of a payload when no single strategy is effective -- modules iterate all variants, any non-WAF response means the variant bypassed
- **BrowserTransport + payload probing**: Phase 1.5 now runs probeStrategies after BrowserTransport activation (JS_CHALLENGE path) -- previously only RULE_BLOCK path probed strategies, leaving BT-solved scans without payload bypass
- **Block type reclassification**: Http.send() reclassifies WAF blocks as RULE_BLOCK (threshold 25) when BrowserTransport is active -- previously stuck at JS_CHALLENGE (threshold 8) after initial challenge detection
- **Module timeout interrupt**: timed-out modules now get Thread.interrupt() via ConcurrentHashMap thread tracking -- fixes "scan concluido com etapas pendentes" where orTimeout() completed the Future but left the thread running
- **XSS/SQLi spray integration**: XssModule and SqlInjectionModule use bypassPayloads() for multi-variant probing when effective strategy is unknown

### v1.9.1

- **CF WAF false positive fix**: `isWafBlocked()` now requires CF-specific body markers (Attention Required, cf_chl_opt, challenge-platform) when `Server: cloudflare` is present -- app-level 403s behind CF CDN no longer trigger circuit breaker
- **Circuit breaker propagation fix**: dedicated `catch(CircuitBreakerException)` clauses in all 11 scanner modules with nested try-catch -- fixes 5 outer catch-alls that silently swallowed the rethrown exception (GraphQL, OAuth, CachePoisoning, MassAssignment)
- **Non-WAF response resets CB counter**: any response that is not a WAF block (including app-level 403/404) now resets the consecutive block counter -- CB only trips on truly consecutive WAF blocks
- **Dynamic threshold for RULE_BLOCK**: WAF rule-block threshold raised from 8 to 25 -- modules behind confirmed WAF get more room for evasion before aborting
- **Bidirectional threshold adjustment**: `adjustThreshold()` replaces `lowerThreshold()` -- threshold can increase when WAF rule-block is detected mid-scan

### v1.9.0

- **Per-module timeout**: 180s timeout via `CompletableFuture.orTimeout()` -- stuck modules no longer block the entire scan
- **Circuit breaker**: per-module consecutive WAF block counter (threshold 8, or 3 for managed challenges) -- aborts module when WAF is persistently blocking
- **Multi-vendor WAF signature detection**: 15 providers (Akamai, AWS WAF, Cloudflare, DataDome, Imperva, PerimeterX, Kasada, Reblaze, Sucuri, Shape, Vercel, hCaptcha, reCAPTCHA, FunCaptcha, GeeTest) detected via cookie/header/URL/content signals with confidence scores
- **CF challenge classification**: distinguishes RULE_BLOCK vs MANAGED_CHALLENGE vs JS_CHALLENGE vs TURNSTILE -- evasion strategies skipped for managed challenges (per-session, not per-payload)
- **CDN vs WAF separation**: passive CDN detection (cf-ray) no longer marks WAF as active -- WAF only marked on confirmed blocking, preventing false positive stealth activation on Cloudflare CDN sites
- **Raw TLS ClientHello probe**: tests weak cipher suites (RC4, NULL, ANON, 3DES, EXPORT) by building raw TLS packets with hardcoded cipher IDs -- bypasses JVM and OpenSSL 3.0 cipher removal
- **Runtime WAF detection**: `Http.send()` detects WAF mid-scan and auto-activates stealth mode, classifies block type, and adjusts circuit breaker threshold dynamically
- **Future recovery**: timed-out or circuit-broken modules no longer abort the entire scan -- `.handle()` recovers failed futures so remaining modules complete normally
- **RawTlsProbe scope validation**: private/link-local/loopback IP check before raw socket connection (defense-in-depth against SSRF)

### v1.8.0

- **AI Assistant integration**: multi-provider LLM assistant (Claude, OpenAI, Gemini, Ollama) with SSE streaming, tool use, and conversation history -- available in both TUI (AssistantPanel) and GUI (AssistantView)
- **Assistant tools**: 7 built-in tools -- get_findings, get_sitemap, get_scan_config, query_kb, explain_cwe, save_document -- dispatched automatically via streaming tool fragment detection
- **Finding Validation Protocol**: 6-step mandatory validation in assistant system prompt based on Bug Bounty Bootcamp methodology -- prevents false positive relay in AI analysis
- **Streaming tool fragments**: cross-provider SSE tool-call detection (Anthropic content_block_start/input_json_delta, OpenAI delta.tool_calls) with robust fragment accumulation
- **SaveDocTool**: assistant can save markdown documents directly to ~/.anarcry/reports/ with timestamped filenames
- **XSS false positive fix**: ProbeResult-based validation -- HTTP status filtering (reject 404), Content-Type validation (require text/html), JSON unicode escape detection (\\u003c is not raw HTML)
- **Reports directory centralized**: all reports now saved to ~/.anarcry/reports/ (was docs/reports/), single source of truth via ReportEngine.REPORTS_DIR
- **IDOR/Crawler progress logging**: progress messages added to silent loops in IDOR and Crawler modules
- **Knowledge base enrichment**: Escalation Techniques, Hunting Methodology, and False Positive Indicators sections added to KB entries from Bug Bounty Bootcamp
- **WAF evasion KB**: new knowledge-base entry for WAF bypass techniques with Cloudflare-specific strategies

### v1.7.2

- **Root cause analysis in reports**: findings grouped by vulnerability class with severity anchor, affected endpoints table, and unified remediation per root cause -- across AnarCry, HackerOne, and Bugcrowd export formats
- **Negative companions**: "Tested and Secure" section lists modules that ran clean, with vulnerability class names from KB
- **Cross-finding correlation**: automatic detection of 11 attack chain patterns (XSS+CORS, SSRF+IDOR, Smuggling+CachePoisoning, etc.)
- **Codacy fixes**: H1 negative companions moved outside root-cause loop (was duplicating per group), extracted shared helpers (groupByRootCause, resolveKb, recordModuleResult)
- **Launcher fixes**: suppressed Gradle OSC escape sequences causing Kitty notification spam, auto-cleanup of old versioned JARs after build
- **README changelog**: collapsed to show only latest release

### v1.7.1

- **Request Smuggling expansion**: 3 new detection phases -- Duplicate Content-Length (RFC 9112 violation), CL.0 desync (body-ignoring backend), Hop-by-hop TE stripping (Connection: Transfer-Encoding confusion)
- **CL.TE/TE.CL refactor**: phases run independently instead of early-returning, so multiple desync types are detected in a single scan
- **KB enrichment -- IDOR**: UI vs API authorization section, 3 real-world cases (0xdelta album, Mozilla account delete, Shopify privilege escalation), detection indicators, scoped query examples
- **KB enrichment -- Request Smuggling**: comprehensive variant taxonomy (25+ techniques), 8 real-world cases (Pingora, HAProxy CVEs, Akamai, Google Cloud TE.0), PortSwigger research timeline, detection methodology, academic/vendor/tooling references
- **6 new harness tests**: positive + negative tests for Duplicate CL, CL.0, and Hop-by-hop TE probes

### v1.7.0

- **IDOR COOKIE authentication**: IdorModule supports COOKIE auth type for cross-user testing with session cookies
- **Constant placeholders in IDOR reproductions**: finding reproduction steps use constant placeholders instead of runtime tokens

### v1.6.1

- **False positive elimination**: severity inflation on clean servers, CDN header false positives (X-Cache, CF-Cache-Status), HSTS correlation with non-HTTPS targets
- **Per-finding CVSS vectors**: JWT (6 finding types) and CORS (4 finding types) carry per-finding vectors instead of flat module-level severity
- **PQC cleanup**: positive indicators (TLS 1.3 supported, X25519MLKEM768 supported) no longer reported as vulnerability findings
- **XSS severity alignment**: log message matches CRITICAL severity
- **6 regression tests**: false-positive regression suite on a clean server

### v1.6.0

- **AuthType selector**: NONE / JWT / COOKIE / BEARER auth mode in both TUI and GUI -- dynamic credential fields, AuthType.buildContext() factory routes tokens/cookies correctly
- **Multi-platform release CI**: matrix build (Linux .deb, Windows .msi, macOS .dmg) via GitHub Actions release workflow
- **Codacy compliance**: 31 findings resolved (13 code fixes, 18 false-positive suppressions via .codacy.yml for scanner-inherent patterns)
- **anarchrypto auto-build**: launcher detects stale JAR and rebuilds automatically via `./gradlew shadowJar`
- **AuthType e2e harness**: 25 tests covering enum contract, wiring, module skip, HTTP header injection, and integration

### v1.5.0

- **WAF evasion engine**: WafState + WafEvasion in scanner/util/ -- 5 bypass strategies (DOUBLE_ENCODE, CASE_MUTATION, UNICODE_NORMALIZE, CHARSET_EBCDIC, HPP)
- **ScanRunner Phase 1.5**: automatic WAF probe between Crawler recon and scanner modules -- detects effective bypass strategy
- **Module integration**: SQLi, XSS, LFI, SSTI, CmdInjection, XXE apply evasion payloads transparently when WAF detected
- **HeadersModule WAF state**: marks shared WafState on 403 + WAF signature detection
- **Test harness**: 26 WAF tests (18 unit + 8 integration with mock WAF server)

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

## 12 - Ethical Use

AnarCry is designed for **authorized security testing** only:

- Always obtain written authorization before scanning
- Respect scope boundaries configured in `ScanConfig`
- Never scan targets without explicit permission
- Findings are for defensive purposes -- helping teams fix vulnerabilities
