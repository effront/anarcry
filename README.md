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
|  Security scanner for bug bounty. 25 attack modules, parallel execution,  |
|  CVSS v3.1 auto-scoring, knowledge base with 26 entries, WAF detection    |
|  (14 providers) + circuit breaker. TUI + Swing GUI + AI Assistant.        |
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
|                         Hop-by-hop TE stripping                           |
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
|  10 - Changelog                                      |
|  11 - Ethical Use                                    |
+------------------------------------------------------+
```

---

## 01 - Quick Start

```bash
./gradlew shadowJar
java -jar build/libs/anarcry-1.9.1.jar
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
java -jar build/libs/anarcry-1.9.1.jar --gui
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
|                      |  knowledge-base/*.md (26 enriched entries)         |
|  AI Assistant        |  Multi-provider (Claude, OpenAI, Gemini, Ollama)   |
|  GUI                 |  Swing + FlatLaf + RSyntaxTextArea + JFreeChart    |
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

Two interfaces: **TUI** (Lanterna, terminal-native) and **GUI** (Swing + FlatLaf, desktop). Both offer the same core functionality: Target scan, Repeater, Findings, SiteMap, Export. The GUI adds a Dashboard with severity chart (JFreeChart), Preferences dialog, and the AI Assistant chat view.

### TUI

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

Launch with `--gui` flag. Tabs: Dashboard, Target, Findings, Repeater, SiteMap, Report, Assistant.

```
+-----------------------------------------------------------------------+
| AnarCry                                    [Privacy] [Preferences]    |
+-----------------------------------------------------------------------+
| Dashboard | Target | Findings | Repeater | SiteMap | Report | AI Asst |
+-----------------------------------------------------------------------+
|                                                                       |
|  Severity Distribution (pie)   |   Recent Findings                    |
|  [CRIT: 3] [HIGH: 5]           |   - JWT alg:none (CRITICAL)          |
|  [MED: 8]  [LOW: 2]            |   - CORS origin reflect (CRITICAL)   |
|                                |   - XSS reflected (HIGH)             |
|                                                                       |
+-----------------------------------------------------------------------+
|  Status: Scanning... | 8/25 modules | C:3 H:5 M:8 L:2 I:0             |
+-----------------------------------------------------------------------+
```

**AI Assistant tab:** chat interface with SSE streaming, tool-use indicators, and token usage display. Supports Claude, OpenAI, Gemini, and Ollama. Configure provider and API key in Preferences.

---

## 06 - Testing

```bash
./gradlew test              # unit + harness (no network)
./gradlew integrationTest   # tests with external hosts (badssl.com, etc.)
```

Test suite covers: JWT probes (alg:none, weak secret, RS256->HS256, JKU, null signature, signature disclosure), CORS (origin reflection, wildcard, null origin), OAuth (well-known discovery, redirect_uri bypass), CRLF (path + header injection), SSRF, GraphQL introspection, Open Redirect, Cache Poisoning, Request Smuggling (CL.TE, TE.CL, Duplicate CL, CL.0, Hop-by-hop TE), SQLi (error-based + time-based), PQC, Headers, HSTS, IDOR (COOKIE auth, cross-user), ScanRunner orchestration (callbacks, module isolation, dedup, omnibus E2E), ReportEngine (MD+JSON export, JSON serialization), KnowledgeBase (loading, lookups, CweRegistry delegation), CvssCalculator, and a false-positive regression suite on a clean server.

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
|   |   +-- WafEvasion.java        5 bypass strategies + 14-vendor signature detection
|   |   +-- CircuitBreaker.java    Per-module WAF block counter with dynamic threshold
|   +-- crypto/                    5 modules: TLS (+ RawTlsProbe), Headers, HSTS,
|   |                               JWT (5 probes), PQC
|   +-- web/                       20 modules: SQLi, XSS, LFI, CmdInject, CORS, OAuth,
|                                   OpenRedirect, SSRF, GraphQL, CRLF, XXE, SSTI, IDOR,
|                                   HostHeader, Actuator, MassAssign, CachePoisoning,
|                                   ReqSmuggling, Crawler, Infra
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
|   +-- GuiController.java         View orchestration and scan lifecycle
|   +-- PrivacyFilter.java         URL/JWT/IP redaction (Ctrl+Shift+P)
|   +-- views/
|   |   +-- DashboardView          Overview with severity chart (JFreeChart)
|   |   +-- TargetView             Target config + module selection
|   |   +-- FindingsView           Findings table with detail panel
|   |   +-- RepeaterView           HTTP request replay
|   |   +-- SiteMapView            Crawled sitemap tree
|   |   +-- ReportView             Report generation and export
|   |   +-- AssistantView          AI Assistant chat with streaming + tools
|   +-- components/                Reusable GUI components
|   +-- theme/                     FlatLaf theme customization
+-- tui/
    +-- AnarCryTui.java            Main TUI window (Lanterna)
    +-- PasteableTextBox.java      Custom text box with paste support
    +-- chrome/                    ModeBar, StatusBar, ActionPalette, EventLogDrawer
    +-- modes/                     Target mode, Repeater mode
    +-- panels/                    FindingsPanel, LogPanel, ModulesPanel, SiteMapPanel,
                                    AssistantPanel
```

**Scan execution flow:**

```
ScanRunner.run(ScanContext)
  -> Phase 1: run Crawler (blocking) to populate DiscoveredPaths
  -> Phase 1.5: WAF detection -- baseline GET + canary probe
     -> multi-vendor signature detection (14 providers)
     -> classify block type: RULE_BLOCK / MANAGED_CHALLENGE / JS_CHALLENGE / TURNSTILE
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

---

## 08 - Knowledge Base

Two layers:

**Structured data** -- `src/main/resources/knowledge_base.json` contains 25 entries (one per vulnerability class). Each entry provides CWE ID, CVSS v3.1 vector, VRT ID, summary, payloads, crawler hints, and remediation. `CweRegistry` delegates to `KnowledgeBase` at runtime -- findings auto-resolve CWE and CVSS from the KB when created via `Finding.of()`.

**Enriched markdown** -- `knowledge-base/*.md` contains 26 entries with extended sections:

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

## 10 - Changelog

### v1.9.1

- **CF WAF false positive fix**: `isWafBlocked()` now requires CF-specific body markers (Attention Required, cf_chl_opt, challenge-platform) when `Server: cloudflare` is present -- app-level 403s behind CF CDN no longer trigger circuit breaker
- **Circuit breaker propagation fix**: dedicated `catch(CircuitBreakerException)` clauses in all 11 scanner modules with nested try-catch -- fixes 5 outer catch-alls that silently swallowed the rethrown exception (GraphQL, OAuth, CachePoisoning, MassAssignment)
- **Non-WAF response resets CB counter**: any response that is not a WAF block (including app-level 403/404) now resets the consecutive block counter -- CB only trips on truly consecutive WAF blocks
- **Dynamic threshold for RULE_BLOCK**: WAF rule-block threshold raised from 8 to 25 -- modules behind confirmed WAF get more room for evasion before aborting
- **Bidirectional threshold adjustment**: `adjustThreshold()` replaces `lowerThreshold()` -- threshold can increase when WAF rule-block is detected mid-scan

### v1.9.0

- **Per-module timeout**: 180s timeout via `CompletableFuture.orTimeout()` -- stuck modules no longer block the entire scan
- **Circuit breaker**: per-module consecutive WAF block counter (threshold 8, or 3 for managed challenges) -- aborts module when WAF is persistently blocking
- **Multi-vendor WAF signature detection**: 14 providers (Akamai, AWS WAF, Cloudflare, DataDome, Imperva, PerimeterX, Kasada, Reblaze, Sucuri, Shape, hCaptcha, reCAPTCHA, FunCaptcha, GeeTest) detected via cookie/header/URL/content signals with confidence scores
- **CF challenge classification**: distinguishes RULE_BLOCK vs MANAGED_CHALLENGE vs JS_CHALLENGE vs TURNSTILE -- evasion strategies skipped for managed challenges (per-session, not per-payload)
- **CDN vs WAF separation**: passive CDN detection (cf-ray) no longer marks WAF as active -- WAF only marked on confirmed blocking, preventing false positive stealth activation on Cloudflare CDN sites
- **Raw TLS ClientHello probe**: tests weak cipher suites (RC4, NULL, ANON, 3DES, EXPORT) by building raw TLS packets with hardcoded cipher IDs -- bypasses JVM and OpenSSL 3.0 cipher removal
- **Runtime WAF detection**: `Http.send()` detects WAF mid-scan and auto-activates stealth mode, classifies block type, and adjusts circuit breaker threshold dynamically
- **Future recovery**: timed-out or circuit-broken modules no longer abort the entire scan -- `.handle()` recovers failed futures so remaining modules complete normally
- **RawTlsProbe scope validation**: private/link-local/loopback IP check before raw socket connection (defense-in-depth against SSRF)

<details>
<summary><kbd>Previous releases (click to expand)</kbd></summary>

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

## 11 - Ethical Use

AnarCry is designed for **authorized security testing** only:

- Always obtain written authorization before scanning
- Respect scope boundaries configured in `ScanConfig`
- Never scan targets without explicit permission
- Findings are for defensive purposes -- helping teams fix vulnerabilities
