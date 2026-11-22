# AnarCry - Product Requirements Document

**Version:** 2.1 | **Date:** 2026-11-10 | **Status:** Draft
**Current Release:** v2.1 (Java 27, Gradle 9.x, AGPL-3.0)

---

## 1. Vision

AnarCry is a bug bounty security scanner that takes a target URL and autonomously discovers vulnerabilities, validates them with exploitation, and generates platform-ready reports (HackerOne, Bugcrowd). It combines automated scanning with AI-assisted analysis, aiming to be the solo hunter's complete toolkit - scanner, repeater, and reporting engine in one, with a planned API client.

---

## 2. Architecture Overview

```
                         +-------------------+
                         |    Entry Points    |
                         |  GUI (Swing/FlatLaf) |
                         |  TUI (Lanterna)    |
                         |  CLI (--headless)  |
                         +--------+----------+
                                  |
                    +-------------+-------------+
                    |      ScanOrchestrator     |
                    |  (builds ScanContext)      |
                    +-------------+-------------+
                                  |
                    +-------------v-------------+
                    |    Phase 1: Recon         |
                    |  CrawlerModule (blocking) |
                    +-------------+-------------+
                                  |
                    +-------------v-------------+
                    |   Phase 1.5: WAF          |
                    |  WafEvasion + Challenge-   |
                    |  Solver (sequential)       |
                    +-------------+-------------+
                                  |
                    +-------------v-------------+
                    |   Phase 2: Scan Modules   |
                    |   (parallel, 4 threads)   |
                    |   25 vulnerability modules|
                    +-------------+-------------+
                                  |
                    +-------------v-------------+
                    |  Phase 3: Exploitation    |
                    |  ExploitOrchestrator      |
                    |  (validate + PoC gen)     |
                    +-------------+-------------+
                                  |
                    +-------------v-------------+
                    |      ReportEngine         |
                    |  MD/JSON/H1/Bugcrowd      |
                    +---------------------------+

    Cross-cutting:
    - AI Assistant (4 providers, 6 tools)
    - Knowledge Base (26 vuln types, 71 CVEs)
    - Auth Subsystem (9 providers, credential harvesting)
```

---

## 3. Current Capabilities (v2.1)

### 3.1 Scanner Modules (25 total)

**Web Vulnerabilities (20 modules):**

| Module | Vuln Type | Techniques |
|--------|-----------|------------|
| SqlInjectionModule | SQLi | Error-based, time-based blind (MySQL/PG/MSSQL), WAF-aware param selection |
| XssModule | XSS | Canary reflection, DOM sink analysis (innerHTML, eval, document.write), CSP check |
| SsrfModule | SSRF | URL param injection, internal IP probing, high-value endpoint filtering |
| SstiModule | SSTI | Template expression injection |
| XxeModule | XXE | XML external entity injection |
| LfiModule | LFI | Path traversal payloads |
| CommandInjectionModule | OS Command Injection | Command chaining payloads |
| CorsModule | CORS Misconfig | Origin reflection testing |
| CrlfModule | CRLF Injection | Header injection via newlines |
| GraphQLModule | GraphQL | Introspection queries, schema enumeration |
| OAuthModule | OAuth Misconfig | OAuth flow analysis |
| OpenRedirectModule | Open Redirect | Redirect parameter probing |
| HostHeaderModule | Host Header Injection | Host header manipulation |
| IdorModule | IDOR | Direct object reference testing (disabled by default) |
| MassAssignmentModule | Mass Assignment | Extra field injection |
| CachePoisoningModule | Cache Poisoning | Cache key manipulation |
| RequestSmugglingModule | HTTP Smuggling | CL/TE desync probing |
| SpringActuatorModule | Actuator Exposure | Endpoint enumeration |
| CrawlerModule | Reconnaissance | 80+ path wordlist, OpenAPI/Swagger, JS path extraction |
| InfraModule | Infrastructure | Port scanning (nmap), admin panel probing (disabled by default) |

**Crypto/Auth Modules (5):**

| Module | Area | Techniques |
|--------|------|------------|
| TlsModule | TLS | Version probing, cipher suite analysis, certificate validation |
| HeadersModule | Security Headers | Header presence/value analysis |
| HSTSModule | HSTS | Strict-Transport-Security validation |
| JwtModule | JWT | alg:none, RS256->HS256, JKU injection, weak secret brute-force (21 passwords) |
| PqcModule | Post-Quantum | PQC readiness assessment |

### 3.2 Exploitation Engine (5 exploiters)

| Exploiter | Target | Techniques |
|-----------|--------|------------|
| FindingValidator | All findings | False positive filtering (generic errors, WAF blocks) |
| AuthBypassExploiter | Auth findings | JWT alg:none, claim manipulation, signature stripping |
| IdorExploiter | IDOR findings | Numeric ID tampering, param injection, method override |
| FirebaseExploiter | Firebase targets | Signup abuse, Firestore IDOR, Storage/RTDB public access |
| EndpointEnumExploiter | All targets | Hidden endpoint/route discovery, framework fingerprinting |

### 3.3 AI Assistant

- **Providers:** Claude (Anthropic), Gemini (Google), OpenAI, Ollama (local)
- **6 tools:** Explain CWE, get findings, get scan config, get sitemap, query KB, save document
- **Streaming support** via SSE with tool-use loop

### 3.4 Report Engine

- **Formats:** AnarCry native (Markdown), HackerOne, Bugcrowd, Validated/Exploit, Platform (generic)
- Root cause grouping, attack chain correlation (IDOR+auth, SSRF+IDOR, XSS+CORS)
- KB-enriched descriptions with CWE, CVSS v3.1, CVE references

### 3.5 UI

- **Swing GUI** (FlatLaf): 8 tabs (Dashboard, Scan, Target, Findings, Repeater, Report, SiteMap, Assistant), dark/light toggle, privacy filter (Ctrl+Shift+P)
- **TUI** (Lanterna): Terminal interface with mode switching, mouse support
- **Headless/CLI** mode: `--headless --target <url>` for CI/automation, 10-minute timeout

### 3.6 WAF Evasion

- Detection for 15+ WAF providers
- 9 bypass strategies: double encode, unicode normalize, HPP, comment split, etc.
- StealthHttpClient with Chrome JA3 TLS fingerprint mimicry
- BrowserTransport with headless Chromium for JS challenge bypass
- CircuitBreaker for rate-limit/block detection

### 3.7 Auth Subsystem

- Enum defines 9 providers: Firebase, Auth0, Cognito, Supabase, Keycloak, OIDC, Cookie, Form, Manual
- Auto-detection implemented for: Firebase, Auth0, Supabase, Keycloak, OIDC, Form
- Auto-detection NOT implemented for: Cognito (stub only), Cookie (user-configured), Manual (user-configured)
- Firebase credential harvesting (config extraction from page JS)
- Form login harvesting (HTML form parsing + automated submit)

### 3.8 Knowledge Base

- 26 vulnerability type entries with YAML frontmatter
- CWE ID, CVSS vector, VRT ID, payloads, bypasses, notable CVEs
- Used by ReportEngine and AI Assistant for finding enrichment

---

## 4. Gaps and Planned Work

### 4.1 CRITICAL - Missing Vulnerability Modules

These are common bug bounty targets with no scanner coverage:

| ID | Module | Priority | Rationale |
|----|--------|----------|-----------|
| G-01 | CSRF Scanner | HIGH | P1 bounty target, no detection at all |
| G-02 | Race Condition Scanner | HIGH | Time-of-check/time-of-use, limit bypass |
| G-03 | NoSQL Injection Scanner | HIGH | MongoDB/DynamoDB targets increasingly common |
| G-04 | Insecure Deserialization | HIGH | Java/PHP/Python deser chains, RCE impact |
| G-05 | File Upload Bypass | HIGH | Extension/content-type/magic byte bypass |
| G-06 | Subdomain Takeover | MEDIUM | Dangling CNAME detection |
| G-07 | WebSocket Security | MEDIUM | WS origin check, message injection |
| G-08 | Prototype Pollution | MEDIUM | JS prototype chain manipulation |
| G-09 | Cloud Misconfig Scanner | MEDIUM | S3 bucket, Azure blob, GCS public access |
| G-10 | Secrets/Credential Discovery | MEDIUM | API keys, tokens, passwords in JS/HTML/responses |

### 4.2 CRITICAL - OAST/Out-of-Band Infrastructure

Currently no OOB detection for blind vulnerabilities. Needed for:
- Blind SSRF (DNS/HTTP callback)
- Blind XXE (external DTD exfiltration)
- Blind SQLi (DNS exfiltration)
- Blind Command Injection (DNS/HTTP callback)

### 4.3 HIGH - Module Enhancements (Phase 2 Sprints)

| Sprint | Enhancement | Status |
|--------|-------------|--------|
| 29 | AI Assistant - contextual chat with scan awareness | Planned |
| 30 | AI Orchestrator - multi-agent vulnerability analysis | Planned |
| 31 | GraphQL++ - mutation testing, nested query DoS, auth bypass | Planned |
| 32 | XXE++ - SVG upload, SAML XXE, OOB exfiltration | Planned |
| 33 | HTTP/2 Smuggling - H2.CL, H2.TE, HPACK manipulation | Planned |
| 34 | JWT++ - x5u/x5c chains, key confusion (JWK/kid already exist) | Planned |

### 4.4 HIGH - Exploitation Maturity

- Current FP rate estimated at ~58% (per PRD-exploitation-modules.md)
- Need: timing analysis, differential response comparison, blind confirmation
- Need: PoC command generation for all confirmed findings
- Need: multi-step exploit chaining (e.g., SSRF -> internal service -> data exfiltration)

### 4.5 RESOLVED - Vercel WAF Integration

~~ChallengeSolver exists but is never invoked in the scan pipeline.~~ Fixed -- ChallengeSolver is now invoked in ScanRunner Phase 1.5 when Vercel Security Checkpoint is detected. Includes fallback to BrowserTransport.

### 4.6 MEDIUM - Credential Harvester Expansion

Only Firebase and form login harvesters are implemented. Auth0, Supabase, Keycloak harvesters are detected but not automated. Cognito has no detection logic at all (enum stub only).

### 4.7 MEDIUM - Missing SARIF Output

No SARIF report format for CI/CD integration (GitHub Code Scanning, GitLab SAST). Required for enterprise/team adoption.

### 4.8 LOW - Scan Persistence/Resume

No checkpoint or resume capability. If a long scan is interrupted, all progress is lost.

### 4.9 MEDIUM - API Client

No API testing client exists. Postman-like collection import, environment management, auth injection, and assertion engine are all unbuilt. This is a new feature, not an enhancement.

---

## 5. User Stories

### Epic 1: Vulnerability Discovery

**US-1.1: Comprehensive Web Scanning**
> As a bug bounty hunter, I want to point AnarCry at a target URL and have it automatically discover all common web vulnerabilities, so I can focus on triaging and reporting rather than manual testing.

Acceptance criteria:
- All 25 existing scanner modules execute in parallel
- Crawler discovers paths, OpenAPI specs, and JS-embedded endpoints
- Findings include CWE, CVSS, evidence, and reproduction steps
- Scan completes within 10 minutes for a typical web app

**US-1.2: Blind Vulnerability Detection via OAST**
> As a hunter testing blind injection points, I want AnarCry to use out-of-band callbacks (DNS/HTTP) to confirm blind SSRF, XXE, SQLi, and command injection, so I don't miss high-impact findings that produce no in-band response.

Acceptance criteria:
- Configurable OAST server (self-hosted or Interactsh-compatible)
- Blind payloads injected for SSRF, XXE, SQLi, CmdInject modules
- Callback correlation links OOB hit to originating scan request
- Finding generated with timestamp, callback data, and originating payload

**US-1.3: CSRF Detection**
> As a hunter, I want AnarCry to detect missing or bypassable CSRF protections on state-changing endpoints, so I can report authentication-bypass-adjacent issues.

Acceptance criteria:
- Detect absence of CSRF tokens on POST/PUT/DELETE forms and AJAX
- Test token validation: remove token, reuse token, change token, cross-user token
- Check SameSite cookie attribute and Referer/Origin validation
- Generate PoC HTML form for confirmed findings

**US-1.4: Race Condition Detection**
> As a hunter, I want AnarCry to detect race conditions on rate-limited and transactional endpoints, so I can find limit-bypass and double-spend bugs.

Acceptance criteria:
- Identify candidate endpoints (payment, transfer, coupon, vote, follow)
- Send concurrent requests (configurable parallelism)
- Detect state inconsistency in responses
- Report with timing evidence and PoC curl commands

**US-1.5: NoSQL Injection Detection**
> As a hunter testing MongoDB/DynamoDB backends, I want AnarCry to inject NoSQL-specific payloads, so I can find injection vulnerabilities that SQL-focused scanners miss.

Acceptance criteria:
- MongoDB operator injection ($gt, $ne, $regex, $where)
- JSON body parameter fuzzing
- Response-based and error-based detection
- Support for both query string and request body injection

**US-1.6: File Upload Bypass Detection**
> As a hunter, I want AnarCry to test file upload endpoints for bypass vulnerabilities, so I can find unrestricted file upload leading to RCE or stored XSS.

Acceptance criteria:
- Extension bypass (double ext, null byte, unicode, case variation)
- Content-type spoofing
- Magic byte manipulation
- Polyglot file generation (image+script)
- Detect uploaded file execution/rendering

**US-1.7: Secrets Discovery**
> As a hunter, I want AnarCry to scan JavaScript bundles, HTML source, and API responses for exposed credentials and API keys, so I can report information disclosure findings.

Acceptance criteria:
- Regex patterns for AWS keys, GCP keys, GitHub tokens, Slack tokens, JWTs, private keys
- JS bundle scanning (webpack chunks, source maps)
- Response body scanning during all module probes
- Deduplication and severity classification by key type

### Epic 2: Validation and Exploitation

**US-2.1: Automated Finding Validation**
> As a hunter, I want AnarCry to automatically validate scanner findings with targeted exploitation, so I can submit only confirmed vulnerabilities and reduce my rejection rate.

Acceptance criteria:
- Each finding passes through FindingValidator (FP filter)
- Confirmed findings get ExploitResult with status, PoC command, evidence, confidence score
- FP rate drops below 20% for top-10 vulnerability types
- Timing-based and differential analysis for ambiguous cases

**US-2.2: Multi-Step Exploit Chaining**
> As a hunter, I want AnarCry to chain related findings into attack paths (e.g., SSRF -> internal API -> data exfiltration), so I can demonstrate maximum impact in my reports.

Acceptance criteria:
- Graph of findings with shared target/parameter edges
- Automatic chain detection for known patterns (SSRF+IDOR, XSS+CORS, Auth+IDOR)
- Chain execution with step-by-step evidence capture
- Impact escalation in report (chain severity > individual severity)

**US-2.3: JWT Exploitation Suite**
> As a hunter, I want comprehensive JWT attack coverage including JWK injection, x5u/x5c certificate chains, and key confusion attacks, so I can fully test JWT implementations.

Acceptance criteria:
- Existing: alg:none, RS256->HS256, JKU injection, JWK embed, kid injection, weak secret brute-force
- New: x5u remote certificate, x5c chain injection
- New: key confusion attacks (RSA/HMAC cross-algorithm)
- PoC token generation for each confirmed weakness

### Epic 3: AI-Assisted Analysis

**US-3.1: Contextual Scan Assistant**
> As a hunter, I want to ask the AI assistant questions about my scan results in natural language and get contextual answers that reference my actual findings, so I can understand complex vulnerabilities faster.

Acceptance criteria:
- Assistant has access to current scan context (findings, sitemap, config)
- Can explain findings with CWE details and real-world impact
- Can suggest manual follow-up testing steps
- Streaming responses with tool use

**US-3.2: AI Orchestrator - Autonomous Triage**
> As a hunter running scans on multiple targets, I want an AI orchestrator that triages findings, prioritizes by exploitability, and drafts report sections, so I can scale my workflow.

Acceptance criteria:
- Multi-agent architecture: Scanner Agent, Triage Agent, Report Agent
- Auto-prioritize findings by: severity x confidence x uniqueness
- Draft HackerOne/Bugcrowd submissions for top findings
- Human-in-the-loop approval before any submission

### Epic 4: Reporting

**US-4.1: Platform-Ready Reports**
> As a hunter, I want one-click report generation in HackerOne and Bugcrowd formats with all required fields pre-filled, so I can submit findings within minutes of discovery.

Acceptance criteria:
- HackerOne format: title, CWE, CVSS, severity, steps to reproduce, impact, PoC
- Bugcrowd format: VRT classification, PoC sections
- KB-enriched descriptions (not just scanner output)
- Attack chain narrative when multiple findings relate

**US-4.2: Validated Exploit Reports**
> As a hunter, I want post-exploitation reports that include confirmed PoCs, evidence screenshots, and confidence scores, so reviewers can quickly verify my findings.

Acceptance criteria:
- Separate section for confirmed vs unconfirmed findings
- PoC command for each confirmed finding
- Evidence: request/response pairs, timing data, diff output
- False positive annotations with reasoning

### Epic 5: WAF Evasion

**US-5.1: Transparent WAF Bypass**
> As a hunter testing WAF-protected targets, I want AnarCry to automatically detect the WAF vendor, apply appropriate bypass techniques, and fall back to headless browser when needed, so my scans work on hardened targets.

Acceptance criteria:
- Auto-detect 15+ WAF vendors (existing)
- Apply vendor-specific bypass strategies (existing 9 strategies)
- Invoke ChallengeSolver for JS challenges (existing -- wired into ScanRunner Phase 1.5)
- Fall back to BrowserTransport for Turnstile/managed challenges (existing)
- Circuit breaker prevents getting IP-banned (existing)

**US-5.2: Vercel WAF Support** (DONE)
> As a hunter, I want AnarCry to handle Vercel's WAF challenges and bot detection, so I can scan Vercel-hosted targets without manual intervention.

Acceptance criteria:
- ChallengeSolver invoked when Vercel challenge detected (done)
- Vercel-specific bypass path in WafEvasion (done)
- Session persistence after challenge solve via cookie injection in Http.send() (done)

### Epic 6: Authentication

**US-6.1: Multi-Provider Credential Harvesting**
> As a hunter, I want AnarCry to auto-detect the target's auth provider and obtain valid session tokens, so I can perform authenticated scanning without manual token setup.

Acceptance criteria:
- Existing: Firebase, form login harvesters
- New: Auth0, Supabase, Keycloak automated login
- New: Cognito detection + harvester (no detection logic exists yet)
- Token refresh during long scans
- Credential store shared across all scan modules

**US-6.2: Authenticated Scan Profiles**
> As a hunter, I want to save and reuse authentication profiles (credentials + provider config) per target, so I don't reconfigure auth on every scan.

Acceptance criteria:
- Save/load auth profiles per target domain
- Encrypted credential storage
- Profile selection in both GUI and TUI

### Epic 7: API Testing

**US-7.1: API Collection Testing**
> As a hunter testing APIs, I want to import Postman/OpenAPI collections and run them with assertion-based validation, so I can test API-specific vulnerabilities systematically.

Acceptance criteria (all new -- nothing exists yet):
- Collection/folder/request hierarchy with environments and variables
- Import from Postman, curl, OpenAPI, Bruno (.bru)
- Auth injectors: API Key, Basic, Bearer, Digest, OAuth2, WSSE
- Assertion engine with status, body, header checks
- Variable interpolation with built-in functions (timestamps, random, UUID)
- Integration with scanner: feed API paths into vulnerability modules

### Epic 8: Platform and UX

**US-8.1: Tri-Interface Parity**
> As a hunter, I want full feature parity between the Swing GUI, TUI, and headless CLI, so I can use whichever interface fits my environment (desktop, SSH, or CI).

Acceptance criteria:
- All three interfaces expose core scan functionality
- Keyboard shortcuts documented and consistent
- Privacy filter available in both (Ctrl+Shift+P in GUI)

**US-8.2: Cross-Platform Distribution**
> As a hunter, I want native installers for my OS, so I can install AnarCry without manually managing Java runtimes.

Acceptance criteria:
- .deb (Debian/Ubuntu), .rpm (RHEL/Fedora), .msi (Windows), .dmg (macOS)
- Bundled JRE via jpackage
- Shadow jar as fallback for any platform

---

## 6. Priority Matrix

| Priority | Items | Target |
|----------|-------|--------|
| P0 - Ship blocker | Reduce FP rate (US-2.1), SARIF output (4.7) | Next sprint |
| P1 - High value | OAST infrastructure (US-1.2), CSRF (US-1.3), Secrets Discovery (US-1.7), Race Conditions (US-1.4) | v2.2 |
| P2 - Competitive | NoSQL Injection (US-1.5), File Upload (US-1.6), JWT++ (US-2.3), AI Orchestrator (US-3.2) | v2.3 |
| P3 - Differentiator | Multi-step chaining (US-2.2), Auth harvester expansion (US-6.1), API Client (US-7.1, new build) | v2.4 |
| P4 - Polish | Auth profiles (US-6.2), Interface parity (US-8.1), Scan persistence (4.8) | v2.5 |

Note: Vercel WAF integration (US-5.2) was resolved and removed from P0.

---

## 7. Technical Constraints

- **Java 27** with Gradle 9.x build system
- **Static analysis enforced:** Checkstyle, PMD, SpotBugs+FindSecBugs, Spotless
- **Test policy:** JUnit 5, `integration` tag for network tests, E2E harness exists
- **Concurrency:** 4-thread parallel scan, 300s module timeout, circuit breaker
- **Dependencies:** Lanterna (TUI), FlatLaf+RSyntaxTextArea+JFreeChart (GUI), BouncyCastle (crypto), Playwright (browser, optional), impersonator-okhttp (TLS fingerprint mimicry), Gson (JSON)
- **License:** AGPL-3.0

---

## 8. Completed Sprints (reference)

Sprints 18-28 are all complete:
- S18: SSRF++ (protocol smuggling, DNS rebinding patterns)
- S19: Host Header Injection module
- S20: Spring Actuator module
- S21: Mass Assignment module
- S22: CORS++ (subdomain wildcard, null origin)
- S23: SSTI RCE (template engine detection)
- S24: IDOR++ (numeric ID, UUID, parameter pollution)
- S25: Cache Poisoning module
- S26: HTTP Request Smuggling (6 phases: CL.TE, TE.CL, TE.TE, H2.CL, H2.TE, detection)
- S27: Open Redirect++ (JS redirect, meta refresh, protocol relative)
- S28: CRLF++ (header injection, log injection, response splitting)
