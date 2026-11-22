# PRD -- AnarCry Bounty Automation Pipeline (v1)

**Data:** 2026-11-14
**Autor:** Bullet
**Baseado em:** SwapCult bug bounty engagement (2026-11-13/14)
**Objetivo:** Fechar os gaps entre o que AnarCry automatiza hoje e o que um bounty end-to-end exige, targeting 99% automation da pipeline recon-to-report.

---

## 1. Problem Statement

During the SwapCult bounty, ~80% of the work that produced findings was manual:

| Step | AnarCry handled | Manual effort |
|---|---|---|
| Crawler (sitemap, paths, JS bundles) | Partial -- found 61 paths, 12 JS files | WAF killed it mid-scan (Playwright bug) |
| JS bundle secret extraction | Missed Meld key:secret (no pattern) | Manually grepped 2.3MB bundle |
| API endpoint extraction from JS | Not supported | Manually read composable chunks |
| Backend liveness check | Not supported | Manually ran dig + curl on extracted apiBase |
| Clickjacking detection | X-Frame-Options flag per-page only | Manually checked 7 pages, built PoC HTML |
| API key validation | Not supported | Manually tested Meld API with 3 auth variations |
| HMAC signature computation | Not supported | Manually computed base64url(HMACSHA256(...)) |
| Subdomain takeover (DO App Platform) | Not in fingerprint DB | Manually tested 5 DO API vectors |
| Multi-page header consistency | Not supported (root only) | Manually checked 7 pages + 404 |
| PoC generation | Not supported | Hand-wrote clickjacking-poc.html |
| Report formatting (bug bounty) | Markdown/JSON only | Hand-wrote REPORT.md, FORM-SUBMISSION.txt, gist |
| DOM sink analysis (innerHTML XSS) | Not supported | Manually found innerHTML in payment chunk |
| Framework config extraction | Not supported | Manually found window.__NUXT__.config |

**Target:** A single `anarcry scan --bounty https://target.com` produces a findings report with validated secrets, PoCs, and a formatted report ready for submission.

---

## 2. Architecture Overview

New modules and enhancements organized by pipeline phase:

```
[Phase 1: Recon]
  CrawlerModule (existing, enhance)
  +-- FrameworkConfigExtractor (new)
  +-- JsBundleAnalyzer (new)
  +-- BackendLivenessProbe (new)

[Phase 2: Scan]
  HeadersModule (existing, enhance for multi-page + clickjacking)
  SecretsModule (existing, enhance patterns)
  SubdomainTakeoverModule (existing, add fingerprints)
  +-- DomSinkAnalyzer (new)
  +-- ClickjackingModule (new, split from Headers)

[Phase 3: Validate]
  +-- SecretValidator (new)
  +-- HmacAuthProber (new)

[Phase 4: Report]
  ReportEngine (existing, enhance)
  +-- PocGenerator (new)
  +-- BountyFormatter (new)
```

---

## 3. Epics and User Stories

### EPIC 1: JS Bundle Intelligence

**Why:** The 2.3MB Nuxt bundle contained the Meld API key:secret, the dead backend URL, all API endpoints, and the innerHTML XSS vector. AnarCry downloaded 12 JS files but only ran regex patterns against them for known secret formats. The highest-impact findings came from JS analysis, not HTTP probing.

#### US-1.1: Framework Config Extraction

**As a** bounty hunter scanning a target,
**I want** AnarCry to extract framework-specific config objects from HTML and JS,
**so that** backend URLs, API keys, feature flags, and route maps are automatically surfaced.

**Acceptance criteria:**
- Parses `window.__NUXT__` (Nuxt.js), `window.__NEXT_DATA__` (Next.js), `window.__REMIX_CONTEXT__` (Remix), `window.env` / `window._env_` (generic), `import.meta.env` (Vite)
- Extracts `apiBase`, `baseURL`, `API_URL` and similar backend URL patterns
- Extracts embedded credentials (apiKey, secret, token patterns in config objects)
- Outputs structured data: `{framework, configKey, value, sourceUrl, lineContext}`
- Feeds extracted URLs into CrawlerModule's discovered paths for downstream scanning

**Technical notes:**
- Runs after CrawlerModule downloads JS bundles
- Regex-based extraction (no full JS parser needed -- configs are serialized JSON in var assignments)
- Patterns: `window\.__NUXT__\s*=\s*\{`, `window\.__NEXT_DATA__\s*=\s*\{`, `"apiBase"\s*:\s*"([^"]+)"`
- Must handle minified JS (no whitespace assumptions)

#### US-1.2: API Endpoint Extraction from JS

**As a** bounty hunter,
**I want** AnarCry to extract API endpoint definitions from JS bundles (fetch calls, axios configs, $fetch),
**so that** hidden/undocumented endpoints are discovered for scanning.

**Acceptance criteria:**
- Detects `fetch("/api/...", ...)`, `$fetch("/api/...", ...)`, `axios.get/post("/api/...")`, `this.$http`
- Extracts: method (GET/POST/PUT/DELETE), path, Content-Type, auth headers (if any)
- Flags endpoints that have NO auth headers as "unauthenticated API" finding (INFO severity)
- Feeds endpoints into ScanContext.discoveredPaths for other modules to test
- Handles template literals: `\`/api/v1/swaps/exchange/${id}\`` extracts `/api/v1/swaps/exchange/{param}`

**SwapCult gap:** The 3 swap endpoints (new-estimate, new-exchange, exchange/{id}) were only found by manually reading composable chunk CkwmW5gq.js. AnarCry's CrawlerModule regex missed them because they were in `$fetch()` calls, not in HTML links or path-like strings.

#### US-1.3: DOM Sink Analysis (Static)

**As a** bounty hunter,
**I want** AnarCry to identify dangerous DOM sinks in JS bundles,
**so that** potential XSS vectors are flagged without requiring runtime testing.

**Acceptance criteria:**
- Detects: `innerHTML`, `outerHTML`, `document.write`, `insertAdjacentHTML`, `eval()`, `setTimeout(string)`, `setInterval(string)`, `new Function(string)`
- For each sink, extracts the surrounding context (variable being assigned)
- Cross-references with data sources (fetch responses, URL params, user input)
- Generates a MEDIUM finding when a sink is fed by external data
- Generates an INFO finding for sinks with unknown data flow

**SwapCult gap:** `innerHTML:S.value` in e_7Lv_jA.js was found manually. This renders exchange data from the unauthenticated API, creating a stored XSS vector.

#### US-1.4: Enhanced Secret Patterns for Crypto/Fintech

**As a** bounty hunter targeting crypto/fintech platforms,
**I want** AnarCry's SecretsModule to detect domain-specific credential patterns,
**so that** API keys for payment processors, onramp providers, and blockchain services are found.

**Acceptance criteria:**
- New patterns: Meld API (`key:secret` format, alphanumeric:alphanumeric 20+ chars), Coinbase Commerce, Transak, MoonPay, Wyre, Ramp, Alchemy, Infura, Moralis, QuickNode, WalletConnect projectId
- Contextual patterns: any `key:secret` pair near keywords like "api", "authorization", "auth", "meld", "onramp"
- Firebase config objects: `apiKey`, `authDomain`, `projectId`, `storageBucket` as a group
- DigitalOcean API tokens: `dop_v1_[a-f0-9]{64}`
- Vercel deployment tokens: `dpl_[a-zA-Z0-9]+`

**SwapCult gap:** SecretsModule has no pattern for Meld-style `key:secret` pairs. The Generic API Key pattern requires `api_key=` prefix and quotes, which `Bae="WXETMuFUQmqqybHuRkSgxv:..."` doesn't match.

---

### EPIC 2: Clickjacking Detection and PoC

**Why:** Clickjacking was the primary finding (HIGH severity, $5K-$20K range). AnarCry's HeadersModule detected missing X-Frame-Options and CSP as separate LOW/MEDIUM findings but never connected them into a clickjacking finding, never checked multiple pages, and never generated a PoC. The PoC HTML was written by hand.

#### US-2.1: Dedicated Clickjacking Module

**As a** bounty hunter,
**I want** a dedicated ClickjackingModule that tests iframe embedding across multiple pages,
**so that** clickjacking vulnerabilities are found with higher confidence and proper severity.

**Acceptance criteria:**
- Checks all discovered paths (from CrawlerModule), not just root
- Tests: X-Frame-Options header, CSP frame-ancestors directive, JS frame-busting code
- Detects inconsistency (e.g., 404 pages have CSP but main pages don't)
- Severity escalation: missing on auth/transaction pages = HIGH; missing on info pages = MEDIUM
- CWE-1021, CVSS adjusted based on page functionality
- Produces a single consolidated finding per domain (not per-header-per-page)
- Reports which pages are vulnerable vs protected

**SwapCult gap:** HeadersModule reported "X-Frame-Options ausente" (MEDIUM) and "CSP ausente" (MEDIUM) as separate findings. Neither mentioned clickjacking by name. The real impact (wallet connection + swap manipulation) was only understood through manual analysis. Also missed that 404 pages DID have `frame-ancestors 'none'` while all other pages didn't.

#### US-2.2: Clickjacking PoC Generator

**As a** bounty hunter,
**I want** AnarCry to generate a working clickjacking PoC HTML file,
**so that** the finding can be demonstrated without manual HTML authoring.

**Acceptance criteria:**
- Generates standalone HTML file with:
  - Invisible iframe loading the target
  - Overlay with realistic phishing pretext (customizable template)
  - Opacity slider for researcher demonstration
  - Evidence bar showing absent headers
  - Banner marking it as authorized PoC
- Templates for common attack contexts: "airdrop claim" (crypto), "reward claim" (generic), "account verification"
- Output path: `{reportDir}/poc-clickjacking-{domain}.html`

---

### EPIC 3: Secret Validation Pipeline

**Why:** Finding an API key in JS is a MEDIUM finding at best. Proving the key is valid against the live API escalates it to HIGH. We manually tested the Meld key with 3 different auth variations to prove it was recognized. This should be automated.

#### US-3.1: Secret Validator Engine

**As a** bounty hunter,
**I want** AnarCry to automatically validate discovered secrets against their respective APIs,
**so that** findings include proof of key validity.

**Acceptance criteria:**
- Post-scan phase: after SecretsModule runs, SecretValidator tests each found credential
- Validation strategies per service:
  - AWS: `sts:GetCallerIdentity` (safe, read-only)
  - GitHub/GitLab: `/user` endpoint
  - Stripe: `/v1/balance`
  - Google API: test against Maps/Translate API
  - Generic: HEAD request with Authorization header, compare responses (with key vs without vs invalid key)
- Records: HTTP status, response body snippet, differential analysis (3-response comparison like the Meld test)
- Finding severity upgrade: unvalidated = MEDIUM; validated-active = HIGH; validated-with-permissions = CRITICAL
- Safety: only safe read-only endpoints, no state modifications, no data creation

**SwapCult gap:** Meld key validation required 3 manual curl commands comparing responses. The 3-response differential (valid key: "Missing Meld-Signature", no auth: "Full authentication required", invalid key: "Forbidden") proved the key was recognized. This pattern is generic and automatable.

#### US-3.2: HMAC Signature Computation

**As a** bounty hunter,
**I want** AnarCry to compute HMAC signatures when it finds a key:secret pair,
**so that** it can fully validate APIs that require signed requests.

**Acceptance criteria:**
- Detects HMAC requirement from API error responses ("Missing signature", "Invalid signature", etc.)
- Supports common HMAC schemes:
  - `HMAC-SHA256(timestamp.url.body)` (Meld style)
  - `HMAC-SHA256(timestamp + method + path + body)` (Coinbase style)
  - `HMAC-SHA512(payload)` (Binance/Kraken style)
- Auto-detects scheme from API documentation patterns in error responses
- Computes signature and retries the request
- Records whether signed request succeeds, fails with 403 (deactivated), or returns data

---

### EPIC 4: Dangling Backend and Infrastructure Detection

**Why:** The dead DigitalOcean backend (`xmr-swap-76mw2.ondigitalocean.app`) was the second-highest impact finding. It was discovered by reading the HTML source, not by any AnarCry module. SubdomainTakeoverModule only checks CNAME chains -- it doesn't detect inline backend references in JS/HTML.

#### US-4.1: Backend Liveness Probe

**As a** bounty hunter,
**I want** AnarCry to check whether all referenced backend URLs are alive,
**so that** dead/dangling backend references are automatically detected.

**Acceptance criteria:**
- Input: URLs extracted by FrameworkConfigExtractor (US-1.1) and JsEndpointExtractor (US-1.2)
- For each external URL: DNS resolution check + HTTP HEAD request
- NXDOMAIN = CRITICAL finding (dangling backend, potential takeover)
- Connection refused / timeout = HIGH finding (dead backend, broken functionality)
- 5xx = MEDIUM finding (backend unhealthy)
- Cross-references with SubdomainTakeoverModule for CNAME-based takeover
- Finding includes: source location in JS/HTML, extracted endpoint list, DNS evidence

**SwapCult gap:** `window.__NUXT__.config.public.apiBase = "https://xmr-swap-76mw2.ondigitalocean.app"` was found by reading HTML source. SubdomainTakeoverModule checked CNAMEs for `swapcult.com` subdomains but never looked at inline references.

#### US-4.2: Expanded Subdomain Takeover Fingerprints

**As a** bounty hunter,
**I want** SubdomainTakeoverModule to cover modern hosting platforms,
**so that** dangling references to all major cloud services are detected.

**Acceptance criteria:**
- Add fingerprints for:
  - DigitalOcean App Platform (`*.ondigitalocean.app`)
  - Vercel (`*.vercel.app`)
  - Netlify (`*.netlify.app`)
  - Firebase Hosting (`*.web.app`, `*.firebaseapp.com`)
  - Fly.io (`*.fly.dev`)
  - Railway (`*.railway.app`)
  - Render (`*.onrender.com`)
  - Cloudflare Pages (`*.pages.dev`)
- Each fingerprint includes: CNAME pattern, HTTP body pattern, and takeover feasibility notes
- Takeover feasibility field: "confirmed_vulnerable" / "requires_account_access" / "slug_recycling_possible" / "not_vulnerable"

**SwapCult gap:** SubdomainTakeoverModule has 10 fingerprints but none for DigitalOcean, Vercel, Netlify, Firebase, Fly, Railway, Render, or Cloudflare Pages -- the platforms most modern web apps use.

---

### EPIC 5: Multi-Page Analysis

**Why:** The clickjacking finding was strengthened by showing that ALL 7 pages lacked frame protection while 404 pages had it -- proving it was a configuration gap, not a deliberate choice. AnarCry only checks the root page for most header-based findings.

#### US-5.1: Multi-Page Header Scanning

**As a** bounty hunter,
**I want** AnarCry to check security headers on multiple pages (not just root),
**so that** per-route misconfigurations and inconsistencies are detected.

**Acceptance criteria:**
- Scans: root (/), all paths from sitemap.xml, discovered paths from CrawlerModule, error page (triggers 404)
- Compares headers across pages: same domain should have consistent policy
- Flags inconsistency as a finding (e.g., "CSP present on /404 but absent on / and /referral")
- Caps at 20 pages to avoid excessive traffic
- Runs after CrawlerModule (depends on discovered paths)

---

### EPIC 6: WAF Bypass Reliability

**Why:** The Vercel Security Checkpoint killed the scan mid-run. ChallengeSolver (Playwright headless) failed with a bug, BrowserTransport timed out, and payload encoding bypass was ineffective. This blocked all active testing.

#### US-6.1: Fix ChallengeSolver Playwright Integration

**As a** bounty hunter running AnarCry against WAF-protected targets,
**I want** ChallengeSolver to reliably solve JS challenges,
**so that** active scanning isn't blocked by WAFs.

**Acceptance criteria:**
- Fixes the current Playwright startup bug (observed: process fails to launch)
- Handles Vercel Security Checkpoint (JS challenge, not CAPTCHA)
- Handles Cloudflare JS Challenge (turnstile non-interactive)
- Extracts and caches clearance cookies for the session
- Falls back gracefully: if challenge requires human interaction (CAPTCHA), log and skip (don't crash)
- Timeout: 15s per challenge attempt, 3 retries with backoff

**SwapCult gap:** Scan log shows `ChallengeSolver` attempting Playwright launch and failing. After that, BrowserTransport timed out, and the circuit breaker kicked in. All subsequent requests returned the challenge page instead of real content.

---

### EPIC 7: Automated PoC and Report Generation

**Why:** Writing the report took longer than finding the vulnerabilities. The clickjacking PoC HTML, the REPORT.md, the FORM-SUBMISSION.txt guide, and the gist -- all manual. For a 99% automated pipeline, the scanner must output submission-ready artifacts.

#### US-7.1: PoC Generator Framework

**As a** bounty hunter,
**I want** AnarCry to generate PoC artifacts for each finding type,
**so that** I can demonstrate vulnerabilities without manual coding.

**Acceptance criteria:**
- Templates for:
  - Clickjacking: HTML with invisible iframe + overlay (US-2.2)
  - CORS misconfiguration: HTML with cross-origin fetch
  - Open redirect: URL demonstrating redirect chain
  - XSS: URL with payload or HTML page
  - IDOR: curl command sequence showing data from different IDs
  - Header findings: curl command showing absent headers
  - Secret exposure: curl command extracting secret from JS (masked)
- Output: files in `{reportDir}/poc/` directory
- Each PoC includes: authorization banner, date, target, finding reference

#### US-7.2: Bug Bounty Report Formatter

**As a** bounty hunter,
**I want** AnarCry to generate a formatted report matching common bug bounty program structures,
**so that** I can submit findings directly without reformatting.

**Acceptance criteria:**
- Formats: Markdown (generic), HackerOne, Bugcrowd, Immunefi, Google Forms (field-by-field)
- Per-finding sections: Title, Severity, CWE, CVSS, Description, Evidence, Impact, Steps to Reproduce, Suggested Fix
- Combined impact analysis: connects related findings (e.g., "clickjacking + wallet signing = fund theft")
- Evidence: inline curl commands, header dumps, code snippets from JS analysis
- Attachment manifest: lists PoC files, screenshots, and suggested gist content
- Template variables: `{target}`, `{date}`, `{hunter}`, `{program_url}`

---

## 4. Priority Matrix

| Epic | Stories | Value (bounty $) | Effort (days) | Priority |
|---|---|---|---|---|
| E1: JS Bundle Intelligence | 1.1, 1.2, 1.3, 1.4 | Critical -- missed $5K+ finding | 8-10 | P0 |
| E2: Clickjacking Detection | 2.1, 2.2 | High -- primary finding was manual | 3-4 | P0 |
| E3: Secret Validation | 3.1, 3.2 | High -- severity escalation | 5-6 | P1 |
| E4: Dangling Backend | 4.1, 4.2 | Critical -- missed CRITICAL finding | 4-5 | P0 |
| E5: Multi-Page Analysis | 5.1 | Medium -- strengthens findings | 2-3 | P1 |
| E6: WAF Bypass | 6.1 | High -- blocks all active scanning | 3-4 | P0 |
| E7: PoC and Report | 7.1, 7.2 | Medium -- saves 2+ hours per bounty | 5-6 | P2 |

**Suggested sprint order:**
1. Sprint 1 (P0): E6 (WAF fix), E1 (JS intelligence), E4 (dangling backend)
2. Sprint 2 (P0+P1): E2 (clickjacking), E3 (secret validation), E5 (multi-page)
3. Sprint 3 (P2): E7 (PoC + report generation)

---

## 5. Integration Points

### New Module Registration (ScanRunner)

```
ctx.has("FrameworkConfig")  -> FrameworkConfigExtractor  (after Crawler)
ctx.has("JsAnalyzer")       -> JsBundleAnalyzer          (after Crawler)
ctx.has("DomSinks")         -> DomSinkAnalyzer           (after Crawler)
ctx.has("BackendLiveness")  -> BackendLivenessProbe      (after FrameworkConfig)
ctx.has("Clickjacking")     -> ClickjackingModule        (after Crawler)
ctx.has("SecretValidator")  -> SecretValidator            (after Secrets)
```

### Data Flow

```
CrawlerModule
  |-> discoveredPaths (existing)
  |-> jsUrls (existing, feed to new modules)
  |
  +-> FrameworkConfigExtractor
  |     |-> extractedConfigs {framework, key, value, sourceUrl}
  |     |-> backendUrls (feed to BackendLivenessProbe)
  |
  +-> JsBundleAnalyzer
  |     |-> apiEndpoints {method, path, contentType, hasAuth}
  |     |-> feed to discoveredPaths
  |
  +-> DomSinkAnalyzer
  |     |-> domSinks {sinkType, context, sourceUrl, dataFlow}
  |
  +-> SecretsModule (enhanced patterns)
        |-> rawSecrets (existing)
        |-> SecretValidator (post-scan)
              |-> validatedSecrets {secret, service, isValid, evidence}
```

### ScanContext Additions

```java
record ExtractedConfig(String framework, String key, String value, String sourceUrl) {}
record ApiEndpoint(String method, String path, String contentType, boolean hasAuth) {}
record DomSink(String type, String context, String sourceUrl) {}

// New fields on ScanContext:
List<ExtractedConfig> extractedConfigs();
List<ApiEndpoint> apiEndpoints();
List<DomSink> domSinks();
```

### CweRegistry Additions

```
ClickjackingModule  -> CWE-1021 (Improper Restriction of Rendered UI Layers)
DomSinkAnalyzer     -> CWE-79   (XSS) -- reuse existing
BackendLiveness     -> CWE-672  (Operation on Resource after Expiration)
SecretValidator     -> CWE-798  (Hard-coded Credentials) -- reuse from Secrets
FrameworkConfig     -> CWE-200  (Exposure of Sensitive Information)
```

---

## 6. Non-Goals (v1)

- Smart contract analysis (out of scope for web scanner)
- CAPTCHA solving (only JS challenges)
- Browser automation for full interaction flows (wallet connect, swap execution)
- Automated bounty submission (report is generated, submission is manual)
- Screenshot capture (requires headless browser -- future version)
- Integration with bounty platforms via API (HackerOne, Immunefi)

---

## 7. Success Metric

Re-run against SwapCult (or equivalent target): AnarCry should automatically find all 4 findings from the report (clickjacking, Meld key, dangling backend, missing headers) without manual intervention beyond target URL input.

Quantitative target: manual effort per bounty drops from ~4 hours to <30 minutes (review + submit).
