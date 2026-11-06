# Prompt: Implement Vercel WAF Detection + Challenge Bypass in AnarCry

## Context

AnarCry is a Java 27 security scanner (bug bounty tool) at `/home/bullet/PROJETOS/AnarCry/`. It has a WAF detection and bypass pipeline that currently supports Cloudflare, Akamai, AWS WAF, Imperva, and others -- but NOT Vercel. When scanning a Vercel-hosted target (e.g. yatari.com.br), every HTTP request gets a 403 with a "Vercel Security Checkpoint" challenge page, and the scanner fails silently -- modules read the challenge page's headers instead of the actual application.

Read the gap analysis at `docs/vercel-waf-gap-analysis.md` for full context. Read `CLAUDE.md` for project rules (no emoji, no auto-commits, no em-dash, run spotlessApply before staging).

## What to implement

There are 6 gaps to fix across 3 files (`WafState.java`, `WafEvasion.java`, `ScanRunner.java`). Two other files (`ChallengeSolver.java`, `Http.java`) already work correctly and need NO changes.

### 1. `WafState.java` -- new block type

Add `VERCEL_CHALLENGE` to `WafBlockType` enum, between `JS_CHALLENGE` and `TURNSTILE`. It represents a solvable-via-headless challenge that requires WASM proof-of-work + mouse simulation (harder than JS_CHALLENGE, but unlike MANAGED_CHALLENGE it IS automatable).

Add a threshold constant `VERCEL_CHALLENGE_THRESHOLD = 5` and wire it into `effectiveThreshold()`.

Add `isVercelChallenge()` convenience method that returns `blockType == VERCEL_CHALLENGE`.

### 2. `WafEvasion.java` -- detection

**WAF_SERVER regex** (line 48-49): add `vercel` to the alternation.

**WAF_BODY regex** (line 51-53): add `vercel security checkpoint` and `we're verifying your browser` to the alternation.

**SIGNATURES list** (line 60-104): add a new `WafSignature` for Vercel:
```
id: "vercel"
name: "Vercel"
category: "waf"
signals:
  HEADER "x-vercel-mitigated"     confidence 100
  HEADER "x-vercel-challenge-token" confidence 100
  HEADER "x-vercel-id"            confidence 60
  CONTENT "Vercel Security Checkpoint" confidence 95
```

**isWafBlocked()** (line 251-262): after the existing server/body checks, add a Vercel-specific check: if status is 403 and header `x-vercel-mitigated` equals "challenge", return true. This ensures runtime WAF detection works even when the body pattern doesn't match.

### 3. `ScanRunner.java` -- Phase 1.5 Vercel branch + post-scan fix

**Phase 1.5 (line 316-446)**: Add a Vercel-specific branch BEFORE the CF challenge check (line 318). The logic:

```
// After the probe response is obtained (around line 315):

// Check Vercel challenge FIRST (before CF checks)
String vercelMitigated = probeResp.headers().firstValue("x-vercel-mitigated").orElse("");
boolean isVercel = "challenge".equalsIgnoreCase(vercelMitigated)
    || (probeBody.contains("Vercel Security Checkpoint"));

if (isVercel) {
    ctx.wafState().markWafDetected(baselineProvider.isEmpty() ? "Vercel" : baselineProvider);
    ctx.wafState().markBlockType(WafState.WafBlockType.VERCEL_CHALLENGE);
    ctx.wafState().markJsChallenge("Vercel Security Checkpoint");
    safeLog.accept("[!] Phase 1.5: Vercel Security Checkpoint detectado (HTTP " + probeResp.statusCode() + ")");

    // Approach 1: automatic -- ChallengeSolver
    safeLog.accept("[*] Phase 1.5: tentando ChallengeSolver (headless Chromium + WASM)...");
    ChallengeSolver.Result csResult = ChallengeSolver.solve(ctx.targetUrl(), safeLog);

    if (csResult != null && csResult.cookies() != null && !csResult.cookies().isBlank()) {
        ctx.wafState().setChallengeCookies(csResult.cookies());
        safeLog.accept("[+] Phase 1.5: Vercel challenge resolvido -- cookies de clearance extraidos");
        safeLog.accept("[+] Phase 1.5: cookies serao injetados em todos os requests via Http.send()");

        // Optionally also spin up BrowserTransport for JS-heavy pages
        BrowserTransport browserTx = BrowserTransport.create(ctx.targetUrl(), safeLog);
        if (browserTx != null) {
            ctx.wafState().setBrowserTransport(browserTx);
            safeLog.accept("[+] Phase 1.5: BrowserTransport ativado como transport complementar");
        }
    } else {
        // Approach 2: fallback -- manual cookie passthrough
        safeLog.accept("[-] Phase 1.5: ChallengeSolver falhou ou Playwright indisponivel");
        safeLog.accept("[*] Fallback: abra o alvo no browser, resolve o challenge, e extraia cookies:");
        safeLog.accept("[*]   1. No console do browser: document.cookie");
        safeLog.accept("[*]   2. Cole o valor no campo 'Session Cookie' do AnarCry");
        safeLog.accept("[*]   3. Mude Auth Type para Cookie e reinicie o scan");

        // If user already provided session cookies, they might contain clearance
        if (!ctx.config().sessionCookie().isBlank()) {
            safeLog.accept("[+] Session Cookie detectado -- tentando usar como clearance");
            ctx.wafState().setChallengeCookies(ctx.config().sessionCookie());
        }
    }
    // Skip the CF/generic branches below
}
```

The `else if` chain for CF checks (line 318 onward) stays as-is but wrapped in `else` so it only fires when Vercel is not detected.

**Post-scan finding (line 517-538)**: Replace the hardcoded "Cloudflare" strings. Use `wafState.challengeType()` when available, falling back to block type name. Something like:

```java
if (ctx.wafState().isManaged() || ctx.wafState().isVercelChallenge()) {
    String challengeLabel = ctx.wafState().challengeType();
    if (challengeLabel.isEmpty()) {
        WafState.WafBlockType wafBt = ctx.wafState().blockType();
        challengeLabel = switch (wafBt) {
            case TURNSTILE -> "Cloudflare Turnstile";
            case VERCEL_CHALLENGE -> "Vercel Security Checkpoint";
            default -> ctx.wafState().wafProduct() + " Managed Challenge";
        };
    }
    // ... use challengeLabel instead of typeName
}
```

Only emit this post-scan finding if the challenge was NOT successfully solved (i.e., no challenge cookies were set).

## What NOT to change

- `ChallengeSolver.java` -- already works, has Vercel support, mouse simulation, cookie extraction
- `Http.java` -- cookie injection already works via `challengeCookies()`
- `BrowserTransport.java` -- transport layer already works
- `CircuitBreaker.java` -- no changes needed

## Build and verify

```bash
cd /home/bullet/PROJETOS/AnarCry
./gradlew spotlessApply
./gradlew build
```

Do NOT commit. Do NOT run the scanner against any target. Just make sure it compiles.

## Code style

- Google Java Format enforced via Spotless (`./gradlew spotlessApply`)
- No emoji anywhere
- Use `--` instead of em-dash
- Records over classes for immutable data
- `Consumer<String> log` callback pattern (no logging framework)
- Import `ChallengeSolver` in `ScanRunner` -- it's in the same `scanner.util` package
