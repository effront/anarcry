# PRD -- Credential Harvester (Multi-Provider Token Extraction)

**Status**: Draft
**Author**: Michael D.
**Date**: 2026-11-04

---

## Problem

AnarCry currently requires the user to manually extract JWT tokens, session cookies,
or bearer tokens from the target application before starting a scan. This involves
opening browser DevTools, navigating IndexedDB/localStorage/cookies, and
copy-pasting values into the scanner. The process varies by auth provider (Firebase,
Auth0, Cognito, Supabase, custom), is error-prone, and breaks workflow -- the user
leaves the scanner to do manual browser archaeology every time a token expires.

## Proposed Solution

A **Credential Harvester** module that sits in the pre-scan phase (both TUI and Swing GUI)
and automates token extraction from known auth providers. The user provides a
target URL and login credentials (or an already-authenticated browser profile/cookie jar),
and the harvester identifies the auth provider, extracts the relevant tokens, and
populates `ScanContext` fields automatically.

## Goals

1. Auto-detect the auth provider used by the target (Firebase, Auth0, Cognito, Supabase, Keycloak, custom OAuth2/OIDC)
2. Extract valid JWT / session cookie / bearer token without manual DevTools work
3. Support token refresh during long scans (tokens expire mid-scan today with no recovery)
4. Integrate into both TUI and Swing GUI as a pre-scan step

## Non-Goals

- Credential bruteforcing or password spraying (this is NOT an auth attack module)
- Bypassing MFA (user must complete MFA themselves if required)
- Storing credentials persistently (tokens live only in memory for the scan session)
- Replacing the manual credential input -- it stays as a fallback

---

## Auth Provider Detection

### Phase 1: Passive Fingerprinting

On target URL input, the harvester makes a single GET to the target and inspects:

| Signal                              | Provider          |
|-------------------------------------|-------------------|
| `/__/auth/` paths, `firebaseapp.com` in scripts | Firebase          |
| `.auth0.com` domain in scripts/redirects         | Auth0             |
| `cognito-idp.*.amazonaws.com` references         | AWS Cognito       |
| `.supabase.co` references, `sb-` prefixed keys   | Supabase          |
| `/auth/realms/` paths                            | Keycloak          |
| `/.well-known/openid-configuration` present       | Generic OIDC      |
| Standard `Set-Cookie` session headers              | Cookie-based      |

### Phase 2: Active Probing (opt-in)

If passive detection fails, probe common auth endpoints:

- `/.well-known/openid-configuration`
- `/oauth/token` (Auth0)
- `/__/auth/handler` (Firebase)
- `/auth/v1/token` (Supabase)
- `/realms/{realm}/protocol/openid-connect/token` (Keycloak)

---

## Extraction Strategies

### Strategy 1: OAuth2/OIDC Password Grant (headless)

For providers that support `grant_type=password` (Resource Owner Password Credentials):

```
POST /oauth/token
Content-Type: application/x-www-form-urlencoded

grant_type=password&username=USER&password=PASS&client_id=CLIENT_ID&scope=openid
```

**Works with**: Auth0 (if enabled), Keycloak, custom OIDC servers
**Requires**: username, password, client_id (auto-discovered from page source)

### Strategy 2: Firebase Auth REST API

Firebase exposes a public REST API for email/password auth:

```
POST https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=API_KEY
Content-Type: application/json

{"email": "USER", "password": "PASS", "returnSecureToken": true}
```

**Auto-discovers**: `apiKey` from page source (`firebaseConfig` object)
**Returns**: `idToken` (JWT), `refreshToken`, `expiresIn`
**Refresh**: `POST /v1/token?key=API_KEY` with `grant_type=refresh_token`

### Strategy 3: Supabase Auth API

```
POST https://<project>.supabase.co/auth/v1/token?grant_type=password
Content-Type: application/json
apikey: <anon-key>

{"email": "USER", "password": "PASS"}
```

**Auto-discovers**: project URL + anon key from page source
**Returns**: `access_token` (JWT), `refresh_token`

### Strategy 4: Cookie Jar Import

For cookie-based auth, import from:

- **Browser profile path** -- read cookies.sqlite (Firefox) or Cookies (Chromium) directly
- **Netscape cookie file** -- standard format used by curl, wget
- **Raw header paste** -- user pastes `Cookie: ...` header from DevTools

### Strategy 5: Browser Automation (Phase 2 -- future)

Headless Chromium via CDP for sites requiring interactive login (OAuth social login,
CAPTCHA, MFA). Out of scope for v1 but the architecture should support plugging it in.

---

## Token Lifecycle Management

### Auto-Refresh

```
CredentialStore
  +-- activeToken: String          -- current JWT/cookie in use
  +-- refreshToken: String         -- refresh token (if available)
  +-- expiresAt: Instant           -- token expiry time
  +-- provider: AuthProvider       -- which strategy to use for refresh
  +-- refreshThreshold: Duration   -- refresh N seconds before expiry (default: 60s)

  refresh() -> String              -- returns new token, updates internal state
  isExpiringSoon() -> boolean      -- true if within refreshThreshold of expiry
```

Integration point: `Http.send()` checks `CredentialStore.isExpiringSoon()` before each
request and transparently refreshes. The scan never sees an expired token.

### Token Expiry by Provider

| Provider    | Default TTL | Refresh mechanism                |
|-------------|-------------|----------------------------------|
| Firebase    | 1 hour      | refresh_token -> /v1/token       |
| Auth0       | varies      | refresh_token -> /oauth/token    |
| Cognito     | 1 hour      | refresh_token -> InitiateAuth    |
| Supabase    | 1 hour      | refresh_token -> /auth/v1/token  |
| Keycloak    | 5 minutes   | refresh_token -> /token          |
| Cookie      | varies      | no auto-refresh (warn user)      |

---

## Architecture

### New Classes

```
scanner/
  auth/
    AuthProvider.java          -- enum: FIREBASE, AUTH0, COGNITO, SUPABASE, KEYCLOAK, OIDC, COOKIE, MANUAL
    ProviderDetector.java      -- passive + active fingerprinting (GET target, parse scripts)
    CredentialStore.java       -- holds active token + refresh logic + expiry tracking
    harvester/
      Harvester.java           -- interface: detect(), harvest(username, password) -> CredentialStore
      FirebaseHarvester.java   -- Firebase REST API auth + apiKey discovery
      Auth0Harvester.java      -- Auth0 password grant + client_id discovery
      SupabaseHarvester.java   -- Supabase auth API + anon key discovery
      KeycloakHarvester.java   -- Keycloak OIDC token endpoint
      OidcHarvester.java       -- Generic OIDC password grant
      CookieHarvester.java     -- Cookie jar import (browser profile, netscape file, raw paste)
```

### Interface

```java
public interface Harvester {
    AuthProvider provider();
    boolean canHandle(String targetUrl, String pageSource);
    CredentialStore harvest(String targetUrl, String username, String password,
                           Map<String, String> extra) throws AuthException;
}
```

### Integration with ScanContext

`ScanContext` gains a `CredentialStore` field. `Http.send()` reads the active token
from `CredentialStore` instead of the static `jwtToken` string. If `CredentialStore`
is null, falls back to the current static token behavior (backwards compatible).

---

## TUI Flow

The harvester appears as a new option in the Target config area, between auth type
selection and the credential fields:

```
Target:  https://target.com
Auth Type: [None | JWT | Cookie | Bearer | Auto-Harvest]
                                          ^^^^^^^^^^^^

--- when Auto-Harvest is selected ---

[Detecting provider...]  Firebase detected (apiKey: AIza...)

Email/Username: [________________________]
Password:       [________________________]

[Harvest Credentials]

Status: [v] ID Token extracted (expires in 58m)
        [v] Refresh token stored -- auto-refresh enabled
        [v] Token injected as JWT auth
```

If detection fails, falls back to manual input with a hint about which provider
was partially detected.

### TUI Keybinds

- `Ctrl+H` in Target mode -- toggle harvester panel
- `Enter` on "Harvest Credentials" -- run extraction
- `F5` anywhere during scan -- force token refresh

### Swing GUI Flow

New tab or expandable section in `TargetView`, above the existing JWT fields:

```
+-------------------------------------------+
| Credential Harvester                  [v]  |
+-------------------------------------------+
| Provider: [Auto-detect | Firebase | ...]   |
| Username: [____________________________]   |
| Password: [____________________________]   |
| [Harvest]  Status: Ready                   |
|                                            |
| Token TTL: 58:23 remaining  [Refresh Now]  |
+-------------------------------------------+
```

The existing JWT/Cookie fields become read-only when the harvester is active,
showing the extracted value (masked by `PrivacyFilter`).

---

## Client ID / API Key Auto-Discovery

Critical for headless auth -- most providers embed their client config in the
page source. Discovery strategy:

1. **GET target URL** -- parse HTML response
2. **Scan inline `<script>` blocks** for config objects:
   - Firebase: `apiKey`, `authDomain` in `firebaseConfig` or `firebase.initializeApp({...})`
   - Auth0: `domain`, `clientId` in `new Auth0Client({...})` or `auth0.createAuth0Client({...})`
   - Supabase: `supabaseUrl`, `supabaseKey` in `createClient(url, key)`
   - Keycloak: `realm`, `url`, `clientId` in `Keycloak({...})`
3. **Scan external JS files** referenced by `<script src>` (first-party only, skip CDNs)
4. **Check `/.well-known/openid-configuration`** for OIDC endpoints

Store discovered config in `ProviderDetector.DiscoveryResult`:

```java
public record DiscoveryResult(
    AuthProvider provider,
    String clientId,
    String apiKey,
    String authEndpoint,
    String tokenEndpoint,
    String refreshEndpoint,
    Map<String, String> extra
) {}
```

---

## Security Considerations

- Credentials are held in memory only -- never written to disk, logs, or reports
- `PrivacyFilter` applies to harvested tokens in both TUI and GUI
- Refresh tokens are zeroed on scan completion (`CredentialStore.destroy()`)
- Harvester only authenticates with user-supplied credentials to user-supplied targets
  -- it does not probe or guess passwords
- Client IDs / API keys discovered from page source are public by design (SPA config)
  -- no secrets are extracted from the target

---

## Migration / Backwards Compatibility

- `AuthType` enum gains a new value: `AUTO` (Auto-Harvest)
- Existing `NONE | JWT | COOKIE | BEARER` modes work exactly as before
- `.env.local` gains optional fields: `auth_provider`, `auth_username`, `auth_password`
  (for headless/CI usage)
- `ScanContext.jwtToken()` continues to work -- `CredentialStore` populates it transparently

---

## Phased Rollout

### Phase 1 (MVP)

- `ProviderDetector` -- passive fingerprinting only
- `FirebaseHarvester` -- Firebase REST API (email/password)
- `CredentialStore` with auto-refresh wired into `Http.send()`
- TUI integration (Auth Type: Auto-Harvest option)
- Swing GUI integration (Credential Harvester section in TargetView)

### Phase 2

- `Auth0Harvester`, `SupabaseHarvester`, `KeycloakHarvester`
- `OidcHarvester` (generic)
- Active probing in `ProviderDetector`
- External JS scanning for client config discovery

### Phase 3

- `CookieHarvester` (browser profile import -- Firefox/Chromium SQLite)
- Netscape cookie file import
- `F5` force-refresh keybind
- Token expiry countdown in status bar

### Phase 4 (future)

- Browser automation via CDP for interactive logins
- OAuth2 authorization code flow with local callback server
- Social login support (GitHub, Google) via OAuth2 device flow

---

## Open Questions

1. **Credential storage between runs** -- should `.env.local` support storing encrypted
   refresh tokens for reuse, or always require fresh auth? Leaning toward always-fresh
   for security.
2. **Rate limiting** -- some providers rate-limit token endpoint calls. Should the
   harvester implement backoff, or just surface the error?
3. **Multi-tenant Keycloak** -- realm auto-discovery is non-trivial. Worth it for Phase 2
   or defer?
4. **CAPTCHA on login** -- Firebase/Auth0 can require reCAPTCHA on sign-in. Surface this
   as "use manual mode" or attempt to handle?
