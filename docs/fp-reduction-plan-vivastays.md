# AnarCry FP Reduction & Detection Gaps -- VivaStays Pentest Analysis

**Source**: Pentest real contra `server.vivastays.co` (2026-11-21)
**Scan**: AnarCry v2.3.0 -- 32 findings, 59.4% FP rate (19 FP, 13 TP, 0 CRITICAL/HIGH detected)
**Manual**: 47 findings (9 CRITICAL, 12 HIGH) -- zero overlap com achados automatizados alem de headers

---

## Metricas do Scan

| Metrica | Valor |
|---------|-------|
| Total findings AnarCry | 32 |
| True Positives | 13 (40.6%) |
| False Positives | 19 (59.4%) |
| Missed (manual encontrou, AnarCry nao) | 34 |
| CRITICAL detectados | 0 / 9 |
| HIGH detectados | 0 / 12 |
| FP por modulo: SQLi | 5/5 (100%) |
| FP por modulo: ProtoPollution | 14/14 (100%) |
| FP por modulo: Headers/CORS/HSTS | 0/13 (0%) |

---

## Phase 0 -- P0: Eliminar False Positives (19 FPs)

### US-01: SQLi time-based -- verificacao proporcional

**Como** operador de scan
**Quero** que o modulo SQLi valide timing com multiplos sleep values
**Para** eliminar FPs causados por latencia de rede/infra

**Contexto**: 5 findings CRITICAL falsos. Todos em rotas 404 com body vazio. Deltas de ~9.4s nao correlacionam com SLEEP(5) (esperado ~5s+baseline). CmdInjection ja implementa verificacao proporcional e descartou spikes identicos no mesmo scan.

**Acceptance Criteria**:
- [ ] Se baseline retorna 404 ou 410, skip time-based probing pra esse path+param
- [ ] Se baseline body e vazio/null, skip time-based probing
- [ ] Apos SLEEP(5) trigger, confirmar com SLEEP(1) -- delta deve escalar proporcionalmente (tolerancia 40%)
- [ ] Se 2+ DBMS diferentes (MySQL + PostgreSQL + MSSQL) triggam no mesmo host, flag batch inteiro como suspect e exigir confirmacao proporcional
- [ ] Portar logica de `CmdInjectionModule.probeProportional()` pro SQLi

**Arquivos**: `scanner/web/sqli/SqlInjectionModule.java`

---

### US-02: ProtoPollution -- canary em URL echo vs reflexao real

**Como** operador de scan
**Quero** que o modulo ProtoPollution distinga reflexao real de URL echo em paginas de erro
**Para** eliminar 14 FPs de canary "refletido" em body de 0 bytes ou error pages

**Contexto**: 14 findings MEDIUM falsos. NestJS 404 retorna `{"message":"Cannot GET /path?__proto__[ppcanary]=anarcry_pp_7x3k9","statusCode":404}` -- o canary aparece porque o framework ecoa a URL no erro, nao porque houve poluicao.

**Acceptance Criteria**:
- [ ] Antes de declarar reflexao, strip a probe URL completa do response body. Se canary desaparece, nao e reflexao real
- [ ] Skip canary check se response status e 404/405/410
- [ ] Skip canary check se body length < 100 bytes ou body matches pattern de error JSON (`{"message":"Cannot GET`, `{"statusCode":4`)
- [ ] Se 100% dos paths testados triggam (N paths = N findings), suprimir batch inteiro (100% hit rate = detector quebrado)
- [ ] Differential check: comparar body COM canary param vs SEM. Se identicos (ambos empty, ambos 404), nao ha reflexao

**Arquivos**: `scanner/web/protopollution/PrototypePollutionModule.java`

---

### US-03: SubTakeover -- fingerprint Railway faltando

**Como** operador de scan
**Quero** que dangling CNAMEs pra Railway sejam detectados como takeover
**Para** nao perder subdomain takeover em `*.up.railway.app`

**Contexto**: Scanner encontrou CNAME chain `opentl.vivastays.co -> 1x12kfkz.up.railway.app` mas reportou "nenhuma vulnerabilidade detectada". O deployment Railway esta deletado (retorna 404 "Application not found") -- classico indicador de takeover.

**Acceptance Criteria**:
- [ ] Adicionar fingerprint Railway: CNAME `*.up.railway.app` + response contendo "Application not found" = takeover confirmado
- [ ] Revisar lista de fingerprints e adicionar outros PaaS faltando (Render, Fly.io, Vercel)

**Arquivos**: `scanner/web/subtakeover/SubdomainTakeoverModule.java`

---

## Phase 1 -- P1: Gaps Criticos de Deteccao

### US-04: IDOR -- probe sem autenticacao (BOLA)

**Como** operador de scan
**Quero** que o modulo IDOR teste endpoints sem auth, nao so cross-user
**Para** detectar BOLA (Broken Object Level Authorization) que foi 100% do ataque real

**Contexto**: O maior blind spot. IDOR module retorna `List.of()` na linha 68-69 quando nao tem auth tokens. Todos os 8 IDORs reais eram endpoints sem autenticacao nenhuma. Esse unico fix teria pego 3 dos 6 CRITICAL findings.

**Acceptance Criteria**:
- [ ] Novo `probeUnauthenticated()` que roda ANTES do auth check
- [ ] Envia GET/POST pra candidate endpoints SEM auth headers
- [ ] Se response 200 com JSON data, flag como BOLA (CWE-306: Missing Authentication for Critical Function)
- [ ] Detectar PII na response (2+ patterns = CRITICAL): email, phone, CPF, coordenadas, campos de senha/doorCode/wifiPW
- [ ] Detectar mass data exposure: response > 100KB ou 100+ JSON objects = flag como data leak
- [ ] Probe de validation error: POST body vazio -> se 422 com Zod errors MAS sem 401/403, flag como "auth bypass -- endpoint processa input sem auth"

**Arquivos**: `scanner/web/idor/IdorModule.java`

---

### US-05: tRPC awareness -- discovery e probing

**Como** operador de scan
**Quero** que o scanner entenda endpoints tRPC (`/trpc/namespace.procedure`)
**Para** mapear a superficie de ataque de apps Next.js/tRPC (100 procedures perdidas nesse scan)

**Contexto**: O alvo usa tRPC exclusivamente. Nenhum modulo entende o formato `/trpc/router.procedure?batch=1&input={"0":{"json":{}}}`. 10 findings CRITICAL/HIGH perdidos por falta de tRPC awareness.

**Acceptance Criteria**:
- [ ] JsAnalyzerModule: novo regex pra `X.namespace.procedure.useQuery/useMutation` em JS bundles
- [ ] JsAnalyzerModule: novo regex pra `.concat("url", "/trpc")` (URL building do tRPC client)
- [ ] CrawlerModule: adicionar `/trpc` ao wordlist e ao `PATH_PATTERN` regex
- [ ] IdorModule: novo `probeTrpc()` que constroi batch queries no formato tRPC e testa com/sem auth
- [ ] XssModule: awareness de endpoints tRPC pra stored XSS via mutations
- [ ] Cada procedure descoberta mapeia pra: `POST /trpc/{namespace}.{procedure}?batch=1`

**Arquivos**: `scanner/web/jsanalyzer/JsAnalyzerModule.java`, `scanner/web/crawler/CrawlerModule.java`, `scanner/web/idor/IdorModule.java`, `scanner/web/xss/XssModule.java`

---

### US-06: JsAnalyzer -- patterns modernos (UploadThing, Server Actions, PostHog)

**Como** operador de scan
**Quero** que o JsAnalyzer detecte patterns de frameworks modernos em JS bundles
**Para** mapear upload endpoints, server actions, e analytics keys que o scan perdeu

**Contexto**: JS bundles continham 4 UploadThing slugs, server action hashes, PostHog key refs, e 6 integration platforms -- tudo invisivel pro scanner atual.

**Acceptance Criteria**:
- [ ] UploadThing: regex pra `endpoint:"*Uploader"` e `startUpload("slug")` -> mapeia pra `/api/uploadthing?slug={slug}`
- [ ] Next.js Server Actions: regex pra `createServerReference("hash", ...)` -> flag hash + nome da action
- [ ] PostHog/analytics: regex pra `posthog.init()`, `NEXT_PUBLIC_*` env vars, `phc_*` keys
- [ ] Issue tracker refs: regex pra `[A-Z]{2,10}-\d{1,6}` (Jira/Linear IDs em configs)
- [ ] JsBundleDiscovery: fix NEXT_CHUNK_PATH pra suportar subdirectory paths (`app/page-HASH.js`)

**Arquivos**: `scanner/web/jsanalyzer/JsAnalyzerModule.java`, `scanner/util/JsBundleDiscovery.java`

---

### US-07: XSS -- stored XSS e upload SVG

**Como** operador de scan
**Quero** que o modulo XSS detecte stored XSS via POST e SVG upload XSS
**Para** cobrir os 2 vetores de XSS que o pentest encontrou e o scanner perdeu

**Contexto**: Pentest achou stored XSS via `POST /trpc/visitor.visitorForm` (script tag em name field) e SVG XSS via upload sem auth no UploadThing (SVG com script servido inline como `image/svg+xml`).

**Acceptance Criteria**:
- [ ] Novo `probeStoredXss()`: POST canary em JSON body fields (`name`, `title`, `description`, `comment`, `message`) -> GET pra verificar persistencia
- [ ] Novo `probeUploadXss()`: probe de config em `/api/uploadthing` e upload endpoints conhecidos. Se SVG permitido e servido com `Content-Type: image/svg+xml` + `Content-Disposition: inline`, flag como HIGH
- [ ] Broadened `isUsable()`: aceitar `image/svg+xml`, `application/xhtml+xml`, `text/xml` alem de `text/html`
- [ ] Novo `isJsonApi()` check pra stored XSS via JSON APIs

**Arquivos**: `scanner/web/xss/XssModule.java`

---

## Phase 2 -- P2: Qualidade e Severity

### US-08: CORS -- severity sem credentials

**Como** operador de scan
**Quero** que CORS wildcard sem `ACAC: true` seja MEDIUM, nao HIGH
**Para** nao inflar severity de CORS em APIs publicas read-only

**Acceptance Criteria**:
- [ ] Se `ACAO: *` mas `ACAC` ausente ou != "true", downgrade pra MEDIUM (CVSS 5.3)
- [ ] Manter HIGH somente quando `ACAC: true` presente
- [ ] Probe secundario: request sem auth headers -> se 401/403, downgrade pra INFO (endpoint auth-gated + sem credentials = zero impact)

**Arquivos**: `scanner/web/cors/CorsModule.java`

---

### US-09: Headers -- 404-aware probing

**Como** operador de scan
**Quero** que o HeadersModule re-probe em um path 2xx quando o base retorna 404
**Para** nao reportar missing headers em error pages que nao representam a app real

**Acceptance Criteria**:
- [ ] Se base response e 404/5xx, adicionar nota na evidence: "HTTP 404 (error page) -- headers may not reflect production routes"
- [ ] Se crawler descobriu paths 2xx, re-rodar header checks no primeiro 2xx path
- [ ] Adicionar PaaS providers (Railway, Heroku, Render, Fly.io, Vercel, Netlify) ao CDN_WAF_NAMES pra skip/downgrade de Server header disclosure

**Arquivos**: `scanner/crypto/headers/HeadersModule.java`

---

### US-10: Crawler -- wordlist moderna

**Como** operador de scan
**Quero** que o Crawler tenha paths de frameworks modernos no wordlist
**Para** nao perder endpoints de tRPC, UploadThing, Clerk, Metabase

**Acceptance Criteria**:
- [ ] Adicionar ao wordlist: `/trpc`, `/api/uploadthing`, `/api/session/properties`, `/api/oembed`, `/v1/environment`, `/_next/data`, `/webhooks`, `/manifest.json`
- [ ] Expandir PATH_PATTERN regex pra incluir `trpc|upload|session|webhook|oembed`

**Arquivos**: `scanner/web/crawler/CrawlerModule.java`

---

## Phase 3 -- P3: Novos Modulos (backlog)

### US-11: RateLimitModule -- deteccao de brute-force

**Contexto**: 4 findings CRITICAL no pentest eram brute-force sem rate limiting (login, MFA, password reset).

- [ ] Novo modulo: envia N requests rapidos pra auth endpoints, checa 429/throttle
- [ ] Testa: login, password reset, MFA verification
- **Arquivos**: novo `scanner/web/ratelimit/RateLimitModule.java`

### US-12: EmailSecurityModule -- SPF/DMARC/DKIM

**Contexto**: Finding MEDIUM no pentest por SPF softfail e DMARC missing.

- [ ] Novo modulo: DNS queries pra SPF, DMARC, DKIM records
- [ ] Flag: softfail, missing DMARC, weak DKIM key sizes
- **Arquivos**: novo `scanner/web/emailsec/EmailSecurityModule.java`

### US-13: ClerkModule -- auth provider detection

**Contexto**: 4 findings por Clerk DEV key em producao e user enumeration.

- [ ] Detectar `pk_test_` keys em HTML/JS (Clerk dev key em prod)
- [ ] Probe `/v1/environment` pra config disclosure
- [ ] User enumeration via differential response em sign-in
- **Arquivos**: novo `scanner/web/clerk/ClerkModule.java`

### US-14: Error disclosure -- stack traces e path leaks

**Contexto**: Source code leak via error stack em tRPC endpoints.

- [ ] Parse error responses pra stack traces, internal paths, framework versions
- [ ] Pode ser cross-cutting concern ou modulo dedicado
- **Arquivos**: novo `scanner/web/errordisclosure/ErrorDisclosureModule.java`

---

## Plano de Implementacao

### Sprint 1 -- FP Elimination (Phase 0)

| US | Estimativa | Impacto |
|----|-----------|---------|
| US-01 SQLi proporcional | M | -5 CRITICAL FPs |
| US-02 ProtoPollution URL echo | M | -14 MEDIUM FPs |
| US-03 SubTakeover Railway | P | +1 HIGH TP |

**Meta**: FP rate de 59.4% -> ~0% nos modulos afetados

### Sprint 2 -- Critical Detection (Phase 1a)

| US | Estimativa | Impacto |
|----|-----------|---------|
| US-04 IDOR unauth probe | G | +3 CRITICAL TPs (BOLA, PII, mass data) |
| US-05 tRPC awareness | G | +10 findings (tRPC procedures) |

**Meta**: Detectar BOLA e tRPC endpoints

### Sprint 3 -- Detection Expansion (Phase 1b)

| US | Estimativa | Impacto |
|----|-----------|---------|
| US-06 JsAnalyzer patterns | M | +4 categories (UploadThing, ServerActions, PostHog, issues) |
| US-07 XSS stored + SVG | G | +2 findings (stored XSS, upload XSS) |

**Meta**: Cobrir vetores de XSS modernos e JS intelligence

### Sprint 4 -- Quality & Polish (Phase 2)

| US | Estimativa | Impacto |
|----|-----------|---------|
| US-08 CORS severity | P | Severity accuracy |
| US-09 Headers 404-aware | P | Evidence quality |
| US-10 Crawler wordlist | P | Discovery coverage |

**Meta**: Severity correta e melhor discovery

### Backlog (Phase 3)

| US | Estimativa | Impacto |
|----|-----------|---------|
| US-11 RateLimit module | G | +4 CRITICAL (brute-force) |
| US-12 EmailSec module | M | +1 MEDIUM (SPF/DMARC) |
| US-13 Clerk module | M | +4 findings (auth provider) |
| US-14 Error disclosure | M | +1 MEDIUM (stack trace) |

---

## Legenda

- **P** = Pequeno (< 2h)
- **M** = Medio (2-4h)
- **G** = Grande (4-8h)
- **FP** = False Positive
- **TP** = True Positive
- **BOLA** = Broken Object Level Authorization

---

**Resultado esperado pos-implementacao (Phase 0-2)**:
- FP rate: 59.4% -> < 5%
- CRITICAL detection: 0/9 -> 4-6/9
- HIGH detection: 0/12 -> 6-8/12
- Coverage geral: 27.7% -> ~60-70%
