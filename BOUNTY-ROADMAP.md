# AnarCry — Bounty Readiness Roadmap

**Data:** 2026-10-23  
**Autor:** Bullet  
**Objetivo:** mapear o delta entre o AnarCry atual e um scanner pronto para uso real em bug bounty, com export para HackerOne/Bugcrowd.

---

## 1. Estado Atual (Inventário Honesto)

### 1.1 Módulos implementados (18)

| Módulo | Categoria | Qualidade atual | Notas |
|--------|-----------|-----------------|-------|
| TLS | Crypto | ✅ Sólido | Versões, cipher suites, certs X.509 |
| Headers | Crypto | ✅ Sólido | HSTS, CSP, cookies, info disclosure |
| JWT | Crypto | ✅ Muito bom | 7 probes — alg:none, RS256→HS256, JWK injection, null sig, kid, sig disclosure, jku |
| PQC | Crypto | ✅ Sólido | TLS 1.3, X25519MLKEM768 — diferencial único |
| CORS | Web | ✅ Bom | reflection, null, prefix/suffix/http-downgrade |
| OAuth | Web | ⚠️ Básico | state param, redirect_uri — discovery limitado |
| OpenRedirect | Web | ⚠️ Básico | 5 paths × 9 params × 3 payloads fixos |
| SSRF | Web | ✅ Bom | 14 probes cloud+localhost, redirect bypass, FP corrigido (Next.js) |
| GraphQL | Web | ✅ Bom | discovery, introspection, error verbosity, batching |
| CRLF | Web | ✅ Bom | 25 payloads, path + query injection |
| XXE | Web | ✅ Bom | 11 paths, file read + SSRF |
| SSTI | Web | ✅ Bom | 6 payloads, engine ID (Jinja2/Twig/FreeMarker/ERB) |
| IDOR | Web | ✅ Bom | GET cross-user, DELETE cross-user, GraphQL mutations |
| HostHeader | Web | ✅ Bom | 4 headers × 5 targets, password reset poisoning |
| SpringActuator | Web | ✅ Bom | 16 endpoints Boot 1.x/2.x — FP corrigido (2026-10-23) |
| MassAssignment | Web | ⚠️ Ruidoso | MEDIUM FP alto — "aceita JSON" afeta qualquer REST API |
| CachePoisoning | Web | ✅ Bom | 5 unkeyed headers, cache-hit detection via x-cache/cf-cache |
| ReqSmuggling | Web | ✅ Muito bom | CL.TE, TE.CL, TE.TE via socket raw — diferencial |

**TUI:** 6 modos (Dashboard, Scan, Target, Findings, Repeater, Report) — completa e funcional.  
**Harness:** 55 testes end-to-end.  
**Report Engine:** exporta `.md` + `.json` no formato AnarCry.

### 1.2 O que está realmente bom

- **Request Smuggling via socket raw** — a maioria das ferramentas usa HTTP libraries que normalizam o request; AnarCry contorna isso.
- **JWT com 7 probes** — cobertura acima de 90% dos scanners gratuitos.
- **PQC probe com JEP 496** — sem concorrência nesta categoria de ferramenta.
- **HTML FP guard** em Actuator, SSRF, MassAssign — padrão estabelecido no código.
- **RequestRecord** logging via `ctx.requestLog()` — base para Repeater funcional.
- **Harness com mock servers Java** — regressions cobertas sem deps externas.

---

## 2. Gap Analysis — Por que ainda não está pronto para bounty

### Gap 1 — Endpoint Discovery (CRÍTICO)

**Problema:** todos os 18 módulos usam paths hardcoded. O scanner é cego para a estrutura real do alvo.

Exemplos concretos do código atual:

```java
// SSRF — 9 paths fixos (SsrfModule.java:33)
private static final List<String> PROBE_PATHS = List.of(
    "/", "/api/", "/api/v1/", "/api/fetch", "/api/proxy", ...);

// IDOR — 16 paths fixos com IDs sequenciais (IdorModule.java:22)
private static final List<String> ID_PATHS = List.of(
    "/api/user/1", "/api/users/1", "/api/user/2", ...);

// MassAssign — 10 endpoints fixos (MassAssignmentModule.java:35)
private static final List<Endpoint> ENDPOINTS = List.of(
    new Endpoint("PUT", "/api/user"), new Endpoint("PUT", "/api/users/me"), ...);
```

Na maioria dos alvos reais de bounty:
- IDs são UUIDs (`/api/user/550e8400-e29b-41d4-a716-446655440000`) — os hardcoded `/1` e `/2` retornam 404.
- Paths de API seguem convenções do alvo (`/v3/accounts/`, `/internal/admin/`) — não o padrão genérico.
- Endpoints de upload, webhook, import ficam de fora completamente.

**Impacto:** o scanner passa em branco em 80% dos alvos reais porque os paths vulneráveis não estão nas listas fixas.

**Solução:** `CrawlerModule` que extrai endpoints do alvo antes dos módulos de scan rodarem, e um `SwaggerModule` para OpenAPI/Swagger discovery.

---

### Gap 2 — CVSS + CWE (obrigatório para HackerOne)

**Problema:** o record `Finding` não tem campos de CVSS nem CWE.

```java
// Finding.java — ausência de cvssScore, cvssVector, cweId
public record Finding(
    String module, String endpoint, String title,
    Severity severity, String evidence, String impact,
    String reproduction, String recommendation
) {}
```

HackerOne exige ao submeter um report:
- `weakness_id` → CWE (ex: CWE-942 para CORS, CWE-918 para SSRF, CWE-639 para IDOR)
- Severidade no formato CVSS v3.1 base score (Critical ≥ 9.0, High ≥ 7.0, etc.)

Sem isso o hunter precisa calcular manualmente para cada finding — exatamente o trabalho repetitivo que o AnarCry deveria eliminar.

**Mapeamento natural por módulo:**

| Módulo | CWE primário | CVSS base exemplo (critical path) |
|--------|-------------|----------------------------------|
| CORS reflection + creds | CWE-942 | AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N = **8.1** |
| SSRF cloud metadata | CWE-918 | AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N = **10.0** |
| IDOR GET cross-user | CWE-639 | AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N = **6.5** |
| JWT alg:none | CWE-347 | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N = **9.1** |
| ReqSmuggling CL.TE | CWE-444 | AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H = **9.0** |
| SSTI RCE | CWE-94 | AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H = **10.0** |
| XXE file read | CWE-611 | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N = **7.5** |
| MassAssign admin=true | CWE-915 | AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N = **8.1** |
| CachePoisoning | CWE-524 | AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:N = **8.7** |
| CRLF cookie injection | CWE-113 | AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N = **6.1** |
| HostHeader pwd reset | CWE-20 | AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N = **8.1** |
| TLS 1.0/1.1 | CWE-326 | AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N = **5.9** |

---

### Gap 3 — HackerOne / Bugcrowd Export Format

**Problema:** `ReportEngine` gera formato AnarCry. HackerOne e Bugcrowd têm templates específicos que os programas esperam.

**HackerOne report template:**
```markdown
## Summary
[1-2 linhas: o que é a vulnerabilidade]

## Description
[Explicação técnica detalhada]

## Steps to Reproduce
1. Autentique-se como usuário comum
2. Execute: curl ...
3. Observe: [resultado]

## Supporting Material / References
- [screenshots, curl outputs, HTTP responses]

## Impact
[O que um atacante pode fazer com isso]

**Weakness:** CWE-942 — Permissive Cross-domain Policy with Untrusted Domains
**Severity:** High (CVSS 8.1)
```

**Bugcrowd template** tem estrutura diferente: usa "Classification" (VRT taxonomy) em vez de CWE, e "Proof of Concept" como campo separado de "Replication".

O `ReportEngine` atual gera uma tabela + seção por finding — útil para relatórios internos mas não para submissão direta a plataformas.

---

### Gap 4 — Rate Limiting

**Problema:** nenhum delay entre requests em nenhum módulo.

Volume atual por scan completo (estimativa):
- SSRF: até 9 paths × 18 params × 14 probes = **2.268 requests**
- SSTI: 6 payloads × 8 paths × 11 params = **528 requests**
- OpenRedirect: 135 requests
- IDOR: 16 paths × 2 tokens + 8 DELETE + 4 GraphQL = **44 requests**
- Actuator: 16 endpoints = **16 requests**
- CORS: 4 paths × 5 origins × 2 auth modes = **40 requests**
- **Total estimado: ~3.000–4.000 requests num scan completo**

Programas de bounty como HackerOne e Bugcrowd têm cláusulas explícitas:
> "Do not perform automated scanning at a rate that would degrade our services."

WAFs de CDN (Cloudflare, Akamai) aplicam rate limiting a partir de ~50–100 req/s de um único IP.

Sem controle de rate, o scanner bane o próprio hunter.

---

### Gap 5 — Cookie Authentication

**Problema:** `ScanContext` só suporta `jwtToken` / `jwtToken2`. Muitos alvos de bounty usam session cookies.

```java
// ScanContext.java — sem campo para session cookie
public record ScanContext(String targetUrl, String jwtToken, 
    Set<String> enabledModules, String jwtToken2, Consumer<RequestRecord> requestLog)
```

Apps que usam cookies: Laravel (PHPSESSID + XSRF-TOKEN), Rails (\_session\_id), Django (sessionid + csrftoken), .NET (`.AspNetCore.Session`), Odoo (session\_id).

Para IDOR, MassAssignment, CORS autenticado — sem cookie não tem acesso aos endpoints protegidos.

---

### Gap 6 — Scope Management

**Problema:** nenhum controle de escopo.

Exemplos de violação possível:
1. SSRF redirect bypass (`hcFollow = HttpClientFactory.followOne()`) segue 1 redirect — pode sair do domínio alvo.
2. OpenRedirect segue redirects para verificar `Location` header — pode fazer requests externos.
3. HostHeader e CORS probes enviam requests com domínios externos (`evil.anarcry-probe.com`, `evil.com`) — isso aparece nos logs do alvo e pode violar regras de "no social engineering" de programas.

Programas sérios de bounty definem:
- **In scope:** `*.target.com`, `api.target.com`
- **Out of scope:** `admin.target.com`, `staging.target.com`

Sair de scope é motivo de ban imediato.

---

### Gap 7 — False Positive Rate em MassAssignment

**Problema:** MassAssignment gera finding MEDIUM para qualquer endpoint que retorna HTTP 200 ao receber o payload JSON — o que é 100% dos REST APIs normais.

```java
// MassAssignmentModule.java:122 — MEDIUM para qualquer 200 com JSON não-HTML
if ((status == 200 || status == 201) && !body.isBlank() && !isHtml(body)) {
    // Only report if baseline GET also returned something (endpoint is real)
    if (getResp.statusCode() == 200 || getResp.statusCode() == 404) {
        findings.add(...MEDIUM...); // ← FP em praticamente todo REST API
    }
}
```

Um MEDIUM falso positivo num relatório de bounty é rejeitado com nota negativa de "não triado" — prejudica a reputação do hunter.

**Solução:** confirmar persistência via GET após a mutation. Se os campos admin aparecerem no GET subsequente → finding real. Se não → descartar.

---

### Gap 8 — IDOR: IDs Sequenciais vs UUIDs

**Problema:** o `IdorModule` usa `/api/user/1` e `/api/user/2` como paths fixos. Alvos modernos usam UUIDs.

```java
// IdorModule.java:22 — IDs numéricos hardcoded
private static final List<String> ID_PATHS = List.of(
    "/api/user/1", "/api/users/1",
    "/api/user/2", "/api/users/2", ...);
```

Sem descoberta dos IDs reais do usuário autenticado, o módulo de IDOR passa em branco em APIs com UUIDs.

**Solução:** no modo autenticado, fazer GET em `/api/me` ou `/api/profile` → extrair o ID do usuário logado → construir paths dinamicamente. Para cross-user, precisar de 2 tokens com IDs conhecidos.

---

### Gap 9 — Paralelismo

**Problema:** `ScanRunner` é single-thread.

```java
// ScanRunner.java:33
private final ExecutorService executor = Executors.newSingleThreadExecutor(...);
```

Com 18 módulos sequenciais e ~4.000 requests, um scan completo demora 3–8 minutos dependendo da latência do alvo. Módulos independentes (TLS, Headers, PQC, JWT) poderiam rodar em paralelo.

---

### Gap 10 — OpenAPI / Swagger Discovery

**Problema:** nenhum módulo descobre ou parseia specs de OpenAPI.

Se o alvo expõe `/swagger.json` ou `/openapi.json`, toda a estrutura da API (endpoints, métodos, parâmetros, schemas) fica disponível. Com isso:
- SSRF sabe exatamente quais parâmetros aceitam URLs
- IDOR sabe quais endpoints têm IDs e qual o formato
- MassAssignment sabe quais campos o objeto tem

Sem isso, todos os módulos operam às cegas.

---

## 3. Roadmap — Sprints 16–22

### Sprint 16 — CVSS + CWE + Deduplicação
**Prioridade: Alta | Pré-requisito para tudo abaixo**

**Motivação:** sem CVSS e CWE nos findings, o export para HackerOne sempre vai precisar de preenchimento manual. São os campos mais cobrados em triagem.

**Entregáveis:**

**`Finding.java` — novos campos:**
```java
public record Finding(
    String module, String endpoint, String title,
    Severity severity, String evidence, String impact,
    String reproduction, String recommendation,
    String cweId,       // ex: "CWE-918"
    String cweTitle,    // ex: "Server-Side Request Forgery (SSRF)"
    String cvssVector,  // ex: "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N"
    double cvssScore    // ex: 10.0
) {}
```

**`CvssCalculator.java` — calculadora CVSS v3.1 base score:**
- Parser de CVSS vector string
- Cálculo conforme fórmula FIRST (ISS, ESS, scope-changed)
- Método estático: `double calculate(String vector)`

**`CweRegistry.java` — mapa de módulo→CWE:**
```java
// Compiletime constants — um finding type = um CWE primário
public static final Map<String, String[]> MODULE_CWE = Map.of(
    "CORS",          new String[]{"CWE-942", "Permissive Cross-domain Policy"},
    "SSRF",          new String[]{"CWE-918", "Server-Side Request Forgery"},
    "IDOR",          new String[]{"CWE-639", "Authorization Bypass Through User-Controlled Key"},
    "JWT",           new String[]{"CWE-347", "Improper Verification of Cryptographic Signature"},
    "ReqSmuggling",  new String[]{"CWE-444", "Inconsistent Interpretation of HTTP Requests"},
    "SSTI",          new String[]{"CWE-94",  "Improper Control of Generation of Code"},
    "XXE",           new String[]{"CWE-611", "Improper Restriction of XML External Entity Reference"},
    "MassAssign",    new String[]{"CWE-915", "Improperly Controlled Modification of Dynamically-Determined Object Attributes"},
    "CachePoisoning",new String[]{"CWE-524", "Use of Cache Containing Sensitive Information"},
    "CRLF",          new String[]{"CWE-113", "Improper Neutralization of CRLF Sequences in HTTP Headers"},
    "HostHeader",    new String[]{"CWE-20",  "Improper Input Validation"},
    "OpenRedirect",  new String[]{"CWE-601", "URL Redirection to Untrusted Site"},
    "TLS",           new String[]{"CWE-326", "Inadequate Encryption Strength"},
    "Headers",       new String[]{"CWE-693", "Protection Mechanism Failure"},
    "OAuth",         new String[]{"CWE-352", "Cross-Site Request Forgery"},
    "GraphQL",       new String[]{"CWE-200", "Exposure of Sensitive Information to an Unauthorized Actor"},
    "Actuator",      new String[]{"CWE-200", "Exposure of Sensitive Information to an Unauthorized Actor"}
);
```

**Deduplicação em `ScanRunner`:**
- Chave: `module + endpoint + title` (hash)
- Set de chaves vistas antes de `findingCb.accept(f)`
- Finding duplicado logado como `[~] dedup: ignorado` sem ser adicionado

**`ReportEngine`:** incluir CVSS score e CWE nas seções de detalhe do MD.

**Harness:** 3 testes — CVSS cálculo correto para 3 vetores conhecidos; dedup bloqueia finding idêntico; CWE mapeado corretamente por módulo.

---

### Sprint 17 — HackerOne + Bugcrowd Export
**Prioridade: Alta | Depende de Sprint 16**

**Motivação:** o objetivo central do roadmap. Com CVSS + CWE disponíveis, gerar o template correto é trabalho de formatação.

**Entregáveis:**

**`ReportEngine.exportH1(findings, target, programName)` → `String`:**
```markdown
# [Severity] Title — target.com

**Program:** ProgramName  
**Asset:** https://target.com  
**Severity:** High (CVSS 8.1 — AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N)  
**Weakness:** CWE-942 — Permissive Cross-domain Policy with Untrusted Domains  

## Summary
[impact field do Finding — 1-2 linhas]

## Description
[evidence + contexto técnico]

## Steps to Reproduce
```
[reproduction field — curl command formatado]
```

## Supporting Material
- Scanner: AnarCry v1.0
- Date: 2026-10-23
- [evidence snippet]

## Impact
[impact field expandido]
```

**`ReportEngine.exportBugcrowd(findings, target)` → `String`:**
- Formato Bugcrowd VRT: Classification ao invés de CWE
- Campo "Proof of Concept" separado de "Replication Steps"
- VRT mapping: SSRF → "Server-Side Injection > SSRF", CORS → "Broken Authentication & Session Management > CORS", etc.

**TUI — modo REPORT (F6) atualizado:**
- Opção de escolha: `[1] AnarCry MD  [2] HackerOne  [3] Bugcrowd  [4] JSON`
- Ao selecionar H1/Bugcrowd: campo para nome do programa
- Export salva `h1-report-<timestamp>.md` ou `bugcrowd-report-<timestamp>.md`

**Harness:** 2 testes — export H1 contém campos obrigatórios; export Bugcrowd contém VRT classification.

---

### Sprint 18 — Crawler / Endpoint Discovery
**Prioridade: Alta | Maior impacto em bounty**

**Motivação:** sem descoberta de endpoints, o scanner é cego. Esta é a maior lacuna estrutural.

**Arquitetura:**
`CrawlerModule` não implementa `Scanner` — é um **enricher** que roda antes de todos os módulos e popula `ScanContext.discoveredPaths`. Os módulos de scan continuam usando seus paths hardcoded como fallback, mas também iteram sobre os descobertos.

**`ScanContext` — novo campo:**
```java
public record ScanContext(
    String targetUrl, String jwtToken, Set<String> enabledModules,
    String jwtToken2, Consumer<RequestRecord> requestLog,
    List<String> discoveredPaths  // ← novo; começa vazio, preenchido pelo crawler
) {}
```

**`CrawlerModule.java` — 4 estratégias:**

**Estratégia 1 — HTML Link Extraction:**
- GET na raiz `/` + `/sitemap.xml` + `/robots.txt`
- Parser HTML mínimo: extrai `href`, `src`, `action` de `<a>`, `<script>`, `<form>`, `<link>`
- Filtra apenas paths do mesmo domínio
- Normaliza: remove fragmentos (#), deduplication, remove static assets (.png, .css, .woff)

**Estratégia 2 — JavaScript Static Analysis:**
- Para cada `.js` encontrado no HTML: download + análise
- Regex para extrair paths de API:
  ```java
  Pattern.compile("(?:fetch|axios|XHR|request)\\s*\\(\\s*['\"]([/][a-zA-Z0-9/_-]+)['\"]");
  Pattern.compile("['\"]([/](?:api|v[0-9]|internal|admin)[a-zA-Z0-9/_-]+)['\"]");
  ```
- Extrai endpoints de React Router, Vue Router, Next.js `getServerSideProps`

**Estratégia 3 — Wordlist Probe (500 paths):**
- Wordlist embutida (`src/main/resources/paths-500.txt`) com paths mais comuns de APIs REST:
  - `/api`, `/api/v1`, `/api/v2`, `/health`, `/status`, `/admin`, `/actuator`
  - `/users`, `/user`, `/me`, `/profile`, `/account`, `/settings`, `/config`
  - `/graphql`, `/graphiql`, `/swagger`, `/openapi.json`, `/api-docs`
  - `/webhook`, `/webhooks`, `/callback`, `/notifications`
  - etc.
- Sonda cada path: status 200/201/301/302/401/403 → path existe; 404/410 → skip
- Rate: 10 req/s (não bombardeia)

**Estratégia 4 — OpenAPI/Swagger Auto-Discovery:**
- Sonda 8 paths de spec: `/swagger.json`, `/swagger/v1/swagger.json`, `/openapi.json`,
  `/api-docs`, `/v2/api-docs`, `/v3/api-docs`, `/api/swagger.json`, `/.well-known/openapi`
- Se encontrado: parseia JSON/YAML, extrai todos os paths com métodos e parâmetros
- Finding INFO: "Swagger/OpenAPI exposto sem autenticação"
- Adiciona paths ao `discoveredPaths` com metadados: método, parâmetros, se tem URL params

**Integração nos módulos existentes:**
- `SsrfModule`: iterar `discoveredPaths` além dos `PROBE_PATHS` fixos
- `IdorModule`: extrair ID real do usuário via `/api/me` → construir paths com UUID real
- `MassAssignmentModule`: adicionar `discoveredPaths` que respondem a PUT/PATCH
- `OpenRedirectModule`: usar paths descobertos com parâmetros de redirect
- `CorsModule`: testar paths descobertos além dos 4 fixos

**Configuração:**
- Checkbox "Crawler" na TUI (desmarcado por padrão — opt-in, pois adiciona requests)
- Opção de profundidade: shallow (só raiz) ou deep (segue links 1 nível)

**Harness:** 5 testes — HTML extraction encontra 3 paths; JS analysis encontra endpoint em arquivo .js mockado; wordlist probe identifica /admin como 403 (existe); Swagger parser extrai endpoints de spec mockada; integração end-to-end com SSRF usa paths descobertos.

---

### Sprint 19 — Rate Limiting + Cookie Auth + Scope
**Prioridade: Média-Alta | Necessário para bounty ético**

**Motivação:** sem essas três features, o uso em bounty real viola regras de programas.

**`ScanConfig.java` — novo record:**
```java
public record ScanConfig(
    int delayBetweenRequestsMs,   // default: 200ms
    int maxRequestsPerMinute,      // default: 60
    String sessionCookie,          // ex: "PHPSESSID=abc123; _csrf=xyz"
    Set<String> inScopeHosts,      // ex: {"api.target.com", "*.target.com"}
    boolean followRedirects        // default: false (safe)
) {}
```

**`ScanContext` — novo campo `ScanConfig config`:**
- Todos os módulos passam `ctx.config()` para `Http.send()`

**`Http.send()` — rate limiting:**
```java
// Throttle global compartilhado entre módulos
private static final RateLimiter LIMITER = RateLimiter.create(1.0); // tokens/s, configurável

public static <T> HttpResponse<T> send(ScanContext ctx, ...) {
    LIMITER.acquire(); // blocks até ter token disponível
    // ... send ...
}
```

**`Http.send()` — cookie injection:**
```java
// Se sessionCookie configurado, injeta em toda request
if (!ctx.config().sessionCookie().isBlank()) {
    builder.header("Cookie", ctx.config().sessionCookie());
}
```

**Scope validation:**
```java
// Antes de cada request — bloqueia URL fora do scope
if (!isInScope(req.uri().getHost(), ctx.config().inScopeHosts())) {
    log.accept("[!] SCOPE: bloqueado — " + req.uri().getHost() + " fora do escopo");
    return null;
}
```

**TUI — campos novos no modo TARGET (F3):**
- "Session Cookie" (campo de texto)
- "Delay entre requests (ms)" (número, default 200)
- "In-Scope Hosts" (campo multilinha, um por linha, aceita wildcard `*.`)

**Harness:** 3 testes — rate limiter mantém < maxReq/min; cookie injeta em request; scope bloqueia URL out-of-scope.

---

### Sprint 20 — MassAssignment FP Reduction + IDOR UUID
**Prioridade: Média | Qualidade de findings**

**Motivação:** um FP num relatório de bounty é rejeitado com nota negativa — prejudica o score do hunter.

**MassAssignment — confirmar persistência:**

Fluxo atual: POST/PUT/PATCH → se 200 e body reflete admin → CRITICAL, se 200 e não reflete → MEDIUM (FP).

Fluxo novo:
1. GET baseline `/api/me` (ou path do endpoint) — captura estado atual
2. POST/PUT/PATCH com payload admin
3. GET follow-up no mesmo endpoint
4. Se GET follow-up contém `admin: true` ou `role: admin` que não estava no baseline → CRITICAL (confirmado)
5. Se body de mutation refletiu mas GET não confirmou → MEDIUM (suspeito — informa para investigação manual)
6. Se 200 mas nada confirmado → skip (sem finding)

Isso elimina o MEDIUM falso positivo para "aceita JSON".

**IDOR — extração de UUID real:**

1. GET `/api/me` ou `/api/profile` ou `/api/user/me` com token1
2. Extrai campo `id`, `userId`, `_id`, `uuid` do JSON (regex ou JSON parser mínimo)
3. Constrói paths com o UUID real: `/api/users/{uuid-do-usuario-1}`
4. GET com token2 para o mesmo path
5. Se resposta similar → IDOR confirmado com evidência real

Para DELETE IDOR:
1. Extrai ID do usuário 2 via GET com token2
2. Tenta DELETE `/api/users/{uuid-usuario-2}` com token1

**IDOR — excluir respostas de erro idênticas:**
```java
// isSimilar() — adicionar: não contar responses de erro pequenas como similar
private boolean isSimilar(String a, String b) {
    if (a == null || b == null) return false;
    // Excluir responses pequenas de erro JSON (ex: {"error":"unauthorized"})
    if (a.length() < 50 && b.length() < 50) return false;
    // ... resto da lógica atual ...
}
```

**Harness:** 4 testes — MassAssign não gera MEDIUM sem confirmação de persistência; MassAssign CRITICAL confirmado via GET follow-up; IDOR extrai UUID de /api/me; IDOR similarity ignora pequenas responses de erro.

---

### Sprint 21 — Paralelismo por Módulo
**Prioridade: Baixa-Média | Qualidade de vida**

**Motivação:** 18 módulos sequenciais × rate limiting de 200ms/req = scan completo pode levar 15–20 minutos.

**Grupos de execução:**

```
Grupo A (sem dependências, rodam em paralelo):
  TLS, PQC, Headers, JWT, CORS, GraphQL, CRLF, HostHeader, Actuator, CachePoisoning, ReqSmuggling

Grupo B (dependem do Crawler — rodam após o Crawler):
  SSRF, OpenRedirect, MassAssignment

Grupo C (dependem de dois tokens — rodam em paralelo após Grupo A):
  IDOR, OAuth
```

**`ScanRunner` — pool de threads:**
```java
// Configurável via ScanConfig.parallelism (default: 4)
private final ExecutorService executor = Executors.newFixedThreadPool(4, r -> {
    Thread t = new Thread(r, "anarcry-scan-" + counter.incrementAndGet());
    t.setDaemon(true);
    return t;
});
```

**StatusBar** — mostrar módulos em andamento simultaneamente:
`[Scanning: TLS Headers JWT CORS | Done: 2/18 | Findings: 3]`

**Harness:** 2 testes — grupos A e B não rodam antes do Crawler; tempo total com 4 threads < tempo com 1 thread para mesmo conjunto de módulos.

---

## 4. Resumo do Delta

### Tabela de features × estado

| Feature | Hoje | Sprint 16 | Sprint 17 | Sprint 18 | Sprint 19 | Sprint 20 | Sprint 21 |
|---------|------|-----------|-----------|-----------|-----------|-----------|-----------|
| CVSS auto | ❌ | ✅ | | | | | |
| CWE mapping | ❌ | ✅ | | | | | |
| Deduplicação | ❌ | ✅ | | | | | |
| Export H1 | ❌ | | ✅ | | | | |
| Export Bugcrowd | ❌ | | ✅ | | | | |
| Crawler HTML/JS | ❌ | | | ✅ | | | |
| Swagger discovery | ❌ | | | ✅ | | | |
| Rate limiting | ❌ | | | | ✅ | | |
| Cookie auth | ❌ | | | | ✅ | | |
| Scope management | ❌ | | | | ✅ | | |
| MassAssign FP fix | ❌ | | | | | ✅ | |
| IDOR UUID support | ⚠️ | | | | | ✅ | |
| Paralelismo | ❌ | | | | | | ✅ |

### Harness — projeção de crescimento

| Sprint | Testes novos | Total acumulado |
|--------|-------------|-----------------|
| Atual | — | **55** |
| Sprint 16 | 3 (CVSS, dedup, CWE) | 58 |
| Sprint 17 | 2 (H1 export, Bugcrowd) | 60 |
| Sprint 18 | 5 (crawler, swagger, integração) | 65 |
| Sprint 19 | 3 (rate limit, cookie, scope) | 68 |
| Sprint 20 | 4 (MassAssign, IDOR) | 72 |
| Sprint 21 | 2 (parallelismo) | **74** |

---

## 5. O que NÃO entra no escopo

- **SAML:** baixíssima prevalência em bounty moderno; complexidade alta de XML signing
- **WebSocket:** casos de uso raros; add como módulo experimental em v3 se demanda aparecer
- **Path traversal directory listing:** coberto indiretamente pelo Crawler + XXE; módulo isolado tem ROI baixo
- **Subdomain takeover:** requer DNS queries externas e infrastructure (não é só HTTP)
- **Burp Suite integration / extension:** produto diferente; fora do posicionamento da ferramenta

---

## 6. Dependências entre Sprints

```
Sprint 16 (CVSS + CWE)
    └── Sprint 17 (H1/Bugcrowd export) — usa cweId e cvssScore do Finding

Sprint 18 (Crawler)
    └── Sprint 19 (Rate Limit + Cookie) — Crawler precisa de rate limiting
    └── Sprint 20 (IDOR UUID) — IDOR extrai UUID via /api/me com cookie suporte

Sprint 16 → Sprint 17 → pronto para submissão manual em H1/Bugcrowd
Sprint 18 + Sprint 19 → pronto para scan em alvos reais sem violar regras
Sprint 16 + 17 + 18 + 19 + 20 → bounty-ready completo
Sprint 21 → nice-to-have de performance
```

---

## 7. Notas Técnicas por Sprint

### Sprint 16 — CVSS v3.1 Calculator

A fórmula CVSS v3.1 (FIRST) sem dependências externas:

```java
// ISS = 1 - [(1-C) * (1-I) * (1-A)]
// ESS = Scope-Changed: 7.52*[ISS-0.029] - 3.25*[ISS-0.02]^15
//       Scope-Unchanged: 6.42 * ISS
// Base Score arredondado para 1 decimal
```

Vetores: AV (N/A/L/P), AC (L/H), PR (N/L/H), UI (N/R), S (U/C), C/I/A (N/L/H).
Apenas base score — temporal e environmental ficam para v2 se demanda aparecer.

### Sprint 18 — HTML Parser sem dependências

Não usar JSoup (adiciona 1MB ao jar). Parser regex mínimo:

```java
Pattern.compile("(?:href|src|action)\\s*=\\s*['\"]([^'\"#?]+)['\"]")
```

Filtrar: só paths do mesmo host, ignorar `javascript:`, `mailto:`, `data:`, `.png`, `.css`, `.woff`.

Profundidade 1: só parseia a raiz + pages linkadas, não spider recursivo (evita crawl infinito).

### Sprint 17 — VRT Mapping para Bugcrowd

Bugcrowd Vulnerability Rating Taxonomy (VRT) é uma lista pública em JSON no GitHub de Bugcrowd. O mapeamento AnarCry→VRT:

| AnarCry | VRT |
|---------|-----|
| SSRF | `server_security_misconfiguration.server_side_request_forgery` |
| CORS | `broken_authentication_and_session_management.authentication_bypass.other` |
| IDOR | `broken_access_control.insecure_direct_object_references` |
| JWT alg:none | `broken_authentication_and_session_management.authentication_bypass.json_web_token_vulnerability` |
| XSS via CRLF | `cross_site_scripting_xss.reflected_xss` |
| ReqSmuggling | `server_security_misconfiguration.http_request_smuggling` |

---

*Atualizar este arquivo ao completar cada sprint.*
