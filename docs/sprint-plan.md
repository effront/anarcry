# AnarCry — Plano de Sprints de Segurança
**Gerado em:** 2026-10-22  
**Base:** Análise side-by-side dos módulos existentes vs. SecurityTesting-master · KingOfBugBountyTips · HackerOne top reports

---

## Sumário executivo

AnarCry tem **13 módulos funcionais** com cobertura boa para detecção básica. Os maiores gaps estão nos vetores de bypass que os scanners automáticos geralmente ignoram (encoding SSRF, CORS regex, redirect tricks) e em técnicas de alta frequência em H1 que ainda não têm módulo (Host Header Injection, Spring Actuator, Mass Assignment, HTTP Request Smuggling, Web Cache Poisoning).

**ROI de implementação (effort vs. H1 upvotes/bounty):**

| Sprint | Módulo | Tipo | Effort | Impacto | Melhor H1 ref |
|--------|--------|------|--------|---------|---------------|
| 18 | SSRF++ (bypasses + webhook) | Melhoria | S | CRITICAL | #897244 (112↑), #508459 |
| 19 | Host Header Injection | Novo | S | MEDIUM-HIGH | #2696271 (75↑) |
| 20 | Spring Actuator Exposure | Novo | S | CRITICAL | #838635 ($12500, 234↑) |
| 21 | Mass Assignment | Novo | S | HIGH | comum, sem número único |
| 22 | CORS regex bypasses | Melhoria | S | HIGH | estudos de CORS regex |
| 23 | SSTI RCE payloads por engine | Melhoria | M | CRITICAL | estudos de SSTI RCE |
| 24 | IDOR GraphQL + DELETE | Melhoria | M | HIGH | #2122671 (394↑), #2207248 ($5000) |
| 25 | Web Cache Poisoning | Novo | M | HIGH | #622122 ($9700, 851↑) |
| 26 | HTTP Request Smuggling | Novo | L | CRITICAL | #737140 (868↑, ATO Slack) |
| 27 | OpenRedirect bypasses | Melhoria | S | HIGH | user-info, backslash |
| 28 | CRLF header injection | Melhoria | S | HIGH | injeção via headers HTTP |

---

## Módulos existentes — análise lado a lado

### SSRF (`SsrfModule.java`)

**Estado atual:**
- 7 probes diretas: `127.0.0.1`, `localhost`, `0.0.0.0`, AWS/Azure/GCP metadata
- 16 URL_PARAMS: url, uri, link, src, source, fetch, path, proxy, redirect, resource, dest, target, page, html, load, document
- 8 PROBE_PATHS: `/`, `/api/`, `/api/v1/`, `/api/fetch`, `/api/proxy`, `/api/url`, `/fetch`, `/proxy`
- Detecção via METADATA_PATTERN regex (ami-id, secretAccessKey, etc.)
- Client: `noRedirect()` — não segue redirects

**Gaps vs. backlog:**
| Gap | Técnica | Fonte H1 |
|-----|---------|----------|
| IP encoding — sem bypass | decimal `2130706433`, hex `0x7f000001`, octal `017700000001`, IPv6 `[::1]`, short `127.1` | #3634400 (NAT64) |
| Redirect bypass — não detecta | filtros bloqueiam IP direto mas seguem 301→169.254.x.x | insight #8 do backlog |
| Webhook params — não testados | `webhook_url`, `callback_url`, `ping_url` (SSRF em 50%+ das apps) | #508459 (Omise) |
| SVG upload — não cobre | SVG com entidade DOCTYPE como imagem | #897244 (Zivver, 112↑) |
| Paths extras — poucos | `/webhook`, `/notification`, `/api/webhook` | frequência H1 |

**Proposta Sprint 18 — diff mínimo:**
```java
// Adicionar em SSRF_PROBES (IP encoding bypasses):
new SsrfProbe("http://2130706433/",          "localhost-decimal",  Severity.HIGH),
new SsrfProbe("http://0x7f000001/",          "localhost-hex",      Severity.HIGH),
new SsrfProbe("http://[::1]/",              "localhost-IPv6",     Severity.HIGH),
new SsrfProbe("http://[::ffff:127.0.0.1]/","localhost-IPv6map",  Severity.HIGH),
new SsrfProbe("http://127.1/",             "localhost-short",    Severity.HIGH),

// Adicionar em URL_PARAMS:
"webhook_url", "callback_url", "ping_url", "imageUrl", "avatarUrl", "import_url"

// Adicionar em PROBE_PATHS:
"/webhook", "/notification", "/api/webhook", "/api/v1/webhook"

// Adicionar cliente redirect-following para testar redirect bypass:
// HttpClientFactory.follow() — permite 1 redirect, registra se chegar em metadata
```

---

### CORS (`CorsModule.java`)

**Estado atual:**
- 3 origins: `evil.com` (reflection), `null` (sandbox), `{host}.evil.com` (prefix bypass)
- 4 PROBE_PATHS: `/`, `/api/`, `/api/v1/`, `/api/me`
- Detecção: ACAO=origin + ACAC=true → CRITICAL; ACAO=* → HIGH; ACAO=null → MEDIUM

**Gaps vs. backlog:**
| Gap | Técnica | Bypass que detecta |
|-----|---------|-------------------|
| Suffix bypass — não testado | `evil.trusted.com` | bypassa `endsWith("trusted.com")` |
| StartsWith bypass — não testado | `trusted.com.evil.com` | bypassa `startsWith("trusted.com")` |
| Backtick bypass — não testado | `trusted.com\`60.evil.com` (URL-encoded) | Chrome-specific |
| Endpoints autenticados — não testados | `/api/me`, `/api/orders` com JWT | dados sensíveis atrás de auth |

**Proposta Sprint 22:**
```java
// Adicionar em origins (no CorsModule.scan()):
"https://evil." + ctx.host(),                    // suffix bypass
"https://" + ctx.host() + ".evil.com",           // (já existe)
"https://" + ctx.host().replace(".", "%60.evil.com/"), // backtick approx

// Adicionar probe autenticada — enviar JWT se disponível:
if (ctx.jwtToken() != null && !ctx.jwtToken().isBlank())
    builder.header("Authorization", "Bearer " + ctx.jwtToken());

// Mais paths:
"/api/v2/", "/api/profile", "/api/orders", "/api/admin"
```

---

### SSTI (`SstiModule.java`)

**Estado atual:**
- 6 probes: `${7*7}`, `{{7*7}}`, `#{7*7}`, `${{7*7}}`, `<%= 7*7 %>`, `{{7*'7'}}`
- Detecta `"49"` no response vs baseline
- Identifica engine (FreeMarker, Jinja2, Twig, Thymeleaf, ERB)
- Sem payloads RCE por engine

**Gaps vs. backlog:**
| Gap | Engine | Payload RCE |
|-----|--------|-------------|
| Jinja2 RCE | Jinja2 | `{{''.__class__.__mro__[1].__subclasses__()}}` |
| FreeMarker RCE | FreeMarker | `<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}` |
| Twig RCE | Twig | `{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}` |
| Smarty RCE | Smarty | `{php}echo shell_exec('id');{/php}` |
| Polymorphic | Todos | `}}{{7*7}}[[7*7]]${7*7}<%= 7*7 %>` (detecção cruzada) |

**Proposta Sprint 23:**
- Após identificar engine via math eval (existente), enviar payload RCE específico
- Detectar presença de string `uid=` ou `root:` na resposta → confirma RCE
- Reportar como CRITICAL com curl e payload de prova
- Adicionar payload polimórfico como fallback quando engine não é identificada

---

### CORS vs. backlog (completo)

**Estado atual:** 3 origins, 4 paths. Detecção passiva sem JWT.

**Gaps:**
- Faltam 2 bypasses de regex comuns: suffix (`evil.trusted.com`) e startsWith (`trusted.com.evil.com`)
- Backtick bypass Chrome-specific
- Não testa endpoints autenticados com JWT

---

### XXE (`XxeModule.java`)

**Estado atual:**
- 12 endpoints testados: `/api/`, `/upload`, `/import`, `/parse`, `/soap`, `/ws`, `/service`, `/xml`, `/feed`, `/rss` etc.
- 3 payloads: file-read (`file:///etc/hostname`), SSRF-via-XXE (`http://127.0.0.1/`), Billion Laughs lite
- Probe inicial: envia XML benigno para verificar se servidor aceita XML
- Detecção: FILE_CONTENT_PATTERN + SSRF_PATTERN

**Gaps vs. backlog:**
| Gap | Técnica | Fonte H1 |
|-----|---------|----------|
| SVG upload XXE | POST com Content-Type: image/svg+xml + DOCTYPE entidade | #897244 (Zivver, 112↑) |
| DOCX/XLSX upload | ZIP com word/document.xml com entidade externa | #334488 ($2000) |
| OOB via DTD externo | Quando output direto está bloqueado — registrar DNS callback | técnica avançada |
| SAML assertion | XML no fluxo SAML — entidade no `<samlp:AuthnRequest>` | #106865 |

**Proposta (Sprint futuro — complexidade média):**
- Upload SVG: detectar endpoints com `multipart/form-data` e `Content-Type: image/svg+xml`, enviar SVG com `<!ENTITY xxe SYSTEM "file:///etc/hostname">`
- Requer suporte a multipart no `Http.java`

---

### IDOR (`IdorModule.java`)

**Estado atual:**
- 16 ID_PATHS: `/api/user/1`, `/api/users/1`, `/api/account/1`, etc.
- Requer `jwtToken2` — skip se não informado
- Comparação: token1 vs token2 na mesma URL, detecta body similar (>90% comprimento + prefixo igual)
- Pausa no primeiro IDOR encontrado

**Gaps vs. backlog:**
| Gap | Técnica | Fonte H1 |
|-----|---------|----------|
| GraphQL mutations | POST para `/graphql` com mutation sem ownership check | #2122671 (394↑), #984965 (TikTok, 84↑) |
| DELETE sem auth | DELETE em `/api/user/2` com token de outro usuário — espera 403, aceita 200/204 | #380410 (Pornhub, $1500) |
| Download por ID numérico | GET `/api/document/2`, `/api/invoice/2` com token alheio | #1626508 |
| Price manipulation | PUT `/api/order/1` com `{"price": 0.01}` — verificar se refletido | #1403176 (Acronis, 146↑) |

**Proposta Sprint 24:**
```java
// Adicionar probe DELETE:
private Finding probeDelete(ScanContext ctx, HttpClient hc, String base, String path, String token1, String token2) {
    // DELETE {path com ID de token1} usando token2
    // Espera: 403/404. Se 200/204 → IDOR via DELETE
}

// Adicionar probe GraphQL:
// POST /graphql com mutation { deleteUser(id: 2) } usando token1
// Se 200 com "success" → GraphQL mutation IDOR
```

---

### OpenRedirect (`OpenRedirectModule.java`)

**Estado atual:**
- 5 PROBE_PATHS: `""`, `/login`, `/logout`, `/redirect`, `/go`
- 9 REDIRECT_PARAMS: url, next, redirect, returnUrl, redirect_uri, return, to, goto, dest
- 3 PAYLOADS: `https://evil.anarcry-probe.com`, `//evil.anarcry-probe.com`, `/%2f%2fevil.anarcry-probe.com`
- Detecção: status 301/302/307/308 + `Location` contém `EVIL_HOST`

**Gaps vs. backlog:**
| Gap | Técnica | Bypass que detecta |
|-----|---------|-------------------|
| User-info parsing | `https://target.com@evil.com` | browser vai para evil.com |
| Backslash | `\evil.com` normalizado para `/evil.com` em alguns parsers | IIS/nginx specific |
| URL encoded scheme | `https%3A%2F%2Fevil.com` | validações que fazem regex no string raw |
| Mais paths | `/auth/callback`, `/oauth/authorize`, `/sso/return` | fluxos OAuth/SSO |

**Proposta Sprint 27 (pequena):**
```java
// Adicionar payloads:
"https://target.com@" + EVIL_HOST,    // user-info
"\\" + EVIL_HOST,                      // backslash
"https%3A%2F%2F" + EVIL_HOST,         // encoded scheme

// Adicionar paths:
"/auth/callback", "/oauth/authorize", "/oauth/return", "/sso"
```

---

### CRLF (`CrlfModule.java`)

**Estado atual:**
- 15 payloads CRLF no path (`/%0aSet-Cookie:crlf=injection`, variantes com `%0d%0a`, `%250a`, etc.)
- Detecta `Set-Cookie: crlf=injection` no response headers

**Gaps vs. backlog:**
| Gap | Técnica |
|-----|---------|
| Injeção via headers | `User-Agent: test%0d%0aInjected: value`, `Referer: ...` |
| Cookie value injection | `value%0d%0aSet-Cookie: malicious=true` em valor de cookie |
| Response Splitting → Cache Poisoning | injetar `Content-Type: text/html` + XSS no body |

**Proposta Sprint 28:**
- Adicionar probes com CRLF nos cabeçalhos da request (User-Agent, Referer, Accept-Language) não apenas no path
- Detectar header injetado nos cabeçalhos de resposta

---

### JWT (`JwtModule.java`)

**Estado atual (bem coberto):**
- Análise local: alg:none, HS256 brute-force (22 senhas), exp ausente/expirado, kid passivo, RS256 info, jku passivo
- Probes ativas: alg:none network probe, kid injection (../../dev/null, SQLi), null signature (CVE-2020-28042), signature disclosure (CVE-2019-7644), RS256→HS256 confusion, JWK injection (RS256 only)

**Gaps menores:**
| Gap | Técnica |
|-----|---------|
| jku ativo — não faz request HTTP | JkuHeaderAnalyzer é passivo — reporta mas não testa se server busca JWK externo |
| iss/aud manipulation | cross-tenant com claim não validado |
| x5u tampering | análogo ao jku, para X.509 — não coberto |

**Proposta Sprint 25 (JWT, baixa prioridade — já bem coberto):**
- Adicionar `JwkInjectionProbe` que serve JWK localmente via simple HTTP server (complexo, requer porta disponível)
- Ou reportar jku como HIGH se header está presente, não apenas INFO

---

## Novos módulos a criar

### Sprint 19 — Host Header Injection (MEDIUM-HIGH) — EFFORT: S

**Por quê:** Cobre dois cenários de alto impacto: SSRF via Host header em infra interna, e password reset poisoning enviando link com domínio do atacante.

**Implementação:**
```java
public class HostHeaderModule implements Scanner {
    
    private static final List<String> INJECT_HOSTS = List.of(
        "evil.anarcry-probe.com",
        "127.0.0.1",
        "169.254.169.254"
    );
    
    // Cenário 1: password reset poisoning
    // POST /forgot-password com Host: evil.com
    // Detectar se body/Location reflete o Host injetado
    
    // Cenário 2: X-Forwarded-Host bypass
    // GET / com X-Forwarded-Host: evil.com
    // Detectar reflexo no body ou em redirect Location
    
    // Cenário 3: X-Host, X-Original-Host, X-Rewrite-URL
}
```

**Detecção:** body ou Location header contém o host injetado (`evil.anarcry-probe.com`)  
**Referências H1:** #2696271 (IBM, 75↑), #2188240 (DoD)

---

### Sprint 20 — Spring Actuator Exposure (CRITICAL) — EFFORT: S

**Por quê:** Um GET request por endpoint, potencial de $12500 de bounty, extremamente comum em stacks Java/Spring.

```java
public class SpringActuatorModule implements Scanner {
    
    private static final List<String> ACTUATOR_PATHS = List.of(
        "/actuator",
        "/actuator/env",           // credenciais de ambiente
        "/actuator/heapdump",      // heap dump com passwords
        "/actuator/mappings",      // mapa de endpoints
        "/actuator/beans",         // beans expostos
        "/actuator/health",
        "/actuator/info",
        "/actuator/loggers",
        "/actuator/threaddump",
        "/actuator/metrics",
        // Spring Boot 1.x — sem prefixo /actuator/
        "/env", "/dump", "/trace", "/mappings", "/beans", "/health"
    );
    
    // Detecção:
    // /actuator → 200 com JSON {"_links": ...} → INFO: actuator habilitado
    // /actuator/env → 200 com JSON → CRITICAL: credenciais expostas
    // /actuator/heapdump → 200 com binary content → CRITICAL: dump disponível
}
```

**Referências H1:** #838635 (LINE, $12500, 234↑)

---

### Sprint 21 — Mass Assignment (HIGH) — EFFORT: S

**Por quê:** Um POST/PUT com payload de campos extras, detectável passivamente na resposta.

```java
public class MassAssignmentModule implements Scanner {
    
    private static final String PROBE_PAYLOAD = 
        "{\"admin\":true,\"role\":\"admin\",\"isAdmin\":true," +
        "\"balance\":99999,\"verified\":true,\"subscription_plan\":\"enterprise\"," +
        "\"is_staff\":true,\"permissions\":[\"admin\"]}";
    
    private static final List<String> TARGET_PATHS = List.of(
        "/api/user", "/api/users", "/api/profile", "/api/me",
        "/api/account", "/api/register", "/api/v1/user",
        "/api/v1/users", "/api/v2/user"
    );
    
    // Envia PUT/PATCH com payload e verifica:
    // 1. Body da resposta reflete admin:true / role:admin
    // 2. GET no mesmo endpoint mostra campo alterado
    // 3. HTTP 200 com campo injetado → CRITICAL
}
```

---

### Sprint 25 — Web Cache Poisoning (HIGH) — EFFORT: M

**Por quê:** Não exige bug no código-fonte — só CDN mal-configurado. Muito comum em apps com Cloudflare, Varnish ou Nginx.

```java
public class CachePoisoningModule implements Scanner {
    
    // Headers "unkeyed" que CDNs ignoram na cache key mas apps usam:
    private static final List<String> UNKEYED_HEADERS = List.of(
        "X-Forwarded-Host",
        "X-Forwarded-Scheme",
        "X-Original-URL",
        "X-Rewrite-URL",
        "X-Forwarded-Prefix"
    );
    
    // Passo 1: enviar request com header unkeyed = evil.anarcry-probe.com
    // Passo 2: verificar se resposta foi cacheada (X-Cache: HIT, Age: N, CF-Cache-Status: HIT)
    // Passo 3: verificar se header injetado é refletido no body/Location
    // → Se refletido + cacheado → CRITICAL (cache pode ser envenenado para todos os usuários)
    
    // Detecção de cache ativo:
    // "X-Cache: HIT", "CF-Cache-Status: HIT", "Age: N > 0", "X-Varnish" header presente
}
```

**Referências H1:** #622122 (PayPal, $9700, 851↑), #1096609 (Shopify, $2900), #1424094 (Glassdoor stored XSS)

---

### Sprint 26 — HTTP Request Smuggling (CRITICAL) — EFFORT: L

**Por quê:** Técnica de altíssimo impacto (ATO, cache poisoning, req hijacking). Maior volume de upvotes em H1. Mais complexa de implementar corretamente.

```java
public class RequestSmugglingModule implements Scanner {
    
    // CL.TE probe — frontend usa Content-Length, backend usa Transfer-Encoding
    // Enviar via raw socket (não HTTP client — ele normaliza os headers)
    private static final String CLTE_PROBE =
        "POST / HTTP/1.1\r\n" +
        "Host: {host}\r\n" +
        "Content-Type: application/x-www-form-urlencoded\r\n" +
        "Content-Length: 6\r\n" +
        "Transfer-Encoding: chunked\r\n\r\n" +
        "0\r\n\r\n" +
        "X";
    
    // TE.CL probe — frontend usa Transfer-Encoding, backend usa Content-Length
    
    // TE.TE obfuscation — ambos entendem TE mas um é confundido:
    // "Transfer-Encoding: xchunked"
    // "Transfer-Encoding : chunked"
    // "Transfer-Encoding: chunked, chunked"
    
    // NOTA: Java HttpClient normaliza e não permite enviar esses requests
    // Requer: java.net.Socket raw com TLS manual (TlsUtil.sslContext)
}
```

**Referências H1:** #737140 (Slack, 868↑, ATO), #740037 (LY, 564↑), #771666 (Zomato, 559↑), #1211724 (Basecamp, $7500)

---

## Roadmap consolidado

```
Sprint 18  ████ SSRF++        — add IP encoding + webhook params [1 semana]
Sprint 19  ████ HostHeader    — novo módulo, 1 file             [3 dias]
Sprint 20  ████ Actuator      — novo módulo, 1 file             [3 dias]
Sprint 21  ████ MassAssign    — novo módulo, 1 file             [3 dias]
Sprint 22  ██░░ CORS++        — +2 bypass origins + JWT probe   [2 dias]
Sprint 23  ███░ SSTI RCE      — payloads por engine após detecção [3 dias]
Sprint 24  ███░ IDOR++        — DELETE + GraphQL mutations       [4 dias]
Sprint 25  ████ CachePoisoning— novo módulo, unkeyed headers    [1 semana]
Sprint 26  ████ Smuggling     — novo módulo, raw socket         [2 semanas]
Sprint 27  ██░░ OpenRedirect++— +3 bypasses + OAuth paths       [2 dias]
Sprint 28  ██░░ CRLF++        — headers HTTP além de path       [2 dias]
```

**Prioridade recomendada (impacto/esforço):**
1. Sprint 18 — SSRF++ (patch mínimo, alto retorno)
2. Sprint 20 — Spring Actuator (trivial de implementar, alto bounty)
3. Sprint 19 — Host Header (novo módulo simples)
4. Sprint 21 — Mass Assignment (novo módulo simples)
5. Sprint 22 — CORS++ (patch mínimo no módulo existente)
6. Sprint 26 — HTTP Request Smuggling (mais complexo, máximo impacto)
