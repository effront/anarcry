---
id: waf_evasion
title: "WAF Detection and Evasion"
module: "waf"
severity: "INFO"
cwe_id: "CWE-693"
cwe_title: "Protection Mechanism Failure"
cvss_vector: "AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N"
vrt_id: "server_security_misconfiguration.waf_bypass"
---

## Summary
Web Application Firewalls (WAFs) interceptam requisicoes HTTP entre o cliente e o servidor, bloqueando payloads maliciosos com base em assinaturas, heuristicas e analise comportamental. Para o scanner, um WAF efetivo impede a deteccao de vulnerabilidades reais -- os probes sao bloqueados antes de chegar a aplicacao. Evasao de WAF nao e ataque: e a tecnica necessaria para testar a seguranca real da aplicacao por tras da camada de protecao.

## Description
WAFs operam em tres modelos:

- **Cloud-based (reverse proxy):** Cloudflare, Akamai, AWS WAF, Sucuri, Imperva Cloud. O trafego passa pelo WAF antes de chegar ao origin. Bypass frequentemente envolve descobrir o IP de origem.
- **Appliance/network:** F5 BIG-IP ASM, Imperva SecureSphere, Barracuda. Inline na rede, mais dificil de contornar sem acesso direto.
- **Application-level:** ModSecurity (CRS), OWASP rules. Integrado ao web server (Apache/Nginx), regras configuradas localmente.

Mecanismos de deteccao:
- **Assinatura (signature-based):** regex contra payloads conhecidos (`<script>`, `UNION SELECT`, `../etc/passwd`). Fragil contra variantes.
- **Anomalia (anomaly scoring):** pontua parametros por desvio do normal (tamanho, charset, frequencia). Paranoia Level no CRS controla sensibilidade.
- **Comportamental:** rate limiting, fingerprinting de bots, JS challenges (Cloudflare Managed Challenge, Vercel Security Checkpoint).

O problema central: WAFs protegem contra ataques *conhecidos* na forma *esperada*. Payloads encodados, fragmentados ou semanticamente equivalentes passam porque o WAF nao interpreta o input da mesma forma que a aplicacao.

## Impact
- **Falso senso de seguranca:** vulnerabilidade real existe mas o scan nao a detecta porque o WAF bloqueia o probe.
- **Bypass + exploit = impacto total:** WAF evasion + XSS/SQLi/SSRF = a vulnerabilidade e exploravel como se o WAF nao existisse.
- **Degradacao de cobertura:** sem evasao, o scanner reporta zero findings em targets protegidos -- o relatorio nao reflete o risco real.
- **Rate limiting e bans:** probes agressivos podem triggerar bloqueio de IP, impedindo o scan inteiro.

## Detection Strategies
O AnarCry detecta WAFs via `WafEvasion.java`:

### Headers HTTP
- `Server: cloudflare` / `Server: AkamaiGHost` / `Server: Sucuri/Cloudproxy`
- Headers especificos: `cf-ray`, `x-sucuri-id`, `x-akamai-transformed`, `x-cdn`
- Pattern regex: `cloudflare|akamai|incapsula|sucuri|ddos-guard|awselb|imperva|f5|barracuda`

### Status Codes
- **403 Forbidden** + body com "blocked", "access denied", "web application firewall"
- **406 Not Acceptable** -- payload rejeitado por politica
- **429 Too Many Requests** -- rate limiting ativo

### JS Challenges
- **Cloudflare Managed Challenge:** `cf-mitigated: challenge` header, body com `cf_chl_opt` ou `cf-challenge-`
- **Vercel Security Checkpoint:** `x-vercel-mitigated: challenge` header, body com "Vercel Security Checkpoint"
- **Cloudflare Bot Fight Mode:** status 403/503, pagina de verificacao com timer

### Body Patterns
```text
blocked|access denied|attention required|request blocked|
web application firewall|security policy|not acceptable
```

## Evasion Techniques
Estrategias implementadas no AnarCry (`WafEvasion.Strategy`):

### 1. Double Encoding (DOUBLE_ENCODE)
WAFs decodificam URL uma vez; a aplicacao decodifica novamente:
```text
# Original
<script>alert(1)</script>

# URL encoded (WAF decodifica e bloqueia)
%3Cscript%3Ealert(1)%3C/script%3E

# Double encoded (WAF decodifica para %3C, aplicacao decodifica para <)
%253Cscript%253Ealert(1)%253C%252Fscript%253E
```

### 2. Case Mutation (CASE_MUTATION)
Regras case-sensitive nao reconhecem variantes:
```text
<ScRiPt>alert(1)</sCrIpT>
<iMg SrC=x OnErRoR=alert(1)>
sElEcT * fRoM users
```
Browsers e SQL parsers sao case-insensitive para tags/keywords.

### 3. Unicode Fullwidth (UNICODE_NORMALIZE)
Caracteres ASCII mapeados para fullwidth Unicode (U+FF00 range):
```text
# ASCII < = U+003C
# Fullwidth ＜ = U+FF1C

＜script＞alert(1)＜/script＞
```
Funciona quando a aplicacao normaliza Unicode antes de processar, mas o WAF nao.

### 4. EBCDIC Charset (CHARSET_EBCDIC)
POST com `Content-Type: application/x-www-form-urlencoded; charset=ibm500`. O WAF espera ASCII/UTF-8, a aplicacao decodifica EBCDIC:
```java
// WafEvasion.java
String formBody = param + "=" + payload;
byte[] encoded = formBody.getBytes(Charset.forName("ibm500"));
```
Limitado a POST -- incompativel com payloads GET inline.

### 5. HTTP Parameter Pollution (HPP)
Duplicar parametros -- o WAF inspeciona o primeiro, a aplicacao usa o ultimo (ou concatena):
```text
# WAF ve q=safe, aplicacao ve q=safe,<script>alert(1)</script>
?q=safe&q=<script>alert(1)</script>
```
Comportamento depende do backend: PHP usa ultimo, ASP.NET concatena, Java depende do framework.

### Tecnicas Adicionais (Bug Bounty Bootcamp)

**fromCharCode() -- payload sem aspas:**
```javascript
// Evita filtros de aspas/strings
String.fromCharCode(60,115,99,114,105,112,116,62,97,108,101,114,116,40,49,41)
```

**Filter logic errors -- tags aninhadas:**
```html
<!-- Filtro remove <script> uma vez, resultado e tag valida -->
<scrip<script>t>alert(1)</scrip</script>t>
```

**Content-Type switching:**
```text
# WAF inspeciona application/x-www-form-urlencoded
# Trocar para multipart/form-data ou application/json pode bypass
Content-Type: multipart/form-data; boundary=----X
```

**Chunked Transfer Encoding:**
```text
Transfer-Encoding: chunked

3
<sc
4
ript
1
>
```
WAF inspeciona chunks individuais, aplicacao reassembla.

**Null bytes e comentarios SQL:**
```text
# Null byte antes do payload
%00<script>alert(1)</script>

# Comentarios SQL quebrando keywords
UN/**/ION SEL/**/ECT
```

## Cloudflare -- Bypass Especifico
Cloudflare e o WAF mais encontrado e o principal desafio do AnarCry:

### Managed Challenges
- **O que e:** pagina de verificacao que requer JavaScript execution (5-second challenge, CAPTCHA, ou verificacao silenciosa).
- **Deteccao:** header `cf-mitigated: challenge`, status 403/503, body com `cf_chl_opt`.
- **Impacto no scan:** scanner sem headless browser nao passa. Mesmo com browser, Cloudflare fingerprinta automacao (Playwright/Puppeteer).

### Bot Fight Mode
- Bloqueia trafego automatizado com base em fingerprint TLS (JA3/JA4), headers HTTP e behavioral patterns.
- Scanner Java com `HttpClient` tem fingerprint distinto de browsers reais.
- **Mitigacao:** impersonator-okhttp (dependencia do AnarCry) para TLS fingerprint spoofing.

### Descoberta do IP de Origem
Metodo mais efetivo -- acessar o servidor diretamente, sem passar pelo Cloudflare:
- **Historico DNS:** SecurityTrails, ViewDNS.info, DNS Dumpster -- buscar registros A/AAAA anteriores a migracao para Cloudflare.
- **Subdominios:** `mail.alvo.com`, `ftp.alvo.com`, `staging.alvo.com` podem apontar para o origin direto.
- **Headers de email:** enviar email ao alvo (formulario de contato) e inspecionar headers `Received:` para IPs do mail server -- frequentemente na mesma infra.
- **Certificados SSL:** pesquisar em Censys/Shodan por certificados do dominio em IPs nao-Cloudflare.
- **IPv6:** dominio pode ter AAAA record apontando para o origin enquanto A record usa Cloudflare.

### Rate Limiting
- Cloudflare rate limiting e por IP/sessao.
- Rotacao de IP via proxies ou delays entre requests reduz deteccao.
- Scanner deve respeitar `Retry-After` header e implementar backoff exponencial.

### WAF Rules (OWASP CRS)
Cloudflare WAF usa regras baseadas em OWASP CRS com customizacoes:
- Paranoia Level varia por plano (Free/Pro/Business/Enterprise).
- Regras managed sao atualizadas frequentemente -- evasao que funciona hoje pode ser bloqueada amanha.
- **Dica:** testar evasao contra versao atual do CRS e monitorar changelogs.

## Hunting Methodology
Processo para testar cobertura do WAF:

1. **Baseline:** enviar requisicao benigna e registrar status code, headers e body de referencia.
2. **Identificar WAF:** verificar headers (`Server`, `cf-ray`, `x-sucuri-id`), status codes e body patterns usando `WafEvasion.detectWafProduct()`.
3. **Confirmar bloqueio:** enviar payload obvio (`<script>alert(1)</script>` ou `' OR 1=1--`). Se bloqueado (403/406/429 + body patterns), WAF esta ativo.
4. **Probe de estrategias:** iterar `WafEvasion.PROBE_ORDER` (double-encode, case mutation, unicode, EBCDIC, HPP). Para cada estrategia, verificar se o request passa sem bloqueio.
5. **Validar efetividade:** um bypass que nao e bloqueado nao e necessariamente util -- a aplicacao precisa interpretar o payload transformado. Confirmar que o payload encodado/mutado ainda triggera a vulnerabilidade.
6. **Testar por categoria:** WAFs podem ter regras diferentes para XSS, SQLi, LFI. Uma evasao efetiva para XSS pode nao funcionar para SQLi.
7. **Monitorar JS challenges:** se o WAF usa Managed Challenge, testar com e sem headless browser. Registrar se `isJsChallenge()` retorna true.
8. **Origin discovery:** em paralelo, tentar descobrir o IP de origem para bypass completo do WAF (ver secao Cloudflare).

## False Negative Indicators
Sinais de que o WAF **nao esta bloqueando** efetivamente:

- **Payload raw nao bloqueado:** scanner envia `<script>alert(1)</script>` e recebe 200 com payload refletido -- WAF pode estar em modo monitor-only ou regras estao desativadas.
- **Bloqueio seletivo:** WAF bloqueia `<script>` mas aceita `<img onerror>` ou `<svg onload>` -- cobertura de regras incompleta.
- **GET bloqueado, POST aceito:** regras aplicadas apenas a query string, nao ao body.
- **Header injection nao coberto:** WAF inspeciona parametros mas nao headers como `Host`, `X-Forwarded-For`, `Referer`.
- **Evasao simples efetiva:** double-encode ou case mutation passa -- indica regras frageis sem normalizacao.
- **JSON body nao inspecionado:** payload em `Content-Type: application/json` nao e bloqueado, mas o mesmo payload em form-data e.

## Target Context (Crawler Hints)
- **Headers indicativos:** `Server: cloudflare`, `cf-ray`, `x-sucuri-id`, `x-akamai-transformed`, `x-cdn`, `x-protected-by`, `x-waf-event-info`.
- **Status codes:** 403, 406, 429 com body de bloqueio.
- **Paths comuns de teste:** qualquer endpoint que aceite input do usuario -- `/search?q=`, `/login`, `/api/*`, `/comment`.
- **Sinais de JS challenge:** body com `cf_chl_opt`, `cf-challenge-`, `Vercel Security Checkpoint`, `Please wait while we verify`.

## Notable CVEs

| CVE | Produto | Ano | Descricao | Tipo |
|-----|---------|-----|-----------|------|
| CVE-2021-45467 | CWP (CentOS Web Panel) | 2021 | LFI bypass via double-encoding contornando ModSecurity rules -- levou a RCE pre-auth | WAF bypass (LFI) |
| CVE-2023-50164 | Apache Struts | 2023 | Path traversal via manipulacao de filename em multipart upload -- WAFs nao inspecionavam Content-Disposition | WAF bypass (path traversal) |
| CVE-2024-22024 | Ivanti Connect Secure | 2024 | XXE em componente SAML -- payloads encodados em base64 nao eram inspecionados por WAFs | WAF bypass (XXE) |
| CVE-2023-22515 | Confluence Data Center | 2023 | Broken access control explorado in-the-wild -- WAF rules publicadas tardiamente, atacantes usaram variantes de URL | WAF bypass (access control) |
| CVE-2020-5902 | F5 BIG-IP TMUI | 2020 | Path traversal via `..;/` (semicolon trick) contornando regex de normalizacao do proprio WAF | Self-bypass |

**Fontes**: CVE List v5 (cvelistV5), NVD, advisories dos vendors, Cloudflare changelogs.

## Recommendation
1. Tratar WAF como camada de defesa em profundidade, nao como correcao de vulnerabilidades. Corrigir a causa raiz no codigo.
2. Manter regras do WAF atualizadas e habilitar OWASP CRS com Paranoia Level adequado ao risco.
3. Configurar WAF para normalizar input (URL decode, Unicode normalize, case fold) antes de inspecionar.
4. Cobrir todos os vetores: query string, body (form, JSON, multipart), headers, cookies.
5. Monitorar logs do WAF para payloads que passaram (anomaly scoring) alem dos bloqueados.
6. Em Cloudflare: habilitar Managed Rules + OWASP, configurar rate limiting por endpoint, e restringir acesso ao origin via IP allowlist ou Cloudflare Tunnel.
7. Nunca expor o IP de origem -- usar Cloudflare Tunnel (cloudflared) em vez de DNS direto, e verificar que subdominios nao vazam o IP.
8. Testar a efetividade do WAF regularmente com ferramentas de evasao (AnarCry, nuclei, sqlmap --tamper) em ambiente autorizado.
9. Para scanners: implementar backoff exponencial, rotacao de User-Agent, e respeitar `Retry-After` para evitar bans.
