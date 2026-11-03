---
id: security_headers_missing
title: "Missing Security Headers"
module: "headers"
severity: "MEDIUM"
cwe_id: "CWE-693"
cwe_title: "Protection Mechanism Failure"
cvss_vector: "AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N"
vrt_id: "server_security_misconfiguration.missing_security_headers"
---

## Summary
Ausência ou má configuração de cabeçalhos de segurança (CSP, HSTS, X-Content-Type-Options, frame protection, Referrer-Policy) remove camadas de defesa em profundidade. O impacto real cresce quando combinado com XSS, clickjacking, sniffing de MIME ou vazamento de URL.

## Description
Cabeçalhos de segurança não corrigem uma vulnerabilidade isolada, mas reduzem a superfície de exploração e o impacto de falhas no código. Os principais:

- `Content-Security-Policy` (CSP): limita origens de script, estilo, imagem, frame e conexão. CSP ausente ou permissiva (`unsafe-inline`, `unsafe-eval`, `*`, `data:`, `http:`) permite execução de JavaScript injetado.
- `Strict-Transport-Security` (HSTS): força HTTPS e bloqueia downgrade/SSL stripping.
- `X-Content-Type-Options: nosniff`: impede MIME sniffing que transforma upload em HTML/JS.
- `X-Frame-Options` ou `frame-ancestors`: previne clickjacking e framing malicioso.
- `Referrer-Policy`: evita vazamento de tokens e paths sensíveis via `Referer`.
- `Permissions-Policy`: restringe câmera, microfone, geolocalização e outras APIs.
- `Cross-Origin-Opener-Policy`, `Cross-Origin-Resource-Policy` e `Cross-Origin-Embedder-Policy`: isolam contexto e previnem vazamentos cross-origin.

Em programas de bug bounty, "missing headers" puro costuma ser LOW/INFO. O finding sobe para MEDIUM/HIGH quando há CSP bypass viável, página autenticada framável com ação sensível, upload servido com MIME sniffing ou ausência de HSTS em fluxo de login.

## Impact
- Facilita exploração de XSS, clickjacking, CSRF e vazamento de tokens via Referer.
- Permite que conteúdo malicioso seja interpretado como script (MIME sniffing).
- Usuários ficam expostos a downgrade para HTTP e interceptação em redes hostis.
- Aumenta o raio de impacto de qualquer injeção futura; dificulta defesa em profundidade.
- Pode gerar não conformidade com baselines (OWASP ASVS, PCI DSS, CIS).

## Payloads and Bypasses
```bash
# Inspeção de cabeçalhos
curl -sI https://alvo.com/ | grep -iE 'content-security-policy|strict-transport-security|x-content-type-options|x-frame-options|referrer-policy|permissions-policy|cross-origin'

# Teste de framing
curl -sI https://alvo.com/ | grep -i 'x-frame-options'
# Em HTML: <iframe src="https://alvo.com/account" width="800" height="600"></iframe>

# Teste de sniffing em upload
curl -s -X POST https://alvo.com/upload -F 'file=@payload.html;type=text/plain'
```

Payloads para validar CSP permissiva (quando o objetivo é provar bypass):
```html
<script>alert(document.domain)</script>
<img src=x onerror=alert(document.domain)>
<svg onload=alert(document.domain)>
<meta http-equiv="refresh" content="0;url=https://evil.com">
<iframe srcdoc="<script>alert(parent.document.domain)</script>"></iframe>
```

CSPs fracas que merecem report:
```text
Content-Security-Policy: default-src *; script-src * 'unsafe-inline' 'unsafe-eval'
Content-Security-Policy: script-src 'self' https: data: blob:
Content-Security-Policy: script-src 'self' *.googleapis.com *.cloudflare.com
Content-Security-Policy: default-src 'none'; script-src 'unsafe-inline'
Content-Security-Policy-Report-Only: ...   # não bloqueia, apenas reporta
```

Bypasses comuns:
```text
- JSONP endpoint confiável no allowlist: /api/jsonp?callback=alert
- Angular/Vue gadget com expressão avaliada
- base-uri ausente + <base href="https://evil.com/">
- object-src ausente + plugin legado
- script-src 'self' com upload de JS same-origin
- HSTS ausente em HTTP antes do redirect 301
```

Casos reais e mentalidade de ataque (RWBH): a ausência de headers é usada como amplificador -- o atacante procura uma página autenticada framável, um upload com MIME sniffing ou uma CSP permissiva para transformar um achado baixo em clickjacking/XSS.

## Target Context (Crawler Hints)
- **Parâmetros comuns:** não se aplica; avaliar todas as respostas HTML e de API.
- **Paths comuns:** `/`, `/login`, `/account`, `/admin`, `/checkout`, `/upload`, `/api/*`, `/graphql`.
- **Sinais:** ausência de CSP/HSTS; CSP com `unsafe-inline`; `X-Frame-Options` ausente em páginas autenticadas; `Content-Type` ambíguo em uploads.

## Escalation Techniques
- **Clickjacking:** sem `X-Frame-Options` / `frame-ancestors`, pagina autenticada pode ser embutida em iframe com overlay -- vitima clica em acao sem perceber.
- **XSS via CSP fraca:** `unsafe-inline` ou `unsafe-eval` na CSP permite execucao de scripts injetados via outros vetores.
- **MIME sniffing:** sem `X-Content-Type-Options: nosniff`, upload de arquivo com content-type ambiguo pode ser interpretado como HTML/JS pelo browser.
- **Data exfiltration via CSP:** CSP sem `connect-src` restritivo permite `fetch()` para dominio do atacante com dados roubados.
- **Referrer leak:** sem `Referrer-Policy`, URLs com tokens/sessao em query string vazam para terceiros via `Referer` header.

## Hunting Methodology
1. Verificar presenca e configuracao de cada header de seguranca em respostas HTML: CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy.
2. Avaliar CSP: presenca de `unsafe-inline`, `unsafe-eval`, wildcards (`*`), `data:` em `script-src`.
3. Verificar se headers variam por endpoint -- frequentemente API tem headers diferentes de paginas HTML.
4. Testar clickjacking: tentar embutir paginas autenticadas em iframe e verificar se carregam.
5. Testar MIME sniffing: upload de arquivo `.html` com `Content-Type: image/png` e verificar se o browser executa HTML.

## False Positive Indicators
- Headers ausentes em respostas de API JSON (sem HTML) -- browsers nao renderizam JSON como HTML, risco e baixo.
- CSP ausente mas aplicacao nao tem input de usuario e nao serve conteudo dinamico -- XSS nao e possivel.
- `X-Frame-Options` ausente em pagina publica sem formularios ou acoes -- clickjacking nao tem impacto.
- Headers presentes em proxy/CDN mas ausentes na resposta raw do backend -- o usuario final recebe os headers.

## Recommendation
1. Definir uma CSP restritiva baseada em nonce/hash, sem `unsafe-inline`/`unsafe-eval` em produção. Exemplo:
```nginx
add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'nonce-$request_id'; style-src 'self' 'nonce-$request_id'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'; object-src 'none'" always;
```
2. Aplicar HSTS em todas as respostas HTTPS: `max-age=31536000; includeSubDomains; preload`.
3. Enviar `X-Content-Type-Options: nosniff` e `Content-Type` correto em todos os uploads; forçar `Content-Disposition: attachment` para arquivos não confiáveis.
4. Usar `frame-ancestors 'none'` (CSP) e `X-Frame-Options: DENY` como fallback.
5. Configurar `Referrer-Policy: strict-origin-when-cross-origin` ou `no-referrer` em fluxos com token na URL.
6. Restringir APIs sensíveis com `Permissions-Policy` e isolar origens com COOP/CORP/COEP quando aplicável.
7. Adotar o padrão no framework, não apenas em rotas isoladas. Em Spring Security:
```java
http.headers(headers -> headers
    .contentSecurityPolicy(csp -> csp.policyDirectives(
        "default-src 'self'; script-src 'self' 'nonce-{nonce}'; frame-ancestors 'none'; object-src 'none'"))
    .httpStrictTransportSecurity(hsts -> hsts
        .includeSubDomains(true).maxAgeInSeconds(31536000).preload(true))
    .contentTypeOptions(Customizer.withDefaults())
    .frameOptions(frame -> frame.deny())
    .referrerPolicy(referrer -> referrer.policy(ReferrerPolicy.STRICT_ORIGIN_WHEN_CROSS_ORIGIN)));
```
8. Validar a política em CI com testes de headers e revisar allowlists periodicamente.
