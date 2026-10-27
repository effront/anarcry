# AnarCry — Sprints de Desenvolvimento

**Projeto:** `gg.effront.anarcry`  
**Última atualização:** 2026-10-20

---

## Status geral

```
Sprint 1  ✅ Skeleton + TUI base
Sprint 2  ✅ Módulos de scan (TLS, Headers, JWT, PQC)
Sprint 3  ✅ Módulos de API (CORS, OAuth, OpenRedirect, SSRF, GraphQL, CRLF)
Sprint 4  ✅ Report Engine (MD + JSON) + E2E Harness (47 testes)
Sprint 5  ✅ Chrome: ModeBar + StatusBar + roteamento de modos (F1-F6)
Sprint 6  ✅ Finding.endpoint + FindingsPanel tabela
Sprint 7  ✅ ScanEvent + progresso por módulo na StatusBar
Sprint 8  ✅ Action Palette (?)
Sprint 9  ✅ Event Log Drawer (F8)
Sprint 10 ✅ Modos Target e Repeater funcionais
Sprint 11 ✅ Módulo XXE
Sprint 12 ✅ Módulo SSTI
Sprint 13 ✅ Módulo IDOR
Sprint 14 ✅ Reorganização de packages (crypto/ + web/) + TUI visual grouping
Sprint 15 ✅ HTTP/2 Connection Pooling (HttpClientFactory)
```

---

## Sprints concluídas

### Sprint 1 — Skeleton + TUI base ✅

**Entregáveis:**
- Projeto Gradle 9, Java 27, Lanterna 3.1.3, Bouncy Castle, Gson
- `BasicWindow` full-screen, sem decorações
- Layout 3 painéis: Módulos (esq) + Log (dir) + Findings (baixo)
- `PasteableTextBox` (suporte a Ctrl+V no terminal)
- Quit com `Q`, foco com `Tab`

**Arquivos criados:**
- `Main.java`, `AnarCryTui.java`
- `tui/panels/ModulesPanel.java`, `LogPanel.java`, `FindingsPanel.java`
- `tui/PasteableTextBox.java`
- `model/Finding.java`, `model/Severity.java`
- `scanner/ScanContext.java`, `scanner/Scanner.java`, `scanner/ScanRunner.java`

---

### Sprint 2 — Módulos TLS, Headers, JWT, PQC ✅

**Entregáveis:**
- `TlsModule`: versões fracas (TLS 1.0/1.1), cipher suites fracas, análise de certificado X.509
- `HeadersModule`: HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, cookies sem Secure/HttpOnly, X-Powered-By, Server header
- `JwtModule`: decode de token, análise estática (exp, kid, alg), probes ativos (alg:none, brute-force de segredo, kid injection)
- Probes JWT: `Rs256Hs256Probe`, `JwkInjectionProbe`, `NullSignatureProbe`, `SignatureDisclosureProbe`, `JkuHeaderAnalyzer`
- `PqcModule`: TLS 1.3 check, X25519MLKEM768 negotiation

**Arquivos criados:**
- `scanner/tls/TlsModule.java`, `TlsVersionProbe.java`, `CipherSuiteProbe.java`, `CertificateProbe.java`
- `scanner/headers/HeadersModule.java`
- `scanner/jwt/JwtModule.java` + 5 probes
- `scanner/pqc/PqcModule.java`
- `scanner/util/TlsUtil.java`

---

### Sprint 3 — Módulos de API ✅

**Entregáveis:**
- `CorsModule`: origin reflection com credentials (CRITICAL), wildcard, null origin
- `OAuthModule`: discovery de endpoints OAuth/OIDC, state parameter ausente, redirect_uri bypass
- `OpenRedirectModule`: 5 paths × 9 params × 3 payloads = 135 requests (reduzido de 1520 para eliminar timeout)
- `SsrfModule`: 7 probes (localhost + cloud metadata AWS/GCP/Azure); fix de falso positivo para SSR frameworks (ignora respostas HTML)
- `GraphQLModule`: endpoint discovery, introspection habilitada, error verbosity
- `CrlfModule`: 25 payloads de CRLF injection em paths e query params

**Bugs corrigidos nesta sprint:**
- `SsrfModule`: falso positivo em Next.js — o IP do probe (`169.254.169.254`) era refletido no `__NEXT_DATA__`; fix duplo: removido o IP do `METADATA_PATTERN` + ignora responses HTML
- `OpenRedirectModule`: timeout de horas por produto cartesiano excessivo (1520 requests); reduzido para 135

**Arquivos criados:**
- `scanner/cors/CorsModule.java`
- `scanner/oauth/OAuthModule.java`
- `scanner/openredirect/OpenRedirectModule.java`
- `scanner/ssrf/SsrfModule.java`
- `scanner/graphql/GraphQLModule.java`
- `scanner/crlf/CrlfModule.java`

---

### Sprint 4 — Report Engine + E2E Harness ✅

**Entregáveis:**
- `ReportEngine`: exporta `.md` + `.json` com timestamp, ordenados por severidade
- Harness com 47 testes end-to-end:
  - ScanContext unit tests (3)
  - PQC skip non-HTTPS, HTTPS local (2)
  - ScanRunner lifecycle: callbacks, módulo desabilitado, zero módulos (3)
  - Omnibus server: testa 8 vulnerabilidades simultâneas num único `HttpServer` (1)
  - Clean server: zero falsos positivos (1)
  - Report pipeline: MD + JSON gerados corretamente (1)
  - 36 testes unitários dos módulos individuais
- `CliScanRunner`: runner headless para escanear alvos reais sem abrir TUI

**Arquivos criados/modificados:**
- `report/ReportEngine.java`
- `test/.../harness/ScanHarnessTest.java` (963+ linhas)
- `test/.../harness/CliScanRunner.java`

---

### Sprint 5 — Chrome: ModeBar + StatusBar + Modos ✅

**Entregáveis:**
- `Mode.java`: enum `DASHBOARD, SCAN, TARGET, FINDINGS, REPEATER, REPORT`
- `ModeBar.java`: 6 tabs horizontais; ativo = preto/amarelo, inativo = vermelho; badge `▶` no scan, badge com contagem no Findings
- `StatusBar.java`: alvo + contadores de severidade `◆▲●▼` + hints de teclado
- `AnarCryTui.java` refatorado:
  - F1-F6 trocam de modo (substituindo os antigos F1/F2/F3 de filtro de findings)
  - Layout root: `ModeBar (TOP)` → `conteúdo do modo (CENTER)` → `StatusBar (BOTTOM)`
  - Modo SCAN: layout original (ModulesPanel + LogPanel + FindingsPanel)
  - Modo FINDINGS: FindingsPanel full-screen
  - Modo DASHBOARD: sumário com histograma de severidades e top findings
  - Modo REPORT: histograma detalhado + `[E] Exportar`
  - Modos TARGET e REPEATER: stubs "Disponível em v2.0"
- Hints do FindingsPanel atualizados (removido F1/F2/F3 obsoletos)
- Botões "F5 Iniciar" / "F6 Parar" → "Iniciar" / "Parar"
- LogPanel: cores trocadas de `_BRIGHT` para versão normal (legibilidade no fundo cinza)
- Rename completo: `AnarchCrypto` → `AnarCry`, pacote `anarchrypto` → `anarcry`

**Arquivos criados:**
- `tui/modes/Mode.java`
- `tui/chrome/ModeBar.java`
- `tui/chrome/StatusBar.java`

**Arquivos modificados:**
- `tui/AnarCryTui.java` (refactor completo)
- `tui/panels/FindingsPanel.java`
- `tui/panels/ModulesPanel.java`
- `tui/panels/LogPanel.java`
- `settings.gradle`, `build.gradle`, script `anarchrypto`

---

## Sprints em andamento

### Sprint 6 — `Finding.endpoint` ✅

**Motivação:** findings sem endpoint dificultam triagem — não fica claro ONDE no alvo o problema foi encontrado.

**Entregáveis:**
- `Finding.java`: adiciona campo `String endpoint` como segundo campo (entre `module` e `title`)
- Todos os 10 módulos passam endpoint correto:
  - TLS/PQC: `host:port`
  - Headers: URL base do alvo
  - JWT (análise estática): `"(token)"`
  - JWT (probe ativo): path do probe (ex: `/api/me`)
  - CORS/OAuth/GraphQL: path do endpoint detectado
  - OpenRedirect/SSRF: `path?param`
  - CRLF: path onde injeção foi detectada
- `FindingsPanel.java`: tabela com colunas `SEV │ MODULE │ ENDPOINT │ TITLE`
- `ReportEngine.java`: coluna Endpoint na tabela MD; campo no detalhe
- `AnarCryTui.java`: modal de detalhe exibe Endpoint
- Harness: 4 `new Finding(...)` diretos no test atualizados

**Arquivo chave:** `model/Finding.java`

---

### Sprint 7 — `ScanEvent` + progresso na StatusBar ✅

**Motivação:** StatusBar mostra `◆0 ▲0 ●0 ▼0` durante o scan — não há feedback de progresso por módulo.

**Entregáveis:**
- `ScanEvent.java`: novo record com campos `type, moduleId, index, total, findingCount, elapsedMs`; enum `Type { SCAN_START, MODULE_START, MODULE_DONE, SCAN_DONE }`
- `ScanRunner.java`: campo `Consumer<ScanEvent> eventCb`; disparos de `MODULE_START` + `MODULE_DONE` em cada módulo (loop indexado)
- `StatusBar.java`: `setModuleProgress(done, total)` atualizado pelo eventCb
- `AnarCryTui.java`: wira eventCb → `statusBar.setModuleProgress()`
- Harness: 2 novos testes (testes 48 e 49): `MODULE_DONE` conta por módulo; indexação correta (1-based)

**Arquivo chave:** `scanner/ScanEvent.java`, `scanner/ScanRunner.java`

---

### Sprint 8 — Action Palette ✅

**Motivação:** ações comuns (iniciar, exportar, trocar modo) exigem decorar atalhos; palette estilo VSCode resolve isso.

**Entregáveis:**
- `ActionPalette.java`: modal centralizado com `ActionListBox`, lista de ações com label + shortcut, Esc fecha
- Ativado pela tecla `?` no window listener
- Ações disponíveis: Iniciar scan, Parar scan, Exportar, ir para cada modo, Sair
- `ModulesPanel.triggerStart()`: método público para Action Palette acionar o scan

**Arquivo chave:** `tui/chrome/ActionPalette.java`

---

## Sprints concluídas (continuação)

### Sprint 9 — Event Log Drawer ✅

**Motivação:** o log desaparece ao trocar de modo; F8 deve abrir um drawer lateral com histórico completo.

**Entregáveis:**
- Overlay `F8` com painel de log full-width (modal centralizado)
- Scrollável com `↑↓`, auto-scroll para último item
- Filtro por prefixo: `1` = todos, `2` = só `[!]`/`[!!]`, `3` = só `[+]`
- Barra de status: filtro ativo + contagem (ex: `Filtro: Avisos   3/47 linhas`)
- Fecha com `Esc` ou `F8`

**Arquivo chave:** `tui/chrome/EventLogDrawer.java`

---

### Sprint 10 — Modos Target e Repeater funcionais ✅

**Motivação:** TARGET e REPEATER eram stubs "Disponível em v2.0".

**Entregáveis:**

**TARGET (F3) — `TargetMode.java`:**
- Formulário com campos: Host/URL completa, Headers customizados (multilinha), JWT Token
- Botão "Definir como alvo" preenche `ModulesPanel.targetBox` via `setTarget()`
- Hint: "Defina o alvo aqui ou diretamente no painel F2 Scan"

**REPEATER (F5) — `RepeaterMode.java`:**
- Layout split: Request (esq) + Response (dir)
- Campos: Método + Path (ex: `GET /api/users`), Headers (multilinha), Body
- Botão "Enviar [Enter]" executa via `java.net.http.HttpClient`, timeout 10s
- Resposta exibe status HTTP, headers e body (read-only)
- Pre-popula `Host:` e `Accept:` a partir do alvo atual

**Arquivos criados:**
- `tui/modes/TargetMode.java`
- `tui/modes/RepeaterMode.java`

**Arquivo modificado:**
- `tui/panels/ModulesPanel.java`: adicionado `setTarget(String)`
- `tui/AnarCryTui.java`: `buildModeContent()` roteia TARGET e REPEATER para classes reais

---

## Sprints concluídas (v2)

### Sprint 11 — Módulo XXE ✅

**Motivação:** endpoints que aceitam XML (REST + SOAP + SVG) são comuns em alvos enterprise e raramente cobertos por scanners leves.

**Entregáveis:**
- `XxeModule.java`: sonda 11 paths comuns; valida aceitação de XML com probe benigno (evita 415); injeta file-read (`file:///etc/hostname`) e SSRF (`http://127.0.0.1/`); detecta indicadores na resposta
- Probe 1: file read → CRITICAL se resposta contém hostname
- Probe 2: SSRF via XXE → CRITICAL se resposta reflete nginx/apache/IIS
- `ScanRunner.java`: `ctx.has("XXE")`
- `ModulesPanel.java`: checkbox XXE (marcado por padrão)
- Harness: 2 testes (endpoint vulnerável, servidor rejeita XML com 415)

**Arquivo chave:** `scanner/xxe/XxeModule.java`

---

### Sprint 12 — Módulo SSTI ✅

**Motivação:** SSTI é RCE em disfarce — detectável por output matemático sem side-effects perigosos.

**Entregáveis:**
- `SstiModule.java`: injeta 6 payloads (`${7*7}`, `{{7*7}}`, `#{7*7}`, `${{7*7}}`, `<%= 7*7 %>`, `{{7*'7'}}`) em 8 paths × 11 params; detecta `49` na resposta; diferencia Jinja2 vs Twig via `{{7*'7'}}`
- Finding title inclui engine identificada (FreeMarker/Spring, Jinja2/Twig, Thymeleaf, ERB/EJS)
- `ScanRunner.java`: `ctx.has("SSTI")`
- `ModulesPanel.java`: checkbox SSTI (marcado por padrão)
- Harness: 2 testes (FreeMarker retorna 49, servidor limpo)

**Arquivo chave:** `scanner/ssti/SstiModule.java`

---

### Sprint 13 — Módulo IDOR ✅

**Motivação:** IDOR é top-3 em bug bounty; detectável comparando responses com dois tokens distintos (BOLA).

**Entregáveis:**
- `IdorModule.java`: compara responses em 16 paths REST comuns (`/api/user/1`, `/api/orders/1`, etc.) usando Bearer Token1 vs Token2; finding se ambos retornam 200 com body similar (≥90% de tamanho e mesmo prefixo)
- Sai rapidamente se `jwtToken2` não informado (skip limpo com log)
- `ScanContext.java`: novo campo `String jwtToken2` (4-arg canonical constructor; 3-arg overload para retrocompatibilidade)
- `ModulesPanel.java`: segundo campo "JWT Token 2 (IDOR)" + checkbox IDOR (desmarcado por padrão)
- Harness: 3 testes (cross-user IDOR detectado, servidor com 403 correto, skip sem token2)

**Arquivo chave:** `scanner/idor/IdorModule.java`, `scanner/ScanContext.java`

---

## Arquitetura de referência

```
src/main/java/gg/effront/anarcry/
├── Main.java
├── model/
│   ├── Finding.java          — record(module, endpoint, title, severity, evidence, impact, reproduction, recommendation)
│   └── Severity.java         — enum CRITICAL/HIGH/MEDIUM/LOW/INFO com TextColor
├── scanner/
│   ├── Scanner.java          — interface scan(ScanContext, Consumer<String>)
│   ├── ScanContext.java      — record(targetUrl, jwtToken, enabledModules) + helpers
│   ├── ScanEvent.java        — record(type, moduleId, index, total, findingCount, elapsedMs) [Sprint 7]
│   ├── ScanRunner.java       — executor single-thread; callbacks onScanStart/Finish + eventCb [Sprint 7]
│   ├── crypto/ — tls/, headers/, jwt/, pqc/   [Sprint 14]
│   ├── web/    — cors/, crlf/, graphql/, oauth/, openredirect/, ssrf/, xxe/, ssti/, idor/   [Sprint 14]
│   └── util/   — TlsUtil.java, HttpClientFactory.java   [Sprint 15]
├── report/
│   └── ReportEngine.java     — export(findings, target) → .md + .json
└── tui/
    ├── AnarCryTui.java       — main window, mode routing, key handler
    ├── PasteableTextBox.java
    ├── chrome/
    │   ├── ModeBar.java       — 6 tabs F1-F6
    │   ├── StatusBar.java     — alvo + módulos X/Y + severidades
    │   └── ActionPalette.java — overlay ? [Sprint 8]
    ├── modes/
    │   └── Mode.java          — enum DASHBOARD/SCAN/TARGET/FINDINGS/REPEATER/REPORT
    └── panels/
        ├── FindingsPanel.java — ActionListBox SEV│MODULE│ENDPOINT│TITLE [Sprint 6]
        ├── LogPanel.java      — stream de log colorido
        └── ModulesPanel.java  — checkboxes + target + JWT + botões
```

---

## Harness — contagem de testes

| Sprint | Testes adicionados | Total acumulado |
|--------|-------------------|-----------------|
| Sprint 4 | 47 | 47 |
| Sprint 6 | 0 (atualização dos existentes) | 47 |
| Sprint 7  | 2 (ScanEvent)         | **49** |
| Sprint 11 | 2 (XXE)               | 51 |
| Sprint 12 | 2 (SSTI)              | 53 |
| Sprint 13 | 3 (IDOR)              | **55** ✅ |

---

## Dependências entre sprints

```
Sprint 6 (endpoint) → FindingsPanel legível
Sprint 7 (ScanEvent) → StatusBar com progresso real
Sprint 8 (Palette) → usabilidade sem decorar atalhos
Sprint 9 (LogDrawer) → acesso ao log em qualquer modo
Sprint 10 (Target/Repeater) → fluxo completo de pentest manual
Sprint 11-13 (novos módulos) → cobertura de ataque expandida
```
