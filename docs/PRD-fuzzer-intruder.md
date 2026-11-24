# PRD -- Fuzzer / Intruder Module

> AnarCry v2.5.0 -- HTTP Fuzzer com payload injection, attack modes e result analysis.
> Referencia: Burp Suite Intruder + OWASP ZAP Fuzzer.

---

## 1. Problema

O AnarCry tem Repeater (request manual) e 25+ scanner modules (payload automatico), mas falta um
meio-termo: enviar um request customizado N vezes, substituindo posicoes marcadas por payloads de
uma wordlist. Hoje o pentester precisa abrir o Burp Intruder ou o ZAP Fuzzer pra isso.

O usuario ja tem wordlists locais (Payloads4All, ProStaff-Audit, nuclei-templates, SecurityTesting
com 220k+ paths, custom lists) que nao sao aproveitadas.

---

## 2. Objetivo

Nova tab **Fuzzer** na GUI que permite:
1. Importar um request (do Repeater ou manual)
2. Marcar posicoes de injection com `{{1}}`, `{{2}}`, etc.
3. Carregar payloads por posicao (arquivo, lista inline, range numerico)
4. Escolher attack mode (como payloads combinam entre posicoes)
5. Disparar em paralelo com virtual threads
6. Visualizar resultados em tabela com filtro, sort e grep match
7. Enviar resultado individual pro Repeater pra analise manual

---

## 3. Referencias

### 3.1 Burp Intruder -- Attack Types

| Tipo | Posicoes | Payloads | Requests | Uso |
|---|---|---|---|---|
| **Sniper** | N | 1 lista | N x M | Testar cada posicao isolada |
| **Battering Ram** | N | 1 lista | M | Mesmo payload em todas posicoes |
| **Pitchfork** | N | N listas | min(M1,M2,...) | Pares sincronizados (user[i], pass[i]) |
| **Cluster Bomb** | N | N listas | M1 x M2 x ... | Produto cartesiano (brute force) |

### 3.2 Burp Intruder -- Payload Processing

Regras aplicadas em sequencia antes de injetar:
- Add prefix / Add suffix
- Match/replace (regex)
- Encode: URL, HTML, Base64, Hex
- Decode: URL, HTML, Base64, Hex
- Hash: MD5, SHA-1, SHA-256, SHA-512
- Skip if matches regex

### 3.3 Burp Intruder -- Results Table

Colunas: Request #, Position, Payload, Status Code, Response Length, Response Time (ms),
Error, Timeout, Cookies. Mais colunas de Grep Match (count por expressao) e Grep Extract
(texto extraido entre markers).

### 3.4 ZAP Fuzzer -- Diferencas

- Sem attack types nomeados -- posicoes com generators independentes, combinacao implicita
- Payload Processors: Base64, MD5, SHA-*, prefix/postfix, URL encode, trim, script-based
- Message Processors: anti-CSRF token refresh, Content-Length auto-update
- Results: State, Method, URI, Payload, Status Code, RTT, Size

### 3.5 Decisao de Design

Implementar os 4 attack types do Burp (Sniper, Battering Ram, Pitchfork, Cluster Bomb) por
serem mais explicitos e intuitivos que a abordagem implicita do ZAP. Payload processing segue
o modelo do Burp (regras em pipeline). Anti-CSRF do ZAP fica pra v2.

---

## 4. Arquitetura

### 4.1 Componentes

```
gui/views/
  FuzzerView.java          -- Tab principal (Swing)
  FuzzerConfigPanel.java   -- Painel de config (attack type, positions, payloads)
  FuzzerResultsPanel.java  -- Tabela de resultados com filtro/sort/grep

scanner/util/
  Http.java                -- Reutilizar Http.send() existente (request logging)
  HttpClientFactory.java   -- Reutilizar HttpClient compartilhado

fuzzer/                    -- Novo package
  AttackType.java          -- Enum: SNIPER, BATTERING_RAM, PITCHFORK, CLUSTER_BOMB
  FuzzPosition.java        -- Record: index, start, end no template
  PayloadSource.java       -- Interface: Iterator<String> de payloads
  FilePayloadSource.java   -- Carrega .txt do disco (lazy, line-by-line)
  InlinePayloadSource.java -- Lista digitada na UI
  RangePayloadSource.java  -- Range numerico (from, to, step, padding)
  PayloadProcessor.java    -- Interface: String process(String input)
  PayloadProcessors.java   -- Factory: prefix, suffix, encode, decode, hash, regex
  FuzzEngine.java          -- Orquestrador: gera requests, despacha, coleta resultados
  FuzzResult.java          -- Record: requestNum, payload, statusCode, length, timeMs, body, headers, error
  GrepMatcher.java         -- Avalia regex/literal patterns no response body
```

### 4.2 Fluxo

```
FuzzerView                    FuzzEngine                      Http.send()
    |                              |                              |
    |-- start(config) ----------->|                              |
    |                              |-- generate combinations --->|
    |                              |   (based on AttackType)     |
    |                              |                              |
    |                              |-- for each combination:     |
    |                              |   1. apply processors       |
    |                              |   2. inject into template   |
    |                              |   3. send via Http.send() ->|
    |                              |   4. collect FuzzResult     |
    |                              |                              |
    |<-- onResult(FuzzResult) ----|                              |
    |<-- onProgress(current/total)|                              |
    |<-- onComplete() ------------|                              |
```

### 4.3 Concorrencia

- Virtual threads via `Thread.ofVirtual()` (ja usado no RepeaterView e CredentialTester)
- `Semaphore` para limitar threads concorrentes (configuravel, default 10)
- Delay entre requests configuravel (ms) para rate limiting
- Cancel via `AtomicBoolean` checked a cada iteracao

---

## 5. User Stories

### Fase 1 -- Core (MVP)

#### FZR-001: Request Template Editor

**Como** pentester, **quero** colar/importar um HTTP request e marcar posicoes de injection,
**para** definir onde os payloads serao inseridos.

**Criterios de aceite:**
- RSyntaxTextArea com o request template (method + URL + headers + body)
- Selecionar texto e clicar "Add Position" insere markers `{{N}}` ao redor
- Botao "Clear Positions" remove todos os markers
- Botao "Auto" detecta valores em query params, headers e body e marca automaticamente
- Posicoes destacadas com background colorido (uma cor por posicao, ate 8)
- Importar request do Repeater via "Send to Fuzzer" no menu de contexto do RepeaterView
- Contador de posicoes no toolbar: "3 positions"

**Implementacao:**
- `FuzzerView.buildTemplatePanel()` com RSyntaxTextArea
- Highlight via `RSyntaxTextArea.addLineHighlight()` ou custom `Painter`
- Regex `\{\{(\d+)\}\}` para parse das posicoes
- Botao "Send to Fuzzer" adicionado ao RepeaterView context menu

---

#### FZR-002: Attack Type Selector

**Como** pentester, **quero** escolher como os payloads combinam entre posicoes,
**para** controlar a estrategia de fuzzing.

**Criterios de aceite:**
- JComboBox com 4 opcoes: Sniper, Battering Ram, Pitchfork, Cluster Bomb
- Tooltip em cada opcao explicando o comportamento
- Contador de requests estimado atualiza ao trocar tipo ou payloads
- Sniper: 1 payload list compartilhada, itera por posicao (N pos x M payloads)
- Battering Ram: 1 payload list, mesmo payload em todas posicoes simultaneamente
- Pitchfork: 1 payload list por posicao, iteracao sincronizada
- Cluster Bomb: 1 payload list por posicao, produto cartesiano

**Implementacao:**
- `AttackType` enum com `calculateTotalRequests(List<PayloadSource>)` method
- Label "~15,000 requests" atualiza via listener no combo e payload panels

---

#### FZR-003: Payload Sources

**Como** pentester, **quero** carregar payloads de arquivo, digitar inline ou gerar ranges,
**para** alimentar o fuzzer com dados de ataque.

**Criterios de aceite:**
- Tab panel por posicao (Pitchfork/Cluster Bomb) ou tab unica (Sniper/Battering Ram)
- **File**: file chooser com filtro .txt, mostra preview das primeiras 10 linhas e total count
- **Inline**: JTextArea para digitar payloads (um por linha)
- **Range**: campos From, To, Step, Padding (ex: 1-100, step 1, pad 3 = 001..100)
- Indicador de payload count por source: "wordlist.txt (12,345 lines)"
- Suporte a arquivos grandes (100k+ linhas) sem carregar tudo em memoria -- lazy reading

**Implementacao:**
- `PayloadSource` interface com `long size()`, `Iterator<String> iterator()`, `void reset()`
- `FilePayloadSource`: `BufferedReader` com lazy line reading, conta linhas em background
- `InlinePayloadSource`: split por newline
- `RangePayloadSource`: calcula size sem gerar, itera sob demanda
- File chooser inicia em `~/wordlists/` se existir, senao home

---

#### FZR-004: Fuzzer Engine

**Como** pentester, **quero** disparar o ataque e ver progresso em tempo real,
**para** executar o fuzzing de forma controlada.

**Criterios de aceite:**
- Botao "Start Attack" inicia o fuzzing em background
- Progress bar com "1,234 / 15,000 requests (8%)"
- Botao "Pause" suspende threads sem cancelar
- Botao "Stop" cancela todas as threads e para
- Config: threads (1-100, default 10), delay entre requests (0-5000ms, default 0)
- Requests enviados via `java.net.http.HttpClient` (reutilizar `HttpClientFactory`)
- Cada resultado aparece na tabela em tempo real (nao espera terminar)
- Erros de rede (timeout, connection refused) registrados como resultado com flag de erro

**Implementacao:**
- `FuzzEngine` com `Semaphore(threadCount)`, `AtomicBoolean cancelled`, `AtomicBoolean paused`
- Cada request: acquire semaphore -> check paused (wait) -> build request -> send -> release
- Resultados via callback `Consumer<FuzzResult>` chamado na virtual thread, SwingUtilities.invokeLater pra UI
- Timer thread atualiza progress bar a cada 100ms

---

#### FZR-005: Results Table

**Como** pentester, **quero** ver os resultados em tabela ordenavel e filtravel,
**para** identificar respostas anomalas rapidamente.

**Criterios de aceite:**
- JTable com colunas: #, Payload, Status, Length, Time (ms), Error
- Sorting por qualquer coluna (click no header)
- Filtro por status code (campo texto, ex: "200", "4xx", "!200")
- Filtro por length range (min-max)
- Highlight automatico de status codes anomalos (5xx em vermelho, 3xx em azul)
- Alternating row colors (reutilizar stripe do DB Explorer)
- Double-click em row abre request/response detail no painel inferior
- Painel inferior com RSyntaxTextArea mostrando response body (syntax highlight auto)
- Context menu: Copy Payload, Copy Response, Send to Repeater

**Implementacao:**
- `DefaultTableModel` + `TableRowSorter` com custom comparators
- `RowFilter` composto para status e length
- NullAwareRenderer reutilizado do DB Explorer (extrair pra util class)
- Split pane: tabela em cima, response viewer embaixo

---

#### FZR-006: "Send to Fuzzer" Integration

**Como** pentester, **quero** enviar um request do Repeater pro Fuzzer com um clique,
**para** reaproveitar requests que ja configurei.

**Criterios de aceite:**
- Menu item "Send to Fuzzer" no RepeaterView (toolbar ou context menu)
- Preenche o template do FuzzerView com method, URL, headers e body do Repeater
- Muda automaticamente pra tab Fuzzer
- Se ja tem um ataque rodando, confirma antes de substituir

**Implementacao:**
- `FuzzerView.loadFromRepeater(String method, String url, String headers, String body)`
- `AnarCryGui` medeia a comunicacao entre tabs (referencia ao FuzzerView)
- Botao no RepeaterView toolbar: "Send to Fuzzer"

---

### Fase 2 -- Payload Processing

#### FZR-007: Payload Processors

**Como** pentester, **quero** transformar payloads antes da injecao (encode, hash, prefix),
**para** adaptar payloads a diferentes contextos de injection.

**Criterios de aceite:**
- Lista de processors por payload source, aplicados em sequencia (pipeline)
- Processors disponiveis:
  - Add prefix / Add suffix (campo texto)
  - URL encode / URL decode
  - Base64 encode / Base64 decode
  - HTML encode / HTML decode
  - Hash: MD5, SHA-1, SHA-256, SHA-512
  - Match/replace (regex pattern + replacement)
  - Skip if matches (regex -- descarta payload)
- UI: JList com Add/Remove/Up/Down, config panel por processor selecionado
- Preview: mostra 5 payloads antes e depois do pipeline

**Implementacao:**
- `PayloadProcessor` interface: `String process(String input)` (retorna null = skip)
- `PayloadProcessors` factory class com metodos estaticos
- Pipeline: `List<PayloadProcessor>`, aplica em ordem, null result = skip payload
- Preview panel atualiza ao mudar config

---

#### FZR-008: Grep Match

**Como** pentester, **quero** buscar patterns nos response bodies automaticamente,
**para** detectar respostas que contem dados sensiveis ou indicadores de vulnerabilidade.

**Criterios de aceite:**
- Painel "Grep -- Match" com lista de patterns (literal ou regex)
- Cada pattern adiciona uma coluna na results table (count de matches)
- Patterns pre-definidos disponiveis: "error", "exception", "SQL syntax", "stack trace",
  "password", "token", "admin", "root", "flag{", "<!DOCTYPE"
- Checkbox "case sensitive" por pattern
- Coluna mostra count (0 = celula vazia, >0 = highlighted)

**Implementacao:**
- `GrepMatcher` com `List<Pattern>`, `int[] match(String responseBody)`
- Colunas dinamicas adicionadas ao TableModel
- Renderer com highlight quando count > 0

---

#### FZR-009: Grep Extract

**Como** pentester, **quero** extrair trechos especificos dos responses,
**para** capturar tokens, IDs ou dados retornados em cada request.

**Criterios de aceite:**
- Definir regex com grupo de captura: ex `"token":"([^"]+)"`
- Coluna na results table mostra o valor extraido (grupo 1)
- Ate 5 grep extract rules
- Valores extraidos copiaveis (context menu -> Copy Extracted Values)

**Implementacao:**
- `GrepMatcher.extract(String body, Pattern pattern)` retorna primeiro grupo
- Coluna dinamica por extract rule

---

### Fase 3 -- Advanced

#### FZR-010: Wordlist Browser

**Como** pentester, **quero** navegar minhas wordlists locais com preview,
**para** escolher rapidamente a lista certa sem sair do app.

**Criterios de aceite:**
- Dialog com JTree mostrando diretorios de wordlists conhecidos:
  - `~/wordlists/`
  - `~/PROJETOS/Payloads4All-master/` (categorizado por vuln type)
  - `~/PROJETOS/ProStaff-Audit/probes/`
  - `~/nuclei-templates/helpers/`
  - Diretorios custom adicionados pelo usuario
- Preview panel mostra primeiras 20 linhas e total count do arquivo selecionado
- Double-click carrega como payload source
- Busca por nome de arquivo
- Persiste diretorios custom em `~/.anarcry/fuzzer-wordlist-dirs.json`

**Implementacao:**
- `WordlistBrowserDialog` como JDialog modal
- File tree com `FileSystemView` filtrado pra .txt/.lst/.csv
- Preview lazy com `BufferedReader.lines().limit(20)`

---

#### FZR-011: Auto-Position Detection

**Como** pentester, **quero** que o fuzzer detecte automaticamente posicoes de injection,
**para** agilizar a configuracao em requests complexos.

**Criterios de aceite:**
- Botao "Auto" analisa o template e marca:
  - Query parameters values: `?param={{1}}&other={{2}}`
  - Header values comuns: Cookie, Authorization, X-Custom-*
  - JSON body values: `"key": "{{3}}"`
  - Form body values: `field={{4}}&other={{5}}`
- Nao marca valores vazios, booleans ou URLs internas
- Resultado pode ser editado manualmente apos auto-detection

**Implementacao:**
- Regex-based parser pra cada formato (query string, headers, JSON, form-urlencoded)
- Numera posicoes sequencialmente

---

#### FZR-012: Results Export

**Como** pentester, **quero** exportar resultados do fuzzing,
**para** documentar achados e compartilhar com a equipe.

**Criterios de aceite:**
- Export para CSV: todas as colunas incluindo grep match/extract
- Export para JSON: array de objetos com request + response completos
- Filtro aplicado antes do export (exporta apenas visible rows)
- File chooser com nome sugerido: `fuzz-{target}-{timestamp}.csv`

**Implementacao:**
- Reutilizar pattern do `DataExporter` existente do DB Explorer

---

#### FZR-013: Request Throttling e Jitter

**Como** pentester, **quero** controlar o rate e adicionar variacao aleatoria,
**para** evitar rate limiting e WAF blocking.

**Criterios de aceite:**
- Delay fixo entre requests (slider 0-5000ms)
- Jitter opcional: +/- random % do delay (0-50%)
- Display de requests/segundo atual na status bar
- Auto-detect de rate limiting: se 3+ respostas consecutivas sao 429, sugere aumentar delay

**Implementacao:**
- `Thread.sleep(delay + random.nextInt(jitter))` entre requests
- Callback `onRateLimited()` pro UI mostrar warning

---

#### FZR-014: Session Token Update

**Como** pentester, **quero** que o fuzzer atualize tokens anti-CSRF automaticamente,
**para** nao ter 100% dos requests falhando por token invalido.

**Criterios de aceite:**
- Checkbox "Update session token" com config:
  - URL do token (ex: GET /csrf-token)
  - Regex para extrair token do response
  - Header ou parameter onde injetar o token
  - Refresh interval (a cada N requests ou quando receber 403)
- Token atualizado em background sem interromper o ataque

**Implementacao:**
- Pre-request hook no FuzzEngine que checa se precisa refresh
- Shared `AtomicReference<String>` com o token atual

---

### Fase 4 -- TUI

#### FZR-015: Fuzzer Mode na TUI

**Como** pentester usando o terminal, **quero** acessar o fuzzer pela TUI,
**para** rodar fuzzing sem precisar da GUI.

**Criterios de aceite:**
- Novo mode "Fuzzer" na TUI (apos Repeater)
- Split: template a esquerda, config a direita
- Results table com sorting e scroll
- Reutilizar `FuzzEngine` (zero duplicacao de logica)

**Implementacao:**
- Extrair toda logica de `fuzzer/` package (nao depende de Swing)
- TUI mode usa os mesmos `FuzzEngine`, `PayloadSource`, `AttackType`
- Apenas a view e Lanterna-specific

---

#### FZR-016: CLI Batch Mode

**Como** pentester, **quero** rodar fuzzing via CLI sem UI,
**para** automatizar em scripts e CI/CD pipelines.

**Criterios de aceite:**
- Flag `--fuzz` com config file JSON:
  ```json
  {
    "template": "POST /login HTTP/1.1\nHost: target.com\n\nuser={{1}}&pass={{2}}",
    "attackType": "CLUSTER_BOMB",
    "payloads": [
      {"type": "file", "path": "/home/user/wordlists/users.txt"},
      {"type": "file", "path": "/home/user/wordlists/passwords.txt"}
    ],
    "threads": 20,
    "delay": 100,
    "output": "results.csv"
  }
  ```
- Output em CSV ou JSON
- Exit code 0 se completou, 1 se erro
- Progress em stderr

**Implementacao:**
- Parse JSON config com Gson
- Reutilizar `FuzzEngine` headless
- Adicionar handler no `Main.java` args parsing

---

## 6. Componentes Reutilizaveis (Existing)

| Componente | Source | Reutilizado em |
|---|---|---|
| `HttpClientFactory` | scanner/util/ | HTTP requests |
| `Http.send()` | scanner/util/ | Request logging |
| Virtual threads pattern | RepeaterView, CredentialTester | Concorrencia |
| `Semaphore` throttling | CredentialTester | Rate limiting |
| RSyntaxTextArea | RepeaterView, DbExplorerView | Template editor, response viewer |
| `NullAwareRenderer` | DbExplorerView | Results table |
| `TableRowSorter` | DbExplorerView | Sorting |
| Stripe/alternating rows | DbExplorerView | Results table |
| `DataExporter` | DbExplorerView | Results export |
| AnarCryLaf theme | gui/theme/ | FlatLaf consistency |

---

## 7. Wordlists Locais Conhecidas

| Path | Conteudo | Linhas |
|---|---|---|
| `~/wordlists/prostaff.gg/paths.txt` | URL paths | 245 |
| `~/wordlists/prostaff.gg/parametros.txt` | Parameter names | 171 |
| `~/wordlists/prostaff.gg/subdominios.txt` | Subdomains | 226 |
| `~/PROJETOS/Payloads4All-master/` | 40+ categorias de payloads (SQLi, XSS, SSTI, etc.) | varies |
| `~/PROJETOS/ProStaff-Audit/probes/payloads/` | SQLi, SSRF, SSTI, traversal, XSS | 84 |
| `~/PROJETOS/ProStaff-Audit/probes/wordlists/` | API endpoints, admin paths | 2 files |
| `~/nuclei-templates/helpers/payloads/` | Command injection, request headers | 433 |
| `~/nuclei-templates/helpers/wordlists/` | MySQL/SSH users+passwords, WP plugins | varies |
| `~/PROJETOS/SecurityTesting-master/wordlists/dir23.txt` | Directory bruteforce | 220,560 |

---

## 8. UI Layout

```
+-------------------------------------------------------------------+
| [Attack Type: v] Sniper    | Threads: [10] Delay: [0]ms  | Start  |
|                            | Positions: 3  Requests: ~45k | Pause  |
|                            |                              | Stop   |
+-------------------------------------------------------------------+
| Template (RSyntaxTextArea)         | Payloads              |
| POST /login HTTP/1.1               | [Position 1] [Pos 2]  |
| Host: target.com                   | Source: [File v]       |
| Content-Type: application/json     | /wordlists/users.txt  |
|                                    | (245 lines)           |
| {"user":"{{1}}","pass":"{{2}}"}    | Preview:              |
|                                    |   admin               |
| [Add Position] [Clear] [Auto]      |   root                |
|                                    |   test                |
|                                    |                       |
|                                    | Processors: [Add v]   |
|                                    |   1. URL encode       |
+----------------------------------+-+-----------------------+
| Results  [Filter: status] [Grep Match] [Export]            |
|  #  | Payload     | Status | Length | Time | Grep:error    |
|-----|-------------|--------|--------|------|---------------|
|  1  | admin       |   200  |  4821  |  45  |     0         |
|  2  | root        |   403  |   312  |  38  |     1         |
|  3  | test        |   200  |  4821  |  42  |     0         |
| ... | ...         |   ...  |   ...  |  ... |    ...        |
+------------------------------------------------------------+
| Response Body (RSyntaxTextArea)                            |
| {"error":"invalid credentials","code":401}                 |
+------------------------------------------------------------+
```

---

## 9. Prioridade e Estimativa

| Fase | Stories | Estimativa | Prioridade |
|---|---|---|---|
| **Fase 1 -- Core** | FZR-001 a FZR-006 | 8-10h | P0 |
| **Fase 2 -- Processing** | FZR-007 a FZR-009 | 4-5h | P1 |
| **Fase 3 -- Advanced** | FZR-010 a FZR-014 | 6-8h | P2 |
| **Fase 4 -- TUI/CLI** | FZR-015 a FZR-016 | 4-5h | P3 |

**MVP (Fase 1)** entrega um fuzzer funcional com os 4 attack types, 3 payload sources,
results table com sort/filter, e integracao com Repeater. Cobre 80% dos use cases.

---

## 10. Riscos e Mitigacoes

| Risco | Mitigacao |
|---|---|
| OOM com wordlists grandes (220k+) | FilePayloadSource com lazy reading, nunca carrega tudo |
| Rate limiting do alvo | Delay + jitter configuravelel, auto-detect 429 |
| UI freeze com muitos resultados | SwingUtilities.invokeLater batched, table update throttled |
| Cluster Bomb explosion (10k x 10k = 100M) | Warning no UI quando > 100k requests, confirm dialog |
| Uso nao autorizado | Scope check via ScanConfig.isInScope() antes de iniciar |

---

## 11. Notas de Implementacao

- Package `fuzzer/` nao depende de Swing -- logica pura reutilizavel entre GUI, TUI e CLI
- `FuzzerView` fica em `gui/views/` seguindo o padrao existente
- Registrar tab em `AnarCryGui` apos "Repeater"
- Keyboard shortcuts: Ctrl+Enter = Start, Escape = Stop, Ctrl+E = Export
- Nao usar emdash/endash em nenhum output
- Spotless antes de qualquer commit

---

Generated: 2026-11-23

Sources:
- Burp Suite Intruder (reverse engineering: ~/PROJETOS/reverse-burp-ui-2026-10-20/)
- OWASP ZAP Fuzzer (config: ~/PROJETOS/prostaff-api/security_tests/zap/)
- Payloads4All (~/PROJETOS/Payloads4All-master/)
- DBeaver UI patterns (icons, table rendering)
