# AnarCry -- Plano de Sprints de Seguranca

**Gerado em:** 2026-10-22
**Atualizado em:** 2026-11-02
**Base:** Analise side-by-side dos modulos existentes vs. SecurityTesting-master, KingOfBugBountyTips, HackerOne top reports, HackBot (multi-agent), Muquirana (AI assistant pattern)

---

## Sumario executivo

AnarCry tem **23 modulos funcionais** (era 13 no plano original) cobrindo web vulns, crypto/infra, e deteccao avancada. Os sprints 18-28 do plano original foram **todos implementados**, a maioria excedendo o escopo planejado. Alem disso, foram adicionados modulos e infra que nao estavam no plano: WAF evasion engine, CrawlerModule, GraphQLModule, OAuthModule, InfraModule, CommandInjectionModule, BrowserTransport, StealthHttpClient, ScanOrchestrator, ProbeExecutor.

**Situacao atual (v1.7.1):**
- 23 scanner modules (vs. 13 no plano original)
- 6 fases no Request Smuggling (CL.TE, TE.CL, TE.TE, Duplicate CL, CL.0, Hop-by-hop)
- Crawler com HTML/JS parsing, wordlist, OpenAPI discovery
- WAF evasion engine com TLS fingerprint + stealth HTTP client
- Knowledge base com 27 entries + 71 CVEs reais do cvelistV5
- AuthType selector (NONE, JWT, COOKIE, BEARER) na TUI e GUI
- Reports enriquecidos com CVEs
- Multi-platform release (deb, rpm, msi, dmg)
- E2E test harness

**Proximos gaps de maior impacto:**

| Sprint | Item | Tipo | Effort | Impacto |
|--------|------|------|--------|---------|
| 29 | AI Assistant (chat contextual) | Novo | M | GAME-CHANGER |
| 30 | AI Orchestrator (multi-agent) | Novo | L | GAME-CHANGER |
| 31 | GraphQL++ (batching, depth, field leak) | Melhoria | S | HIGH |
| 32 | XXE++ (SVG upload, SAML, OOB) | Melhoria | M | HIGH |
| 33 | HTTP/2 Smuggling (H2.CL, H2.TE) | Melhoria | M | CRITICAL |
| 34 | JWT++ (jku ativo, x5u) | Melhoria | S | MEDIUM |
| -- | Gaps residuais (CORS backtick, SSTI Smarty, IDOR price) | Patch | S | LOW-MEDIUM |

---

## Sprints 18-28 -- Status de execucao

### Sprint 18 -- SSRF++ : CONCLUIDO (excedeu escopo)

**Planejado:** IP encoding bypasses, webhook params, extra paths, redirect-following client
**Entregue:** Tudo acima + octal encoding, redirect bypass phase, open-redirect relay bypass, crawler-fed dynamic paths/params, parallelized probing via ProbeExecutor, HTML response filtering para FP reduction

### Sprint 19 -- Host Header Injection : CONCLUIDO

**Planejado:** Novo modulo com password reset poisoning, X-Forwarded-Host, X-Host
**Entregue:** `HostHeaderModule.java` implementado, KB entry criada

### Sprint 20 -- Spring Actuator Exposure : CONCLUIDO

**Planejado:** Novo modulo com actuator paths + Spring Boot 1.x paths
**Entregue:** `SpringActuatorModule.java` implementado, KB entry criada

### Sprint 21 -- Mass Assignment : CONCLUIDO

**Planejado:** Novo modulo com probe payload + target paths
**Entregue:** `MassAssignmentModule.java` com confirmacao de persistencia (GET apos PUT), KB entry criada

### Sprint 22 -- CORS++ : CONCLUIDO (gaps residuais menores)

**Planejado:** suffix bypass, startsWith bypass, backtick bypass, JWT probes, extra paths
**Entregue:** suffix bypass, prefix bypass, HTTP downgrade, JWT-authenticated probes (authModes toggle)
**Gaps residuais:**
- Backtick bypass Chrome-specific (baixa prioridade -- Chrome-only, edge case)
- Extra paths (`/api/admin`, `/api/orders`) -- nao criticos

### Sprint 23 -- SSTI RCE : CONCLUIDO (gaps residuais menores)

**Planejado:** Engine-specific RCE payloads apos math-eval, polymorphic fallback
**Entregue:** Phase 2 RCE para FreeMarker, Spring EL, Jinja2, Twig, Thymeleaf, ERB, Pebble, Velocity. Deteccao via `uid=`/`root:` pattern
**Gaps residuais:**
- Smarty `{php}exec{/php}` payload (Smarty e raro em ambientes modernos)
- Polymorphic fallback probe (coberto parcialmente pelos probes individuais)

### Sprint 24 -- IDOR++ : CONCLUIDO (gaps residuais menores)

**Planejado:** DELETE probes, GraphQL mutation IDOR, download-by-ID, price manipulation
**Entregue:** DELETE probes (8 paths), GraphQL mutations (4 mutations, 3 endpoints), auto user-ID discovery, COOKIE auth support, crawler-discovered paths
**Gaps residuais:**
- Price manipulation (PUT com `{"price": 0.01}`) -- requer logica de comparacao de resposta mais sofisticada
- Download-by-ID binary detection (paths existem, mas sem check de Content-Type binary)

### Sprint 25 -- Web Cache Poisoning : CONCLUIDO

**Planejado:** Novo modulo com unkeyed headers, cache detection
**Entregue:** `CachePoisoningModule.java` implementado, KB entry criada

### Sprint 26 -- HTTP Request Smuggling : CONCLUIDO (excedeu escopo)

**Planejado:** CL.TE, TE.CL, TE.TE via raw socket
**Entregue:** 6 fases completas:
1. CL.TE (timing-based com baseline)
2. TE.CL (independente do CL.TE)
3. TE.TE obfuscation (7 variantes, threshold 2/3)
4. Duplicate Content-Length (validacao 3-digit status)
5. CL.0 desync (keep-alive smuggled GET, dual response detection)
6. Hop-by-hop TE stripping (differential: TE-only hangs vs Connection:TE responds)

Raw socket com TLS via BouncyCastle. KB entry criada

### Sprint 27 -- OpenRedirect++ : CONCLUIDO

**Planejado:** user-info, backslash, URL-encoded scheme bypasses + OAuth paths
**Entregue:** Todos os 3 bypasses + OAuth paths (/auth/callback, /oauth/authorize, /oauth/return, /sso)

### Sprint 28 -- CRLF++ : CONCLUIDO

**Planejado:** Header-based injection (User-Agent, Referer)
**Entregue:** Header injection via User-Agent, Referer, X-Forwarded-For, Cookie. Raw socket para CRLF em headers (Java HttpClient bloqueia). Response splitting detection

---

## Trabalho realizado alem do plano original

Estes itens nao estavam no plano de sprints mas foram implementados durante o ciclo:

### Infraestrutura

| Item | Descricao | Versao |
|------|-----------|--------|
| WAF Evasion Engine | TLS fingerprint bypass via impersonator-okhttp, stealth HTTP client | v1.5.0 |
| BrowserTransport | Playwright-based transport para bypass de JS challenges | v1.5.0 |
| StealthHttpClient | HTTP client com randomizacao de headers, timing jitter | v1.5.0 |
| ChallengeSolver | Deteccao e bypass de Cloudflare/reCAPTCHA challenges | v1.5.0 |
| ScanOrchestrator | Orquestracao paralela de modulos | v1.4.0 |
| ProbeExecutor | Executor paralelo de probes dentro de modulos | v1.4.0 |
| CrawlerModule | HTML/JS parsing, wordlist bruteforce, OpenAPI discovery | v1.2.0 |
| DiscoveredPaths | Paths e params compartilhados entre modulos via crawler | v1.2.0 |

### Modulos novos (nao planejados)

| Modulo | Descricao |
|--------|-----------|
| GraphQLModule | Introspection detection, endpoint discovery, __typename fallback |
| OAuthModule | OAuth misconfiguration detection |
| CommandInjectionModule | OS command injection via parameter injection |
| InfraModule | Infrastructure exposure detection |
| CrawlerModule | Web crawling + path discovery |

### Qualidade e distribuicao

| Item | Descricao |
|------|-----------|
| AuthType selector | NONE, JWT, COOKIE, BEARER na TUI e GUI |
| CVE-enriched reports | 71 CVEs reais do cvelistV5 integrados no report engine |
| E2E test harness | Testes end-to-end para validar modulos |
| Multi-platform release | jpackage para deb, rpm, msi, dmg |
| Codacy integration | Static analysis + 31+ findings corrigidos |
| Per-finding CVSS vectors | CVSS v3.1 calculado por finding individual |

---

## Fase 2 -- Novos sprints

### Sprint 29 -- AI Assistant: Chat Contextual (GAME-CHANGER) -- EFFORT: M

**Motivacao:** Analise de 3 projetos:
- **HackBot** (effront/HackBot): multi-agent system com pydantic-ai, MCP tool server, orchestrator pattern (plan -> delegate -> synthesize), typed contracts (ResearchBrief, TriageReport), Rich TUI
- **Muquirana** (effront/muquirana): Rails app com AI assistant integrado, provider abstraction (OpenAI/Anthropic/self-hosted), function tools com JSON Schema, streaming SSE, single-depth tool calls

**O que e:** Um modo ASSISTANT (F8) na TUI do AnarCry -- chat com IA que tem contexto completo do scan em andamento. Diferente de um chatbot generico, o assistente sabe o que o scanner encontrou e pode interpretar, explicar e recomendar.

**Arquitetura (inspirada no Muquirana):**

```
src/main/java/gg/effront/anarcry/
  assistant/
    AiAssistant.java          -- LLM API wrapper (HTTP direto, sem SDK)
    AssistantConfig.java      -- Provider, API key, model config
    ChatMessage.java          -- Record: role + content + timestamp
    ContextBuilder.java       -- Monta system prompt a partir do estado do scan
  tui/
    modes/Mode.java           -- Adicionar ASSISTANT ao enum
    panels/AssistantPanel.java -- Chat UI em Lanterna
```

**Context injection (diferencial vs. chatbot generico):**

| Fonte de contexto | O que injeta no system prompt |
|---|---|
| `findingHistory` | Findings atuais com severity, CWE, endpoint |
| `requestHistory` | HTTP traffic log do scan |
| `knowledge-base/*.md` | KB entries como material de referencia |
| `ScanContext` | Target URL, auth type, modulos habilitados, scope |
| `CrawlerModule` results | Sitemap, attack surface mapeada |
| `CweRegistry` | Classificacao CWE/CVSS estruturada |

**Provider abstraction (inspirada no Muquirana):**
- `ASSISTANT_PROVIDER=gemini|claude|openai|ollama` via `.env.local`
- `ASSISTANT_API_KEY=...` via `.env.local`
- `ASSISTANT_MODEL=...` (override opcional)
- Fallback para self-hosted (Ollama) quando sem API key
- Zero dependencias novas -- `java.net.http.HttpClient` + Gson (ja no projeto)

**Slash commands no chat:**
- `/findings` -- injeta findings atuais no contexto
- `/explain <finding-id>` -- deep dive em finding especifico
- `/remediate` -- plano de remediacao para todos os findings
- `/plan` -- sugere estrategia de pentest para o target
- `/kb <topic>` -- consulta knowledge base
- `/report` -- gera sumario executivo dos findings

**System prompt (gerado dinamicamente pelo ContextBuilder):**

```
Voce e o assistente de seguranca do AnarCry. Esta analisando {target}.
Status do scan: {status}
Findings ate agora: {findings_summary}
Modulos habilitados: {modules}
Tipo de autenticacao: {auth_type}
Sitemap: {discovered_paths_summary}

Ajude o operador a interpretar resultados, sugerir proximos passos,
explicar impacto de vulnerabilidades e recomendar remediacao.
Responda no idioma do operador. Seja direto e tecnico.
Use referencias CWE/CVSS quando relevante.
```

**Estimativa:** 5-7 dias

---

### Sprint 30 -- AI Orchestrator: Multi-Agent (GAME-CHANGER) -- EFFORT: L

**Motivacao:** Evolucao do Sprint 29. Inspirado no HackBot, que usa orchestrator pattern com agentes especialistas. O AnarCry deixa de ser um scanner que voce configura e passa a ser um scanner que **pensa** -- adapta estrategia baseado no que encontra.

**Arquitetura (inspirada no HackBot):**

```
src/main/java/gg/effront/anarcry/
  assistant/
    orchestrator/
      ScanOrchestrationAgent.java  -- Plano: recebe target, decide modulos, interpreta
      TriageAgent.java             -- Prioriza findings por risco de negocio
      ResearchAgent.java           -- Consulta KB + contexto para findings
      ReportAgent.java             -- Gera relatorio de pentest a partir de triage
    tools/                         -- Tool definitions para o LLM
      RunModuleTool.java           -- Wraps ScanRunner.runSingle()
      GetFindingsTool.java         -- Retorna findings filtrados
      GetSitemapTool.java          -- Retorna sitemap do crawler
      QueryKbTool.java             -- Consulta knowledge base
      SendRequestTool.java         -- Http.send() para probing manual
      ExplainCweTool.java          -- CweRegistry lookup + KB
```

**Fluxo do orchestrator:**

```
1. Operador fornece target + credenciais
2. ScanOrchestrationAgent analisa o target:
   - Roda CrawlerModule para mapear superficie
   - Analisa headers da resposta inicial (Server, X-Powered-By)
   - Decide quais modulos rodar baseado na stack detectada:
     - Spring Boot detectado? -> Habilita Actuator, MassAssignment
     - JWT presente? -> Habilita JwtModule, IDOR com auth
     - GraphQL endpoint? -> Habilita GraphQLModule
     - Cloudflare detectado? -> Ativa WAF evasion
3. Roda modulos selecionados via tool calls
4. TriageAgent recebe findings, prioriza por:
   - Severity CVSS
   - Encadeamento (SSRF + IDOR = chain de maior impacto)
   - Business risk (admin access > info disclosure)
5. ResearchAgent enriquece findings com contexto do KB
6. ReportAgent gera relatorio final
```

**Tool definitions (o que o LLM pode chamar):**

```java
// Tool: run_module
// Parametros: moduleId (string), overrides (optional config)
// Retorno: List<Finding>

// Tool: get_findings
// Parametros: filter (severity, module, endpoint)
// Retorno: List<Finding> filtrada

// Tool: get_sitemap
// Parametros: nenhum
// Retorno: Map<String, Set<String>> (endpoints descobertos)

// Tool: query_kb
// Parametros: topic (string)
// Retorno: KnowledgeEntry com descricao, impacto, CVEs

// Tool: send_request
// Parametros: method, url, headers, body
// Retorno: RequestRecord (status, headers, body)

// Tool: explain_cwe
// Parametros: cweId (int)
// Retorno: CWE descricao + CVSS vector + KB entry
```

**Single-depth tool calls (inspirado no Muquirana):**
- O LLM pode chamar tools, mas os tools nao chamam o LLM de volta
- Previne runaway cost e loops infinitos
- O orchestrator e o unico que faz multiplas chamadas ao LLM

**Prerequisito:** Sprint 29 (o `AiAssistant.java` e a base para o orchestrator)

**Estimativa:** 3-4 semanas

---

### Sprint 31 -- GraphQL++ -- EFFORT: S

**Estado atual:** GraphQLModule detecta introspection e endpoint discovery via `__typename`

**Gaps identificados:**

| Gap | Tecnica | Impacto |
|-----|---------|---------|
| Query batching | Array de queries `[{query1}, {query2}, ...]` para rate limit bypass | HIGH |
| Query depth/complexity | Nested queries profundas para DoS | MEDIUM |
| Field suggestion leak | Resposta `Did you mean X?` revela schema sem introspection | HIGH |
| Mutation enum | Enumerar mutations via `__schema{mutationType{fields{name}}}` | MEDIUM |

**Implementacao:**
```java
// Phase 2: Batching probe
// POST /graphql com [{query: "{__typename}"}, {query: "{__typename}"}]
// Se 200 com array de respostas -> batching habilitado

// Phase 3: Field suggestion
// POST /graphql com {query: "{usrr}"} (typo proposital)
// Resposta "Did you mean 'user'?" -> leak de field names

// Phase 4: Depth probe
// Query aninhada: {user{posts{comments{user{posts{...}}}}}}
// Se nao retorna erro de depth -> DoS potencial
```

**Estimativa:** 2-3 dias

---

### Sprint 32 -- XXE++ (SVG, SAML, OOB) -- EFFORT: M

**Estado atual:** XxeModule tem 3 payloads (file-read, SSRF-via-XXE, Billion Laughs), 12 endpoints

**Gaps identificados:**

| Gap | Tecnica | Fonte H1 |
|-----|---------|----------|
| SVG upload XXE | POST com `Content-Type: image/svg+xml` + DOCTYPE entity | #897244 (Zivver, 112 upvotes) |
| DOCX/XLSX upload | ZIP com `word/document.xml` contendo entity externa | #334488 ($2000) |
| OOB via DTD externo | DNS/HTTP callback quando output direto esta bloqueado | tecnica avancada |
| SAML assertion | Entity no `<samlp:AuthnRequest>` em fluxos SSO | #106865 |

**Implementacao:**
```java
// Phase 2: SVG XXE
// POST endpoints com Content-Type: image/svg+xml
// Body: <svg xmlns="http://www.w3.org/2000/svg">
//   <!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/hostname">]>
//   <text>&xxe;</text></svg>

// Phase 3: SAML XXE
// Detectar endpoints SAML (/saml/login, /auth/saml, /sso)
// Injetar entity no SAMLRequest

// Requer: suporte a multipart no Http.java para upload de SVG
```

**Estimativa:** 1 semana

---

### Sprint 33 -- HTTP/2 Smuggling -- EFFORT: M

**Estado atual:** RequestSmugglingModule tem 6 fases, todas HTTP/1.1

**Gaps identificados:**

| Gap | Tecnica | Referencia |
|-----|---------|------------|
| H2.CL | HTTP/2 request com Content-Length divergente do body real | James Kettle research |
| H2.TE | HTTP/2 request com Transfer-Encoding header (proibido mas aceito por proxies bugados) | HTTP/2 Desync Attacks |
| Request tunneling | CONNECT method para tunelar requests atraves do frontend | albinowax |
| H2C smuggling | Upgrade de HTTP/1.1 para HTTP/2 cleartext para bypass de proxy | Bishop Fox |

**Implementacao:**
```java
// Phase 7: H2.CL
// Usar Java HttpClient em HTTP/2 mode
// Enviar request com :method POST, content-length incorreto
// Se backend usa CL do HTTP/2 frame vs header -> desync

// Phase 8: H2.TE
// Injetar Transfer-Encoding header via HTTP/2 (normalmente proibido)
// Requer manipulacao de frames HTTP/2 raw

// Nota: Java HttpClient suporta HTTP/2 nativamente mas nao permite
// headers malformados. Pode precisar de raw frame manipulation
```

**Estimativa:** 1-2 semanas

---

### Sprint 34 -- JWT++ -- EFFORT: S

**Estado atual:** JwtModule bem coberto (alg:none, brute-force, kid injection, null signature, RS256->HS256, JWK injection)

**Gaps identificados:**

| Gap | Tecnica |
|-----|---------|
| jku ativo | JkuHeaderAnalyzer e passivo -- nao testa se server busca JWK externo |
| x5u tampering | Analogo ao jku, para X.509 -- nao coberto |
| iss/aud manipulation | Cross-tenant com claim nao validado |

**Implementacao:**
```java
// jku ativo: enviar JWT com jku apontando para server controlado
// Requer: HTTP server embutido na porta disponivel, ou callback externo

// x5u: mesmo pattern que jku mas para certificado X.509
// Enviar JWT com x5u header apontando para cert controlado

// iss/aud: alterar claims iss e aud para outro tenant
// Verificar se token e aceito com claims diferentes
```

**Baixa prioridade -- modulo ja tem boa cobertura**

**Estimativa:** 2-3 dias

---

## Gaps residuais dos sprints 18-28

Itens menores que ficaram pendentes. Podem ser tratados como patches incrementais:

| Sprint | Gap | Prioridade | Effort |
|--------|-----|------------|--------|
| 22 | CORS backtick bypass (Chrome-only) | LOW | 1h |
| 22 | CORS extra paths (/api/admin, /api/orders) | LOW | 1h |
| 23 | SSTI Smarty `{php}exec{/php}` | LOW | 1h |
| 23 | SSTI polymorphic fallback probe | LOW | 2h |
| 24 | IDOR price manipulation (PUT price:0.01) | MEDIUM | 4h |
| 24 | IDOR download binary Content-Type check | LOW | 2h |

**Estimativa total gaps residuais:** 1-2 dias como batch

---

## Roadmap consolidado -- Fase 2

```
CONCLUIDOS (v1.0 -> v1.7.1):
Sprint 18  [DONE] SSRF++         -- IP encoding, webhook, redirect bypass, crawler-fed
Sprint 19  [DONE] HostHeader     -- novo modulo completo
Sprint 20  [DONE] Actuator       -- novo modulo completo
Sprint 21  [DONE] MassAssign     -- novo modulo com persistencia confirm
Sprint 22  [DONE] CORS++         -- suffix/prefix bypass, JWT probes (gap: backtick)
Sprint 23  [DONE] SSTI RCE       -- 8 engines com RCE (gap: Smarty, polymorphic)
Sprint 24  [DONE] IDOR++         -- DELETE, GraphQL, COOKIE auth (gap: price manip)
Sprint 25  [DONE] CachePoisoning -- novo modulo completo
Sprint 26  [DONE] Smuggling      -- 6 fases, raw socket, TLS (excedeu escopo)
Sprint 27  [DONE] OpenRedirect++ -- 3 bypasses + OAuth paths
Sprint 28  [DONE] CRLF++         -- header injection + raw socket
  +extra   [DONE] WAF Evasion, Crawler, GraphQL, OAuth, CmdInject, Infra modules
  +extra   [DONE] BrowserTransport, StealthHttpClient, ProbeExecutor
  +extra   [DONE] AuthType selector, CVE reports, E2E tests, multi-platform release

PROXIMOS:
Sprint 29  ████ AI Assistant     -- chat contextual na TUI           [1 semana]
Sprint 30  ████ AI Orchestrator  -- multi-agent scan planning        [3-4 semanas]
Sprint 31  ██░░ GraphQL++        -- batching, depth, field leak      [2-3 dias]
Sprint 32  ███░ XXE++            -- SVG upload, SAML, OOB            [1 semana]
Sprint 33  ███░ HTTP/2 Smuggling -- H2.CL, H2.TE, tunneling         [1-2 semanas]
Sprint 34  ██░░ JWT++            -- jku ativo, x5u                   [2-3 dias]
  patch    █░░░ Gaps residuais   -- CORS backtick, SSTI Smarty, etc  [1-2 dias]
```

**Prioridade recomendada (impacto/esforco):**
1. Sprint 29 -- AI Assistant (diferencial competitivo, base para Sprint 30)
2. Sprint 31 -- GraphQL++ (patch rapido, alto retorno)
3. Sprint 32 -- XXE++ (SVG XXE e top H1 bounty)
4. Sprint 33 -- HTTP/2 Smuggling (maximo impacto, complementa Sprint 26)
5. Sprint 30 -- AI Orchestrator (longo prazo, requer Sprint 29)
6. Sprint 34 -- JWT++ (modulo ja bem coberto, baixa prioridade)
7. Gaps residuais (batch de patches)

---

## Analise de integracao -- HackBot e Muquirana

### HackBot (effront/HackBot)

**O que e:** Multi-agent system em Python com pydantic-ai. Orchestrator central que nunca pesquisa diretamente -- planeja, delega para agentes especialistas (researcher, analyst, document_analyst, tutor) em paralelo via asyncio.gather, depois sintetiza.

**Arquitetura relevante:**
- MCP tool server (`hackbot-mcp`): `web_search`, `fetch_page`, `cwe_lookup`, `load_sarif`, `sarif_findings`
- Typed contracts: todos os outputs sao Pydantic models (ResearchBrief, TriageReport, DocumentReport) -- estruturados, validados
- ACP server para discovery/invocacao remota de agentes
- Streaming com activity tree (tool calls, text deltas, thoughts)
- Rich TUI com command palette, chat, triage review

**O que aproveitar no AnarCry:**
1. **Orchestrator pattern** (plan -> delegate -> synthesize) -- Sprint 30
2. **Typed contracts** para outputs estruturados -- mapear para Finding/ScanEvent
3. **MCP tool server** -- expor modulos do AnarCry como MCP tools (futuro)
4. **Triage agent** -- consumir findings do AnarCry para priorizacao inteligente
5. **Safety guardrails** -- pattern de prompt de seguranca

### Muquirana (effront/muquirana)

**O que e:** Rails app de financas com AI assistant integrado. PORO-based Assistant class com provider abstraction, function tools, streaming SSE.

**Arquitetura relevante:**
- Provider resolution: BYOK -> instance key -> error (OpenAI, Anthropic, self-hosted)
- Function tools como classes separadas com JSON Schema definitions
- Event-based streaming com listeners
- Single-depth tool calls (previne runaway cost)
- Async job queue para LLM calls
- Turbo Streams broadcast para UI updates em real-time

**O que aproveitar no AnarCry:**
1. **Provider abstraction** -- suporte a multiplos LLMs sem SDK
2. **Function tool pattern** -- cada tool e uma classe com schema + call()
3. **Single-depth** -- o LLM chama tools, tools nao chamam o LLM
4. **Streaming para TUI** -- broadcast para Lanterna analogamente ao Turbo Streams
5. **Config via .env.local** -- ja existe no AnarCry (EnvLoader)

### Zero-Click Framework (AI-Driven-Zero-Click-Exploit-Deployment-Framework)

**O que e:** Framework conceitual/research de exploit deployment com AI. Escopo massivo (C2, exploits, post-exploitation, IoT, wireless).

**Relevancia para AnarCry:** Nenhuma direta. O framework e conceitual (README-heavy, sem codigo producao). O overlap com AnarCry e minimo -- AnarCry e web scanner, o framework e post-exploitation/C2. Descartado para integracao.
