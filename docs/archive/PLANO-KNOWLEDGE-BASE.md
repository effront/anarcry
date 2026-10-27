# Plano de Implementação — knowledge_base.json

> Revisão 2 — 2026-10-26. Deep review completo dos 25 .md + 4 classes Java + build.gradle + 32 scanner modules.

---

## 1. Estado Atual (Deep Review)

### 1.1 Arquivos Markdown (knowledge-base/)

| Item | Status |
|---|---|
| Total de arquivos | 25 vulnerabilidades + INDEX.md + 3 livros-fonte em `_sources/` |
| Front matter | 100% consistente — 8 campos (`id`, `title`, `module`, `severity`, `cwe_id`, `cwe_title`, `cvss_vector`, `vrt_id`) |
| Seções `##` | 100% consistentes — Summary, Description, Impact, Payloads and Bypasses, Target Context (Crawler Hints), Recommendation |
| INDEX.md | 25 IDs, sem órfãos ou ausentes |
| `_sources/` | 3 livros (Bug Bounty Bootcamp 19K lines, Day Zero 16K lines, Hacking Kali 7K lines). Já destilados nos 25 .md — **não precisam re-parse** |

#### 1.1.1 Severidade vs CVSS — 100% Consistente

Todos os 25 arquivos têm score CVSS dentro da banda de severidade declarada.

| Severidade | Arquivos | Score Range |
|---|---|---|
| CRITICAL (9) | xss, sql_injection, ssrf, command_injection, ssti, jwt_signature_bypass, oauth_misconfiguration, request_smuggling, infrastructure_exposure | 9.0–10.0 |
| HIGH (8) | csrf, cors, lfi, xxe, host_header, mass_assignment, spring_actuator, graphql, cache_poisoning | 7.5–8.7 |
| MEDIUM (5) | security_headers, idor, open_redirect, crlf, tls_weak | 5.4–6.5 |
| LOW (2) | hsts_missing, post_quantum_readiness | 3.1–3.7 |

#### 1.1.2 CWEs — 3 Debatíveis (não bloqueantes)

| Arquivo | CWE Atual | Observação | CWE Alternativo |
|---|---|---|---|
| `oauth_misconfiguration` | CWE-352 | CSRF é um vetor, mas OAuth misconfig é mais amplo | CWE-287 (Improper Auth) |
| `host_header_injection` | CWE-20 | CWE-20 é o catch-all genérico | CWE-644 (HTTP Header Neutralization) |
| `cache_poisoning` | CWE-524 | CWE-524 é "cache com dados sensíveis", não poisoning | CWE-349 (Extraneous Untrusted Data) |

**Decisão:** Manter os CWEs atuais por agora. São aceitáveis nas hierarquias CWE. Podem ser refinados em iteração futura.

#### 1.1.3 CVSS Vector Format

Todos os 25 vetores usam formato bare (`AV:N/AC:L/...`) **sem** prefixo `CVSS:3.1/`. O `CvssCalculator.java` já aceita ambos os formatos. O JSON preservará o formato bare dos .md.

#### 1.1.4 Payloads — Anatomia Completa

| Aspecto | Achado |
|---|---|
| Localização | 100% dentro de blocos de código cercados (` ``` `) — **nenhum** payload solto em prosa |
| Lang tags usadas | `bash`, `sql`, `html`, `text`, `http`, `xml`, `json`, `graphql`, `python`, `nginx` |
| Total estimado | ~1.100 linhas de payload nos 25 arquivos |
| "Casos reais" | Presente como parágrafo de prosa **após** o último bloco de código em **todos** os 25 arquivos — parser deve parar na última fence ` ``` `, não no próximo `##` |
| Code blocks em `## Recommendation` | Presentes em **todos** os 25 arquivos (exemplos Java/Python/nginx) — **NÃO** são payloads, parser deve escopo apenas `## Payloads and Bypasses` |
| Scripts multi-linha | `jwt_signature_bypass` tem script Python de ~15 linhas como payload. `csrf`/`oauth` têm formulários HTML multi-linha |
| Caracteres JSON-sensíveis | `"`, `'`, `<`, `>`, `\`, `{`, `}`, `\r\n`, `%00`, `&`, backticks — **escape obrigatório via serializer JSON** |

#### 1.1.5 Target Context — Mapeamento de Sub-Labels

| Sub-label | Presença | Mapeamento JSON |
|---|---|---|
| `**Parâmetros comuns:**` | 25/25 (3 dizem "não se aplica") | → `crawlerHints.parameters` |
| `**Paths comuns:**` | 22/25 | → `crawlerHints.paths` |
| `**Headers comuns:**` | 2/25 (cache_poisoning, crlf_injection) | → descartado (schema não tem `headers` — **futuro**) |
| `**Portas comuns:**` | 1/25 (infrastructure_exposure) | → descartado |
| `**Ativos comuns:**` | 1/25 (tls_weak_configuration) | → descartado |
| `**Sinais:**` | 25/25 | → descartado |

**Formato dos itens:** Backtick-quoted, separados por `, `. Exceção: `infrastructure_exposure` portas são números plain (`21, 22, 23...`).

**Edge cases:**
- `"não se aplica"` e variantes com parênteses (`"não se aplica (portas/serviços)"`) → array vazio, strip parênteses
- Itens com contexto entre parênteses (`` `key`, `value` (POST /env) ``) → extrair só o conteúdo dos backticks, descartar parênteses
- `infrastructure_exposure` NÃO tem `Paths comuns` → `paths: []`

### 1.2 Código Java Existente (Deep Review)

#### 1.2.1 Finding.java

```
Record(module, endpoint, title, severity:Severity, evidence, impact,
       reproduction, recommendation, cweId, cweTitle, cvssVector, cvssScore:double)
```

- 2 factory methods: `of(8 args)` auto-fill via CweRegistry, `of(12 args)` explicit
- `Severity` é enum: `CRITICAL, HIGH, MEDIUM, LOW, INFO`
- **Não precisa de alteração** — é dado de scan, não de KB

#### 1.2.2 CweRegistry.java

- 25 entries hardcoded em `Map<String, String[]>`
- Lookup é **case-sensitive, exact match** com `Map.getOrDefault`
- Fallback: `{"CWE-200", "Exposure of Sensitive Information", defaultVector(MEDIUM)}`
- **Chaves usam PascalCase** do scanner: `"XSS"`, `"SQLi"`, `"Actuator"`, `"CachePoisoning"`, etc.

#### 1.2.3 CvssCalculator.java

- Parser/calculator CVSS v3.1 completo
- Aceita vetores com e sem prefixo `CVSS:3.1/`
- Retorna `-1.0` para input inválido
- **Mantido como está**

#### 1.2.4 ReportEngine.java

- Usa Gson 2.11.0
- 3 exports: Generic (MD+JSON), HackerOne, Bugcrowd
- VRT map hardcoded com **21 entries** (faltam: HSTS, PQC, Infra, CSRF)
- Fallback VRT: `"other"`
- **Migrar para KB preenche os 4 gaps de VRT automaticamente**

#### 1.2.5 Build & Infra

- `build.gradle` (Groovy, não Kotlin). Gson `2.11.0` confirmado
- Java 27 toolchain, Shadow JAR
- **Zero uso de classpath resources** — nenhum `getResourceAsStream` no projeto inteiro
- `src/main/resources/` **não existe**
- 32 scanner modules referenciam `Finding.of()` ou `CweRegistry`

---

## 2. ACHADOS CRÍTICOS DO DEEP REVIEW

### 2.1 Module Key Case Mismatch (BLOQUEANTE)

| Camada | Formato | Exemplo |
|---|---|---|
| Scanner `id()` | PascalCase/UPPER | `"Actuator"`, `"CachePoisoning"`, `"SQLi"` |
| CweRegistry keys | PascalCase (= scanner) | `"Actuator"`, `"CachePoisoning"`, `"SQLi"` |
| .md `module:` field | **all-lowercase** | `"actuator"`, `"cachepoisoning"`, `"sqli"` |

**Solução:** O JSON usará **duas chaves de lookup**:
- Chave raiz do objeto: `id` snake_case do .md (ex: `"spring_actuator_exposure"`)
- Campo `module` dentro do entry: **PascalCase do scanner** (ex: `"Actuator"`)

O parser gerará um mapeamento `.md module → scanner PascalCase`:

| .md module | Scanner PascalCase |
|---|---|
| `xss` | `XSS` |
| `sqli` | `SQLi` |
| `ssrf` | `SSRF` |
| `csrf` | `CSRF` |
| `idor` | `IDOR` |
| `lfi` | `LFI` |
| `cmdinjection` | `CmdInjection` |
| `ssti` | `SSTI` |
| `xxe` | `XXE` |
| `cors` | `CORS` |
| `crlf` | `CRLF` |
| `hostheader` | `HostHeader` |
| `jwt` | `JWT` |
| `oauth` | `OAuth` |
| `massassign` | `MassAssign` |
| `graphql` | `GraphQL` |
| `cachepoisoning` | `CachePoisoning` |
| `reqsmuggling` | `ReqSmuggling` |
| `actuator` | `Actuator` |
| `openredirect` | `OpenRedirect` |
| `headers` | `Headers` |
| `hsts` | `HSTS` |
| `tls` | `TLS` |
| `infra` | `Infra` |
| `pqc` | `PQC` |

`KnowledgeBase.byModule(String)` fará lookup case-insensitive para tolerância.

### 2.2 CVSS Vector Divergência (2 módulos)

| Módulo | CweRegistry | .md file | Delta |
|---|---|---|---|
| HSTS | `AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N` (~5.9) | `AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N` (~3.1) | .md menos severo |
| PQC | `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` (~7.5) | `AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N` (~3.7) | .md menos severo |

**Decisão:** Os .md foram curados mais recentemente e com mais rigor. O KB JSON será a **source of truth**. Quando `CweRegistry` delegar ao KB, esses 2 módulos terão seus vetores corrigidos.

### 2.3 VRT Coverage Gap

ReportEngine VRT map tem 21 entries. Faltam 4:

| Módulo | VRT do .md (preencherá o gap) |
|---|---|
| HSTS | `server_security_misconfiguration.lack_of_security_headers.hsts` |
| PQC | `cryptographic_weakness.insufficient_entropy` |
| Infra | `server_security_misconfiguration.misconfigured_dns` |
| CSRF | `cross_site_request_forgery_csrf` |

### 2.4 Enriquecimento de Exports

HackerOne export atualmente usa campos do `Finding` (scan-level). Com o KB disponível:

| Campo Export | Hoje (Finding) | Com KB |
|---|---|---|
| Summary | `finding.impact()` (curto) | KB `summary` + finding-specific context |
| Description | `finding.evidence()` (técnico) | KB `description` como contexto + evidence como prova |
| Recommendation | `finding.recommendation()` (genérico) | KB `recommendation` (detalhado, com code examples) |

---

## 3. Arquitetura Proposta (Revisada)

### 3.1 Novo Record: `KnowledgeEntry`

```java
// src/main/java/gg/effront/anarcry/model/KnowledgeEntry.java
public record KnowledgeEntry(
    String title,
    String module,        // PascalCase do scanner (ex: "XSS", "SQLi")
    String severity,
    String cweId,
    String cweTitle,
    String cvssVector,    // formato bare (sem "CVSS:3.1/" prefix)
    String vrtId,
    String summary,
    String description,
    String impact,
    List<String> payloads,
    CrawlerHints crawlerHints,
    String recommendation
) {
    public record CrawlerHints(
        List<String> parameters,
        List<String> paths
    ) {}
}
```

### 3.2 Novo Loader: `KnowledgeBase`

```java
// src/main/java/gg/effront/anarcry/model/KnowledgeBase.java
```

Responsabilidades:
- Carregar `knowledge_base.json` do classpath via `getResourceAsStream`
- Deserializar com Gson em `Map<String, KnowledgeEntry>`
- Lookups: `byId(String)`, `byModule(String)` — **case-insensitive**
- Singleton thread-safe (holder pattern)
- Fallback: `Optional.empty()` para entries não encontradas

### 3.3 Recurso JSON

```
src/main/resources/knowledge_base.json
```

Objeto raiz onde cada chave é o `id` snake_case. Campo `module` dentro de cada entry usa PascalCase do scanner.

### 3.4 Migração Incremental

| Etapa | O que muda | Breaking? | Impacto nos 32 scanners |
|---|---|---|---|
| Criar `knowledge_base.json` + `src/main/resources/` | Adiciona recurso | Não | Nenhum |
| Criar `KnowledgeEntry` + `KnowledgeBase` | Adiciona classes novas | Não | Nenhum |
| `CweRegistry` delega para `KnowledgeBase` internamente | API pública inalterada; 2 vetores CVSS mudam (HSTS, PQC) | **Micro-break:** score de HSTS e PQC muda | Findings de HSTS/PQC terão score menor (mais preciso) |
| `ReportEngine` VRT delega para `KnowledgeBase` | API pública inalterada; 4 VRT gaps preenchidos | Não | Bugcrowd export de HSTS/PQC/Infra/CSRF ganha VRT real |

---

## 4. Tarefas (Sequência de Execução)

### Fase 1 — Gerar o JSON (esta sessão)

- [ ] **T1.1** Parser dos 25 .md com regras:
  - Parse front matter YAML (8 campos)
  - Conversão `module` lowercase → PascalCase via tabela de mapeamento
  - Conversão snake_case → camelCase nos campos (`cwe_id` → `cweId`, etc.)
  - Extração de seções: texto entre `## Header` e próximo `## Header`
  - Payloads: **apenas** blocos cercados dentro de `## Payloads and Bypasses` (NÃO incluir blocks de `## Recommendation`)
  - Payloads: cada linha não-vazia = 1 string. Manter comentários (`#`, `--`, `//`). Descartar prosa entre blocos ("Casos reais" etc.)
  - Target Context: regex `**Parâmetros comuns:**` → `parameters[]`, `**Paths comuns:**` → `paths[]`
  - Handle edge cases: "não se aplica" + parênteses → `[]`, itens com parênteses context → strip, ausência → `[]`
- [ ] **T1.2** Gerar `src/main/resources/knowledge_base.json`
- [ ] **T1.3** Validação:
  - 25 entries presentes
  - Todos os 13 campos em cada entry
  - `module` em PascalCase corresponde a CweRegistry key
  - `payloads` é array não-vazio em todos os 25
  - `crawlerHints.parameters` e `.paths` são arrays (podem ser `[]`)
  - JSON válido (parseable por Gson)

### Fase 2 — Integrar no Java

- [ ] **T2.1** Criar `src/main/resources/` (mkdir)
- [ ] **T2.2** Mover `knowledge_base.json` para `src/main/resources/`
- [ ] **T2.3** Criar `KnowledgeEntry.java` (record com inner record `CrawlerHints`)
- [ ] **T2.4** Criar `KnowledgeBase.java` (loader + lookups case-insensitive)
- [ ] **T2.5** Teste unitário: deserializar JSON completo, verificar 25 entries, spot-check campos
- [ ] **T2.6** Refatorar `CweRegistry` — delegar ao `KnowledgeBase`, manter API pública
- [ ] **T2.7** Refatorar `ReportEngine` VRT — delegar ao `KnowledgeBase`, manter API pública
- [ ] **T2.8** Testes de regressão: `Finding.of()` com todos os 25 module keys
- [ ] **T2.9** Verificar que HSTS e PQC agora usam os vetores corrigidos do KB

### Fase 3 — Consumo pelos Módulos (Sprints 16-18)

- [ ] **T3.1** Enriquecer exports HackerOne/Bugcrowd com `summary`, `description`, `recommendation` do KB
- [ ] **T3.2** CrawlerModule consome `crawlerHints` para guiar crawling
- [ ] **T3.3** Scanner modules podem consultar `payloads` do KB para injeção dinâmica

---

## 5. Decisões de Parsing (Revisadas)

### 5.1 Payloads

**Estratégia:** Extrair **apenas** blocos cercados dentro da seção `## Payloads and Bypasses`. Escopo delimitado por `## Payloads and Bypasses` (início) até o próximo `##` (fim). Blocks em `## Recommendation` são ignorados.

**Granularidade:** Cada linha não-vazia dentro de um bloco = 1 payload string. Scripts multi-linha (Python no jwt, HTML forms no csrf/oauth) são preservados **linha a linha** — o consumer que precisar reconstruir blocos contíguos poderá fazê-lo pela sequência do array.

**Comentários:** Mantidos (`# bypass WAF`, `-- SQL comment`, `// JS`). São contexto útil e baratos.

**"Casos reais":** Parágrafo de prosa após o último code block em todos os 25 arquivos. Descartado automaticamente porque não está dentro de fences.

### 5.2 Target Context

**Estratégia:** Regex para capturar linha após `**Parâmetros comuns:**` e `**Paths comuns:**`. Extrair itens entre backticks (`` ` ``). Split por `, `.

**Edge cases tratados:**
- `"não se aplica"` / `"não se aplica (portas/serviços)"` → `[]`
- Itens com contexto `(POST /env)` → strip parênteses, extrair só backticks
- Sub-label ausente (ex: `infrastructure_exposure` sem `Paths comuns`) → `[]`
- Sub-labels extras (`Headers comuns`, `Portas comuns`, `Ativos comuns`, `Sinais`) → descartadas do JSON v1

### 5.3 Texto das Seções

**Estratégia:** Extrair texto bruto entre `## Header` e próximo `## Header`. Trim whitespace. Manter Markdown inline (bold, code, links). Não converter para HTML.

### 5.4 Module PascalCase Mapping

Tabela hardcoded de 25 entries no parser. Validada contra as chaves reais do `CweRegistry.java`. Sem fuzzy matching — cada .md module tem correspondência exata.

---

## 6. Riscos e Mitigações (Revisados)

| Risco | Probabilidade | Mitigação |
|---|---|---|
| JSON com encoding quebrado (unicode, aspas em payloads) | Média | Serializer JSON nativo (não escape manual). Validar com Gson após geração |
| Module key mismatch quebra CweRegistry lookup | **Alta sem tratamento** | Tabela de mapeamento explícita + lookup case-insensitive no KnowledgeBase |
| CVSS score de HSTS/PQC muda (micro-break) | Certa | Documentar no changelog. Scores novos são mais precisos |
| Scanner module sem entry no KB (ex: Crawler) | Baixa | `KnowledgeBase.byModule()` retorna `Optional.empty()`. CweRegistry fallback mantido |
| Front matter .md muda no futuro | Baixa | Parser com fallback para campos ausentes. Validação pós-geração |
| Payloads de `## Recommendation` vazam para o array | **Alta sem tratamento** | Parser delimita escopo estritamente por seção `##` |

---

## 7. Schema JSON Final

```json
{
  "xss": {
    "title": "Cross-Site Scripting (XSS)",
    "module": "XSS",
    "severity": "CRITICAL",
    "cweId": "CWE-79",
    "cweTitle": "Improper Neutralization of Input During Web Page Generation",
    "cvssVector": "AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N",
    "vrtId": "cross_site_scripting_xss.reflected_xss",
    "summary": "...",
    "description": "...",
    "impact": "...",
    "payloads": ["<script>alert(1)</script>", "...", "..."],
    "crawlerHints": {
      "parameters": ["q", "search", "url", "..."],
      "paths": ["/search", "/redirect", "..."]
    },
    "recommendation": "..."
  }
}
```

---

## 8. Estimativa (Revisada)

| Fase | Esforço | Notas |
|---|---|---|
| Fase 1 (gerar JSON) | ~30-45 min | Mapeamento module + edge cases de Target Context adicionam complexidade |
| Fase 2 (integração Java) | ~1-2h | Case-insensitive lookup + testes de regressão para 25 modules |
| Fase 3 (consumo por módulos) | Sprints 16-18 | Dependência de CrawlerModule e enrichment de exports |

---

## 9. Próximo Passo

Após aprovação deste plano: executar **Fase 1** — parsing dos 25 .md e geração do `knowledge_base.json` com todas as regras e edge cases documentados acima.
