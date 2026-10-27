# AnarchCrypto v2 — PRD de Expansão

**Versão:** 2.0-draft  
**Data:** 2026-10-20  
**Projeto:** `gg.effront.anarchrypto`  
**Fontes mapeadas:** Payloads4All-master · CatSec-TryHackMe-WriteUps-main

---

## 1. Contexto

AnarchCrypto v1.0 cobre: TLS (versões, cipher suites, certificados), HTTP Security Headers, JWT (alg:none, HMAC brute-force, kid injection) e PQC detection.

Este PRD descreve o plano de expansão para v2.0, extraindo o máximo valor dos repositórios de referência acima e cobrindo os vetores mais comuns de bug bounty que envolvem criptografia, autenticação e controle de acesso.

---

## 2. Mapeamento de Fontes

### 2.1 Payloads4All-master — Categorias aproveitáveis

| Diretório | Relevância | Como usar no AnarchCrypto |
|---|---|---|
| `JSON Web Token/README.md` | ALTA | RS256→HS256, JWK injection, jku injection, null signature, signature disclosure |
| `CORS Misconfiguration/README.md` | ALTA | Origens refletidas, wildcard, credenciais com null origin |
| `OAuth Misconfiguration/README.md` | ALTA | redirect_uri bypass, state CSRF, token via referer |
| `Open Redirect/Intruder/{3 files}` | ALTA | Wordlist de 400+ payloads para params de redirect |
| `Server Side Request Forgery/README.md` | ALTA | SSRF via params comuns, cloud metadata endpoints |
| `GraphQL Injection/README.md` | MÉDIA | Introspecção habilitada, endpoints expostos |
| `CRLF Injection/crlfinjection.txt` | MÉDIA | 25 payloads de injeção em headers de resposta |
| `Request Smuggling/README.md` | MÉDIA | CL.TE / TE.CL desync detection |
| `SAML Injection/README.md` | BAIXA | Signature wrapping — requer SAML endpoint ativo |
| `Web Cache Deception/Intruder/param_miner_lowercase_headers.txt` | BAIXA | Cache poisoning via headers — complementar ao Headers module |

### 2.2 CatSec-TryHackMe-WriteUps-main — Valor extraível

Os writeups são majoritariamente educacionais (CTF walk-throughs com screenshots). Não contêm wordlists ou payloads inéditos. O valor está nos **padrões de ataque documentados** que embasam os textos de `impact`, `reproduction` e `recommendation` dos findings:

| Room | Técnica mapeada | Uso em AnarchCrypto |
|---|---|---|
| `Authenticate/README.md` | JWT brute-force, re-registration | Enriquece findings do JwtModule |
| `ZTH Obscure Web Vulns/README.md` | SSTI, CSRF, JWT, XXE | Base para reprodução de XXE/CSRF |
| `Hashing - Crypto 101/README.md` | MD5/SHA1 collisions, rainbow tables | Finding text de WeakHashModule (v2) |
| `Encryption - Crypto 101/README.md` | RSA, quantum computing | Finding text de PqcModule (já implementado) |
| `Overpass 2 - Hacked/README.md` | Backdoor em tokens de auth | Contextualiza ataques de privilege escalation |
| `WebAppSec 101/README.md` | OWASP top 10 intro | Estrutura de reprodução de findings |

---

## 3. Módulos Novos — Especificação

### MOD-01: CORS Module

**Categoria:** Auth / CORS  
**Severidade potencial:** CRITICAL (com `ACAO: *` + `ACAC: true`)

#### Vetores de probe (em ordem de envio)

| # | Origin enviada | Achado se refletida |
|---|---|---|
| 1 | `https://evil.com` | Origin reflection — permite leitura cross-origin de dados autenticados |
| 2 | `null` | Null origin accepted — sandbox iframe bypass |
| 3 | `https://<target>.evil.com` | Prefix bypass — regex mal configurada no servidor |
| 4 | `https://evil<target>` | Suffix bypass — regex case #2 |
| 5 | `https://notevil.com` | Wildcard sem restrição |

#### Condições de finding

- **CRITICAL:** `Access-Control-Allow-Origin` = origem injetada **E** `Access-Control-Allow-Credentials: true`
- **HIGH:** `Access-Control-Allow-Origin: *` em endpoint com cookies ou bearer token
- **MEDIUM:** `Access-Control-Allow-Origin: null`
- **INFO:** CORS ausente (não é vulnerabilidade, apenas informativo)

#### Endpoints alvo
Proba os paths: `/`, `/api/`, `/api/v1/`, `/api/v2/`, `/graphql`, `/user`, `/me`

#### Fonte
`Payloads4All-master/CORS Misconfiguration/README.md`

---

### MOD-02: JWT v2 — Extensão do JwtModule

**Mantém todos os probes v1 e adiciona:**

#### JWT-05: RS256 → HS256 Key Confusion (CVE-2016-5431)

**Severidade potencial:** CRITICAL

**Lógica:**
1. Detecta se token alvo usa `alg: RS256`
2. Extrai a chave pública do servidor: tenta `GET /` via TLS → extrai cert → extrai public key PEM → converte para bytes
3. Forge token com `alg: HS256`, assina com a public key como HMAC secret
4. Envia para endpoints de auth: `/api/me`, `/api/user`, `/api/profile`, `/api/v1/me`
5. Se HTTP 200 → CRITICAL

**Nota técnica:** usa Bouncy Castle `HMac` com `SHA256Digest` + `PEMParser` para extrair a chave pública do certificado TLS obtido via `CertificateProbe`.

**Fonte:** `Payloads4All-master/JSON Web Token/README.md` — seção "Key Confusion Attack RS256 to HS256 (CVE-2016-5431)"

---

#### JWT-06: JWK Header Injection (CVE-2018-0114)

**Severidade potencial:** CRITICAL

**Lógica:**
1. Detecta se token usa `alg: RS256`
2. Gera par RSA 2048 efêmero (Bouncy Castle `RSAKeyPairGenerator`)
3. Forja token com `alg: RS256` + header `jwk: {kty, kid, use, e, n}` contendo a chave pública gerada
4. Assina com a chave privada gerada
5. Envia para endpoints de auth
6. Se HTTP 200 → CRITICAL

**Fonte:** `Payloads4All-master/JSON Web Token/README.md` — seção "Key Injection Attack (CVE-2018-0114)"

---

#### JWT-07: jku Header Injection

**Severidade potencial:** HIGH

**Lógica (detecção passiva):**
1. Analisa header do token
2. Se campo `jku` presente → verifica se aponta para URL interna ou não-TLS
3. Finding HIGH: "jku header presente — servidor pode ser induzido a buscar JWKS de URL controlada pelo atacante"

**Nota:** probe ativo (hosting JWKS externo) requer infraestrutura, fica como detecção passiva com PoC instructions no finding.

**Fonte:** `Payloads4All-master/JSON Web Token/README.md` — seção "JWKS - jku header injection"

---

#### JWT-08: Null Signature (CVE-2020-28042)

**Severidade potencial:** HIGH

**Lógica:**
1. Detecta token com `alg: HS256`
2. Remove a signature (mantém o ponto final vazio: `header.payload.`)
3. Envia para endpoints de auth
4. Se HTTP 200 → HIGH

**Fonte:** `Payloads4All-master/JSON Web Token/README.md` — seção "Null Signature Attack (CVE-2020-28042)"

---

#### JWT-09: Signature Disclosure (CVE-2019-7644)

**Severidade potencial:** MEDIUM

**Lógica:**
1. Forja token com signature deliberadamente incorreta (1 byte alterado)
2. Envia para endpoint de auth
3. Parseia response body para padrões: `"Expected .* got"`, `"Invalid signature"`, `"correct signature"`
4. Se match com a signature correta no body → MEDIUM (server discloses valid sig)

**Fonte:** `Payloads4All-master/JSON Web Token/README.md` — seção "Disclosure of a correct signature (CVE-2019-7644)"

---

### MOD-03: OAuth Module

**Categoria:** Auth / OAuth  
**Severidade potencial:** CRITICAL (token theft via redirect)

#### Endpoints de descoberta
Detecta OAuth nos paths: `/oauth/`, `/oauth2/`, `/authorize`, `/auth`, `/.well-known/openid-configuration`

#### Probe OA-01: State Parameter Absent (CSRF)

**Severidade:** HIGH

Faz GET para o authorization endpoint; analisa se a URL de redirect contém parâmetro `state`. Se ausente → HIGH.

**Fonte:** `Payloads4All-master/OAuth Misconfiguration/README.md` — seção "Cross-Site Request Forgery"

#### Probe OA-02: redirect_uri Bypass Attempts

**Severidade:** CRITICAL

Se authorization endpoint detectado, testa variações de `redirect_uri`:
- `redirect_uri=https://evil.com`
- `redirect_uri=https://localhost.evil.com`
- `redirect_uri=https://accounts.google.com/BackToAuthSubTarget?next=https://evil.com`

Detecta se a resposta aceita a URI modificada (redirect 302 para domínio externo).

**Fonte:** `Payloads4All-master/OAuth Misconfiguration/README.md` — seção "Grabbing OAuth Token via redirect_uri"

#### Probe OA-03: Token via Referer

**Severidade:** HIGH

Se endpoint de callback detectado, verifica se a página inclui o token em link href ou meta refresh — exposto ao Referer header. Detecção passiva via análise do HTML.

---

### MOD-04: Open Redirect Module

**Categoria:** Redirect / Phishing  
**Severidade potencial:** MEDIUM (HIGH se encadeado com OAuth)

#### Wordlist de parâmetros (embutida no JAR)

Extraída de `Open Redirect/Intruder/Open-Redirect-payloads.txt` + `open_redirect_wordlist.txt` — aprox. 400 payloads.

Os parâmetros mais comuns a testar: `redirect`, `url`, `next`, `return`, `returnTo`, `return_url`, `redirect_url`, `continue`, `forward`, `dest`, `destination`, `go`, `goto`, `target`, `rurl`, `r`, `returnurl`.

#### Probe OR-01: Direct Injection

1. Faz GET para `/` e extrai todos os links e formulários com parâmetros de redirect
2. Injecta payloads: `https://evil.com`, `//evil.com`, `////evil.com`, `https:evil.com`, `\/\/evil.com`
3. Se resposta é 3xx com `Location` para domínio externo → MEDIUM

#### Probe OR-02: Filter Bypass

Payloads de bypass de filtro embutidos (do `Open Redirect/Intruder/`):
- `http://www.whitelisted.com.evil.com`
- `java%0d%0ascript%0d%0a:alert(0)` (CRLF+open redirect combo)
- `%2F%2Fevil.com`

**Fonte:** `Payloads4All-master/Open Redirect/`

---

### MOD-05: SSRF Module

**Categoria:** SSRF  
**Severidade potencial:** CRITICAL (acesso a metadados de cloud)

#### Endpoints alvo para injeção

Parâmetros comuns: `url`, `uri`, `path`, `fetch`, `load`, `src`, `href`, `image`, `img`, `resource`, `link`, `dest`, `data`, `api`.

Obtidos via: análise do HTML da página inicial, parâmetros de query string, e probe em endpoints comuns de APIs.

#### Probe SS-01: Localhost / Internal Probing

Payloads injetados (extraídos de `Server Side Request Forgery/README.md`):
```
http://localhost/
http://127.0.0.1/
http://0.0.0.0/
http://[::1]/
http://2130706433/  (decimal de 127.0.0.1)
http://0177.0.0.01/ (octal)
```

Se resposta diferenciada (tempo, tamanho, conteúdo) → HIGH.

#### Probe SS-02: Cloud Metadata Endpoints

Endpoints de IMDS dos principais provedores:
- AWS: `http://169.254.169.254/latest/meta-data/`
- GCP: `http://metadata.google.internal/computeMetadata/v1/`
- Azure: `http://169.254.169.254/metadata/instance?api-version=2021-02-01`
- Digital Ocean: `http://169.254.169.254/metadata/v1/`

Se HTTP 200 com conteúdo de metadata → CRITICAL.

#### Probe SS-03: File Protocol

Payload: `file:///etc/passwd`, `file:///c:/windows/win.ini`

**Fonte:** `Payloads4All-master/Server Side Request Forgery/README.md`

---

### MOD-06: GraphQL Module

**Categoria:** API / Information Disclosure  
**Severidade potencial:** HIGH (introspecção exposta) → CRITICAL (mutations não autenticadas)

#### Probe GQ-01: Endpoint Discovery

Paths testados: `/graphql`, `/graphiql`, `/api/graphql`, `/api/v1/graphql`, `/query`, `/gql`

Método: GET + POST com body `{"query":"{__typename}"}`

#### Probe GQ-02: Introspection Enabled

Query:
```graphql
{__schema{types{name}}}
```

Se resposta contém `__schema` → HIGH (vazamento de schema completo da API).

#### Probe GQ-03: Error Verbosity

Queries intencionalmente inválidas: `{thisdoesnotexist}`, `{}`, `{__schema`

Se stack trace ou nome de framework visível → MEDIUM.

#### Probe GQ-04: Batching / Rate Limit Bypass

Envia array de queries (batching): `[{"query":"{__typename}"},{"query":"{__typename}"}]` × 10

Se todas retornam 200 → INFO (GraphQL batching habilitado — pode facilitar brute-force).

**Fonte:** `Payloads4All-master/GraphQL Injection/README.md`

---

### MOD-07: CRLF Injection Module

**Categoria:** Header Injection  
**Severidade potencial:** MEDIUM (cookie injection) → HIGH (XSS via response splitting)

#### Payloads embutidos

25 payloads do arquivo `Payloads4All-master/CRLF Injection/crlfinjection.txt`:
```
/%0d%0aSet-Cookie:crlf=injection
/%250aSet-Cookie:crlf=injection
/%0aSet-Cookie:crlf=injection
/%u000aSet-Cookie:crlf=injection
/%2F..%0d%0aSet-Cookie:crlf=injection
... (25 variações com encoding diferente)
```

#### Probe CR-01: Path Injection

1. Faz GET para `<target><payload>` para cada payload
2. Analisa headers de resposta: se `Set-Cookie: crlf=injection` presente → HIGH
3. Analisa body: se conteúdo de resposta injetado → MEDIUM

#### Probe CR-02: Query Param Injection

Para cada parâmetro detectado na página, injeta `param=value%0d%0aSet-Cookie:crlf=injection`

**Fonte:** `Payloads4All-master/CRLF Injection/crlfinjection.txt`

---

### MOD-08: Request Smuggling Detector

**Categoria:** HTTP Desync  
**Severidade potencial:** HIGH (bypass de controles de segurança, cache poisoning)

#### Probe RS-01: CL.TE Probe

Envia request com `Content-Length: 4` e `Transfer-Encoding: chunked` conflitantes. Mede timing diferencial — se segunda request é processada com body "smuggled" → HIGH.

```
POST / HTTP/1.1
Host: <target>
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED
```

#### Probe RS-02: TE.CL Probe

Variante com `Transfer-Encoding` no front-end, `Content-Length` no back-end.

#### Condição de detecção

Diferença de timing > 5s entre request normal e request smuggled → MEDIUM (timing inconsistency, possível desync).

**Nota:** detecção 100% é difícil sem backend de callbacke. Módulo reporta indício para investigação manual.

**Fonte:** `Payloads4All-master/Request Smuggling/README.md`

---

## 4. Melhorias de TUI (v2)

### TUI-01: Log Coloring

Colorir linhas do log por prefixo:

| Prefixo | Cor (Lanterna TextColor) |
|---|---|
| `[*]` | ANSI.CYAN (info neutro) |
| `[✓]` / `[+]` | ANSI.GREEN_BRIGHT (sucesso) |
| `[!]` | ANSI.YELLOW_BRIGHT (aviso) |
| `[!!]` / `CRITICAL` | ANSI.RED_BRIGHT (crítico) |

Implementação: substituir `TextBox` do LogPanel por `Panel` com `Label` por linha, cada uma com cor baseada no prefixo.

### TUI-02: Findings ordenados por severidade

`FindingsPanel.addFinding()` atualmente adiciona ao final. Em v2, inserir em posição ordenada: CRITICAL → HIGH → MEDIUM → LOW → INFO.

### TUI-03: [C] Copy curl em modal de finding

No `showFindingDetail()`, adicionar botão `[C] Copiar curl` que monta um comando `curl` baseado no campo `reproduction` do finding e copia para o clipboard via `xclip`/`xsel`/`wl-copy`.

### TUI-04: Barra de progresso de scan

Adicionar indicador de progresso na titlebar: `[Scanning 3/7 modules...]` durante scan ativo.

### TUI-05: Filtro de severidade no FINDINGS

Adicionar teclas de atalho para filtrar findings no painel:
- `F1` → mostrar todos
- `F2` → apenas CRITICAL/HIGH
- `F3` → apenas MEDIUM/LOW

---

## 5. User Stories v2

### Sprint 1 — JWT Completude (alta prioridade, sem dependências externas)

| ID | Story | Módulo | Complexidade |
|---|---|---|---|
| US-201 | Como pentester, quero detectar RS256→HS256 confusion pra revelar falha crítica de validação | JwtModule | ALTA |
| US-202 | Como pentester, quero detectar JWK injection pra identificar servidores que confiam em chaves embutidas no token | JwtModule | ALTA |
| US-203 | Como pentester, quero detectar jku presente no header pra sinalizar possibilidade de JWKS hijacking | JwtModule | BAIXA |
| US-204 | Como pentester, quero probar null signature pra identificar servidores que aceitam tokens sem assinatura | JwtModule | MÉDIA |
| US-205 | Como pentester, quero detectar signature disclosure pra identificar APIs que retornam a assinatura correta em erros | JwtModule | MÉDIA |

### Sprint 2 — CORS e OAuth (alta prioridade, alto ROI em bug bounty)

| ID | Story | Módulo | Complexidade |
|---|---|---|---|
| US-206 | Como pentester, quero probar origin reflection CORS com credentials pra detectar exfiltração cross-origin | CorsModule | MÉDIA |
| US-207 | Como pentester, quero detectar CORS null origin pra identificar bypass via iframe sandbox | CorsModule | BAIXA |
| US-208 | Como pentester, quero detectar OAuth sem state parameter pra identificar CSRF no fluxo de autorização | OAuthModule | MÉDIA |
| US-209 | Como pentester, quero testar redirect_uri bypass pra identificar token theft via open redirect | OAuthModule | ALTA |

### Sprint 3 — Módulos de API (médio prazo)

| ID | Story | Módulo | Complexidade |
|---|---|---|---|
| US-210 | Como pentester, quero testar open redirect em parâmetros comuns pra encontrar vetores de phishing e chain com OAuth | OpenRedirectModule | MÉDIA |
| US-211 | Como pentester, quero probar SSRF em parâmetros de URL pra acessar metadados de cloud e serviços internos | SsrfModule | ALTA |
| US-212 | Como pentester, quero detectar GraphQL com introspecção habilitada pra mapear toda a API | GraphQLModule | MÉDIA |
| US-213 | Como pentester, quero probar CRLF injection em paths e params pra injetar cookies e causar response splitting | CrlfModule | MÉDIA |

### Sprint 4 — TUI e Qualidade

| ID | Story | Módulo | Complexidade |
|---|---|---|---|
| US-214 | Como usuário, quero log com cores por severidade pra identificar achados críticos de forma visual | TUI | MÉDIA |
| US-215 | Como usuário, quero findings ordenados por severidade pra priorizar investigação | TUI | BAIXA |
| US-216 | Como usuário, quero copiar o curl de reprodução com [C] no modal pra acelerar validação | TUI | BAIXA |
| US-217 | Como usuário, quero barra de progresso do scan pra saber quantos módulos já finalizaram | TUI | BAIXA |

---

## 6. Harness v2 — Casos de Teste Adicionais

### JWT v2 Tests (6 novos)

| Teste | Tipo | Servidor mock |
|---|---|---|
| `jwtNullSignatureDetected` | Local | Aceita token sem signature → HMAC check |
| `jwtNullSignatureActiveFails` | Local | Não aceita → sem finding |
| `jwtSignatureDisclosureDetected` | Local | Retorna `Expected X got Y` no body |
| `jwtJkuHeaderDetected` | Fast | Decode de token com jku no header |
| `jwtRs256Hs256Detected` | Fast | Detecta alg RS256 no token para flag de probe |
| `jwtJwkInjectionSkipsNonRsa` | Fast | Não roda probe em HS256 |

### CORS Tests (4)

| Teste | Tipo | Mock |
|---|---|---|
| `corsCriticalOriginReflectionWithCredentials` | Local | ACAO=evil.com + ACAC=true |
| `corsHighWildcardWithCredentials` | Local | ACAO=* → HIGH |
| `corsMediumNullOrigin` | Local | ACAO=null |
| `corsCleanNoFinding` | Local | Sem CORS headers → sem finding |

### OAuth Tests (3)

| Teste | Tipo | Mock |
|---|---|---|
| `oauthStateParamMissingDetected` | Local | /authorize sem state |
| `oauthStateParamPresentNoFinding` | Local | /authorize com state |
| `oauthEndpointNotFoundNoFinding` | Local | Servidor sem /oauth |

### Open Redirect Tests (2)

| Teste | Tipo | Mock |
|---|---|---|
| `openRedirectDetectedDirectParam` | Local | 302 Location: evil.com |
| `openRedirectCleanNoFinding` | Local | 302 Location: /home |

### GraphQL Tests (3)

| Teste | Tipo | Mock |
|---|---|---|
| `graphqlIntrospectionDetected` | Local | `__schema` visível |
| `graphqlEndpointNotFoundNoFinding` | Local | Sem /graphql |
| `graphqlErrorVerbosityDetected` | Local | Stack trace em query inválida |

### CRLF Tests (2)

| Teste | Tipo | Mock |
|---|---|---|
| `crlfInjectionDetectedPathParam` | Local | Response com Set-Cookie injetado |
| `crlfInjectionNotReflectedNoFinding` | Local | Payload sanitizado |

**Total harness v2:** 15 (v1) + 20 (v2) = **35 testes**

---

## 7. Arquitetura de Classes — Novos Módulos

```
scanner/
  cors/
    CorsModule.java          — implementa Scanner, orquestra probes
    CorsProbe.java           — lógica de HTTP + análise de headers
  oauth/
    OAuthModule.java
    OAuthDiscovery.java      — detecção de endpoints OAuth
    StateParamProbe.java
    RedirectUriProbe.java
  redirect/
    OpenRedirectModule.java
    RedirectPayloads.java    — wordlist embutida (recurso em src/main/resources/)
  ssrf/
    SsrfModule.java
    SsrfPayloads.java        — localhost + cloud metadata URLs
    SsrfProbe.java           — timing differential + response analysis
  graphql/
    GraphQLModule.java
    GraphQLProbe.java        — endpoint discovery + introspection query
  crlf/
    CrlfModule.java
    CrlfPayloads.java        — 25 payloads do Payloads4All embutidos
    CrlfProbe.java

scanner/jwt/
  Rs256Hs256Probe.java       — CVE-2016-5431
  JwkInjectionProbe.java     — CVE-2018-0114
  NullSignatureProbe.java    — CVE-2020-28042
  SignatureDisclosureProbe.java — CVE-2019-7644
  JkuHeaderAnalyzer.java     — detecção passiva de jku

tui/panels/
  LogPanel.java              — v2: Label colorido por linha
  FindingsPanel.java         — v2: inserção ordenada por severidade
```

---

## 8. Novas Dependências

Nenhuma dependência nova de runtime necessária para v2. Todos os probes usam:
- `java.net.http.HttpClient` (JDK built-in)
- `javax.net.ssl.SSLSocket` via Bouncy Castle (já presente)
- `org.bouncycastle.crypto.generators.RSAKeyPairGenerator` (já presente em bcprov)

---

## 9. Priorização

```
Sprint 1 (imediato):  US-201 a 205  — JWT v2
Sprint 2 (próxima):   US-206 a 209  — CORS + OAuth  
Sprint 3 (médio):     US-210 a 213  — API modules
Sprint 4 (last):      US-214 a 217  — TUI polish
```

**Critério:** sprints 1 e 2 têm maior ROI em bug bounty, não requerem infraestrutura externa (callback servers), e aproveitam código já existente (JWT/TLS infrastructure).

---

## 10. Fora de Escopo (v2)

- **Request Smuggling ativo:** detecção definitiva requer timing preciso e múltiplas conexões — complexidade alta, falso-positivo frequente. Pode ser explorado em v3 como módulo experimental com flag `--experimental`.
- **SAML:** requer endpoint SAML ativo e parsing de XML com assinatura — baixíssima prevalência em bug bounty moderno.
- **XXE:** alto risco de causar side effects no servidor alvo (OOB requests a partir do servidor). Fica para v3 com opt-in explícito.
- **SSTI:** requer injeção em campos de formulário — fora do escopo de scanner de criptografia/auth.
