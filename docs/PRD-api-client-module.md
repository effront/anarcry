# PRD: API Client Module (Bruno-inspired)

**Data:** 2026-11-06
**Autor:** Yatari Security
**Status:** Draft
**Versao alvo:** 2.1.0

---

## 1. Problema

AnarCry e um scanner automatizado - descobre vulns com modulos pre-definidos (XSS, SQLi, IDOR, etc). Mas pentests reais exigem **interacao manual com a API do alvo**: testar fluxos de negocio, encadear requests, manipular parametros, trocar auth entre usuarios. Hoje o pentester precisa:

1. Abrir um client separado (Bruno, Postman, Insomnia, curl) pra testes manuais
2. Copiar tokens/cookies do AnarCry pro client externo e vice-versa
3. Perder contexto WAF (stealth mode, cookie rotation, circuit breaker)
4. Duplicar trabalho: endpoints ja descobertos pelo CrawlerModule precisam ser re-criados manualmente
5. Resultados manuais ficam fora do report final

**Impacto real (caso Duma Finance - 2026-11-06):** Das 13 vulns encontradas, 7 vieram de teste manual (account takeover chain, phone change sem senha, delete sem confirmacao, overflow de transacao, precisao float). O scanner encontrou 6. Um client integrado teria acelerado os testes manuais e centralizado evidencias no report.

---

## 2. Solucao

Modulo de API Client integrado ao AnarCry com:

- **Collections**: arvore de pastas e requests persistidos em JSON no filesystem (Git-friendly)
- **Environments**: variaveis por ambiente (dev, staging, prod) com secrets separados
- **Request builder**: URL, method, params (query/path), headers, body (JSON/form/multipart/XML/GraphQL/file), auth (12 modos)
- **Variable interpolation**: `{{var}}` em URL, headers, body, auth fields
- **Runner**: execucao sequencial de collections com chaining entre requests
- **Assertions**: validacao declarativa de responses (status, body, headers, timing)
- **Import**: Postman, OpenAPI 3.0, Bruno .bru collections
- **Integracao AnarCry**: compartilha Http.send() (WAF-aware), CredentialStore, findings alimentam report

---

## 3. Analise do Bruno (referencia)

### 3.1 Arquitetura Bruno

Monorepo com 18 packages. Os relevantes pro port:

| Package | Funcao | Decisao pro AnarCry |
|---------|--------|---------------------|
| bruno-lang | Parser .bru (Ohm.js PEG grammar) | Implementar importer, nao o DSL inteiro - usar JSON nativo |
| bruno-common | Interpolation engine (`{{var}}` com recursao e circular detection) | Portar pra Java - core do sistema de variaveis |
| bruno-requests | Axios + auth helpers (OAuth2, Digest, NTLM, AWS SigV4) | Integrar com Http.send() existente + novos auth injectors |
| bruno-js | Scripting runtime (QuickJS/NodeVM) com API bru/req/res | Substituir por Java lambdas + Groovy scripts (opcional) |
| bruno-schema | Yup validation schemas | Records Java com validacao no construtor |
| bruno-converters | Import Postman/OpenAPI/Insomnia | Implementar importers como classes separadas |

### 3.2 Collection Format Bruno vs AnarCry

**Bruno**: cada request e um arquivo `.bru` com DSL custom. Vantagem: diff-friendly. Desvantagem: parser complexo.

**AnarCry (proposta)**: cada collection e um diretorio com arquivos JSON.

```
collections/
  duma-finance/
    collection.json       # metadata, default auth, default headers, scripts
    environments/
      production.json     # variables para producao
      staging.json
    auth/
      login.json          # request: POST /auth/login
      register.json
    users/
      folder.json         # folder-level headers, auth, vars
      get-me.json         # request: GET /users/me
      patch-me.json       # request: PATCH /users/me
      delete-me.json      # request: DELETE /users/me
    transactions/
      folder.json
      create.json
      list.json
      export-csv.json
```

### 3.3 Request Model (baseado no Bruno, adaptado)

```json
{
  "meta": {
    "name": "patch-me",
    "type": "http",
    "seq": 3
  },
  "request": {
    "method": "PATCH",
    "url": "{{baseUrl}}/api/v1/users/me",
    "params": {
      "query": [
        {"name": "fields", "value": "name,phone", "enabled": true}
      ],
      "path": [
        {"name": "userId", "value": "{{userId}}", "enabled": true}
      ]
    },
    "headers": [
      {"name": "Content-Type", "value": "application/json", "enabled": true},
      {"name": "Authorization", "value": "Bearer {{accessToken}}", "enabled": true},
      {"name": "X-Debug", "value": "true", "enabled": false}
    ],
    "auth": {
      "mode": "bearer",
      "bearer": {"token": "{{accessToken}}"}
    },
    "body": {
      "mode": "json",
      "json": "{\"phone\": \"{{attackerPhone}}\"}"
    }
  },
  "vars": {
    "pre": [
      {"name": "timestamp", "value": "{{$timestamp}}"}
    ],
    "post": [
      {"name": "updatedPhone", "value": "res.body.phone"}
    ]
  },
  "assertions": [
    {"lhs": "res.status", "op": "eq", "rhs": "200"},
    {"lhs": "res.body.phone", "op": "eq", "rhs": "{{attackerPhone}}"},
    {"lhs": "res.responseTime", "op": "lt", "rhs": "2000"}
  ],
  "docs": "Testa alteracao de telefone sem senha - VULN-0B PoC"
}
```

### 3.4 Environment Model

```json
{
  "name": "production",
  "color": "#CC0000",
  "variables": [
    {"name": "baseUrl", "value": "https://api.dumafinance.com.br", "secret": false, "enabled": true},
    {"name": "accessToken", "value": "", "secret": true, "enabled": true},
    {"name": "attackerPhone", "value": "5511999999999", "secret": false, "enabled": true},
    {"name": "victimUserId", "value": "280e8c20-4267-4764-94f5-15292e71b564", "secret": false, "enabled": true}
  ],
  "extends": null
}
```

### 3.5 Auth Modes (12 - compativel Bruno)

| Modo | Campos | Injecao |
|------|--------|---------|
| none | - | - |
| inherit | - | Herda de folder/collection |
| basic | username, password | Header `Authorization: Basic base64(user:pass)` |
| bearer | token | Header `Authorization: Bearer <token>` |
| digest | username, password | Challenge-response RFC 7616 |
| ntlm | username, password, domain | NTLM handshake |
| oauth1 | consumerKey, consumerSecret, accessToken, tokenSecret, signatureMethod, placement | OAuth 1.0a signature |
| oauth2 | grantType, accessTokenUrl, clientId, clientSecret, scope, callbackUrl, pkce, credPlacement, tokenPlacement, autoRefresh | OAuth 2.0 flow (4 grant types) |
| apikey | key, value, placement (header/query) | Header ou query param |
| awsv4 | accessKeyId, secretAccessKey, sessionToken, service, region | AWS Signature V4 |
| wsse | username, password | X-WSSE header |
| akamai-edgegrid | accessToken, clientToken, clientSecret | Akamai EdgeGrid auth |

### 3.6 Variable Interpolation (port do Bruno)

**Algoritmo**:
1. Merge variables por precedencia: runtime > request > folder > env > collection > global > process.env
2. Para cada string com `{{var}}`:
   - Resolve `var` no mapa merged
   - Se o valor contem `{{outraVar}}`, resolve recursivamente
   - Circular detection via Set de visitados
   - `{{$timestamp}}`, `{{$randomInt}}`, `{{$guid}}` sao funcoes built-in
3. Aplica em: URL, headers (name+value), params (name+value), body, auth fields
4. JSON string escaping quando dentro de body JSON

**Precedencia (highest wins)**:
```
runtimeVariables      (set por scripts/vars:post-response durante execucao)
requestVariables      (vars:pre-request do request)
folderVariables       (folder.json vars)
envVariables          (environment selecionado)
collectionVariables   (collection.json vars)
processEnvVars        (System.getenv())
```

### 3.7 Runner Pipeline

```
Para cada request na collection (sequencial):

1. MERGE       - folder headers/auth/vars cascade pra request
2. PRE-VARS    - resolve vars:pre-request
3. INTERPOLATE - {{var}} em URL, headers, body, auth, params
4. AUTH INJECT  - aplica auth mode (Bearer header, Basic header, OAuth2 token fetch, etc)
5. HTTP SEND   - via Http.send() (WAF-aware, stealth, cookie rotation)
6. POST-VARS   - extrai vars:post-response do response (ex: token = res.body.access_token)
7. ASSERTIONS  - valida res.status, res.body.*, res.headers.*, res.responseTime
8. RECORD      - salva request/response pair como evidencia
```

**Flow control**:
- `setNextRequest("name")` - pula pra request especifico (chaining)
- `stopExecution()` - para o runner
- `skipRequest()` - pula o request atual
- Max jumps: 10,000 (previne loop infinito)

### 3.8 Exemplo real: Duma Finance ATO chain como collection

```
duma-finance-ato/
  collection.json
  environments/
    prod.json              # baseUrl, hCaptchaKey
  01-login/
    login.json             # POST /auth/login -> extrai accessToken
  02-recon/
    get-profile.json       # GET /users/me -> extrai phone original
    list-accounts.json     # GET /accounts -> extrai accountId
  03-exploit/
    change-phone.json      # PATCH /users/me {phone: attackerPhone} -> assert 200
    verify-change.json     # GET /users/me -> assert phone == attackerPhone
    trigger-reset.json     # POST /auth/password/forgot {channel: WHATSAPP}
  04-cleanup/
    restore-phone.json     # PATCH /users/me {phone: ""} -> restaura
```

Runner executa em ordem, extraindo tokens e dados entre requests. Report final inclui cada request/response como evidencia de PoC.

---

## 4. Arquitetura no AnarCry

### 4.1 Package Structure

```
src/main/java/gg/effront/anarcry/
  apiclient/
    model/
      Collection.java           # record: name, environments, items, rootConfig
      Environment.java          # record: name, color, variables, extends
      EnvVariable.java          # record: name, value, secret, enabled, type
      Folder.java               # record: name, items, rootConfig
      RequestItem.java          # record: meta, request, vars, assertions, docs
      RequestMeta.java          # record: name, type, seq
      HttpRequest.java          # record: method, url, params, headers, auth, body, settings
      Param.java                # record: name, value, type(QUERY/PATH), enabled
      Header.java               # record: name, value, enabled
      AuthConfig.java           # sealed interface + records per mode
      BodyConfig.java           # sealed interface + records per mode (JsonBody, FormBody, etc)
      Assertion.java            # record: lhs, operator, rhs, enabled
      RequestSettings.java      # record: followRedirects, timeout, encodeUrl
      RunResult.java            # record: items[], summary, duration
      RequestResult.java        # record: request, response, assertions[], timing, passed
      ResponseData.java         # record: status, statusText, headers, body, responseTime, size
    vars/
      VariableStore.java        # hierarchical variable storage (collection > env > folder > request > runtime)
      Interpolator.java         # {{var}} resolution with recursion + circular detection
      BuiltInFunctions.java     # $timestamp, $randomInt, $guid, $randomEmail, etc
    auth/
      AuthInjector.java         # interface: inject(HttpRequest, AuthConfig, VariableStore) -> HttpRequest
      BasicAuthInjector.java
      BearerAuthInjector.java
      DigestAuthInjector.java
      OAuth2Injector.java       # 4 grant types, token cache, auto-refresh
      ApiKeyInjector.java
      AwsV4Injector.java
      NtlmInjector.java
      OAuth1Injector.java
      WsseInjector.java
      EdgeGridInjector.java
      AuthInjectorRegistry.java # maps AuthMode -> AuthInjector
    runner/
      CollectionRunner.java     # sequential execution with flow control
      RequestExecutor.java      # single request lifecycle (7 phases)
      AssertionEngine.java      # evaluates assertions against response
      RunContext.java           # runtime state: variables, cookie jar, results, flow control
    io/
      CollectionLoader.java     # loads collection from filesystem (JSON)
      CollectionWriter.java     # saves collection to filesystem
      BruImporter.java          # imports Bruno .bru collections
      PostmanImporter.java      # imports Postman v2.1 collections
      OpenApiImporter.java      # imports OpenAPI 3.0 specs as collections
      CurlImporter.java         # parses curl commands into requests
    report/
      CollectionReportEngine.java  # exports run results as MD/HTML/JSON with evidence
```

### 4.2 Integracao com componentes existentes

| Componente existente | Como integra |
|---------------------|--------------|
| `Http.send()` | RequestExecutor usa Http.send() pra dispatch - herda WAF handling, stealth, cookie rotation, circuit breaker |
| `CredentialStore` | OAuth2Injector delega token lifecycle pro CredentialStore existente |
| `ScanContext` | CollectionRunner recebe ScanContext pra compartilhar auth e config do scan |
| `ReportEngine` | CollectionReportEngine gera secoes de evidencia que o ReportEngine principal inclui |
| `CrawlerModule` | Endpoints descobertos pelo crawler podem ser exportados como collection skeleton |
| `ExploitOrchestrator` | Findings do collection run alimentam Phase 3 (exploitation validation) |
| `ProbeExecutor` | Reutiliza pra timeout e cancelamento de requests |
| TUI/GUI | Nova tab/panel "API Client" com tree view de collection + request editor + response viewer |

### 4.3 Fluxo de dados

```
                    +-----------------+
                    |  CrawlerModule  |  (discovered endpoints)
                    +--------+--------+
                             |
                             v
+----------------+   +------+------+   +-----------------+
| Bruno .bru     |-->|  Collection  |<--| Postman/OpenAPI |
| Import         |   |  (JSON fs)  |   | Import          |
+----------------+   +------+------+   +-----------------+
                             |
                     +-------+-------+
                     |               |
              +------v------+  +-----v------+
              |  TUI Panel  |  | GUI Panel  |
              | (edit/run)  |  | (edit/run) |
              +------+------+  +-----+------+
                     |               |
                     v               v
              +------+---------------+------+
              |     CollectionRunner         |
              |  (sequential + chaining)     |
              +------+----------------------+
                     |
              +------v------+
              | Http.send() | (WAF-aware, stealth, cookies)
              +------+------+
                     |
              +------v------+
              | RunResult   | (request/response pairs + assertions)
              +------+------+
                     |
         +-----------+-----------+
         |                       |
  +------v------+     +---------v----------+
  | ReportEngine|     | ExploitOrchestrator|
  | (evidence)  |     | (validate findings)|
  +-------------+     +--------------------+
```

---

## 5. Data Models (Java records)

### 5.1 Collection

```java
public record Collection(
    String uid,
    String name,
    String version,
    List<Environment> environments,
    List<CollectionItem> items,      // Folder | RequestItem
    RootConfig root,                 // default headers, auth, vars
    CollectionSettings settings      // proxy, clientCerts, timeout defaults
) {}

public sealed interface CollectionItem permits Folder, RequestItem {
    String uid();
    String name();
}

public record Folder(
    String uid,
    String name,
    List<CollectionItem> items,
    RootConfig root
) implements CollectionItem {}

public record RootConfig(
    List<Header> headers,
    AuthConfig auth,
    List<EnvVariable> vars
) {}
```

### 5.2 Request

```java
public record RequestItem(
    String uid,
    String name,
    RequestMeta meta,
    HttpRequestDef request,
    VarsDef vars,
    List<Assertion> assertions,
    String docs
) implements CollectionItem {}

public record HttpRequestDef(
    String method,
    String url,
    ParamsDef params,
    List<Header> headers,
    AuthConfig auth,
    BodyConfig body,
    RequestSettings settings
) {}

public record ParamsDef(
    List<Param> query,
    List<Param> path
) {}
```

### 5.3 Auth (sealed hierarchy)

```java
public sealed interface AuthConfig {
    String mode();

    record None() implements AuthConfig { public String mode() { return "none"; } }
    record Inherit() implements AuthConfig { public String mode() { return "inherit"; } }
    record Basic(String username, String password) implements AuthConfig { public String mode() { return "basic"; } }
    record Bearer(String token) implements AuthConfig { public String mode() { return "bearer"; } }
    record Digest(String username, String password) implements AuthConfig { public String mode() { return "digest"; } }
    record Ntlm(String username, String password, String domain) implements AuthConfig { public String mode() { return "ntlm"; } }
    record ApiKey(String key, String value, String placement) implements AuthConfig { public String mode() { return "apikey"; } }
    record OAuth2(
        String grantType, String accessTokenUrl, String refreshTokenUrl,
        String clientId, String clientSecret, String scope, String callbackUrl,
        String authorizationUrl, boolean pkce, String credPlacement,
        String tokenPlacement, boolean autoRefresh, boolean autoFetch,
        Map<String, String> additionalParams
    ) implements AuthConfig { public String mode() { return "oauth2"; } }
    record AwsV4(
        String accessKeyId, String secretAccessKey, String sessionToken,
        String service, String region
    ) implements AuthConfig { public String mode() { return "awsv4"; } }
    record OAuth1(
        String consumerKey, String consumerSecret, String accessToken,
        String tokenSecret, String signatureMethod, String placement
    ) implements AuthConfig { public String mode() { return "oauth1"; } }
    record Wsse(String username, String password) implements AuthConfig { public String mode() { return "wsse"; } }
    record EdgeGrid(
        String accessToken, String clientToken, String clientSecret
    ) implements AuthConfig { public String mode() { return "akamai-edgegrid"; } }
}
```

### 5.4 Body (sealed hierarchy)

```java
public sealed interface BodyConfig {
    String mode();

    record None() implements BodyConfig { public String mode() { return "none"; } }
    record Json(String content) implements BodyConfig { public String mode() { return "json"; } }
    record Text(String content) implements BodyConfig { public String mode() { return "text"; } }
    record Xml(String content) implements BodyConfig { public String mode() { return "xml"; } }
    record FormUrlEncoded(List<Param> params) implements BodyConfig { public String mode() { return "formUrlEncoded"; } }
    record MultipartForm(List<MultipartField> fields) implements BodyConfig { public String mode() { return "multipartForm"; } }
    record GraphQL(String query, String variables) implements BodyConfig { public String mode() { return "graphql"; } }
    record FileBody(String filePath, String contentType) implements BodyConfig { public String mode() { return "file"; } }

    record MultipartField(String name, String value, String type, String filePath, String contentType, boolean enabled) {}
}
```

### 5.5 Assertion

```java
public record Assertion(String lhs, AssertOp op, String rhs, boolean enabled) {}

public enum AssertOp {
    EQ, NEQ, GT, GTE, LT, LTE,
    IN, NOT_IN, CONTAINS, NOT_CONTAINS,
    LENGTH, MATCHES, NOT_MATCHES,
    STARTS_WITH, ENDS_WITH, BETWEEN,
    IS_NULL, IS_UNDEFINED, IS_DEFINED,
    IS_TRUTHY, IS_FALSY, IS_JSON,
    IS_NUMBER, IS_STRING, IS_BOOLEAN, IS_ARRAY,
    IS_EMPTY, IS_NOT_EMPTY;
}
```

---

## 6. Interpolation Engine

### 6.1 Algoritmo (port do Bruno)

```java
public class Interpolator {
    private static final Pattern VAR_PATTERN = Pattern.compile("\\{\\{(.+?)}}");
    private static final int MAX_DEPTH = 10;

    public String interpolate(String template, VariableStore vars) {
        return interpolate(template, vars, new HashSet<>(), 0);
    }

    private String interpolate(String template, VariableStore vars, Set<String> visited, int depth) {
        if (template == null || depth > MAX_DEPTH) return template;

        return VAR_PATTERN.matcher(template).replaceAll(match -> {
            String key = match.group(1).trim();

            // Built-in functions
            if (key.startsWith("$")) return BuiltInFunctions.resolve(key);

            // Process env
            if (key.startsWith("process.env.")) {
                return Matcher.quoteReplacement(
                    Objects.toString(System.getenv(key.substring(12)), ""));
            }

            // Circular detection
            if (visited.contains(key)) return match.group(0);
            visited.add(key);

            String value = vars.resolve(key);
            if (value == null) return match.group(0); // keep unresolved

            // Recursive resolution
            String resolved = interpolate(value, vars, visited, depth + 1);
            visited.remove(key);
            return Matcher.quoteReplacement(resolved);
        });
    }
}
```

### 6.2 VariableStore (hierarquico)

```java
public class VariableStore {
    private final Map<String, String> processEnv;      // System.getenv()
    private final Map<String, String> collectionVars;   // collection.json vars
    private final Map<String, String> envVars;          // environment vars
    private final Map<String, String> folderVars;       // folder.json vars
    private final Map<String, String> requestVars;      // request-level vars
    private final Map<String, String> runtimeVars;      // set during execution (highest priority)

    // Resolve com precedencia: runtime > request > folder > env > collection > process
    public String resolve(String key) {
        if (runtimeVars.containsKey(key)) return runtimeVars.get(key);
        if (requestVars.containsKey(key)) return requestVars.get(key);
        if (folderVars.containsKey(key)) return folderVars.get(key);
        if (envVars.containsKey(key)) return envVars.get(key);
        if (collectionVars.containsKey(key)) return collectionVars.get(key);
        return processEnv.get(key);
    }

    public void setRuntime(String key, String value) {
        runtimeVars.put(key, value);
    }
}
```

---

## 7. Runner Engine

### 7.1 CollectionRunner

```java
public class CollectionRunner {
    private final RequestExecutor executor;
    private final AssertionEngine assertionEngine;
    private final int maxJumps = 10_000;

    public RunResult run(Collection collection, Environment env,
                         Consumer<String> log, AtomicBoolean cancel) {
        List<RequestItem> flatRequests = flatten(collection.items());
        VariableStore vars = buildVarStore(collection, env);
        RunContext ctx = new RunContext(vars, new CookieJar(), new ArrayList<>());

        int index = 0;
        int jumps = 0;

        while (index < flatRequests.size() && !cancel.get()) {
            RequestItem item = flatRequests.get(index);
            log.accept("[*] Running: " + item.name());

            RequestResult result = executor.execute(item, ctx, collection, log);
            ctx.results().add(result);

            // Flow control
            if (ctx.shouldStop()) break;
            if (ctx.nextRequest() != null && jumps < maxJumps) {
                index = findByName(flatRequests, ctx.nextRequest());
                ctx.clearNextRequest();
                jumps++;
            } else {
                index++;
            }
        }

        return new RunResult(ctx.results(), computeSummary(ctx.results()));
    }
}
```

### 7.2 RequestExecutor (7 phases)

```java
public class RequestExecutor {
    private final Http http;  // AnarCry's WAF-aware HTTP client
    private final Interpolator interpolator;
    private final AuthInjectorRegistry authRegistry;

    public RequestResult execute(RequestItem item, RunContext ctx,
                                  Collection collection, Consumer<String> log) {
        long start = System.nanoTime();

        // Phase 1: MERGE - cascade folder/collection config
        HttpRequestDef merged = mergeInherited(item, collection);

        // Phase 2: PRE-VARS - resolve pre-request variables
        resolvePreVars(item.vars().pre(), ctx.vars());

        // Phase 3: INTERPOLATE - {{var}} in all fields
        HttpRequestDef interpolated = interpolateRequest(merged, ctx.vars());

        // Phase 4: AUTH INJECT - apply auth mode
        HttpRequestDef authed = authRegistry.inject(interpolated, ctx);

        // Phase 5: HTTP SEND - via Http.send() (WAF-aware)
        ResponseData response = dispatch(authed, ctx);

        // Phase 6: POST-VARS - extract from response
        resolvePostVars(item.vars().post(), response, ctx.vars());

        // Phase 7: ASSERTIONS - validate response
        List<AssertionResult> assertResults = assertionEngine.evaluate(
            item.assertions(), response, ctx.vars());

        long duration = (System.nanoTime() - start) / 1_000_000;
        boolean passed = assertResults.stream().allMatch(AssertionResult::passed);

        return new RequestResult(item, interpolated, response, assertResults, duration, passed);
    }
}
```

---

## 8. Importers

### 8.1 Bruno .bru Import

Parse .bru files usando regex patterns (nao precisa do parser PEG completo):
- Blocks: `tag { ... }` para dicionarios, `tag { ... }` para texto livre
- Meta: `name:`, `type:`, `seq:`
- Method block: `get { url: ... }`, `post { url: ... body: ... auth: ... }`
- Headers: `key: value` dentro de `headers { }`
- Body: conteudo dentro de `body:json { }`, `body:form-urlencoded { }`, etc
- Vars: `key: value` dentro de `vars:pre-request { }`, `vars:post-response { }`
- Assertions: `lhs: op rhs` dentro de `assert { }`
- `~` prefix = disabled

### 8.2 Postman v2.1 Import

JSON direto - mapear:
- `info.name` -> Collection.name
- `item[]` -> recursive Folder/RequestItem
- `request.method`, `request.url`, `request.header`, `request.body`
- `request.auth` -> AuthConfig
- `variable[]` -> collection vars
- `environment` files separados

### 8.3 OpenAPI 3.0 Import

- Cada `paths["/endpoint"][method]` -> RequestItem
- `servers[0].url` -> baseUrl variable
- `components.securitySchemes` -> auth configs
- `parameters` -> query/path params
- `requestBody.content` -> body config
- Tags -> folders

### 8.4 cURL Import

Parse curl command string:
- `-X METHOD` -> method
- URL -> url
- `-H "Key: Value"` -> headers
- `-d '...'` -> body (json/form based on Content-Type)
- `-u user:pass` -> basic auth
- `-b "cookie=value"` -> cookies
- `--data-urlencode` -> form-urlencoded

---

## 9. UI Integration

### 9.1 TUI (Lanterna)

Nova tab "API Client" no ModulesPanel com 3 paineis:

```
+--Collection Tree--+--Request Editor---------+--Response Viewer--------+
| > duma-finance     | [GET v] {{baseUrl}}/... | Status: 200 OK         |
|   > auth           | [Send] [Save]           | Time: 145ms Size: 1.2K |
|     login          |                         |                        |
|     register       | Params | Headers | Body | Body | Headers | Assert|
|   > users          | +------+------+------+  | {                      |
|     get-me         | | key  | val  | [x]  |  |   "name": "clube...",  |
|     patch-me  <--  | | page | 1    | [x]  |  |   "phone": "",         |
|     delete-me      | +------+------+------+  |   "email": "club..."   |
|   > transactions   |                         | }                      |
|     create         | Auth: [Bearer v]        |                        |
|     list           | Token: {{accessToken}}  | Assertions: 3/3 passed |
+--------------------+-------------------------+------------------------+
| Env: [production v]  | Vars: baseUrl=https://api.duma... | Runner: [Run All] |
+----------------------+------------------------------------+-------------------+
```

### 9.2 GUI (Swing + FlatLaf)

Split-pane layout similar ao TUI mas com:
- JTree para collection browser
- JTabbedPane para request sections (params, headers, body, auth, vars, assertions, docs)
- JTabbedPane para response (body com syntax highlight, headers, assertions, timing)
- ComboBox para environment selection
- Toolbar: Send, Save, New Request, New Folder, Import, Run Collection
- Context menu no tree: duplicate, move, delete, rename

---

## 10. Integracao com Security Workflow

### 10.1 Crawler -> Collection

```java
// Apos CrawlerModule completar, oferecer:
List<String> discoveredEndpoints = crawlerModule.getDiscoveredEndpoints();
Collection skeleton = CollectionGenerator.fromEndpoints(discoveredEndpoints, ctx);
// Gera collection com requests GET pra cada endpoint, auth do ScanContext
```

### 10.2 Collection Run -> Findings

```java
// RequestResult com assertion failure ou anomalia -> Finding
if (!result.passed()) {
    Finding finding = Finding.builder()
        .title("Assertion failed: " + result.failedAssertions())
        .endpoint(result.request().url())
        .severity(Severity.INFO)
        .evidence(result.response().body())
        .build();
}

// Anomalias automaticas:
// - Status 500 em qualquer request -> potential server error
// - Response time > 5s -> potential DoS
// - Unexpected 200 em request que deveria dar 401/403 -> auth bypass
// - Response body diferente entre users (IDOR indicator)
```

### 10.3 Evidence no Report

```java
// CollectionReportEngine gera secao "Manual Testing Evidence"
// com request/response pairs formatados como PoC
String poc = """
    ## PoC: Account Takeover via Phone Change

    **Request:**
    ```
    PATCH /api/v1/users/me HTTP/1.1
    Authorization: Bearer eyJ...
    Content-Type: application/json

    {"phone": "5511999999999"}
    ```

    **Response:**
    ```
    HTTP/1.1 200 OK
    {"name":"clube do Java","phone":"5511999999999","email":"clubdojava@gmail.com"}
    ```

    **Assertions:** 2/2 passed (status eq 200, body.phone eq attackerPhone)
    """;
```

---

## 11. Plano de implementacao

### Phase 1: Core Data Model + IO (1-2 dias)
- Records: Collection, Environment, Folder, RequestItem, AuthConfig, BodyConfig, etc
- CollectionLoader/Writer (JSON filesystem)
- CurlImporter (mais simples, util imediato)

### Phase 2: Interpolation + Variables (1 dia)
- Interpolator com recursao e circular detection
- VariableStore hierarquico
- BuiltInFunctions ($timestamp, $guid, $randomInt, etc)

### Phase 3: Auth Injectors (1-2 dias)
- AuthInjectorRegistry + interface
- Basic, Bearer, ApiKey, Digest (os mais comuns)
- OAuth2 (4 grant types) - complexo, pode ser Phase 4

### Phase 4: Runner + Assertions (1-2 dias)
- RequestExecutor (7 phases)
- CollectionRunner (sequential + flow control)
- AssertionEngine (30+ operators)
- RunContext com cookie jar

### Phase 5: Importers (1 dia)
- BruImporter (regex-based .bru parser)
- PostmanImporter (JSON mapping)
- OpenApiImporter (spec -> collection)

### Phase 6: TUI Integration (1-2 dias)
- Collection tree panel
- Request editor (params, headers, body, auth tabs)
- Response viewer (body, headers, assertions)
- Environment selector
- Runner controls

### Phase 7: GUI Integration (1 dia)
- Same layout as TUI but Swing components
- Syntax highlighting no body editor/viewer

### Phase 8: Report + Scan Integration (1 dia)
- CollectionReportEngine
- Crawler -> Collection generator
- Collection findings -> ExploitOrchestrator feed

**Total estimado: 8-12 dias**

---

## 12. Gaps conhecidos (pra versoes futuras)

- **WebSocket support** (Bruno tem, AnarCry nao)
- **gRPC support** (Bruno tem, AnarCry nao)
- **Script runtime** (Bruno usa QuickJS/NodeVM - AnarCry poderia usar GraalJS ou Groovy)
- **GraphQL introspection** (auto-complete de queries a partir do schema)
- **Response diff** (comparar responses entre environments ou entre execucoes)
- **Load testing** (executar collection N vezes em paralelo com metricas)
- **Proxy intercept** (MITM proxy integrado pra capturar requests do browser -> collection)

---

## 13. Metricas de sucesso

- Pentester consegue importar Postman collection e rodar no AnarCry em < 2min
- Collection run de 20 requests completa em < 30s (com assertions)
- Findings manuais com PoC evidence aparecem no report final
- Zero perda de contexto WAF/auth entre scan automatico e teste manual
- Endpoints do CrawlerModule viram collection skeleton com 1 click
