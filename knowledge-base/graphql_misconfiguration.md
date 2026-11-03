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

Casos reais e mentalidade de ataque (RWBH): GitHub (IDOR via `node`) e Shopify (introspection) mostram que o endpoint único concentra autorização, enumeração e batching; o atacante começa pelo schema e depois testa cada resolver.

## Target Context (Crawler Hints)
- **Parâmetros comuns:** `query`, `variables`, `operationName`, `id`, `nodeId`, `input`, `filter`, `first`, `after`, `orderBy`.
- **Paths comuns:** `/graphql`, `/api/graphql`, `/v1/graphql`, `/graphiql`, `/playground`, `/api/v1/graphql`, `/query`.
- **Sinais:** `__schema` acessível; mensagens "Did you mean"; erros com stack trace; endpoint aceita GET; playground habilitado; batching sem limite.

## Escalation Techniques
- **Introspection + IDOR em massa:** usar o schema obtido via introspection para identificar queries com parametros de ID (ex.: `user(id:)`, `order(id:)`, `node(id:)`), depois enumerar IDs sequenciais ou decodificar IDs base64 para acessar dados de outros usuarios -- transforma info disclosure em vazamento massivo de dados.
- **Batching/aliasing + brute force:** abusar de alias queries ou batching para enviar centenas de tentativas de login ou OTP em um unico request HTTP, contornando rate limiting por-request e viabilizando brute force de credenciais.
- **Mutation + mass assignment:** quando a mutation aceita campos nao documentados (ex.: `role`, `isAdmin`, `verified`), enviar esses campos extras para escalar privilegios -- combina GraphQL misconfiguration com mass assignment.
- **Depth bomb + DoS:** construir queries com profundidade recursiva extrema (ex.: `friends { friends { friends { ... } } }`) para causar esgotamento de memoria/CPU no servidor, especialmente quando nao ha complexity limits.
- **GraphQL + SSRF via custom scalars:** quando um campo aceita URLs (ex.: `avatarUrl`, `webhookUrl`) e o servidor faz fetch interno, injetar URLs de servicos internos (`http://169.254.169.254/`, `http://localhost:8080/admin`) para SSRF.

## Hunting Methodology
1. **Descobrir o endpoint GraphQL:** testar paths comuns (`/graphql`, `/api/graphql`, `/v1/graphql`, `/gql`, `/g`, `/query`, `/graphiql`, `/playground`). Verificar tanto POST com `Content-Type: application/json` quanto GET com `?query=`.
2. **Testar introspection:** enviar a query `{ __schema { types { name fields { name } } } }`. Se retornar o schema, documentar todos os tipos, campos e mutations. Se for bloqueada, testar `__type(name:"Query")` e observar mensagens "Did you mean..." para enumerar campos via sugestoes.
3. **Mapear autorizacao por resolver:** para cada query e mutation sensivel, testar com tokens de diferentes niveis de privilegio (usuario normal, admin, sem token). Verificar se e possivel acessar dados de outros usuarios via IDs diretos.
4. **Testar batching e aliasing:** enviar um array de queries ou usar aliases (`a1: user(id:"1") { email } a2: user(id:"2") { email }`) para verificar se rate limiting e aplicado por operacao ou apenas por request HTTP.
5. **Testar depth e complexity:** enviar queries com profundidade crescente (5, 10, 20 niveis) e observar se o servidor rejeita ou se o tempo de resposta cresce exponencialmente. Medir o impacto em latencia.
6. **Verificar mutations nao autorizadas:** tentar executar mutations administrativas (ex.: `updateUser(id:"outro", input:{role:"ADMIN"})`) com token de usuario comum. Verificar se o servidor valida ownership e role no resolver.

## False Positive Indicators
- **Introspection habilitada em ambiente de desenvolvimento:** muitos frameworks habilitam introspection por padrao em dev/staging; se o endpoint nao esta exposto em producao, o finding nao tem impacto real.
- **Schema exposto mas sem dados sensiveis:** a introspection revela tipos e campos, mas todos os resolvers exigem autenticacao e autorizacao adequadas -- o schema em si nao e uma vulnerabilidade se o controle de acesso funciona.
- **Field suggestions sem introspection:** o servidor retorna "Did you mean X?" em mensagens de erro, o que permite enumerar campos lentamente, mas se a autorizacao por resolver e solida, a enumeracao nao leva a vazamento de dados.
- **Batching limitado por configuracao:** o servidor aceita arrays de queries mas aplica rate limiting por operacao dentro do batch e limita o tamanho do array -- o batching existe mas nao e abusavel para brute force.
- **Endpoint GraphQL requer autenticacao forte:** o endpoint exige token valido e todos os campos sensiveis verificam ownership -- mesmo que a introspection esteja ativa, um atacante nao consegue acessar dados de outros usuarios.

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

