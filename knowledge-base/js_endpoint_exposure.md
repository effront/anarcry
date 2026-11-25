---
id: js_endpoint_exposure
title: "JavaScript API Endpoint Exposure"
module: "jsanalyzer"
severity: "MEDIUM"
cwe_id: "CWE-200"
cwe_title: "Exposure of Sensitive Information to an Unauthorized Actor"
cvss_vector: "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
vrt_id: "sensitive_data_exposure.api_endpoints"
---

## Summary
API endpoints extracted from client-side JavaScript bundles reveal backend attack surface including undocumented, admin, and internal endpoints not visible through crawling.

## Description
JavaScript bundles frequently contain hardcoded API endpoint paths in fetch(), $fetch(), axios, and XMLHttpRequest calls. Static analysis of these bundles reveals:

- REST API paths (e.g. /api/v1/swaps/new-exchange, /api/admin/users)
- GraphQL endpoints and query patterns
- WebSocket connection URLs
- Third-party API integration endpoints
- Internal/admin endpoints not linked from the UI

These endpoints expand the attack surface beyond what a crawler discovers and often include endpoints with missing authentication, broken access control, or sensitive data exposure.

## Impact
- Discovery of undocumented or admin-only API endpoints
- Identification of endpoints with missing authentication
- Mapping of full API surface for automated fuzzing
- Discovery of deprecated but still-active endpoints

## Payloads and Bypasses
Padroes de deteccao de endpoints em JS:
```javascript
// fetch() calls
fetch("/api/v1/users", { method: "POST", headers: { "Authorization": "Bearer " + token } })
fetch(`/api/users/${id}/profile`)

// $fetch() (Nuxt)
$fetch("/api/admin/settings", { method: "PUT" })

// axios
axios.get("/api/internal/config")
axios.post("/api/admin/users", data)
axios({ method: "post", url: "/api/payments/process" })

// XMLHttpRequest
xhr.open("GET", "/api/v2/secrets")

// tRPC
api.user.getProfile.useQuery()
api.admin.deleteUser.useMutation()

// UploadThing
startUpload("imageUploader")
useUploadThing("documentUploader")

// Next.js Server Actions
createServerReference("abc123hash", "deleteAccount")
```

Extracao via CLI:
```bash
# Extrair fetch/axios calls de JS bundles
curl -s https://target/_next/static/chunks/*.js | grep -oE 'fetch\(["'"'"'`][^"'"'"'`]+["'"'"'`]'
# Extrair rotas de API
curl -s https://target | grep -oE '/api/[a-zA-Z0-9/_-]+'
# Buscar endpoints sem auth header
curl -s https://target/static/js/main.js | grep -B5 'fetch(' | grep -v 'Authorization'
# Extrair tRPC procedures
curl -s https://target | grep -oE '\w+\.\w+\.(useQuery|useMutation)'
# Buscar analytics keys
curl -s https://target | grep -oE 'phc_[A-Za-z0-9_-]{20,}'
curl -s https://target | grep -oE 'pk_(live|test)_[A-Za-z0-9_-]{20,}'
# Extrair NEXT_PUBLIC env vars
curl -s https://target | grep -oE 'NEXT_PUBLIC_[A-Z_]+'
# Extrair URLs completas de JS bundles
grep -oE 'https?://[a-zA-Z0-9._/-]+' all_bundles.js | sort -u
# LinkFinder pattern simplificado
grep -oE '["'"'"'](\/[a-zA-Z0-9_?&=\/\-#.]*?)["'"'"']' all_bundles.js | sort -u | grep '/api\|/v[0-9]\|/admin\|/internal'
```

Padroes especificos de framework:
```javascript
// Next.js API routes
// /pages/api/ -> /api/ endpoints
// /app/api/ -> /api/ endpoints (App Router)
"api/auth/[...nextauth]"
"api/trpc/[trpc]"

// Nuxt.js server routes
// /server/api/ -> /api/ endpoints
"server/api/users.get"
"server/api/admin/config.post"

// SPA router definitions (revelam paginas/features ocultas)
{path: '/admin/users', component: AdminUsers}
{path: '/internal/debug', component: DebugPanel}
{path: '/api/v2/beta/exports', hidden: true}
```

## Target Context (Crawler Hints)
- **Parameters:** `id`, `userId`, `slug`, `action`, `method`, `batch`, `query`, `input`, `variables`
- **Paths:** `/api/*`, `/api/v1/*`, `/api/v2/*`, `/api/admin/*`, `/api/internal/*`, `/trpc/*`, `/api/uploadthing`, `/graphql`, `/_next/data/*`

## Notable CVEs

| CVE | Produto | Ano | Descricao | Tipo |
|-----|---------|-----|-----------|------|
| CVE-2024-34351 | Next.js | 2024 | SSRF via Server Actions -- endpoints internos descobertos em bundles client-side permitiram acesso a servicos internos | Endpoint exposure + SSRF |
| CVE-2024-39693 | Next.js | 2024 | Server Actions IDs expostos em chunks publicos permitem invocacao direta sem UI -- bypass de controle de acesso | Server Action exposure |
| CVE-2023-46729 | Sentry Next.js SDK | 2023 | Tunnel route do Sentry exposto em bundle permite relay de requests arbitrarios via proxy SSRF | SDK endpoint exposure |
| CVE-2024-37890 | ws (Node.js WebSocket) | 2024 | DoS em WebSocket server -- WS endpoints descobertos em JS podem ser alvos diretos | WebSocket endpoint targeting |
| CVE-2021-43798 | Grafana | 2021 | Endpoints internos de plugin revelados no frontend JS permitem path traversal e leitura de arquivos | Internal endpoint exposure |

## Escalation Techniques
- **IDOR em endpoints descobertos:** endpoints como `/api/users/{id}/profile` extraidos de JS permitem testar acesso horizontal/vertical substituindo IDs -- frequentemente sem verificacao de autorizacao.
- **Admin endpoint sem auth:** endpoints como `/api/admin/users`, `/api/internal/config` descobertos em JS podem estar acessiveis sem autenticacao se o controle de acesso depende apenas de nao estar linkado na UI.
- **tRPC procedure enumeration:** hooks tRPC como `admin.deleteUser.useMutation` revelam procedures sensiveis -- invocar diretamente via POST `/trpc/admin.deleteUser?batch=1`.
- **Server Action invocation direta:** hashes de Next.js Server Actions permitem chamada direta via POST com header `Next-Action: <hash>` -- bypass de UI controls.
- **Upload endpoint abuse:** slugs de UploadThing descobertos permitem upload arbitrario se o endpoint nao valida sessao/permissao server-side.
- **Source map exploitation:** se `.js.map` esta acessivel, reconstruir o codigo-fonte original com `sourcemapper` ou `unwebpack-sourcemap` -- revela comentarios, variaveis, logica de negocios e vulnerabilidades ocultas pela minificacao.
- **GraphQL introspection:** se `/graphql` e descoberto em bundle, testar `{__schema{types{name,fields{name}}}}` para mapear todo o schema -- mesmo com introspection desabilitado, queries no bundle revelam tipos e campos.

## Hunting Methodology
1. Baixar todos os JS bundles da aplicacao (incluindo lazy-loaded chunks via JsBundleDiscovery).
2. Buscar por padroes de chamada HTTP: `fetch(`, `$fetch(`, `axios.`, `.open(` em cada bundle.
3. Extrair o path e method de cada chamada -- classificar como autenticado (tem Authorization header) ou nao-autenticado.
4. Mapear endpoints admin/internal que nao aparecem na UI -- testar acesso direto sem credenciais.
5. Buscar tRPC hooks (`*.useQuery`, `*.useMutation`) e construir URLs de invocacao direta.
6. Buscar UploadThing slugs e Server Action hashes -- testar invocacao direta.
7. Verificar se source maps estao acessiveis: testar `bundle.js.map`, headers `SourceMap:` e `X-SourceMap:`.
8. Alimentar todos os paths descobertos no DiscoveredPaths para que modulos downstream (SSRF, SQLi, XSS) testem contra eles.

## False Positive Indicators
- Endpoint descoberto tem autenticacao server-side funcional (retorna 401/403 sem credenciais validas) -- e info disclosure mas nao vulnerabilidade de acesso.
- Endpoints sao de API publica documentada (ex.: `/api/v1/products` em e-commerce) -- nao e exposicao de superficie interna.
- tRPC procedures sao read-only e publicas por design (ex.: `product.list.useQuery`) -- nao ha impacto de seguranca.
- Analytics keys sao publicas por design (PostHog project keys sao client-side) -- avaliar se permitem write ou apenas read.
- NEXT_PUBLIC_ vars contem apenas valores nao-sensiveis (APP_NAME, SITE_URL) -- nao ha exposicao de dados internos.
- Endpoints descobertos pertencem a CDN/third-party (Cloudflare, AWS) e nao a infraestrutura do target.
- Rotas de SPA client-side (ex.: `/dashboard`, `/settings`) que nao correspondem a endpoints de API backend -- sao rotas de navegacao, nao superficie de ataque.

## Recommendation
1. Implementar autenticacao e autorizacao server-side em TODOS os endpoints de API, independente de estarem ou nao linkados na UI.
2. Usar code splitting para evitar que endpoints admin/internal sejam incluidos em bundles publicos -- imports dinamicos isolam codigo privilegiado.
3. Remover codigo de API client nao utilizado dos bundles de producao -- tree shaking e dead code elimination devem ser configurados corretamente.
4. Implementar API gateway com enforcement de autenticacao consistente -- nenhum endpoint deve ser acessivel sem auth a menos que seja explicitamente publico.
5. Nao depender de security through obscurity -- assumir que todo endpoint em JS bundles sera descoberto e testado por atacantes.
6. Auditar tRPC procedures e Server Actions para garantir que procedures sensiveis tem middleware de autorizacao.
7. Revisar slugs de upload (UploadThing, etc.) para garantir validacao de sessao e permissao server-side.
8. Implementar rate limiting e logging em endpoints descobertos para detectar enumeracao automatizada.
