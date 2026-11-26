---
id: framework_config_exposure
title: "Framework Configuration Exposure"
module: "frameworkconfig"
severity: "MEDIUM"
cwe_id: "CWE-200"
cwe_title: "Exposure of Sensitive Information to an Unauthorized Actor"
cvss_vector: "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
vrt_id: "sensitive_data_exposure.configuration_data"
---

## Summary
Framework runtime configuration (e.g. window.__NUXT__, __NEXT_DATA__) exposed in client-side JavaScript reveals internal backend URLs, API keys, environment flags, and infrastructure details.

## Description
Modern JavaScript frameworks like Nuxt.js and Next.js inject runtime configuration into the page via global variables (window.__NUXT__.config, __NEXT_DATA__.runtimeConfig). When backend URLs, API base paths, feature flags, or environment identifiers are included, attackers gain direct knowledge of internal infrastructure without active scanning.

Common exposures:
- Backend API base URLs (apiBase, API_URL) revealing internal hostnames or cloud platform slugs
- Environment identifiers (production, staging, dev) enabling targeted attacks
- Third-party service configurations (payment providers, analytics keys)
- Feature flags revealing unreleased or hidden functionality

## Impact
- Internal infrastructure mapping without active probing
- Discovery of dead/dangling backend references (subdomain takeover vector)
- Exposure of API keys or service credentials embedded in config
- Targeted attacks against revealed staging/dev environments

## Payloads and Bypasses
Extracao de config de frameworks:
```javascript
// Nuxt.js 2 (window.__NUXT__)
JSON.stringify(window.__NUXT__.config, null, 2)
// Chaves tipicas: apiBase, API_URL, baseURL, wsBase, PUBLIC_API

// Nuxt.js 3 (useRuntimeConfig / __NUXT_DATA__)
document.getElementById('__NUXT_DATA__')?.textContent
JSON.stringify(window.__NUXT__?.config?.public, null, 2)

// Next.js (__NEXT_DATA__)
JSON.stringify(window.__NEXT_DATA__?.runtimeConfig, null, 2)
JSON.stringify(window.__NEXT_DATA__?.props?.pageProps, null, 2)

// Remix (__remixContext / __REMIX_CONTEXT__)
JSON.stringify(window.__remixContext, null, 2)
JSON.stringify(window.__remixManifest, null, 2)

// Vite / generic
window.env
window._env_
import.meta.env
window.__ENV__
window.APP_CONFIG
```

Extracao via curl:
```bash
# Extrair __NUXT__ config
curl -s https://target | grep -oP 'window\.__NUXT__\s*=\s*\K\{[^;]+'
# Extrair __NEXT_DATA__
curl -s https://target | grep -oP '(?<=<script id="__NEXT_DATA__" type="application/json">)[^<]+'
# Buscar secrets em config blocks
curl -s https://target | grep -iE '(secret|password|api_key|apikey|token|private_key)\s*[:=]\s*["'"'"'][^"'"'"']+'
# Extrair todas as URLs dos config blocks
curl -s https://target | grep -oE 'https?://[^"'"'"' ]+'
# Buscar backend URL assignments em JS
curl -s https://target/_nuxt/entry.js | grep -oiE '(apiBase|baseURL|API_URL|BACKEND_URL|SERVER_URL)\s*[:=]\s*["'"'"'][^"'"'"']+'
# Buscar URLs internas em config
curl -s https://target | grep -oE 'https?://[a-zA-Z0-9._-]+\.(internal|local|corp|private|staging|dev|test)[^"'"'"' ]*'
```

Padroes de config sensivel em frontend:
```
# Chaves que nunca devem estar em publicRuntimeConfig / NEXT_PUBLIC_
API_KEY / apiKey / api_key
SECRET_KEY / secretKey / secret
DATABASE_URL / MONGO_URI / REDIS_URL
AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY
STRIPE_SECRET_KEY (vs STRIPE_PUBLISHABLE_KEY)
GITHUB_TOKEN / GH_TOKEN
JWT_SECRET / SESSION_SECRET
SMTP_PASSWORD / MAIL_PASSWORD
SENTRY_DSN (pode revelar org/project)
GOOGLE_MAPS_API_KEY (se sem restricao de dominio)
```

## Target Context (Crawler Hints)
- **Parameters:** `apiBase`, `baseURL`, `API_URL`, `BACKEND_URL`, `SERVER_URL`, `api_url`, `config`, `env`, `runtimeConfig`
- **Paths:** `/`, `/_nuxt/*`, `/_next/*`, `/static/js/*`, `/__remix_context`, `/env.js`, `/config.js`, `/runtime-config.js`, `/_payload.json`

## Notable CVEs

| CVE | Produto | Ano | Descricao | Tipo |
|-----|---------|-----|-----------|------|
| CVE-2024-34351 | Next.js | 2024 | Server Actions redirect SSRF -- runtimeConfig exposto facilita o ataque ao revelar URLs internas | Config-assisted SSRF |
| CVE-2023-46729 | Sentry Next.js SDK | 2023 | Tunnel route expondo token DSN no __NEXT_DATA__ -- credencial acessivel no source da pagina | Credential in config |
| CVE-2024-46982 | Next.js | 2024 | Cache poisoning em self-hosted Next.js -- atacante pode envenenar cache com dados de config alterados | Cache poisoning (config) |
| CVE-2024-24758 | undici (Node.js HTTP) | 2024 | Authorization header leak em redirects -- config com backend URLs amplifica o impacto ao revelar targets | Header leak + config exposure |
| CVE-2024-29041 | Express.js | 2024 | Open redirect via URL parsing -- config com backend URLs pode ser encadeado para redirect | Config + redirect chain |

## Escalation Techniques
- **Mapeamento de infraestrutura:** URLs de backend expostas revelam hostnames internos, cloud slugs, staging/dev endpoints -- usar para direcionar ataques sem descoberta ativa.
- **Credencial extraction:** secrets, API keys e tokens encontrados em config blocks podem ser usados diretamente para acessar servicos de terceiros (Stripe, SendGrid, etc.) ou backends internos.
- **Subdomain takeover via backend dangling:** URLs de backend em configs que apontam para servicos descomissionados (NXDOMAIN) sao reclaimaveis -- encadeamento direto com BackendLiveness.
- **Acesso a staging/dev:** environment flags (`NODE_ENV=development`, `staging: true`) revelam existencia de ambientes nao-produtivos -- frequentemente com menos protecao.
- **Feature flag enumeration:** flags expostas revelam features nao-lancadas que podem ter vulnerabilidades nao-testadas ou code paths incompletos.
- **Backend URL como SSRF target:** usar URLs de backend descobertas como alvos para SSRF -- ja se sabe que o backend aceita conexoes do frontend.

## Hunting Methodology
1. Abrir a pagina no browser e verificar `window.__NUXT__`, `window.__NEXT_DATA__`, `window.__REMIX_CONTEXT__` no console -- cada um expoe config do framework.
2. Buscar no HTML source por `window.env`, `window._env_`, `import.meta.env`, `window.__ENV__`, `window.APP_CONFIG`.
3. Analisar JS bundles para assignment patterns: `const API_URL = "..."`, `const baseURL = "..."`, etc.
4. Extrair todas as URLs dos config blocks e classificar: same-origin (normal), external (info), cloud platform (risco de takeover), internal hostname (info disclosure).
5. Buscar credenciais nos config blocks: patterns como `secret`, `password`, `api_key`, `token`, `private_key` seguidos de valor string.
6. Filtrar UI labels (strings com espacos, palavras de formulario) que sao falso positivo para deteccao de credenciais.
7. Registrar backend URLs descobertas para downstream modules (BackendLiveness, SSRF).

## False Positive Indicators
- Config block contem apenas variaveis publicas e nao-sensiveis (ex.: `APP_NAME`, `THEME`, `LOCALE`) -- nao ha exposicao de dados internos.
- URLs no config sao CDN publicas ou servicos third-party conhecidos (ex.: `https://cdn.jsdelivr.net`, `https://fonts.googleapis.com`) -- nao revelam infraestrutura interna.
- Credential pattern match pega label de formulario (ex.: `password: "Enter your password"`) -- detector de UI labels deve filtrar strings com espacos e palavras de UI.
- Config block e de ambiente de desenvolvimento local (localhost, 127.0.0.1) visto em pagina de staging -- nao e exposicao em producao.
- Environment flag mostra `production` mas sem informacao sensivel adicional -- a presenca do config block e INFO, nao necessariamente vulnerabilidade.
- Backend URL no config e same-origin (mesmo dominio) -- nao e exposicao de infraestrutura externa.

## Recommendation
1. Mover configuracoes sensiveis para server-side only: usar `privateRuntimeConfig` (Nuxt) ou env vars sem prefixo `NEXT_PUBLIC_` (Next.js) para dados que nao devem estar no client.
2. Auditar `publicRuntimeConfig` e variaveis `NEXT_PUBLIC_*` para garantir que nenhuma credencial, URL interna ou secret esta exposto.
3. Usar builds environment-specific que removem URLs internas e informacoes de infraestrutura dos bundles de producao.
4. Implementar CSP para restringir quais scripts podem acessar objetos de configuracao global.
5. Remover ou minimizar `window.__NUXT__`, `window.__NEXT_DATA__` e similares do HTML renderizado quando os dados nao sao necessarios para hydration.
6. Classificar toda variavel de ambiente como publica ou privada -- tratar como privada por padrao e mover para publica apenas quando necessario.
7. Implementar secret scanning no CI/CD para detectar credenciais expostas em config blocks antes do deploy.
8. Monitorar endpoints de staging/dev revelados por config blocks e garantir que estao protegidos com autenticacao.
