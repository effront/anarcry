---
id: backend_liveness
title: "Dangling Backend Reference"
module: "backendliveness"
severity: "HIGH"
cwe_id: "CWE-672"
cwe_title: "Operation on a Resource after Expiration or Release"
cvss_vector: "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
vrt_id: "server_security_misconfiguration.dangling_dns"
---

## Summary
Frontend references a backend URL that is dead (NXDOMAIN, connection refused, or HTTP error), indicating a dangling resource that may be claimable by an attacker for subdomain takeover or traffic interception.

## Description
When a frontend application hardcodes backend API URLs (via framework config, environment variables, or JavaScript), and the corresponding backend infrastructure is decommissioned without updating the frontend, the reference becomes dangling. This creates several attack vectors:

- NXDOMAIN: the domain/subdomain no longer resolves, potentially allowing an attacker to register it or claim the cloud resource
- Connection refused: the server is down but DNS still resolves, indicating abandoned infrastructure
- HTTP 404/502/503 from cloud platforms: the app was deleted but the platform still responds

Cloud platforms like DigitalOcean App Platform, Heroku, Azure, and AWS use predictable naming patterns. An attacker who claims the abandoned resource receives all API traffic the frontend sends.

## Impact
- Full API traffic interception (credentials, user data, transaction details)
- Man-in-the-middle attacks on application functionality
- Data exfiltration from users who interact with the compromised frontend
- Subdomain takeover enabling phishing and cookie theft

## Payloads and Bypasses
Padroes de URL de backend em frontend code:
```
apiBase
baseURL
API_URL
BACKEND_URL
SERVER_URL
apiUrl
serverUrl
window.__NUXT__
window.__NEXT_DATA__
window.__REMIX_CONTEXT__
```

Plataformas cloud com naming previsivel (reclaimaveis):
```
.ondigitalocean.app
.herokuapp.com
.vercel.app
.netlify.app
.railway.app
.onrender.com
.fly.dev
.web.app
.pages.dev
.azurewebsites.net
.appspot.com
.cloudfunctions.net
.run.app
.amplifyapp.com
```

Script de extracao de backend URLs de JS bundles:
```bash
# Extrair URLs de backend de HTML/JS
curl -s https://target | grep -oE '(apiBase|baseURL|API_URL|BACKEND_URL|SERVER_URL)[^"]*"(https?://[^"]+)"'
# Buscar URLs de plataformas cloud
curl -s https://target | grep -oE 'https?://[^ "]+\.(herokuapp\.com|ondigitalocean\.app|vercel\.app|netlify\.app|fly\.dev)'
# Verificar NXDOMAIN
dig +short backend.example.com
# Probe HTTP
curl -sI -o /dev/null -w "%{http_code}" https://backend.example.com
```

## Target Context (Crawler Hints)
- **Parameters:** `apiBase`, `baseURL`, `API_URL`, `BACKEND_URL`, `SERVER_URL`, `apiUrl`, `serverUrl`
- **Paths:** `/`, `/_nuxt/*`, `/_next/*`, `/static/js/*`, `/assets/*.js`, `/config.js`, `/env.js`

## Notable CVEs

| CVE | Produto | Ano | Descricao | Tipo |
|-----|---------|-----|-----------|------|
| CVE-2021-23017 | Nginx | 2021 | DNS resolver vulnerability permitindo off-by-one heap write via resposta DNS crafted -- relevante para backends que dependem de resolucao DNS | DNS resolution exploit |
| CVE-2024-21893 | Ivanti Connect Secure | 2024 | SSRF no componente SAML expondo endpoints internos administrativos -- backend reference exploitation | Backend reference abuse |
| CVE-2023-44487 | HTTP/2 (multiplos) | 2023 | Rapid Reset attack contra backends HTTP/2 -- backends dangling podem ser reclamados e usados para pivot | Protocol-level backend abuse |
| CVE-2021-25742 | Kubernetes Ingress-Nginx | 2021 | Snippet injection permitindo redirecionar trafego para backend arbitrario | Backend routing hijack |
| CVE-2024-4985 | GitHub Enterprise Server | 2024 | SAML authentication bypass -- demonstra risco de backends com autenticacao mal configurada | Auth bypass on backend |

## Escalation Techniques
- **Reclamar recurso NXDOMAIN:** quando o hostname retorna NXDOMAIN, registrar o dominio/subdominio na plataforma cloud correspondente (DigitalOcean, Heroku, etc.) e receber todo o trafego de API que o frontend envia -- credenciais, tokens de sessao, dados de usuario.
- **Man-in-the-middle via IP claim:** quando DNS resolve mas conexao e recusada, o IP pode estar abandonado na cloud. Reclamar o IP elastico/floating IP e interceptar trafego.
- **Credential harvesting automatico:** configurar o backend reclamado para retornar respostas validas (200 OK) e coletar todas as credenciais, JWT tokens e dados de sessao enviados pelo frontend.
- **Phishing via dominio confiavel:** o frontend original aponta para o backend reclamado -- usuarios confiam na interface original e nao percebem que o backend mudou.
- **Encadeamento com subdomain takeover:** backend dangling + cloud platform = subdomain takeover classico. Se o frontend seta cookies para o dominio pai, o atacante herda cookies de sessao.

## Hunting Methodology
1. Obter o HTML da pagina principal e de paginas descobertas pelo crawler -- buscar por padroes `apiBase`, `baseURL`, `API_URL`, `BACKEND_URL`, `SERVER_URL` no source.
2. Analisar JS bundles (incluindo lazy-loaded chunks em `/_nuxt/`, `/_next/`, `/static/js/`) para URLs hardcoded de backend.
3. Verificar `window.__NUXT__` config para URLs de backend expostas no runtime config do Nuxt.js.
4. Para cada URL de backend externa encontrada, fazer probe DNS (`dig hostname`) -- NXDOMAIN indica recurso reclaimavel.
5. Se DNS resolve, fazer HTTP HEAD com timeout curto -- ConnectException/timeout indica servidor morto mas DNS ativo.
6. Verificar se a URL pertence a plataforma cloud com naming previsivel (`.herokuapp.com`, `.ondigitalocean.app`, etc.) -- estas sao as mais faceis de reclamar.
7. Cruzar com resultados do FrameworkConfig e JsAnalyzer para maximizar cobertura de URLs de backend.

## False Positive Indicators
- URL de backend externa e intencional e ativa (ex.: CDN, analytics, payment gateway) -- verificar se o servico e third-party legítimo e operacional.
- URL pertence a servico compartilhado (ex.: Cloudflare Workers, AWS API Gateway) onde o namespace nao e reclaimavel por terceiros.
- Backend retorna HTTP 200 com conteudo valido -- nao e dangling, apenas referencia externa. Reportado como INFO, nao HIGH.
- URL e relativa ao mesmo dominio mas capturada como absoluta por erro de regex -- verificar se o hostname realmente difere do target.
- DNS retorna NXDOMAIN temporariamente por problema de propagacao ou TTL expirado -- repetir resolucao apos alguns minutos.
- Backend retorna erro 5xx mas e servico ativo com problema temporario -- verificar health check e status page antes de reportar como abandono.

## Recommendation
1. Remover ou atualizar referencias de backend mortas na configuracao do frontend -- URLs que retornam NXDOMAIN ou connection refused devem ser corrigidas imediatamente.
2. Implementar health checks que alertem quando URLs de backend ficam inacessiveis -- monitoramento proativo evita que referencias se tornem dangling.
3. Usar infrastructure-as-code para acoplar deploys de frontend e backend -- garantir que descomissionar um backend atualiza automaticamente o frontend correspondente.
4. Monitorar DNS para NXDOMAIN em subdominios criticos -- alertar quando um hostname previamente resolvido comecar a retornar NXDOMAIN.
5. Manter recursos de plataformas cloud reservados mesmo apos descomissionar servicos -- evitar que hostnames como `.herokuapp.com`, `.ondigitalocean.app` sejam reclamados por terceiros.
6. Auditar JS bundles e config blocks periodicamente para identificar URLs de backend que apontam para servicos externos desativados.
7. Implementar allowlist de dominios de backend no frontend -- rejeitar requisicoes para dominios que nao estao na lista aprovada.
