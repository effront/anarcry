---
id: subdomain_takeover
title: "Subdomain Takeover"
module: "SubTakeover"
severity: "HIGH"
cwe_id: "CWE-672"
cwe_title: "Operation on a Resource after Expiration or Release"
cvss_vector: "AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:H/A:N"
vrt_id: "server_security_misconfiguration.subdomain_takeover"
---

## Summary
Registros DNS CNAME apontando para servicos externos desativados (dangling CNAMEs) permitem que um atacante reivindique o subdominio no servico de destino, servindo conteudo arbitrario sob o dominio da organizacao -- habilitando phishing, roubo de cookies e bypass de same-origin policy.

## Description
Subdomain takeover ocorre quando um registro CNAME aponta para um servico externo (GitHub Pages, Heroku, AWS S3, Azure, Vercel, Netlify, etc.) e o recurso nesse servico foi deletado ou nunca foi configurado. O atacante cria uma conta no servico e reivindica o hostname, passando a servir conteudo sob o subdominio da organizacao.

Fluxo de ataque:

1. **Reconhecimento:** enumeracao de subdominios via DNS brute-force, certificate transparency logs ou crawling.
2. **Deteccao de dangling CNAME:** resolver a chain de CNAMEs e verificar se o target final retorna NXDOMAIN ou pagina de erro do servico.
3. **Fingerprinting:** comparar a resposta HTTP com patterns conhecidos de servicos vulneraveis (ex.: "There isn't a GitHub Pages site here", "NoSuchBucket", "No such app").
4. **Takeover:** criar conta no servico e configurar o hostname customizado para apontar para o subdominio alvo.

Servicos vulneraveis e fingerprints:

| Servico | CNAME Pattern | Fingerprint |
|---------|---------------|-------------|
| GitHub Pages | `*.github.io` | "There isn't a GitHub Pages site here" |
| Heroku | `*.herokuapp.com` | "No such app" |
| AWS S3 | `*.s3*.amazonaws.com` | "NoSuchBucket" |
| Azure | `*.azurewebsites.net` | "404 Web Site not found" |
| Shopify | `shops.myshopify.com` | "Sorry, this shop is currently unavailable" |
| Fastly | `*.fastly.net` | "Fastly error: unknown domain" |
| Vercel | `*.vercel.app`, `cname.vercel-dns.com` | "DEPLOYMENT_NOT_FOUND" |
| Netlify | `*.netlify.app` | "Not Found.*Request ID" |
| Firebase | `*.web.app`, `*.firebaseapp.com` | "Site Not Found" |
| Cloudflare Pages | `*.pages.dev` | "project not found" |
| Fly.io | `*.fly.dev` | "not found" |
| Railway | `*.railway.app` | "Application not found" |
| Render | `*.onrender.com` | "Not Found.*Render" |
| DigitalOcean | `*.ondigitalocean.app` | "not a registered DigitalOcean" |
| Surge.sh | `*.surge.sh` | "project not found" |
| Pantheon | `*.pantheonsite.io` | "404 error unknown site" |
| Tumblr | `*.tumblr.com` | "There's nothing here" |
| WordPress | `*.wordpress.com` | "Do you want to register" |

## Impact
- Phishing sob dominio legitimo da organizacao -- certificados TLS validos via Let's Encrypt.
- Roubo de cookies de sessao se o cookie domain e `.example.com` (inclui subdominios).
- Bypass de same-origin policy -- acesso a APIs e dados do dominio principal.
- Distribuicao de malware sob dominio confiavel.
- Comprometimento de OAuth flows se o subdominio e usado como redirect URI.
- Danos reputacionais e perda de confianca.

## Payloads and Bypasses
```bash
# -- Enumeracao de subdominios --
# Via DNS brute-force
subfinder -d example.com -silent
amass enum -passive -d example.com
# Via certificate transparency
curl -s "https://crt.sh/?q=%.example.com&output=json" | jq -r '.[].name_value' | sort -u

# -- Resolucao de CNAME chain --
dig CNAME subdomain.example.com
dig CNAME subdomain.example.com +trace
host -t CNAME subdomain.example.com

# -- Verificacao de dangling CNAME --
# NXDOMAIN = dangling
dig subdomain.example.com
# Probe HTTP para fingerprint
curl -sI https://subdomain.example.com/
curl -s https://subdomain.example.com/ | head -20

# -- Verificacao de subdominios comuns --
for sub in www api app dev staging admin mail cdn assets static beta test; do
  echo -n "$sub.example.com: "
  dig +short CNAME $sub.example.com
done

# -- Takeover verification (nao executar sem autorizacao) --
# GitHub Pages: criar repo com CNAME file contendo o subdominio
# S3: criar bucket com o nome do subdominio
# Heroku: criar app com o nome do subdominio
```

## Target Context (Crawler Hints)
- **Parametros comuns:** nenhum (scan de DNS e HTTP).
- **Paths comuns:** `/` (probe de root em cada subdominio).
- **Sinais:** resposta NXDOMAIN em CNAME target; pagina de erro de servico PaaS; subdominios com `www`, `api`, `app`, `dev`, `staging`, `admin`, `mail`, `cdn`, `assets`, `static`, `beta`, `test` como prefixo.

## Notable CVEs

| CVE | Produto | Ano | Descricao | Tipo |
|-----|---------|-----|-----------|------|
| CVE-2021-23848 | Bosch IP cameras | 2021 | CNAME para servico externo desativado permite takeover e distribuicao de firmware malicioso | Dangling CNAME |
| CVE-2020-15138 | Prism (GitHub) | 2020 | Subdominio de documentacao com dangling CNAME permite phishing sob dominio do projeto | Dangling CNAME |
| CVE-2023-27217 | Belkin Wemo | 2023 | Dominio de update com CNAME dangling permite man-in-the-middle em atualizacoes de firmware | Dangling CNAME |

## Hunting Methodology
1. Enumerar subdominios do alvo usando multiplas fontes: DNS brute-force (`subfinder`, `amass`, `gobuster dns`), certificate transparency logs (`crt.sh`, `certspotter`), search engines (`site:*.example.com`), crawling de JS/HTML para referencias a subdominios.
2. Resolver cada subdominio e coletar registros CNAME: `dig CNAME sub.example.com`. Registros CNAME que apontam para servicos PaaS/CDN sao candidatos a takeover.
3. Para cada CNAME apontando para servico externo, verificar se o recurso existe: fazer HTTP GET no subdominio e comparar a resposta com fingerprints conhecidos de servicos vulneraveis (tabela acima).
4. Verificar NXDOMAIN: se `dig sub.example.com` retorna NXDOMAIN mas o CNAME record ainda existe, o recurso foi deletado no servico externo -- candidato forte para takeover.
5. Testar subdominios comuns que sao frequentemente esquecidos: `dev`, `staging`, `test`, `beta`, `old`, `legacy`, `demo`, `uat`, `sandbox`, `preview`, `temp`, `backup`.
6. Verificar wildcard DNS: se `*.example.com` resolve para um servico, qualquer subdominio nao configurado explicitamente pode ser vulneravel.
7. Monitorar mudancas: servicos sao desativados continuamente -- re-escanear periodicamente (semanal/mensal) para detectar novos dangling CNAMEs.
8. Verificar NS delegation: subdominios com NS records apontando para nameservers desativados permitem takeover completo da zona DNS (mais critico que CNAME takeover).
9. Priorizar subdominios de staging, dev, test e CDN -- dados de H1 mostram que a maioria dos takeovers reais ocorre em ambientes nao-producao esquecidos (Starbucks teve 10+ takeovers em subdominios de staging/dev, Shipt em fly.staging, Uber em saostatic).

## Escalation Techniques
- **Phishing sob dominio legitimo:** hospedar pagina de login identica no subdominio sequestrado -- certificado TLS valido via Let's Encrypt aumenta credibilidade. Usuarios confiam no dominio da organizacao.
- **Roubo de cookies de sessao:** se cookies sao configurados com `Domain=.example.com` (incluindo subdominios), o atacante pode ler cookies do dominio principal via JavaScript no subdominio sequestrado.
- **Bypass de Content Security Policy:** se CSP do dominio principal confia em `*.example.com` (wildcard), o subdominio sequestrado pode injetar scripts no contexto do dominio principal.
- **Interceptar OAuth flows:** se o subdominio e usado como `redirect_uri` em OAuth, o atacante captura authorization codes/tokens de usuarios que autenticam via SSO.
- **MX takeover:** se registros MX apontam para servico desativado, o atacante pode receber emails destinados ao subdominio -- incluindo emails de reset de senha e confirmacao.
- **Distribuicao de malware:** hospedar executaveis maliciosos sob dominio confiavel -- bypass de filtros de download corporativos que confiam no dominio.
- **Pivot para outros ataques:** usar o subdominio sequestrado como plataforma para SSRF callbacks, exfiltracao de dados ou C2 sob dominio legitimo.
- **Auth bypass via cookie scoping (ATO):** sequestrar subdominio e setar cookies scoped ao dominio pai (`.target.com`). Quando vitima visita qualquer pagina do dominio pai, cookie do atacante sobrescreve sessao autenticada -- full account takeover. H1: Roblox #335330 (782 upvotes), Uber #219205 (182 upvotes), Ubiquiti #172137. Este e o vetor de maior impacto em subdomain takeover.
- **S3 bucket takeover:** CNAME aponta para bucket S3 inexistente (`NoSuchBucket`). Criar bucket com mesmo nome na mesma regiao e servir conteudo malicioso sob o dominio da organizacao. H1: Starbucks #186766, TikTok #1102537, Khan Academy #474798. Buckets S3 sao o servico mais frequente em takeovers reais.
- **Firebase takeover:** CNAME para projeto Firebase deletado (`*.web.app`, `*.firebaseapp.com`). Criar novo projeto Firebase e reivindicar o hostname. Acesso a Realtime Database pode vazar dados de usuarios. H1: MTN Group (3 reports).
- **Docker registry poisoning:** registry Docker publico em subdominio permite push de imagens maliciosas que serao consumidas por pipelines CI/CD da organizacao. H1: Semmle #347296 (83 upvotes).
- **NS delegation takeover:** subdominios com NS records apontando para nameservers desativados permitem takeover completo da zona DNS -- mais critico que CNAME pois controla todos os registros (A, MX, TXT). H1: Basecamp #1342422 (77 upvotes).

## False Positive Indicators
- CNAME aponta para servico ativo e corretamente configurado -- o servico retorna conteudo valido mesmo que nao seja a pagina esperada (ex.: pagina default do Heroku para app ativo).
- Servico retorna erro generico (404, 403) mas o recurso existe e esta protegido por autenticacao -- nao e takeover, e access control.
- DNS retorna NXDOMAIN temporariamente devido a propagacao -- repetir query apos 24h para confirmar que e persistente.
- CDN com fallback page que retorna texto similar a fingerprint de takeover mas esta configurado intencionalmente (ex.: Cloudflare custom error page que contem "not found").
- Servico externo que rejeita registro de custom domains por politica (ex.: Azure que requer verificacao de propriedade via TXT record) -- mesmo com dangling CNAME, takeover nao e possivel sem verificacao.
- Wildcard DNS que resolve para load balancer com health check -- todos os subdominios retornam resposta, mas nao ha servico ativo atras.

## Notable HackerOne Reports

| Report | Programa | Upvotes | Bounty | Tecnica |
|--------|----------|---------|--------|---------|
| #335330 | Roblox | 782 | $0 | Cookie scoping ATO via subdomain takeover |
| #325336 | Starbucks | 330 | $2,000 | 10+ takeovers em subdominios staging/dev |
| #219205 | Uber | 182 | $0 | Subdomain takeover + cookie hijacking |
| #172137 | Ubiquiti | 140 | $0 | Subdomain takeover + auth bypass chain |
| #186766 | Starbucks | 130 | $0 | S3 bucket takeover em subdominio de producao |
| #1102537 | TikTok | 110 | $0 | S3 bucket takeover servindo conteudo malicioso |
| #1342422 | Basecamp | 77 | $0 | NS delegation takeover -- controle total da zona DNS |
| #347296 | Semmle | 83 | $0 | Docker registry poisoning via subdomain |
| #474798 | Khan Academy | 65 | $0 | S3 bucket takeover em CDN |

## Recommendation
1. Remover registros DNS CNAME que apontam para recursos desativados imediatamente apos descomissionar o servico.
2. Auditar todos os registros CNAME regularmente -- automatizar com ferramentas de monitoramento de DNS.
3. Configurar cookies com dominio especifico (nao `.example.com`) para prevenir roubo via subdominios.
4. Usar ferramentas de monitoramento continuo (subjack, nuclei, dnsreaper) para detectar dangling CNAMEs.
5. Manter inventario de todos os servicos externos vinculados a subdominios.
6. Reclamar namespaces em servicos PaaS antes de criar registros DNS (ou remover DNS antes de desativar o servico).
7. Implementar CAA records para restringir quais CAs podem emitir certificados para o dominio.
