---
id: secrets_exposure
title: "Secrets Exposure"
module: "Secrets"
severity: "HIGH"
cwe_id: "CWE-200"
cwe_title: "Exposure of Sensitive Information to an Unauthorized Actor"
cvss_vector: "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
vrt_id: "sensitive_data_exposure.hardcoded_secrets"
---

## Summary
Credenciais, API keys, tokens e chaves privadas expostas em codigo-fonte client-side (JavaScript bundles, source maps, HTML), endpoints de configuracao (/.env, /config.json) ou respostas HTTP, permitindo acesso nao autorizado a servicos externos e infraestrutura.

## Description
Secrets exposure ocorre quando credenciais sao hardcoded no codigo-fonte ou em arquivos de configuracao acessiveis publicamente. Em aplicacoes web modernas, o vetor principal sao bundles JavaScript minificados que contem API keys, tokens e segredos embutidos durante o build.

Categorias de segredos detectados:

- **Cloud providers:** AWS Access Key (`AKIA...`), AWS Secret Key, DigitalOcean API Token (`dop_v1_...`).
- **Repositorios de codigo:** GitHub Token (`ghp_`/`ghs_`), GitHub OAuth (`gho_`), GitLab Token (`glpat-`).
- **Comunicacao:** Slack Bot Token (`xoxb-`), Slack User Token (`xoxp-`), Twilio API Key (`SK...`), SendGrid (`SG...`), Mailgun (`key-...`).
- **Pagamento:** Stripe Secret Key (`sk_live_`), Stripe Publishable Key (`pk_live_`).
- **Google/Firebase:** Google API Key (`AIza...`), Firebase API Key (`AIzaSy...`), Supabase Service Key.
- **Crypto/Fintech:** Alchemy API Key (`alch_`), Infura Project ID, MoonPay/Transak API Keys, key:secret pairs em JS.
- **Generico:** Private keys (PEM), JWTs longos, `api_key=`, `password=` em codigo.
- **Source maps:** `.map` files acessiveis expoe codigo-fonte original com todos os segredos pre-minificacao.

Fontes de exposicao:
1. Bundles JS minificados (`/static/js/main.js`, `/_next/static/chunks/`, `/assets/js/`).
2. Source maps (`.map`) referenciados via `//# sourceMappingURL=`.
3. Arquivos de configuracao (`/.env`, `/config.json`, `/config.js`).
4. HTML source code (meta tags, inline scripts).
5. Respostas de API (headers, bodies).

## Impact
- Acesso nao autorizado a servicos cloud (AWS, GCP, Azure) -- criacao de recursos, exfiltracao de dados.
- Takeover de contas de servico (GitHub, GitLab, Slack) -- acesso a repositorios privados e comunicacoes.
- Fraude financeira via chaves de pagamento (Stripe) -- transacoes nao autorizadas.
- Exfiltracao de dados de banco via chaves de servico (Supabase, Firebase).
- Envio de emails/SMS nao autorizados via tokens de comunicacao (SendGrid, Twilio, Mailgun).
- Comprometimento de chaves criptograficas (private keys, JWT secrets).

## Payloads and Bypasses
```bash
# -- Busca de secrets em JavaScript bundles --
curl -s https://alvo.com/static/js/main.js | grep -oP 'AKIA[0-9A-Z]{16}'
curl -s https://alvo.com/static/js/main.js | grep -oP 'ghp_[A-Za-z0-9_]{36,}'
curl -s https://alvo.com/static/js/main.js | grep -oP 'sk_live_[0-9a-zA-Z]{24,}'
curl -s https://alvo.com/static/js/main.js | grep -oP 'xoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,}'

# -- Source map discovery --
curl -s https://alvo.com/static/js/main.js | grep -oP 'sourceMappingURL=\K[^\s]+'
curl -s https://alvo.com/static/js/main.js.map | grep -oP 'api[_-]?key["\s:=]+[A-Za-z0-9\-_]{16,}'

# -- Arquivos de configuracao --
curl -s https://alvo.com/.env
curl -s https://alvo.com/config.json
curl -s https://alvo.com/config.js
curl -s https://alvo.com/.env.local
curl -s https://alvo.com/.env.production

# -- Validacao de chaves encontradas --
# AWS:
aws sts get-caller-identity --access-key-id AKIA... --secret-access-key ...
# GitHub:
curl -sH "Authorization: token ghp_..." https://api.github.com/user
# Stripe:
curl -s https://api.stripe.com/v1/charges -u sk_live_...:
# Slack:
curl -s "https://slack.com/api/auth.test?token=xoxb-..."

# -- Chunk discovery (Next.js, Webpack) --
curl -s https://alvo.com | grep -oP '/_next/static/chunks/[a-zA-Z0-9._-]+\.js'
curl -s https://alvo.com | grep -oP '/static/js/[a-zA-Z0-9._-]+\.js'
```

## Target Context (Crawler Hints)
- **Parametros comuns:** nenhum (scan passivo de conteudo).
- **Paths comuns:** `/static/js/main.js`, `/static/js/bundle.js`, `/static/js/app.js`, `/_next/static/chunks/main.js`, `/_next/static/chunks/app.js`, `/assets/js/app.js`, `/assets/js/bundle.js`, `/build/bundle.js`, `/dist/bundle.js`, `/dist/app.js`, `/config.js`, `/config.json`, `/.env`.
- **Sinais:** bundles JS grandes (>100KB); presenca de source maps; frameworks SPA (React, Next.js, Vue, Angular); endpoints de configuracao acessiveis sem autenticacao.

## Notable CVEs

| CVE | Produto | Ano | Descricao | Tipo |
|-----|---------|-----|-----------|------|
| CVE-2023-35078 | Ivanti EPMM | 2023 | Endpoint nao autenticado expoe credenciais e configuracao do servidor | Config exposure |
| CVE-2024-23334 | aiohttp | 2024 | Path traversal permite leitura de arquivos sensiveis incluindo .env e config | File read to secrets |
| CVE-2021-21311 | Adminer | 2021 | SSRF permite leitura de credenciais de banco armazenadas no servidor | SSRF to secrets |
| CVE-2023-26256 | WPScan | 2023 | Credenciais de API vazadas em logs de debug acessiveis publicamente | Log exposure |

## Hunting Methodology
1. Mapear todos os JS bundles referenciados no HTML: `<script src="...">`, `/_next/static/chunks/`, `/static/js/`, `/assets/js/`, `/build/`, `/dist/`. Incluir bundles carregados dinamicamente (lazy loading).
2. Baixar cada bundle e rodar regex para padroes de API keys conhecidos: `AKIA[0-9A-Z]{16}` (AWS), `ghp_[A-Za-z0-9_]{36}` (GitHub), `sk_live_[0-9a-zA-Z]{24}` (Stripe), `xoxb-` (Slack), `AIza[0-9A-Za-z\-_]{35}` (Google), `SG\.[A-Za-z0-9\-_]{22}` (SendGrid).
3. Verificar source maps: buscar `sourceMappingURL` no fim de cada JS. Se o `.map` for acessivel, o codigo-fonte original com todos os segredos pre-minificacao esta exposto.
4. Testar paths sensiveis diretamente: `/.env`, `/.env.local`, `/.env.production`, `/.env.backup`, `/config.json`, `/config.yaml`, `/config.js`, `/.git/config`, `/wp-config.php`, `/application.properties`.
5. Analisar HTML comments (`<!-- -->`) e meta tags para tokens vazados, URLs internas, credenciais de staging.
6. Verificar endpoints de debug e status que retornam variaveis de ambiente: `/actuator/env`, `/debug`, `/phpinfo.php`, `/server-info`, `/_config`.
7. Usar grep recursivo em todas as respostas capturadas pelo proxy (Burp, mitmproxy) para padroes de tokens -- segredos podem aparecer em qualquer endpoint, nao apenas em JS.
8. Para aplicacoes SPA (React, Next.js, Vue, Angular): verificar se variaveis com prefixo `NEXT_PUBLIC_`, `REACT_APP_`, `VITE_` contem valores que deveriam ser server-side only.

## Escalation Techniques
- **Acesso a servicos cloud:** usar AWS Access Key para listar buckets S3 (`aws s3 ls`), ler objetos, criar instancias EC2, ou escalar via IAM policies.
- **Takeover de contas de servico:** usar GitHub/GitLab tokens para acessar repositorios privados, ler segredos em CI/CD, modificar pipelines, ou criar backdoor em codigo.
- **Fraude financeira:** usar Stripe secret key para criar charges, refunds ou transferencias. Verificar scopes da chave antes de reportar.
- **Pivotar via service accounts:** tokens de servico frequentemente tem acesso a outros ambientes (staging -> production) ou servicos (Slack -> internal channels -> mais segredos).
- **Forjar JWT:** usar JWT secrets expostos para criar tokens com claims arbitrarios (admin, qualquer user ID) e bypass completo de autenticacao.
- **Combinar com SSRF:** usar credenciais cloud para acessar metadata endpoints internos (`169.254.169.254`) e obter credenciais IAM temporarias com mais privilegios.
- **Enviar comunicacoes:** usar tokens Twilio/SendGrid/Mailgun para enviar emails/SMS como a organizacao -- util para phishing interno ou demonstracao de impacto.

## False Positive Indicators
- Strings que matcham regex de tokens mas sao exemplos ou placeholders: `AKIAIOSFODNN7EXAMPLE`, `sk_test_...`, `your-api-key-here`, `xxx`, valores com apenas caracteres repetidos.
- Tokens revogados ou expirados -- validar com chamada API antes de reportar (ex.: `aws sts get-caller-identity`, `curl -H "Authorization: token ghp_..." https://api.github.com/user`).
- Chaves de test/staging sem acesso a dados de producao -- Stripe `sk_test_` vs `sk_live_`, tokens com scope limitado a sandbox.
- Hashes (SHA-256, MD5, bcrypt) que matcham regex de tokens por comprimento e charset mas nao sao credenciais.
- Chaves publicas (Stripe `pk_live_`, Firebase API Key para client) que sao intencionalmente expostas e tem restricoes de dominio/IP -- verificar se a chave realmente da acesso nao intencional.
- UUIDs e session IDs que matcham padroes genericos de tokens mas sao efemeros e nao reutilizaveis.

## Recommendation
1. Nunca incluir segredos em codigo client-side. Usar variaveis de ambiente carregadas server-side only.
2. Usar prefixo `NEXT_PUBLIC_` / `REACT_APP_` / `VITE_` apenas para valores realmente publicos. Chaves de API de servicos pagos ou com permissoes elevadas devem ficar server-side.
3. Rotacionar imediatamente qualquer credencial exposta -- revoke e re-emitir.
4. Desabilitar source maps em producao (`devtool: false` no Webpack, `productionSourceMaps: false`).
5. Implementar secret scanning no CI/CD (gitleaks, trufflehog, detect-secrets) para prevenir commits com segredos.
6. Bloquear acesso a `/.env`, `/config.json` e source maps no web server ou CDN.
7. Usar proxies server-side para chamadas a APIs externas -- o client nunca precisa da chave real.
8. Auditar bundles JS periodicamente com regex para padroes de segredos conhecidos.
