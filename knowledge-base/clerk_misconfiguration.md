---
id: clerk_misconfiguration
title: "Clerk Authentication Misconfiguration"
module: "clerk"
severity: "HIGH"
cwe_id: "CWE-200"
cwe_title: "Exposure of Sensitive Information to an Unauthorized Actor"
cvss_vector: "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N"
vrt_id: "sensitive_data_exposure.authentication_credentials"
---

## Summary
Clerk e um provedor de autenticacao popular para aplicacoes Next.js, React e outros frameworks modernos. Misconfiguracao do Clerk em producao -- como uso de chaves de desenvolvimento (pk_test_), exposicao do endpoint /v1/environment, e user enumeration via sign-in -- pode expor dados sensiveis, facilitar engenharia social e permitir ataques de credential stuffing.

## Description
O Clerk fornece autenticacao como servico (AuthaaS) com SDKs frontend que utilizam chaves publicaveis (publishable keys) para inicializar o client-side. Existem dois tipos de chaves:

- **pk_live_**: chave de producao, vinculada ao ambiente de producao com politicas de seguranca estritas.
- **pk_test_**: chave de desenvolvimento/teste, vinculada a ambientes com configuracoes relaxadas (ex.: rate limiting desabilitado, MFA opcional, dominios de teste).

Quando uma chave pk_test_ e usada em producao, o frontend se conecta ao ambiente de desenvolvimento do Clerk, que pode ter:
- Politicas de senha mais fracas
- MFA desabilitado
- Rate limiting ausente ou relaxado
- Dados de teste misturados com dados reais

Alem disso, o Clerk expoe endpoints de API que podem vazar informacoes de configuracao:

- **/v1/environment** -- retorna configuracao completa do ambiente incluindo auth providers habilitados (Google, GitHub, email/password), configuracoes de MFA, URLs de callback, branding/identidade visual. Essa informacao facilita ataques direcionados.
- **/v1/client/sign_ins** -- endpoint de login que pode permitir user enumeration se retornar respostas diferentes para usuarios existentes vs inexistentes (ex.: "identifier not found" vs "wrong password" ou "needs first factor").

A deteccao de versoes antigas do Clerk JS (< 4.0) tambem e relevante pois versoes anteriores podem conter vulnerabilidades conhecidas de XSS e bypass de autenticacao.

## Impact
- **Chave de desenvolvimento em producao**: atacante usa a pk_test_ para interagir com API Clerk do ambiente dev, potencialmente acessando configuracoes inseguras ou dados de teste.
- **Config disclosure via /v1/environment**: revela quais auth providers estao habilitados, facilitando engenharia social (saber que apenas email/password esta habilitado vs Google OAuth).
- **User enumeration**: atacante pode compilar lista de emails validos para credential stuffing, phishing direcionado ou account takeover.
- **Versao antiga**: vulnerabilidades conhecidas podem permitir XSS no fluxo de autenticacao ou bypass de verificacao.

## Payloads and Bypasses
```bash
# Detectar pk_test_ key em paginas HTML ou bundles JS
curl -s https://alvo.com/ | grep -oP 'pk_test_[A-Za-z0-9+/=]+'

# Buscar em bundles Next.js
curl -s https://alvo.com/_next/static/chunks/app/layout-*.js | grep -oP 'pk_test_[A-Za-z0-9+/=]+'

# Probar /v1/environment sem auth
curl -s https://alvo.com/v1/environment | jq .

# Probar /v1/environment com dev key
curl -s https://alvo.com/v1/environment \
  -H 'Authorization: Bearer pk_test_XXXX' | jq .

# User enumeration -- comparar respostas
curl -s -w '\n%{http_code}' -X POST https://alvo.com/v1/client/sign_ins \
  -H 'Content-Type: application/json' \
  -d '{"identifier":"fake-nonexistent@example.com"}'

curl -s -w '\n%{http_code}' -X POST https://alvo.com/v1/client/sign_ins \
  -H 'Content-Type: application/json' \
  -d '{"identifier":"admin@alvo.com"}'
```

## Target Context (Crawler Hints)
- **Sinais de Clerk**: presenca de `pk_test_` ou `pk_live_` em HTML/JS; script tags carregando `clerk.browser.js` ou `@clerk/clerk-js`; cookies `__clerk_db_jwt` ou `__session`.
- **Paths comuns**: `/v1/environment`, `/v1/client/sign_ins`, `/v1/client/sign_ups`, `/v1/me`, `/_clerk/`.
- **Frameworks associados**: Next.js, Remix, React, Gatsby -- Clerk e comum em stacks JavaScript modernas.

## Escalation Techniques
- **Chave dev + API Clerk**: com pk_test_, atacante pode fazer requests autenticados contra a API Clerk do ambiente dev -- listar sessoes, obter tokens, e potencialmente criar contas de teste com permissoes elevadas.
- **Config disclosure + social engineering**: saber quais auth providers estao habilitados permite ataques de phishing mais convincentes (ex.: "faça login com Google" falso se Google OAuth esta habilitado).
- **User enumeration + credential stuffing**: lista de emails validos combinada com bases de senhas vazadas para account takeover automatizado.
- **Versao antiga + XSS**: Clerk JS < 4.0 em combinacao com DOM sinks pode permitir XSS no fluxo de autenticacao, roubando tokens de sessao.

## False Positive Indicators
- **pk_test_ em ambiente de staging/dev**: se o alvo e um ambiente de desenvolvimento/staging, a presenca de pk_test_ e esperada e nao configura vulnerabilidade.
- **/v1/environment retornando dados publicos**: alguns dados retornados sao intencionalmente publicos (branding, nome da app). A finding e relevante quando auth_config ou user_settings estao expostos.
- **User enumeration com rate limiting**: se o endpoint aplica rate limiting agressivo (429 apos poucas tentativas), o risco pratico de enumeracao em massa e reduzido.
- **Respostas identicas para ambos probes de sign-in**: se status codes e mensagens de erro sao identicos, nao ha user enumeration.

## Notable CVEs

| CVE | Produto | Ano | Descricao | Tipo |
|-----|---------|-----|-----------|------|
| CVE-2024-22206 | Clerk (@clerk/nextjs) | 2024 | Bypass de autorizacao em auth() e getAuth() permite acesso nao autorizado ou escalacao de privilegios em aplicacoes Next.js (CVSS 9.8) | Auth Bypass |
| CVE-2025-53548 | Clerk (@clerk/backend) | 2025 | Bypass de verificacao de webhook permite envio de eventos com assinatura invalida para aplicacoes que consomem webhooks Clerk | Webhook Verification Bypass |
| CVE-2025-63700 | Clerk (clerk-js 5.88.0) | 2025 | Bypass do fluxo de autenticacao OAuth via manipulacao do request na etapa de verificacao OTP | OAuth Flow Bypass |
| CVE-2023-49103 | ownCloud graphapi | 2023 | Endpoint graphapi expoe phpinfo() com credenciais e chaves de API do admin -- CVSS 10.0, explorado em massa -- analogo a exposicao de /v1/environment | Config Disclosure |
| CVE-2023-28432 | MinIO | 2023 | Endpoint /minio/health/cluster vaza variaveis de ambiente incluindo MINIO_SECRET_KEY sem autenticacao -- analogo a vazamento de config em auth providers | Credential Disclosure |

## Recommendation
1. Usar chaves de producao (pk_live_) em ambientes de producao; armazenar chaves em variaveis de ambiente e nunca hardcoded no codigo.
2. Separar ambientes Clerk (dev, staging, prod) com instancias distintas.
3. Restringir acesso ao endpoint /v1/environment via middleware ou WAF -- bloquear acesso externo a endpoints internos da API Clerk.
4. Configurar Clerk para retornar mensagens de erro genericas em sign-in (nao diferenciar "usuario nao encontrado" de "senha incorreta").
5. Habilitar rate limiting e CAPTCHA no fluxo de sign-in para mitigar enumeracao e credential stuffing.
6. Manter @clerk/clerk-js atualizado para a versao mais recente; monitorar changelogs e security advisories do Clerk.
7. Auditar bundles JS de producao para garantir que nao contenham chaves de desenvolvimento ou informacoes de debug.
8. Exemplo de configuracao segura (Next.js):
```env
# .env.production
NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY=pk_live_xxxxx
CLERK_SECRET_KEY=sk_live_xxxxx
```
```javascript
// middleware.ts -- proteger endpoints Clerk internos
import { clerkMiddleware } from '@clerk/nextjs/server';
export default clerkMiddleware();
export const config = {
  matcher: ['/((?!_next|[^?]*\\.(?:html?|css|js|jpe?g|webp|png|gif|svg|ttf|woff2?|ico|csv|docx?|xlsx?|zip|webmanifest)).*)'],
};
```
