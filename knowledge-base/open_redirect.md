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

## Escalation Techniques
Open redirect isolado e frequentemente classificado como baixo impacto, mas pode ser escalado significativamente:

- **Phishing de alta credibilidade:** o atacante envia link no dominio legitimo (ex: `https://example.com/login?next=https://attacker.com/fake_login.html`). Apos login real, a vitima e redirecionada para pagina falsa que imita o login e pede credenciais novamente ("senha incorreta, tente de novo"). O atacante pode ate redirecionar de volta para o site real para esconder o roubo.
- **Bypass de allowlist/blocklist em SSRF:** um open redirect em pagina do dominio permitido pode ser usado para redirecionar requests SSRF para enderecos internos, contornando validacoes que aceitam apenas URLs do proprio dominio.
- **Roubo de tokens OAuth:** quando a pagina redireciona, o browser inclui a URL de origem no header `Referer`. Se a URL original contiver tokens de autenticacao (access tokens, authorization codes), o atacante pode captura-los via Referer no servidor de destino.
- **Encadeamento com redirect chains:** mesmo sem open redirect direto no endpoint sensivel, cadeias de redirecionamento podem ser usadas para vazar tokens para fora do dominio.
- **Bypass de controles baseados em dominio:** webhooks, integracoes e validacoes que confiam em "redirect interno" podem ser abusados se existir um open redirect no dominio confiavel.

Ao avaliar impacto, considere: o redirect pode ser encadeado com OAuth, SSRF ou outra vuln? Tokens sensiveis estao presentes na URL de origem? O dominio e de alta confianca (banco, e-mail)?

## Hunting Methodology
Processo passo a passo para identificar Open Redirects:

1. **Buscar parametros de redirect:** navegar pelo site com proxy e identificar parametros que contem URLs absolutas ou relativas -- nomes comuns: `redirect`, `redir`, `next`, `u`, `n`, `forward`, `return`, `RelayState`, `dest`, `url`, `continue`.
2. **Usar Google Dorks:** buscar parametros de redirect indexados com `inurl:%3Dhttp site:example.com` (encontra `=http` em parametros) e `inurl:%3D%2F site:example.com` (encontra `=/` para URLs relativas). Testar tambem `inurl:redir`, `inurl:redirect`, `inurl:returnurl`, `inurl:next` etc.
3. **Identificar redirects por Referer:** anotar paginas que redirecionam automaticamente (3XX) sem parametro de redirect na URL -- elas podem usar o header Referer para determinar o destino. Testar hospedando pagina HTML com link para o alvo e verificando se o redirect volta para o atacante.
4. **Testar parameter-based redirect:** inserir hostname externo no parametro de redirect e verificar se o site redireciona para ele. Algumas paginas so redirecionam apos acao do usuario (login, logout) -- executar a acao completa.
5. **Bypassar protecoes:** se o redirect e bloqueado, tentar: autocorrecao do browser (`https:attacker.com`, `https;attacker.com`, `https:\/\/attacker.com`); subdominio falso (`http://example.com.attacker.com`); `@` no userinfo (`https://example.com@attacker.com`); double encoding (`%252f`); data URL (`data:text/html;base64,...`); caracteres non-ASCII e Unicode lookalikes.
6. **Encadear com outros bugs:** usar o open redirect para escalar impacto -- tentar bypass de SSRF allowlist, roubo de token OAuth via Referer, ou phishing sofisticado.

## False Positive Indicators
Sinais de que o redirect detectado pelo scanner **nao e Open Redirect exploravel**:

- **Redirect para path relativo interno:** se o parametro aceita apenas paths relativos (`/dashboard`, `/settings`) e o servidor prefixa o proprio dominio, nao e possivel redirecionar para site externo.
- **Allowlist por host exato:** se o servidor valida o hostname contra lista exata (nao por substring/prefixo), payloads como `example.com.attacker.com` e `example.com@attacker.com` serao bloqueados.
- **Pagina de aviso intermediaria:** se o servidor exibe pagina "Voce esta saindo de example.com" antes de redirecionar, o impacto e reduzido significativamente -- o usuario tem chance de perceber o destino.
- **Redirect apenas em 3XX sem dados sensiveis:** um redirect 301/302 puro sem tokens na URL ou Referer tem impacto limitado a phishing basico, que muitos programas consideram fora de escopo.
- **Bypass nao funciona no browser real:** alguns bypasses de URL (double encoding, unicode) podem funcionar no parser do servidor mas nao no browser, ou vice-versa. Confirmar sempre no browser.
- **Parametro nao e usado para redirect:** o scanner pode detectar URL em parametro que e usada para outro fim (ex: `?url=` que carrega conteudo em iframe sem redirecionar a pagina inteira). Isso pode ser outro tipo de vuln (SSRF), mas nao e open redirect.

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
