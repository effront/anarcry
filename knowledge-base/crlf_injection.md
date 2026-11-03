---
id: crlf_injection
title: "CRLF Injection / HTTP Response Splitting"
module: "crlf"
severity: "MEDIUM"
cwe_id: "CWE-113"
cwe_title: "Improper Neutralization of CRLF Sequences in HTTP Headers ('HTTP Response Splitting')"
cvss_vector: "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"
vrt_id: "cross_site_scripting_xss.reflected_xss"
---

## Summary
Injeção de sequências CR/LF em headers ou parâmetros permite criar cabeçalhos e respostas HTTP forjadas, levando a XSS, cache poisoning, fixação de sessão e bypass de controles.

## Description
O protocolo HTTP usa `\r\n` para separar headers e o corpo. Quando a aplicação insere entrada do usuário em um header (`Location`, `Set-Cookie`, `Content-Type`, `X-Forwarded-*`) ou em um contexto que será interpretado como header, um atacante pode injetar novas linhas e criar headers adicionais ou até uma resposta completa (HTTP response splitting).

Variações:
- **Header injection:** `?lang=en%0d%0aSet-Cookie:admin=1`.
- **Response splitting:** dois CRLF seguidos para terminar headers e iniciar corpo com HTML/JS.
- **Log injection:** quebra de linha em logs pode forjar entradas e confundir SIEM.
- **Cache poisoning:** headers injetados são cacheados e servidos a outras vítimas.
- **Session fixation:** `Set-Cookie` forjado define sessão do atacante.
- **Open redirect bypass:** `Location` com CRLF permite adicionar headers e corpo.

O bug depende de o servidor/proxy não normalizar ou rejeitar CR/LF. Frameworks modernos geralmente bloqueiam, mas wrappers, gateways, linguagens legadas e bibliotecas de terceiros podem reintroduzir a falha.

## Impact
- XSS em respostas que refletem headers (ex.: `Location` em página de erro).
- Cache poisoning e envenenamento de respostas para outros usuários.
- Fixação de sessão e roubo de cookies.
- Bypass de CSP, CORS e redirecionamentos.
- Falsificação de logs e dificuldade de auditoria.
- Impacto MEDIUM, escalando para HIGH em cache poisoning ou XSS armazenado.

## Payloads and Bypasses
```text
# Injeção básica em parâmetro refletido em header
?lang=en%0d%0aSet-Cookie:session=atacante
?url=https://alvo.com%0d%0aSet-Cookie:admin=true
?next=/home%0d%0aContent-Length:0

# Response splitting
?name=x%0d%0a%0d%0a<html><script>alert(document.domain)</script></html>
?q=x%0d%0a%0d%0aHTTP/1.1 200 OK%0d%0aContent-Type:text/html%0d%0a%0d%0a<script>alert(1)</script>

# Variações de newline
%0a
%0d
%0d%0a
%0a%0d
\r\n
\n
\r

# Double encoding
%250d%250a
%250a
%25250d%25250a

# Unicode / overlong
%E5%98%8A%E5%98%8D
%C0%8D%C0%8A

# Header injection em User-Agent / Referer / X-Forwarded-Host
User-Agent: x%0d%0aX-Forwarded-Host: evil.com
Referer: https://alvo.com/%0d%0aSet-Cookie:admin=1
```

PoC de response splitting:
```http
GET /redirect?url=%0d%0a%0d%0a<script>alert(document.domain)</script> HTTP/1.1
Host: alvo.com
```

Bypasses de WAF:
```text
- CRLF codificado uma ou duas vezes
- Mistura de \r e \n
- Unicode line separators (U+2028/U+2029) quando o parser normaliza
- Espaços/tabs entre header e valor
- Injeção via header de proxy (X-Forwarded-Host, X-Original-URL)
- Injeção em nome de cookie/atributo
- Quebra de linha em multipart/form-data
```

Casos reais e mentalidade de ataque (RWBH): Twitter e Yahoo (headers refletidos) ilustram response splitting, `Set-Cookie` forjado e envenenamento de cache; o atacante testa `%0d%0a`, dupla codificação e headers de proxy.

## Target Context (Crawler Hints)
- **Parâmetros comuns:** `url`, `redirect`, `next`, `return`, `lang`, `locale`, `page`, `file`, `name`, `email`, `subject`, `host`, `domain`, `callback`, `state`.
- **Headers comuns:** `Host`, `X-Forwarded-Host`, `X-Forwarded-For`, `X-Forwarded-Proto`, `Referer`, `User-Agent`, `Origin`.
- **Paths comuns:** `/redirect`, `/login`, `/logout`, `/set-locale`, `/api/redirect`, `/download`, `/error`, `/search`.
- **Sinais:** entrada refletida em `Location`, `Set-Cookie` ou `Content-Type`; headers duplicados; resposta com `\r\n` no valor; logs com linhas forjadas.

## Escalation Techniques
CRLF injection e um vetor inicial que escala rapidamente quando combinado com cache, sessao ou contexto HTML:

- **HTTP response splitting para XSS:** injetar `\r\n\r\n` seguido de body HTML com `<script>` para servir conteudo arbitrario ao browser da vitima. Se o proxy/CDN cachear a resposta splitada, o XSS se torna armazenado e afeta todos os usuarios -- equivalente a stored XSS de alto impacto.
- **Session fixation:** injetar `Set-Cookie: session=TOKEN_DO_ATACANTE` via CRLF para fixar a sessao da vitima; apos a vitima autenticar, o atacante usa o mesmo token para acessar a conta. O livro (Bug Bounty Bootcamp, Cap. 17) descreve como fluxos de autenticacao com logica falha sao explorados por session manipulation.
- **CSP bypass via header injection:** injetar `Content-Security-Policy: default-src *` que sobrescreve ou complementa o CSP existente, permitindo execucao de scripts inline ou de origens externas que seriam bloqueados pela politica original.
- **Open redirect chain:** quando CRLF existe em um header `Location`, o atacante encadeia com open redirect para phishing -- a vitima ve o dominio confiavel na URL inicial, mas e redirecionada para o site do atacante. O livro (Cap. 7) detalha tecnicas de bypass de validacao de URL que potencializam esse vetor.
- **CORS bypass:** injetar `Access-Control-Allow-Origin: https://evil.com` e `Access-Control-Allow-Credentials: true` via CRLF para contornar a politica CORS e ler dados autenticados cross-origin.
- **Log poisoning:** injetar newlines em campos que vao para logs (User-Agent, Referer) para forjar entradas de log, confundir SIEM, ou injetar payloads que serao interpretados por log viewers vulneraveis a XSS/injection.

## Hunting Methodology
Processo passo a passo para identificar CRLF injection, adaptado da abordagem geral de injection testing do livro (Bug Bounty Bootcamp, Cap. 5/6/25):

1. **Identificar pontos de reflexao em headers:** usar o proxy para mapear parametros cujo valor aparece em headers de resposta (`Location`, `Set-Cookie`, `Content-Type`, headers custom). Priorizar endpoints de redirect, login, locale, download e qualquer funcionalidade que use o parametro para construir um header.
2. **Testar injecao basica:** enviar `%0d%0aX-Injected:true` no valor do parametro e verificar se o header `X-Injected` aparece na resposta. Usar `curl -i` para inspecionar os headers brutos -- proxies de browser podem normalizar a resposta.
3. **Testar variantes de encoding:** se o basico for bloqueado, tentar double-encoding (`%250d%250a`), Unicode overlong (`%C0%8D%C0%8A`), e separadores Unicode (`%E5%98%8A%E5%98%8D`). Testar tambem `%0a` sozinho (LF sem CR), que pode funcionar em servidores que aceitam LF como terminador.
4. **Testar response splitting:** enviar `%0d%0a%0d%0a<html><script>alert(document.domain)</script></html>` para verificar se e possivel injetar corpo na resposta. Se o conteudo HTML renderizar no navegador, o impacto e XSS.
5. **Verificar cacheabilidade:** repetir o request com CRLF e verificar se a resposta manipulada e servida a outros usuarios (enviar o mesmo request sem o payload e checar se os headers injetados persistem). Isso indica cache poisoning, escalando o impacto significativamente.
6. **Testar headers de proxy:** injetar CRLF via `X-Forwarded-Host`, `Referer` e `User-Agent` -- esses headers sao frequentemente refletidos em logs ou respostas de erro sem sanitizacao.
7. **Fuzzing automatizado:** o livro (Cap. 25) descreve como usar Wfuzz ou Burp Intruder com wordlist de payloads CRLF em todos os pontos de entrada identificados. Analisar respostas que contenham headers inesperados.

## False Positive Indicators
Sinais de que a CRLF injection detectada pelo scanner **nao e exploravel**:

- **Framework moderno com protecao nativa:** frameworks como Spring Boot (5.x+), Express.js (4.x+) e Django rejeitam automaticamente `\r\n` em valores de header via API padrao -- a injecao nao passa mesmo que o parametro seja refletido.
- **Servidor retorna 400 Bad Request:** ao receber CRLF, o servidor rejeita a requisicao com erro -- a protecao esta funcionando e a injecao nao tem efeito.
- **Header refletido mas sem CRLF efetivo:** o scanner detecta que o valor do parametro aparece em um header, mas o servidor codifica ou remove `%0d%0a` antes de inserir -- o header nao e quebrado e nenhum header adicional e criado.
- **Proxy/WAF normaliza a resposta:** mesmo que o backend aceite CRLF, um proxy reverso (Nginx, Cloudflare) na frente pode normalizar headers e remover quebras de linha antes de entregar ao cliente -- o impacto real depende da topologia de rede.
- **Reflexao em corpo, nao em header:** o scanner marca CRLF porque o valor `%0d%0a` aparece na resposta, mas ele esta no corpo HTML (nao em um header HTTP) -- isso nao e CRLF injection, pode ser XSS se renderizado.
- **CRLF apenas em logs:** o payload afeta apenas logs do servidor, sem impacto na resposta HTTP ao cliente. Log injection e uma vulnerabilidade separada e de menor severidade.
## Recommendation
1. Rejeitar qualquer entrada que contenha `\r`, `\n` ou caracteres de controle antes de inserir em headers; usar validação de allowlist.
2. Usar APIs do framework que codificam headers automaticamente; nunca concatenar strings em `Location`/`Set-Cookie`.
3. Em Java, usar `HttpServletResponse.setHeader()` com valor sanitizado e validar com regex; evitar `addHeader` com entrada crua.
4. Em Nginx, usar `$uri` normalizado e `return 302` com destino validado; não repassar headers não confiáveis.
5. Normalizar e rejeitar sequências codificadas (`%0d`, `%0a`, `%250d`) após decodificação.
6. Configurar proxies/WAF para bloquear CR/LF em headers e parâmetros, mas não confiar apenas neles.
7. Sanitizar logs (escapar newlines) e nunca usar entrada do usuário como nome de header.
8. Exemplo Java:
```java
private static final Pattern CRLF = Pattern.compile("[\\r\\n\\u0000]");

public void redirect(HttpServletResponse res, String target) throws IOException {
    if (CRLF.matcher(target).find()) throw new IllegalArgumentException("invalid target");
    res.setStatus(302);
    res.setHeader("Location", target);
}
```
9. Testar respostas com `curl -i` e inspecionar headers/corpo após cada entrada.

