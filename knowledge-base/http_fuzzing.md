---
id: http_fuzzing
title: "HTTP Fuzzing and Intruder Techniques"
module: "waf"
severity: "MEDIUM"
cwe_id: "CWE-20"
cwe_title: "Improper Input Validation"
cvss_vector: "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N"
vrt_id: "input_validation.fuzzing"
---

## Summary
HTTP fuzzing e a tecnica automatizada de enviar multiplas requisicoes HTTP modificadas a um alvo, variando parametros especificos com payloads de wordlists ou ranges numericos, para descobrir vulnerabilidades como SQLi, XSS, auth bypass, IDOR e enumeracao de diretorios.

## Description
O fuzzer HTTP (Intruder) permite injetar payloads em posicoes marcadas com `{{N}}` em templates de requisicao HTTP. Quatro modos de ataque cobrem cenarios distintos:

- **Sniper**: testa uma posicao por vez com um wordlist -- ideal para testar cada parametro individualmente.
- **Battering Ram**: mesma payload em todas as posicoes simultaneamente -- para valores que devem ser identicos em multiplos pontos.
- **Pitchfork**: wordlists diferentes em paralelo (zip) -- para pares correlacionados (username:password).
- **Cluster Bomb**: produto cartesiano de todas as wordlists -- para brute-force de combinacoes.

Payloads podem ser transformados via pipeline de processadores (URL encode, Base64, hash, regex replace, prefix/suffix) antes da injecao.

## Impact
- Descoberta de vulnerabilidades de injecao (SQLi, XSS, CMDi, SSTI) via variacao automatizada de payloads.
- Brute-force de credenciais e tokens.
- Enumeracao de diretorios, arquivos e endpoints ocultos.
- Descoberta de IDOR via iteracao de IDs.
- Bypass de rate limiting e deteccao de WAF.

## Payloads and Bypasses
Wordlists essenciais para fuzzing:
```
# Enumeracao de diretorios
common.txt
directory-list-2.3-medium.txt
raft-large-directories.txt
raft-large-files.txt

# Injecao
xss.txt
sqli-time-based.txt
command-injection.txt
ssti-payloads.txt
lfi-linux.txt
lfi-windows.txt

# Auth
default-credentials.txt
top-passwords-10000.txt
usernames-top-500.txt

# Parametros
burp-parameter-names.txt
common-api-params.txt
```

Tecnicas de fuzzing avancado:
```
# Content-Type fuzzing
application/json
application/xml
application/x-www-form-urlencoded
multipart/form-data
text/plain
text/xml

# HTTP Method fuzzing
GET POST PUT DELETE PATCH OPTIONS HEAD TRACE

# Header fuzzing
X-Forwarded-For: 127.0.0.1
X-Forwarded-Host: evil.com
X-Original-URL: /admin
X-Rewrite-URL: /admin
```

## Target Context (Crawler Hints)
- **Parameters:** `id`, `q`, `search`, `username`, `password`, `email`, `page`, `limit`, `sort`, `order`, `filter`, `token`, `file`, `path`, `url`, `redirect`
- **Paths:** `/api/*`, `/login`, `/search`, `/admin`, `/upload`, `/export`, `/import`, `/graphql`, `/api/v1/*`, `/api/v2/*`

## Notable CVEs

| CVE | Produto | Ano | Descricao | Tipo |
|-----|---------|-----|-----------|------|
| CVE-2023-34362 | MOVEit Transfer | 2023 | SQLi descoberto via fuzzing de parametros em endpoint de transferencia -- explorado em massa pelo Cl0p | Fuzzing-discovered SQLi |
| CVE-2023-46747 | F5 BIG-IP | 2023 | Auth bypass descoberto via fuzzing de headers em endpoint de management -- AJP smuggling | Header fuzzing |
| CVE-2024-3400 | Palo Alto PAN-OS | 2024 | Command injection via fuzzing de cookie SESSID em GlobalProtect -- RCE pre-auth (CVSS 10.0) | Parameter fuzzing |
| CVE-2021-44228 | Log4j | 2021 | JNDI injection descoberto via fuzzing de headers User-Agent e X-Forwarded-For -- Log4Shell | Header fuzzing |
| CVE-2023-22515 | Atlassian Confluence | 2023 | Auth bypass via fuzzing de parametros de setup -- permite criar admin sem autenticacao | Parameter fuzzing |

## Escalation Techniques
- **De enumeracao para injecao:** usar o fuzzer para encontrar parametros que refletem input no body (potencial XSS) ou causam erros de banco (potencial SQLi), depois escalar com payloads especificos.
- **De auth bypass para account takeover:** quando fuzzing de credenciais encontra credenciais validas, usar para acessar a conta e escalar privilegios.
- **De IDOR para data dump:** quando fuzzing de IDs revela dados de outros usuarios, automatizar a extracao iterando todo o range de IDs.
- **Combinacao com grep extract:** usar grep para extrair tokens CSRF, session IDs ou dados sensiveis das respostas, e usa-los em requisicoes subsequentes.
- **Rate limit bypass via fuzzing:** testar diferentes headers (X-Forwarded-For, X-Real-IP) com IPs variados para contornar rate limiting.

## Hunting Methodology
1. Mapear todos os endpoints e parametros da aplicacao via Crawler.
2. Para cada parametro, fazer fuzzing inicial com payloads de deteccao generica (aspas, operadores SQL, tags HTML, template markers).
3. Filtrar respostas por anomalias: status code diferente, tamanho de resposta significativamente diferente, tempo de resposta anormal.
4. Para parametros que mostraram anomalia, escalar com payloads especificos do tipo de vulnerabilidade suspeita.
5. Usar grep match para identificar padroes de erro (stack traces, SQL errors, template errors) nas respostas.
6. Para autenticacao, usar Pitchfork com listas de credenciais e monitorar diferencas no tamanho da resposta.
7. Para IDOR, usar Range source com IDs sequenciais e filtrar por respostas com tamanho variavel.

## False Positive Indicators
- Resposta com status 200 mas body identico para todos os payloads -- servidor retorna pagina generica independente do input.
- Variacao de tamanho de resposta e minima (< 10 bytes) e consistente -- pode ser timestamp ou request ID no body.
- Rate limiting ativado (429) confundido com deteccao de vulnerabilidade -- repetir com delay.
- WAF bloqueando payloads (403) -- indica protecao, nao vulnerabilidade.
- Respostas lentas devido a carga do servidor, nao a time-based injection -- repetir com baseline.

## Recommendation
1. Implementar validacao de input e queries parametrizadas para prevenir injecao.
2. Aplicar rate limiting e lockout de conta para mitigar brute-force.
3. Configurar regras de WAF para detectar padroes comuns de fuzzing.
4. Usar CSRF tokens para prevenir submissao automatizada de formularios.
5. Retornar mensagens de erro consistentes para prevenir information leakage.
6. Monitorar logs para detectar padroes de fuzzing (volume alto de requests com payloads similares).
