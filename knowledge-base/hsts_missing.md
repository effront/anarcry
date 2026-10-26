---
id: hsts_missing
title: "Missing HTTP Strict Transport Security"
module: "hsts"
severity: "LOW"
cwe_id: "CWE-319"
cwe_title: "Cleartext Transmission of Sensitive Information"
cvss_vector: "AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N"
vrt_id: "server_security_misconfiguration.missing_security_headers"
---

## Summary
Ausência do header `Strict-Transport-Security` permite que o navegador continue acessando o site via HTTP, expondo usuários a SSL stripping e interceptação em redes hostis.

## Description
HSTS instrui o navegador a usar somente HTTPS para um domínio por um período (`max-age`), opcionalmente incluindo subdomínios e solicitando inclusão na lista de preload dos navegadores. Sem HSTS, um atacante em posição de rede pode interceptar a primeira requisição HTTP, redirecionar para uma versão HTTP controlada e capturar credenciais/cookies antes do redirect para HTTPS (SSL stripping).

A ausência é particularmente relevante em:
- Domínios sem redirect 301 de HTTP para HTTPS.
- Cookies de sessão sem `Secure`.
- Subdomínios que ainda servem HTTP.
- Aplicações com login, pagamento e painéis administrativos.
- Sites que usam `X-Forwarded-Proto` de forma incorreta e emitem HSTS apenas em algumas rotas.

HSTS não protege a primeira visita (se o site nunca foi acessado via HTTPS) nem contra certificados inválidos se o usuário aceitar a exceção; por isso é complementado por preload e redirect.

## Impact
- Interceptação de credenciais e cookies em redes Wi-Fi públicas/hostis.
- SSL stripping e phishing de downgrade.
- Vazamento de tokens em tráfego HTTP.
- Não conformidade com baselines de segurança.
- Impacto LOW isoladamente; sobe quando há cookies sem `Secure` ou login em HTTP.

## Payloads and Bypasses
```bash
# Verificar HSTS em HTTPS
curl -sI https://alvo.com/ | grep -i strict-transport-security

# Verificar comportamento em HTTP
curl -sI http://alvo.com/ | head -20

# Verificar subdomínios
curl -sI https://sub.alvo.com/ | grep -i strict-transport-security

# Verificar cookie Secure
curl -sI https://alvo.com/login | grep -i set-cookie

# Verificar redirecionamento
curl -s -o /dev/null -w '%{http_code} %{redirect_url}\n' http://alvo.com/
```

Configurações fracas a reportar:
```text
Strict-Transport-Security: max-age=0
Strict-Transport-Security: max-age=300
Strict-Transport-Security: max-age=31536000          # sem includeSubDomains em site com subdomínios
Strict-Transport-Security: max-age=31536000; includeSubDomains   # sem preload
Header presente apenas em /login, ausente em /admin
Header presente em HTTPS, mas HTTP não redireciona
Cookie de sessão sem Secure/HttpOnly
```

Bypasses/observações:
```text
- HSTS é ignorado em HTTP; se o site não redireciona, o primeiro acesso é vulnerável
- Subdomínio sem HSTS pode ser usado para setar cookies para o domínio pai
- `includeSubDomains` ausente permite downgrade em subdomínios
- Preload removal é lento; validar antes de solicitar
- X-Forwarded-Proto: http pode suprimir HSTS em apps que confiam no header
```

Casos reais e mentalidade de ataque (RWBH): a mentalidade é combinar ausência de HSTS com cookies sem `Secure` e login HTTP para capturar sessão em redes hostis; o atacante procura o primeiro request antes do redirect.

## Target Context (Crawler Hints)
- **Parâmetros comuns:** não se aplica (header de resposta); observar `Host`, `X-Forwarded-Proto`.
- **Paths comuns:** `/`, `/login`, `/account`, `/admin`, `/checkout`, todos os subdomínios.
- **Sinais:** ausência de `Strict-Transport-Security`; `max-age` curto; HTTP sem 301; cookies sem `Secure`.

## Recommendation
1. Enviar em todas as respostas HTTPS:
```http
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
```
2. Redirecionar todo HTTP para HTTPS com 301 antes de qualquer conteúdo:
```nginx
server {
    listen 80;
    server_name alvo.com www.alvo.com;
    return 301 https://$host$request_uri;
}
```
3. Garantir que todos os subdomínios suportem HTTPS antes de usar `includeSubDomains`.
4. Marcar cookies de sessão como `Secure`, `HttpOnly` e `SameSite=Lax/Strict`.
5. Remover recursos mistos (HTTP dentro de HTTPS) e usar HSTS apenas após validar a cadeia completa.
6. Solicitar inclusão na HSTS Preload List após cumprir os requisitos; manter o header por longo prazo.
7. Não confiar em `X-Forwarded-Proto` do cliente para decidir emitir HSTS; configurar o proxy para normalizar.
8. Monitorar expiração/regressão do header e cookies em CI.
