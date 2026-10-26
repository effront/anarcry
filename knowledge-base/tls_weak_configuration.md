---
id: tls_weak_configuration
title: "Weak TLS Configuration"
module: "tls"
severity: "MEDIUM"
cwe_id: "CWE-326"
cwe_title: "Inadequate Encryption Strength"
cvss_vector: "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N"
vrt_id: "cryptography_issues.weak_tls"
---

## Summary
Configuração de TLS que aceita versões obsoletas, cifras fracas ou certificados inválidos, permitindo downgrade e interceptação do tráfego. Afeta a confidencialidade de credenciais, tokens e dados pessoais em trânsito.

## Description
O TLS protege a confidencialidade e a integridade do canal entre cliente e servidor por meio de um handshake que negocia versão, suíte de cifras e autenticação do servidor. Quando o servidor ainda aceita SSLv3, TLS 1.0 ou TLS 1.1, ou permite suítes sem forward secrecy (RSA key exchange), RC4, 3DES, CBC com MAC fraco ou NULL ciphers, um atacante em posição de rede pode forçar downgrade, explorar fraquezas conhecidas (BEAST, POODLE, SWEET32, Lucky13) ou quebrar a sessão com custo reduzido.

A falha também se manifesta por certificado expirado, hostname mismatch, cadeia incompleta, chave RSA curta, ausência de OCSP stapling e protocolos legados habilitados em portas alternativas (8443, 9443, 993, 995, 465, 587). Do ponto de vista de bug bounty, o achado costuma ser aceito quando há impacto demonstrável: captura de sessão, aceitação de cipher export-grade, certificado inválido em endpoint autenticado ou TLS 1.0 em fluxo de pagamento.

## Impact
- Interceptação e leitura de tráfego sensível (credenenciais, cookies, JWTs, dados de cartão, PII).
- Ataques de downgrade e SSL stripping contra usuários em redes hostis.
- Quebra de conformidade com PCI DSS, LGPD, HIPAA e requisitos de segurança de fornecedores.
- Possibilidade de personificação do servidor quando o certificado é inválido ou a validação é desativada.
- Reputação e confiança do cliente afetadas; dependendo do fluxo, o impacto sobe para HIGH.

## Payloads and Bypasses
```bash
# Enumeração de versões e cifras
openssl s_client -connect alvo.com:443 -servername alvo.com -tls1
openssl s_client -connect alvo.com:443 -servername alvo.com -tls1_1
openssl s_client -connect alvo.com:443 -servername alvo.com -tls1_2
openssl s_client -connect alvo.com:443 -servername alvo.com -tls1_3

# Cifras fracas / ausência de PFS
openssl s_client -connect alvo.com:443 -cipher 'RC4-SHA'
openssl s_client -connect alvo.com:443 -cipher 'DES-CBC3-SHA'
openssl s_client -connect alvo.com:443 -cipher 'TLS_RSA_WITH_AES_128_CBC_SHA'

# Certificado
openssl s_client -connect alvo.com:443 -servername alvo.com </dev/null 2>/dev/null \
  | openssl x509 -noout -subject -issuer -dates -serial -fingerprint -sha256

# Ferramentas de varredura
nmap --script ssl-enum-ciphers -p 443,8443 alvo.com
testssl.sh --severity HIGH --fast alvo.com
sslyze --regular alvo.com
```

Bypasses e variações que o crawler deve considerar:
```text
- Portas alternativas com o mesmo serviço: 443, 8443, 9443, 993, 995, 465, 587, 636
- SNI diferente do Host (vhosts internos)
- Handshake sem SNI (-noservername) para obter o certificado default
- TLS 1.0/1.1 habilitado apenas em endpoints legados (/api/v1, /payment)
- Certificado válido no apex, mas inválido em subdomínio ou wildcard incompleto
- Cadeia incompleta que falha em clientes estritos, mas passa no navegador
- Cipher suites com chave < 2048 bits ou certificado SHA-1
```

Casos reais e mentalidade de ataque (RWBH): o TLS fraco é tratado como porta de entrada para downgrade e captura de sessão; em programas como Uber, Twitter e Yahoo, versões legadas e certificados inválidos costumam ser reportados como falha de infraestrutura, não como bug isolado.

## Target Context (Crawler Hints)
- **Parâmetros comuns:** não se aplica (nível de transporte); observar `Host`, `SNI` e porta de destino.
- **Paths comuns:** qualquer endpoint HTTPS, especialmente `/login`, `/oauth/token`, `/api/*`, `/payment`, `/admin`, `/graphql`.
- **Ativos comuns:** portas 443, 8443, 9443, 993, 995, 465, 587, 636, 5061.

## Recommendation
1. Desabilitar SSLv3, TLS 1.0 e TLS 1.1. Aceitar apenas TLS 1.2 e TLS 1.3.
2. Restringir suítes a AEAD com forward secrecy: `ECDHE-ECDSA-AES128-GCM-SHA256`, `ECDHE-RSA-AES128-GCM-SHA256`, `ECDHE-ECDSA-AES256-GCM-SHA384`, `ECDHE-RSA-AES256-GCM-SHA384`, `TLS_AES_128_GCM_SHA256`, `TLS_AES_256_GCM_SHA384`, `TLS_CHACHA20_POLY1305_SHA256`.
3. Desabilitar RC4, 3DES, NULL, EXPORT, CBC sem AEAD e troca de chave RSA estática.
4. Usar certificados RSA >= 2048 bits ou ECDSA P-256/P-384, com automação de renovação (ACME), OCSP stapling e cadeia completa.
5. Aplicar HSTS com `max-age` longo após validar todos os subdomínios.
6. Monitorar expiração e regressões de configuração com testes contínuos (`testssl.sh`, `sslyze`) no CI/CD.

Exemplo de configuração Nginx:
```nginx
ssl_protocols TLSv1.2 TLSv1.3;
ssl_prefer_server_ciphers off;
ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384';
ssl_session_tickets off;
ssl_stapling on;
ssl_stapling_verify on;
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
```

Exemplo de configuração Java/Spring Boot:
```yaml
server:
  ssl:
    enabled: true
    enabled-protocols: TLSv1.3,TLSv1.2
    ciphers:
      - TLS_AES_256_GCM_SHA384
      - TLS_CHACHA20_POLY1305_SHA256
      - TLS_AES_128_GCM_SHA256
      - TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
      - TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
```

Para APIs internas, use mTLS e rotação de certificados. Para bancos e mensageria, aplique a mesma política e desabilite protocolos legados nos listeners.
