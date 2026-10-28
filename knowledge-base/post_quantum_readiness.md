---
id: post_quantum_readiness
title: "Post-Quantum Cryptography Readiness Gap"
module: "pqc"
severity: "LOW"
cwe_id: "CWE-311"
cwe_title: "Missing Encryption of Sensitive Data"
cvss_vector: "AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N"
vrt_id: "cryptography_issues.weak_tls"
---

## Summary
Ausência de criptografia híbrida pós-quântica (ML-KEM) em TLS e outros canais permite "harvest now, decrypt later": tráfego capturado hoje pode ser decifrado por um computador quântico futuro. É um risco de longo prazo, não uma exploração imediata.

## Description
Algoritmos de chave pública tradicionais (RSA, ECDH, ECDSA) são vulneráveis ao algoritmo de Shor em um computador quântico suficientemente grande. A migração recomendada é híbrida: combinar um KEM pós-quântico (ML-KEM, FIPS 203) com um algoritmo clássico (X25519), de modo que o canal permaneça seguro se qualquer um dos dois resistir.

O grupo híbrido `X25519MLKEM768` é o padrão de facto para TLS 1.3 e já está disponível em OpenSSL 3.5+, BoringSSL, Chrome e Java 27 (JEP 496/497 para ML-KEM e ML-DSA). A ausência desse grupo não é uma falha explorável hoje, mas indica dívida criptográfica: inventário incompleto, bibliotecas antigas, impossibilidade de trocar algoritmos rapidamente e dados de longa vida (saúde, financeiro, segredos de estado) expostos a descriptografia futura.

O finding deve ser classificado como LOW/INFO e contextualizado: não há PoC de quebra, mas há risco estratégico e requisitos regulatórios emergentes (NIST IR 8547, CNSA 2.0, orientações de bancos centrais).

## Impact
- Dados sensíveis capturados hoje podem ser lidos no futuro ("harvest now, decrypt later").
- Atraso na migração aumenta custo e risco de ruptura quando a criptografia clássica for depreciada.
- Sistemas com longo ciclo de vida (IoT, firmware, arquivos, backups, VPN) são os mais afetados.
- Potencial não conformidade com requisitos de agilidade criptográfica e normas setoriais.
- Sem impacto imediato em confidencialidade/integridade; por isso a severidade é baixa.

## Payloads and Bypasses
```bash
# Verificar suporte a grupos híbridos no servidor
openssl s_client -connect alvo.com:443 -servername alvo.com -groups X25519MLKEM768 -tls1_3

# Listar grupos suportados
nmap --script ssl-enum-ciphers -p 443 alvo.com
testssl.sh --protocols --groups alvo.com

# Verificar a pilha local
openssl version -a
openssl list -kem-algorithms | grep -i mlkem
openssl list -signature-algorithms | grep -i mldsa

# Java 27: confirmar algoritmos disponíveis
java --list-modules | grep -i crypto
```

Indicadores de prontidão a coletar:
```text
- TLS 1.3 habilitado
- Grupo X25519MLKEM768 ou SecP256r1MLKEM768 negociado
- Biblioteca TLS com suporte a ML-KEM (OpenSSL 3.5+, BoringSSL, AWS-LC)
- Certificados/assinaturas com migração planejada para ML-DSA
- Inventário de dependências criptográficas e plano de agilidade
- VPN/IPsec, SSH, S/MIME e code signing cobertos pelo plano
```

Casos reais e mentalidade de ataque (RWBH): a mentalidade é de risco futuro -- inventariar onde a criptografia clássica protege dados de longa vida e simular a migração híbrida antes que a quebra seja viável.

## Target Context (Crawler Hints)
- **Parâmetros comuns:** não se aplica (transporte); observar `SNI`, `Host` e versão TLS.
- **Paths comuns:** endpoints TLS 1.3, VPN, API gateways, mTLS entre serviços, `/health`, `/metrics`.
- **Sinais:** TLS 1.3 ausente, apenas grupos clássicos (`X25519`, `P-256`), bibliotecas antigas, ausência de política de criptografia.

## Recommendation
1. Habilitar TLS 1.3 e o grupo híbrido `X25519MLKEM768` (ou `SecP256r1MLKEM768`) nos terminadores TLS, load balancers, CDN e API gateways.
2. Atualizar OpenSSL/BoringSSL/AWS-LC e runtime Java; validar interoperabilidade com clientes antes de tornar o grupo preferencial.
3. Criar inventário de criptografia (algoritmos, bibliotecas, certificados, protocolos) e um plano de agilidade criptográfica.
4. Priorizar dados de longa vida: backups, arquivos, saúde, financeiro e segredos de infraestrutura.
5. Planejar migração de assinaturas para ML-DSA (FIPS 204) e SLH-DSA (FIPS 205) em certificados, firmware e code signing.
6. Não remover algoritmos clássicos prematuramente: usar modo híbrido durante a transição.
7. Monitorar suporte de clientes e fallback; medir a taxa de negociação híbrida antes de exigir o grupo.

Exemplo Nginx/OpenSSL (quando suportado):
```nginx
ssl_protocols TLSv1.3 TLSv1.2;
ssl_conf_command Groups X25519MLKEM768:X25519:P-256;
```

Exemplo Java 27 (JEP 496/497, conforme disponibilidade da build):
```java
KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-KEM");
kpg.initialize(MLKEMParameterSpec.ML_KEM_768);
KeyPair kp = kpg.generateKeyPair();
```
