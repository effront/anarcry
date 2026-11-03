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

## Escalation Techniques
TLS fraco nao e apenas um achado de compliance -- e o ponto de partida para interceptacao real de trafego:

- **TLS downgrade + roubo de credenciais:** o atacante em posicao MitM (ARP spoofing, rogue Wi-Fi) forca downgrade para TLS 1.0/CBC e explora BEAST ou POODLE para decifrar cookies de sessao ou Bearer tokens byte a byte. Com o token capturado, assume a sessao da vitima.
- **Cipher fraco + session hijacking:** se o servidor negocia RC4 ou ciphers export-grade, o bias do keystream (RC4) ou o tamanho pequeno da chave (EXPORT) permite decifrar a sessao com custo computacional moderado. Cookies roubados dao account takeover completo.
- **Certificado invalido + phishing:** certificado self-signed, expirado ou com hostname mismatch em subdominio pode ser combinado com DNS spoofing para criar site de phishing convincente. O browser exibe aviso, mas usuarios clicam "continuar" -- especialmente em mobile.
- **Ausencia de forward secrecy + vigilancia passiva:** quando o servidor usa troca de chave RSA estatica (sem ECDHE/DHE), um atacante que comprometa a chave privada do servidor no futuro pode decifrar todo o trafego capturado anteriormente. E o cenario "harvest now, decrypt later" para criptografia classica.
- **TLS fraco interno + SSRF pivot:** se servicos internos usam TLS fraco ou nenhum TLS, uma vulnerabilidade SSRF na aplicacao publica permite interceptar ou alterar trafego interno que era considerado seguro.
- **Cadeia incompleta + client mismatch:** certificado com intermediarios faltando funciona em browsers que fazem cache, mas falha em clientes estritos (curl, apps mobile, IoT). Isso pode causar denial of service seletivo ou forcar fallback inseguro.

## Hunting Methodology
Processo passo a passo para avaliar a configuracao TLS:

1. **Enumerar versoes de protocolo:** testar SSLv3, TLS 1.0, TLS 1.1, TLS 1.2 e TLS 1.3 com `openssl s_client` ou `testssl.sh`. Qualquer versao abaixo de TLS 1.2 e um finding. Registrar quais versoes sao aceitas.
2. **Enumerar cipher suites:** usar `nmap --script ssl-enum-ciphers` ou `sslyze` para listar todas as suites aceitas. Sinalizar RC4, 3DES, NULL, EXPORT, anonymous (aNULL), CBC sem AEAD e troca de chave RSA estatica (sem PFS).
3. **Verificar cadeia de certificados:** confirmar que subject/SAN bate com o hostname, certificado nao esta expirado, cadeia esta completa (sem intermediarios faltando), chave RSA >= 2048 bits ou ECDSA P-256+, e assinatura usa SHA-256 ou superior.
4. **Testar portas alternativas:** escanear 443, 8443, 9443, 993, 995, 465, 587, 636 e portas customizadas. Servicos em portas nao padrao frequentemente tem configuracao mais fraca que o listener HTTPS principal.
5. **Testar comportamento SNI:** conectar sem SNI (`-noservername`) e com valores `Host` diferentes para verificar certificados default que exponham hostnames internos ou aceitem ciphers mais fracos em virtual hosts.
6. **Validar OCSP e revogacao:** verificar OCSP stapling (`openssl s_client -status`), pontos de distribuicao de CRL e se o servidor responde corretamente a certificados revogados.
7. **Contextualizar o finding:** TLS 1.0 em endpoint de login/pagamento e HIGH; TLS 1.0 em endpoint de health check publico e LOW. Documentar qual dado flui pela conexao.

## False Positive Indicators
Sinais de que o finding de TLS fraco **nao representa risco real no contexto**:

- **CDN ou load balancer termina TLS antes da origem:** o scanner pode testar o edge do CDN (Cloudflare, CloudFront, Akamai) que suporta TLS moderno, enquanto a origem atras dele tem config mais fraca. Ou vice-versa -- o scanner atinge a origem diretamente e reporta TLS fraco que usuarios nunca veem porque o CDN forca configuracao forte.
- **Cipher listado como suportado mas nunca negociado na pratica:** alguns servidores anunciam cipher suites para compatibilidade mas sempre preferem a mais forte via server-order preference. Se o cipher fraco e o ultimo na prioridade e so usado quando o cliente nao suporta nada melhor, o risco real e menor.
- **Certificado intermediario parece ausente mas esta em cache:** browsers fazem cache de certificados intermediarios de conexoes anteriores. O scanner pode reportar "cadeia incompleta" enquanto browsers funcionam normalmente. E um finding valido mas de severidade menor -- clientes novos ou estritos falharao.
- **Certificado self-signed em endpoint interno/nao-producao:** endpoints de desenvolvimento, staging ou health check podem usar certificados self-signed legitimamente. Confirmar que o endpoint e user-facing e lida com dados sensiveis antes de escalar.
- **TLS 1.0 habilitado em porta sem dados sensiveis:** endpoint de monitoramento ou metricas em porta nao padrao que serve apenas dados publicos de health check tem risco menor que uma pagina de login. Contextualizar o finding baseado no tipo de dado que trafega pela conexao.

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
