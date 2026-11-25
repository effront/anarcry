---
id: sensitive_endpoint_exposure
title: "Sensitive Endpoint and API Spec Exposure"
module: "Crawler"
severity: "HIGH"
cwe_id: "CWE-200"
cwe_title: "Exposure of Sensitive Information to an Unauthorized Actor"
cvss_vector: "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
vrt_id: "sensitive_data_exposure.endpoint_exposure"
---

## Summary
Endpoints sensiveis (backups, configuracoes, repositorios Git, especificacoes API) estao acessiveis publicamente sem autenticacao, expondo dados internos, credenciais e estrutura da aplicacao.

## Description
O modulo Crawler realiza probing ativo contra uma wordlist de paths criticos (API docs, admin panels, .git, .env, backups, phpinfo) e analisa JS bundles para descobrir rotas adicionais. Tambem cruza com crawlerHints do Knowledge Base de todos os modulos habilitados para expandir a superficie de probing.

Dois tipos de finding sao gerados:

- **OpenAPI/Swagger exposto:** especificacao da API acessivel sem autenticacao, revelando todos os endpoints, parametros, schemas e modelos de dados internos.
- **Endpoint sensivel acessivel:** arquivos como .env, .git/config, backup.sql, phpinfo.php acessiveis via GET, expondo credenciais, configuracao do servidor e codigo-fonte.

A exposicao de .git e particularmente critica -- permite reconstruir o repositorio completo com historico de commits, onde credenciais frequentemente aparecem em commits antigos mesmo que removidas do HEAD atual.

## Impact
- Vazamento de credenciais de banco, API keys e tokens de servico via .env, config.json, .git
- Reconstrucao completa do codigo-fonte via .git/objects (inclui historico com segredos deletados)
- Mapeamento total da API via OpenAPI/Swagger spec -- facilita ataques direcionados em cada endpoint
- Acesso a backups de banco (backup.sql, dump.sql) com dados completos de producao
- Informacoes de debug (phpinfo, stack traces, heapdump) revelam versoes, paths internos e configuracao do runtime
- Escala de acesso via admin panels sem autenticacao

## Payloads and Bypasses
Paths de probing:
```
/.git/config
/.git/HEAD
/.git/logs/HEAD
/.git/refs/heads/main
/.git/objects/
/.env
/.env.local
/.env.production
/.env.backup
/config.json
/config.yaml
/settings.json
/phpinfo.php
/info.php
/backup.sql
/database.sql
/dump.sql
/backup.tar.gz
/backup.zip
```

API spec discovery:
```
/swagger.json
/swagger.yaml
/openapi.json
/openapi.yaml
/api-docs
/v2/api-docs
/v3/api-docs
/swagger-ui.html
/swagger-ui/index.html
/graphiql
/playground
/.well-known/openid-configuration
/.well-known/oauth-authorization-server
```

Admin e debug endpoints:
```
/admin
/admin/login
/administrator
/dashboard
/panel
/console
/debug
/trace
/actuator
/actuator/health
/actuator/env
/actuator/heapdump
/metrics
/healthz
/status
/rails/info/properties
/rails/mailers
/wp-admin
/wp-login.php
/xmlrpc.php
/phpmyadmin
```

Juicy paths (complemento):
```
/.DS_Store
/.svn
/.wp-config.php.swp
/api/proxy
/api/batch
/heapdump
/server-status
/nginx_status
/pprof
/jenkins/script
```

Tecnica de extracao .git:
```bash
# Verificar exposicao
curl -s -o /dev/null -w "%{http_code}" https://target/.git/config
curl -s -o /dev/null -w "%{http_code}" https://target/.git/HEAD

# Dump automatico com git-dumper
git-dumper https://target/.git/ output-dir/

# Buscar segredos no historico
trufflehog filesystem output-dir/
gitleaks detect --source output-dir/

# Recuperar objeto manualmente
wget https://target/.git/objects/26/e35470d38c4d6815bc4426a862d5399f04865c
git cat-file -p 26e35470d38c4d6815bc4426a862d5399f04865c
```

## Target Context (Crawler Hints)
- **Parametros comuns:** `q`, `search`, `query`, `url`, `path`, `file`, `page`, `dir`, `folder`, `redirect`
- **Paths comuns:** `/api/*`, `/admin`, `/.git/config`, `/.env`, `/swagger.json`, `/actuator`, `/backup`, `/phpinfo.php`, `/graphql`, `/debug`, `/console`, `/metrics`, `/healthz`, `/sitemap.xml`, `/robots.txt`

## Notable CVEs

| CVE | Produto | Ano | Descricao | Tipo |
|-----|---------|-----|-----------|------|
| CVE-2023-26360 | Adobe ColdFusion | 2023 | Directory traversal expondo arquivos de configuracao e credenciais -- explorado in-the-wild | Sensitive file exposure |
| CVE-2024-21893 | Ivanti Connect Secure | 2024 | SSRF no componente SAML expondo endpoints internos administrativos | Endpoint exposure |
| CVE-2023-34362 | MOVEit Transfer | 2023 | Acesso nao autenticado a endpoint de setup expondo configuracao e dados | Config endpoint exposure |
| CVE-2021-41773 | Apache HTTP Server 2.4.49 | 2021 | Path traversal via URL encoding -- acesso a arquivos fora do document root | Directory traversal to file read |
| CVE-2019-19781 | Citrix ADC/Gateway | 2019 | Path traversal expondo arquivos de configuracao sensiveis sem autenticacao | Config file exposure |

## Escalation Techniques
- **Reconstrucao de repositorio via .git dump:** usar `git-dumper` para baixar todo o diretorio `.git`, depois `trufflehog`/`gitleaks` para extrair credenciais do historico de commits -- mesmo segredos removidos do HEAD atual ficam no reflog.
- **Mapeamento total da API via spec exposta:** OpenAPI/Swagger spec revela todos os endpoints, parametros, schemas e modelos de dados -- usar para direcionar ataques em endpoints que nao sao linkados na UI (admin, internal, debug).
- **RCE via endpoints de debug:** `phpinfo.php` revela paths e configuracao; `/console` (Werkzeug, Rails) oferece shell interativo; `/actuator/env` expoe variaveis de ambiente com credenciais.
- **Dump de banco via backups expostos:** `backup.sql`, `dump.sql`, `database.sqlite` acessiveis diretamente fornecem todos os dados de producao -- credenciais, PII, tokens.
- **Encadeamento com outras vulns:** info disclosure + credential stuffing (admin panel + credenciais de .env); API spec + IDOR (mapear endpoints e testar acesso horizontal); .git + source review + exploits direcionados.
- **Exfiltracao via .DS_Store:** arquivo contem lista de nomes de arquivos do diretorio -- usar para descobrir arquivos sensiveis que nao estao na wordlist.

## Hunting Methodology
1. Iniciar com `robots.txt` e `sitemap.xml` para paths declarados pelo proprio servidor -- disallow entries frequentemente apontam para endpoints sensiveis.
2. Probar wordlist de paths criticos: `/admin`, `/.env`, `/.git/config`, `/.git/HEAD`, `/backup.sql`, `/phpinfo.php`, `/actuator`, `/swagger.json`, `/api-docs`.
3. Analisar HTML e JS bundles para extrair rotas internas: buscar em `href`, `action`, `src`, chamadas `fetch`/`axios`/`XMLHttpRequest` no source code.
4. Verificar headers de resposta para indicios de tecnologia: `X-Powered-By`, `Server`, `X-Generator` direcionam a wordlist (e.g., `X-Powered-By: Express` sugere probar `/api-docs`, `/.env`).
5. Testar variacoes de path: com/sem trailing slash, case variations (`/Admin`, `/ADMIN`), extensoes alternativas (`.bak`, `.old`, `.swp`, `.orig`, `~`), prefixos (`/old-`, `/bkp-`).
6. Verificar source code management exposto: `.git/config`, `.svn/entries`, `.hg/store`, `.bzr/README`. Se `.git/HEAD` retorna 200, o repositorio inteiro pode ser reconstruido.
7. Cruzar paths descobertos com crawlerHints do Knowledge Base de cada modulo habilitado -- o modulo Crawler faz isso automaticamente, expandindo a superficie de probing.

## False Positive Indicators
- Path retorna HTTP 200 mas com conteudo generico ou 404 customizado (soft 404) -- verificar se o body contem dados reais ou apenas pagina padrao de erro.
- `.git/config` retorna 200 mas `.git/objects/` retorna 403 -- acesso parcial bloqueado, reconstrucao do repositorio pode nao ser possivel.
- `swagger-ui.html` retorna pagina de UI mas sem dados da API (nao aponta para spec valido) -- placeholder ou template nao configurado.
- Endpoint retorna 301/302 redirect para pagina de login -- nao e acesso direto, autenticacao e exigida.
- Path retorna 200 com conteudo vazio ou minimo (0 bytes, `{}`, `[]`) -- nao e exposicao de dados sensiveis.
- Actuator endpoints retornam apenas health status sem dados sensiveis (`{"status":"UP"}`) -- avaliar quais endpoints estao habilitados antes de reportar como HIGH.

## Recommendation
1. Bloquear acesso a diretorio .git no web server (Nginx: `location ~ /\.git { deny all; }`, Apache: `RedirectMatch 404 /\.git`).
2. Remover arquivos de backup, dump SQL e .env do web root -- usar variaveis de ambiente do sistema.
3. Proteger endpoints OpenAPI/Swagger com autenticacao ou remover de producao.
4. Desabilitar phpinfo(), debug panels e console em producao.
5. Configurar WAF para bloquear requests a paths sensiveis conhecidos.
6. Remover admin panels de URLs previssiveis ou proteger com VPN/IP allowlist.
7. Usar .gitignore para prevenir commit de .env e arquivos de configuracao com credenciais.
8. Auditar historico Git com trufflehog/gitleaks antes de deploy e apos remoção de segredos.
9. Implementar Content-Security-Policy e X-Content-Type-Options para prevenir sniffing de resposta.
