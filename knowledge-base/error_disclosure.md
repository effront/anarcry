---
id: error_disclosure
title: "Sensitive Error Disclosure"
module: "errordisclosure"
severity: "MEDIUM"
cwe_id: "CWE-209"
cwe_title: "Generation of Error Message Containing Sensitive Information"
cvss_vector: "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
vrt_id: "sensitive_data_exposure.internal_information_disclosure"
---

## Summary
Aplicacoes que retornam mensagens de erro detalhadas -- stack traces, caminhos internos, versoes de framework, informacoes de banco de dados, ou fragmentos de codigo-fonte -- expoe informacoes que facilitam ataques direcionados contra a infraestrutura e logica de negocio.

## Description
Quando uma aplicacao encontra uma condicao inesperada (input malformado, recurso inexistente, falha de banco de dados), o comportamento padrao de muitos frameworks e retornar uma pagina de erro detalhada contendo informacoes de diagnostico. Em ambientes de desenvolvimento isso e util, mas em producao expoe dados sensiveis para atacantes.

A divulgacao de erros sensiveis se manifesta em varias categorias:

**Stack Traces:** mensagens como `at com.example.UserService.getUser(UserService.java:42)` ou `Traceback (most recent call last)` revelam nomes de classes, metodos, numeros de linha, e dependencias internas. Isso permite ao atacante mapear a arquitetura da aplicacao, identificar versoes especificas de bibliotecas com CVEs conhecidos, e localizar pontos de entrada vulneraveis.

**Caminhos internos do sistema de arquivos:** strings como `/home/deploy/app/src/controllers/auth.js` ou `C:\inetpub\wwwroot\api\config.xml` revelam a estrutura de diretorios, sistema operacional, nomes de usuario de deploy, e localizacao de arquivos de configuracao. Essa informacao auxilia ataques de path traversal (LFI) e ajuda a localizar arquivos sensiveis como `.env`, `config.yml`, ou chaves privadas.

**Versoes de framework e servidor:** headers como `Server: Apache/2.4.49` ou mensagens contendo `Express/4.17.1` permitem ao atacante consultar bancos de CVE e encontrar exploits publicos para a versao exata em uso. A diferenca entre "o alvo usa Express" e "o alvo usa Express 4.17.1 com CVE-2022-24999" e significativa para a viabilidade do ataque.

**Informacoes de banco de dados:** erros como `PostgreSQL error: relation "users" does not exist` ou connection strings (`postgres://admin:senha@db.internal:5432/prod`) revelam o tipo de DBMS, schema de tabelas, credenciais, e hostnames internos. Isso facilita SQL injection direcionado e tentativas de acesso direto ao banco.

**Fragmentos de codigo-fonte:** algumas configuracoes de debug exibem o codigo-fonte ao redor da linha que gerou o erro. Isso expoe logica de negocio, mecanismos de autenticacao, endpoints internos de API, e potencialmente secrets hardcoded.

**Variaveis de ambiente:** paginas de debug (como a pagina de erro padrao do Django ou Next.js) podem exibir todas as variaveis de ambiente do processo, incluindo `DATABASE_URL`, `AWS_SECRET_ACCESS_KEY`, `JWT_SECRET`, e outras credenciais.

## Impact
- Mapeamento completo da stack tecnologica para ataques direcionados
- Identificacao de versoes vulneraveis com exploits publicos conhecidos
- Descoberta de caminhos internos que facilitam path traversal e LFI
- Vazamento de credenciais de banco de dados e chaves de API em connection strings
- Exposicao de logica de negocio e mecanismos de autenticacao via codigo-fonte
- Comprometimento total do sistema quando variaveis de ambiente com secrets sao expostas
- Encadeamento com outras vulnerabilidades -- error disclosure transforma findings de baixo impacto em ataques viabilizados

## Payloads and Bypasses
```bash
# JSON malformado para provocar erro de parsing
curl -s -D - https://alvo.com/api -X POST \
  -H 'Content-Type: application/json' \
  -d '{"broken": }'

# Content-Type inesperado
curl -s -D - https://alvo.com/ -X POST \
  -H 'Content-Type: application/xml' \
  -d '<x>'

# Parametro oversized
curl -s -D - "https://alvo.com/?x=$(python3 -c 'print("A"*2000)')"

# Path inexistente profundo
curl -s -D - https://alvo.com/api/v1/nonexistent/path/that/does/not/exist

# Input SQL-like
curl -s -D - "https://alvo.com/?id='"

# Type confusion
curl -s -D - https://alvo.com/api/user/undefined
curl -s -D - https://alvo.com/api/user/null
curl -s -D - https://alvo.com/api/user/NaN

# Null byte em path descoberto
curl -s -D - https://alvo.com/api/users/..%00
```

## Target Context (Crawler Hints)
- **Endpoints provaveis:** `/api/*`, `/api/v1/*`, `/graphql`, `/admin/*`, `/debug/*`, `/_next/*`, `/actuator/*`.
- **Parametros comuns:** `id`, `user_id`, `q`, `query`, `page`, `file`, `callback`.
- **Sinais:** respostas com status 400/404/500 contendo HTML com formatacao de debug; headers `X-Powered-By` com versao; `Server` header detalhado; resposta JSON com campo `stack` ou `trace`.

## Escalation Techniques
Error disclosure raramente e o objetivo final de um ataque, mas e um enabler critico para encadear com outras vulnerabilidades:

- **Error disclosure + LFI:** caminhos internos revelados em erros (`/home/deploy/app/`) permitem construir payloads de path traversal precisos ao inves de brute-force de profundidade de diretorio.
- **Error disclosure + SQLi:** mensagens de erro de banco revelam o DBMS exato e a estrutura de queries, transformando blind SQLi em error-based SQLi com exfiltracao direta.
- **Error disclosure + RCE:** versoes de framework identificadas (ex: `Spring Boot 2.6.0` com Spring4Shell) permitem ao atacante selecionar exploits publicos com alta confianca.
- **Error disclosure + account takeover:** variaveis de ambiente com `JWT_SECRET` permitem forjar tokens; connection strings permitem acesso direto ao banco para dump de credenciais.
- **Error disclosure + SSRF:** hostnames internos revelados em erros (`db.internal:5432`, `redis.internal:6379`) fornecem alvos para SSRF sem necessidade de enumeracao.

## False Positive Indicators
- **Paginas de documentacao de API:** endpoints como `/docs` ou `/swagger` podem exibir nomes de classes e metodos como parte da documentacao -- nao como leak de erro.
- **Respostas de ambiente de staging/dev:** ambientes nao produtivos sem dados reais e sem acesso publico tem impacto reduzido.
- **Stack traces em endpoints de health check:** alguns frameworks retornam traces em `/actuator/health` ou `/debug` intencionalmente quando o caller e interno -- verificar se o endpoint e acessivel externamente.
- **Versoes genericas sem patch level:** `nginx` sem numero de versao ou `Express` sem versao especifica tem impacto informacional apenas.
- **Caminhos relativos comuns:** strings como `/api/v1/users` em mensagens de erro sao paths de rotas, nao paths internos do filesystem.

## Notable CVEs

| CVE | Produto | Ano | Descricao | Tipo |
|-----|---------|-----|-----------|------|
| CVE-2024-21514 | Opencart | 2024 | Mensagens de erro SQL detalhadas expostas em endpoints de busca -- permite exfiltracao de dados via error-based SQLi | SQL Error Disclosure to SQLi |
| CVE-2023-46747 | F5 BIG-IP | 2023 | Pagina de erro expoe informacoes internas de configuracao e versao -- permite RCE via request smuggling encadeado | Error Disclosure to RCE |
| CVE-2023-34060 | VMware Cloud Director | 2023 | Stack traces detalhados em respostas de erro revelam versao exata e caminhos internos -- facilita ataques direcionados | Stack Trace Disclosure |
| CVE-2022-22963 | Spring Cloud Function | 2022 | Mensagens de erro expoe detalhes de execucao SpEL -- atacante identifica versao vulneravel a RCE via Spring4Shell | Error Disclosure (Framework Version) |
| CVE-2021-22986 | F5 BIG-IP iControl REST | 2021 | Respostas de erro expoe tokens de sessao e configuracao interna -- permite auth bypass e RCE pre-autenticacao | Error Disclosure to Auth Bypass |
| CVE-2020-5902 | F5 BIG-IP TMUI | 2020 | Interface de gerenciamento retorna stack traces com caminhos internos e credenciais parciais -- encadeado com path traversal para RCE | Error Disclosure to RCE |
| CVE-2019-11043 | PHP-FPM + Nginx | 2019 | Mensagens de erro do PHP-FPM expoe detalhes de configuracao e caminhos -- permite RCE via manipulacao de path_info | Error Disclosure to RCE |

Fonte: cvelistV5 (MITRE CVE List v5 dataset)

## Recommendation
1. **Configurar paginas de erro customizadas** para todos os codigos HTTP (400, 404, 500, etc.) que retornem apenas uma mensagem generica sem detalhes tecnicos.
2. **Desabilitar modo debug em producao** -- verificar `DEBUG=false` (Django), `NODE_ENV=production` (Express/Next.js), `spring.profiles.active=prod` (Spring Boot), `APP_DEBUG=false` (Laravel).
3. **Implementar global exception handler** que captura todas as excecoes nao tratadas, loga detalhes completos no servidor (Sentry, ELK, CloudWatch), e retorna apenas `{"error": "Internal Server Error"}` ao cliente.
4. **Remover headers de versao** -- configurar `server_tokens off` (nginx), `ServerTokens Prod` (Apache), remover `X-Powered-By` no framework.
5. **Sanitizar mensagens de erro de banco** -- nunca propagar a mensagem original do DBMS ao cliente; mapear para erros genericos da aplicacao.
6. **Auditar variaveis de ambiente** -- garantir que secrets nao sao logadas em startup, nao aparecem em endpoints de debug, e nao sao renderizadas em paginas de erro.
7. **Separar configuracao por ambiente** -- usar profiles (Spring), env files (Node.js), ou feature flags para garantir que configuracoes de debug nunca sao ativadas em producao.
8. Exemplo Express.js:
```javascript
// Middleware de erro global -- nunca expor stack em producao
app.use((err, req, res, next) => {
  console.error(err.stack); // log server-side
  res.status(err.status || 500).json({
    error: process.env.NODE_ENV === 'production'
      ? 'Internal Server Error'
      : err.message
  });
});
```
9. Exemplo Spring Boot:
```yaml
# application-prod.yml
server:
  error:
    include-stacktrace: never
    include-message: never
    include-binding-errors: never
```
