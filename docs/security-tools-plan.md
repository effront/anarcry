# AnarCry -- Database Explorer & FTP Explorer

**Baseado em**: DBeaver (Java, /home/bullet/PROJETOS/dbeaver) e FileZilla (C++, /home/bullet/PROJETOS/filezilla)
**Objetivo**: Ferramentas leves de pos-exploitation integradas ao AnarCry, focadas em pentest/bounty/CTF

---

## 1. Database Explorer (inspirado no DBeaver)

### Problema

AnarCry detecta SQLi, NoSQLi, connection strings vazadas (JsAnalyzer, ErrorDisclosure, Secrets). Mas nao tem como EXPLORAR os bancos encontrados -- conectar, navegar schemas, executar queries, exportar dados como evidencia. DBeaver tem tudo, mas e um monstro OSGi de 160 plugins.

### Arquitetura DBeaver (referencia)

DBeaver usa uma camada model pura (sem UI) com interfaces `DBP*`, `DBC*`, `DBS*`:

| Camada | O que faz | O que a gente precisa |
|--------|-----------|----------------------|
| `model.connection` | Config de conexao (host/port/db/user/pass/URL) | SIM -- holder de config |
| `model.jdbc` | JDBC connect + metadata | SIM -- core da conexao |
| `model.exec.jdbc` | Query execution (Statement/ResultSet) | SIM -- executor de SQL |
| `model.struct` | Schema tree (Entity/Schema/DataContainer) | SIM -- browser de tabelas |
| `model.sql` / `model.sql.jdbc` | SQL dialect handling (identifier quoting, LIMIT vs TOP, information_schema) | SIM -- multi-DB SQL compat |
| `net.ssh` | SSH tunnel via SSHJ ou JSch (dois backends) | SIM -- usamos MINA SSHD (pure Java, integra BouncyCastle) |
| `data.transfer` | Export CSV/JSON/XML | SIM -- dump pra evidencia |
| `model.erd` | ER diagrams | NAO -- visual fluff |
| `model.ai` | AI/LLM integration | NAO -- irrelevante |
| `model.dashboard` | Analytics | NAO -- bloat |
| 100+ extensoes nicho | Altibase, Cubrid, Dameng, Exasol, etc | NAO -- so top 6 DBs |

**Nota sobre driver management**: DBeaver usa `DBPDriverDependencies` / `DBPDataSourceProviderRegistry` pra download on-demand de drivers JDBC. Nos vamos bundlar no shadow jar, o que adiciona ~50-80MB. Se o tamanho for problema, considerar download sob demanda via `DriverLoader`.

### Features: KEEP vs SKIP

**KEEP (essencial pra pentest)**

| Feature | Descricao | Prioridade |
|---------|-----------|-----------|
| Multi-DB connect | MySQL, PostgreSQL, MSSQL, SQLite, Oracle, MongoDB, Redis | P0 |
| Connection string parser | Auto-preencher de leaked `DATABASE_URL`, `JDBC_URL` | P0 |
| Schema browser | Tables, columns, row count, indexes | P0 |
| SQL executor | Run arbitrary queries, ver resultados | P0 |
| SQL dialect switcher | Identifier quoting (backtick vs double-quote), LIMIT vs TOP, information_schema diffs | P0 |
| Data export | ResultSet -> CSV/JSON pra report | P1 |
| SSH tunnel | Bounce por hosts comprometidos via MINA SSHD (port-forward) | P1 |
| Credential brute-force | Loop user:pass combos, catch SQLException, connection pool management | P1 |
| SSL/TLS options | Conectar com/sem SSL, inspecionar certs | P2 |
| NoSQL query | MongoDB find/aggregate, Redis GET/KEYS | P2 |

**SKIP (bloat)**

- ER diagrams
- Data transfer/migration wizards
- Database comparison
- Cloud integrations (AWS RDS console)
- Code completion / SQL formatting
- Project management
- Dashboard/analytics

### Dependencias (JARs)

| Dependencia | Proposito | Maven | Tamanho aprox. |
|-------------|-----------|-------|---------------|
| MySQL Connector/J | MySQL JDBC | `com.mysql:mysql-connector-j` | ~2.5MB |
| PostgreSQL JDBC | Postgres | `org.postgresql:postgresql` | ~1MB |
| MSSQL JDBC | SQL Server | `com.microsoft.sqlserver:mssql-jdbc` | ~1.5MB |
| SQLite JDBC | SQLite (embarca native libs) | `org.xerial:sqlite-jdbc` | ~12MB |
| Oracle JDBC | Oracle | `com.oracle.database.jdbc:ojdbc11` | ~5MB |
| MongoDB Driver | MongoDB | `org.mongodb:mongodb-driver-sync` | ~2MB |
| Jedis | Redis | `redis.clients:jedis` | ~0.5MB |
| Apache MINA SSHD | SSH tunnel (port-forward) | `org.apache.sshd:sshd-sftp:2.14.0` | ~1.5MB |

**Total estimado**: ~25-30MB adicionais ao shadow jar.

**Nota**: MINA SSHD e usado tanto pro DB SSH tunnel (port-forward) quanto pro FTP SFTP client. Uma unica lib SSH pra ambos.

### SQL Dialect Handling

MySQL, PostgreSQL e MSSQL tem syntax SQL significativamente diferente. O DB Explorer precisa de um dialect switcher minimo:

| Aspecto | MySQL | PostgreSQL | MSSQL |
|---------|-------|-----------|-------|
| Identifier quoting | `` ` `` (backtick) | `"` (double-quote) | `[]` (brackets) |
| Row limit | `LIMIT n` | `LIMIT n` | `TOP n` |
| Schema listing | `information_schema.SCHEMATA` | `pg_catalog.pg_namespace` | `sys.schemas` |
| Table listing | `information_schema.TABLES` | `pg_catalog.pg_class` | `sys.tables` |
| Current DB | `SELECT DATABASE()` | `SELECT current_database()` | `SELECT DB_NAME()` |

Implementar como enum `SqlDialect` com metodos `quoteIdentifier()`, `limitQuery()`, `listSchemas()`, `listTables()`, `currentDatabase()`. Auto-detectar pelo tipo de conexao.

### Integracao com AnarCry

1. **SQLi finding -> DB explorer**: SQLi module confirma injectable param -> DB explorer oferece conexao direta
2. **Connection string leak -> auto-connect**: JsAnalyzer/ErrorDisclosure/Secrets encontra `DATABASE_URL=postgresql://user:pass@host:5432/db` -> parser auto-preenche
3. **CredentialStore**: DB explorer le creds do store do AnarCry ou input manual
4. **SSH chain**: SSRF ou SSH exposto -> DB explorer tunela por dentro
5. **Report integration**: Query results exportados como JSON junto com findings pra evidencia
6. **UI flow**: Findings panel -> right-click "Explore Database" -> DB explorer pre-preenchido

### User Stories

**US-DB-01: Connection Manager**
- Como pentester, quero conectar a qualquer DB (MySQL/Postgres/MSSQL/SQLite/Oracle) usando JDBC
- AC: Suportar connection string raw, host+port+db+user+pass, e auto-parse de leaked URLs. Cada tipo de DB tem parser dedicado (jdbc:mysql://, jdbc:postgresql://, postgres://, mongodb://, redis://). ConnectionConfig e record (convencao do projeto). Timeout configurable (default 10s connect, 30s query). Conexao retorna AutoCloseable wrapper
- Arquivos: `postexploit/dbexplorer/ConnectionConfig.java` (record), `postexploit/dbexplorer/ConnectionManager.java`, `postexploit/dbexplorer/ConnectionStringParser.java`, `postexploit/dbexplorer/DbType.java` (enum)

**US-DB-02: SQL Dialect**
- Como pentester, quero que queries se adaptem ao tipo de banco automaticamente
- AC: Enum SqlDialect com metodos quoteIdentifier(), limitQuery(), listSchemas(), listTables(), currentDatabase(). Auto-detectar pelo driver/URL
- Arquivos: `postexploit/dbexplorer/SqlDialect.java`

**US-DB-03: Schema Browser**
- Como pentester, quero navegar schemas, tabelas, colunas e row counts
- AC: Tree view com database -> schema -> tables -> columns (name, type, nullable, pk). Usar SqlDialect pra queries de metadata
- Arquivos: `postexploit/dbexplorer/SchemaBrowser.java`

**US-DB-04: SQL Executor**
- Como pentester, quero executar queries arbitrarias e ver resultados em tabela
- AC: Text input -> execute -> ResultSet renderizado em tabela, suportar multi-statement
- Arquivos: `postexploit/dbexplorer/SqlExecutor.java`

**US-DB-05: Data Export**
- Como pentester, quero exportar resultados como CSV/JSON pra incluir no report
- AC: Exportar ResultSet ou tabela inteira como CSV ou JSON, integrar com ReportEngine
- Arquivos: `postexploit/dbexplorer/DataExporter.java`

**US-DB-06: Credential Tester**
- Como pentester, quero testar listas de user:pass contra um DB server
- AC: Aceitar wordlist, testar conexoes em paralelo (Semaphore pra limitar concurrency), reportar combos validas, timeout configurable per-attempt
- Arquivos: `postexploit/dbexplorer/CredentialTester.java`

**US-DB-07: SSH Tunnel**
- Como pentester, quero tunelar conexoes DB por um host comprometido via SSH
- AC: Configurar SSH hop (host+port+user+key/pass), port forward local -> DB remoto. Usar MINA SSHD (mesma lib do SFTP client). AutoCloseable pra cleanup do tunnel. Timeout configurable
- Arquivos: `postexploit/dbexplorer/SshTunnel.java`

**US-DB-08: MongoDB Explorer**
- Como pentester, quero conectar e explorar MongoDB
- AC: Listar databases/collections, run find/aggregate, ver documentos, exportar resultados
- Arquivos: `postexploit/dbexplorer/MongoExplorer.java`

**US-DB-09: Redis Explorer**
- Como pentester, quero conectar e explorar Redis
- AC: AUTH (password e ACL user:pass), KEYS, GET, TYPE, INFO, DBSIZE, CONFIG GET *. Detectar dados sensiveis em keys comuns (session:*, user:*, token:*, secret:*). Suportar Redis com/sem TLS. Timeout configurable
- Arquivos: `postexploit/dbexplorer/RedisExplorer.java`

---

## 2. FTP/SFTP Explorer (inspirado no FileZilla)

### Problema

InfraModule detecta FTP (21), SFTP (22) abertos. SecretsModule encontra credenciais FTP em configs. Mas nao tem como CONECTAR e explorar -- listar diretorios, baixar arquivos sensiveis, testar anonymous, analisar permissoes. FileZilla e C++ com wxWidgets -- pesado e sem foco em security.

### Arquitetura FileZilla (referencia)

FileZilla usa engine/interface split:

| Camada | O que faz | O que a gente precisa |
|--------|-----------|----------------------|
| `engine/ftpcontrolsocket` | FTP state machine (14 states: WELCOME(0) -> AUTH_TLS(1) -> AUTH_SSL(2) -> AUTH_WAIT(3) -> LOGON(4) -> SYST(5) -> FEAT(6) -> CLNT(7) -> OPTSUTF8(8) -> PBSZ(9) -> PROT(10) -> OPTSMLST(11) -> CUSTOMCOMMANDS(12) -> DONE(13)) | SIM -- referencia pro login flow |
| `engine/sftpcontrolsocket` | SFTP via fzsftp (PuTTY-derived subprocess, comunicacao por stdin/stdout pipes) | NAO -- usamos MINA SSHD (pure Java) |
| `engine/directorylistingparser` | Parsa 14 formatos de listing (Unix, Dos, Eplf, Vms, Ibm, WfFtp, IBM_MVS + 4 variantes, Mlsd, OS9, ZVM) | PARCIAL -- Commons Net ja cobre os comuns |
| `engine/tlssocket` | GnuTLS handshake (desabilita 3DES-CBC, MD5, SIGN-RSA-MD5 no priority string) | NAO -- usamos JSSE + BouncyCastle |
| `engine/servercapabilities` | FEAT/SYST tracking (16+ caps: utf8, clnt, mlsd, mfmt, pret, mdtm, size, mode_z, tvfs, list_hidden, rest_stream, tls_resume, timezone_offset) | SIM -- fingerprinting |
| `engine/transfersocket` | PASV/PORT data channel | SIM -- via Commons Net |
| `engine/proxy` | SOCKS4/5 e HTTP proxy com login sequences dedicadas | SIM -- pivoting por proxy |

### Features: KEEP vs SKIP

**KEEP (essencial pra pentest)**

| Feature | Descricao | Prioridade |
|---------|-----------|-----------|
| FTP/FTPS/SFTP connect | Conectar nos 3 protocolos | P0 |
| Anonymous detection | Auto-try anonymous/ftp/anonymous@ | P0 |
| Directory listing | Listar arquivos com permissoes, tamanhos, datas | P0 |
| Sensitive file scan | Buscar .env, .git/, .ssh/, *.sql, *.bak, wp-config, id_rsa, .htpasswd | P0 |
| File download | Download seletivo pra evidencia | P0 |
| Banner fingerprinting | SYST + FEAT -> mapear pra CVEs conhecidas (vsftpd 2.3.4, ProFTPD mod_copy) | P1 |
| Credential spraying | Testar wordlists user:pass contra FTP LOGIN | P1 |
| .git dump | Se .git/ legivel, baixar HEAD/config/refs pra reconstruir repo | P1 |
| TLS downgrade detection | Verificar se server cai pra plaintext quando AUTH TLS falha | P1 |
| PASV/EPSV modes | Passive mode pra bypass de firewall | P1 |
| PASV range analysis | Detectar ranges misconfigured (0.0.0.0, IPs internos em PASV response) | P1 |
| Proxy support | SOCKS4/5 e HTTP proxy pra pivoting por hosts comprometidos | P1 |
| Custom post-login commands | Executar comandos FTP arbitrarios apos login (SITE, STAT, HELP) | P1 |
| TLS session resume check | Verificar se FTPS suporta TLS session resume (finding se nao) | P1 |
| Permission analysis | Flags em dirs escritaveis (potencial upload) | P2 |
| SFTP cipher audit | Reportar kex/ciphers fracos (DH-group1, 3DES-CBC, arcfour, MD5-based MACs) | P2 |
| Data channel encryption | Verificar se PROT P (criptografia no data channel) esta ativo em FTPS | P2 |

**SKIP (bloat)**

- File upload (destructive -- opt-in separado)
- Drag-and-drop GUI
- Site manager/bookmarks
- Transfer queue
- Speed limits
- Synchronized browsing
- File comparison

### Dependencias (JARs)

| Dependencia | Proposito | Maven |
|-------------|-----------|-------|
| Apache Commons Net | FTP/FTPS client (LOGIN, LIST, MLSD, PASV, RETR, FEAT, SYST, AUTH TLS) | `commons-net:commons-net:3.11.1` |
| Apache MINA SSHD | SFTP/SSH2 pure Java (kex/cipher audit, hostkey fingerprint) | `org.apache.sshd:sshd-sftp:2.14.0` |

**Por que MINA SSHD e nao JSch?**
- JSch original esta abandonado. Fork mwiede/jsch existe mas tem menos kex algos
- MINA SSHD integra com BouncyCastle (ja no AnarCry)
- Expoe kex algorithms, ciphers, hostkey fingerprint diretamente -- essencial pra audit
- Nota: DBeaver suporta ambos (SSHJ e JSch) como backends separados. SSHJ seria alternativa viavel, mas MINA SSHD tem melhor introspeccao de algoritmos

### Features que FileZilla NAO tem (a gente adiciona)

| Feature | Descricao |
|---------|-----------|
| Credential spraying | Testar wordlists contra FTP LOGIN -- FileZilla so faz single login |
| Anonymous auto-detect | Tentar anonymous/ftp/anonymous@ automaticamente |
| Sensitive file scan | Busca recursiva por .env, .git/, .ssh/, *.sql, *.bak |
| .git dump | Download de .git/ pra reconstruir repo e extrair secrets do historico |
| Writable dir detection | Parse permission bits do LIST + opt-in STOR test |
| TLS downgrade test | Detectar fallback pra plaintext |
| Banner -> CVE mapping | vsftpd 2.3.4 backdoor, ProFTPD mod_copy, etc |
| Data channel sniff | Verificar PROT P em FTPS |
| SFTP cipher audit | kex/ciphers fracos (FileZilla bloqueia 3DES/MD5 via GnuTLS priority, nos reportamos como finding) |
| PASV range analysis | Detectar ranges misconfigured (0.0.0.0, IPs internos) |
| TLS session resume | Verificar suporte a session resume em FTPS (FileZilla tracka mas nao reporta) |
| Proxy pivoting | SOCKS4/5 e HTTP proxy pra pivoting -- FileZilla suporta mas nao com foco ofensivo |

### Integracao com AnarCry

1. **InfraModule -> FTP Explorer**: Detecta FTP (21) ou SFTP (22) aberto -> feed host:port direto
2. **SecretsModule -> auto-connect**: Encontra credenciais FTP em .env/config -> feed user:pass
3. **CrawlerModule -> backup hunt**: Descobre URLs de backup (.sql.gz, .tar.gz) -> FTP Explorer verifica se existem no FTP
4. **JsAnalyzer -> FTP URLs**: Encontra ftp:// URLs em bundles JS -> adiciona ao scan
5. **Report integration**: Arquivos sensiveis baixados como evidencia, listados no report
6. **UI flow**: Findings panel -> right-click "Explore FTP" -> FTP explorer pre-preenchido

### User Stories

**US-FTP-01: FTP/FTPS Client**
- Como pentester, quero conectar a servidores FTP/FTPS com suporte a AUTH TLS
- AC: Login flow completo (WELCOME -> AUTH TLS -> LOGON -> FEAT -> SYST -> CLNT -> OPTSUTF8 -> PBSZ -> PROT -> DONE), PASV/EPSV, LIST, RETR
- Arquivos: `postexploit/ftpexplorer/FtpClient.java`

**US-FTP-02: SFTP Client**
- Como pentester, quero conectar a servidores SFTP com audit de ciphers
- AC: Conexao SSH2, listar kex/ciphers usados, navegar dirs, download seletivo
- Arquivos: `postexploit/ftpexplorer/SftpClient.java`

**US-FTP-03: Anonymous Detector**
- Como pentester, quero detectar automaticamente acesso anonimo em FTP
- AC: Tentar anonymous/ftp/anonymous@, reportar o que e acessivel
- Arquivos: `postexploit/ftpexplorer/AnonDetector.java`

**US-FTP-04: Sensitive File Scanner**
- Como pentester, quero scan recursivo por arquivos sensiveis no FTP
- AC: Buscar .env, .git/, .ssh/, *.sql, *.bak, wp-config, id_rsa, .htpasswd, *.pem, *.key, authorized_keys, known_hosts, .docker/, docker-compose.yml em todos os dirs. Max depth configurable (default 5). Download automatico de matches pra diretorio de evidencias. Limite de tamanho por arquivo (default 10MB)
- Arquivos: `postexploit/ftpexplorer/SensitiveFileScanner.java`

**US-FTP-05: Credential Sprayer**
- Como pentester, quero testar wordlists de credenciais contra FTP
- AC: Aceitar user:pass list, testar em paralelo, reportar combos validas, respeitar lockout
- Arquivos: `postexploit/ftpexplorer/CredentialSprayer.java`

**US-FTP-06: Banner Fingerprinter**
- Como pentester, quero identificar o software FTP e mapear pra CVEs conhecidas
- AC: Capturar SYST + FEAT + welcome banner, mapear pra DB de versoes vulneraveis
- Arquivos: `postexploit/ftpexplorer/BannerFingerprinter.java`

**US-FTP-07: Git Dumper**
- Como pentester, quero extrair repositorios .git expostos em FTP
- AC: Detectar .git/, baixar HEAD, config, packed-refs, objects/info/packs, refs/heads/*. Reconstruir repo local via manual object fetch (sem JGit -- nao adicionar dep extra). Parsear pack index pra listar objects. Download pra diretorio temporario configuravel. Suportar tanto loose objects quanto pack files
- Arquivos: `postexploit/ftpexplorer/GitDumper.java`

**US-FTP-08: TLS Audit**
- Como pentester, quero verificar a seguranca TLS de FTPS e SFTP
- AC: FTPS: AUTH TLS negotiation, PROT P check, downgrade detection, TLS session resume check. SFTP: kex/cipher audit (flag DH-group1, 3DES-CBC, arcfour, MD5-based MACs)
- Arquivos: `postexploit/ftpexplorer/TlsAuditor.java`

**US-FTP-09: PASV Range Analyzer**
- Como pentester, quero detectar misconfiguration em PASV responses
- AC: Enviar PASV/EPSV, parsear response, flag se IP retornado e 0.0.0.0, IP interno, ou range inconsistente com o server IP
- Arquivos: `postexploit/ftpexplorer/PasvAnalyzer.java`

**US-FTP-10: Proxy Connector**
- Como pentester, quero pivoting por proxy pra acessar FTP em redes internas
- AC: Suportar SOCKS4, SOCKS5 e HTTP CONNECT proxy. Configurar host+port+user+pass do proxy
- Arquivos: `postexploit/ftpexplorer/ProxyConnector.java`

**US-FTP-11: Custom Commands**
- Como pentester, quero executar comandos FTP arbitrarios apos login
- AC: Enviar SITE, STAT, HELP e outros comandos raw. Capturar e exibir response completa
- Arquivos: `postexploit/ftpexplorer/CustomCommandExecutor.java`

---

## 3. Plano de Implementacao

### Sprint 1 -- Core DB Explorer (P0)

| US | Estimativa | Impacto |
|----|-----------|---------|
| US-DB-01 Connection Manager | XG | Multi-DB connect, connection string parser pra 7 formatos |
| US-DB-02 SQL Dialect | M | Identifier quoting, metadata queries per-DB |
| US-DB-03 Schema Browser | M | Navegar schemas/tables/columns |
| US-DB-04 SQL Executor | M | Executar queries arbitrarias |

### Sprint 2 -- Core FTP Explorer (P0)

| US | Estimativa | Impacto |
|----|-----------|---------|
| US-FTP-01 FTP/FTPS Client | G | FTP connect com AUTH TLS, login flow completo |
| US-FTP-02 SFTP Client | G | SFTP connect com cipher audit |
| US-FTP-03 Anonymous Detector | P | Auto-detect anonymous access |
| US-FTP-04 Sensitive File Scanner | M | Busca recursiva por arquivos sensiveis |

### Sprint 3 -- Exploitation Features (P1)

| US | Estimativa | Impacto |
|----|-----------|---------|
| US-DB-05 Data Export | P | CSV/JSON export pra reports |
| US-DB-06 Credential Tester | M | Brute-force DB credentials com connection pooling |
| US-DB-07 SSH Tunnel | M | Bounce por hosts comprometidos |
| US-FTP-05 Credential Sprayer | M | Brute-force FTP credentials |
| US-FTP-06 Banner Fingerprinter | M | Software ID + CVE mapping |
| US-FTP-07 Git Dumper | XG | Extract .git repos expostos, reconstruct + pack file support |
| US-FTP-09 PASV Range Analyzer | P | Detectar PASV misconfiguration |
| US-FTP-10 Proxy Connector | M | SOCKS4/5 e HTTP proxy pivoting |
| US-FTP-11 Custom Commands | P | Comandos FTP arbitrarios pos-login |

### Sprint 4 -- Advanced (P2)

| US | Estimativa | Impacto |
|----|-----------|---------|
| US-DB-08 MongoDB Explorer | G | MongoDB exploration |
| US-DB-09 Redis Explorer | M | Redis exploration |
| US-FTP-08 TLS Audit | M | FTPS/SFTP crypto audit + session resume check |

---

## Legenda

- **P** = Pequeno (< 2h)
- **M** = Medio (2-4h)
- **G** = Grande (4-8h)
- **XG** = Extra Grande (8-16h)

---

## Notas de Arquitetura

### Package naming: `postexploit/` em vez de `tools/`

Os explorers sao ferramentas de **pos-exploitation**, nao scanners. O package `postexploit/` torna isso semanticamente claro:

```
src/main/java/gg/effront/anarcry/
├── scanner/          # Deteccao de vulnerabilidades
├── postexploit/      # Exploracao e coleta de evidencias
│   ├── dbexplorer/   # Database exploration
│   └── ftpexplorer/  # FTP/SFTP exploration
├── model/
├── report/
└── tui/
```

### Impacto no shadow jar

Dependencias atuais do AnarCry: ~15MB shadow jar. Com os drivers DB + Commons Net + MINA SSHD, o jar vai pra ~45-50MB. Se isso for inaceitavel, alternativas:

1. **Jar separado**: `anarcry-postexploit.jar` com os drivers, carregado sob demanda
2. **Download on-demand**: `DriverLoader` que baixa JARs de drivers na primeira conexao
3. **Aceitar o tamanho**: 50MB ainda e razoavel pra uma ferramenta de pentest

---

**Resultado esperado**: Scan-to-exploit workflow completo -- AnarCry detecta, DB/FTP Explorer explora e coleta evidencias, ReportEngine documenta tudo.
