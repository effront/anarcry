# AnarCry -- Claude Context

## Project Overview

**Type**: Java 27 security scanner / pentest toolkit
**Purpose**: Automated vulnerability scanner with TUI/GUI, targeting web applications
**Architecture**: Modular scanner engine with Lanterna TUI + Swing GUI, report generation, knowledge base, API client, and post-exploitation tools

## Tech Stack

```
Java 27 (Zulu)
Gradle (Shadow, Checkstyle, PMD, SpotBugs + FindSecBugs, Spotless)
Lanterna 3.1.3 (TUI)
FlatLaf + RSyntaxTextArea (Swing GUI)
GraalVM Polyglot 24.1.1 (JS script engine for API client)
BouncyCastle 1.80 (TLS, JWT crypto, PQC)
Gson 2.11.0 (JSON serialization)
Apache Commons Net 3.11.1 (FTP/FTPS)
Apache MINA SSHD 2.14.0 (SFTP, SSH tunneling)
JDBC drivers (MySQL, PostgreSQL, MSSQL, SQLite, Oracle)
MongoDB Driver Sync 5.2.1
Jedis 5.2.0 (Redis)
JUnit 5.11.3 (testing)
```

## Project Structure

```
src/main/java/gg/effront/anarcry/
├── Main.java                        # Entry point (--fuzz for CLI batch fuzzing)
├── EnvLoader.java                   # .env.local loader
├── fuzzer/
│   ├── AttackType.java              # Enum: SNIPER, BATTERING_RAM, PITCHFORK, CLUSTER_BOMB
│   ├── FuzzEngine.java              # Orchestrator: virtual threads + Semaphore, pause/stop
│   ├── FuzzPosition.java            # {{N}} marker parsing and injection
│   ├── FuzzResult.java              # Request result record
│   ├── GrepMatcher.java             # Response pattern matching and extraction
│   ├── PayloadSource.java           # Interface: lazy payload iteration
│   ├── FilePayloadSource.java       # Lazy file reading (BufferedReader, never loads all)
│   ├── InlinePayloadSource.java     # Payloads from text/list
│   ├── RangePayloadSource.java      # Numeric range with step and padding
│   ├── PayloadProcessor.java        # @FunctionalInterface: transform before injection
│   └── PayloadProcessors.java       # Factory: 14 processors (encode, hash, regex, etc.)
├── model/
│   ├── Finding.java                 # Scan result record (module, endpoint, severity, CWE, CVSS)
│   ├── Severity.java                # CRITICAL / HIGH / MEDIUM / LOW / INFO
│   ├── CweRegistry.java             # CWE ID + CVSS vector per module
│   ├── CvssCalculator.java          # CVSS v3.1 score calculation
│   ├── KnowledgeBase.java           # Knowledge base loader (knowledge-base/*.md)
│   ├── KnowledgeEntry.java          # Single KB entry
│   ├── AuthType.java                # Auth selector enum (NONE, JWT, COOKIE, BEARER)
│   ├── RequestRecord.java           # HTTP request/response log
│   └── Suppression.java             # Finding suppression config
├── scanner/
│   ├── Scanner.java                 # Interface: id() + scan(ScanContext, log)
│   ├── ScanRunner.java              # Orchestrator: parallel module execution, dedup, suppression
│   ├── ScanContext.java             # Target URL, JWT tokens, enabled modules, config
│   ├── ScanConfig.java              # Scope rules, suppression list
│   ├── ScanEvent.java               # Progress events (SCAN_START, MODULE_START, MODULE_DONE, SCAN_DONE)
│   ├── SuppressionLoader.java       # Loads .anarcry-ignore.json
│   ├── util/
│   │   ├── Http.java                # HTTP send wrapper with request logging
│   │   ├── HttpClientFactory.java   # Shared HttpClient (HTTP/2, custom TLS)
│   │   └── TlsUtil.java            # BouncyCastle TLS context setup
│   ├── crypto/                      # Crypto / infra modules
│   │   ├── headers/HeadersModule    # Security headers check
│   │   ├── hsts/HSTSModule          # HSTS enforcement check
│   │   ├── jwt/JwtModule            # JWT attack suite (alg:none, RS256→HS256, JKU, sig disclosure)
│   │   ├── pqc/PqcModule            # Post-Quantum Cryptography readiness
│   │   └── tls/TlsModule            # TLS version, cipher suites, certificate checks
│   └── web/                         # Web vulnerability modules
│       ├── actuator/SpringActuatorModule
│       ├── cachepoisoning/CachePoisoningModule
│       ├── cmdinject/CommandInjectionModule
│       ├── cors/CorsModule
│       ├── crawler/CrawlerModule
│       ├── crlf/CrlfModule
│       ├── graphql/GraphQLModule
│       ├── hostheader/HostHeaderModule
│       ├── idor/IdorModule
│       ├── infra/InfraModule
│       ├── lfi/LfiModule
│       ├── massassign/MassAssignmentModule
│       ├── oauth/OAuthModule
│       ├── openredirect/OpenRedirectModule
│       ├── smuggling/RequestSmugglingModule
│       ├── sqli/SqlInjectionModule
│       ├── ssrf/SsrfModule
│       ├── ssti/SstiModule
│       ├── xss/XssModule
│       └── xxe/XxeModule
├── postexploit/
│   ├── dbexplorer/                  # Database post-exploitation tools
│   │   ├── ConnectionConfig.java    # Connection record (host, port, creds, timeouts, SSL)
│   │   ├── ConnectionManager.java   # JDBC connection factory with per-DB timeout config
│   │   ├── ConnectionStringParser.java  # Parse JDBC/shorthand URLs to ConnectionConfig
│   │   ├── CredentialTester.java    # DB credential brute-force (virtual threads + semaphore)
│   │   ├── DataExporter.java        # Export query results to CSV/JSON
│   │   ├── DbType.java             # Enum: MYSQL, POSTGRESQL, MSSQL, SQLITE, ORACLE
│   │   ├── MongoExplorer.java       # MongoDB client (list DBs, collections, find, aggregate)
│   │   ├── RedisExplorer.java       # Redis client (SCAN, type-aware GET, sensitive key scan)
│   │   ├── SchemaBrowser.java       # DB metadata navigator (schemas, tables, columns)
│   │   ├── SqlDialect.java          # Enum: quoting, LIMIT, metadata queries per DB
│   │   ├── SqlExecutor.java         # Execute SQL with timeout, multi-statement, BLOB handling
│   │   └── SshTunnel.java          # SSH local port forwarding via MINA SSHD
│   └── ftpexplorer/                 # FTP/SFTP post-exploitation tools
│       ├── AnonDetector.java        # Anonymous FTP access detection
│       ├── BannerFingerprinter.java # FTP software + CVE identification (7 signatures)
│       ├── CredentialSprayer.java   # FTP credential brute-force with lockout detection
│       ├── CustomCommandExecutor.java  # Raw FTP command execution
│       ├── FtpClient.java          # FTP/FTPS wrapper (Commons Net)
│       ├── GitDumper.java           # .git repo extraction (manual object parsing, no JGit)
│       ├── PasvAnalyzer.java        # PASV/EPSV misconfiguration detection
│       ├── ProxyConnector.java      # Pivoting via SOCKS4/5, HTTP CONNECT
│       ├── SensitiveFileScanner.java  # Recursive sensitive file scan (7 categories)
│       ├── SftpClient.java         # SFTP wrapper (MINA SSHD)
│       └── TlsAuditor.java         # FTPS TLS + SFTP cipher/KEX audit
├── report/
│   └── ReportEngine.java            # Markdown + JSON report generation
└── tui/
    ├── AnarCryTui.java              # Main TUI window (Lanterna)
    ├── PasteableTextBox.java        # Custom text box with paste support
    ├── chrome/                      # TUI chrome components
    │   ├── ActionPalette.java       # Command palette (Ctrl+P)
    │   ├── EventLogDrawer.java      # Scan event log drawer
    │   ├── ModeBar.java             # Tab bar (Scan, Target, Repeater, Fuzzer, etc.)
    │   └── StatusBar.java           # Bottom status bar
    ├── modes/                       # TUI operational modes
    │   ├── Mode.java                # Enum: SCAN, TARGET, REPEATER, FUZZER, etc.
    │   ├── TargetMode.java          # Main scan mode
    │   ├── RepeaterMode.java        # HTTP repeater mode
    │   └── FuzzerMode.java          # HTTP fuzzer mode (uses FuzzEngine)
    └── panels/                      # TUI panels
        ├── FindingsPanel.java       # Findings list with detail view
        ├── LogPanel.java            # Scan log output
        ├── ModulesPanel.java        # Module selection checkboxes
        └── SiteMapPanel.java        # Crawled sitemap tree

knowledge-base/                      # Vulnerability knowledge base (Markdown files)
config/                              # Checkstyle, PMD, SpotBugs config
.github/workflows/                   # CI: lint.yml, security-scan.yml
```

## Scanner Module Contract

Every scanner module implements `Scanner`:

```java
public interface Scanner {
    String id();                                    // e.g. "SQLi", "XSS", "TLS"
    List<Finding> scan(ScanContext ctx, Consumer<String> log) throws Exception;
}
```

Findings are created via `Finding.of(module, endpoint, title, severity, evidence, impact, reproduction, recommendation)` -- CWE and CVSS are auto-resolved from `CweRegistry`.

### Module Registration

Modules are registered in `ScanRunner.run()` via `ctx.has("ModuleName")` checks. When adding a new module:
1. Create the module class implementing `Scanner`
2. Add the `ctx.has("YourModule")` check + instantiation in `ScanRunner.run()`
3. Register CWE/CVSS mapping in `CweRegistry`
4. Add checkbox in `ModulesPanel`
5. Add entry in `knowledge-base/`

## Build & Run

```bash
./gradlew shadowJar                  # Build fat JAR
java -jar build/libs/anarcry-2.4.0.jar # Run (GUI)
java -jar build/libs/anarcry-2.4.0.jar --tui  # Run (TUI)
java -jar build/libs/anarcry-2.4.0.jar --fuzz config.json  # Fuzzer CLI batch mode

./gradlew test                       # Unit tests (excludes @Tag("integration"))
./gradlew spotlessApply              # Fix formatting (Google Java Format)
./gradlew spotlessCheck              # Check formatting (CI)
./gradlew checkstyleMain             # Checkstyle
./gradlew spotbugsMain               # SpotBugs + FindSecBugs
```

## CI/CD

**Workflows** (`.github/workflows/`):
- `lint.yml` -- Spotless (Google Java Format) + Checkstyle on push/PR
- `security-scan.yml` -- SpotBugs + FindSecBugs on push/PR + weekly Monday 9AM UTC

## Code Quality Standards

### Formatting
- Google Java Format enforced via Spotless
- Run `./gradlew spotlessApply` before committing

### Static Analysis
- Checkstyle: NeedBraces, LineLength violations block CI
- PMD: standard Java rules
- SpotBugs + FindSecBugs: security-focused static analysis

### Code Style
- Records over classes for immutable data (Finding, ScanContext, ScanEvent, etc.)
- `java.net.http.HttpClient` (HTTP/2 by default) -- no third-party HTTP libs
- BouncyCastle for all crypto operations (TLS, JWT, PQC)
- No external logging framework -- `Consumer<String> log` callback pattern

## Key Patterns

### HTTP Requests
All HTTP requests go through `Http.send()` which logs to `ScanContext.requestLog`:
```java
Http.send(ctx, httpClient, request, bodyHandler, moduleId);
```

### Finding Deduplication
`ScanRunner` deduplicates findings by `module|endpoint|title` key.

### Suppression
`.anarcry-ignore.json` defines findings to suppress:
```json
[{"module": "Headers", "title": "Missing X-Frame-Options", "host": "*.example.com"}]
```

### Authentication Types
`AuthType` enum (`model/AuthType.java`) controls how credentials are wired into scans:

| AuthType | ScanContext.jwtToken | ScanConfig.sessionCookie | Header on wire |
|---|---|---|---|
| `NONE` | `""` | `""` | none |
| `JWT` | JWT string | `""` | `Authorization: Bearer <jwt>` (per-module) |
| `COOKIE` | `""` | cookie value | `Cookie: <value>` (via `Http.send()`) |
| `BEARER` | opaque token | `""` | `Authorization: Bearer <token>` (per-module) |

Helper methods: `usesBearer()`, `usesCookie()`, `requiresJwtParsing()`, `hasAuth()`.

**Known gaps**: `HeadersModule` and `HSTSModule` use `HttpURLConnection` directly (bypass `Http.send()` -- cookies not injected). `IdorModule` skips on COOKIE auth (no `sessionCookie2` for cross-user testing).

### Scope Control
`ScanConfig.isInScope(host)` enforces target scope -- scan is cancelled if host is out of scope.

### HTTP Fuzzer
The `fuzzer/` package is Swing/TUI-independent so all three UIs (GUI, TUI, CLI) share one engine:

- **Template**: raw HTTP request with `{{N}}` injection markers parsed by `FuzzPosition`
- **Attack types**: `AttackType` enum -- SNIPER (one position at a time), BATTERING_RAM (same payload everywhere), PITCHFORK (parallel lists), CLUSTER_BOMB (cartesian product)
- **Payload sources**: `PayloadSource` interface -- `FilePayloadSource` (lazy BufferedReader), `InlinePayloadSource`, `RangePayloadSource`
- **Processing**: `PayloadProcessor` pipeline applied before injection (14 built-in processors in `PayloadProcessors`)
- **Engine**: `FuzzEngine` dispatches via virtual threads + `Semaphore`, supports pause/stop via `AtomicBoolean`, throttling with delay + jitter
- **Grep**: `GrepMatcher` counts pattern matches and extracts capture groups from responses
- **GUI**: `FuzzerView` tab with RSyntaxTextArea template editor, payload config tabs, results JTable with sort/filter, response viewer
- **TUI**: `FuzzerMode` in Lanterna with template editor, inline payloads, attack type selector, results list
- **CLI**: `--fuzz config.json` in `Main.java` for headless batch mode with CSV/JSON output

## Ethical Use

AnarCry is designed for **authorized security testing** only:
- Always obtain written authorization before scanning
- Respect scope boundaries configured in ScanConfig
- Never scan targets without explicit permission
- Findings are for defensive purposes -- helping teams fix vulnerabilities

## Claude Rules

1. **NO EMOJIS** in code, comments, logs, commit messages, or output
2. **NO AUTO-COMMITS** -- always ask before `git add`, `git commit`, `git push`
3. **NO AUTO-DOCUMENTATION** -- do not create .md files unless explicitly requested
4. **AUTHORIZED CONTEXT ONLY** -- scanner modules exist for pentest/CTF/defensive use
5. **Spotless before commit** -- always run `./gradlew spotlessApply` before staging
6. **Never use `git add .`** -- add files by name explicitly
7. **NO EMDASH/ENDASH** -- use `--` instead of emdash and `-` instead of endash everywhere (code, comments, reports, KB)
8. **NO CO-AUTHORED-BY** -- never add Co-Authored-By or attribution lines to commits or PRs

---

**Last Updated**: 2026-11-25
