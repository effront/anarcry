# AnarchCrypto — Harness de Testes

**Data:** 2026-10-19

---

## Estrutura de testes

```
src/test/java/gg/effront/anarchrypto/
├── fixtures/                    # certificados, tokens e respostas HTTP de fixture
│   ├── certs/
│   │   ├── expired.pem
│   │   ├── self-signed.pem
│   │   ├── weak-rsa1024.pem
│   │   └── valid.pem
│   ├── jwt/
│   │   ├── alg-none.txt
│   │   ├── hs256-weak-secret.txt    # segredo: "secret"
│   │   └── rs256-valid.txt
│   └── http/
│       ├── headers-missing-hsts.txt
│       ├── headers-full-secure.txt
│       └── headers-weak-cookies.txt
├── cli/
│   └── AnarchCryptoCommandTest.java
├── modules/
│   ├── tls/
│   │   ├── TlsVersionProbeTest.java
│   │   ├── CipherSuiteProbeTest.java
│   │   └── CertificateProbeTest.java
│   ├── headers/
│   │   └── HeadersModuleTest.java
│   ├── jwt/
│   │   ├── JwtParserTest.java
│   │   ├── AlgNoneProbeTest.java
│   │   ├── AlgConfusionProbeTest.java
│   │   └── JwtBruteProbeTest.java
│   └── pqc/
│       └── PqcTlsProbeTest.java
├── report/
│   ├── MarkdownReportTest.java
│   └── JsonReportTest.java
└── integration/
    ├── MockTlsServer.java           # servidor TLS local para testes de integração
    ├── MockHttpServer.java          # servidor HTTP local para headers/JWT
    └── FullScanIntegrationTest.java
```

---

## Estratégia por camada

### Unitários (sem rede)
- Todos os parsers (JWT, headers, certificado) recebem strings/bytes diretos
- Probes recebem interfaces mockadas (`SslConnectionFactory`, `HttpClientAdapter`)
- Rodam em < 2s no total
- Cobertura mínima: 80% das classes de módulo

### Integração (rede local)
- `MockTlsServer`: servidor TLS em porta aleatória com configuração controlável
  - Modo `weak`: aceita TLS 1.0, RC4, certificado expirado
  - Modo `strong`: TLS 1.3 only, cipher suites modernas
  - Modo `pqc`: suporte a X25519MLKEM768
- `MockHttpServer`: servidor HTTP com headers configuráveis por cenário
- Rodam isolados com `@BeforeEach` / `@AfterEach`

### Fixtures de certificado
Geradas uma vez com `keytool` / `openssl` e commitadas em `src/test/resources/fixtures/certs/`:

```bash
# Certificado expirado (validade em 1970)
openssl req -x509 -newkey rsa:2048 -keyout expired-key.pem -out expired.pem \
  -days 1 -nodes -subj "/CN=expired.test" \
  -set_serial 1 -not_before 19700101000000Z -not_after 19700102000000Z

# RSA 1024 bits (chave fraca)
openssl req -x509 -newkey rsa:1024 -keyout weak-key.pem -out weak-rsa1024.pem \
  -days 365 -nodes -subj "/CN=weak.test"

# Autoassinado válido
openssl req -x509 -newkey rsa:2048 -keyout self-key.pem -out self-signed.pem \
  -days 365 -nodes -subj "/CN=self.test"
```

### Fixtures de JWT
Tokens reais gerados localmente para cada cenário de ataque:

```bash
# alg:none — header: {"alg":"none"}, payload: {"sub":"1","admin":true}
echo -n '{"alg":"none","typ":"JWT"}' | base64url
echo -n '{"sub":"1","admin":true}' | base64url
# token final: <header>.<payload>.

# HS256 com segredo fraco "secret"
python3 -c "import jwt; print(jwt.encode({'sub':'1'}, 'secret', algorithm='HS256'))"
```

---

## Cenários de teste por módulo

### TLS Audit

| Teste | Entrada | Esperado |
|---|---|---|
| TLS 1.0 aceito | MockTlsServer modo weak | Finding MEDIUM `TLS 1.0 Enabled` |
| TLS 1.1 aceito | MockTlsServer modo weak | Finding MEDIUM `TLS 1.1 Enabled` |
| TLS 1.3 only | MockTlsServer modo strong | Nenhum finding de versão |
| RC4 aceito | MockTlsServer com RC4 | Finding HIGH `Weak Cipher Suite` |
| Certificado expirado | fixture `expired.pem` | Finding LOW `Expired Certificate` |
| RSA 1024 | fixture `weak-rsa1024.pem` | Finding MEDIUM `Weak Certificate Key` |
| Autoassinado | fixture `self-signed.pem` | Finding MEDIUM `Self-Signed Certificate` |

### Crypto Headers

| Teste | Entrada | Esperado |
|---|---|---|
| HSTS ausente | response sem header | Finding LOW `HSTS Missing` |
| HSTS max-age=0 | `Strict-Transport-Security: max-age=0` | Finding LOW |
| Cookie sem Secure | `Set-Cookie: session=abc` | Finding LOW `Cookie Missing Secure Flag` |
| Cookie sem HttpOnly | `Set-Cookie: session=abc; Secure` | Finding LOW `Cookie Missing HttpOnly Flag` |
| CSP ausente | response sem CSP | Finding LOW `CSP Missing` |
| Headers completos | fixture `headers-full-secure.txt` | Zero findings |

### JWT Analyzer

| Teste | Entrada | Esperado |
|---|---|---|
| alg:none local | token de fixture | Finding CRITICAL detectado localmente |
| HS256 segredo "secret" | fixture `hs256-weak-secret.txt` | Finding HIGH com segredo no evidence |
| Token sem exp | payload sem campo `exp` | Finding MEDIUM |
| Token expirado aceito | mock server aceita token expirado | Finding MEDIUM |
| kid path traversal | `kid: ../../etc/passwd` | Finding HIGH |

### PQC Probe

| Teste | Entrada | Esperado |
|---|---|---|
| Servidor sem PQC | MockTlsServer modo strong (sem ML-KEM) | Finding LOW `No PQC Support` |
| Servidor com PQC | MockTlsServer modo pqc | Finding INFO `PQC Supported` |
| Downgrade permitido | MockTlsServer modo pqc + downgrade | Finding LOW `PQC Downgrade Allowed` |

---

## Testes de regressão de output

Para garantir que o formato markdown e JSON não quebram silenciosamente:

```java
@Test
void markdownReport_containsAllSections() {
    var findings = List.of(
        new Finding(Module.TLS, "TLS 1.0 Enabled", Severity.MEDIUM, ...),
        new Finding(Module.JWT, "Algorithm None", Severity.CRITICAL, ...)
    );
    var report = new MarkdownReporter().render(findings, "https://alvo.com", 4200);

    assertThat(report).contains("## Resumo");
    assertThat(report).contains("| Critical | 1 |");
    assertThat(report).contains("### [CRITICAL]");
    assertThat(report).contains("### [MEDIUM]");
}
```

Golden snapshots para o JSON report ficam em `src/test/resources/fixtures/golden/`.

---

## Como rodar

```bash
# Unitários
gradle test

# Integração (sobe mock servers)
gradle integrationTest

# Tudo
gradle check

# Com report de cobertura
gradle test jacocoTestReport
# Abre build/reports/jacoco/test/html/index.html
```

---

## CI (futuro)

```yaml
# .github/workflows/ci.yml
- uses: actions/setup-java@v4
  with:
    java-version: '27'
    distribution: 'zulu'
- run: gradle check
```
