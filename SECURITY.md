# Security Policy

## Reporting a Vulnerability

**AnarCry** is a security scanner, so we hold ourselves to a high standard. We appreciate your efforts to responsibly disclose your findings.

### Reporting Process

**DO NOT** create public GitHub issues for security vulnerabilities.

Instead, please report security vulnerabilities by emailing:

```
security@effront.gg
```

### What to Include

Please include the following information in your report:

- **Type of vulnerability** (e.g., command injection, path traversal, credential exposure, RCE via payload)
- **Full path** of the affected source file(s)
- **Location** of the affected code (file path, line number, commit hash)
- **Step-by-step instructions** to reproduce the issue
- **Proof-of-concept or exploit code** (if possible)
- **Impact** of the vulnerability
- **Suggested fix** (if you have one)

### Response Timeline

- **Initial Response**: Within 48 hours
- **Status Update**: Within 7 days
- **Resolution Target**: Depends on severity (see below)

### Severity Levels

| Severity | Response Time | Examples |
|----------|---------------|----------|
| **Critical** | 24-48 hours | RCE via crafted scan target, credential leakage in reports |
| **High** | 3-7 days | Path traversal in scanner modules, SSRF in scanner itself |
| **Medium** | 7-14 days | Information disclosure in generated reports, unsafe deserialization |
| **Low** | 14-30 days | Verbose error messages, minor information leakage |

## Security Architecture

AnarCry implements security measures to protect both the operator and the targets being scanned:

### Scan Scope Enforcement
- Target scope validation via `ScanConfig.isInScope(host)` before every request
- Scan is cancelled if any module attempts out-of-scope requests
- `.anarcry-ignore.json` suppression to manage known findings

### Cryptographic Operations
- BouncyCastle 1.80 for all TLS, JWT, and PQC operations
- Custom TLS context via `TlsUtil` (no default JVM trust store weaknesses)
- HTTP/2 by default via `java.net.http.HttpClient`

### Code Quality & Static Analysis
- SpotBugs + FindSecBugs on every push (security-focused SAST)
- Checkstyle and PMD for code quality enforcement
- Spotless (Google Java Format) for consistent formatting
- CI workflows: `lint.yml` and `security-scan.yml`

### Input Handling
- No external logging framework (controlled `Consumer<String>` callback pattern)
- HTTP requests routed through `Http.send()` with full request/response logging
- Finding deduplication by `module|endpoint|title` key

## Ethical Use

AnarCry is designed exclusively for **authorized security testing**:

- Always obtain written authorization before scanning any target
- Respect scope boundaries configured in `ScanConfig`
- Never scan targets without explicit permission
- Findings are for defensive purposes only
- Comply with all applicable local, national, and international laws

Unauthorized use of AnarCry against systems you do not own or have permission to test is illegal and unethical. The authors assume no liability for misuse.

## Security Testing

### Automated Scans (CI/CD)

Every push triggers:

```bash
# Static Analysis (SAST)
- SpotBugs + FindSecBugs    # Security-focused static analysis
- Checkstyle                # Code quality rules (NeedBraces, LineLength)
- PMD                       # Standard Java rules

# Formatting
- Spotless                  # Google Java Format enforcement
```

### For Contributors

**Before committing code:**

```bash
./gradlew spotlessApply      # Fix formatting
./gradlew checkstyleMain     # Checkstyle
./gradlew spotbugsMain       # SpotBugs + FindSecBugs
./gradlew test               # Unit tests
```

### Security Considerations for Scanner Modules

When contributing scanner modules:

1. **Never store credentials** in scan results or logs
2. **Respect scope** -- all requests must go through `Http.send()` which enforces scope
3. **No destructive payloads** -- scanners must be read-only and non-destructive
4. **Rate limiting** -- avoid flooding targets; respect server responses
5. **Error handling** -- never expose internal state in scan output
6. **Payload safety** -- knowledge-base payloads must be detection-only, not exploitation

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.x     | Yes       |

## Safe Harbor

AnarCry provides a safe harbor for security researchers who:

- Make a good faith effort to avoid privacy violations, data destruction, and service disruption
- Only interact with accounts you own or with explicit permission
- Do not exploit a vulnerability beyond the minimum necessary to demonstrate it
- Report vulnerabilities promptly
- Give us reasonable time to fix the issue before any public disclosure

We will not pursue legal action against researchers who follow this policy.

## Out of Scope

The following are explicitly **out of scope** for vulnerability reports:

- Social engineering attacks against maintainers
- Denial of Service (DoS/DDoS) against project infrastructure
- Vulnerabilities in third-party dependencies (report to their maintainers directly)
- Attacks on scan targets (that is the tool's intended purpose under authorization)
- Issues requiring physical access to the operator's machine
- Vulnerabilities in outdated or unsupported versions

## Contact

- **Security Team**: security@effront.gg
- **GitHub Issues**: For non-security bugs only

## Additional Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CWE Top 25](https://cwe.mitre.org/top25/)
- [CVSS v3.1 Calculator](https://www.first.org/cvss/calculator/3.1)

---

**Last Updated**: 2026-10-27
**Policy Version**: 1.0
