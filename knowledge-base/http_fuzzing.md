# HTTP Fuzzing / Intruder

## Overview

HTTP fuzzing is the automated technique of sending many modified HTTP requests to a target, varying specific parameters with payloads from wordlists or generated ranges. It is used to discover vulnerabilities like SQL injection, XSS, authentication bypass, IDOR, and directory enumeration.

## Attack Types

### Sniper
Tests one payload position at a time while keeping others at their default values. Good for testing each parameter individually with a single wordlist.

**Use when**: Testing each input separately (e.g., checking each form field for SQLi).

### Battering Ram
Uses the same payload in all positions simultaneously. Good for testing identical values across multiple injection points.

**Use when**: The same value must appear in multiple places (e.g., username repeated in body and header).

### Pitchfork
Uses different wordlists for each position in parallel (zip). Position 1 gets wordlist 1 line N, position 2 gets wordlist 2 line N. Stops when the shortest list runs out.

**Use when**: Testing correlated values (e.g., username:password pairs).

### Cluster Bomb
Cartesian product of all wordlists across all positions. Tests every combination.

**Use when**: Brute-forcing combinations (e.g., all usernames x all passwords). Warning: combinatorial explosion with large lists.

## Payload Sources

- **Wordlist files**: .txt files with one payload per line (SecLists, custom lists)
- **Inline payloads**: Manually entered payloads separated by newlines
- **Numeric range**: Generated sequences with start, end, step, and zero-padding

## Payload Processing

Payloads can be transformed before injection through a processing pipeline:

| Processor | Description |
|---|---|
| URL encode/decode | Percent-encoding for URLs |
| Base64 encode/decode | Base64 transformation |
| HTML encode/decode | HTML entity encoding |
| Hash (MD5/SHA) | One-way hash of payload |
| Prefix/Suffix | Add fixed text before/after |
| Match/Replace | Regex-based transformation |
| Skip if matches | Filter out payloads matching a pattern |

## Grep Match / Extract

**Grep Match**: Count occurrences of patterns in responses to identify interesting behavior (error messages, SQL syntax, tokens).

**Grep Extract**: Extract specific values from responses using regex capture groups (CSRF tokens, session IDs, error codes).

## Common Fuzzing Scenarios

### Directory/File Discovery
- Fuzz the path component with a directory wordlist
- Filter by status code (200, 301, 403) and response length
- Use wordlists like `common.txt`, `directory-list-2.3-medium.txt`

### Parameter Brute-Force
- Fuzz parameter values with common injection payloads
- Monitor for status code changes, response length anomalies
- Grep for error strings indicating successful injection

### Authentication Testing
- Pitchfork with username:password lists
- Monitor response length differences (login success vs failure)
- Rate limit detection via 429 or response time changes

### IDOR Discovery
- Range source (1-10000) on ID parameters
- Filter by response length changes (different user data)
- Grep for PII patterns

## Mitigation (Defensive Perspective)

- Input validation and parameterized queries prevent injection
- Rate limiting and account lockout slow brute-force
- WAF rules detect common fuzzing patterns
- CSRF tokens prevent automated form submission
- Consistent error messages prevent information leakage

## References

- CWE-20: Improper Input Validation
- CWE-307: Improper Restriction of Excessive Authentication Attempts
- OWASP Testing Guide -- Input Validation Testing
- Burp Suite Intruder documentation
- OWASP ZAP Fuzzer documentation
