# AnarCry -- Base de Conhecimento de Vulnerabilidades

Base estruturada para o motor de varredura, triagem e geração de relatórios do AnarCry.
Cada arquivo corresponde a um módulo/finding suportado pela ferramenta e segue o schema
YAML consumido pelo `ReportEngine`.

## Findings

| ID | Título | Módulo | Severidade | CWE | VRT |
|---|---|---|---|---|---|
| `tls_weak_configuration` | Weak TLS Configuration | `tls` | MEDIUM | CWE-326 | `cryptography_issues.weak_tls` |
| `security_headers_missing` | Missing Security Headers | `headers` | MEDIUM | CWE-693 | `server_security_misconfiguration.missing_security_headers` |
| `jwt_signature_bypass` | JWT Signature and Algorithm Bypass | `jwt` | CRITICAL | CWE-347 | `broken_authentication_and_session_management.authentication_bypass.json_web_token_vulnerability` |
| `post_quantum_readiness` | Post-Quantum Cryptography Readiness Gap | `pqc` | LOW | CWE-311 | `cryptography_issues.weak_tls` |
| `cors_misconfiguration` | CORS Misconfiguration | `cors` | HIGH | CWE-942 | `broken_authentication_and_session_management.authentication_bypass.other` |
| `oauth_misconfiguration` | OAuth 2.0 / OIDC Misconfiguration | `oauth` | CRITICAL | CWE-352 | `broken_authentication_and_session_management.oauth_misconfiguration` |
| `open_redirect` | Open Redirect | `openredirect` | MEDIUM | CWE-601 | `broken_authentication_and_session_management.open_redirect` |
| `ssrf` | Server-Side Request Forgery | `ssrf` | CRITICAL | CWE-918 | `server_security_misconfiguration.server_side_request_forgery` |
| `graphql_misconfiguration` | GraphQL Misconfiguration | `graphql` | HIGH | CWE-200 | `server_security_misconfiguration.graphql_misconfiguration` |
| `crlf_injection` | CRLF Injection / HTTP Response Splitting | `crlf` | MEDIUM | CWE-113 | `cross_site_scripting_xss.reflected_xss` |
| `xxe` | XML External Entity Injection | `xxe` | HIGH | CWE-611 | `injection.xml_external_entity_injection` |
| `ssti` | Server-Side Template Injection | `ssti` | CRITICAL | CWE-94 | `injection.remote_code_execution.server_side_template_injection` |
| `idor` | Insecure Direct Object Reference | `idor` | MEDIUM | CWE-639 | `broken_access_control.insecure_direct_object_references` |
| `host_header_injection` | Host Header Injection | `hostheader` | HIGH | CWE-20 | `server_security_misconfiguration.host_header_injection` |
| `spring_actuator_exposure` | Spring Boot Actuator Exposure | `actuator` | HIGH | CWE-200 | `server_security_misconfiguration.sensitive_data_exposure` |
| `mass_assignment` | Mass Assignment | `massassign` | HIGH | CWE-915 | `broken_access_control.mass_assignment` |
| `cache_poisoning` | Web Cache Poisoning | `cachepoisoning` | HIGH | CWE-524 | `server_security_misconfiguration.web_cache_poisoning` |
| `request_smuggling` | HTTP Request Smuggling | `reqsmuggling` | CRITICAL | CWE-444 | `server_security_misconfiguration.http_request_smuggling` |
| `xss` | Cross-Site Scripting | `xss` | CRITICAL | CWE-79 | `cross_site_scripting_xss.reflected_xss` |
| `sql_injection` | SQL Injection | `sqli` | CRITICAL | CWE-89 | `injection.sql_injection` |
| `lfi` | Local File Inclusion / Path Traversal | `lfi` | HIGH | CWE-22 | `server_security_misconfiguration.path_traversal` |
| `command_injection` | OS Command Injection | `cmdinjection` | CRITICAL | CWE-78 | `injection.remote_code_execution.command_injection` |
| `hsts_missing` | Missing HTTP Strict Transport Security | `hsts` | LOW | CWE-319 | `server_security_misconfiguration.missing_security_headers` |
| `csrf` | Cross-Site Request Forgery | `csrf` | HIGH | CWE-352 | `broken_authentication_and_session_management.csrf` |
| `infrastructure_exposure` | Exposed Infrastructure Service | `infra` | CRITICAL | CWE-284 | `server_security_misconfiguration.exposed_admin_interface` |

## Convenções

- `module` usa o identificador do módulo do AnarCry em lowercase.
- `severity` segue o CVSS v3.1 Base Score: CRITICAL >= 9.0, HIGH 7.0-8.9, MEDIUM 4.0-6.9, LOW 0.1-3.9.
- `cvss_vector` representa o pior caso razoável do finding, não o caso mais brando.
- `vrt_id` segue a Bugcrowd Vulnerability Rating Taxonomy.

## Fontes extraídas

Os três PDFs fornecidos foram convertidos para Markdown e salvos em `_sources/`:

| Arquivo | Autor | Páginas |
|---|---|---|
| [`_sources/bug_bounty_bootcamp_vickie_li.md`](_sources/bug_bounty_bootcamp_vickie_li.md) | Vickie Li | 418 |
| [`_sources/from_day_zero_to_zero_day_eugene_lim.md`](_sources/from_day_zero_to_zero_day_eugene_lim.md) | Eugene Lim | 321 |
| [`_sources/hacking_com_kali_linux_broad_bindner.md`](_sources/hacking_com_kali_linux_broad_bindner.md) | James Broad & Andrew Bindner | 247 |

## Nota de proveniência

- **Bug Bounty Bootcamp (Vickie Li)**: fonte conceitual primária dos findings web
  (descrição, impacto, remediação e metodologia de caça), extraída via `pdftotext`.
- **From Day Zero to Zero Day (Eugene Lim)**: fonte de apoio para metodologia de
  pesquisa, fuzzing e exploração; não cobre a maioria das falhas web/crypto do catálogo.
- **Hacking com Kali Linux (Broad & Bindner)**: fonte de apoio para ferramentas e
  metodologia de testes de invasão; não é usada como base conceitual dos findings.
- **Real-World Bug Hunting (Peter Yaworski)**: o PDF não estava disponível no ambiente no
  momento da geração. Os cenários de ataque, parâmetros e mutações de payload foram
  consolidados a partir do conhecimento público da obra e de relatórios reais de programas
  de bug bounty; devem ser tratados como material de apoio, não como citação literal.

## Integração com o AnarCry

O `ReportEngine` pode carregar o frontmatter de cada arquivo para enriquecer os findings:

```java
// Mapa module -> arquivo markdown
// O título, CWE, CVSS e VRT do knowledge-base devem prevalecer sobre o fallback
// apenas quando o finding real não trouxer evidência que justifique outro score.
```
