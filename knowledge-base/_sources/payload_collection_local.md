---
title: "Colecao Local de Payloads"
author: "Diversas fontes (compilacao)"
source_path: "/home/bullet/PROJETOS/payloads/"
language: "en"
extraction_tool: "manual"
extracted_at: "2026-11-25"
---

Colecao de 60+ arquivos de payload para enriquecimento do knowledge-base.
Mapeamento de arquivos usados:

| Arquivo | Linhas | KB Alvo | Conteudo |
|---|---|---|---|
| `ssrf.txt` | 122 | `ssrf.md` | Localhost, cloud metadata, gopher/dict/jar payloads |
| `ssrfBypass-payloads.txt` | 56 | `ssrf.md` | Allowlist bypass, authority confusion, encoding, nip.io |
| `ssti.txt` | 107 | `ssti.md` | Jinja2, FreeMarker, Mako, Smarty, SpEL, Pebble payloads |
| `crlf.txt` | 63 | `crlf_injection.md` | Encoding variants, Unicode CRLF, response splitting |
| `xss.txt` | 2670 | `xss.md` | Angular injection, event handlers, data URI, encoding bypass |
| `xsswafbypss.txt` | 102 | `xss.md` | WAF bypass: Cloudflare, Unicode, popover API, constructor chains |
| `xsspollygots.txt` | 96 | `xss.md` | Polyglot XSS multi-context payloads |
| `blindsqli.txt` | 96 | `sql_injection.md` | Time-based blind SQLi para MySQL, PostgreSQL, MSSQL, Oracle |
| `directory_traversal_unix.txt` | 871 | `lfi.md` | Path traversal /etc/passwd com encoding bypass |
| `directory_traversal_win.txt` | 847 | `lfi.md` | Path traversal boot.ini com encoding bypass |
| `xml.txt` | 77 | `xxe.md` | WEB-INF paths para Java apps (Struts, JSF, SOAP) |
| `jwt-secrets.txt` | 3503 | `jwt_signature_bypass.md` | Wordlist de segredos JWT comuns para brute-force |
| `spring-boot.txt` | 113 | `spring_actuator_exposure.md` | Endpoints do Spring Boot Actuator |
