---
id: email_security
title: "Email Security Misconfiguration"
module: "emailsec"
severity: "MEDIUM"
cwe_id: "CWE-183"
cwe_title: "Permissive List of Allowed Inputs"
cvss_vector: "AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N"
vrt_id: "server_security_misconfiguration.mail_server_misconfiguration"
---

## Summary
Missing or misconfigured email authentication records (SPF, DMARC, DKIM) allow attackers to send spoofed emails on behalf of the target domain, enabling phishing, business email compromise (BEC), and brand impersonation.

## Description
Modern email authentication relies on three complementary DNS-based mechanisms that work together to prevent unauthorized use of a domain in email:

**SPF (Sender Policy Framework)** -- a DNS TXT record published at the domain root that declares which IP addresses and mail servers are authorized to send email for the domain. When a receiving server gets an email, it checks the sender's IP against the SPF record. The record ends with a qualifier that determines how unauthorized senders are handled:
- `-all` -- hard fail: reject unauthorized senders (recommended)
- `~all` -- soft fail: mark but deliver (weak, often treated the same as no SPF)
- `+all` -- pass all: explicitly permits any server to send (dangerous -- negates SPF entirely)
- `?all` -- neutral: no policy assertion

**DMARC (Domain-based Message Authentication, Reporting, and Conformance)** -- a DNS TXT record at `_dmarc.{domain}` that tells receiving servers what to do when SPF and DKIM checks fail. The `p=` tag defines the policy:
- `p=reject` -- reject emails that fail authentication (strongest)
- `p=quarantine` -- deliver to spam/junk folder
- `p=none` -- take no action, only report (monitoring mode -- does not prevent spoofing)

DMARC also supports reporting via `rua` (aggregate) and `ruf` (forensic) tags, allowing domain owners to monitor authentication results.

**DKIM (DomainKeys Identified Mail)** -- uses public-key cryptography to sign outgoing emails. The sending server attaches a digital signature to the email headers, and the receiving server verifies it against the public key published in a DNS TXT record at `<selector>._domainkey.{domain}`. DKIM proves that the email was authorized by the domain owner and was not tampered with in transit. Key size matters -- keys shorter than 1024 bits can be factored with moderate resources.

### What happens when they are missing or misconfigured

When SPF is absent, any server can claim to send on behalf of the domain with no mechanism for receivers to detect the forgery. When SPF uses `+all`, it explicitly authorizes the entire internet. When DMARC is missing or set to `p=none`, even if SPF/DKIM fail, receiving servers have no instruction to reject or quarantine the message. Without DKIM, there is no cryptographic proof that the email content is authentic and unmodified.

The combination of all three is critical. SPF alone only checks the envelope sender (MAIL FROM), not the visible From header. DKIM alone does not tell receivers what to do on failure. DMARC ties them together by aligning the visible From header with SPF and DKIM results and enforcing a policy.

## Impact
- **Phishing and spear-phishing:** attackers send emails that appear to come from the target domain, tricking employees, customers, or partners into revealing credentials, clicking malicious links, or transferring funds.
- **Business Email Compromise (BEC):** spoofed emails from executive addresses (CEO, CFO) instruct finance teams to wire money to attacker-controlled accounts. The FBI reports billions in annual BEC losses.
- **Brand and reputation damage:** customers who receive spoofed emails lose trust in the organization, and the domain may be blocklisted by email providers.
- **Supply chain attacks:** attackers impersonate the organization in communications with vendors and partners to redirect payments or inject malicious content.
- **Regulatory non-compliance:** many compliance frameworks (PCI DSS, NIST 800-177, GDPR data protection measures) recommend or require email authentication.
- **Email deliverability degradation:** domains without proper authentication are increasingly penalized by major email providers (Google, Microsoft) with lower delivery rates.

## Payloads and Verification
```bash
# Check SPF record
dig TXT example.com +short
# Look for v=spf1 ... -all

# Check DMARC record
dig TXT _dmarc.example.com +short
# Look for v=DMARC1; p=reject; ...

# Check DKIM (requires knowing the selector -- common ones listed)
dig TXT default._domainkey.example.com +short
dig TXT google._domainkey.example.com +short
dig TXT selector1._domainkey.example.com +short
dig TXT selector2._domainkey.example.com +short
# Look for v=DKIM1; k=rsa; p=<base64 public key>

# Verify SPF alignment with a test email
# Send email from the domain and inspect headers for:
# Authentication-Results: spf=pass, dkim=pass, dmarc=pass

# Online tools for comprehensive checks:
# mxtoolbox.com, dmarcanalyzer.com, mail-tester.com
```

## False Positive Indicators
- **Subdomain-specific mail:** the organization may use a subdomain (e.g., `mail.example.com`) for email with its own SPF/DMARC records, while the apex domain intentionally has no mail configuration.
- **Third-party email services:** SPF records may use `include:` mechanisms that are resolved at query time and may not be immediately visible.
- **Non-standard DKIM selectors:** the scanner checks only common selectors (default, google, selector1). The domain may use custom selectors not covered by this check.
- **Domains not used for email:** some domains are purely web-facing and do not send email. Even so, best practice is to publish `v=spf1 -all` and `v=DMARC1; p=reject` to prevent misuse.

## Notable CVEs

| CVE | Produto | Ano | Descricao | Tipo |
|-----|---------|-----|-----------|------|
| CVE-2024-7209 | SMTP Implementations | 2024 | Vulnerabilidade em servidores SMTP permite spoofing de remetente via encaminhamento autenticado -- bypass de SPF e DKIM ao usar credenciais validas de outro dominio | Email Spoofing (SPF/DKIM Bypass) |
| CVE-2024-7208 | SMTP Implementations | 2024 | Servidores SMTP permitem que usuario autenticado envie e-mails com dominio arbitrario no MAIL FROM -- bypass completo de SPF | Email Spoofing (SPF Bypass) |
| CVE-2023-27043 | Python email.utils | 2023 | Funcao parseaddr() aceita enderecos de e-mail malformados -- permite bypass de validacao em aplicacoes que dependem dela para verificar remetentes | Email Parsing Bypass |
| CVE-2020-12272 | OpenDMARC | 2020 | Falha no enforcement de DMARC permite bypass da politica p=reject via manipulacao de alinhamento de dominio SPF/DKIM | DMARC Policy Bypass |
| CVE-2019-7164 | OpenSMTPD | 2019 | Validacao insuficiente de e-mails permite execucao remota de comandos -- atacante explora parsing de endereco no envelope MAIL FROM | RCE via Email Parsing |
| CVE-2024-39929 | Exim | 2024 | Parsing incorreto de headers RFC 2231 permite bypass de bloqueio de extensoes de arquivo em anexos -- malware chega ao destinatario | Email Filter Bypass |

Fonte: cvelistV5 (MITRE CVE List v5 dataset)

## Recommendation
1. **Publish a strict SPF record:** list all authorized senders via `include:` and IP mechanisms, and end with `-all`. Example: `v=spf1 include:_spf.google.com include:sendgrid.net -all`
2. **Deploy DMARC with enforcement:** start with `p=none` and `rua=mailto:dmarc-reports@example.com` to collect data, then escalate to `p=quarantine` and finally `p=reject` once all legitimate sources are authenticated.
3. **Enable DKIM signing:** configure the mail server to sign outgoing emails with at least a 2048-bit RSA key (or Ed25519). Publish the public key at `<selector>._domainkey.{domain}`.
4. **Align all three mechanisms:** DMARC alignment requires that the domain in the visible From header matches the SPF and/or DKIM domains.
5. **Monitor DMARC reports:** regularly review aggregate reports to identify unauthorized senders and legitimate sources that need to be added to SPF/DKIM.
6. **Rotate DKIM keys periodically:** replace keys at least annually and use 2048-bit minimum. Retire old selectors from DNS.
7. **For domains that do not send email:** publish `v=spf1 -all`, `v=DMARC1; p=reject`, and no MX records to signal that the domain should never originate email.
