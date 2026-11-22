---
id: clickjacking
title: "Clickjacking - Missing Frame Protection"
module: "clickjacking"
severity: "HIGH"
cwe_id: "CWE-1021"
cwe_title: "Improper Restriction of Rendered UI Layers"
cvss_vector: "AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N"
vrt_id: "clickjacking.non_sensitive_action"
---

## Summary
The application can be loaded inside an iframe on attacker-controlled domains due to missing X-Frame-Options and CSP frame-ancestors headers, enabling clickjacking attacks.

## Description
Clickjacking (UI Redress Attack) occurs when an attacker embeds the target application in a transparent or disguised iframe on a malicious page. The victim interacts with what they believe is the attacker's page, but their clicks and keystrokes are actually directed to the hidden target application.

Frame protection is provided by two complementary mechanisms:
- X-Frame-Options header (DENY or SAMEORIGIN) -- legacy but widely supported
- Content-Security-Policy frame-ancestors directive -- modern, more flexible

When both are absent, any domain can embed the target in an iframe. The attack is especially dangerous for applications with:
- Wallet connection flows (cryptocurrency exchanges, DeFi)
- One-click actions (transfer funds, approve transactions)
- Session-authenticated state-changing operations
- Form submissions with pre-filled or hidden fields

JavaScript frame-busting code is unreliable as a defense due to sandbox attribute bypasses and race conditions.

## Impact
- Unauthorized wallet connections and transaction signing
- One-click fund transfers to attacker-controlled addresses
- Account setting changes (email, password, 2FA)
- Social actions performed without user awareness
- Data exfiltration via UI manipulation

## Remediation
- Set X-Frame-Options: DENY (or SAMEORIGIN if embedding is required)
- Set Content-Security-Policy: frame-ancestors 'none' (or 'self')
- Apply headers on ALL pages, including error pages and static assets
- For Vercel: configure in vercel.json headers section
- For Nuxt: configure in nuxt.config.ts routeRules headers
- Do not rely on JavaScript frame-busting as the sole defense
