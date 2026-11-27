---
title: "The Ultimate Guide to SSRF: Hunting, Bypassing and Exploiting in Modern Bug Bounty"
author: "Lostsec"
source_url: "https://infosecwriteups.com/the-ultimate-guide-to-ssrf-hunting-bypassing-and-exploiting-in-modern-bug-bounty-a43fa34ba324"
platform: "Medium / InfoSec Write-ups"
language: "en"
extraction_tool: "claude-code (HTML parse)"
extracted_at: "2026-11-25"
---

Guia completo de SSRF para bug bounty moderno cobrindo:
- Bypass de allowlists (IP obfuscation, DNS rebinding, protocol smuggling, URL parser differentials)
- Vetores avancados (SVG image processing, GraphQL mutations, WebSocket proxying, FFmpeg/HLS, PDF renderer)
- Cloud metadata endpoints (AWS IMDSv1/v2, ECS, GCP, Azure, DigitalOcean, Alibaba, Hetzner, OpenStack, Oracle, Packetcloud)
- Protocolos de exfiltracao (gopher, dict, file, jar, netdoc, ldap, sftp)
- Cadeia de escalacao (SSRF -> credential theft -> RCE)
- Pipeline de deteccao (subfinder + gau + gf ssrf + nuclei)
- Ferramentas (Interactsh, SSRFmap, Gopherus3)

Usado para enriquecer: `ssrf.md`
