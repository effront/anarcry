---
id: backend_liveness
title: "Dangling Backend Reference"
module: "backendliveness"
severity: "HIGH"
cwe_id: "CWE-672"
cwe_title: "Operation on a Resource after Expiration or Release"
cvss_vector: "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
vrt_id: "server_security_misconfiguration.dangling_dns"
---

## Summary
Frontend references a backend URL that is dead (NXDOMAIN, connection refused, or HTTP error), indicating a dangling resource that may be claimable by an attacker for subdomain takeover or traffic interception.

## Description
When a frontend application hardcodes backend API URLs (via framework config, environment variables, or JavaScript), and the corresponding backend infrastructure is decommissioned without updating the frontend, the reference becomes dangling. This creates several attack vectors:

- NXDOMAIN: the domain/subdomain no longer resolves, potentially allowing an attacker to register it or claim the cloud resource
- Connection refused: the server is down but DNS still resolves, indicating abandoned infrastructure
- HTTP 404/502/503 from cloud platforms: the app was deleted but the platform still responds

Cloud platforms like DigitalOcean App Platform, Heroku, Azure, and AWS use predictable naming patterns. An attacker who claims the abandoned resource receives all API traffic the frontend sends.

## Impact
- Full API traffic interception (credentials, user data, transaction details)
- Man-in-the-middle attacks on application functionality
- Data exfiltration from users who interact with the compromised frontend
- Subdomain takeover enabling phishing and cookie theft

## Remediation
- Remove or update dead backend references in frontend configuration
- Implement health checks that alert when backend URLs become unreachable
- Use infrastructure-as-code to ensure frontend and backend deployments are coupled
- Monitor DNS for NXDOMAIN on critical subdomains
- Keep cloud platform resources reserved even after decommissioning
