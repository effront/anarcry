---
id: framework_config_exposure
title: "Framework Configuration Exposure"
module: "frameworkconfig"
severity: "MEDIUM"
cwe_id: "CWE-200"
cwe_title: "Exposure of Sensitive Information to an Unauthorized Actor"
cvss_vector: "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
vrt_id: "sensitive_data_exposure.configuration_data"
---

## Summary
Framework runtime configuration (e.g. window.__NUXT__, __NEXT_DATA__) exposed in client-side JavaScript reveals internal backend URLs, API keys, environment flags, and infrastructure details.

## Description
Modern JavaScript frameworks like Nuxt.js and Next.js inject runtime configuration into the page via global variables (window.__NUXT__.config, __NEXT_DATA__.runtimeConfig). When backend URLs, API base paths, feature flags, or environment identifiers are included, attackers gain direct knowledge of internal infrastructure without active scanning.

Common exposures:
- Backend API base URLs (apiBase, API_URL) revealing internal hostnames or cloud platform slugs
- Environment identifiers (production, staging, dev) enabling targeted attacks
- Third-party service configurations (payment providers, analytics keys)
- Feature flags revealing unreleased or hidden functionality

## Impact
- Internal infrastructure mapping without active probing
- Discovery of dead/dangling backend references (subdomain takeover vector)
- Exposure of API keys or service credentials embedded in config
- Targeted attacks against revealed staging/dev environments

## Remediation
- Move sensitive configuration to server-side only (privateRuntimeConfig in Nuxt, server-only env vars in Next)
- Audit publicRuntimeConfig/NEXT_PUBLIC_ variables for sensitive values
- Use environment-specific builds that strip internal URLs from production bundles
- Implement CSP to restrict which scripts can access configuration objects
