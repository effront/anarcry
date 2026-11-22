---
id: js_endpoint_exposure
title: "JavaScript API Endpoint Exposure"
module: "jsanalyzer"
severity: "MEDIUM"
cwe_id: "CWE-200"
cwe_title: "Exposure of Sensitive Information to an Unauthorized Actor"
cvss_vector: "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
vrt_id: "sensitive_data_exposure.api_endpoints"
---

## Summary
API endpoints extracted from client-side JavaScript bundles reveal backend attack surface including undocumented, admin, and internal endpoints not visible through crawling.

## Description
JavaScript bundles frequently contain hardcoded API endpoint paths in fetch(), $fetch(), axios, and XMLHttpRequest calls. Static analysis of these bundles reveals:

- REST API paths (e.g. /api/v1/swaps/new-exchange, /api/admin/users)
- GraphQL endpoints and query patterns
- WebSocket connection URLs
- Third-party API integration endpoints
- Internal/admin endpoints not linked from the UI

These endpoints expand the attack surface beyond what a crawler discovers and often include endpoints with missing authentication, broken access control, or sensitive data exposure.

## Impact
- Discovery of undocumented or admin-only API endpoints
- Identification of endpoints with missing authentication
- Mapping of full API surface for automated fuzzing
- Discovery of deprecated but still-active endpoints

## Remediation
- Implement proper authentication and authorization on all API endpoints
- Use code splitting to avoid bundling admin endpoints in public-facing code
- Remove unused API client code from production bundles
- Implement API gateway with consistent auth enforcement
