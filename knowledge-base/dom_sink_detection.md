---
id: dom_sink_detection
title: "Dangerous DOM Sinks in JavaScript"
module: "domsinks"
severity: "MEDIUM"
cwe_id: "CWE-79"
cwe_title: "Improper Neutralization of Input During Web Page Generation (XSS)"
cvss_vector: "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"
vrt_id: "cross_site_scripting_xss.dom_based"
---

## Summary
Dangerous DOM sink functions (innerHTML, eval, document.write) detected in JavaScript source code indicate potential DOM-based XSS vulnerabilities when user-controlled data flows into these sinks.

## Description
DOM-based XSS occurs when client-side JavaScript writes user-controlled data to dangerous sinks without sanitization. Common dangerous sinks include:

- element.innerHTML / element.outerHTML -- injects parsed HTML
- eval() / Function() / setTimeout(string) / setInterval(string) -- executes arbitrary code
- document.write() / document.writeln() -- rewrites page content
- location.href / location.assign() / location.replace() -- navigates to attacker URL
- jQuery .html() / .append() with unsanitized input

When data from sources like location.hash, location.search, document.referrer, postMessage, or URL fragments flows into these sinks without encoding, attackers can inject and execute arbitrary JavaScript.

## Impact
- Session hijacking via cookie theft
- Account takeover through credential harvesting
- Defacement of the application interface
- Redirection to phishing pages
- Keystroke logging and form data exfiltration

## Remediation
- Replace innerHTML with textContent for plain text insertion
- Use DOMPurify or equivalent for HTML that must be rendered
- Avoid eval() and Function() entirely -- use JSON.parse() for data
- Implement Content-Security-Policy with strict script-src
- Use framework-provided safe rendering (v-text in Vue, {} in React)
