# ShieldInbound Audit Suite

**A FedRAMP-High Simulated Zero-Trust Control Plane**
*Serverless - Azure Static Web Apps - Node.js Azure Functions v4*

[![Live Demo](https://img.shields.io/badge/Live%20Demo-Azure%20SWA-0ea5e9?style=flat-square)](https://gray-cliff-0ed98850f.7.azurestaticapps.net)
[![Azure](https://img.shields.io/badge/Platform-Azure%20Static%20Web%20Apps-0078d4?style=flat-square&logo=microsoftazure)](https://azure.microsoft.com/en-us/products/app-service/static)
[![License](https://img.shields.io/badge/License-MIT-64748b?style=flat-square)](LICENSE)

---

## Overview

**ShieldInbound** is a serverless, single-page security control plane engineered to simulate the access enforcement and monitoring behaviors of a FedRAMP High-authorized cloud environment. The application validates three security mechanics in real time: just-in-time cryptographic credential issuance, AI prompt payload inspection, and SIEM-style audit telemetry, without incurring infrastructure cost beyond Azure's free tier.

The system was designed to demonstrate practical alignment with NIST SP 800-53 Rev. 5, FedRAMP High, CMMC 2.0 Level 2, ISO/IEC 27001:2022, and SOC 2 Type II controls across a single, auditable backend runtime.

> **Scope Note:** This application is a portfolio simulation. The UI functions as an administrative audit pane. In a production topology, the backend would operate as an invisible inline API proxy integrated with IAM webhook pipelines, Azure PIM orchestration, and a SIEM data lake such as Microsoft Sentinel or Splunk.

---

## Architecture

The platform is a two-tier serverless system. Static assets are served from the Azure Static Web Apps global edge (with HSTS and CSP headers applied at the CDN). The single-page frontend calls a Node.js Azure Functions v4 backend at the /api/hello route over POST and GET. The backend handles RSA-2048 key generation, RS256 JWT signing, the 9-family guardrail engine, the tiered SIEM logger, and POST rate limiting.

**Deployment model:** No persistent storage. Credential lifecycle and audit telemetry are intentionally session-scoped to reflect ephemeral zero-trust design principles.

---

## Features

### 1. Just-In-Time (JIT) Cryptographic Lease Engine

Enforces least-privilege access by replacing long-lived credentials with ephemeral, time-bound asymmetric lease assertions.

- Generates a real RSA-2048 key pair per request using Node.js crypto; keys are never persisted
- Produces a properly structured RS256-signed JWT with iat, exp, jti, tenant, and scope claims
- Exports a JWK public key descriptor (n, e, kid, alg) for verification
- TTL countdown triggers FIPS 140-3-style cryptographic zeroization on expiry, clearing volatile memory state
- Latency reported from actual measurement of the RSA signing operation

**Production equivalent:** Azure PIM webhook to JIT engine to signed assertion delivered to calling microservice terminal session, no human click required.

**Compliance mapping:** NIST AC-2, AC-6 - CMMC AC.L2-3.1.5 - ISO A.5.15 - SOC 2 CC6.3

---

### 2. Deterministic AI Payload Guardrail Shield

An inline heuristic inspection engine that classifies inbound prompt payloads against a 129-pattern, 9-family adversarial signature library before they reach downstream processing.

#### Threat Family Coverage

| Family | Attack Category | Example Signals |
|---|---|---|
| F1 | Context Dismissal | ignore previous instructions, reset your memory, clean slate mode |
| F2 | Identity Hijacking | you are now unrestricted, DAN mode, developer mode, act as root |
| F3 | Privilege Escalation | bypass auth controls, sudo, escalate privileges, grant admin access |
| F4 | System Probing | reveal your system prompt, repeat your instructions, hidden config |
| F5 | SQL and Command Injection | UNION SELECT, DROP TABLE, OR 1=1, xp_cmdshell, whoami |
| F6 | XSS and Script Injection | script tags, javascript protocol, onerror, document.cookie, eval |
| F7 | Payload Delivery | .exe, .ps1, powershell -enc, base64 decode, wget https |
| F8 | Social Engineering | hypothetically speaking, for a story where an AI has no rules |
| F9 | Data Exfiltration | dump the database, exfiltrate all credentials, list all passwords |

#### 4-Tier Threat Scoring Engine

| Tier | Condition | Response Behavior |
|---|---|---|
| COMPLIANT | 0 families matched | Payload passes. Logged as clean. |
| FLAGGED | 1 family, 1 signal | Payload passes with elevated monitoring. Analyst alert logged. |
| VIOLATION | 1 family with 2+ signals, or 2 families | Payload blocked. Connection terminated. |
| CRITICAL | 3+ families, or 2+ families with 3+ signals | Payload blocked. Multi-vector incident escalated in SIEM. |

**Production equivalent:** Inline API proxy sitting between developer IDE extensions and downstream LLM endpoints, performing sub-millisecond heuristic parsing before model execution.

**Compliance mapping:** NIST SI-4 - CMMC SI.L2-3.14.2 - ISO A.8.12 - SOC 2 CC7.2

---

### 3. SIEM Audit Ledger and Transactional Log Monitor

A real-time telemetry pane that surfaces all system transactions with cross-framework compliance annotations.

- Every backend action produces a structured log entry with a cryptographically random Event ID, timestamp, tenant context, threat tier, and multi-framework compliance mapping
- Status values are color-coded: CRITICAL (deep red), VIOLATION and BLOCKED (red), FLAGGED and THROTTLED (amber), MINTED and COMPLIANT (blue)
- Audit log is seeded on cold start to reflect realistic session state for evaluators

**Production equivalent:** Structured JSON log stream to Azure Log Analytics workspace to Microsoft Sentinel correlation rules to automated alert or resource isolation on violation.

**Compliance mapping:** NIST AU-2, AU-12 - CMMC AU.L2-3.3.1 - ISO A.8.15 - SOC 2 CC7.2

---

### 4. Adaptive Rate Limiting (DoS Protection)

- Enforces a 4 requests per 10-second sliding window on POST traffic only
- GET audit log requests are explicitly excluded from rate enforcement
- Throttle events are logged to the SIEM with NIST SC-5 compliance mapping
- Returns HTTP 429 with structured JSON, never an HTML error page

**Compliance mapping:** NIST SC-5 - CMMC SC.L2-3.13.5 - ISO A.8.20 - SOC 2 CC8.1

---

## Security Control Cross-Reference

| Technical Feature | NIST SP 800-53 Rev. 5 | CMMC 2.0 (Level 2) | ISO/IEC 27001:2022 | SOC 2 Type II |
|---|---|---|---|---|
| JIT Asymmetric Token Minting | AC-2 / AC-6 | AC.L2-3.1.5 | A.5.15 | CC6.3 |
| FIPS 140-3 Cryptographic Zeroization | MP-6 / SC-12 | IA.L2-3.5.3 | A.8.10 | CC6.5 |
| 9-Family Prompt Guardrail | SI-4 | SI.L2-3.14.2 | A.8.12 | CC7.2 |
| 4-Tier Threat Classification | SI-4 / IR-4 | SI.L2-3.14.3 | A.8.16 | CC7.3 |
| Adaptive DoS Throttling | SC-5 | SC.L2-3.13.5 | A.8.20 | CC8.1 |
| SIEM Audit Telemetry | AU-2 / AU-12 | AU.L2-3.3.1 | A.8.15 | CC7.2 |
| HTTP Security Headers | SC-8 / SI-10 | SC.L2-3.13.8 | A.8.23 | CC6.6 |

---

## Tech Stack

| Layer | Technology |
|---|---|
| Hosting | Azure Static Web Apps (Free Tier) |
| Backend Runtime | Azure Functions v4, Node.js 22 |
| Cryptography | Node.js crypto: RSA-2048 / RS256 / PSS padding |
| Frontend | Vanilla HTML5 / CSS3 / JavaScript (no framework dependencies) |
| Security Headers | staticwebapp.config.json: HSTS, CSP, X-Frame-Options, X-Content-Type-Options |
| Deployment | Azure SWA CLI |

---

## HTTP Security Headers

Configured globally via staticwebapp.config.json and enforced at the Azure CDN edge on every response:

- Strict-Transport-Security: max-age 31536000, includeSubDomains, preload
- Content-Security-Policy: default-src self, script-src self with unsafe-inline
- X-Frame-Options: DENY
- X-Content-Type-Options: nosniff
- Referrer-Policy: strict-origin-when-cross-origin
- X-XSS-Protection: 1, mode block

> **Known limitation:** script-src includes unsafe-inline because all JavaScript is currently embedded in the HTML file. A hardened production deployment would externalize scripts and replace this with a nonce-based CSP directive.

---

## Known Architectural Boundaries

| Boundary | Production Upgrade Path |
|---|---|
| authLevel anonymous on API function | Replace with Azure AD-backed function keys or APIM subscription key enforcement |
| In-memory audit log (session-scoped) | Stream structured JSON to Azure Log Analytics and Microsoft Sentinel |
| unsafe-inline in CSP | Externalize JS files and implement nonce-based CSP directives |
| Regex-based guardrail (signature detection only) | Layer Azure AI Content Safety or a fine-tuned classification model for semantic detection |
| Single-function API handler | Decompose into dedicated function endpoints per action as traffic scales |

---

## Author

**Tory Keit**
Lead Systems Architect - Zero Trust and FedRAMP Compliance
Live Demo: https://gray-cliff-0ed98850f.7.azurestaticapps.net

---

SYS VER: 2.9.5 - CUI // FEDRAMP-HIGH-SIM // FIPS 199 HIGH IMPACT
