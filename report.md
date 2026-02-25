# CS382 – Secure Architecture & Threat Modeling Report
## Scenario: Option A – Online Payment Processing Application

---

# Task 1 – System Definition & Architecture

## 1.1 System Overview

This system is a web-based online payment processing platform that enables customers to securely pay merchants through card-based transactions. The platform integrates with external banking infrastructure to authorize and settle payments. It exposes a public-facing web interface for customers, a separate portal for merchants, and a restricted administrative interface for internal staff. All components are designed under a cloud-agnostic architecture with no dependency on vendor-specific services, making the system portable and infrastructure-independent.

---

## 1.2 Application Components

| Component | Description |
|---|---|
| **Web Frontend** | The customer-facing interface through which users initiate payments. Communicates with the Backend API over HTTPS. |
| **Merchant Portal** | A separate interface for merchants to manage their accounts, view transaction history, and configure payment settings. |
| **Admin Portal** | A restricted interface for internal administrators to manage users, merchants, and system configuration. Accessible only from the Administrative Zone. |
| **Backend API** | The central application server that processes all business logic, routes requests, and orchestrates communication between all internal and external components. |
| **Authentication Service** | Handles identity verification for all user types (customers, merchants, administrators). Issues and validates session tokens. |
| **User Database** | Stores customer account information, credentials (hashed), and profile data. |
| **Merchant Database** | Stores merchant account details, financial configuration, and integration credentials. |
| **Transaction Database** | Records all payment transactions including status, timestamps, amounts, and references to external payment events. |
| **Payment Gateway** | An external third-party service that processes card payments and communicates authorization responses back to the Backend API. |
| **Core Banking System** | An external banking system that handles fund transfers and settlement between accounts. |
| **Logging & Monitoring System** | A centralized system that collects logs from all components, detects anomalies, and maintains immutable audit trails. |

---

## 1.3 Users and Roles

| Role | Type | Description |
|---|---|---|
| Customer | Human User | Initiates payment transactions through the Web Frontend. |
| Merchant | Human User | Manages merchant account and views transaction data through the Merchant Portal. |
| Administrator | Human User | Manages system configuration, users, and merchants through the Admin Portal. |
| Internal Operations Staff | Human User | Monitors system health and may access logs. Subject to least-privilege access controls. |
| Payment Gateway | External System | Receives payment requests from the Backend API and returns authorization results. |
| Core Banking System | External System | Receives settlement instructions from the Backend API and processes fund transfers. |
| External Attacker | Threat Actor | An unauthorized party attempting to exploit internet-facing components. |
| Malicious Insider | Threat Actor | An internal user (staff or merchant) attempting to abuse authorized access for unauthorized purposes. |

---

## 1.4 Data Types Handled

| Data Type | Sensitivity | Description |
|---|---|---|
| User Credentials | High | Usernames, hashed passwords, MFA tokens used for authentication. |
| Payment Card Data | Critical | Card numbers, expiry dates, CVVs handled during transaction initiation. Tokenized after initial capture. |
| Transaction Records | High | Records of all payment events including amounts, timestamps, status, and merchant references. |
| Merchant Financial Data | High | Merchant account details, settlement preferences, and revenue figures. |
| Authentication Tokens | High | Session tokens and API keys issued by the Authentication Service. |
| Audit Logs | Medium | System-generated records of all user and admin actions for accountability. |
| Administrative Actions | High | Records of configuration changes, user management operations, and system overrides. |

---

## 1.5 External Dependencies

| Dependency | Role |
|---|---|
| Payment Gateway | Processes card transactions and returns authorization status. |
| Core Banking System | Handles fund settlement between financial institutions. |
| Email / SMS Service | Delivers transaction notifications and authentication codes to users. |
| DNS Infrastructure | Resolves domain names for all internet-facing components. |
| Network Infrastructure | Provides connectivity between all zones and external systems. |

---

## 1.6 Trust Boundaries

Trust boundaries define points where data crosses between security zones, requiring validation, authentication, or encryption.

| Boundary | From | To | Controls Required |
|---|---|---|---|
| TB1a | Internet (Public Zone) | Web Frontend | HTTPS/TLS, WAF, Input validation |
| TB1b | Internet (Public Zone) | Merchant Portal | HTTPS/TLS, WAF, Input validation |
| TB2 | Web Frontend / Merchant Portal | Backend API | Authenticated API calls, rate limiting |
| TB3 | Backend API | Databases | Authenticated DB connections, encrypted at rest |
| TB4 | Backend API | Payment Gateway | Mutual TLS, API key authentication |
| TB5 | Backend API | Core Banking System | Mutual TLS, signed requests |
| TB6 | Admin Portal | Backend API | MFA-enforced, role-based access, separate auth plane |
| TB7 | Internal Network | Admin Portal | VPN or restricted network access only |

**Security Zones:**

- **Public Zone** — Untrusted internet-facing users (customers, merchants)
- **Application Zone** — Web Frontend, Merchant Portal, Backend API, Auth Service, Logging & Monitoring
- **Data Zone** — User DB, Merchant DB, Transaction DB
- **External Systems Zone** — Payment Gateway, Core Banking System
- **Administrative Zone** — Admin Portal (restricted access)

---

## 1.7 Architecture Diagram

![Architecture Diagram](./architechture_diagram.png)

The diagram illustrates all system components, security zones, and data flows between the Public Zone, Application Zone, Data Zone, Admin Zone, and External Systems Zone.

---

# Task 2 – Asset Identification & Security Objectives

## 2.1 Critical Assets

| Asset | Type | CIA Priority | Rationale |
|---|---|---|---|
| User Credentials | Sensitive | C, I | Must be kept confidential to prevent account takeover. Integrity ensures credentials are not silently altered. |
| Payment Card Data | Financial / Critical | C, I, A | Highest sensitivity. Must be confidential (fraud prevention), accurate (integrity), and available during transactions. |
| Transaction Records | Financial | I, A | Must be tamper-proof for legal compliance and dispute resolution. Must remain available for auditing and reporting. |
| Merchant Financial Data | Financial | C, I | Merchant account details and revenue data are commercially sensitive and must not be exposed or modified. |
| Admin Credentials | Critical | C, I | Compromise grants full system control. Must be confidential and unalterable. |
| Authentication Tokens | Sensitive | C, I | Tokens must be secret to prevent session hijacking, and must not be forged or replayed. |
| Audit Logs | Operational | I, A | Must remain unmodified to ensure accountability. Must be available for incident response and forensic analysis. |
| Business Logic | Intellectual Property | I | If tampered with, attackers could manipulate transaction processing to commit fraud. |

---

## 2.2 Security Objectives

The following four security objectives apply across all assets. Each asset is mapped to the objectives it prioritises.

**Confidentiality** — Sensitive data must only be accessible to authorised parties. Applies to user credentials, payment card data, merchant financial data, admin credentials, and authentication tokens.

**Integrity** — Data must remain accurate and unmodified throughout its lifecycle. Applies to all assets, particularly transaction records, audit logs, and business logic where tampering has direct financial or legal consequences.

**Availability** — Critical systems and data must remain accessible when needed. Applies to transaction records and payment card data, where downtime directly disrupts payment processing.

**Accountability** — Actions performed by users and administrators must be traceable. Applies to audit logs and administrative actions, ensuring non-repudiation and enabling forensic investigation.

---

# Task 3 – Threat Modeling (STRIDE)

## 3.1 Methodology

Threat modeling was performed using the STRIDE framework, applied systematically across the six required threat areas: authentication, authorization, data storage, API communication, logging and monitoring, and administrative access. Each threat was assessed using impact × likelihood reasoning to assign a risk level of Low, Medium, or High.

---

## 3.2 Threat Surface Diagram

![Threat Surface Diagram](./threat_surface_diagram.png)

The diagram annotates the architecture with five identified threat surfaces (TS1–TS5), each indicated by a red label. Dotted lines connect each threat surface node to the components it targets. Trust boundaries are labeled on relevant data flow edges.

| Threat Surface | Label | Targets |
|---|---|---|
| TS1 | XSS, MITM, Input Injection | Web Frontend, Merchant Portal |
| TS2 | Broken Auth, Session Hijack | Authentication Service, Backend API |
| TS3 | SQL Injection, Data Breach | User DB, Transaction DB, Merchant DB |
| TS4 | MITM, Replay Attack | Payment Gateway, Core Banking System |
| TS5 | Privilege Escalation, Insider Threat | Admin Portal |

---

## 3.3 STRIDE Threat Model Table

| # | Threat | STRIDE Category | Affected Component | Impact | Likelihood | Risk Level |
|---|---|---|---|---|---|---|
| T1 | Attacker intercepts HTTPS traffic between customer and Web Frontend via MITM | Information Disclosure | Web Frontend (TB1a) | Critical — payment card data and credentials exposed | Low (requires TLS downgrade or network position) | **Medium** |
| T2 | Attacker injects malicious scripts into the Web Frontend to steal session tokens (XSS) | Tampering / Information Disclosure | Web Frontend, Merchant Portal (TS1) | High — session hijacking leads to account takeover | High (very common web attack vector) | **High** |
| T3 | Attacker submits malformed input to the Backend API to inject commands or manipulate logic | Tampering | Backend API (TB2) | High — could corrupt transaction logic or extract data | Medium (requires API knowledge) | **High** |
| T4 | Attacker obtains a valid session token and replays it to impersonate an authenticated user | Spoofing | Authentication Service (TS2) | High — full account access without credentials | Medium (tokens often leaked via XSS or logs) | **High** |
| T5 | Brute-force or credential stuffing attack against the login endpoint | Spoofing | Authentication Service (TS2) | High — unauthorized account access | High (automated tooling is widely available) | **High** |
| T6 | Authenticated merchant submits SQL injection payload through the Merchant Portal | Tampering / Information Disclosure | Merchant DB, Transaction DB (TS3) | Critical — full database read or deletion | Medium (requires bypassing input validation) | **High** |
| T7 | Backend API sends payment data over improperly validated TLS channel, enabling MITM | Information Disclosure | Payment Gateway (TB4, TS4) | Critical — live payment card data in transit exposed | Low (requires network-level attacker on backend path) | **Medium** |
| T8 | Attacker replays a previously captured authorized payment request to the Core Banking System | Spoofing | Core Banking System (TB5, TS4) | High — unauthorized fund transfer | Low (requires capture of signed request) | **Medium** |
| T9 | Admin account is compromised; attacker escalates privileges to modify system configuration | Elevation of Privilege | Admin Portal (TS5, TB6) | Critical — full system control | Medium (phishing or credential reuse) | **High** |
| T10 | Malicious insider accesses the Admin Portal from an authorized workstation to exfiltrate data | Elevation of Privilege / Information Disclosure | Admin Portal (TS5) | Critical — bulk data access without triggering alerts | Medium (insider access is authorized at the network layer) | **High** |
| T11 | Application logs are tampered with to erase evidence of a breach | Tampering | Logging & Monitoring System | High — forensic investigation is undermined | Medium (requires write access to log storage) | **High** |
| T12 | Logging system fails to capture an attack event due to misconfiguration or bypass | Repudiation | Logging & Monitoring System | Medium — inability to detect or attribute attacks | Medium (easy to miss without explicit audit rules) | **Medium** |
| T13 | Encrypted data at rest is exposed due to key mismanagement (keys stored alongside data) | Information Disclosure | User DB, Merchant DB, Transaction DB (TS3) | Critical — database encryption is rendered useless | Low (requires key infrastructure access) | **Medium** |
| T14 | Denial of Service attack floods the Backend API, disrupting payment processing | Denial of Service | Backend API | High — payment processing fully unavailable | High (DDoS is low-cost to execute) | **High** |
| T15 | Merchant uses their own authorized credentials to access or modify another merchant's data | Elevation of Privilege | Backend API, Merchant DB | High — cross-tenant data breach | Medium (depends on authorization logic correctness) | **High** |

---

## 3.4 Risk Reasoning

Risk levels were derived by applying the formula: **Risk = Impact × Likelihood**, mapped to a qualitative scale (Low / Medium / High).

**High-risk threats (T2, T3, T4, T5, T6, T9, T10, T11, T14, T15)**

These threats are rated High because they combine a High or Critical impact with a Medium or High likelihood. XSS (T2), credential stuffing (T5), SQL injection (T6), and DDoS (T14) are extremely common in web-facing payment systems and require minimal attacker skill. Privilege escalation through the Admin Portal (T9, T10) carries Critical impact because admin access grants control over the entire system, including all user data and payment routing. Log tampering (T11) is rated High because it directly undermines the effectiveness of every other control — an attacker who can erase audit trails can operate undetected indefinitely. Cross-tenant access (T15) is High because incorrectly scoped authorization in the Backend API could allow one merchant to access another's financial data, constituting both a breach and a compliance violation.

**Medium-risk threats (T1, T7, T8, T12, T13)**

These threats are rated Medium because their likelihood is constrained by technical prerequisites. MITM attacks on TLS connections (T1, T7) require an attacker to be positioned on the network path and to successfully perform a TLS downgrade or certificate substitution — both of which are significantly harder to achieve when TLS is correctly configured. Replay attacks (T8) against the Core Banking System require prior capture of a valid signed request, which is non-trivial. Log misconfiguration (T12) and encryption key mismanagement (T13) are operationally plausible but require specific deployment failures to be exploitable. These threats are not dismissed — they represent residual risks that controls must specifically address.

---

# Task 4 – Secure Architecture Design

Security controls proposed here are architectural — they operate at the system design level, not as code-level patches. Each control is justified by direct reference to threats identified in the STRIDE analysis (Task 3) and mapped to the CIA triad objectives defined in Task 2.

---

## 4.1 Identity and Access Management (IAM)

### Multi-Factor Authentication (MFA)
All user login flows — customer, merchant, and administrator — must require a second authentication factor beyond a password. For administrators, MFA must be mandatory and enforced at the network level (no login plane access without passing MFA).

**Justification:** Directly mitigates T5 (credential stuffing) and T9 (admin account compromise). Even when credentials are leaked or guessed, MFA prevents an attacker from completing the login. Admin MFA specifically addresses T10 (malicious insider) by adding a second barrier to high-value access.

### Role-Based Access Control (RBAC)
Every component in the system must enforce access based on role, not just identity. Customers may only access their own transactions and payment initiation. Merchants may only access their own merchant account and transaction history. Administrators have scoped access to configuration — not raw database access.

**Justification:** Directly mitigates T15 (cross-tenant data access) and T10 (insider abuse). Role scoping ensures that even an authenticated and legitimate user cannot access resources outside their role boundary.

### Least Privilege Enforcement
Every internal service-to-service connection must use a credential that grants only the permissions required for its specific function. The Backend API must not hold database credentials that permit schema modification. The logging service must hold write-only credentials against the audit log store.

**Justification:** Limits blast radius of T6 (SQL injection) and T9 (privilege escalation). If the Backend API is compromised, the attacker inherits only its restricted permissions — not full database control.

### Separate Admin Authentication Plane
The Admin Portal must use a completely separate authentication mechanism from the customer and merchant flows. This means a different login endpoint, different session store, and different credential management system, accessible only from restricted internal networks (TB7).

**Justification:** Mitigates T9 and T10. Separating the admin plane ensures that a compromise of the customer-facing authentication system does not grant admin access, and that admin sessions cannot be hijacked via XSS attacks on the public frontend.

### Strong Session Management
All sessions must use cryptographically random, short-lived tokens. Tokens must be invalidated on logout, after inactivity, and on re-authentication events. Tokens must be transmitted only over HTTPS and stored in HttpOnly, Secure cookies — never in localStorage.

**Justification:** Mitigates T4 (session replay) and T2 (XSS-based token theft). HttpOnly cookies prevent JavaScript access to tokens, directly limiting the damage XSS can cause. Short expiry limits the exploitation window of a stolen token.

---

## 4.2 Network Segmentation

The architecture enforces five security zones with strict inter-zone communication rules:

| Zone | Contents | Communication Rules |
|---|---|---|
| Public Zone | Internet-facing users (customers, merchants) | May only reach Application Zone via TB1a, TB1b over HTTPS |
| Application Zone | Web Frontend, Merchant Portal, Backend API, Auth Service, Logging | Internal components communicate over authenticated channels; Frontends have no direct access to Data Zone |
| Data Zone | User DB, Merchant DB, Transaction DB | Accessible only from Backend API over authenticated, encrypted connections (TB3) |
| External Systems Zone | Payment Gateway, Core Banking System | Accessible only from Backend API over Mutual TLS (TB4, TB5) |
| Administrative Zone | Admin Portal | Accessible only via VPN or internal restricted network (TB7); communicates with Backend API via separate auth plane (TB6) |

**Justification:** Segmentation limits lateral movement. If an attacker compromises the Web Frontend (via T2 or T3), they cannot directly reach databases or admin systems — they must pivot through the Backend API, which enforces authentication and authorization at every boundary. This constrains T9, T10, T15 and reduces the blast radius of all other threats.

---

## 4.3 Data Protection

### TLS for All Communications
All in-transit communication must use TLS 1.2 or higher with valid certificates. Mutual TLS (mTLS) must be used for Backend API → Payment Gateway (TB4) and Backend API → Core Banking System (TB5), ensuring that both sides authenticate the connection.

**Justification:** Mitigates T1 (customer MITM), T7 (payment data in transit), and T8 (replay attacks). mTLS specifically prevents an attacker from impersonating the Payment Gateway, and adds replay resistance because requests are signed by the client certificate.

### Encryption at Rest
All three databases must use AES-256 encryption at rest. Field-level encryption must be applied to especially sensitive columns such as payment card data and authentication credentials, using keys stored separately from the database files.

**Justification:** Mitigates T13. Encryption at rest ensures that raw database files, backups, or storage media cannot be read without the decryption keys, even if physical media is compromised.

### Payment Card Data Tokenization
Card data must be tokenized immediately after initial capture at the point of transaction initiation. The actual card number (PAN) must not be stored in the Transaction Database or transmitted beyond the tokenization boundary. Only the token is retained for subsequent reference.

**Justification:** Reduces the value of a successful T6 or T13 attack. Even if an attacker exfiltrates the Transaction Database, they obtain non-reversible tokens rather than live card numbers, which cannot be used for fraud.

### Strong Credential Hashing
User passwords must be hashed using a memory-hard algorithm (bcrypt or Argon2) before storage. No plaintext or weakly hashed passwords may be stored at any layer.

**Justification:** Mitigates T6 and T13. If the User DB is exfiltrated, passwords cannot be trivially recovered through brute-force or rainbow table attacks.

---

## 4.4 Secrets Management

### No Hardcoded Credentials
All API keys, database passwords, TLS certificates, and service credentials must be injected at runtime from a dedicated secrets management solution. No credentials may appear in source code, configuration files committed to version control, or build artefacts.

**Justification:** Prevents a class of vulnerability where a source code exposure immediately results in full system compromise. Directly relevant to T9 and T13.

### Secure Secret Storage with Scoped Access
A dedicated secrets management system must store all credentials. Secrets must be scoped to specific services — the Backend API credential for the Payment Gateway must not be accessible to the Logging Service. Access to secrets must be logged and audited.

**Justification:** Enforces least privilege at the credential level, limiting what a compromised service can access. Supports T9 and T10 mitigations.

### Key Rotation Policies
Encryption keys, API keys, and session signing keys must be rotated on a defined schedule. Key rotation must be automated where possible to eliminate human error.

**Justification:** Limits the window of exposure if a key is silently compromised. Directly addresses the residual risk in T13.

---

## 4.5 Monitoring and Logging

### Centralized, Immutable Logging
All components must emit structured logs to the centralized Logging & Monitoring System. The log store must be append-only — application-layer credentials must not have the ability to delete or modify existing log entries. Log access must require separate, elevated permissions distinct from application credentials.

**Justification:** Directly mitigates T11 (log tampering) and T12 (log bypass). Immutability ensures that an attacker who compromises the application layer cannot retroactively erase evidence. Centralized collection ensures that component-level bypasses cannot achieve total log suppression.

### Alerting on Suspicious Behavior
The monitoring system must define automated alert rules for: repeated failed logins (→ T5), abnormal transaction volumes (→ T14), admin actions outside business hours (→ T10), and cross-tenant data access patterns (→ T15). Alerts must be routed to a human-monitored channel with defined response SLAs.

**Justification:** Converts logging from a passive record into an active detection layer. This is the primary control against insider threats and ongoing attacks that bypass perimeter defenses.

### Non-Repudiable Audit Trails for Admin Actions
Every action taken through the Admin Portal — user modification, merchant configuration, system override — must generate a structured, immutable audit record including the acting user, timestamp, action taken, target resource, and source IP.

**Justification:** Provides accountability (the fourth security objective from Task 2). Directly addresses T10 by ensuring that all insider actions are traceable and cannot be denied.

---

## 4.6 Secure Deployment Practices

### Secure CI/CD Pipeline
The build and deployment pipeline must incorporate automated security checks: static analysis (SAST), dependency vulnerability scanning (SCA), and secret detection. No deployment may proceed if critical-severity vulnerabilities are detected.

**Justification:** Prevents the introduction of known-vulnerable libraries exploitable via T3 or T6, and prevents accidental credential exposure relevant to T9 and T13.

### Infrastructure as Code (IaC)
All infrastructure — networks, firewall rules, database configurations, and zone definitions — must be defined in version-controlled IaC files. Manual configuration changes must be prohibited in production environments.

**Justification:** Enforces the network segmentation design in 4.2. IaC prevents configuration drift, where manual changes inadvertently open trust boundaries or disable security controls, undermining T1, T7, and T9 mitigations.

### Patch Management
All operating system, runtime, and library dependencies must be patched within a defined SLA (critical CVEs within 72 hours). A software bill of materials (SBOM) must be maintained to enable rapid identification of affected components following a new vulnerability disclosure.

**Justification:** Reduces the attack surface for all threats by ensuring that known exploitable vulnerabilities are not present in the deployed system.

---

## 4.7 Defense-in-Depth Summary

The controls above are not independent solutions — they are layered to create defense-in-depth, where each High-risk threat from Task 3 is addressed by at least two independent controls:

| Threat | Primary Control | Secondary Control | Residual Risk After Controls |
|---|---|---|---|
| T2 (XSS, token theft) | HttpOnly session cookies | Content Security Policy (deployment layer) | Minimal — tokens inaccessible to JavaScript |
| T5 (credential stuffing) | MFA | Rate limiting on login endpoint | Residual DoS risk on login endpoint |
| T6 (SQL injection) | Parameterized queries (deployment), RBAC | Least privilege DB credentials, encryption at rest | Constrained — no credential grants schema-wide access |
| T9 (admin compromise) | Separate admin auth plane, MFA | RBAC, immutable audit trails | Insider with physical key access remains out-of-scope risk |
| T10 (malicious insider) | Immutable audit trails, behavioral alerting | RBAC, least privilege, separation of duties | Legitimate access cannot be prevented — only detected and investigated |
| T11 (log tampering) | Immutable, append-only log store | Separate log credentials scoped write-only | Compromise of log infrastructure platform itself |
| T14 (DDoS) | Rate limiting (deployment layer) | Network segmentation limits exposed attack surface | Full volumetric DDoS requires upstream infrastructure mitigation |
| T15 (cross-tenant access) | RBAC, scoped API authorization | Audit alerting on anomalous access patterns | Depends on correct implementation of authorization logic |

No single control eliminates any threat completely. The value of defense-in-depth is that an attacker must defeat multiple independent layers — a failure in one layer (e.g., MFA bypass) does not translate into a full breach, because RBAC, audit logging, and network segmentation remain independently in place.

---


---

