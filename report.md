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

