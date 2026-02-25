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
