# Security Policy & Threat Model
## Advanced Password Strength Analyzer and Security Recommendation System

### 1. Executive Summary & Core Security Guarantees

This document establishes the security principles, privacy architecture, threat model, and protective controls implemented in the **Advanced Password Strength Analyzer and Security Recommendation System**.

As an educational cybersecurity application, its primary security mandate is:
> **"Provide actionable, rigorous password vulnerability insights without becoming a vector for credential compromise."**

---

### 2. Privacy & Data Protection Model

#### The Zero-Retention Principle
- **No Disk Storage of Credentials:** The application does not write entered passwords to SQLite, flat files, browser LocalStorage, or cookies.
- **No Log Leakage:**
  - Standard Flask access logging does not log the HTTP POST body.
  - Custom logging explicitly suppresses any representation of the input string.
  - Stack traces and error pages do not echo request payloads.
- **No Third-Party Transmission:**
  - Password analysis is executed 100% locally on the Flask server.
  - The application does NOT query external APIs (such as remote HaveIBeenPwned endpoints with full passwords), preventing network interception, man-in-the-middle leakage, or DNS surveillance.
- **No Credential Reflection:**
  - The API response (`POST /api/analyze`) purposefully omits the `password` field. It returns only metadata (score, strength, entropy, detected patterns, recommendations).
- **Volatile In-Memory Lifecycle:**
  - The password string is accessed in Python process memory only during metric calculation and is subsequently unreferenced to facilitate garbage collection.

---

### 3. Threat Modeling & Mitigation Analysis

| Threat Actor / Vector | Description | System Mitigation |
|---|---|---|
| **Eavesdropper / MitM** | Attacker intercepts transit traffic to capture entered credentials. | In production, enforce HTTPS/TLS; in development, runs on localhost only. Password never transmitted in URL query strings (strictly HTTP POST with JSON body). |
| **Server Log Harvester** | Malicious insider or compromised log collector reads server logs. | Logging configuration explicitly filters out request bodies; passwords are never printed to stdout/stderr. |
| **Cross-Site Scripting (XSS)** | Malicious injected scripts read password input elements or response payloads. | Content Security Policy (`default-src 'self'`); Jinja2 automatic HTML escaping; absence of inline scripting; no storage in DOM `localStorage`. |
| **Cross-Site Request Forgery (CSRF)** | Attacker forces user's browser to submit passwords to analyzer. | API endpoints consume strictly `application/json` with origin validation; analyzer is stateless and idempotent; analysis does not perform state modification. |
| **Clickjacking / Framing** | Attacker embeds analyzer in an iframe to trick user into entering credentials. | HTTP Header `X-Frame-Options: DENY` and CSP `frame-ancestors 'none'`. |
| **MIME Sniffing & Caching** | User's browser caches sensitive analysis responses on disk. | HTTP Headers: `X-Content-Type-Options: nosniff`, `Cache-Control: no-store, no-cache, must-revalidate`, `Pragma: no-cache`. |
| **Predictable Password Generation** | Attacker predicts passwords created by the generator. | Replaced standard pseudo-random number generator (`random`) with OS-backed CSPRNG (`secrets` module using `os.urandom` / Windows `CryptGenRandom`). |
| **DoS via Massive Input** | Attacker submits a multi-megabyte string to cause denial of service. | Input validation enforces a strict maximum password length (capped at 256 characters) and validates payload size. |

---

### 4. Critical Conceptual Distinction: Password Analysis vs. Secure Password Storage

In cybersecurity academic assessments (viva) and engineering practice, it is vital to clearly delineate between **Password Strength Analysis** and **Secure Password Storage**:

```
+---------------------------------------------------------------------------------------+
|                               PASSWORD LIFECYCLE STAGES                               |
+---------------------------------------------------------------------------------------+
| 1. Creation & Evaluation (This Project)      | 2. Storage & Authentication (Backends) |
+----------------------------------------------+----------------------------------------+
| Goal: Help user pick high-entropy secrets    | Goal: Verify user identity securely    |
| When: User registers or updates password     | When: User logs in                     |
| Operation: Evaluates length, patterns,       | Operation: One-way cryptographic       |
| dictionary matches, and Shannon entropy      | Slow Key Derivation Function (KDF)     |
| Data Persisted: NONE (Zero retention)        | Data Persisted: Salt + One-way Hash    |
| Standard: NIST SP 800-63B Guidelines         | Algorithms: Argon2id, bcrypt, scrypt   |
+----------------------------------------------+----------------------------------------+
```

#### Why Passwords Must Never Be Stored Plaintext or with Reversible Encryption
1. **Plaintext Storage:** A single SQL injection (SQLi) or compromised database backup instantly exposes all accounts across the entire organization.
2. **Reversible Encryption (AES/DES):** Requires storing an encryption key. If an attacker gains server access, they acquire both the database and the decryption key, rendering the encryption useless.
3. **Legacy Fast Hashes (MD5, SHA-1, SHA-256):** These algorithms were designed for file integrity and speed. A modern GPU cluster can compute **tens of billions** of SHA-256 hashes per second, making brute-force and rainbow table attacks trivial.

#### Modern Standard: Slow Salted Password Hashing
- **Argon2id (Winner of the Password Hashing Competition):** Provides resistance to GPU and ASIC attacks by demanding both high CPU time and configurable memory footprints.
- **bcrypt:** Incorporates a salt to defeat rainbow tables and a configurable work factor (cost) to adapt to escalating computing power.
- **Unique Per-User Salt:** Ensures that identical passwords produce distinct hash representations, defeating precomputed lookup tables.

---

### 5. NIST SP 800-63B-4 Compliance Alignment

The application incorporates key shifts from modern NIST Digital Identity standards:
1. **Length over Complexity:** Encourages lengthy passphrases (16+ characters) rather than forcing arbitrary punctuation swaps (`P@$$w0rd`).
2. **Blocklist Enforcement:** Actively flags passwords appearing on known compromised and frequently chosen lists.
3. **No Arbitrary Composition Restrictions:** Does not penalize users for choosing natural multi-word phrases.
4. **Pattern Penalty:** Detects keyboard walks, sequential counting, and dictionary words.
