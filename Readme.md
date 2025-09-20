
### 🔐 SecureAuth Documentation

This document outlines a robust, secure authentication system designed to protect against a wide range of modern web threats. It leverages **passwordless authentication** as the primary method while providing secure fallbacks.

### 🏛️ Architecture & Components

The system is built on a layered architecture with distinct, specialized components:

* **Auth API (Backend)**: The core service handling all authentication flows. It's responsible for user registration, login, token management, and user administration. It is stateless where possible, with state managed externally.
* **User Database**: A relational database (e.g., PostgreSQL) that stores user records, hashed password data, and WebAuthn credentials. No raw secrets are stored here.
* **Credential Store / KMS**: A Key Management Service (KMS) or Hardware Security Module (HSM) is used to store critical, non-database secrets, such as the global pepper for password hashing and the private key for signing JWTs. This isolates the most sensitive data from the main database.
* **Session Store (Redis)**: A high-performance in-memory data store used for rate limiting, session state, and server-side refresh token revocation lists. This enables real-time session invalidation.
* **Rate Limiter / WAF**: Deployed in front of the API, this component mitigates brute-force attacks and credential stuffing by throttling requests based on IP and user account.
* **SIEM / Audit Logs**: A centralized logging system to record all authentication events for monitoring, alerting, and forensic analysis.
* **Frontend**: The client-side application that orchestrates the user interaction, handling WebAuthn API calls and managing the user interface for all authentication flows.

### 🛡️ Threat Model & Mitigations

This section outlines key threats and the system's defenses.

* **Database Leak**:
    * **Defense**: Passwords are not stored. Password hashes are created using **Argon2id** with a per-user salt and a global pepper stored in the KMS. This makes offline cracking extremely difficult, even if the entire user database is compromised.
* **Phishing**:
    * **Defense**: The primary authentication method is **WebAuthn (passkeys)**, which is inherently phishing-resistant. The passkey is cryptographically bound to the website's origin, preventing it from being used on a fraudulent site.
* **Token Theft (Replay Attacks)**:
    * **Defense**: The system uses short-lived JWTs for access tokens and long-lived, opaque refresh tokens stored in secure, HttpOnly cookies. **Refresh token rotation** is implemented; each time a refresh token is used, a new one is issued, and the previous one is revoked server-side. If a refresh token is reused, all user sessions are immediately revoked.
* **Cross-Site Request Forgery (CSRF)**:
    * **Defense**: The system uses a **Synchronizer Token Pattern** to protect state-changing requests. The server issues a unique, unpredictable CSRF token that is sent to the client. The client then includes this token in a custom HTTP header for subsequent requests. The server validates the token against the one stored in the user's session.
* **Credential Stuffing**:
    * **Defense**: In addition to rate limiting and account lockouts, a service can check incoming credentials against a known list of breached passwords (e.g., using the **HaveIBeenPwned** API).

### ⚙️ Technical Specifications & Crypto Choices

* **Password Hashing**: **Argon2id** (memory: 64 MiB, time: 3, parallelism: 4), with a per-user salt and a global pepper from KMS.
* **WebAuthn**: Follows FIDO2 specifications. Verifies `clientDataJSON.type`, checks the `challenge`, and validates the `origin`. It uses a **`signCount`** check to detect cloned authenticators.
* **Tokens**:
    * **Access Token**: JWT, signed with an asymmetric key (RS256/ES256) from KMS, with a short expiration (e.g., 15 minutes).
    * **Refresh Token**: Long-lived, opaque token stored in an **`HttpOnly`**, **`Secure`**, **`SameSite=Strict`** cookie.
* **CSRF Token**: A cryptographically secure, random token generated server-side on login. Stored in Redis and also provided to the client. The client then sends it back in an HTTP header (e.g., `X-CSRF-Token`).
* **Transport**: Enforce **TLS 1.3** with **HSTS** to prevent protocol downgrade attacks.

### 🚶‍♀️ Step-by-Step Flows

#### 1. Registration (Passwordless-First)

1.  User enters email.
2.  Server creates a registration challenge and stores it in a temporary session.
3.  Browser invokes `navigator.credentials.create()` with the challenge.
4.  User's authenticator (e.g., fingerprint reader, Face ID) creates a new passkey.
5.  Browser sends the passkey credential to the server.
6.  Server verifies the attestation and stores the public key. A `CSRF` token is generated, stored in Redis, and sent to the client.

#### 2. Login (WebAuthn Primary)

1.  User enters email.
2.  Server generates an assertion challenge, retrieving valid credential IDs from the DB.
3.  Browser invokes `navigator.credentials.get()` with the challenge.
4.  User authenticates with their passkey.
5.  Browser sends the signed assertion back to the server.
6.  Server verifies the signature and `signCount`. On success, it issues a short-lived access token and a rotating refresh token, and a new CSRF token.

#### 3. Token & CSRF Handling

1.  Upon successful login, the server sets the refresh token in a secure cookie.
2.  A new CSRF token is generated.
3.  The client receives the new CSRF token, stores it, and includes it in an HTTP header for all subsequent state-changing API calls (e.g., `POST`, `PUT`, `DELETE`).
4.  For every state-changing request, the server compares the token in the header with the token stored in the user's Redis session. A mismatch results in an immediate **403 Forbidden** error.
5.  On refresh token rotation, the server issues a new refresh token and a new CSRF token to the client.

#### 4. Logout

1.  Client sends a logout request. The request includes the CSRF token.
2.  Server validates the CSRF token.
3.  The refresh token is revoked server-side in Redis.
4.  The secure cookie containing the refresh token is cleared from the browser.

### 📈 Monitoring & Auditing

* **Logging**: All authentication events are logged to the SIEM, including successful/failed logins, token refreshes, and account lockouts.
* **Alerting**: Automated alerts are configured for high-priority events, such as multiple failed login attempts from a single IP, refresh token reuse, or impossible travel (a user logging in from two geographically distant locations in a short time).
* **Penetration Testing**: Regular third-party penetration tests and internal red-teaming exercises are conducted to proactively identify vulnerabilities.

