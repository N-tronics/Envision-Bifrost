# Bifrost Authentication Server & 2FA Engine

Bifrost is a secure, custom-built Two-Factor Authentication (2FA) server portal and API backend. It implements a from-scratch Diffie-Hellman Key Exchange and an RFC 6238-compliant Time-Based One-Time Password (TOTP) validation engine. 

This project was engineered to demonstrate applied network security, ephemeral routing, and raw cryptographic algorithms without relying on abstract third-party authenticator libraries (like `pyotp` or external OAuth providers).

---

## 🚀 Core Features & Security Posture

* **Native TOTP Implementation (RFC 6238):** A custom cryptographic engine that converts shared secrets into 6-digit rolling codes using HMAC-SHA1 hashing and dynamic array truncation.
* **Diffie-Hellman Key Exchange:** Secure, over-the-network shared secret generation. The master authentication key is dynamically negotiated and *never* transmitted across the network in plain text.
* **"Burn-After-Reading" Endpoints:** Single-use API routes explicitly designed to facilitate the key exchange and immediately self-destruct, effectively neutralizing Replay Attacks.
* **Asynchronous State Polling:** A lightweight HTTP polling mechanism that allows the web frontend to react in real-time to external cryptographic handshakes.
* **Custom Arbitrary-Precision Math:** Built-in modular exponentiation and Miller-Rabin primality testing to handle the massive integer mathematics required for secure cryptography.

---

## 🏗️ Codebase Architecture & Deep Dive

The backend is cleanly separated into specialized modules to handle web routing, database state, and complex mathematics independently.

### 1. `App.py` (The Core Server & API Gateway)
The main entry point built with Flask and SQLAlchemy. 
* **Database State Management:** * `User` Table: Stores finalized, fully registered accounts.
  * `PendingExchange` Table: A temporary holding cell for users currently attempting to pair a device.
* **Garbage Collection:** Every time the signup endpoint is hit, a subroutine purges any `PendingExchange` records older than 5 minutes to prevent database bloating and state hijacking.

### 2. `Totp.py` (The Authentication Engine)
This module implements the core RFC 6238 standard algorithm completely from scratch.
1. **Time Slicing:** Grabs the current UTC UNIX timestamp and divides it by 30 to create a distinct 30-second active window.
2. **HMAC-SHA1 Hashing:** Hashes the 30-second window against the user's secret digital key using `hmac.new()`.
3. **Dynamic Truncation:** Looks at the last byte of the hash to find an offset, then grabs a specific 4-byte chunk of the hash.
4. **Modulo Reduction:** Converts those 4 bytes into a massive integer, applies `& 0x7FFFFFFF` to drop the sign bit, and uses modulo `% 1000000` to squish it into a readable 6-digit code.

### 3. `Diffie_hellman.py` & `Math_Utils.py` (The Cryptography Suite)
* **Constants:** Initializes the global Prime (`P = 775145549137931`) and Generator (`G = 23`).
* **`mod_exp(base, exp, mod)`:** Because `(base^exp) % mod` would crash a computer when the exponent is a 64-bit number, this custom algorithm calculates the remainder iteratively, keeping memory usage microscopic.
* **`isPrime(n, k)`:** Implements the Miller-Rabin primality test for future-proofing dynamic prime generation.

---

## 📡 API Reference

While the web interface handles standard user interaction, the system exposes two primary APIs for the device handshake:

### `POST /signup/<code>`
The single-use endpoint for external device pairing.
* **Payload:** `{"bifrost-public-key": "<hex_encoded_string>"}`
* **Response (200):** `{"status": "success", "server-public-key": "<hex_encoded_string>"}`
* **Behavior:** Calculates the shared secret, commits the user to the permanent database, and immediately deletes this endpoint.

### `GET /api/status/<code>`
Used by the web frontend to check if a device has completed the pairing process.
* **Response (Pending):** `{"status": "pending"}`
* **Response (Success):** `{"status": "success"}` — Triggers a frontend redirect to the login page.

---

## 🚧 Challenges Faced & Engineering Solutions

**1. Replay Attacks on Key Exchanges**
* **The Threat:** Malicious actors could intercept the initial public key transmission and replay it later to force a rogue device pairing.
* **The Solution:** Implemented Ephemeral Endpoints (`PendingExchange`). The server performs an atomic database transaction that registers the user and *instantly deletes the route record*. Even if intercepted, the endpoint no longer exists a millisecond later.

**2. Asynchronous Frontend State Tracking**
* **The Challenge:** The Flask backend needed a way to tell the user's web browser that an external API request (the handshake from the C++ terminal) had successfully completed.
* **The Solution:** Built a lightweight HTTP polling mechanism. The `signup_waiting.html` page executes a JavaScript `setInterval` fetch request to `/api/status/<code>` every 2 seconds. The server checks the permanent database and safely redirects the user to login once the handshake clears.

**3. Handling Cryptographic Integer Overflows in Memory**
* **The Challenge:** Diffie-Hellman generates enormous integer values. Storing these directly as numbers in standard databases or attempting to convert them naively into binary byte-arrays for HMAC hashing leads to precision loss and system crashes.
* **The Solution:** The shared secret is stored universally as a `String(500)` inside the SQLite database. When processed by the TOTP engine, the string is explicitly cast to a big integer and packed into an 8-byte big-endian format (`byteorder="big"`) to guarantee exact bit-for-bit matching on every execution cycle.

---

## 🔮 Technical Debt & Future Scope
*(Note for production scaling)*
* **Password Hashing:** Currently, user passwords are stored in plain text to facilitate easy debugging of the cryptographic layers. In a production build, `App.py` should implement `werkzeug.security.generate_password_hash`.
* **HTTPS/TLS:** The Diffie-Hellman exchange prevents the *secret key* from being sniffed, but standard web traffic (passwords) requires a TLS certificate layer for full MITM protection.