# Project Bifrost


# Bifrost – Two-Factor Authentication System

Bifrost is a secure Two-Factor Authentication (2FA) system built in C++ that combines Diffie–Hellman key exchange, HMAC-SHA1, and Time-based One-Time Passwords (TOTP) to provide secure user authentication.

The project demonstrates how modern authentication systems securely generate and verify OTPs without transmitting secret keys over the network.


## Features

- Secure key exchange using Diffie–Hellman
- Time-based OTP generation (TOTP)
- HMAC-SHA1 based authentication
- REST API communication using CPR
- JSON handling with nlohmann/json
- Modular C++ project structure
- CMake build support
- OpenSSL cryptographic integration


## How It Works

### 1. Diffie–Hellman Key Exchange

The client and server generate public-private key pairs and exchange public keys over the network.

Using the exchanged public keys:

- Client computes a shared secret
- Server computes the same shared secret independently

This shared secret is never transmitted directly, making the communication secure.


### 2. Secret Key Generation

The shared secret is processed and resized into a secure key suitable for HMAC operations.

This key is stored securely on both client and server sides.

### 3. TOTP Generation

The current Unix timestamp is divided into fixed time intervals (typically 30 seconds).

```text
T = floor(Current Unix Time / 30)
```

The resulting timestep value is used as the message input for HMAC-SHA1.


### 4. HMAC-SHA1 Computation

The secret key and timestep are passed into the HMAC-SHA1 algorithm.

```text
OTP = HMAC_SHA1(secret_key, timestep)
```

The generated hash is dynamically truncated to produce a numeric One-Time Password.


### 5. OTP Verification

The server independently generates the OTP using the stored secret key and current timestep.

If both OTPs match, authentication succeeds.


## Technologies Used

- C++17
- OpenSSL
- Boost Multiprecision
- CPR (HTTP Requests)
- nlohmann/json
- CMake

## Example Workflow

```text
Client ── Public Key ──► Server
Client ◄─ Public Key ── Server

Both compute shared secret

Shared Secret → HMAC-SHA1 → TOTP

User enters OTP

Server verifies OTP
```


## License

This project is intended for educational and research purposes.

