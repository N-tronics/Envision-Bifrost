# Project Bifrost

A from-scratch two-factor authentication system built around a C++ hardware-style token generator and a Flask web portal. Bifrost pairs a local C++ client with a web server using a custom Diffie-Hellman key exchange, then uses the resulting shared secret to generate RFC 6238-compliant TOTP codes for login — no third-party authenticator libraries or OAuth providers involved.

## Features

- **Custom Diffie-Hellman key exchange** — Both the C++ client and the Python server implement modular exponentiation and shared-secret derivation from scratch (no external crypto library for the DH math itself).
- **RFC 6238 TOTP engine** — A from-scratch Time-based One-Time Password implementation using HMAC-SHA1, dynamic truncation, and 30-second time windows, implemented independently in both C++ (via OpenSSL's HMAC) and Python.
- **Miller-Rabin primality testing** — Custom arbitrary-precision prime generation and primality checking, used to support the underlying DH math.
- **One-time pairing codes** — Signup generates a single-use 6-digit exchange code. The corresponding server endpoint is deleted immediately after use, so intercepted codes can't be replayed.
- **Live pairing status via polling** — The signup page polls the server every 2 seconds while waiting for the C++ client to complete the key exchange, then redirects automatically once pairing succeeds.
- **Simple web UI** — Minimal Flask + Jinja2 templates for account creation, login, and TOTP verification, backed by SQLite via SQLAlchemy.

## How It Works

1. **Sign up** on the web portal with a username and password. The server generates a temporary Diffie-Hellman keypair and displays a 6-digit exchange code.
2. **Run the Bifrost C++ client** and enter that exchange code when prompted. The client generates its own DH keypair and POSTs its public key to the server's `/signup/<code>` endpoint.
3. The server computes the shared secret, finalizes the account, and deletes the temporary pairing endpoint. The client independently computes the same shared secret locally.
4. On future logins, the client reads its saved secret from `shared_secret.txt` and prints a 6-digit TOTP code. The user enters that code on the site's verification page, which is checked against the value the server computes from the same shared secret.

## Project Structure

```
envision-bifrost
├── bifrost/            # C++ client — key exchange + TOTP generator
│   ├── CMakeLists.txt
│   ├── include/
│   └── src/
└── login-server/       # Flask web portal + API
    ├── App.py
    ├── Diffie_hellman.py
    ├── Math_Utils.py
    ├── Totp.py
    └── templates/
```

## Installation

### Prerequisites

- CMake 3.10+ and a C++17 compiler
- OpenSSL development headers (`libssl-dev` on Debian/Ubuntu, or the OpenSSL package on your distro)
- [Boost.Multiprecision](https://www.boost.org/doc/libs/release/libs/multiprecision/) (used for the arbitrary-precision integer type in the DH math) — install via your system package manager (e.g. `libboost-dev`)
- Python 3.9+ and `pip`

`nlohmann/json` and `cpr` are fetched automatically by CMake via `FetchContent`, so you don't need to install them manually.

### Building the C++ client

```bash
cd bifrost
mkdir build && cd build
cmake ..
cmake --build .
```

This produces a `Bifrost` executable in the build directory.

### Setting up the login server

```bash
cd login-server
pip install flask flask_sqlalchemy
python App.py
```

The server starts on `http://localhost:5000` and creates a local SQLite database (`bifrost.db`) on first run.

> **Note:** The C++ client currently posts to a hardcoded URL of `http://localhost:5000/signup/`. If you run the server on a different host or port, update `SERVER_URL` in `bifrost/src/Bifrost.cpp` before building.

## Usage

1. Start the login server (`python App.py`) and visit `http://localhost:5000` in your browser.
2. Click **Create Account**, choose a username and password, and note the 6-digit exchange code shown on the waiting screen.
3. In a terminal, run the Bifrost client:
   ```bash
   ./Bifrost
   ```
4. When prompted, enter the 6-digit exchange code from the browser. The client and server complete the key exchange, and the browser redirects to the login page automatically.
5. Log in on the web portal with your username and password.
6. Run `./Bifrost` again — this time it will detect the saved `shared_secret.txt`, skip pairing, and print a 6-digit TOTP code with a countdown.
7. Enter that code on the verification page to complete login.

## Configuration

There's no dedicated config file yet; the following values are set directly in source and can be changed if needed:

| Setting | Location | Default |
|---|---|---|
| Server URL used by the client | `bifrost/src/Bifrost.cpp` (`SERVER_URL`) | `http://localhost:5000/signup/` |
| Local shared-secret file | `bifrost/src/Bifrost.cpp` (`SECRET_KEY_FILE`) | `shared_secret.txt` |
| Flask session secret key | `login-server/App.py` (`app.secret_key`) | hardcoded placeholder — change before any real deployment |
| Server host/port | `login-server/App.py` (`app.run(...)`) | `0.0.0.0:5000`, debug mode on |
| DH prime/generator | Shared between `bifrost/src/Diffie-Hellman.cpp` and `login-server/Diffie_hellman.py` | `P = 775145549137931`, `G = 23` |
| SQLite database path | `login-server/App.py` (`SQLALCHEMY_DATABASE_URI`) | `sqlite:///bifrost.db` |

## Testing

There is no automated test suite in the repository yet. To manually verify a working setup:

1. Confirm the C++ client builds cleanly with `cmake --build .` and no errors.
2. Run through the full pairing flow described in **Usage** end-to-end, confirming the exchange code accepted by the client matches the one shown by the server.
3. Confirm `shared_secret.txt` is created after a successful pairing, and that re-running the client produces a valid TOTP code without prompting for a new exchange code.
4. Confirm that the code printed by the client is accepted on the `/verify-totp` page within the same 30-second window, and rejected once expired.

## Known Limitations

This project was built for learning and demonstration purposes, and there are a few things worth knowing before using it beyond that:

- **Passwords are stored in plain text** in the database. A production build should hash them (e.g. with `werkzeug.security.generate_password_hash`).
- **No TLS/HTTPS** — the Diffie-Hellman exchange protects the derived shared secret, but login credentials are otherwise sent over plain HTTP.
- **Custom DH parameters are small** relative to production-grade key exchange (the modulus is a fixed value hardcoded in source, not dynamically generated for each deployment).
- **Flask's `secret_key`** is a hardcoded placeholder string and should be replaced with a securely generated value for any real deployment.

## Acknowledgements

- [nlohmann/json](https://github.com/nlohmann/json) — JSON handling in the C++ client
- [libcpr/cpr](https://github.com/libcpr/cpr) — C++ HTTP requests library
- [Boost.Multiprecision](https://www.boost.org/doc/libs/release/libs/multiprecision/) — arbitrary-precision integer arithmetic
- [OpenSSL](https://www.openssl.org/) — HMAC-SHA1 implementation
- [Flask](https://flask.palletsprojects.com/) and [Flask-SQLAlchemy](https://flask-sqlalchemy.palletsprojects.com/) — web server and ORM
- Built as part of the IEEE NITK Envision mentorship program
