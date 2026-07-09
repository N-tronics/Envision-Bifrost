Project Path: envision-bifrost

I'd like you to generate a high-quality README file for this project, suitable for hosting on GitHub. Analyze the codebase to understand the purpose, functionality, and structure of the project. 

Source Tree:
```
envision-bifrost
├── README.md
├── bifrost
│   ├── CMakeLists.txt
│   ├── README.md
│   ├── include
│   │   ├── DiffieHellman.hpp
│   │   ├── HMAC_SHA1.hpp
│   │   ├── random.hpp
│   │   ├── typedefs.hpp
│   │   └── utilities.hpp
│   └── src
│       ├── Bifrost.cpp
│       ├── Diffie-Hellman.cpp
│       ├── HMAC-SHA1.cpp
│       ├── random.cpp
│       └── utilities.cpp
├── login-server
│   ├── App.py
│   ├── Diffie_hellman.py
│   ├── Math_Utils.py
│   ├── README.md
│   ├── Totp.py
│   └── templates
│       ├── index.html
│       ├── login.html
│       ├── signup.html
│       ├── signup_waiting.html
│       └── verify_totp.html
└── prompt.md

```

`README.md`:

# Project Bifrost


`bifrost/CMakeLists.txt`:

cmake_minimum_required(VERSION 3.10)
project(Bifrost)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
find_package(OpenSSL REQUIRED)
# 3. Find Dependencies
# Finds OpenSSL on Arch Linux (provided by libssl-dev/openssl)
find_package(OpenSSL REQUIRED)

include(FetchContent)
FetchContent_Declare(
    json
    GIT_REPOSITORY https://github.com/nlohmann/json.git
    GIT_TAG v3.11.3
)
FetchContent_MakeAvailable(json)

# Fetch CPR (C++ Requests)
FetchContent_Declare(
    cpr
    GIT_REPOSITORY https://github.com/libcpr/cpr.git
    GIT_TAG 1.10.5 # Or stable release of your choice
)
# Disable CPR's internal tests and PDF generation to keep build times fast
set(CPR_BUILD_TESTS OFF CACHE INTERNAL "")
FetchContent_MakeAvailable(cpr)

file (GLOB SOURCES "src/*.cpp")

add_executable(${PROJECT_NAME} ${SOURCES})

target_include_directories(${PROJECT_NAME} PRIVATE
    include
    ${OPENSSL_INLCUDE_DIR}
)
target_link_libraries(${PROJECT_NAME} PRIVATE OpenSSL::Crypto cpr::cpr nlohmann_json::nlohmann_json)



`bifrost/README.md`:

# Project Bifrost


`bifrost/include/DiffieHellman.hpp`:

#pragma once
#include "typedefs.hpp"

#include <boost/multiprecision/cpp_int.hpp>

using namespace boost::multiprecision;
extern cpp_int prime;
extern cpp_int generator;
constexpr int nBytes = 8;
class Diffie_Hellman {
    private:
        cpp_int private_key;

    public:
        cpp_int public_key;

        Diffie_Hellman();

        cpp_int mod_exp(cpp_int base, cpp_int exp, cpp_int mod);
        cpp_int generate_public_key();
        Bytes compute_shared_secret(const Bytes &other_public_key);
};


`bifrost/include/HMAC_SHA1.hpp`:

#pragma once

#include "typedefs.hpp"

Bytes hmac_sha1(const Bytes& key,const Bytes& message);

`bifrost/include/random.hpp`:

#pragma once
#include <utilities.hpp> // Includes your types (vector<uint8_t>, cpp_int) and functions

class Random {
    public:
        // Generates a vector of random bytes
        static Bytes generateRandomBytes(size_t num_bytes);

        // Generates a random arbitrary precision integer by generating bytes
        // first!
        static cpp_int generateRandomNumber(unsigned int bits);

        // Generates a large prime number of a specific bit size
        static cpp_int generateLargePrime(unsigned int bits);

    private:
        static cpp_int power_mod(cpp_int base, cpp_int exp, cpp_int mod);
        static bool miller_rabin(cpp_int n, int k = 40);
};


`bifrost/include/typedefs.hpp`:

#pragma once

#include <vector>
#include <cstdint>

using Byte = uint8_t;
using Bytes = std::vector<Byte>;

`bifrost/include/utilities.hpp`:

#ifndef UTILITIES_HPP
#define UTILITIES_HPP

#include <string>
#include <typedefs.hpp>

#include <boost/multiprecision/cpp_int.hpp>

using namespace std;
using namespace boost::multiprecision;

// cpp_int -> bytes
Bytes cppIntToBytes(const cpp_int &num);

// bytes -> cpp_int
cpp_int bytesToCppInt(const Bytes &bytes);

// bytes -> hex
string bytesToHex(const Bytes &bytes);

// hex -> bytes
Bytes hexToBytes(const string &hex);

// cpp_int -> hex string
string cppIntToHex(const cpp_int &num);

// hex -> cpp_int
cpp_int hexToCppInt(const string &hex);

// print bytes
void printBytes(const Bytes &bytes);

// Resize a given key
Bytes resizeKey(const Bytes &key, const int nBytes);

#endif


`bifrost/src/Bifrost.cpp`:

#include <DiffieHellman.hpp>
#include <HMAC_SHA1.hpp>
#include <random.hpp>
#include <typedefs.hpp>
#include <utilities.hpp>

#include <ctime>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>

#include <cpr/cpr.h>
#include <nlohmann/json.hpp>

using namespace std;
using json = nlohmann::json;
namespace fs = std::filesystem;

#define SERVER_URL "http://localhost:5000/signup/"
#define SECRET_KEY_FILE "shared_secret.txt"

string generateTOTP(Bytes key) {
    // TOTP
    time_t timestamp = time(NULL);

    cpp_int timestep = timestamp / 30;

    Bytes message = resizeKey(cppIntToBytes(timestep), nBytes);

    Bytes hmac_bytes = hmac_sha1(key, message);

    int offset = hmac_bytes[hmac_bytes.size() - 1] & 0x0F;

    Bytes sample_bytes;

    for (int i = offset; i < offset + 4; i++) {
        sample_bytes.push_back(hmac_bytes[i]);
    }

    sample_bytes[0] &= 0x7f;

    cpp_int sample = bytesToCppInt(sample_bytes);

    int OTP = (sample % 1000000).convert_to<int>();

    string otp_string = to_string(OTP);

    while (otp_string.length() < 6) {
        otp_string = "0" + otp_string;
    }

    return otp_string;
}

Bytes exchangeSecret(string registrationCode) {
    Diffie_Hellman bifrostDH;

    string bifrostPublicKeyHex = cppIntToHex(bifrostDH.public_key);

    json requestBody;

    requestBody["bifrost-public-key"] = bifrostPublicKeyHex;

    string url = SERVER_URL + registrationCode;

    cout << "\nSending POST request to:\n";
    cout << url << endl;

    cout << "\nBifrost public key:\n";
    cout << bifrostPublicKeyHex << endl;

    cpr::Response response =
        cpr::Post(cpr::Url{url}, cpr::Body{requestBody.dump()},
                  cpr::Header{{"Content-Type", "application/json"}});

    if (response.error) {
        throw runtime_error(response.error.message);
    }

    if (response.status_code != 200) {
        cout << "\nServer response:\n";
        cout << response.text << endl;

        throw runtime_error("Server returned status code " +
                            to_string(response.status_code));
    }

    json responseJson = json::parse(response.text);

    if (!responseJson.contains("server-public-key")) {
        throw runtime_error(
            "Response JSON does not contain server-public-key.");
    }

    Bytes serverPublicKey = hexToBytes(responseJson["server-public-key"]);
    Bytes sharedSecretKey =
        resizeKey(bifrostDH.compute_shared_secret(serverPublicKey), nBytes);

    cout << "\nBifrost public key:\n" << bifrostPublicKeyHex << endl;
    cout << "\nServer public key:\n" << bytesToHex(serverPublicKey) << endl;
    cout << "\nShared Secret key:\n" << bytesToHex(sharedSecretKey) << endl;
    return sharedSecretKey;
}

int main() {
    Bytes sharedSecretKey;

    if (fs::exists(SECRET_KEY_FILE)) {
        ifstream saved_file(SECRET_KEY_FILE);
        if (!saved_file) {
            throw runtime_error("couldn't open shared_secret.txt");
        }
        string loaded_secret;
        getline(saved_file, loaded_secret);
        saved_file.close();
        sharedSecretKey = resizeKey(hexToBytes(loaded_secret), nBytes);
    } else {
        try {
            string registrationCode;

            cout << "Enter 6-digit registration code: ";
            cin >> registrationCode;

            if (registrationCode.length() != 6) {
                throw runtime_error("Registration code must be 6 digits.");
            }

            Bytes sharedSecretKey = exchangeSecret(registrationCode);
            string sharedSecret_hex = bytesToHex(sharedSecretKey);

            ofstream file("shared_secret.txt");
            if (!file) {
                throw runtime_error("Could not create shared_secret.txt");
            }
            file << bytesToHex(sharedSecretKey);
            file.close();
            cout << "\nShared secret saved in shared_secret.txt" << endl;
        } catch (const exception &e) {
            cerr << "\nError: " << e.what() << endl;
            return 1;
        }
    }

    string otp = generateTOTP(sharedSecretKey);
    cout << "\nGenerated OTP: " << otp << endl;
    int timeLeft = 30 - (time(NULL) % 30);
    cout << "Valid for: " << timeLeft << "s" << endl;

    return 0;
}


`bifrost/src/Diffie-Hellman.cpp`:

#include <DiffieHellman.hpp>
#include <HMAC_SHA1.hpp>
#include <random.hpp>
#include <utilities.hpp>

cpp_int prime = 775145549137931;
cpp_int generator = 23;

Diffie_Hellman::Diffie_Hellman() {
    private_key = Random::generateRandomNumber(30);
    public_key = generate_public_key();
}
cpp_int Diffie_Hellman::mod_exp(cpp_int base, cpp_int exp, cpp_int mod) {
    cpp_int ans = 1;
    while (exp != 0) {
        if (exp & 1) {
            ans = (ans * base) % mod;
        }
        base = (base * base) % mod;
        exp /= 2; // similar to right shift
    }
    return ans;
}
cpp_int Diffie_Hellman::generate_public_key() {
    return mod_exp(generator, private_key, prime);
}
Bytes Diffie_Hellman::compute_shared_secret(const Bytes &other_public_key) {
    cpp_int keyInt =
        mod_exp(bytesToCppInt(other_public_key), private_key, prime);
    return cppIntToBytes(keyInt);
}


`bifrost/src/HMAC-SHA1.cpp`:

#include <HMAC_SHA1.hpp>

#include <openssl/evp.h>
#include <openssl/hmac.h>

Bytes hmac_sha1(const Bytes &key, const Bytes &message) {
    unsigned int len;

    unsigned char digest[EVP_MAX_MD_SIZE];

    HMAC(EVP_sha1(), // hash function
         key.data(), //.data fn returns pointer to first member of key vector
         key.size(), message.data(), message.size(),
         digest, // array where output is stored
         &len    // HMAC fn rewrites size of output in len according to hash
              // function used
    );

    return Bytes(digest, digest + len); // copy elements of array to vector
}


`bifrost/src/random.cpp`:

#include <ctime>
#include <random.hpp>
#include <random>

// ---------------------------------------------------------
// Byte Generation
// ---------------------------------------------------------
vector<uint8_t> Random::generateRandomBytes(size_t num_bytes) {
    vector<uint8_t> buffer(num_bytes);

    static std::mt19937 gen(std::time(nullptr));
    std::uniform_int_distribution<uint8_t> dist(0, 255);

    for (size_t i = 0; i < num_bytes; ++i) {
        buffer[i] = dist(gen);
    }

    return buffer;
}

// ---------------------------------------------------------
// Large Number / Prime Generation
// ---------------------------------------------------------
cpp_int Random::generateRandomNumber(unsigned int bits) {
    // 1. Calculate how many bytes are needed for the given bit size
    size_t num_bytes = (bits + 7) / 8;

    // 2. Generate random raw bytes
    vector<uint8_t> bytes = generateRandomBytes(num_bytes);

    // 3. Convert the bytes into a cpp_int using YOUR utility function!
    cpp_int num = bytesToCppInt(bytes);

    // 4. Ensure it doesn't exceed the exact bit boundary by masking
    return num % (cpp_int(1) << bits);
}

cpp_int Random::generateLargePrime(unsigned int bits) {
    cpp_int candidate;
    while (true) {
        candidate = generateRandomNumber(bits);

        // Ensure odd
        if (candidate % 2 == 0)
            candidate++;

        if (miller_rabin(candidate)) {
            return candidate;
        }
    }
}

// ---------------------------------------------------------
// Private Mathematical Helpers
// ---------------------------------------------------------
cpp_int Random::power_mod(cpp_int base, cpp_int exp, cpp_int mod) {
    cpp_int result = 1;
    base = base % mod;

    while (exp > 0) {
        if (exp % 2 == 1) {
            result = (result * base) % mod;
        }
        exp = exp >> 1;
        base = (base * base) % mod;
    }
    return result;
}

bool Random::miller_rabin(cpp_int n, int k) {
    if (n <= 1 || n == 4)
        return false;
    if (n <= 3)
        return true;
    if (n % 2 == 0)
        return false;

    cpp_int d = n - 1;
    int r = 0;
    while (d % 2 == 0) {
        d /= 2;
        r++;
    }

    for (int i = 0; i < k; i++) {
        cpp_int a = 2 + (generateRandomNumber(256) % (n - 4));
        cpp_int x = power_mod(a, d, n);

        if (x == 1 || x == n - 1)
            continue;

        bool composite = true;
        for (int j = 1; j < r; j++) {
            x = power_mod(x, 2, n);
            if (x == n - 1) {
                composite = false;
                break;
            }
        }
        if (composite)
            return false;
    }
    return true;
}


`bifrost/src/utilities.cpp`:

#include <utilities.hpp>

// =======================================
// cpp_int -> bytes
// =======================================

Bytes cppIntToBytes(const cpp_int &num) {
    Bytes bytes;
    cpp_int n = num;

    while (n > 0) {
        uint8_t byte = static_cast<uint8_t>(n & 0xFF);

        bytes.insert(bytes.begin(), byte);

        n >>= 8;
    }

    return bytes;
}

// =======================================
// bytes -> cpp_int
// =======================================

cpp_int bytesToCppInt(const Bytes &bytes) {
    cpp_int num = 0;

    for (uint8_t byte : bytes) {
        num <<= 8;

        num += byte;
    }

    return num;
}

// =======================================
// bytes -> hex
// =======================================

string bytesToHex(const Bytes &bytes) {
    const char *hexChars = "0123456789ABCDEF";

    string hex;

    for (uint8_t byte : bytes) {
        hex += hexChars[(byte >> 4) & 0x0F];

        hex += hexChars[byte & 0x0F];
    }

    return hex;
}

// =======================================
// hex -> bytes
// =======================================

Bytes hexToBytes(const string &hex) {
    auto hexStr = hex;
    if (hex.length() % 2)
        hexStr = "0" + hex;
    Bytes bytes;

    for (size_t i = 0; i < hexStr.length(); i += 2) {
        string part = hexStr.substr(i, 2);

        uint8_t byte = static_cast<uint8_t>(strtol(part.c_str(), nullptr, 16));

        bytes.push_back(byte);
    }

    return bytes;
}

// =======================================
// cpp_int -> hex
// =======================================

string cppIntToHex(const cpp_int &num) {
    if (num == 0)
        return "0";
    cpp_int n = num;

    const char *hexChars = "0123456789ABCDEF";

    string hex;

    while (n > 0) {
        int digit = static_cast<int>(n & 0xF);

        hex = hexChars[digit] + hex;

        n >>= 4;
    }

    return hex;
}

// =======================================
// hex -> cpp_int
// =======================================

cpp_int hexToCppInt(const string &hex) {
    cpp_int num = 0;

    for (char c : hex) {
        num <<= 4;

        if (c >= '0' && c <= '9')
            num += c - '0';

        else if (c >= 'A' && c <= 'F')
            num += c - 'A' + 10;

        else if (c >= 'a' && c <= 'f')
            num += c - 'a' + 10;
    }

    return num;
}

// =======================================
// print bytes
// =======================================

void printBytes(const Bytes &bytes) {
    for (uint8_t byte : bytes) {
        printf("%02X ", byte);
    }

    cout << endl;
}

// =======================================
// print bytes
// =======================================

Bytes resizeKey(const Bytes &key, const int nBytes) {
    if (key.size() >= nBytes) { // when key size is bigger than required
        return Bytes(key.end() - nBytes, key.end());
    }
    Bytes padded(nBytes,
                 0); // when key size is smaller than required-> front padding
    int start = nBytes - key.size();
    for (auto i = 0; i < key.size(); i++)
        padded[i + start] = key[i];
    return padded;
}


`login-server/App.py`:

import secrets
from datetime import datetime, timedelta

from flask import (
    Flask,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from flask_sqlalchemy import SQLAlchemy

import Diffie_hellman as dh
import Totp as totp

app = Flask(__name__)
app.secret_key = "super_secure_bifrost_key"

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///bifrost.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)


# --- DATABASE MODELS ---
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    shared_secret = db.Column(db.String(500), nullable=False)


class PendingExchange(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    alice_private = db.Column(db.String(500), nullable=False)
    alice_public = db.Column(db.String(500), nullable=False)
    exchange_code = db.Column(db.String(6), unique=True, nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)


with app.app_context():
    db.create_all()


def to_hex_be(num):
    return hex(int(num))[2:]


def from_hex_be(hex_str):
    return int(hex_str, 16)


@app.route("/")
def home():
    if "user" in session:
        return render_template("index.html", user=session["user"])
    return render_template("index.html", user=None)


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        # Check if user already exists
        if User.query.filter_by(username=username).first():
            flash("Username already exists. Please choose a different one.", "danger")
            return redirect(url_for("signup"))

        # Clean up any existing pending exchanges for this user (Only 1 allowed)
        PendingExchange.query.filter_by(username=username).delete()

        # Generate Alice's Keys and a 6-digit endpoint code
        alice_private, alice_public = dh.generate_keys()
        exchange_code = str(secrets.randbelow(1000000)).zfill(6)

        # Store in pending database, expires in 5 minutes
        pending = PendingExchange(
            username=username,
            password=password,
            alice_private=str(alice_private),
            alice_public=str(alice_public),
            exchange_code=exchange_code,
            expires_at=datetime.utcnow() + timedelta(minutes=5),
        )
        db.session.add(pending)
        db.session.commit()

        # Save username in session so the browser knows who to poll for
        session["pending_username"] = username

        # Render the waiting screen with the code
        return render_template("signup_waiting.html", exchange_code=exchange_code)

    return render_template("signup.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.args.get("success") == "1":
        flash("Exchange Successful! Please log in.", "success")

    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        user = User.query.filter_by(username=username, password=password).first()
        if user:
            session["pending_user"] = username
            return redirect(url_for("verify_totp"))

        flash("Invalid username or password. Please try again.", "danger")
        return redirect(url_for("login"))

    return render_template("login.html")


@app.route("/verify-totp", methods=["GET", "POST"])
def verify_totp():
    if "pending_user" not in session:
        return redirect(url_for("login"))

    if request.method == "POST":
        user_otp = request.form.get("otp")
        username = session["pending_user"]

        user = User.query.filter_by(username=username).first()
        expected_otp = totp.generate_totp(user.shared_secret)

        print(f"Expected OTP: {expected_otp}")

        if user_otp == expected_otp:
            session["user"] = session.pop("pending_user")
            return redirect(url_for("home"))

        flash("Invalid TOTP code. Please check your Bifrost and try again.", "danger")
        return redirect(url_for("verify_totp"))

    return render_template("verify_totp.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))


@app.route("/signup/<code>", methods=["POST"])
def bifrost_exchange(code):
    # Clean up globally expired endpoints to keep DB clean
    PendingExchange.query.filter(
        PendingExchange.expires_at < datetime.utcnow()
    ).delete()
    db.session.commit()

    # Look for the specific code
    pending = PendingExchange.query.filter_by(exchange_code=code).first()

    if not pending:
        return jsonify(
            {"status": "fail", "error": "Endpoint does not exist or has expired"}
        ), 404

    data = request.get_json()
    if not data or "bifrost-public-key" not in data:
        return jsonify({"status": "fail", "error": "Missing bifrost-public-key"}), 400

    try:
        # Perform the DH Math using Big-Endian Hex conversion
        bob_public = from_hex_be(data["bifrost-public-key"])
        alice_private = int(pending.alice_private)

        shared_secret = dh.compute_shared_secret(bob_public, alice_private, dh.P)

        # Save the finalized user to the permanent database
        new_user = User(
            username=pending.username,
            password=pending.password,
            shared_secret=str(shared_secret),
        )
        db.session.add(new_user)

        # Destroy the temporary endpoint
        db.session.delete(pending)
        db.session.commit()

        print(f"bifrost public key: {to_hex_be(bob_public)}")
        print(f"server public key: {to_hex_be(pending.alice_public)}")
        print(f"shared secret: {hex(shared_secret)}")

        return jsonify(
            {"server-public-key": to_hex_be(pending.alice_public), "status": "success"}
        )

    except Exception as e:
        return jsonify({"status": "fail", "error": str(e)}), 500


@app.route("/api/status/<code>", methods=["GET"])
def check_status(code):
    username = session.get("pending_username")
    if not username:
        return jsonify({"status": "error"})

    # If the user is in the main DB, the exchange succeeded
    if User.query.filter_by(username=username).first():
        session.pop("pending_username", None)
        return jsonify({"status": "success"})

    # Check if the pending endpoint still exists and hasn't expired
    pending = PendingExchange.query.filter_by(exchange_code=code).first()
    if pending and pending.expires_at > datetime.utcnow():
        return jsonify({"status": "waiting"})

    return jsonify({"status": "expired"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)



`login-server/Diffie_hellman.py`:

import secrets
import Math_Utils

P = 775145549137931
G = 23

def generate_keys():
    my_private_key = secrets.randbits(64) % (P - 2) + 2
    my_public_key = Math_Utils.mod_exp(G, my_private_key, P)
    return my_private_key, my_public_key

def compute_shared_secret(other_persons_public_key, my_private_key, modulus):
    final_shared_secret = Math_Utils.mod_exp(other_persons_public_key, my_private_key, modulus)
    return final_shared_secret

`login-server/Math_Utils.py`:

import secrets
import random

def mod_exp(base, exp, mod):
    result = 1
    base = base % mod
    while exp>0:
        if(exp%2==1):
            result = (result*base)%mod
        exp = exp//2
        base = (base*base)%mod
    return result

def random_odd_integer(bitlength):
    num = secrets.randbits(bitlength)
    num = num|1
    return num

def isPrime(n,k=40):
    if(n<=1):
        return False
    if(n<=3):
        return True
    if(n%2==0):
        return False
    r = 0
    oddpart= n-1
    while(oddpart%2==0):
        oddpart = oddpart//2
        r = r+1
    for i in range(k):
        a = random.randint(2,n-2)
        x = mod_exp(a, oddpart, n)
        if(x==1 or x==n-1): #initial check
            continue
        passed = False
        temp_d = oddpart
        while temp_d != n - 1:
            x = (x * x) % n
            temp_d = temp_d * 2

            if x == 1:
                return False
            if x == n - 1:
                passed = True
                break
        
        if passed == False:
            return False
            
    return True

def generate_prime(bit_length):
    candidate = 0
    prime_found = False
    while prime_found == False:
        candidate = random_odd_integer(bit_length)
        if isPrime(candidate)==True:
            prime_found = True
    return candidate

`login-server/README.md`:

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

`login-server/Totp.py`:

import hashlib
import hmac
import struct
import time


def generate_totp(shared_secret):
    # --- STEP 1: PREPARE THE SECRET ---
    digital_key = int(shared_secret).to_bytes(8, byteorder="big")

    # --- STEP 2: CHECK THE CLOCK ---
    current_seconds = time.time()
    thirty_second_window = int(current_seconds / 30)

    time_message = struct.pack(">Q", thirty_second_window)

    # --- STEP 3: THE DIGITAL BLENDER (HMAC) ---
    hash_result = hmac.new(digital_key, time_message, hashlib.sha1).digest()

    # --- STEP 4: PICKING THE NUMBERS ---
    start_position = hash_result[-1] & 0x0F

    # We grab 4 bytes of data starting from that position.
    grabbed_data = hash_result[start_position : start_position + 4]

    # Turn those 4 bytes into a single big whole number.
    big_number = struct.unpack(">I", grabbed_data)[0] & 0x7FFFFFFF

    # --- STEP 5: THE 6-DIGIT SQUISH ---
    six_digit_code = big_number % 1000000

    return str(six_digit_code).zfill(6)


# --- QUICK TEST AREA ---
if __name__ == "__main__":
    test_secret = "my_super_secret_key"
    print(f"Your 6-digit code for right now is: {generate_totp(test_secret)}")
    print("Wait 30 seconds and run it again to see it change!")


`login-server/templates/index.html`:

<!DOCTYPE html>
<html lang="en">
<head>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Bifrost | Home</title>
    
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&display=swap" rel="stylesheet">
    
    <style>
        :root {
            --primary: #3b82f6;      
            --bg-color: #f8fafc;    
            --text-main: #1e293b;  
        }
        body {    
            font-family: 'Inter', sans-serif; 
            background: var(--bg-color);
            display: flex; 
            justify-content: center; 
            align-items: center;
            min-height: 100vh; 
            margin: 0; 
            color: var(--text-main);
        }
        .card { 
            background: white; 
            padding: 50px; 
            border-radius: 24px; 
            box-shadow: 0 10px 25px rgba(0,0,0,0.05); 
            width: 100%; 
            max-width: 500px; 
            text-align: center;
        }
        .btn-group { margin-top: 30px; display: flex; gap: 15px; justify-content: center; }
        .btn {
            padding: 12px 24px; border-radius: 10px; text-decoration: none;
            font-weight: 600; font-size: 14px; transition: 0.2s;
        }
        .btn-primary { 
            background: var(--primary); 
            color: white; 
        }
        .btn-outline { 
            border: 1px solid #e2e8f0; 
            color: #64748b; 
        }
        .btn:hover { opacity: 0.9; transform: translateY(-1px); }

        .alert {
            padding: 12px; margin-bottom: 20px; border-radius: 8px;
            font-size: 14px; font-weight: 500;
        }
        .alert-success {
            background-color: #dcfce7; color: #166534; border: 1px solid #bbf7d0;
        }
    </style>
</head>
<body>

    <div class="card">
        
        <div style="color: var(--primary); font-weight: 700; letter-spacing: 2px; margin-bottom: 20px;">BIFROST</div>
        
        
        {% with messages = get_flashed_messages(with_categories=true) %}
          {% if messages %}
            {% for category, message in messages %}
              <div class="alert alert-{{ category }}">
                {{ message }}
              </div>
            {% endfor %}
          {% endif %}
        {% endwith %}


        {% if user %}
            <h1>Welcome Back, {{ user }}</h1>
            <p>Your secure terminal is active and ready.</p>
            <div class="btn-group">
                <a href="/logout" class="btn btn-outline">Sign Out</a>
            </div>
            
        {% else %}
            <h1>Secure Communication</h1>
            <p>Implement RFC 6238 TOTP and Diffie-Hellman exchanges seamlessly.</p>
            <div class="btn-group">
                <a href="/login" class="btn btn-primary">Login to Terminal</a>
                <a href="/signup" class="btn btn-outline">Create Account</a>
            </div>
        {% endif %}
        </div>
</body>
</html>

`login-server/templates/login.html`:

<!DOCTYPE html>
<html lang="en">
<head>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Bifrost | Login</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&display=swap" rel="stylesheet">
    <style>
        :root { 
            --primary: #3b82f6; 
            --bg-color: #f8fafc; 
            --text-main: #1e293b; 
        }
        body { 
            font-family: 'Inter', sans-serif; 
            background: var(--bg-color); 
            display: flex; 
            justify-content: center; 
            align-items: center; 
            min-height: 100vh;
            margin: 0; 
            color: var(--text-main); 
        }
        .card { 
            background: white; 
            padding: 50px; 
            border-radius: 24px; 
            box-shadow: 0 10px 25px rgba(0,0,0,0.05); 
            width: 100%; 
            max-width: 400px; 
            text-align: center; 
        }
        .btn-primary { 
            background: var(--primary); 
            color: white; 
            padding: 12px 24px; 
            border-radius: 10px; 
            font-weight: 600; 
            font-size: 14px; 
            transition: 0.2s; 
            width: 100%; 
            border: none; 
            cursor: pointer; 
        }
        .btn-primary:hover { 
            opacity: 0.9; 
            transform: translateY(-1px); 
        }
        .alert { padding: 12px; margin-bottom: 20px; border-radius: 8px; font-size: 14px; font-weight: 500; }
        .alert-success { background-color: #dcfce7; color: #166534; border: 1px solid #bbf7d0; }
        .alert-danger { background-color: #fee2e2; color: #991b1b; border: 1px solid #fecaca; }
    </style>
</head>
<body>
    <div class="card">
        <div style="color: var(--primary); font-weight: 700; letter-spacing: 2px; margin-bottom: 20px;">BIFROST</div>
        
        {% with messages = get_flashed_messages(with_categories=true) %}
          {% if messages %}
            {% for category, message in messages %}
              <div class="alert alert-{{ category }}">{{ message }}</div>
            {% endfor %}
          {% endif %}
        {% endwith %}

        <h1 style="font-size: 24px; margin-bottom: 10px;">System Login</h1>
        <p style="color: #64748b; font-size: 14px; margin-bottom: 30px;">Enter your credentials to access the 2FA portal.</p>

        <form action="/login" method="POST">
            <input type="text" name="username" placeholder="Username" required style="width: 100%; padding: 12px; margin-bottom: 15px; border-radius: 8px; border: 1px solid #e2e8f0; box-sizing: border-box;">
            <input type="password" name="password" placeholder="Password" required style="width: 100%; padding: 12px; margin-bottom: 20px; border-radius: 8px; border: 1px solid #e2e8f0; box-sizing: border-box;">
            <button type="submit" class="btn-primary">Authenticate</button>
        </form>

        <div style="margin-top: 20px; font-size: 14px;">
            <a href="/" style="color: #64748b; text-decoration: none;">&larr; Back to Home</a>
        </div>
    </div>
</body>
</html>

`login-server/templates/signup.html`:

<!DOCTYPE html>
<html lang="en">
<head>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Bifrost | Create Account</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&display=swap" rel="stylesheet">
    <style>
        :root { 
            --primary: #3b82f6; 
            --bg-color: #f8fafc; 
            --text-main: #1e293b; 
        }
        body { 
            font-family: 'Inter', sans-serif; 
            background: var(--bg-color);
            display: flex; 
            justify-content: center; 
            align-items: center; 
            min-height: 100vh; 
            margin: 0; 
            color: var(--text-main); 
        }

        .card { background: white; 
            padding: 50px; 
            border-radius: 24px; 
            box-shadow: 0 10px 25px rgba(0,0,0,0.05); 
            width: 100%; 
            max-width: 400px;
            text-align: center; 
        }
        .btn-primary { 
            background: var(--primary); 
            color: white; 
            padding: 12px 24px; 
            border-radius: 10px; 
            font-weight: 600; 
            font-size: 14px; 
            transition: 0.2s; 
            width: 100%; 
            border: none; 
            cursor: pointer; 
        }
        .btn-primary:hover { opacity: 0.9; transform: translateY(-1px); }
        .alert { 
            padding: 12px; 
            margin-bottom: 20px; 
            border-radius: 8px; 
            font-size: 14px; 
            font-weight: 500; 
        }
        .alert-danger { 
            background-color: #fee2e2; 
            color: #991b1b; 
            border: 1px solid #fecaca; 
        }
    </style>
</head>
<body>
    <div class="card">
        <div style="color: var(--primary); font-weight: 700; letter-spacing: 2px; margin-bottom: 20px;">BIFROST</div>
        <h1 style="font-size: 24px; margin-bottom: 10px;">Register Device</h1>
        <p style="color: #64748b; font-size: 14px; margin-bottom: 30px;">Step 1: Create your secure account credentials.</p>
        
        {% with messages = get_flashed_messages(with_categories=true) %}
          {% if messages %}
            {% for category, message in messages %}
              <div class="alert alert-{{ category }}">{{ message }}</div>
            {% endfor %}
          {% endif %}
        {% endwith %}

        <form action="/signup" method="POST">
            <input type="text" name="username" placeholder="Choose a Username" required style="width: 100%; padding: 12px; margin-bottom: 15px; border-radius: 8px; border: 1px solid #e2e8f0; box-sizing: border-box;">
            <input type="password" name="password" placeholder="Create a Password" required style="width: 100%; padding: 12px; margin-bottom: 20px; border-radius: 8px; border: 1px solid #e2e8f0; box-sizing: border-box;">
            <button type="submit" class="btn-primary">Generate Endpoint Code</button>
        </form>

        <div style="margin-top: 20px; font-size: 14px;">
            <a href="/login" style="color: var(--primary); text-decoration: none; font-weight: 600;">Log in instead</a>
        </div>
    </div>
</body>
</html>

`login-server/templates/signup_waiting.html`:

<!DOCTYPE html>
<html lang="en">
<head>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Bifrost | Awaiting Connection</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
        body { 
            font-family: 'Inter', sans-serif; 
            background: #0f172a; 
            color: white; 
            display: flex; 
            justify-content: center; 
            align-items: center; 
            min-height: 100vh; 
            margin: 0; }
        .card { 
            background: #1e293b; 
            padding: 40px; 
            border-radius: 24px; 
            text-align: center; 
            max-width: 400px; 
            width: 100%; 
            box-shadow: 0 20px 40px rgba(0,0,0,0.3); 
        }
        .code-display { 
            font-size: 48px; 
            letter-spacing: 12px; 
            font-weight: 700; 
            color: #3b82f6; 
            background: #0f172a; 
            padding: 20px; 
            border-radius: 12px; 
            margin: 30px 0; 
            border: 1px solid #334155; 
        }
        .loader { 
            border: 3px solid #334155; 
            border-top: 3px solid #3b82f6; 
            border-radius: 50%; 
            width: 24px; 
            height: 24px; 
            animation: spin 1s linear infinite; 
            margin: 0 auto 15px auto; 
        }
        @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
    </style>
</head>
<body>
    <div class="card">
        <div class="loader"></div>
        <h2>Awaiting Bifrost...</h2>
        <p style="color: #94a3b8; font-size: 14px;">Enter this endpoint code into your Bifrost terminal to complete the key exchange. Expires in 5 minutes.</p>
        
        <div class="code-display">{{ exchange_code }}</div>
        
        <p id="status-text" style="color: #10b981; font-size: 13px; font-weight: 600;">Listening for connection...</p>
    </div>

    <script>
        const endpointCode = "{{ exchange_code }}";
        
        setInterval(() => {
            fetch(`/api/status/${endpointCode}`)
                .then(response => response.json())
                .then(data => {
                    if (data.status === 'success') {
                        document.getElementById('status-text').innerText = "Exchange Successful! Redirecting...";
                        window.location.href = "/login?success=1";
                    } else if (data.status === 'expired') {
                        document.getElementById('status-text').innerText = "Endpoint expired. Please try again.";
                        document.getElementById('status-text').style.color = "#ef4444";
                        setTimeout(() => window.location.href = "/signup", 3000);
                    }
                });
        }, 2000);
    </script>
</body>
</html>

`login-server/templates/verify_totp.html`:

<!DOCTYPE html>
<html lang="en">
<head>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Bifrost | Two-Factor Auth</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&display=swap" rel="stylesheet">
    <style>
        body {    
            font-family: 'Inter', sans-serif; 
            background: #0f172a;
            display: flex; justify-content: center; align-items: center;
            min-height: 100vh; margin: 0; color: white;
        }
        .card { 
            background: #1e293b; padding: 40px; border-radius: 24px; 
            box-shadow: 0 20px 40px rgba(0,0,0,0.3); 
            width: 100%; max-width: 380px; text-align: center;
        }
        .otp-input {
            width: 100%; padding: 15px; margin: 20px 0;
            background: #334155; border: 2px solid #475569;
            color: #10b981; font-size: 32px; font-weight: 700;
            text-align: center; letter-spacing: 8px; border-radius: 12px;
            box-sizing: border-box;
        }
        .otp-input.error {
            border-color: #ef4444;
            color: #ef4444;
        }
        button { 
            width: 100%; padding: 14px; background: #3b82f6; 
            color: white; border: none; border-radius: 12px; 
            font-weight: 600; cursor: pointer; transition: 0.2s;
        }
        button:hover { background: #2563eb; transform: translateY(-2px); }
        .alert { 
            padding: 12px; margin-bottom: 16px; border-radius: 8px; 
            font-size: 14px; font-weight: 500; 
        }
        .alert-danger { 
            background-color: rgba(239, 68, 68, 0.15); 
            color: #fca5a5; 
            border: 1px solid rgba(239, 68, 68, 0.3); 
        }
    </style>
</head>
<body>
    <div class="card">
        <h2 style="margin:0">Verify Identity</h2>
        <p style="color: #94a3b8; font-size: 14px;">Enter the 6-digit code from Bifrost.</p>

        {% with messages = get_flashed_messages(with_categories=true) %}
          {% if messages %}
            {% for category, message in messages %}
              <div class="alert alert-{{ category }}">{{ message }}</div>
            {% endfor %}
          {% endif %}
        {% endwith %}

        <form action="/verify-totp" method="POST">
            <input 
                type="text" 
                name="otp" 
                class="otp-input{% if get_flashed_messages() %} error{% endif %}" 
                placeholder="000000" 
                maxlength="6" 
                autocomplete="one-time-code"
                required
            >
            <button type="submit">Verify & Sign In</button>
        </form>
    </div>
</body>
</html>


The README should include the following sections:

1. Project Title
2. Brief description (1-2 sentences)
3. Features
4. Installation instructions
5. Usage examples
6. Configuration options (if applicable) 
7. Contribution guidelines
8. Testing instructions
9. License
10. Acknowledgements/Credits

Write the content in Markdown format. Use your analysis of the code to generate accurate and helpful content, but also explain things clearly for users who may not be familiar with the implementation details.

Feel free to infer reasonable details if needed, but try to stick to what can be determined from the codebase itself. Let me know if you have any other questions as you're writing!