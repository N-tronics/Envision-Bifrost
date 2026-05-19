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
