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
