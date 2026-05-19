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
