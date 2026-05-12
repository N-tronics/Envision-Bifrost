#include <DiffieHellman.hpp>
#include <HMAC_SHA1.hpp>
#include <algorithm>
#include <random.hpp>

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
cpp_int Diffie_Hellman::compute_shared_secret(cpp_int other_public_key) {
    return mod_exp(other_public_key, private_key, prime);
}
Bytes Diffie_Hellman::cpp_int_to_bytes(cpp_int num) {
    Bytes converted_key;
    while (num > 0) {
        Byte byte = (num & 0xFF).convert_to<Byte>(); // to get the last 8 bits
        converted_key.push_back(byte);
        num >>= 8;
    }
    std::reverse(converted_key.begin(), converted_key.end());
    return converted_key;
}

Bytes Diffie_Hellman::resizeKey(const Bytes &key, const int nBytes) {
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
