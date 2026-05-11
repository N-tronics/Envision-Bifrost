#include <iostream>
#include "random.hpp"
#include "utilities.hpp" // Contains all your conversions

int main() {
    cout << "=== BIFROST: Integrated Random & Utilities ===\n\n";

    // ---------------------------------------------------------
    // Test 1: Random Bytes & Utility Hex Conversion
    // ---------------------------------------------------------
    cout << "[*] Generating 16 random bytes..." << endl;
    vector<uint8_t> random_bytes = Random::generateRandomBytes(16);
    
    cout << "    Using printBytes():  ";
    printBytes(random_bytes); // Utilizing your utility function
    
    cout << "    Using bytesToHex():  " << bytesToHex(random_bytes) << "\n\n";

    // ---------------------------------------------------------
    // Test 2: Prime Generation (Powered by bytesToCppInt under the hood)
    // ---------------------------------------------------------
    unsigned int prime_bits = 256; 
    cout << "[*] Generating a " << prime_bits << "-bit prime number..." << endl;
    
    cpp_int large_prime = Random::generateLargePrime(prime_bits);
    
    cout << "    Prime (Decimal): \n    " << large_prime << "\n\n";
    cout << "    Prime (Hex) via cppIntToHex(): \n    " << cppIntToHex(large_prime) << "\n\n";

    cout << "=== Test Complete ===" << endl;

    return 0;
}