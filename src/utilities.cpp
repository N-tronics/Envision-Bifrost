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
    Bytes bytes;

    for (size_t i = 0; i < hex.length(); i += 2) {
        string part = hex.substr(i, 2);

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
