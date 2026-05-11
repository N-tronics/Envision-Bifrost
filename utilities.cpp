#include "utilities.hpp"

// =======================================
// cpp_int -> bytes
// =======================================

vector<uint8_t> cppIntToBytes(cpp_int num)
{
    vector<uint8_t> bytes;

    while(num > 0)
    {
        uint8_t byte = static_cast<uint8_t>(num & 0xFF);

        bytes.insert(bytes.begin(), byte);

        num >>= 8;
    }

    return bytes;
}

// =======================================
// bytes -> cpp_int
// =======================================

cpp_int bytesToCppInt(vector<uint8_t> bytes)
{
    cpp_int num = 0;

    for(uint8_t byte : bytes)
    {
        num <<= 8;

        num += byte;
    }

    return num;
}

// =======================================
// bytes -> hex
// =======================================

string bytesToHex(vector<uint8_t> bytes)
{
    const char* hexChars = "0123456789ABCDEF";

    string hex;

    for(uint8_t byte : bytes)
    {
        hex += hexChars[(byte >> 4) & 0x0F];

        hex += hexChars[byte & 0x0F];
    }

    return hex;
}

// =======================================
// hex -> bytes
// =======================================

vector<uint8_t> hexToBytes(string hex)
{
    vector<uint8_t> bytes;

    for(size_t i = 0; i < hex.length(); i += 2)
    {
        string part = hex.substr(i, 2);

        uint8_t byte = static_cast<uint8_t>(
            strtol(part.c_str(), nullptr, 16)
        );

        bytes.push_back(byte);
    }

    return bytes;
}

// =======================================
// cpp_int -> hex
// =======================================

string cppIntToHex(cpp_int num)
{
    if(num == 0)
        return "0";

    const char* hexChars = "0123456789ABCDEF";

    string hex;

    while(num > 0)
    {
        int digit = static_cast<int>(num & 0xF);

        hex = hexChars[digit] + hex;

        num >>= 4;
    }

    return hex;
}

// =======================================
// hex -> cpp_int
// =======================================

cpp_int hexToCppInt(string hex)
{
    cpp_int num = 0;

    for(char c : hex)
    {
        num <<= 4;

        if(c >= '0' && c <= '9')
            num += c - '0';

        else if(c >= 'A' && c <= 'F')
            num += c - 'A' + 10;

        else if(c >= 'a' && c <= 'f')
            num += c - 'a' + 10;
    }

    return num;
}

// =======================================
// print bytes
// =======================================

void printBytes(vector<uint8_t> bytes)
{
    for(uint8_t byte : bytes)
    {
        printf("%02X ", byte);
    }

    cout << endl;
}