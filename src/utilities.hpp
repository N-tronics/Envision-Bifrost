#ifndef UTILITIES_HPP
#define UTILITIES_HPP

#include <iostream>
#include <vector>
#include <string>

#include <boost/multiprecision/cpp_int.hpp>

using namespace std;
using namespace boost::multiprecision;

// cpp_int -> bytes
vector<uint8_t> cppIntToBytes(cpp_int num);

// bytes -> cpp_int
cpp_int bytesToCppInt(vector<uint8_t> bytes);

// bytes -> hex
string bytesToHex(vector<uint8_t> bytes);

// hex -> bytes
vector<uint8_t> hexToBytes(string hex);

// cpp_int -> hex string
string cppIntToHex(cpp_int num);

// hex -> cpp_int
cpp_int hexToCppInt(string hex);

// print bytes
void printBytes(vector<uint8_t> bytes);

#endif