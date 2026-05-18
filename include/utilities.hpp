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
