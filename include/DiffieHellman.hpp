#pragma once
#include "typedefs.hpp"

#include <boost/multiprecision/cpp_int.hpp>

using namespace boost::multiprecision;
extern cpp_int prime;
extern cpp_int generator;
constexpr int nBytes=8;
class Diffie_Hellman{
    private:
    cpp_int private_key;

    public:
    cpp_int public_key;
    
    Diffie_Hellman();

    cpp_int mod_exp(cpp_int base, cpp_int exp, cpp_int mod);
    cpp_int generate_public_key();
    cpp_int compute_shared_secret(cpp_int other_public_key);
    Bytes cpp_int_to_bytes(cpp_int num);
    Bytes resizeKey(const Bytes &key, const int nBytes);

};