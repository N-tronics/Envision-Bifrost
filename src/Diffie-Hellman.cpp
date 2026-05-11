#include "HMAC_SHA1.hpp"
#include "DiffieHellman.hpp"

cpp_int prime;
cpp_int generator;
   Diffie_Hellman::Diffie_Hellman(){
        //generate private key
        public_key=generate_public_key();
    }
    cpp_int Diffie_Hellman::mod_exp(cpp_int base, cpp_int exp, cpp_int mod){
        cpp_int ans=1;
        while(exp!=0){
            if(exp&1){
                ans=(ans*base)%mod;
            }
            base=(base*base)%mod;
            exp/=2; //similar to right shift
        }
        return ans;
    }
    cpp_int Diffie_Hellman::generate_public_key(){
        return mod_exp(generator,private_key,prime);
    }
    cpp_int Diffie_Hellman::compute_shared_secret(cpp_int other_public_key){
        return mod_exp(other_public_key, private_key, prime);
    }
    

