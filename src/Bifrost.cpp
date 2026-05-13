#include "typedefs.hpp"
#include "utilities.hpp"
#include "random.hpp"
#include "HMAC_SHA1.hpp"
#include "DiffieHellman.hpp"
#include<time.h>
int main(){
    //TOTP
    Bytes key;
    time_t timestamp = time(NULL);
    cpp_int timestep = timestamp/30;
    Bytes message = Diffie_Hellman::cpp_int_to_bytes(timestep);
    Bytes hmac_bytes = hmac_sha1(&key, &message);
    int offset= hmac_bytes[hmac_bytes.size()-1] & 0x0F;
    Bytes sample_bytes;
    for(int i=offset;i<offset+4;i++) sample_bytes.push_back(hmac_bytes[i]);
    sample_bytes[0]&=0x7f;
    cpp_int sample = bytesToCppInt(sample_bytes);
    int OTP = (sample%1000000).convert_to<int>();
    return OTP;



}