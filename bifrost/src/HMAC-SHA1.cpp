#include <HMAC_SHA1.hpp>

#include <openssl/evp.h>
#include <openssl/hmac.h>

Bytes hmac_sha1(const Bytes &key, const Bytes &message) {
    unsigned int len;

    unsigned char digest[EVP_MAX_MD_SIZE];

    HMAC(EVP_sha1(), // hash function
         key.data(), //.data fn returns pointer to first member of key vector
         key.size(), message.data(), message.size(),
         digest, // array where output is stored
         &len    // HMAC fn rewrites size of output in len according to hash
              // function used
    );

    return Bytes(digest, digest + len); // copy elements of array to vector
}
