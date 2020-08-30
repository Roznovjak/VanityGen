#include <iomanip>
#include <sstream>
#include <string>
#include <vector>

#include "openssl/ec.h"
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/ripemd.h>
#include <openssl/sha.h>

class ec_key {
 private:
   BIGNUM *private_key;
   EC_POINT *public_key;

 public:
   ec_key(BIGNUM *priv, EC_POINT *pub) : private_key{priv}, public_key{pub} {}
   ec_key(const std::string &priv_hex, const std::string &pub_hex);
   ~ec_key();
   static ec_key generate();

   std::string get_wif_priv_key() const;
   std::string get_public_key() const;
   std::string get_hex_priv_key() const;
   std::string get_hex_pub_key() const;
   std::string get_bin_priv_key() const;
   std::string get_bin_pub_key() const;
   static std::string to_hex(const std::string &d);
   static std::string b58(const std::string &hex);
   static std::string sha256(const std::string &data); // returns hex
};
