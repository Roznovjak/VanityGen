#include "crypto_utility.hpp"

ec_key::ec_key(const std::string &priv_hex, const std::string &pub_hex) {
   BIGNUM *bn{BN_new()};
   BN_hex2bn(&bn, priv_hex.c_str());
   private_key = bn;

   EC_GROUP *ec_group{EC_GROUP_new_by_curve_name(NID_secp256k1)};
   BN_CTX *bn_ctx{BN_CTX_new()};
   EC_POINT *ec_point{EC_POINT_new(ec_group)};
   EC_POINT_hex2point(ec_group, pub_hex.c_str(), ec_point, bn_ctx);
   public_key = ec_point;
   EC_GROUP_free(ec_group);
   BN_CTX_free(bn_ctx);
}

std::string ec_key::to_hex(const std::string &d) {
   size_t s{d.length()};
   std::string r;
   const char *to_hex = "0123456789abcdef";
   const uint8_t *c = reinterpret_cast<const uint8_t*>(d.c_str());
   for (size_t i = 0; i < s; ++i)
      (r += to_hex[(c[i] >> 4)]) += to_hex[(c[i] & 0x0f)];
   return r;
}

std::string ec_key::b58(const std::string &hex) {
   char table[] = {'1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C',
                   'D', 'E', 'F', 'G', 'H', 'J', 'K', 'L', 'M', 'N', 'P', 'Q',
                   'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c',
                   'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'm', 'n', 'o', 'p',
                   'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z'};

   BIGNUM *base58{NULL};

   BIGNUM *resultExp{BN_new()};
   BIGNUM *resultAdd{BN_new()};
   BIGNUM *resultRem{BN_new()};
   BN_CTX *bn_ctx{BN_CTX_new()};

   BN_dec2bn(&base58, "58");

   std::string endresult;
   std::vector<int> v;

   BN_hex2bn(&resultAdd, hex.c_str());

   while (!BN_is_zero(resultAdd)) {
      BN_div(resultAdd, resultRem, resultAdd, base58, bn_ctx);
      char *asdf = BN_bn2dec(resultRem);
      v.push_back(atoi(asdf));
      OPENSSL_free(asdf);
   }

   for (int i = (int)v.size() - 1; i >= 0; i--)
      endresult.push_back(table[v[i]]);

   BN_free(resultAdd);
   BN_free(resultExp);
   BN_free(resultRem);
   BN_free(base58);
   BN_CTX_free(bn_ctx);

   return endresult;
}

std::string ec_key::sha256(const std::string &data) {
   unsigned char hash[SHA256_DIGEST_LENGTH];
   SHA256_CTX ctx;
   SHA256_Init(&ctx);
   SHA256_Update(&ctx, data.c_str(), data.length());
   SHA256_Final(hash, &ctx);
   std::stringstream ss;
   for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
      ss << std::hex << std::setw(2) << std::setfill('0')
         << static_cast<int>(hash[i]);
   return ss.str();
}

ec_key::~ec_key() {
   BN_clear_free(private_key);
   EC_POINT_clear_free(public_key);
}

ec_key ec_key::generate() {
   EC_KEY *k{ EC_KEY_new_by_curve_name(NID_secp256k1)};
   EC_KEY_generate_key(k);
   BIGNUM *priv_key{BN_dup(EC_KEY_get0_private_key(k))};
   EC_GROUP *ec_group{EC_GROUP_new_by_curve_name(NID_secp256k1)};
   EC_POINT *pub_key{EC_POINT_dup(EC_KEY_get0_public_key(k), ec_group)};
   EC_GROUP_free(ec_group);
   EC_KEY_free(k);
   return ec_key(priv_key, pub_key);
}

std::string ec_key::get_hex_priv_key() const {
   char *tmp_res{BN_bn2hex(private_key)};
   std::string res{tmp_res};
   OPENSSL_free(tmp_res);
   return res;
}

std::string ec_key::get_hex_pub_key() const {
   EC_GROUP *ec_group{EC_GROUP_new_by_curve_name(NID_secp256k1)};
   BN_CTX *bn_ctx{BN_CTX_new()};
   char *tmp_res{EC_POINT_point2hex(ec_group, public_key,
                                    POINT_CONVERSION_COMPRESSED, bn_ctx)};
   std::string result{tmp_res};
   delete[] tmp_res;
   EC_GROUP_free(ec_group);
   BN_CTX_free(bn_ctx);
   return result;
}

std::string ec_key::get_bin_priv_key() const {
   std::string res(BN_num_bytes(private_key), '\0');
   BN_bn2bin(private_key, reinterpret_cast<unsigned char *>(&res[0]));
   return res;
}

std::string ec_key::get_wif_priv_key() const {
   std::string subres{get_bin_priv_key().insert(0, "\x80")};
   std::string sha1{sha256(subres)};
   BIGNUM *bn{BN_new()};
   BN_hex2bn(&bn, sha1.c_str());
   std::string sha1_bin(BN_num_bytes(bn), '\0');
   BN_bn2bin(bn, reinterpret_cast<unsigned char *>(&sha1_bin[0]));
   std::string sha2{sha256(sha1_bin)};
   BN_free(bn);
   return b58(to_hex(subres) + sha2.substr(0, 8));
}

std::string ec_key::get_bin_pub_key() const {
   BIGNUM *bn{BN_new()};
   BN_hex2bn(&bn, get_hex_pub_key().c_str());
   std::string bin(BN_num_bytes(bn), '\0');
   BN_bn2bin(bn, reinterpret_cast<unsigned char *>(&bin[0]));
   BN_free(bn);
   return bin;
}

std::string ec_key::get_public_key() const {
   unsigned char ripemd160[21]{};
   RIPEMD160(reinterpret_cast<const unsigned char *>(get_bin_pub_key().c_str()),
             33, ripemd160);
   return b58(get_hex_pub_key() +
              to_hex(reinterpret_cast<char *>(ripemd160)).substr(0, 8));
}
