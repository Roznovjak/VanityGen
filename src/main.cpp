#include <cassert>
#include <csignal>
#include <iostream>
#include <thread>
#include <vector>

#include "crypto_utility.hpp"

const char *test_priv_key_hex{
    "D8FE3C7A39A1B4FCEEE8229B0F6F567D4869BCF24F709730AFC98BE60EA07E83"};
const char *test_priv_key_wif{
    "5KTrNx95QnQeYBwG55YbxWvXRRLVYWgRTZEaSunjKMj6PAhqeWZ"};
const char *test_pub_key_hex{
    "036235FBDD582DC4D12CDC33F88FE102DF853ADAE201D9BF9EAC49C15E204E8A49"};
const char *test_pub_key{"7aVCGKRZobQ3r4zWTizQP4ASsbn3abqBr3rqeaptVRUMci2Md7"};

const char *test_input{"The quick brown fox jumps over the lazy dog"};
const char *test_sha256_output{
    "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592"};
const char *test_base58_output{
    "7DdiPPYtxLjCD3wA1po2rvZHTDYjkZYiEtazrfiwJcwnKCizhGFhBGHeRdx"};
const char *test_hex_output{"54686520717569636b2062726f776e20666f78206a756d7073"
                            "206f76657220746865206c617a7920646f67"};

void test() {
   assert(ec_key::to_hex(test_input) == test_hex_output);
   assert(ec_key::sha256(test_input) == test_sha256_output);
   assert(ec_key::b58(test_hex_output) == test_base58_output);
   ec_key test(test_priv_key_hex, test_pub_key_hex);
   assert(test.get_wif_priv_key() == test_priv_key_wif);
   assert(test.get_public_key() == test_pub_key);
}

// requires one program argument, string
int main(int argc, char *argv[]) {
   signal(SIGINT, [](int s) { exit(s); });
   test();

   if (argc != 2)
   {
      std::cout << "No arguments were provided." << std::endl;
      return 1;
   }
   
   std::cout << "Press Ctrl-C to quit." << std::endl;

   std::string str{argv[1]};
   bool key_found{false};

   auto find = [&key_found](std::string str) {
      while (!key_found) {
         ec_key k{ec_key::generate()};
         if (k.get_public_key().substr(1, str.length()) == str) {
            std::cout << "public key:  " << k.get_public_key() << '\n';
            std::cout << "private key: " << k.get_wif_priv_key() << std::endl;
            key_found = true;
            break;
         }
      }
   };

   unsigned int num_threads{std::thread::hardware_concurrency()};
   std::vector<std::thread> thread_pool;
   for (int i = 0; i < num_threads; ++i)
      thread_pool.push_back(std::thread(find, str));

   for (auto &elem : thread_pool)
      elem.join();

   return 0;
}
