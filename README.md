# VanityGen
Vanity public key generator for Graphene based blockchains.

Requires installed *OpenSSL* library (version 1.1). <br />
The program expects one command line argument: a pattern to search for. <br />
Due to the way how *Graphene* based blockchains generate public key, the pattern the program search for starts at the second character (the pattern is preceded by a digit). <br />
Generates public and private keys without a blockchain prefix. Prefix the public key with *DCT* to get keys for the DECENT blockchain. <br /><br />

Set `OPENSSL_ROOT_DIR` to the root directory on an OpenSSL installation if *CMake* can not locate it: <br />
```cmake -G "Unix Makefiles" -DOPENSSL_ROOT_DIR=/path/to/openssl_root_dir``` <br /><br />

#### Example ( Warning: do not use the following keys! )<br />
```
$ vanity_address_gen rich
public key:  7richUiVWesUUGUiMLho4JSkdmviUDHJWBVSaL5UhV3sQW9C3r
private key: 5HtSKXr7VVfs4dwrWjXAdPRm5DwzFGqC7oq7fJZCtaCgHkdyk6J
```
