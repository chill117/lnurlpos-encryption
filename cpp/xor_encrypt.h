#ifndef XOR_ENCRYPT_H
#define XOR_ENCRYPT_H

#include "src/Hash.h"
#include "src/Conversion.h"
#include <iostream>// for std::cout

typedef uint8_t byte;
int xor_encrypt(uint8_t *output, size_t outlen, uint8_t *key, size_t keylen, uint8_t *nonce, size_t nonce_len, uint64_t pin, uint64_t amount_in_cents);
void makeLNURL();
int main();

#endif
