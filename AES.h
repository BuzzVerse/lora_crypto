#ifndef AES_H
#define AES_H

#include <stdbool.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>

bool encrypt(uint8_t *data, int data_len, uint8_t *key, uint8_t *iv, uint8_t *ciphertext);
bool decrypt(uint8_t *ciphertext, int ciphertext_len, uint8_t *key, uint8_t *iv, uint8_t *data);

#endif // AES_H