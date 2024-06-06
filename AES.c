
#include "AES.h"

bool handleErrors(void) {
    ERR_print_errors_fp(stderr);
    abort();
    return false;
}

bool encrypt(uint8_t *data, int data_len, uint8_t *key, uint8_t *iv, uint8_t *ciphertext) {
    EVP_CIPHER_CTX *ctx;
    
    int len;
    int ciphertext_len;

    if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, key, iv))
        handleErrors();

    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, data, data_len))
        handleErrors();
    ciphertext_len = len;

    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) handleErrors();
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    return true;
}

bool decrypt(uint8_t *ciphertext, int ciphertext_len, uint8_t *key, uint8_t *iv, uint8_t *data) {
    EVP_CIPHER_CTX *ctx;

    int len;
    int data_len;

    if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, key, iv))
        handleErrors();

    if(1 != EVP_DecryptUpdate(ctx, data, &len, ciphertext, ciphertext_len))
        handleErrors();
    data_len = len;

    if(1 != EVP_DecryptFinal_ex(ctx, data + len, &len)) handleErrors();
    data_len += len;

    EVP_CIPHER_CTX_free(ctx);

    return true;
}