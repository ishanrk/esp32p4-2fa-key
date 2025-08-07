#ifndef P4_CRYPTO_H
#define P4_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

#include "p4_crypto_err.h"

#define P4_CRYPTO_SHA256_LEN 32
#define P4_CRYPTO_AES256_KEY_LEN 32
#define P4_CRYPTO_GCM_NONCE_LEN 12
#define P4_CRYPTO_GCM_TAG_LEN 16

int crypto_init(void);

int rand_fill(uint8_t *out, size_t out_len);

int sha256_sum(const uint8_t *in, size_t in_len,
               uint8_t out[P4_CRYPTO_SHA256_LEN]);

int gcm_seal(
    const uint8_t key[P4_CRYPTO_AES256_KEY_LEN],
    const uint8_t nonce[P4_CRYPTO_GCM_NONCE_LEN],
    const uint8_t *aad,
    size_t aad_len,
    const uint8_t *plain,
    size_t plain_len,
    uint8_t *cipher,
    uint8_t tag[P4_CRYPTO_GCM_TAG_LEN]);

int gcm_open(
    const uint8_t key[P4_CRYPTO_AES256_KEY_LEN],
    const uint8_t nonce[P4_CRYPTO_GCM_NONCE_LEN],
    const uint8_t *aad,
    size_t aad_len,
    const uint8_t *cipher,
    size_t cipher_len,
    const uint8_t tag[P4_CRYPTO_GCM_TAG_LEN],
    uint8_t *plain);

void secret_clear(void *ptr, size_t len);

#endif
