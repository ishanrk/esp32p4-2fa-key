#ifndef P4_CRYPTO_H
#define P4_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

#include "p4_crypto_err.h"

#define P4_CRYPTO_SHA256_LEN 32
#define P4_CRYPTO_AES256_KEY_LEN 32
#define P4_CRYPTO_GCM_NONCE_LEN 12
#define P4_CRYPTO_GCM_TAG_LEN 16
#define P4_CRYPTO_P256_SCALAR_LEN 32
#define P4_CRYPTO_P256_DER_MAX 72

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

int p256_make(
    uint8_t priv[P4_CRYPTO_P256_SCALAR_LEN],
    uint8_t x[P4_CRYPTO_P256_SCALAR_LEN],
    uint8_t y[P4_CRYPTO_P256_SCALAR_LEN]);

int p256_pub(
    const uint8_t priv[P4_CRYPTO_P256_SCALAR_LEN],
    uint8_t x[P4_CRYPTO_P256_SCALAR_LEN],
    uint8_t y[P4_CRYPTO_P256_SCALAR_LEN]);

int p256_sign_hash(
    const uint8_t priv[P4_CRYPTO_P256_SCALAR_LEN],
    const uint8_t hash[P4_CRYPTO_SHA256_LEN],
    uint8_t *sig,
    size_t sig_cap,
    size_t *sig_len);

int p256_verify_hash(
    const uint8_t x[P4_CRYPTO_P256_SCALAR_LEN],
    const uint8_t y[P4_CRYPTO_P256_SCALAR_LEN],
    const uint8_t hash[P4_CRYPTO_SHA256_LEN],
    const uint8_t *sig,
    size_t sig_len);

void secret_clear(void *ptr, size_t len);

#endif
