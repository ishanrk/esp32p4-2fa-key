#include "make_cred_fakes.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "p4_cred.h"
#include "p4_press.h"


static const uint8_t s_root[P4_CRYPTO_AES256_KEY_LEN] = {
    0x91, 0x82, 0x73, 0x64, 0x55, 0x46, 0x37, 0x28,
    0x19, 0x0a, 0xfb, 0xec, 0xdd, 0xce, 0xbf, 0xa0,
    0x12, 0x24, 0x36, 0x48, 0x5a, 0x6c, 0x7e, 0x80,
    0x92, 0xa4, 0xb6, 0xc8, 0xda, 0xec, 0xfe, 0x10,
};

const uint8_t make_fake_rp_hash[P4_CRYPTO_SHA256_LEN] = {
    0xa3, 0x79, 0xa6, 0xf6, 0xee, 0xaf, 0xb9, 0xa5,
    0x5e, 0x37, 0x8c, 0x11, 0x80, 0x34, 0xe2, 0x75,
    0x1e, 0x68, 0x2f, 0xab, 0x9f, 0x2d, 0x30, 0xab,
    0x13, 0xd2, 0x12, 0x55, 0x86, 0xce, 0x19, 0x47,
};

const uint8_t make_fake_private[P4_CRYPTO_P256_SCALAR_LEN] = {
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
    0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
};

const uint8_t make_fake_x[P4_CRYPTO_P256_SCALAR_LEN] = {
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
    0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
    0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
};

const uint8_t make_fake_y[P4_CRYPTO_P256_SCALAR_LEN] = {
    0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
    0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
    0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
    0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,
};

unsigned make_fake_sha_calls;
unsigned make_fake_press_calls;
unsigned make_fake_key_calls;
unsigned make_fake_rand_calls;
unsigned make_fake_seal_calls;


void make_fakes_reset(void)
{
    make_fake_sha_calls = 0;
    make_fake_press_calls = 0;
    make_fake_key_calls = 0;
    make_fake_rand_calls = 0;
    make_fake_seal_calls = 0;
}


void secret_clear(void *ptr, size_t len)
{
    volatile uint8_t *bytes = ptr;
    while (bytes != NULL && len-- != 0) {
        *bytes++ = 0;
    }
}


int sha256_sum(const uint8_t *in, size_t in_len,
               uint8_t out[P4_CRYPTO_SHA256_LEN])
{
    static const uint8_t expected[] = "example.com";
    make_fake_sha_calls++;
    if (in == NULL || out == NULL ||
        in_len != sizeof(expected) - 1 ||
        memcmp(in, expected, sizeof(expected) - 1) != 0) {
        return P4_CRYPTO_BAD_ARG;
    }
    memcpy(out, make_fake_rp_hash, P4_CRYPTO_SHA256_LEN);
    return P4_CRYPTO_OK;
}


int p256_make(uint8_t private_scalar[P4_CRYPTO_P256_SCALAR_LEN],
              uint8_t x[P4_CRYPTO_P256_SCALAR_LEN],
              uint8_t y[P4_CRYPTO_P256_SCALAR_LEN])
{
    make_fake_key_calls++;
    memcpy(private_scalar, make_fake_private, P4_CRYPTO_P256_SCALAR_LEN);
    memcpy(x, make_fake_x, P4_CRYPTO_P256_SCALAR_LEN);
    memcpy(y, make_fake_y, P4_CRYPTO_P256_SCALAR_LEN);
    return P4_CRYPTO_OK;
}


int p256_pub(const uint8_t private_scalar[P4_CRYPTO_P256_SCALAR_LEN],
             uint8_t x[P4_CRYPTO_P256_SCALAR_LEN],
             uint8_t y[P4_CRYPTO_P256_SCALAR_LEN])
{
    if (memcmp(private_scalar, make_fake_private,
               P4_CRYPTO_P256_SCALAR_LEN) != 0) {
        secret_clear(x, P4_CRYPTO_P256_SCALAR_LEN);
        secret_clear(y, P4_CRYPTO_P256_SCALAR_LEN);
        return P4_CRYPTO_KEY;
    }
    memcpy(x, make_fake_x, P4_CRYPTO_P256_SCALAR_LEN);
    memcpy(y, make_fake_y, P4_CRYPTO_P256_SCALAR_LEN);
    return P4_CRYPTO_OK;
}


int rand_fill(uint8_t *out, size_t out_len)
{
    if (out == NULL || out_len != P4_CRYPTO_GCM_NONCE_LEN) {
        return P4_CRYPTO_BAD_ARG;
    }
    make_fake_rand_calls++;
    for (size_t index = 0; index < out_len; index++) {
        out[index] = (uint8_t)(0x40U + index);
    }
    return P4_CRYPTO_OK;
}


int p4_root_load(uint8_t root[P4_CRYPTO_AES256_KEY_LEN])
{
    memcpy(root, s_root, sizeof(s_root));
    return P4_CRED_OK;
}


static void make_tag(
    const uint8_t key[P4_CRYPTO_AES256_KEY_LEN],
    const uint8_t nonce[P4_CRYPTO_GCM_NONCE_LEN],
    const uint8_t *aad,
    size_t aad_len,
    const uint8_t *cipher,
    size_t cipher_len,
    uint8_t tag[P4_CRYPTO_GCM_TAG_LEN])
{
    for (size_t index = 0; index < P4_CRYPTO_GCM_TAG_LEN; index++) {
        tag[index] = (uint8_t)(0x6dU ^ key[index] ^ key[index + 16]);
    }
    for (size_t index = 0; index < P4_CRYPTO_GCM_NONCE_LEN; index++) {
        tag[index % P4_CRYPTO_GCM_TAG_LEN] ^=
            (uint8_t)(nonce[index] + (uint8_t)index);
    }
    for (size_t index = 0; index < aad_len; index++) {
        tag[index % P4_CRYPTO_GCM_TAG_LEN] ^=
            (uint8_t)(aad[index] + (uint8_t)(index * 3U));
    }
    for (size_t index = 0; index < cipher_len; index++) {
        tag[index % P4_CRYPTO_GCM_TAG_LEN] ^=
            (uint8_t)(cipher[index] + (uint8_t)(index * 5U));
    }
}


int gcm_seal(
    const uint8_t key[P4_CRYPTO_AES256_KEY_LEN],
    const uint8_t nonce[P4_CRYPTO_GCM_NONCE_LEN],
    const uint8_t *aad,
    size_t aad_len,
    const uint8_t *plain,
    size_t plain_len,
    uint8_t *cipher,
    uint8_t tag[P4_CRYPTO_GCM_TAG_LEN])
{
    make_fake_seal_calls++;
    for (size_t index = 0; index < plain_len; index++) {
        cipher[index] = (uint8_t)(plain[index] ^ key[index % 32] ^
                                  nonce[index % 12] ^ 0xa5U);
    }
    make_tag(key, nonce, aad, aad_len, cipher, plain_len, tag);
    return P4_CRYPTO_OK;
}


int gcm_open(
    const uint8_t key[P4_CRYPTO_AES256_KEY_LEN],
    const uint8_t nonce[P4_CRYPTO_GCM_NONCE_LEN],
    const uint8_t *aad,
    size_t aad_len,
    const uint8_t *cipher,
    size_t cipher_len,
    const uint8_t tag[P4_CRYPTO_GCM_TAG_LEN],
    uint8_t *plain)
{
    uint8_t expected[P4_CRYPTO_GCM_TAG_LEN];
    make_tag(key, nonce, aad, aad_len, cipher, cipher_len, expected);
    uint8_t different = 0;
    for (size_t index = 0; index < sizeof(expected); index++) {
        different |= (uint8_t)(expected[index] ^ tag[index]);
    }
    secret_clear(expected, sizeof(expected));
    if (different != 0) {
        secret_clear(plain, cipher_len);
        return P4_CRYPTO_AUTH;
    }
    for (size_t index = 0; index < cipher_len; index++) {
        plain[index] = (uint8_t)(cipher[index] ^ key[index % 32] ^
                                 nonce[index % 12] ^ 0xa5U);
    }
    return P4_CRYPTO_OK;
}


int press_wait(uint32_t cid)
{
    if (cid == 0) {
        return P4_PRESS_DENIED;
    }
    make_fake_press_calls++;
    return P4_PRESS_OK;
}


bool press_cancelled(uint32_t cid)
{
    return cid == 0;
}
