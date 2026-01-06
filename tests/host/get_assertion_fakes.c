#include "get_assertion_fakes.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <openssl/sha.h>

#include "p4_cred.h"
#include "p4_press.h"


static const uint8_t s_root[P4_CRYPTO_AES256_KEY_LEN] = {
    0x91, 0x82, 0x73, 0x64, 0x55, 0x46, 0x37, 0x28,
    0x19, 0x0a, 0xfb, 0xec, 0xdd, 0xce, 0xbf, 0xa0,
    0x12, 0x24, 0x36, 0x48, 0x5a, 0x6c, 0x7e, 0x80,
    0x92, 0xa4, 0xb6, 0xc8, 0xda, 0xec, 0xfe, 0x10,
};

const uint8_t assert_fake_private[P4_CRYPTO_P256_SCALAR_LEN] = {
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
    0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
};

const uint8_t assert_fake_x[P4_CRYPTO_P256_SCALAR_LEN] = {
    0x51, 0x5c, 0x3d, 0x6e, 0xb9, 0xe3, 0x96, 0xb9,
    0x04, 0xd3, 0xfe, 0xca, 0x7f, 0x54, 0xfd, 0xcd,
    0x0c, 0xc1, 0xe9, 0x97, 0xbf, 0x37, 0x5d, 0xca,
    0x51, 0x5a, 0xd0, 0xa6, 0xc3, 0xb4, 0x03, 0x5f,
};

const uint8_t assert_fake_y[P4_CRYPTO_P256_SCALAR_LEN] = {
    0x45, 0x36, 0xbe, 0x3a, 0x50, 0xf3, 0x18, 0xfb,
    0xf9, 0xa5, 0x47, 0x59, 0x02, 0xa2, 0x21, 0x50,
    0x2b, 0xef, 0x0d, 0x57, 0xe0, 0x8c, 0x53, 0xb2,
    0xcc, 0x0a, 0x56, 0xf1, 0x7d, 0x9f, 0x93, 0x54,
};

static const uint8_t s_assert_digest[P4_CRYPTO_SHA256_LEN] = {
    0x5f, 0xa3, 0x53, 0xcf, 0x29, 0xf8, 0xb9, 0xfd,
    0x28, 0x29, 0xb2, 0x12, 0x92, 0x7e, 0xd2, 0x3a,
    0x83, 0x5f, 0x39, 0x96, 0x0f, 0xe0, 0xdb, 0x5e,
    0xe1, 0x7c, 0x9f, 0x6c, 0x24, 0xc5, 0x8c, 0xff,
};

static const uint8_t s_assert_signature[] = {
    0x30, 0x45, 0x02, 0x21, 0x00, 0xf1, 0x5e, 0x0b,
    0x89, 0x08, 0x91, 0x8c, 0x64, 0xcc, 0x3d, 0x3a,
    0xf3, 0x26, 0x96, 0xd0, 0xe8, 0x4a, 0x94, 0x25,
    0xbd, 0xf9, 0x08, 0x30, 0x49, 0xf1, 0xa5, 0xb7,
    0x18, 0x0e, 0xab, 0x20, 0x25, 0x02, 0x20, 0x00,
    0xb3, 0x34, 0xf5, 0x67, 0x8b, 0x74, 0x71, 0x24,
    0x84, 0xa1, 0xc9, 0xcd, 0x1d, 0xe5, 0x1e, 0xf5,
    0x90, 0xd0, 0x46, 0x4b, 0xd5, 0xd9, 0x76, 0xe5,
    0x89, 0x10, 0xdb, 0x27, 0xf8, 0xab, 0x62,
};

unsigned assert_fake_press_calls;
unsigned assert_fake_sign_calls;

static int s_press_result = P4_PRESS_OK;


void assert_fakes_reset(void)
{
    assert_fake_press_calls = 0;
    assert_fake_sign_calls = 0;
    s_press_result = P4_PRESS_OK;
}


void assert_fake_set_press_result(int result)
{
    s_press_result = result;
}


void assert_fake_hash(const uint8_t *in, size_t in_len,
                      uint8_t out[P4_CRYPTO_SHA256_LEN])
{
    (void)SHA256(in, in_len, out);
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
    if ((in == NULL && in_len != 0) || out == NULL) {
        return P4_CRYPTO_BAD_ARG;
    }
    assert_fake_hash(in, in_len, out);
    return P4_CRYPTO_OK;
}


int p256_make(uint8_t private_scalar[P4_CRYPTO_P256_SCALAR_LEN],
              uint8_t x[P4_CRYPTO_P256_SCALAR_LEN],
              uint8_t y[P4_CRYPTO_P256_SCALAR_LEN])
{
    memcpy(private_scalar, assert_fake_private,
           P4_CRYPTO_P256_SCALAR_LEN);
    memcpy(x, assert_fake_x, P4_CRYPTO_P256_SCALAR_LEN);
    memcpy(y, assert_fake_y, P4_CRYPTO_P256_SCALAR_LEN);
    return P4_CRYPTO_OK;
}


int p256_pub(const uint8_t private_scalar[P4_CRYPTO_P256_SCALAR_LEN],
             uint8_t x[P4_CRYPTO_P256_SCALAR_LEN],
             uint8_t y[P4_CRYPTO_P256_SCALAR_LEN])
{
    if (memcmp(private_scalar, assert_fake_private,
               P4_CRYPTO_P256_SCALAR_LEN) != 0) {
        secret_clear(x, P4_CRYPTO_P256_SCALAR_LEN);
        secret_clear(y, P4_CRYPTO_P256_SCALAR_LEN);
        return P4_CRYPTO_KEY;
    }
    memcpy(x, assert_fake_x, P4_CRYPTO_P256_SCALAR_LEN);
    memcpy(y, assert_fake_y, P4_CRYPTO_P256_SCALAR_LEN);
    return P4_CRYPTO_OK;
}


int p256_sign_hash(
    const uint8_t private_scalar[P4_CRYPTO_P256_SCALAR_LEN],
    const uint8_t hash[P4_CRYPTO_SHA256_LEN],
    uint8_t *signature,
    size_t signature_cap,
    size_t *signature_len)
{
    if (private_scalar == NULL || hash == NULL || signature == NULL ||
        signature_len == NULL || signature_cap < sizeof(s_assert_signature)) {
        if (signature_len != NULL) {
            *signature_len = 0;
        }
        return P4_CRYPTO_BAD_ARG;
    }
    if (memcmp(private_scalar, assert_fake_private,
               P4_CRYPTO_P256_SCALAR_LEN) != 0 ||
        memcmp(hash, s_assert_digest, sizeof(s_assert_digest)) != 0) {
        *signature_len = 0;
        return P4_CRYPTO_KEY;
    }
    assert_fake_sign_calls++;
    memcpy(signature, s_assert_signature, sizeof(s_assert_signature));
    *signature_len = sizeof(s_assert_signature);
    return P4_CRYPTO_OK;
}


int p256_verify_hash(
    const uint8_t x[P4_CRYPTO_P256_SCALAR_LEN],
    const uint8_t y[P4_CRYPTO_P256_SCALAR_LEN],
    const uint8_t hash[P4_CRYPTO_SHA256_LEN],
    const uint8_t *signature,
    size_t signature_len)
{
    bool matches = x != NULL && y != NULL && signature != NULL &&
        memcmp(x, assert_fake_x, P4_CRYPTO_P256_SCALAR_LEN) == 0 &&
        memcmp(y, assert_fake_y, P4_CRYPTO_P256_SCALAR_LEN) == 0 &&
        memcmp(hash, s_assert_digest, sizeof(s_assert_digest)) == 0 &&
        signature_len == sizeof(s_assert_signature) &&
        memcmp(signature, s_assert_signature,
               sizeof(s_assert_signature)) == 0;
    return matches ? P4_CRYPTO_OK : P4_CRYPTO_AUTH;
}


int rand_fill(uint8_t *out, size_t out_len)
{
    if (out == NULL || out_len != P4_CRYPTO_GCM_NONCE_LEN) {
        return P4_CRYPTO_BAD_ARG;
    }
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
    uint8_t expected[P4_CRYPTO_GCM_TAG_LEN] = {0};
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
    assert_fake_press_calls++;
    return s_press_result;
}


bool press_cancelled(uint32_t cid)
{
    return cid == 0;
}
