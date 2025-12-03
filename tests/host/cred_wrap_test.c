#include "p4_aaguid.h"
#include "p4_cred.h"
#include "p4_cred_priv.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "p4_crypto.h"


enum {
    HEADER_LEN = 8,
    NONCE_OFFSET = 8,
    CIPHER_OFFSET = 20,
    CIPHER_LEN = 64,
    TAG_OFFSET = 84,
    AAD_LEN = 24,
};


static const uint8_t s_expected_header[HEADER_LEN] = {
    'P', '4', 'K', '1', 1, 1, 0, 0,
};
static const uint8_t s_root[P4_CRYPTO_AES256_KEY_LEN] = {
    0x91, 0x82, 0x73, 0x64, 0x55, 0x46, 0x37, 0x28,
    0x19, 0x0a, 0xfb, 0xec, 0xdd, 0xce, 0xbf, 0xa0,
    0x12, 0x24, 0x36, 0x48, 0x5a, 0x6c, 0x7e, 0x80,
    0x92, 0xa4, 0xb6, 0xc8, 0xda, 0xec, 0xfe, 0x10,
};


static unsigned s_rand_calls;
static unsigned s_root_calls;
static unsigned s_seal_calls;
static unsigned s_open_calls;
static uint8_t s_last_aad[AAD_LEN];
static uint8_t s_last_plain[CIPHER_LEN];


static void fail(const char *name, int line)
{
    fprintf(stderr, "FAIL %s line %d\n", name, line);
    exit(1);
}

#define CHECK(value) do { if (!(value)) fail(__func__, __LINE__); } while (0)


static bool all_zero(const uint8_t *bytes, size_t len)
{
    uint8_t value = 0;
    for (size_t index = 0; index < len; index++) {
        value |= bytes[index];
    }
    return value == 0;
}


void secret_clear(void *ptr, size_t len)
{
    if (ptr != NULL) {
        volatile uint8_t *bytes = ptr;
        while (len-- != 0) {
            *bytes++ = 0;
        }
    }
}


int p4_root_load(uint8_t root[P4_CRYPTO_AES256_KEY_LEN])
{
    s_root_calls++;
    memcpy(root, s_root, sizeof(s_root));
    return P4_CRED_OK;
}


int rand_fill(uint8_t *out, size_t out_len)
{
    CHECK(out != NULL);
    CHECK(out_len == P4_CRYPTO_GCM_NONCE_LEN);
    s_rand_calls++;
    for (size_t index = 0; index < out_len; index++) {
        out[index] = (uint8_t)(0x40U + index);
    }
    return P4_CRYPTO_OK;
}


int p256_pub(const uint8_t priv[P4_CRYPTO_P256_SCALAR_LEN],
             uint8_t x[P4_CRYPTO_P256_SCALAR_LEN],
             uint8_t y[P4_CRYPTO_P256_SCALAR_LEN])
{
    if (all_zero(priv, P4_CRYPTO_P256_SCALAR_LEN)) {
        memset(x, 0, P4_CRYPTO_P256_SCALAR_LEN);
        memset(y, 0, P4_CRYPTO_P256_SCALAR_LEN);
        return P4_CRYPTO_KEY;
    }
    for (size_t index = 0; index < P4_CRYPTO_P256_SCALAR_LEN; index++) {
        x[index] = (uint8_t)(priv[index] ^ 0x55U);
        y[index] = (uint8_t)(priv[index] ^ 0xaaU);
    }
    return P4_CRYPTO_OK;
}


static void make_tag(const uint8_t key[P4_CRYPTO_AES256_KEY_LEN],
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
    CHECK(aad_len == AAD_LEN);
    CHECK(plain_len == CIPHER_LEN);
    s_seal_calls++;
    memcpy(s_last_aad, aad, aad_len);
    memcpy(s_last_plain, plain, plain_len);
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
    CHECK(aad_len == AAD_LEN);
    CHECK(cipher_len == CIPHER_LEN);
    s_open_calls++;
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


static void fill_inputs(uint8_t rp[P4_CRED_RP_ID_HASH_LEN],
                        uint8_t scalar[P4_CRED_PRIVATE_SCALAR_LEN])
{
    for (size_t index = 0; index < P4_CRED_RP_ID_HASH_LEN; index++) {
        rp[index] = (uint8_t)(index * 7U + 3U);
        scalar[index] = (uint8_t)(index + 1U);
    }
}


static void expect_mismatch(const uint8_t *rp,
                            const uint8_t *credential,
                            size_t credential_len,
                            int expected)
{
    uint8_t output[P4_CRED_PRIVATE_SCALAR_LEN];
    memset(output, 0x5a, sizeof(output));
    CHECK(cred_open(rp, P4_CRED_RP_ID_HASH_LEN,
                    credential, credential_len,
                    output, sizeof(output)) == expected);
    CHECK(all_zero(output, sizeof(output)));
}


static void test_format_round_trip_and_tamper(void)
{
    uint8_t rp[P4_CRED_RP_ID_HASH_LEN];
    uint8_t scalar[P4_CRED_PRIVATE_SCALAR_LEN];
    uint8_t credential[P4_CRED_ID_LEN];
    fill_inputs(rp, scalar);
    memset(credential, 0x5a, sizeof(credential));

    CHECK(cred_wrap(rp, sizeof(rp), scalar, sizeof(scalar),
                    credential, sizeof(credential)) == P4_CRED_OK);
    CHECK(sizeof(credential) == 100);
    CHECK(memcmp(credential, s_expected_header,
                 sizeof(s_expected_header)) == 0);
    for (size_t index = 0; index < P4_CRYPTO_GCM_NONCE_LEN; index++) {
        CHECK(credential[NONCE_OFFSET + index] == (uint8_t)(0x40U + index));
    }
    CHECK(s_rand_calls == 1 && s_root_calls == 1 && s_seal_calls == 1);
    CHECK(memcmp(s_last_plain, rp, sizeof(rp)) == 0);
    CHECK(memcmp(s_last_plain + sizeof(rp), scalar, sizeof(scalar)) == 0);
    CHECK(memcmp(s_last_aad, s_expected_header, HEADER_LEN) == 0);
    CHECK(memcmp(s_last_aad + HEADER_LEN,
                 p4_aaguid, P4_AAGUID_LEN) == 0);

    uint8_t opened[P4_CRED_PRIVATE_SCALAR_LEN];
    memset(opened, 0x5a, sizeof(opened));
    CHECK(cred_open(rp, sizeof(rp), credential, sizeof(credential),
                    opened, sizeof(opened)) == P4_CRED_OK);
    CHECK(memcmp(opened, scalar, sizeof(opened)) == 0);

    int generic = P4_CRED_ERR_MISMATCH;
    uint8_t wrong_rp[sizeof(rp)];
    memcpy(wrong_rp, rp, sizeof(wrong_rp));
    wrong_rp[0] ^= 1U;
    expect_mismatch(wrong_rp, credential, sizeof(credential), generic);

    uint8_t modified[P4_CRED_ID_LEN];
    memcpy(modified, credential, sizeof(modified));
    modified[CIPHER_OFFSET + 7] ^= 1U;
    expect_mismatch(rp, modified, sizeof(modified), generic);
    memcpy(modified, credential, sizeof(modified));
    modified[TAG_OFFSET + 5] ^= 1U;
    expect_mismatch(rp, modified, sizeof(modified), generic);

    expect_mismatch(rp, credential, P4_CRED_ID_LEN - 1, generic);
    uint8_t longer[P4_CRED_ID_LEN + 1];
    memcpy(longer, credential, sizeof(credential));
    longer[P4_CRED_ID_LEN] = 0;
    expect_mismatch(rp, longer, sizeof(longer), generic);
    CHECK(s_open_calls == 4);

    secret_clear(opened, sizeof(opened));
    secret_clear(scalar, sizeof(scalar));
    secret_clear(credential, sizeof(credential));
    secret_clear(modified, sizeof(modified));
    secret_clear(longer, sizeof(longer));
}


static void test_zero_scalar_fails(void)
{
    uint8_t rp[P4_CRED_RP_ID_HASH_LEN];
    uint8_t scalar[P4_CRED_PRIVATE_SCALAR_LEN];
    fill_inputs(rp, scalar);
    memset(scalar, 0, sizeof(scalar));
    uint8_t credential[P4_CRED_ID_LEN];
    memset(credential, 0x5a, sizeof(credential));

    unsigned rand_before = s_rand_calls;
    unsigned root_before = s_root_calls;
    unsigned seal_before = s_seal_calls;
    CHECK(cred_wrap(rp, sizeof(rp), scalar, sizeof(scalar),
                    credential, sizeof(credential)) == P4_CRED_ERR_KEY);
    CHECK(all_zero(credential, sizeof(credential)));
    CHECK(s_rand_calls == rand_before);
    CHECK(s_root_calls == root_before);
    CHECK(s_seal_calls == seal_before);
}


static void test_authenticated_zero_scalar_is_generic(void)
{
    uint8_t rp[P4_CRED_RP_ID_HASH_LEN];
    uint8_t unused_scalar[P4_CRED_PRIVATE_SCALAR_LEN];
    fill_inputs(rp, unused_scalar);

    uint8_t credential[P4_CRED_ID_LEN] = {0};
    memcpy(credential, s_expected_header, HEADER_LEN);
    for (size_t index = 0; index < P4_CRYPTO_GCM_NONCE_LEN; index++) {
        credential[NONCE_OFFSET + index] = (uint8_t)(0x70U + index);
    }
    uint8_t aad[AAD_LEN];
    memcpy(aad, s_expected_header, HEADER_LEN);
    memcpy(aad + HEADER_LEN, p4_aaguid, P4_AAGUID_LEN);
    uint8_t plain[CIPHER_LEN] = {0};
    memcpy(plain, rp, sizeof(rp));
    CHECK(gcm_seal(s_root, credential + NONCE_OFFSET,
                   aad, sizeof(aad), plain, sizeof(plain),
                   credential + CIPHER_OFFSET,
                   credential + TAG_OFFSET) == P4_CRYPTO_OK);

    expect_mismatch(rp, credential, sizeof(credential),
                    P4_CRED_ERR_MISMATCH);
    secret_clear(plain, sizeof(plain));
    secret_clear(credential, sizeof(credential));
}


int main(void)
{
    CHECK(P4_CRED_ID_LEN == 100);
    CHECK(P4_AAGUID_LEN == 16);
    test_format_round_trip_and_tamper();
    test_zero_scalar_fails();
    test_authenticated_zero_scalar_is_generic();
    puts("PASS exact wrapped credential format and failures");
    return 0;
}
