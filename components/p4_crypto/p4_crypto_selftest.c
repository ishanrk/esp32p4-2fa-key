#include "p4_crypto_test.h"

#include "p4_crypto.h"
#include "p4_crypto_bench.h"
#include "p4_crypto_priv.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "esp_heap_caps.h"
#include "esp_log.h"
#include "esp_memory_utils.h"
#include "esp_timer.h"
#include "psa/crypto.h"

#define NONCE_SAMPLE_COUNT 4096
#define TEST_CHECK(condition)          \
    do {                               \
        if (!(condition)) {            \
            result = __LINE__;         \
            goto cleanup;              \
        }                              \
    } while (0)

static const char *test_tag = "p4crypto";

// bounded storage exists only in the opt in test image
static uint8_t nonce_sample[NONCE_SAMPLE_COUNT][P4_CRYPTO_GCM_NONCE_LEN];

// nist aes 256 gcm known answer material
static const uint8_t zero_key[P4_CRYPTO_AES256_KEY_LEN] = {0};
static const uint8_t zero_nonce[P4_CRYPTO_GCM_NONCE_LEN] = {0};
static const uint8_t empty_tag[P4_CRYPTO_GCM_TAG_LEN] = {
    0x53, 0x0f, 0x8a, 0xfb, 0xc7, 0x45, 0x36, 0xb9,
    0xa9, 0x63, 0xb4, 0xf1, 0xc4, 0xcb, 0x73, 0x8b,
};
static const uint8_t zero16_cipher[16] = {
    0xce, 0xa7, 0x40, 0x3d, 0x4d, 0x60, 0x6b, 0x6e,
    0x07, 0x4e, 0xc5, 0xd3, 0xba, 0xf3, 0x9d, 0x18,
};
static const uint8_t zero16_tag[P4_CRYPTO_GCM_TAG_LEN] = {
    0xd0, 0xd1, 0xc8, 0xa7, 0x99, 0x99, 0x6b, 0xf0,
    0x26, 0x5b, 0x98, 0xb5, 0xd4, 0x8a, 0xb9, 0x19,
};

static const uint8_t gcm_key[P4_CRYPTO_AES256_KEY_LEN] = {
    0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c,
    0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08,
    0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c,
    0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08,
};
static const uint8_t gcm_nonce[P4_CRYPTO_GCM_NONCE_LEN] = {
    0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce,
    0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88,
};
static const uint8_t gcm_aad[20] = {
    0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef,
    0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef,
    0xab, 0xad, 0xda, 0xd2,
};
static const uint8_t gcm_plain[64] = {
    0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5,
    0xa5, 0x59, 0x09, 0xc5, 0xaf, 0xf5, 0x26, 0x9a,
    0x86, 0xa7, 0xa9, 0x53, 0x15, 0x34, 0xf7, 0xda,
    0x2e, 0x4c, 0x30, 0x3d, 0x8a, 0x31, 0x8a, 0x72,
    0x1c, 0x3c, 0x0c, 0x95, 0x95, 0x68, 0x09, 0x53,
    0x2f, 0xcf, 0x0e, 0x24, 0x49, 0xa6, 0xb5, 0x25,
    0xb1, 0x6a, 0xed, 0xf5, 0xaa, 0x0d, 0xe6, 0x57,
    0xba, 0x63, 0x7b, 0x39, 0x1a, 0xaf, 0xd2, 0x55,
};
static const uint8_t gcm_cipher[64] = {
    0x52, 0x2d, 0xc1, 0xf0, 0x99, 0x56, 0x7d, 0x07,
    0xf4, 0x7f, 0x37, 0xa3, 0x2a, 0x84, 0x42, 0x7d,
    0x64, 0x3a, 0x8c, 0xdc, 0xbf, 0xe5, 0xc0, 0xc9,
    0x75, 0x98, 0xa2, 0xbd, 0x25, 0x55, 0xd1, 0xaa,
    0x8c, 0xb0, 0x8e, 0x48, 0x59, 0x0d, 0xbb, 0x3d,
    0xa7, 0xb0, 0x8b, 0x10, 0x56, 0x82, 0x88, 0x38,
    0xc5, 0xf6, 0x1e, 0x63, 0x93, 0xba, 0x7a, 0x0a,
    0xbc, 0xc9, 0xf6, 0x62, 0x89, 0x80, 0x15, 0xad,
};
static const uint8_t gcm_multi_tag[P4_CRYPTO_GCM_TAG_LEN] = {
    0xb0, 0x94, 0xda, 0xc5, 0xd9, 0x34, 0x71, 0xbd,
    0xec, 0x1a, 0x50, 0x22, 0x70, 0xe3, 0xcc, 0x6c,
};
static const uint8_t gcm_aad_tag[P4_CRYPTO_GCM_TAG_LEN] = {
    0x76, 0xfc, 0x6e, 0xce, 0x0f, 0x4e, 0x17, 0x68,
    0xcd, 0xdf, 0x88, 0x53, 0xbb, 0x2d, 0x55, 0x1b,
};

// fixed sha 256 answers are compared but never logged
static const uint8_t sha_abc[P4_CRYPTO_SHA256_LEN] = {
    0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
    0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
    0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
    0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
};

static bool bytes_zero(const uint8_t *data, size_t len)
{
    // scan the full tentative plaintext region
    uint8_t found = 0;
    for (size_t i = 0; i < len; ++i) {
        found |= data[i];
    }
    return found == 0;
}

static int nonce_compare(const void *left, const void *right)
{
    // sorting keeps duplicate detection simple and bounded
    return memcmp(left, right, P4_CRYPTO_GCM_NONCE_LEN);
}

static int test_rng_lengths(void)
{
    // public random source boundary behavior
    int result = 0;
    uint8_t data[257] = {0x5a};

    TEST_CHECK(rand_fill(data, 0) == P4_CRYPTO_OK);
    TEST_CHECK(data[0] == 0x5a);
    TEST_CHECK(rand_fill(data, 1) == P4_CRYPTO_OK);
    TEST_CHECK(rand_fill(data, 31) == P4_CRYPTO_OK);
    TEST_CHECK(rand_fill(data, 32) == P4_CRYPTO_OK);
    TEST_CHECK(rand_fill(data, sizeof(data)) == P4_CRYPTO_OK);
    TEST_CHECK(rand_fill(NULL, 0) == P4_CRYPTO_BAD_ARG);

cleanup:
    secret_clear(data, sizeof(data));
    return result;
}


static int test_rng_consecutive(void)
{
    int result = 0;
    uint8_t first[32] = {0};
    uint8_t second[32] = {0};

    TEST_CHECK(rand_fill(first, sizeof(first)) == P4_CRYPTO_OK);
    TEST_CHECK(rand_fill(second, sizeof(second)) == P4_CRYPTO_OK);
    TEST_CHECK(memcmp(first, second, sizeof(first)) != 0);

cleanup:
    secret_clear(first, sizeof(first));
    secret_clear(second, sizeof(second));
    return result;
}

static int test_rng_nonce_smoke(void)
{
    // collision smoke does not claim entropy quality
    int result = 0;

    for (size_t i = 0; i < NONCE_SAMPLE_COUNT; ++i) {
        TEST_CHECK(rand_fill(nonce_sample[i], sizeof(nonce_sample[i])) ==
                   P4_CRYPTO_OK);
    }

    qsort(nonce_sample, NONCE_SAMPLE_COUNT, sizeof(nonce_sample[0]),
          nonce_compare);
    for (size_t i = 1; i < NONCE_SAMPLE_COUNT; ++i) {
        TEST_CHECK(memcmp(nonce_sample[i - 1], nonce_sample[i],
                          sizeof(nonce_sample[i])) != 0);
    }

cleanup:
    secret_clear(nonce_sample, sizeof(nonce_sample));
    return result;
}

static int test_sha_empty(void)
{
    // official empty message answer
    static const uint8_t expected[P4_CRYPTO_SHA256_LEN] = {
        0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
        0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
        0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
        0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
    };
    int result = 0;
    uint8_t digest[P4_CRYPTO_SHA256_LEN] = {0};

    TEST_CHECK(sha256_sum(NULL, 0, digest) == P4_CRYPTO_OK);
    TEST_CHECK(memcmp(digest, expected, sizeof(digest)) == 0);

cleanup:
    secret_clear(digest, sizeof(digest));
    return result;
}


static int test_sha_abc(void)
{
    int result = 0;
    uint8_t digest[P4_CRYPTO_SHA256_LEN] = {0};

    TEST_CHECK(sha256_sum((const uint8_t *)"abc", 3, digest) ==
               P4_CRYPTO_OK);
    TEST_CHECK(memcmp(digest, sha_abc, sizeof(digest)) == 0);

cleanup:
    secret_clear(digest, sizeof(digest));
    return result;
}


static int test_sha_block(void)
{
    static const uint8_t message[] =
        "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    static const uint8_t expected[P4_CRYPTO_SHA256_LEN] = {
        0x24, 0x8d, 0x6a, 0x61, 0xd2, 0x06, 0x38, 0xb8,
        0xe5, 0xc0, 0x26, 0x93, 0x0c, 0x3e, 0x60, 0x39,
        0xa3, 0x3c, 0xe4, 0x59, 0x64, 0xff, 0x21, 0x67,
        0xf6, 0xec, 0xed, 0xd4, 0x19, 0xdb, 0x06, 0xc1,
    };
    int result = 0;
    uint8_t digest[P4_CRYPTO_SHA256_LEN] = {0};

    TEST_CHECK(sha256_sum(message, sizeof(message) - 1, digest) ==
               P4_CRYPTO_OK);
    TEST_CHECK(memcmp(digest, expected, sizeof(digest)) == 0);

cleanup:
    secret_clear(digest, sizeof(digest));
    return result;
}


static int test_sha_multi(void)
{
    static const uint8_t expected[P4_CRYPTO_SHA256_LEN] = {
        0x41, 0xed, 0xec, 0xe4, 0x2d, 0x63, 0xe8, 0xd9,
        0xbf, 0x51, 0x5a, 0x9b, 0xa6, 0x93, 0x2e, 0x1c,
        0x20, 0xcb, 0xc9, 0xf5, 0xa5, 0xd1, 0x34, 0x64,
        0x5a, 0xdb, 0x5d, 0xb1, 0xb9, 0x73, 0x7e, 0xa3,
    };
    int result = 0;
    uint8_t input[1000];
    uint8_t digest[P4_CRYPTO_SHA256_LEN] = {0};

    memset(input, 'a', sizeof(input));
    TEST_CHECK(sha256_sum(input, sizeof(input), digest) == P4_CRYPTO_OK);
    TEST_CHECK(memcmp(digest, expected, sizeof(digest)) == 0);

cleanup:
    secret_clear(input, sizeof(input));
    secret_clear(digest, sizeof(digest));
    return result;
}


static int test_sha_precondition(void)
{
    int result = 0;
    uint8_t digest[P4_CRYPTO_SHA256_LEN];
    uint8_t before[P4_CRYPTO_SHA256_LEN];

    memset(digest, 0x5a, sizeof(digest));
    memcpy(before, digest, sizeof(before));
    TEST_CHECK(sha256_sum(NULL, 1, digest) == P4_CRYPTO_BAD_ARG);
    TEST_CHECK(memcmp(digest, before, sizeof(digest)) == 0);

cleanup:
    secret_clear(digest, sizeof(digest));
    secret_clear(before, sizeof(before));
    return result;
}

static int gcm_vector(const uint8_t key[32], const uint8_t nonce[12],
                      const uint8_t *aad, size_t aad_len,
                      const uint8_t *plain, size_t plain_len,
                      const uint8_t *expected_cipher,
                      const uint8_t expected_tag[16])
{
    // seal then authenticate and open the same known answer
    int result = 0;
    uint8_t cipher[64] = {0};
    uint8_t opened[64] = {0};
    uint8_t tag[16] = {0};

    TEST_CHECK(plain_len <= sizeof(cipher));
    TEST_CHECK(gcm_seal(key, nonce, aad, aad_len, plain, plain_len,
                        cipher, tag) == P4_CRYPTO_OK);
    TEST_CHECK(plain_len == 0 ||
               memcmp(cipher, expected_cipher, plain_len) == 0);
    TEST_CHECK(memcmp(tag, expected_tag, sizeof(tag)) == 0);
    TEST_CHECK(gcm_open(key, nonce, aad, aad_len, cipher, plain_len,
                        tag, opened) == P4_CRYPTO_OK);
    TEST_CHECK(plain_len == 0 || memcmp(opened, plain, plain_len) == 0);

cleanup:
    secret_clear(cipher, sizeof(cipher));
    secret_clear(opened, sizeof(opened));
    secret_clear(tag, sizeof(tag));
    return result;
}


static int test_gcm_empty(void)
{
    uint8_t dummy = 0;
    return gcm_vector(zero_key, zero_nonce, NULL, 0, NULL, 0,
                      &dummy, empty_tag);
}


static int test_gcm_plain(void)
{
    static const uint8_t plain[16] = {0};
    return gcm_vector(zero_key, zero_nonce, NULL, 0,
                      plain, sizeof(plain), zero16_cipher, zero16_tag);
}


static int test_gcm_multi(void)
{
    return gcm_vector(gcm_key, gcm_nonce, NULL, 0,
                      gcm_plain, sizeof(gcm_plain),
                      gcm_cipher, gcm_multi_tag);
}


static int test_gcm_aad(void)
{
    return gcm_vector(gcm_key, gcm_nonce, gcm_aad, sizeof(gcm_aad),
                      gcm_plain, 60, gcm_cipher, gcm_aad_tag);
}

static bool auth_clears(const uint8_t key[32], const uint8_t nonce[12],
                        const uint8_t *aad, size_t aad_len,
                        const uint8_t *cipher, size_t cipher_len,
                        const uint8_t tag[16])
{
    // no unauthenticated bytes may reach the caller
    uint8_t opened[64];
    memset(opened, 0xa5, sizeof(opened));

    int status = gcm_open(key, nonce, aad, aad_len, cipher, cipher_len,
                          tag, opened);
    bool passed = status == P4_CRYPTO_AUTH &&
                  bytes_zero(opened, cipher_len);
    secret_clear(opened, sizeof(opened));
    return passed;
}


static int test_gcm_tamper(void)
{
    int result = 0;
    uint8_t key[32];
    uint8_t nonce[12];
    uint8_t aad[20];
    uint8_t cipher[60];
    uint8_t tag[16];

    memcpy(key, gcm_key, sizeof(key));
    memcpy(nonce, gcm_nonce, sizeof(nonce));
    memcpy(aad, gcm_aad, sizeof(aad));
    memcpy(cipher, gcm_cipher, sizeof(cipher));
    memcpy(tag, gcm_aad_tag, sizeof(tag));

    nonce[0] ^= 1;
    TEST_CHECK(auth_clears(key, nonce, aad, sizeof(aad),
                           cipher, sizeof(cipher), tag));
    nonce[0] ^= 1;

    aad[0] ^= 1;
    TEST_CHECK(auth_clears(key, nonce, aad, sizeof(aad),
                           cipher, sizeof(cipher), tag));
    aad[0] ^= 1;

    cipher[0] ^= 1;
    TEST_CHECK(auth_clears(key, nonce, aad, sizeof(aad),
                           cipher, sizeof(cipher), tag));
    cipher[0] ^= 1;

    tag[0] ^= 1;
    TEST_CHECK(auth_clears(key, nonce, aad, sizeof(aad),
                           cipher, sizeof(cipher), tag));
    tag[0] ^= 1;

    key[0] ^= 1;
    TEST_CHECK(auth_clears(key, nonce, aad, sizeof(aad),
                           cipher, sizeof(cipher), tag));

cleanup:
    secret_clear(key, sizeof(key));
    secret_clear(nonce, sizeof(nonce));
    secret_clear(aad, sizeof(aad));
    secret_clear(cipher, sizeof(cipher));
    secret_clear(tag, sizeof(tag));
    return result;
}


static int test_gcm_zero_open(void)
{
    int result = 0;
    uint8_t dummy = 0x5a;

    TEST_CHECK(gcm_open(zero_key, zero_nonce, NULL, 0, NULL, 0,
                        empty_tag, &dummy) == P4_CRYPTO_OK);
    TEST_CHECK(dummy == 0x5a);

cleanup:
    return result;
}


static int test_gcm_alias(void)
{
    int result = 0;
    uint8_t data[40] = {0};
    uint8_t tag[16] = {0};

    TEST_CHECK(gcm_seal(zero_key, zero_nonce, NULL, 0,
                        data, 16, data, tag) == P4_CRYPTO_OVERLAP);
    TEST_CHECK(gcm_seal(zero_key, zero_nonce, NULL, 0,
                        data, 16, data + 1, tag) == P4_CRYPTO_OVERLAP);
    TEST_CHECK(gcm_seal(zero_key, zero_nonce, NULL, 0,
                        data, 16, data + 16, data + 20) ==
               P4_CRYPTO_OVERLAP);
    TEST_CHECK(gcm_open(zero_key, zero_nonce, NULL, 0,
                        zero16_cipher, 16, zero16_tag, data) ==
               P4_CRYPTO_OK);
    TEST_CHECK(gcm_open(zero_key, zero_nonce, NULL, 0,
                        data, 16, zero16_tag, data) == P4_CRYPTO_OVERLAP);
    TEST_CHECK(gcm_open(zero_key, zero_nonce, NULL, 0,
                        data, 16, zero16_tag, data + 1) ==
               P4_CRYPTO_OVERLAP);

cleanup:
    secret_clear(data, sizeof(data));
    secret_clear(tag, sizeof(tag));
    return result;
}

static int test_gcm_hw_one_shot(void)
{
    // proof only route meets the pinned dma branch conditions
    int result = 0;
    uint8_t *input = NULL;
    uint8_t *output = NULL;
    size_t output_len = 0;
    psa_key_id_t key_id = 0;
    bool key_live = false;
    psa_status_t status = PSA_SUCCESS;

    input = heap_caps_malloc(sizeof(gcm_plain),
                             MALLOC_CAP_DMA | MALLOC_CAP_INTERNAL);
    output = heap_caps_malloc(sizeof(gcm_cipher) + sizeof(gcm_multi_tag),
                              MALLOC_CAP_DMA | MALLOC_CAP_INTERNAL);
    TEST_CHECK(input != NULL && output != NULL);
    TEST_CHECK(esp_ptr_dma_capable(input));
    TEST_CHECK(esp_ptr_dma_capable(output));
    memcpy(input, gcm_plain, sizeof(gcm_plain));

    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attr, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attr, 256);
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_ENCRYPT);
    psa_set_key_algorithm(&attr, PSA_ALG_GCM);
    status = psa_import_key(&attr, gcm_key, sizeof(gcm_key), &key_id);
    psa_reset_key_attributes(&attr);
    if (status != PSA_SUCCESS) {
        p4_crypto_detail_set((int)status);
    }
    TEST_CHECK(status == PSA_SUCCESS);
    key_live = true;

    status = psa_aead_encrypt(
        key_id, PSA_ALG_GCM, gcm_nonce, sizeof(gcm_nonce),
        NULL, 0, input, sizeof(gcm_plain), output,
        sizeof(gcm_cipher) + sizeof(gcm_multi_tag), &output_len);
    if (status != PSA_SUCCESS) {
        p4_crypto_detail_set((int)status);
    }
    TEST_CHECK(status == PSA_SUCCESS);
    TEST_CHECK(output_len == sizeof(gcm_cipher) + sizeof(gcm_multi_tag));
    TEST_CHECK(memcmp(output, gcm_cipher, sizeof(gcm_cipher)) == 0);
    TEST_CHECK(memcmp(output + sizeof(gcm_cipher), gcm_multi_tag,
                      sizeof(gcm_multi_tag)) == 0);

cleanup:
    p4_crypto_key_drop(key_id, key_live, &status);
    if (status != PSA_SUCCESS) {
        p4_crypto_detail_set((int)status);
        if (result == 0) {
            result = __LINE__;
        }
    }
    if (input != NULL) {
        secret_clear(input, sizeof(gcm_plain));
        heap_caps_free(input);
    }
    if (output != NULL) {
        secret_clear(output, sizeof(gcm_cipher) + sizeof(gcm_multi_tag));
        heap_caps_free(output);
    }
    return result;
}

static const uint8_t p256_gx[32] = {
    // generator x in big endian form
    0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47,
    0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4, 0x40, 0xf2,
    0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0,
    0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98, 0xc2, 0x96,
};
static const uint8_t p256_gy[32] = {
    0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b,
    0x8e, 0xe7, 0xeb, 0x4a, 0x7c, 0x0f, 0x9e, 0x16,
    0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce,
    0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf, 0x51, 0xf5,
};
static const uint8_t p256_order[32] = {
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84,
    0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
};

static int test_p256_scalars(void)
{
    // fixed boundary values plus authoritative psa import
    int result = 0;
    uint8_t scalar[32] = {0};
    uint8_t x[32] = {0};
    uint8_t y[32] = {0};

    TEST_CHECK(p256_pub(scalar, x, y) == P4_CRYPTO_KEY);
    scalar[31] = 1;
    TEST_CHECK(p256_pub(scalar, x, y) == P4_CRYPTO_OK);
    TEST_CHECK(memcmp(x, p256_gx, sizeof(x)) == 0);
    TEST_CHECK(memcmp(y, p256_gy, sizeof(y)) == 0);

    memcpy(scalar, p256_order, sizeof(scalar));
    scalar[31]--;
    TEST_CHECK(p256_pub(scalar, x, y) == P4_CRYPTO_OK);
    memcpy(scalar, p256_order, sizeof(scalar));
    TEST_CHECK(p256_pub(scalar, x, y) == P4_CRYPTO_KEY);
    memset(scalar, 0xff, sizeof(scalar));
    TEST_CHECK(p256_pub(scalar, x, y) == P4_CRYPTO_KEY);

cleanup:
    secret_clear(scalar, sizeof(scalar));
    secret_clear(x, sizeof(x));
    secret_clear(y, sizeof(y));
    return result;
}


static int test_p256_generate(void)
{
    int result = 0;
    uint8_t priv[32] = {0};
    uint8_t x[32] = {0};
    uint8_t y[32] = {0};
    uint8_t x_again[32] = {0};
    uint8_t y_again[32] = {0};

    TEST_CHECK(p256_make(priv, x, y) == P4_CRYPTO_OK);
    TEST_CHECK(p256_pub(priv, x_again, y_again) == P4_CRYPTO_OK);
    TEST_CHECK(memcmp(x, x_again, sizeof(x)) == 0);
    TEST_CHECK(memcmp(y, y_again, sizeof(y)) == 0);

cleanup:
    secret_clear(priv, sizeof(priv));
    secret_clear(x, sizeof(x));
    secret_clear(y, sizeof(y));
    secret_clear(x_again, sizeof(x_again));
    secret_clear(y_again, sizeof(y_again));
    return result;
}

static int make_signature(uint8_t priv[32], uint8_t x[32], uint8_t y[32],
                          uint8_t sig[72], size_t *sig_len)
{
    // generated values remain inside the calling test
    if (p256_make(priv, x, y) != P4_CRYPTO_OK) {
        return 1;
    }
    if (p256_sign_hash(priv, sha_abc, sig, 72, sig_len) != P4_CRYPTO_OK) {
        return 1;
    }
    return 0;
}


static int test_p256_sign(void)
{
    int result = 0;
    uint8_t priv[32] = {0};
    uint8_t x[32] = {0};
    uint8_t y[32] = {0};
    uint8_t sig[72] = {0};
    size_t sig_len = 0;

    TEST_CHECK(make_signature(priv, x, y, sig, &sig_len) == 0);
    TEST_CHECK(sig_len >= 8 && sig_len <= sizeof(sig));
    TEST_CHECK(p256_verify_hash(x, y, sha_abc, sig, sig_len) ==
               P4_CRYPTO_OK);

cleanup:
    secret_clear(priv, sizeof(priv));
    secret_clear(x, sizeof(x));
    secret_clear(y, sizeof(y));
    secret_clear(sig, sizeof(sig));
    return result;
}


static int test_p256_negative(void)
{
    int result = 0;
    uint8_t priv[32] = {0};
    uint8_t x[32] = {0};
    uint8_t y[32] = {0};
    uint8_t hash[32];
    uint8_t sig[72] = {0};
    size_t sig_len = 0;

    memcpy(hash, sha_abc, sizeof(hash));
    TEST_CHECK(make_signature(priv, x, y, sig, &sig_len) == 0);
    TEST_CHECK(sig_len >= 8 && sig_len <= sizeof(sig));

    hash[0] ^= 1;
    TEST_CHECK(p256_verify_hash(x, y, hash, sig, sig_len) ==
               P4_CRYPTO_AUTH);
    hash[0] ^= 1;

    sig[sig_len - 1] ^= 1;
    TEST_CHECK(p256_verify_hash(x, y, hash, sig, sig_len) !=
               P4_CRYPTO_OK);
    sig[sig_len - 1] ^= 1;

    x[0] ^= 1;
    TEST_CHECK(p256_verify_hash(x, y, hash, sig, sig_len) !=
               P4_CRYPTO_OK);

cleanup:
    secret_clear(priv, sizeof(priv));
    secret_clear(x, sizeof(x));
    secret_clear(y, sizeof(y));
    secret_clear(hash, sizeof(hash));
    secret_clear(sig, sizeof(sig));
    return result;
}


static int test_p256_der(void)
{
    int result = 0;
    uint8_t priv[32] = {0};
    uint8_t x[32] = {0};
    uint8_t y[32] = {0};
    uint8_t sig[73];
    uint8_t before[72];
    size_t sig_len = 9;

    TEST_CHECK(p256_make(priv, x, y) == P4_CRYPTO_OK);
    memset(sig, 0x5a, sizeof(sig));
    memcpy(before, sig, sizeof(before));
    TEST_CHECK(p256_sign_hash(priv, sha_abc, sig, 71, &sig_len) ==
               P4_CRYPTO_SMALL);
    TEST_CHECK(sig_len == 0);
    TEST_CHECK(memcmp(sig, before, sizeof(before)) == 0);

    TEST_CHECK(p256_sign_hash(priv, sha_abc, sig, 72, &sig_len) ==
               P4_CRYPTO_OK);
    TEST_CHECK(sig_len < sizeof(sig));
    sig[sig_len] = 0;
    TEST_CHECK(p256_verify_hash(x, y, sha_abc, sig, sig_len + 1) ==
               P4_CRYPTO_DER);

cleanup:
    secret_clear(priv, sizeof(priv));
    secret_clear(x, sizeof(x));
    secret_clear(y, sizeof(y));
    secret_clear(sig, sizeof(sig));
    secret_clear(before, sizeof(before));
    return result;
}


static int test_p256_repeat(void)
{
    int result = 0;
    uint8_t priv[32] = {0};
    uint8_t x[32] = {0};
    uint8_t y[32] = {0};
    uint8_t sig[72] = {0};

    TEST_CHECK(p256_make(priv, x, y) == P4_CRYPTO_OK);
    for (size_t i = 0; i < 4; ++i) {
        size_t sig_len = 0;
        TEST_CHECK(p256_sign_hash(priv, sha_abc, sig, sizeof(sig),
                                  &sig_len) == P4_CRYPTO_OK);
        TEST_CHECK(p256_verify_hash(x, y, sha_abc, sig, sig_len) ==
                   P4_CRYPTO_OK);
        secret_clear(sig, sizeof(sig));
    }

cleanup:
    secret_clear(priv, sizeof(priv));
    secret_clear(x, sizeof(x));
    secret_clear(y, sizeof(y));
    secret_clear(sig, sizeof(sig));
    return result;
}


static int test_p256_siglen_alias(void)
{
    union {
        size_t aligned;
        uint8_t bytes[32];
    } key = {0};
    int result = 0;
    uint8_t before[32] = {0};
    uint8_t sig[72] = {0};

    key.bytes[31] = 1;
    memcpy(before, key.bytes, sizeof(before));
    TEST_CHECK(p256_sign_hash(key.bytes, sha_abc, sig, sizeof(sig),
                              (size_t *)key.bytes) == P4_CRYPTO_OVERLAP);
    TEST_CHECK(memcmp(key.bytes, before, sizeof(before)) == 0);

cleanup:
    secret_clear(key.bytes, sizeof(key.bytes));
    secret_clear(before, sizeof(before));
    secret_clear(sig, sizeof(sig));
    return result;
}


typedef int (*test_fn)(void);

struct test_case {
    const char *name;
    test_fn run;
};

static bool run_case(const struct test_case *test)
{
    // values never enter target logs
    int64_t start = esp_timer_get_time();
    int status = test->run();
    int64_t elapsed = esp_timer_get_time() - start;

    if (status == 0) {
        ESP_LOGI(test_tag, "CRYPTO_TEST %s PASS us=%lld",
                 test->name, (long long)elapsed);
        return true;
    }

    ESP_LOGE(test_tag,
             "CRYPTO_TEST %s FAIL code=%d detail=%d us=%lld",
             test->name, status, p4_crypto_last_detail(),
             (long long)elapsed);
    return false;
}

int p4_crypto_selftest_run(void)
{
    // one bounded pass for an explicitly enabled test boot
    static const struct test_case tests[] = {
        {"rng_lengths", test_rng_lengths},
        {"rng_consecutive", test_rng_consecutive},
        {"rng_nonce_smoke", test_rng_nonce_smoke},
        {"sha_empty", test_sha_empty},
        {"sha_abc", test_sha_abc},
        {"sha_block", test_sha_block},
        {"sha_multi", test_sha_multi},
        {"sha_precondition", test_sha_precondition},
        {"gcm_empty", test_gcm_empty},
        {"gcm_plain", test_gcm_plain},
        {"gcm_multi", test_gcm_multi},
        {"gcm_aad", test_gcm_aad},
        {"gcm_tamper", test_gcm_tamper},
        {"gcm_zero_open", test_gcm_zero_open},
        {"gcm_alias", test_gcm_alias},
        {"gcm_hw_one_shot", test_gcm_hw_one_shot},
        {"p256_scalars", test_p256_scalars},
        {"p256_generate", test_p256_generate},
        {"p256_sign", test_p256_sign},
        {"p256_negative", test_p256_negative},
        {"p256_der", test_p256_der},
        {"p256_repeat", test_p256_repeat},
        {"p256_siglen_alias", test_p256_siglen_alias},
    };
    size_t passed = 0;

    ESP_LOGI(test_tag, "CRYPTO_SELFTEST START tests=%u",
             (unsigned)(sizeof(tests) / sizeof(tests[0])));
    for (size_t i = 0; i < sizeof(tests) / sizeof(tests[0]); ++i) {
        if (run_case(&tests[i])) {
            passed++;
        }
    }

    if (passed != sizeof(tests) / sizeof(tests[0])) {
        ESP_LOGE(test_tag, "CRYPTO_SELFTEST FAIL passed=%u total=%u",
                 (unsigned)passed,
                 (unsigned)(sizeof(tests) / sizeof(tests[0])));
        return 1;
    }

    ESP_LOGI(test_tag, "CRYPTO_SELFTEST PASS tests=%u", (unsigned)passed);
#if CONFIG_P4KEY_CRYPTO_BENCH
    if (p4_crypto_bench_run() != 0) {
        return 1;
    }
#endif
    return 0;
}
