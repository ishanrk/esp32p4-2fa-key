#include "p4_cred.h"
#include "p4_cred_priv.h"

#include <stdbool.h>
#include <string.h>

#include "p4_aaguid.h"
#include "p4_crypto.h"


enum {
    CRED_HEADER_LEN = 8,
    CRED_NONCE_OFFSET = 8,
    CRED_NONCE_LEN = P4_CRYPTO_GCM_NONCE_LEN,
    CRED_CIPHER_OFFSET = 20,
    CRED_CIPHER_LEN = 64,
    CRED_TAG_OFFSET = 84,
    CRED_TAG_LEN = P4_CRYPTO_GCM_TAG_LEN,
    CRED_AAD_LEN = CRED_HEADER_LEN + P4_AAGUID_LEN,
};


static const uint8_t s_header[CRED_HEADER_LEN] = {
    'P', '4', 'K', '1', 1, 1, 0, 0,
};


_Static_assert(CRED_NONCE_OFFSET + CRED_NONCE_LEN == CRED_CIPHER_OFFSET,
               "credential nonce layout");
_Static_assert(CRED_CIPHER_OFFSET + CRED_CIPHER_LEN == CRED_TAG_OFFSET,
               "credential ciphertext layout");
_Static_assert(CRED_TAG_OFFSET + CRED_TAG_LEN == P4_CRED_ID_LEN,
               "credential tag layout");
_Static_assert(P4_CRED_RP_ID_HASH_LEN + P4_CRED_PRIVATE_SCALAR_LEN ==
               CRED_CIPHER_LEN, "credential plaintext layout");


static void clear_prefix(uint8_t *out, size_t out_cap, size_t needed)
{
    if (out != NULL) {
        secret_clear(out, out_cap < needed ? out_cap : needed);
    }
}


static bool equal_hash(const uint8_t left[P4_CRED_RP_ID_HASH_LEN],
                       const uint8_t right[P4_CRED_RP_ID_HASH_LEN])
{
    uint32_t different = 0;
    for (size_t index = 0; index < P4_CRED_RP_ID_HASH_LEN; index++) {
        different |= (uint32_t)(left[index] ^ right[index]);
    }
    return different == 0;
}


static int scalar_check(const uint8_t scalar[P4_CRED_PRIVATE_SCALAR_LEN],
                        bool mismatch_on_key)
{
    uint8_t x[P4_CRYPTO_P256_SCALAR_LEN] = {0};
    uint8_t y[P4_CRYPTO_P256_SCALAR_LEN] = {0};
    int err = p256_pub(scalar, x, y);
    secret_clear(x, sizeof(x));
    secret_clear(y, sizeof(y));

    if (err == P4_CRYPTO_OK) {
        return P4_CRED_OK;
    }
    if (err == P4_CRYPTO_KEY) {
        return mismatch_on_key ? P4_CRED_ERR_MISMATCH : P4_CRED_ERR_KEY;
    }
    return P4_CRED_ERR_CRYPTO;
}


int cred_wrap(const uint8_t *rp_id_hash,
              size_t rp_id_hash_len,
              const uint8_t *private_scalar,
              size_t private_scalar_len,
              uint8_t *credential_id,
              size_t credential_id_cap)
{
    if (rp_id_hash == NULL || private_scalar == NULL ||
        credential_id == NULL ||
        rp_id_hash_len != P4_CRED_RP_ID_HASH_LEN ||
        private_scalar_len != P4_CRED_PRIVATE_SCALAR_LEN) {
        clear_prefix(credential_id, credential_id_cap, P4_CRED_ID_LEN);
        return P4_CRED_ERR_ARG;
    }
    if (credential_id_cap < P4_CRED_ID_LEN) {
        clear_prefix(credential_id, credential_id_cap, P4_CRED_ID_LEN);
        return P4_CRED_ERR_SMALL;
    }

    int result = scalar_check(private_scalar, false);
    if (result != P4_CRED_OK) {
        clear_prefix(credential_id, credential_id_cap, P4_CRED_ID_LEN);
        return result;
    }

    uint8_t root[P4_CRYPTO_AES256_KEY_LEN] = {0};
    uint8_t nonce[CRED_NONCE_LEN] = {0};
    uint8_t plain[CRED_CIPHER_LEN] = {0};
    uint8_t aad[CRED_AAD_LEN] = {0};
    uint8_t wrapped[P4_CRED_ID_LEN] = {0};

    memcpy(plain, rp_id_hash, P4_CRED_RP_ID_HASH_LEN);
    memcpy(plain + P4_CRED_RP_ID_HASH_LEN,
           private_scalar, P4_CRED_PRIVATE_SCALAR_LEN);
    memcpy(aad, s_header, sizeof(s_header));
    memcpy(aad + sizeof(s_header), p4_aaguid, P4_AAGUID_LEN);
    memcpy(wrapped, s_header, sizeof(s_header));

    if (rand_fill(nonce, sizeof(nonce)) != P4_CRYPTO_OK) {
        result = P4_CRED_ERR_CRYPTO;
        goto out;
    }
    if (p4_root_load(root) != P4_CRED_OK) {
        result = P4_CRED_ERR_ROOT;
        goto out;
    }
    memcpy(wrapped + CRED_NONCE_OFFSET, nonce, sizeof(nonce));

    if (gcm_seal(root, nonce, aad, sizeof(aad),
                 plain, sizeof(plain),
                 wrapped + CRED_CIPHER_OFFSET,
                 wrapped + CRED_TAG_OFFSET) != P4_CRYPTO_OK) {
        result = P4_CRED_ERR_CRYPTO;
        goto out;
    }

    memcpy(credential_id, wrapped, sizeof(wrapped));
    result = P4_CRED_OK;

out:
    secret_clear(root, sizeof(root));
    secret_clear(nonce, sizeof(nonce));
    secret_clear(plain, sizeof(plain));
    secret_clear(aad, sizeof(aad));
    secret_clear(wrapped, sizeof(wrapped));
    if (result != P4_CRED_OK) {
        clear_prefix(credential_id, credential_id_cap, P4_CRED_ID_LEN);
    }
    return result;
}


int cred_open(const uint8_t *rp_id_hash,
              size_t rp_id_hash_len,
              const uint8_t *credential_id,
              size_t credential_id_len,
              uint8_t *private_scalar,
              size_t private_scalar_cap)
{
    if (rp_id_hash == NULL || credential_id == NULL ||
        private_scalar == NULL ||
        rp_id_hash_len != P4_CRED_RP_ID_HASH_LEN) {
        clear_prefix(private_scalar, private_scalar_cap,
                     P4_CRED_PRIVATE_SCALAR_LEN);
        return P4_CRED_ERR_ARG;
    }
    if (private_scalar_cap < P4_CRED_PRIVATE_SCALAR_LEN) {
        clear_prefix(private_scalar, private_scalar_cap,
                     P4_CRED_PRIVATE_SCALAR_LEN);
        return P4_CRED_ERR_SMALL;
    }
    if (credential_id_len != P4_CRED_ID_LEN ||
        memcmp(credential_id, s_header, sizeof(s_header)) != 0) {
        clear_prefix(private_scalar, private_scalar_cap,
                     P4_CRED_PRIVATE_SCALAR_LEN);
        return P4_CRED_ERR_MISMATCH;
    }

    uint8_t root[P4_CRYPTO_AES256_KEY_LEN] = {0};
    uint8_t plain[CRED_CIPHER_LEN] = {0};
    uint8_t aad[CRED_AAD_LEN] = {0};
    memcpy(aad, credential_id, CRED_HEADER_LEN);
    memcpy(aad + CRED_HEADER_LEN, p4_aaguid, P4_AAGUID_LEN);

    int result = p4_root_load(root);
    if (result != P4_CRED_OK) {
        result = P4_CRED_ERR_ROOT;
        goto out;
    }

    int crypto_err = gcm_open(
        root,
        credential_id + CRED_NONCE_OFFSET,
        aad,
        sizeof(aad),
        credential_id + CRED_CIPHER_OFFSET,
        CRED_CIPHER_LEN,
        credential_id + CRED_TAG_OFFSET,
        plain);
    if (crypto_err != P4_CRYPTO_OK) {
        result = crypto_err == P4_CRYPTO_AUTH
                     ? P4_CRED_ERR_MISMATCH
                     : P4_CRED_ERR_CRYPTO;
        goto out;
    }

    bool rp_matches = equal_hash(plain, rp_id_hash);
    int key_result = scalar_check(
        plain + P4_CRED_RP_ID_HASH_LEN, true);
    if (!rp_matches || key_result == P4_CRED_ERR_MISMATCH) {
        result = P4_CRED_ERR_MISMATCH;
        goto out;
    }
    if (key_result != P4_CRED_OK) {
        result = key_result;
        goto out;
    }

    memcpy(private_scalar,
           plain + P4_CRED_RP_ID_HASH_LEN,
           P4_CRED_PRIVATE_SCALAR_LEN);
    result = P4_CRED_OK;

out:
    secret_clear(root, sizeof(root));
    secret_clear(plain, sizeof(plain));
    secret_clear(aad, sizeof(aad));
    if (result != P4_CRED_OK) {
        clear_prefix(private_scalar, private_scalar_cap,
                     P4_CRED_PRIVATE_SCALAR_LEN);
    }
    return result;
}
