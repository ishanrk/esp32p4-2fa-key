#include "p4_crypto.h"
#include "p4_crypto_priv.h"

#include <string.h>

#include "psa/crypto.h"

#define SHA_CHUNK 64


int sha256_sum(const uint8_t *in, size_t in_len,
               uint8_t out[P4_CRYPTO_SHA256_LEN])
{
    p4_crypto_detail_set(0);
    if (out == NULL || (in == NULL && in_len != 0)) {
        return P4_CRYPTO_BAD_ARG;
    }
    if (!p4_crypto_ready()) {
        return P4_CRYPTO_STATE;
    }

    psa_hash_operation_t op = PSA_HASH_OPERATION_INIT;
    uint8_t digest[P4_CRYPTO_SHA256_LEN];
    size_t digest_len = 0;
    psa_status_t status = psa_hash_setup(&op, PSA_ALG_SHA_256);

    size_t offset = 0;
    while (status == PSA_SUCCESS && offset < in_len) {
        size_t take = in_len - offset;
        if (take > SHA_CHUNK) {
            take = SHA_CHUNK;
        }
        status = psa_hash_update(&op, in + offset, take);
        offset += take;
    }

    if (status == PSA_SUCCESS) {
        status = psa_hash_finish(&op, digest, sizeof(digest), &digest_len);
    }

    if (status != PSA_SUCCESS || digest_len != sizeof(digest)) {
        if (status == PSA_SUCCESS) {
            status = PSA_ERROR_CORRUPTION_DETECTED;
        }
        psa_hash_abort(&op);
        secret_clear(digest, sizeof(digest));
        p4_crypto_detail_set((int)status);
        return p4_crypto_from_psa(status);
    }

    memcpy(out, digest, sizeof(digest));
    secret_clear(digest, sizeof(digest));
    p4_crypto_detail_set(0);
    return P4_CRYPTO_OK;
}
