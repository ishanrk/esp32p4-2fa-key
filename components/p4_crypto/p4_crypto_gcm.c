#include "p4_crypto.h"
#include "p4_crypto_priv.h"

#include <stdbool.h>
#include <string.h>

#include "psa/crypto.h"


static psa_status_t key_add(const uint8_t key[P4_CRYPTO_AES256_KEY_LEN],
                            psa_key_usage_t usage,
                            psa_key_id_t *key_id)
{
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attr, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attr, 256);
    psa_set_key_usage_flags(&attr, usage);
    psa_set_key_algorithm(&attr, PSA_ALG_GCM);

    psa_status_t status = psa_import_key(
        &attr, key, P4_CRYPTO_AES256_KEY_LEN, key_id);
    psa_reset_key_attributes(&attr);
    return status;
}


static int seal_fail(psa_aead_operation_t *op, psa_key_id_t key_id,
                     bool key_live, psa_status_t status,
                     uint8_t *cipher, size_t plain_len,
                     uint8_t tag[P4_CRYPTO_GCM_TAG_LEN])
{
    psa_aead_abort(op);
    p4_crypto_key_drop(key_id, key_live, &status);

    if (plain_len != 0) {
        secret_clear(cipher, plain_len);
    }
    secret_clear(tag, P4_CRYPTO_GCM_TAG_LEN);
    p4_crypto_detail_set((int)status);
    return p4_crypto_from_psa(status);
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
    p4_crypto_detail_set(0);
    if (key == NULL || nonce == NULL || cipher == NULL || tag == NULL ||
        (aad == NULL && aad_len != 0) ||
        (plain == NULL && plain_len != 0)) {
        return P4_CRYPTO_BAD_ARG;
    }
    if (p4_crypto_overlap(cipher, plain_len, key, P4_CRYPTO_AES256_KEY_LEN) ||
        p4_crypto_overlap(cipher, plain_len, nonce,
                          P4_CRYPTO_GCM_NONCE_LEN) ||
        p4_crypto_overlap(cipher, plain_len, aad, aad_len) ||
        p4_crypto_overlap(cipher, plain_len, plain, plain_len) ||
        p4_crypto_overlap(cipher, plain_len, tag,
                          P4_CRYPTO_GCM_TAG_LEN) ||
        p4_crypto_overlap(tag, P4_CRYPTO_GCM_TAG_LEN,
                          key, P4_CRYPTO_AES256_KEY_LEN) ||
        p4_crypto_overlap(tag, P4_CRYPTO_GCM_TAG_LEN,
                          nonce, P4_CRYPTO_GCM_NONCE_LEN) ||
        p4_crypto_overlap(tag, P4_CRYPTO_GCM_TAG_LEN, aad, aad_len) ||
        p4_crypto_overlap(tag, P4_CRYPTO_GCM_TAG_LEN,
                          plain, plain_len)) {
        return P4_CRYPTO_OVERLAP;
    }
    if (!p4_crypto_ready()) {
        return P4_CRYPTO_STATE;
    }

    psa_aead_operation_t op = PSA_AEAD_OPERATION_INIT;
    psa_key_id_t key_id = 0;
    bool key_live = false;
    uint8_t tail[P4_CRYPTO_GCM_TAG_LEN];
    size_t body_len = 0;
    size_t tail_len = 0;
    size_t tag_len = 0;

    psa_status_t status = key_add(key, PSA_KEY_USAGE_ENCRYPT, &key_id);
    if (status == PSA_SUCCESS) {
        key_live = true;
        status = psa_aead_encrypt_setup(&op, key_id, PSA_ALG_GCM);
    }
    if (status == PSA_SUCCESS) {
        status = psa_aead_set_nonce(&op, nonce, P4_CRYPTO_GCM_NONCE_LEN);
    }
    if (status == PSA_SUCCESS) {
        status = psa_aead_set_lengths(&op, aad_len, plain_len);
    }
    if (status == PSA_SUCCESS && aad_len != 0) {
        status = psa_aead_update_ad(&op, aad, aad_len);
    }
    if (status == PSA_SUCCESS && plain_len != 0) {
        status = psa_aead_update(
            &op, plain, plain_len, cipher, plain_len, &body_len);
    }
    if (status == PSA_SUCCESS && body_len == plain_len) {
        status = psa_aead_finish(
            &op, tail, sizeof(tail), &tail_len,
            tag, P4_CRYPTO_GCM_TAG_LEN, &tag_len);
    } else if (status == PSA_SUCCESS) {
        status = PSA_ERROR_CORRUPTION_DETECTED;
    }
    if (status == PSA_SUCCESS &&
        (tail_len != 0 || tag_len != P4_CRYPTO_GCM_TAG_LEN)) {
        status = PSA_ERROR_CORRUPTION_DETECTED;
    }

    secret_clear(tail, sizeof(tail));
    if (status != PSA_SUCCESS) {
        return seal_fail(&op, key_id, key_live, status,
                         cipher, plain_len, tag);
    }

    status = psa_destroy_key(key_id);
    if (status != PSA_SUCCESS) {
        // destruction can leave a volatile slot live on failure
        return seal_fail(&op, key_id, true, status,
                         cipher, plain_len, tag);
    }

    p4_crypto_detail_set(0);
    return P4_CRYPTO_OK;
}


static int open_fail(psa_aead_operation_t *op, psa_key_id_t key_id,
                     bool key_live, psa_status_t status,
                     uint8_t *plain, size_t cipher_len)
{
    psa_aead_abort(op);
    p4_crypto_key_drop(key_id, key_live, &status);

    // update can expose bytes before verify checks the tag
    if (cipher_len != 0) {
        secret_clear(plain, cipher_len);
    }
    p4_crypto_detail_set((int)status);
    return p4_crypto_from_psa(status);
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
    p4_crypto_detail_set(0);
    if (key == NULL || nonce == NULL || tag == NULL || plain == NULL ||
        (aad == NULL && aad_len != 0) ||
        (cipher == NULL && cipher_len != 0)) {
        return P4_CRYPTO_BAD_ARG;
    }
    if (p4_crypto_overlap(plain, cipher_len,
                          key, P4_CRYPTO_AES256_KEY_LEN) ||
        p4_crypto_overlap(plain, cipher_len,
                          nonce, P4_CRYPTO_GCM_NONCE_LEN) ||
        p4_crypto_overlap(plain, cipher_len, aad, aad_len) ||
        p4_crypto_overlap(plain, cipher_len, cipher, cipher_len) ||
        p4_crypto_overlap(plain, cipher_len,
                          tag, P4_CRYPTO_GCM_TAG_LEN)) {
        return P4_CRYPTO_OVERLAP;
    }
    if (!p4_crypto_ready()) {
        return P4_CRYPTO_STATE;
    }

    psa_aead_operation_t op = PSA_AEAD_OPERATION_INIT;
    psa_key_id_t key_id = 0;
    bool key_live = false;
    uint8_t tail[P4_CRYPTO_GCM_TAG_LEN];
    size_t body_len = 0;
    size_t tail_len = 0;

    psa_status_t status = key_add(key, PSA_KEY_USAGE_DECRYPT, &key_id);
    if (status == PSA_SUCCESS) {
        key_live = true;
        status = psa_aead_decrypt_setup(&op, key_id, PSA_ALG_GCM);
    }
    if (status == PSA_SUCCESS) {
        status = psa_aead_set_nonce(&op, nonce, P4_CRYPTO_GCM_NONCE_LEN);
    }
    if (status == PSA_SUCCESS) {
        status = psa_aead_set_lengths(&op, aad_len, cipher_len);
    }
    if (status == PSA_SUCCESS && aad_len != 0) {
        status = psa_aead_update_ad(&op, aad, aad_len);
    }
    if (status == PSA_SUCCESS && cipher_len != 0) {
        status = psa_aead_update(
            &op, cipher, cipher_len, plain, cipher_len, &body_len);
    }
    if (status == PSA_SUCCESS && body_len == cipher_len) {
        status = psa_aead_verify(
            &op, tail, sizeof(tail), &tail_len,
            tag, P4_CRYPTO_GCM_TAG_LEN);
    } else if (status == PSA_SUCCESS) {
        status = PSA_ERROR_CORRUPTION_DETECTED;
    }
    if (status == PSA_SUCCESS && tail_len != 0) {
        status = PSA_ERROR_CORRUPTION_DETECTED;
    }

    secret_clear(tail, sizeof(tail));
    if (status != PSA_SUCCESS) {
        return open_fail(&op, key_id, key_live, status,
                         plain, cipher_len);
    }

    status = psa_destroy_key(key_id);
    if (status != PSA_SUCCESS) {
        // destruction can leave a volatile slot live on failure
        return open_fail(&op, key_id, true, status,
                         plain, cipher_len);
    }

    p4_crypto_detail_set(0);
    return P4_CRYPTO_OK;
}
