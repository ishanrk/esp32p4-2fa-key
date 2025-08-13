#include "p4_crypto.h"
#include "p4_crypto_p256_util.h"
#include "p4_crypto_priv.h"

#include <stdbool.h>
#include <string.h>

#include "mbedtls/psa_util.h"
#include "psa/crypto.h"

#define P256_BITS 256u
#define P256_PUBLIC_LEN 65u
#define P256_RAW_SIG_LEN 64u
#define P256_ALG PSA_ALG_ECDSA(PSA_ALG_SHA_256)

_Static_assert(P4_CRYPTO_P256_DER_MAX ==
               MBEDTLS_ECDSA_DER_MAX_SIG_LEN(P256_BITS),
               "unexpected p256 DER bound");
_Static_assert(P256_RAW_SIG_LEN == PSA_ECDSA_SIGNATURE_SIZE(P256_BITS),
               "unexpected p256 raw signature size");


static psa_key_attributes_t pair_attr(psa_key_usage_t usage)
{
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(
        &attr, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&attr, P256_BITS);
    psa_set_key_usage_flags(&attr, usage);
    psa_set_key_algorithm(&attr, P256_ALG);
    return attr;
}


static psa_key_attributes_t public_attr(void)
{
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(
        &attr, PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&attr, P256_BITS);
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_VERIFY_HASH);
    psa_set_key_algorithm(&attr, P256_ALG);
    return attr;
}


static psa_status_t pair_import(
    const uint8_t priv[P4_CRYPTO_P256_SCALAR_LEN],
    psa_key_usage_t usage,
    psa_key_id_t *key_id)
{
    psa_key_attributes_t attr = pair_attr(usage);
    psa_status_t status = psa_import_key(
        &attr, priv, P4_CRYPTO_P256_SCALAR_LEN, key_id);
    psa_reset_key_attributes(&attr);
    return status;
}


static psa_status_t public_import(const uint8_t pub[P256_PUBLIC_LEN],
                                  psa_key_id_t *key_id)
{
    psa_key_attributes_t attr = public_attr();
    psa_status_t status = psa_import_key(
        &attr, pub, P256_PUBLIC_LEN, key_id);
    psa_reset_key_attributes(&attr);
    return status;
}


static int key_error(psa_status_t status)
{
    p4_crypto_detail_set((int)status);
    if (status == PSA_ERROR_INVALID_ARGUMENT ||
        status == PSA_ERROR_DATA_INVALID) {
        return P4_CRYPTO_KEY;
    }
    return p4_crypto_from_psa(status);
}


static int psa_error(psa_status_t status)
{
    p4_crypto_detail_set((int)status);
    return p4_crypto_from_psa(status);
}


int p256_make(
    uint8_t priv[P4_CRYPTO_P256_SCALAR_LEN],
    uint8_t x[P4_CRYPTO_P256_SCALAR_LEN],
    uint8_t y[P4_CRYPTO_P256_SCALAR_LEN])
{
    p4_crypto_detail_set(0);
    if (priv == NULL || x == NULL || y == NULL) {
        return P4_CRYPTO_BAD_ARG;
    }
    if (p4_crypto_overlap(priv, P4_CRYPTO_P256_SCALAR_LEN,
                          x, P4_CRYPTO_P256_SCALAR_LEN) ||
        p4_crypto_overlap(priv, P4_CRYPTO_P256_SCALAR_LEN,
                          y, P4_CRYPTO_P256_SCALAR_LEN) ||
        p4_crypto_overlap(x, P4_CRYPTO_P256_SCALAR_LEN,
                          y, P4_CRYPTO_P256_SCALAR_LEN)) {
        return P4_CRYPTO_OVERLAP;
    }
    if (!p4_crypto_ready()) {
        return P4_CRYPTO_STATE;
    }

    secret_clear(priv, P4_CRYPTO_P256_SCALAR_LEN);
    memset(x, 0, P4_CRYPTO_P256_SCALAR_LEN);
    memset(y, 0, P4_CRYPTO_P256_SCALAR_LEN);

    uint8_t private_tmp[P4_CRYPTO_P256_SCALAR_LEN] = {0};
    uint8_t public_tmp[P256_PUBLIC_LEN] = {0};
    size_t private_len = 0;
    size_t public_len = 0;
    psa_key_id_t pair_id = 0;
    psa_key_id_t check_id = 0;
    bool pair_live = false;
    bool check_live = false;

    psa_key_attributes_t attr = pair_attr(PSA_KEY_USAGE_EXPORT);
    psa_status_t status = psa_generate_key(&attr, &pair_id);
    psa_reset_key_attributes(&attr);
    if (status == PSA_SUCCESS) {
        pair_live = true;
        status = psa_export_key(
            pair_id, private_tmp, sizeof(private_tmp), &private_len);
    }
    if (status == PSA_SUCCESS) {
        status = psa_export_public_key(
            pair_id, public_tmp, sizeof(public_tmp), &public_len);
    }
    if (status == PSA_SUCCESS &&
        (private_len != sizeof(private_tmp) ||
         public_len != sizeof(public_tmp) || public_tmp[0] != 0x04 ||
         !p4_p256_scalar_valid(private_tmp))) {
        status = PSA_ERROR_CORRUPTION_DETECTED;
    }
    if (status == PSA_SUCCESS) {
        status = public_import(public_tmp, &check_id);
        check_live = status == PSA_SUCCESS;
    }

    p4_crypto_key_drop(check_id, check_live, &status);
    p4_crypto_key_drop(pair_id, pair_live, &status);

    if (status == PSA_SUCCESS) {
        memcpy(priv, private_tmp, P4_CRYPTO_P256_SCALAR_LEN);
        memcpy(x, public_tmp + 1, P4_CRYPTO_P256_SCALAR_LEN);
        memcpy(y, public_tmp + 1 + P4_CRYPTO_P256_SCALAR_LEN,
               P4_CRYPTO_P256_SCALAR_LEN);
    }

    secret_clear(private_tmp, sizeof(private_tmp));
    secret_clear(public_tmp, sizeof(public_tmp));
    if (status != PSA_SUCCESS) {
        return psa_error(status);
    }

    p4_crypto_detail_set(0);
    return P4_CRYPTO_OK;
}


int p256_pub(
    const uint8_t priv[P4_CRYPTO_P256_SCALAR_LEN],
    uint8_t x[P4_CRYPTO_P256_SCALAR_LEN],
    uint8_t y[P4_CRYPTO_P256_SCALAR_LEN])
{
    p4_crypto_detail_set(0);
    if (priv == NULL || x == NULL || y == NULL) {
        return P4_CRYPTO_BAD_ARG;
    }
    if (p4_crypto_overlap(x, P4_CRYPTO_P256_SCALAR_LEN,
                          priv, P4_CRYPTO_P256_SCALAR_LEN) ||
        p4_crypto_overlap(y, P4_CRYPTO_P256_SCALAR_LEN,
                          priv, P4_CRYPTO_P256_SCALAR_LEN) ||
        p4_crypto_overlap(x, P4_CRYPTO_P256_SCALAR_LEN,
                          y, P4_CRYPTO_P256_SCALAR_LEN)) {
        return P4_CRYPTO_OVERLAP;
    }
    if (!p4_crypto_ready()) {
        return P4_CRYPTO_STATE;
    }
    if (!p4_p256_scalar_valid(priv)) {
        return P4_CRYPTO_KEY;
    }

    memset(x, 0, P4_CRYPTO_P256_SCALAR_LEN);
    memset(y, 0, P4_CRYPTO_P256_SCALAR_LEN);

    uint8_t public_tmp[P256_PUBLIC_LEN] = {0};
    size_t public_len = 0;
    psa_key_id_t pair_id = 0;
    bool pair_live = false;

    psa_status_t status = pair_import(priv, 0, &pair_id);
    if (status == PSA_SUCCESS) {
        pair_live = true;
        status = psa_export_public_key(
            pair_id, public_tmp, sizeof(public_tmp), &public_len);
    }
    if (status == PSA_SUCCESS &&
        (public_len != sizeof(public_tmp) || public_tmp[0] != 0x04)) {
        status = PSA_ERROR_CORRUPTION_DETECTED;
    }

    p4_crypto_key_drop(pair_id, pair_live, &status);
    if (status == PSA_SUCCESS) {
        memcpy(x, public_tmp + 1, P4_CRYPTO_P256_SCALAR_LEN);
        memcpy(y, public_tmp + 1 + P4_CRYPTO_P256_SCALAR_LEN,
               P4_CRYPTO_P256_SCALAR_LEN);
    }

    secret_clear(public_tmp, sizeof(public_tmp));
    if (status != PSA_SUCCESS) {
        return key_error(status);
    }

    p4_crypto_detail_set(0);
    return P4_CRYPTO_OK;
}


int p256_sign_hash(
    const uint8_t priv[P4_CRYPTO_P256_SCALAR_LEN],
    const uint8_t hash[P4_CRYPTO_SHA256_LEN],
    uint8_t *sig,
    size_t sig_cap,
    size_t *sig_len)
{
    p4_crypto_detail_set(0);
    if (sig_len == NULL) {
        return P4_CRYPTO_BAD_ARG;
    }
    if (priv == NULL || hash == NULL || sig == NULL) {
        *sig_len = 0;
        return P4_CRYPTO_BAD_ARG;
    }
    if (p4_crypto_overlap(sig_len, sizeof(*sig_len),
                          priv, P4_CRYPTO_P256_SCALAR_LEN) ||
        p4_crypto_overlap(sig_len, sizeof(*sig_len),
                          hash, P4_CRYPTO_SHA256_LEN) ||
        p4_crypto_overlap(sig_len, sizeof(*sig_len),
                          sig, P4_CRYPTO_P256_DER_MAX)) {
        return P4_CRYPTO_OVERLAP;
    }

    *sig_len = 0;
    if (sig_cap < P4_CRYPTO_P256_DER_MAX) {
        return P4_CRYPTO_SMALL;
    }
    if (p4_crypto_overlap(sig, P4_CRYPTO_P256_DER_MAX,
                          priv, P4_CRYPTO_P256_SCALAR_LEN) ||
        p4_crypto_overlap(sig, P4_CRYPTO_P256_DER_MAX,
                          hash, P4_CRYPTO_SHA256_LEN)) {
        return P4_CRYPTO_OVERLAP;
    }
    if (!p4_crypto_ready()) {
        return P4_CRYPTO_STATE;
    }
    if (!p4_p256_scalar_valid(priv)) {
        return P4_CRYPTO_KEY;
    }

    uint8_t raw[P256_RAW_SIG_LEN] = {0};
    uint8_t der[P4_CRYPTO_P256_DER_MAX] = {0};
    size_t raw_len = 0;
    size_t der_len = 0;
    psa_key_id_t pair_id = 0;
    bool pair_live = false;

    psa_status_t status = pair_import(
        priv, PSA_KEY_USAGE_SIGN_HASH, &pair_id);
    if (status == PSA_SUCCESS) {
        pair_live = true;
        status = psa_sign_hash(
            pair_id, P256_ALG, hash, P4_CRYPTO_SHA256_LEN,
            raw, sizeof(raw), &raw_len);
    }
    if (status == PSA_SUCCESS && raw_len != sizeof(raw)) {
        status = PSA_ERROR_CORRUPTION_DETECTED;
    }

    int der_status = 0;
    if (status == PSA_SUCCESS) {
        der_status = mbedtls_ecdsa_raw_to_der(
            P256_BITS, raw, raw_len, der, sizeof(der), &der_len);
        if (der_status != 0 || !p4_p256_der_strict(der, der_len)) {
            status = PSA_ERROR_CORRUPTION_DETECTED;
        }
    }

    p4_crypto_key_drop(pair_id, pair_live, &status);
    if (status == PSA_SUCCESS) {
        memcpy(sig, der, der_len);
        *sig_len = der_len;
    }

    secret_clear(raw, sizeof(raw));
    secret_clear(der, sizeof(der));
    if (status != PSA_SUCCESS) {
        if (der_status != 0) {
            p4_crypto_detail_set(der_status);
            return P4_CRYPTO_DER;
        }
        return psa_error(status);
    }

    p4_crypto_detail_set(0);
    return P4_CRYPTO_OK;
}


int p256_verify_hash(
    const uint8_t x[P4_CRYPTO_P256_SCALAR_LEN],
    const uint8_t y[P4_CRYPTO_P256_SCALAR_LEN],
    const uint8_t hash[P4_CRYPTO_SHA256_LEN],
    const uint8_t *sig,
    size_t sig_len)
{
    p4_crypto_detail_set(0);
    if (x == NULL || y == NULL || hash == NULL ||
        (sig == NULL && sig_len != 0)) {
        return P4_CRYPTO_BAD_ARG;
    }
    if (!p4_crypto_ready()) {
        return P4_CRYPTO_STATE;
    }
    if (!p4_p256_der_strict(sig, sig_len)) {
        return P4_CRYPTO_DER;
    }

    uint8_t public_tmp[P256_PUBLIC_LEN] = {0};
    uint8_t raw[P256_RAW_SIG_LEN] = {0};
    uint8_t canonical[P4_CRYPTO_P256_DER_MAX] = {0};
    size_t raw_len = 0;
    size_t canonical_len = 0;

    public_tmp[0] = 0x04;
    memcpy(public_tmp + 1, x, P4_CRYPTO_P256_SCALAR_LEN);
    memcpy(public_tmp + 1 + P4_CRYPTO_P256_SCALAR_LEN,
           y, P4_CRYPTO_P256_SCALAR_LEN);

    int der_status = mbedtls_ecdsa_der_to_raw(
        P256_BITS, sig, sig_len, raw, sizeof(raw), &raw_len);
    if (der_status == 0) {
        der_status = mbedtls_ecdsa_raw_to_der(
            P256_BITS, raw, raw_len, canonical,
            sizeof(canonical), &canonical_len);
    }
    if (der_status != 0 || raw_len != sizeof(raw) ||
        canonical_len != sig_len || memcmp(canonical, sig, sig_len) != 0) {
        secret_clear(public_tmp, sizeof(public_tmp));
        secret_clear(raw, sizeof(raw));
        secret_clear(canonical, sizeof(canonical));
        p4_crypto_detail_set(der_status);
        return P4_CRYPTO_DER;
    }

    psa_key_id_t public_id = 0;
    bool public_live = false;
    psa_status_t status = public_import(public_tmp, &public_id);
    if (status == PSA_SUCCESS) {
        public_live = true;
        status = psa_verify_hash(
            public_id, P256_ALG, hash, P4_CRYPTO_SHA256_LEN,
            raw, raw_len);
    }

    p4_crypto_key_drop(public_id, public_live, &status);
    secret_clear(public_tmp, sizeof(public_tmp));
    secret_clear(raw, sizeof(raw));
    secret_clear(canonical, sizeof(canonical));
    if (status != PSA_SUCCESS) {
        if (!public_live) {
            return key_error(status);
        }
        return psa_error(status);
    }

    p4_crypto_detail_set(0);
    return P4_CRYPTO_OK;
}
