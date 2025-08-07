#include "p4_crypto.h"
#include "p4_crypto_check.h"
#include "p4_crypto_priv.h"

#include <stdbool.h>
#include <stdint.h>

#include "bootloader_random.h"
#include "mbedtls/platform_util.h"
#include "psa/crypto.h"

static bool ready;
static int last_detail;


int crypto_init(void)
{
    p4_crypto_detail_set(0);
    if (ready) {
        return P4_CRYPTO_OK;
    }

    // bootloader turns this source off before app start
    // no radio or ADC owner exists in this profile
    bootloader_random_enable();

    psa_status_t status = psa_crypto_init();
    if (status != PSA_SUCCESS) {
        bootloader_random_disable();
        p4_crypto_detail_set((int)status);
        return p4_crypto_from_psa(status);
    }

    ready = true;
    p4_crypto_detail_set(0);
    return P4_CRYPTO_OK;
}


void secret_clear(void *ptr, size_t len)
{
    if (ptr == NULL || len == 0) {
        return;
    }

    mbedtls_platform_zeroize(ptr, len);
}


bool p4_crypto_ready(void)
{
    return ready;
}


void p4_crypto_detail_set(int detail)
{
    last_detail = detail;
}


int p4_crypto_last_detail(void)
{
    return last_detail;
}


int p4_crypto_from_psa(psa_status_t status)
{
    switch (status) {
    case PSA_SUCCESS:
        return P4_CRYPTO_OK;
    case PSA_ERROR_INVALID_ARGUMENT:
        return P4_CRYPTO_BAD_ARG;
    case PSA_ERROR_BUFFER_TOO_SMALL:
        return P4_CRYPTO_SMALL;
    case PSA_ERROR_INVALID_SIGNATURE:
        return P4_CRYPTO_AUTH;
    case PSA_ERROR_INVALID_HANDLE:
    case PSA_ERROR_BAD_STATE:
        return P4_CRYPTO_STATE;
    case PSA_ERROR_NOT_SUPPORTED:
        return P4_CRYPTO_NOT_SUPPORTED;
    default:
        return P4_CRYPTO_LIB;
    }
}


bool p4_crypto_overlap(const void *a, size_t a_len,
                       const void *b, size_t b_len)
{
    if (a_len == 0 || b_len == 0) {
        return false;
    }
    if (a == NULL || b == NULL) {
        return false;
    }

    uintptr_t a_first = (uintptr_t)a;
    uintptr_t b_first = (uintptr_t)b;

    // malformed ranges fail closed as overlap
    if (a_len - 1 > UINTPTR_MAX - a_first ||
        b_len - 1 > UINTPTR_MAX - b_first) {
        return true;
    }

    uintptr_t a_last = a_first + a_len - 1;
    uintptr_t b_last = b_first + b_len - 1;
    return a_first <= b_last && b_first <= a_last;
}
