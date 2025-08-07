#include "p4_crypto.h"
#include "p4_crypto_priv.h"

#include "esp_random.h"


int rand_fill(uint8_t *out, size_t out_len)
{
    p4_crypto_detail_set(0);
    if (out == NULL) {
        return P4_CRYPTO_BAD_ARG;
    }
    if (!p4_crypto_ready()) {
        return P4_CRYPTO_STATE;
    }

    if (out_len != 0) {
        esp_fill_random(out, out_len);
    }

    p4_crypto_detail_set(0);
    return P4_CRYPTO_OK;
}
