#ifndef P4_CRYPTO_P256_UTIL_H
#define P4_CRYPTO_P256_UTIL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

bool p4_p256_scalar_valid(const uint8_t scalar[32]);
bool p4_p256_der_strict(const uint8_t *der, size_t der_len);

#endif
