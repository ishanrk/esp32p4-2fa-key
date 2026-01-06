#pragma once

#include <stddef.h>
#include <stdint.h>

#include "p4_crypto.h"


extern const uint8_t assert_fake_private[P4_CRYPTO_P256_SCALAR_LEN];
extern const uint8_t assert_fake_x[P4_CRYPTO_P256_SCALAR_LEN];
extern const uint8_t assert_fake_y[P4_CRYPTO_P256_SCALAR_LEN];

extern unsigned assert_fake_press_calls;
extern unsigned assert_fake_sign_calls;

void assert_fakes_reset(void);
void assert_fake_set_press_result(int result);
void assert_fake_hash(const uint8_t *in, size_t in_len,
                      uint8_t out[P4_CRYPTO_SHA256_LEN]);
