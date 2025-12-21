#pragma once

#include <stdint.h>

#include "p4_crypto.h"


extern const uint8_t make_fake_rp_hash[P4_CRYPTO_SHA256_LEN];
extern const uint8_t make_fake_private[P4_CRYPTO_P256_SCALAR_LEN];
extern const uint8_t make_fake_x[P4_CRYPTO_P256_SCALAR_LEN];
extern const uint8_t make_fake_y[P4_CRYPTO_P256_SCALAR_LEN];

extern unsigned make_fake_sha_calls;
extern unsigned make_fake_press_calls;
extern unsigned make_fake_key_calls;
extern unsigned make_fake_rand_calls;
extern unsigned make_fake_seal_calls;

void make_fakes_reset(void);
