#pragma once

#include <stdint.h>

#include "p4_crypto.h"

int p4_root_load(uint8_t root[P4_CRYPTO_AES256_KEY_LEN]);
