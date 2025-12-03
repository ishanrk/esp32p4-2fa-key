#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

enum {
    P4_CRED_RP_ID_HASH_LEN = 32,
    P4_CRED_PRIVATE_SCALAR_LEN = 32,
    P4_CRED_ID_LEN = 100,

    P4_CRED_OK = 0,
    P4_CRED_ERR_ARG = -1,
    P4_CRED_ERR_SMALL = -2,
    P4_CRED_ERR_ROOT = -3,
    P4_CRED_ERR_CRYPTO = -4,
    P4_CRED_ERR_KEY = -5,
    P4_CRED_ERR_MISMATCH = -6,
};

// Initializes the persistent development wrapping root.
// This must run after crypto_init() and before credential operations.
int p4_cred_init(void);

int cred_wrap(const uint8_t *rp_id_hash,
              size_t rp_id_hash_len,
              const uint8_t *private_scalar,
              size_t private_scalar_len,
              uint8_t *credential_id,
              size_t credential_id_cap);

int cred_open(const uint8_t *rp_id_hash,
              size_t rp_id_hash_len,
              const uint8_t *credential_id,
              size_t credential_id_len,
              uint8_t *private_scalar,
              size_t private_scalar_cap);

#ifdef __cplusplus
}
#endif
