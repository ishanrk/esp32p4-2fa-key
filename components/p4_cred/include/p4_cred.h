#pragma once

#ifdef __cplusplus
extern "C" {
#endif

enum {
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

#ifdef __cplusplus
}
#endif
