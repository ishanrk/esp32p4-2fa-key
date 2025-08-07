#ifndef P4_CRYPTO_ERR_H
#define P4_CRYPTO_ERR_H

enum {
    P4_CRYPTO_OK = 0,
    P4_CRYPTO_BAD_ARG = -1,
    P4_CRYPTO_SMALL = -2,
    P4_CRYPTO_AUTH = -3,
    P4_CRYPTO_KEY = -4,
    P4_CRYPTO_DER = -5,
    P4_CRYPTO_STATE = -6,
    P4_CRYPTO_OVERLAP = -7,
    P4_CRYPTO_NOT_SUPPORTED = -8,
    P4_CRYPTO_LIB = -9,
};

#endif
