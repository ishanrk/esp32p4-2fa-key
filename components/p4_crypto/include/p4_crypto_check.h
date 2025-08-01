#ifndef P4_CRYPTO_CHECK_H
#define P4_CRYPTO_CHECK_H

#ifndef P4KEY_HOST_TEST

#include "sdkconfig.h"

#if !defined(CONFIG_IDF_TARGET_ESP32P4) || !CONFIG_IDF_TARGET_ESP32P4
#error "P4Key crypto requires the ESP32-P4 target"
#endif

#if !defined(CONFIG_ESP32P4_SELECTS_REV_LESS_V3) || \
    !CONFIG_ESP32P4_SELECTS_REV_LESS_V3
#error "this board requires the pre-v3 ESP32-P4 silicon path"
#endif

#if !defined(CONFIG_MBEDTLS_HARDWARE_SHA) || !CONFIG_MBEDTLS_HARDWARE_SHA
#error "P4Key requires hardware SHA"
#endif

#if !defined(CONFIG_MBEDTLS_HARDWARE_AES) || !CONFIG_MBEDTLS_HARDWARE_AES
#error "P4Key requires hardware AES"
#endif

#if !defined(CONFIG_MBEDTLS_HARDWARE_GCM) || !CONFIG_MBEDTLS_HARDWARE_GCM
#error "P4Key requires the accelerated GCM path"
#endif

#if !defined(CONFIG_MBEDTLS_HARDWARE_ECC) || !CONFIG_MBEDTLS_HARDWARE_ECC
#error "P4Key requires general hardware ECC"
#endif

#if defined(CONFIG_MBEDTLS_AES_SOFT_FALLBACK) && \
    CONFIG_MBEDTLS_AES_SOFT_FALLBACK
#error "P4Key release crypto forbids AES software fallback"
#endif

#if defined(CONFIG_MBEDTLS_ECC_OTHER_CURVES_SOFT_FALLBACK) && \
    CONFIG_MBEDTLS_ECC_OTHER_CURVES_SOFT_FALLBACK
#error "P4Key release crypto forbids ECC software fallback"
#endif

#if defined(CONFIG_MBEDTLS_HARDWARE_ECDSA_SIGN) && \
    CONFIG_MBEDTLS_HARDWARE_ECDSA_SIGN
#error "P4Key credential signing must not use the eFuse ECDSA signer"
#endif

#if defined(CONFIG_MBEDTLS_HARDWARE_ECDSA_VERIFY) && \
    CONFIG_MBEDTLS_HARDWARE_ECDSA_VERIFY
#error "P4Key P-256 proof must use the general ECC verify path"
#endif

#endif

#endif
