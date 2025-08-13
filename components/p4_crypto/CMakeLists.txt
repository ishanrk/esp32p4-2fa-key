idf_component_register(
    SRCS
        "p4_crypto.c"
        "p4_crypto_rng.c"
        "p4_crypto_sha.c"
        "p4_crypto_gcm.c"
        "p4_crypto_p256.c"
        "p4_crypto_p256_util.c"
    INCLUDE_DIRS "include"
    PRIV_INCLUDE_DIRS "."
    REQUIRES bootloader_support esp_hw_support mbedtls
)
