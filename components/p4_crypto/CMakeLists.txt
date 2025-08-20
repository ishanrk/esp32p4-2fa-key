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
    REQUIRES bootloader_support esp_hw_support esp_timer heap mbedtls
)

if(CONFIG_P4KEY_CRYPTO_SELFTEST)
    target_sources(${COMPONENT_LIB} PRIVATE "p4_crypto_selftest.c")
endif()

if(CONFIG_P4KEY_CRYPTO_BENCH)
    target_sources(${COMPONENT_LIB} PRIVATE "p4_crypto_bench.c")
endif()
