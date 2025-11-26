idf_component_register(
    SRCS "p4_root.c"
    INCLUDE_DIRS "include"
    PRIV_INCLUDE_DIRS "."
    PRIV_REQUIRES nvs_flash p4_crypto
)
