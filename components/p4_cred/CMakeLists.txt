idf_component_register(
    SRCS "p4_aaguid.c" "p4_cred.c" "p4_root.c"
    INCLUDE_DIRS "include"
    PRIV_INCLUDE_DIRS "."
    PRIV_REQUIRES nvs_flash p4_crypto
)
