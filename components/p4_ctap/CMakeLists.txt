idf_component_register(
    SRCS "p4_cbor.c" "p4_ctap.c" "p4_get_info.c" "p4_make_credential.c"
    INCLUDE_DIRS "include"
    REQUIRES p4_cred p4_crypto p4_press
)
