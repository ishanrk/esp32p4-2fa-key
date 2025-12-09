idf_component_register(
    SRCS "p4_aaguid.c" "p4_cred.c" "p4_root.c"
    INCLUDE_DIRS "include"
    PRIV_INCLUDE_DIRS "."
    PRIV_REQUIRES nvs_flash p4_crypto
)

if(CONFIG_P4KEY_CRED_REBOOT_TEST)
    target_sources(${COMPONENT_LIB} PRIVATE "p4_cred_reboot_test.c")
    idf_component_optional_requires(PRIVATE esp_mm esp_system freertos)
endif()
