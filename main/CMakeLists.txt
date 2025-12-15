idf_component_register(
    SRCS "app_main.c" "ctap_stub.c"
    REQUIRES p4_board p4_cred p4_crypto p4_ctap p4_ctaphid p4_press p4_state p4_usb
)
