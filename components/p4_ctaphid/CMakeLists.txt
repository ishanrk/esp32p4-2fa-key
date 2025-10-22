idf_component_register(
    SRCS
        "p4_ctaphid.c"
        "p4_ctaphid_rx.c"
        "p4_ctaphid_tx.c"
        "p4_ctaphid_chan.c"
        "p4_ctaphid_time.c"
    INCLUDE_DIRS "include"
    PRIV_INCLUDE_DIRS "."
    PRIV_REQUIRES p4_crypto p4_usb esp_timer freertos
)
