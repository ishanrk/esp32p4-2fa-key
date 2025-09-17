idf_component_register(
    SRCS
        "p4_usb.c"
        "p4_usb_desc.c"
        "p4_usb_queue.c"
    INCLUDE_DIRS "include"
    PRIV_INCLUDE_DIRS "."
    PRIV_REQUIRES esp_tinyusb freertos log
)
