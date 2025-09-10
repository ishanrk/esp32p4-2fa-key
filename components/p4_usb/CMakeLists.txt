idf_component_register(
    SRCS "p4_usb_desc.c"
    INCLUDE_DIRS "include"
    PRIV_INCLUDE_DIRS "."
    PRIV_REQUIRES esp_tinyusb
)
