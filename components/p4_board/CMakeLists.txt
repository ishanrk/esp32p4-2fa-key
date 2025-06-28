idf_component_register(
    SRCS "p4_board.c" "p4_button.c"
    INCLUDE_DIRS "include"
    REQUIRES esp_driver_gpio
)
