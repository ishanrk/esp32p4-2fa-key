idf_component_register(
    SRCS "p4_state.c"
    INCLUDE_DIRS "include"
    REQUIRES esp_hw_support esp_psram spi_flash
)
