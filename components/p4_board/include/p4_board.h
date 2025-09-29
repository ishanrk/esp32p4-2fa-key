#ifndef P4_BOARD_H
#define P4_BOARD_H

#include <stdbool.h>

#include "esp_err.h"

esp_err_t p4_board_init(void);
esp_err_t p4_board_usb_prepare(void);
bool p4_board_button_ready(void);
int p4_board_button_gpio(void);
bool p4_board_button_active_low(void);
int p4_board_button_raw(void);
const char *p4_board_profile(void);
const char *p4_board_usb_connector(void);

#endif
