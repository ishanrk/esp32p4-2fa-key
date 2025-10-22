#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

enum {
    P4_HID_OK = 0,
    P4_HID_ERR_ARG = -1,
    P4_HID_ERR_STATE = -2,
    P4_HID_ERR_TIMEOUT = -3,
    P4_HID_ERR_DISCONNECTED = -4,
    P4_HID_ERR_SMALL = -5,
    P4_HID_ERR_DRIVER = -6,
    P4_HID_ERR_RATE = -7,
};

int hid_start(void);

int hid_take_msg(uint32_t *cid,
                 uint8_t *cmd,
                 uint8_t *data,
                 size_t cap,
                 size_t *data_len,
                 uint32_t wait_ms);

int hid_send_msg(uint32_t cid,
                 uint8_t cmd,
                 const uint8_t *data,
                 size_t data_len);

int hid_keepalive(uint32_t cid, uint8_t status);
bool hid_cancelled(uint32_t cid);
void hid_clear_cancel(uint32_t cid);
void hid_reset_all(void);

#ifdef __cplusplus
}
#endif
