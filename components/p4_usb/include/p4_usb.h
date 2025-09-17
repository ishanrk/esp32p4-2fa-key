#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "p4_usb_desc.h"

#ifdef __cplusplus
extern "C" {
#endif

enum {
    P4_USB_OK = 0,
    P4_USB_ERR_ARG = -1,
    P4_USB_ERR_STATE = -2,
    P4_USB_ERR_TIMEOUT = -3,
    P4_USB_ERR_DISCONNECTED = -4,
    P4_USB_ERR_STALE = -5,
    P4_USB_ERR_DRIVER = -6,
};

int usb_start(void);
int usb_take(uint8_t report[P4_USB_REPORT_BYTES], uint32_t wait_ms);
int usb_send(const uint8_t report[P4_USB_REPORT_BYTES], uint32_t wait_ms);
bool usb_ready(void);
void usb_drop_pending(void);
uint32_t usb_unmount_generation(void);

// call deliberately from a development build never from a packet callback
void usb_diag_print(void);

#ifdef __cplusplus
}
#endif
