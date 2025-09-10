#pragma once

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

enum {
    P4_USB_REPORT_BYTES = 64,
    P4_USB_RX_QUEUE_DEPTH = 8,
    P4_USB_REPORT_DESC_BYTES = 34,
    P4_USB_CONFIG_DESC_BYTES = 41,
    P4_USB_EP_OUT = 0x01,
    P4_USB_EP_IN = 0x81,
    P4_USB_POLL_INTERVAL_MS = 5,
};

extern const uint8_t p4_usb_report_desc[P4_USB_REPORT_DESC_BYTES];
extern const uint8_t p4_usb_config_desc[P4_USB_CONFIG_DESC_BYTES];

#ifdef __cplusplus
}
#endif
