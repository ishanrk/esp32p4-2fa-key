#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "p4_usb_desc.h"

typedef struct {
    uint8_t report[P4_USB_REPORT_BYTES];
    uint32_t generation;
} p4_usb_queue_item_t;

typedef struct {
    p4_usb_queue_item_t items[P4_USB_RX_QUEUE_DEPTH];
    uint8_t head;
    uint8_t count;
} p4_usb_queue_t;

void p4_usb_queue_init(p4_usb_queue_t *queue);
bool p4_usb_queue_push(p4_usb_queue_t *queue,
                       const uint8_t report[P4_USB_REPORT_BYTES],
                       uint32_t generation);
bool p4_usb_queue_pop(p4_usb_queue_t *queue, p4_usb_queue_item_t *item);
void p4_usb_queue_reset(p4_usb_queue_t *queue);
uint8_t p4_usb_queue_count(const p4_usb_queue_t *queue);
