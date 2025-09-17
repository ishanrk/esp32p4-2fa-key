#include "p4_usb_queue.h"

#include <string.h>


void p4_usb_queue_init(p4_usb_queue_t *queue)
{
    if (queue == NULL) {
        return;
    }

    memset(queue, 0, sizeof(*queue));
}


bool p4_usb_queue_push(p4_usb_queue_t *queue,
                       const uint8_t report[P4_USB_REPORT_BYTES],
                       uint32_t generation)
{
    if (queue == NULL || report == NULL ||
        queue->count >= P4_USB_RX_QUEUE_DEPTH) {
        return false;
    }

    uint8_t tail = (queue->head + queue->count) % P4_USB_RX_QUEUE_DEPTH;
    memcpy(queue->items[tail].report, report, P4_USB_REPORT_BYTES);
    queue->items[tail].generation = generation;
    queue->count++;
    return true;
}


bool p4_usb_queue_pop(p4_usb_queue_t *queue, p4_usb_queue_item_t *item)
{
    if (queue == NULL || item == NULL || queue->count == 0) {
        return false;
    }

    *item = queue->items[queue->head];
    queue->head = (queue->head + 1) % P4_USB_RX_QUEUE_DEPTH;
    queue->count--;
    return true;
}


void p4_usb_queue_reset(p4_usb_queue_t *queue)
{
    if (queue == NULL) {
        return;
    }

    // old bytes are not secret at this stage but clear them for later reuse
    memset(queue, 0, sizeof(*queue));
}


uint8_t p4_usb_queue_count(const p4_usb_queue_t *queue)
{
    return queue == NULL ? 0 : queue->count;
}

_Static_assert(P4_USB_RX_QUEUE_DEPTH > 0, "USB receive queue cannot be empty");
_Static_assert(P4_USB_RX_QUEUE_DEPTH <= UINT8_MAX,
               "USB receive queue indexes fit in one byte");
