#include "ctap_stub.h"

#if !CONFIG_P4KEY_USB_BRINGUP

#include "p4_ctaphid.h"
#include "p4_ctaphid_wire.h"
#include "p4_ctap.h"
#include "p4_crypto.h"

#include <string.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

enum {
    P4_CTAP_STUB_STACK_BYTES = 3072,
    P4_CTAP_STUB_WAIT_MS = 100,
    P4_CTAP_STUB_TOTAL_WAIT_MS = 1000,
};

static StaticTask_t s_stub_task_storage;
static StackType_t
    s_stub_stack[P4_CTAP_STUB_STACK_BYTES / sizeof(StackType_t)];
static uint8_t s_request[P4_CTAPHID_MAX_PAYLOAD];
static uint8_t s_response[P4_CTAP_MAX_MESSAGE];

#if CONFIG_P4KEY_HID_WAIT_TEST
static const uint8_t s_wait_request[] = "P4KEY CTAPHID WAIT TEST v1";
#endif

_Static_assert(P4_CTAP_STUB_STACK_BYTES % sizeof(StackType_t) == 0,
               "ctap stub stack alignment");


static void send_dispatch_result(uint32_t cid, uint8_t command,
                                 size_t request_len)
{
    size_t response_len = 0;
    int error = p4_ctap_dispatch(s_request, request_len,
                                 s_response, sizeof(s_response),
                                 &response_len);
    if (error != P4_CTAP_OK) {
        s_response[0] = P4_CTAP_STATUS_OTHER;
        response_len = 1;
    }
    (void)hid_send_msg(cid, command, s_response, response_len);
    secret_clear(s_response, sizeof(s_response));
}


#if CONFIG_P4KEY_HID_WAIT_TEST
static void send_stub_result(uint32_t cid, uint8_t result)
{
    (void)hid_send_msg(cid, CTAPHID_CBOR, &result, 1);
}


static bool is_wait_request(const uint8_t *request, size_t request_len)
{
    return request_len == sizeof(s_wait_request) - 1 &&
           memcmp(request, s_wait_request, sizeof(s_wait_request) - 1) == 0;
}


static void run_wait(uint32_t cid)
{
    uint32_t elapsed_ms = 0;
    while (elapsed_ms < P4_CTAP_STUB_TOTAL_WAIT_MS) {
        if (hid_cancelled(cid)) {
            send_stub_result(cid, CTAP2_ERR_KEEPALIVE_CANCEL);
            return;
        }

        int error = hid_keepalive(cid, CTAPHID_KEEPALIVE_PROCESSING);
        if (error != P4_HID_OK && error != P4_HID_ERR_RATE) {
            if (hid_cancelled(cid)) {
                send_stub_result(cid, CTAP2_ERR_KEEPALIVE_CANCEL);
            }
            return;
        }

        (void)ulTaskNotifyTake(pdTRUE,
                               pdMS_TO_TICKS(P4_CTAP_STUB_WAIT_MS));
        elapsed_ms += P4_CTAP_STUB_WAIT_MS;
    }

    if (hid_cancelled(cid)) {
        send_stub_result(cid, CTAP2_ERR_KEEPALIVE_CANCEL);
    } else {
        send_stub_result(cid, CTAP1_ERR_INVALID_COMMAND);
    }
}
#endif


static void ctap_stub_task(void *arg)
{
    (void)arg;

    for (;;) {
        uint32_t cid = 0;
        uint8_t command = 0;
        size_t request_len = 0;
        int error = hid_take_msg(&cid, &command, s_request,
                                 sizeof(s_request), &request_len, 1000);
        if (error != P4_HID_OK) {
            if (error == P4_HID_ERR_DISCONNECTED) {
                vTaskDelay(pdMS_TO_TICKS(25));
            }
            continue;
        }

#if CONFIG_P4KEY_HID_WAIT_TEST
        if (command == CTAPHID_CBOR &&
            is_wait_request(s_request, request_len)) {
            run_wait(cid);
            secret_clear(s_request, sizeof(s_request));
            continue;
        }
#endif

        send_dispatch_result(cid, command, request_len);
        secret_clear(s_request, sizeof(s_request));
    }
}


bool p4_ctap_stub_start(void)
{
    TaskHandle_t task = xTaskCreateStatic(
        ctap_stub_task,
        "p4_ctap_stub",
        sizeof(s_stub_stack) / sizeof(s_stub_stack[0]),
        NULL,
        tskIDLE_PRIORITY + 1,
        s_stub_stack,
        &s_stub_task_storage);
    return task != NULL;
}

#else

bool p4_ctap_stub_start(void)
{
    return false;
}

#endif
