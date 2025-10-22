#include "p4_ctaphid.h"

#include "p4_ctaphid_priv.h"

#include <string.h>

#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "p4_crypto.h"
#include "p4_usb.h"

enum {
    P4_CTAPHID_TASK_STACK_BYTES = 4096,
    P4_CTAPHID_USB_WAIT_MS = 25,
    P4_CTAPHID_USB_SEND_MS = 250,
    P4_CTAPHID_LOCK_MS = 1000,
};

typedef struct {
    bool valid;
    uint32_t cid;
    uint32_t operation_generation;
    uint32_t usb_generation;
    uint8_t command;
    TaskHandle_t owner;
} p4_ctaphid_claim_t;

typedef struct {
    uint32_t usb_generation;
    int usb_error;
} p4_ctaphid_emit_context_t;

static p4_ctaphid_core_t s_core;
static p4_ctaphid_claim_t s_claim;
static uint32_t s_message_usb_generation;
static uint32_t s_seen_usb_generation;
static uint32_t s_reset_epoch;
static bool s_started;
static bool s_reset_requested;

static portMUX_TYPE s_flag_lock = portMUX_INITIALIZER_UNLOCKED;

static StaticSemaphore_t s_core_mutex_storage;
static StaticSemaphore_t s_message_wake_storage;
static StaticSemaphore_t s_tx_mutex_storage;
static SemaphoreHandle_t s_core_mutex;
static SemaphoreHandle_t s_message_wake;
static SemaphoreHandle_t s_tx_mutex;

static StaticTask_t s_transport_task_storage;
static StackType_t
    s_transport_stack[P4_CTAPHID_TASK_STACK_BYTES / sizeof(StackType_t)];

static uint8_t s_immediate_payload[P4_CTAPHID_MAX_PAYLOAD];

_Static_assert(P4_CTAPHID_TASK_STACK_BYTES % sizeof(StackType_t) == 0,
               "ctaphid task stack alignment");


static TickType_t wait_ticks(uint32_t wait_ms)
{
    if (wait_ms == 0) {
        return 0;
    }

    uint64_t ticks = ((uint64_t)wait_ms * configTICK_RATE_HZ + 999) / 1000;
    if (ticks == 0) {
        ticks = 1;
    }
    if (ticks >= portMAX_DELAY) {
        ticks = portMAX_DELAY - 1;
    }
    return (TickType_t)ticks;
}


static uint32_t now_ms(void)
{
    return (uint32_t)((uint64_t)esp_timer_get_time() / 1000U);
}


static int random_bytes(void *ctx, uint8_t *out, size_t len)
{
    (void)ctx;
    return rand_fill(out, len);
}


static int map_usb_error(int error)
{
    if (error == P4_USB_ERR_TIMEOUT) {
        return P4_HID_ERR_TIMEOUT;
    }
    if (error == P4_USB_ERR_DISCONNECTED || error == P4_USB_ERR_STALE) {
        return P4_HID_ERR_DISCONNECTED;
    }
    if (error == P4_USB_ERR_ARG) {
        return P4_HID_ERR_ARG;
    }
    return P4_HID_ERR_DRIVER;
}


static bool transport_reset_pending(void)
{
    taskENTER_CRITICAL(&s_flag_lock);
    bool pending = s_reset_requested;
    taskEXIT_CRITICAL(&s_flag_lock);
    return pending;
}


static bool claim_matches_locked(uint32_t cid, bool require_owner)
{
    if (transport_reset_pending() ||
        !s_claim.valid || s_claim.cid != cid ||
        s_core.phase != P4_CTAPHID_PHASE_PROCESSING ||
        s_core.active_cid != cid ||
        s_seen_usb_generation != s_claim.usb_generation ||
        usb_unmount_generation() != s_claim.usb_generation ||
        !usb_ready()) {
        return false;
    }

    const p4_ctaphid_channel_t *channel =
        p4_ctaphid_chan_find_const(&s_core, cid);
    if (channel == NULL ||
        channel->generation != s_claim.operation_generation) {
        return false;
    }
    return !require_owner || s_claim.owner == xTaskGetCurrentTaskHandle();
}


static TaskHandle_t clear_claim_locked(void)
{
    TaskHandle_t owner = s_claim.valid ? s_claim.owner : NULL;
    memset(&s_claim, 0, sizeof(s_claim));
    return owner;
}


static TaskHandle_t clear_stale_claim_locked(void)
{
    if (!s_claim.valid || claim_matches_locked(s_claim.cid, false)) {
        return NULL;
    }
    return clear_claim_locked();
}


static TaskHandle_t reset_core_locked(void)
{
    TaskHandle_t owner = clear_claim_locked();
    p4_ctaphid_core_reset(&s_core);
    s_message_usb_generation = 0;
    s_reset_epoch++;
    return owner;
}


static int emit_usb_report(
    void *ctx,
    const uint8_t report[P4_CTAPHID_REPORT_BYTES])
{
    p4_ctaphid_emit_context_t *emit = ctx;
    if (transport_reset_pending()) {
        emit->usb_error = P4_USB_ERR_STALE;
        return -1;
    }
    emit->usb_error = usb_send_for_generation(
        report, emit->usb_generation, P4_CTAPHID_USB_SEND_MS);
    return emit->usb_error == P4_USB_OK ? 0 : -1;
}


// the caller owns the core mutex so a resync cannot cut through a response
static int send_locked(uint32_t cid,
                       uint8_t command,
                       const uint8_t *data,
                       size_t data_len,
                       uint32_t usb_generation)
{
    if (xSemaphoreTake(s_tx_mutex, wait_ticks(P4_CTAPHID_LOCK_MS)) != pdTRUE) {
        return P4_HID_ERR_TIMEOUT;
    }

    p4_ctaphid_emit_context_t emit = {
        .usb_generation = usb_generation,
        .usb_error = P4_USB_OK,
    };
    int error = p4_ctaphid_tx_send(cid, command, data, data_len,
                                    emit_usb_report, &emit);
    (void)xSemaphoreGive(s_tx_mutex);

    if (error == P4_CTAPHID_TX_ARG) {
        return P4_HID_ERR_ARG;
    }
    if (error != P4_CTAPHID_TX_OK) {
        return map_usb_error(emit.usb_error);
    }
    return P4_HID_OK;
}


static void notify_owner(TaskHandle_t owner)
{
    if (owner != NULL) {
        xTaskNotifyGive(owner);
    }
}


static void drain_message_wake(void)
{
    if (s_message_wake != NULL) {
        while (xSemaphoreTake(s_message_wake, 0) == pdTRUE) {
        }
    }
}


static void request_transport_reset(void)
{
    taskENTER_CRITICAL(&s_flag_lock);
    s_reset_requested = true;
    taskEXIT_CRITICAL(&s_flag_lock);
}


static bool take_transport_reset_request(void)
{
    taskENTER_CRITICAL(&s_flag_lock);
    bool requested = s_reset_requested;
    s_reset_requested = false;
    taskEXIT_CRITICAL(&s_flag_lock);
    return requested;
}


void hid_reset_all(void)
{
    if (!s_started || s_core_mutex == NULL) {
        return;
    }

    // publish the boundary before waiting so an in-flight fragmenter stops
    request_transport_reset();
    (void)xSemaphoreGive(s_message_wake);
    if (xSemaphoreTake(s_core_mutex, wait_ticks(P4_CTAPHID_LOCK_MS)) != pdTRUE) {
        // the transport task completes the already published request
        return;
    }

    (void)take_transport_reset_request();
    TaskHandle_t owner = reset_core_locked();
    // drain reports inside the same state boundary used before every receive
    usb_drop_pending();
    (void)xSemaphoreGive(s_core_mutex);

    (void)xSemaphoreGive(s_message_wake);
    notify_owner(owner);
}


static bool process_requested_reset(void)
{
    if (!transport_reset_pending()) {
        return true;
    }
    if (xSemaphoreTake(s_core_mutex,
                       wait_ticks(P4_CTAPHID_LOCK_MS)) != pdTRUE) {
        return false;
    }

    if (!take_transport_reset_request()) {
        (void)xSemaphoreGive(s_core_mutex);
        return true;
    }

    TaskHandle_t owner = reset_core_locked();
    usb_drop_pending();
    (void)xSemaphoreGive(s_core_mutex);

    (void)xSemaphoreGive(s_message_wake);
    notify_owner(owner);
    return true;
}


static bool sync_usb_before_take(uint32_t generation, uint32_t *epoch)
{
    if (xSemaphoreTake(s_core_mutex,
                       wait_ticks(P4_CTAPHID_LOCK_MS)) != pdTRUE) {
        return false;
    }

    TaskHandle_t owner = NULL;
    bool changed = generation != s_seen_usb_generation;
    if (changed) {
        s_seen_usb_generation = generation;
        owner = reset_core_locked();
    }
    *epoch = s_reset_epoch;
    (void)xSemaphoreGive(s_core_mutex);

    if (changed) {
        (void)xSemaphoreGive(s_message_wake);
        notify_owner(owner);
    }
    return true;
}


static void transport_task(void *arg)
{
    (void)arg;
    uint8_t report[P4_CTAPHID_REPORT_BYTES];

    for (;;) {
        if (!process_requested_reset()) {
            vTaskDelay(wait_ticks(P4_CTAPHID_USB_WAIT_MS));
            continue;
        }

        uint32_t take_epoch = 0;
        if (!sync_usb_before_take(usb_unmount_generation(), &take_epoch)) {
            vTaskDelay(wait_ticks(P4_CTAPHID_USB_WAIT_MS));
            continue;
        }

        uint32_t usb_generation = 0;
        int error = usb_take_with_generation(
            report, P4_CTAPHID_USB_WAIT_MS, &usb_generation);
        if (error == P4_USB_ERR_TIMEOUT) {
            if (xSemaphoreTake(s_core_mutex,
                               wait_ticks(P4_CTAPHID_LOCK_MS)) == pdTRUE) {
                p4_ctaphid_core_cleanup(&s_core, now_ms());
                (void)xSemaphoreGive(s_core_mutex);
            }
            continue;
        }
        if (error != P4_USB_OK) {
            if (error == P4_USB_ERR_DISCONNECTED) {
                vTaskDelay(wait_ticks(P4_CTAPHID_USB_WAIT_MS));
            }
            continue;
        }

        if (xSemaphoreTake(s_core_mutex,
                           wait_ticks(P4_CTAPHID_LOCK_MS)) != pdTRUE) {
            continue;
        }

        uint32_t current_usb_generation = usb_unmount_generation();
        TaskHandle_t owner = NULL;
        bool reset_raced = s_reset_epoch != take_epoch;
        if (take_transport_reset_request()) {
            owner = reset_core_locked();
            usb_drop_pending();
            reset_raced = true;
        }

        bool accept_report = !reset_raced;
        if (current_usb_generation != usb_generation) {
            // a report from the old connection never enters the new core
            if (current_usb_generation != s_seen_usb_generation) {
                s_seen_usb_generation = current_usb_generation;
                if (!reset_raced) {
                    owner = reset_core_locked();
                }
            }
            accept_report = false;
        } else if (usb_generation != s_seen_usb_generation) {
            // the first report can arrive before the loop observes mount
            s_seen_usb_generation = usb_generation;
            if (!reset_raced) {
                owner = reset_core_locked();
            }
        }

        if (!accept_report) {
            (void)xSemaphoreGive(s_core_mutex);
            (void)xSemaphoreGive(s_message_wake);
            notify_owner(owner);
            continue;
        }

        p4_ctaphid_action_t action;
        (void)p4_ctaphid_core_feed(&s_core, report, now_ms(),
                                    random_bytes, NULL, &action);
        TaskHandle_t stale_owner = clear_stale_claim_locked();
        if (stale_owner != NULL) {
            owner = stale_owner;
        }
        bool wake_message = false;

        if (action.kind == P4_CTAPHID_ACTION_SEND &&
            action.data_len <= sizeof(s_immediate_payload)) {
            if (action.data_len != 0) {
                memcpy(s_immediate_payload, action.data, action.data_len);
            }
            (void)send_locked(action.cid, action.command,
                              s_immediate_payload, action.data_len,
                              usb_generation);
            if (action.generation != 0) {
                p4_ctaphid_core_finish_response(&s_core, action.cid,
                                                 action.generation);
            }
        } else if (action.kind == P4_CTAPHID_ACTION_MESSAGE) {
            s_message_usb_generation = usb_generation;
            wake_message = true;
        } else if (action.kind == P4_CTAPHID_ACTION_CANCEL &&
                   s_claim.valid && s_claim.cid == action.cid &&
                   s_claim.operation_generation == action.generation) {
            owner = s_claim.owner;
        }

        (void)xSemaphoreGive(s_core_mutex);

        if (wake_message) {
            (void)xSemaphoreGive(s_message_wake);
        }
        notify_owner(owner);
    }
}


int hid_start(void)
{
    if (s_started) {
        return P4_HID_ERR_STATE;
    }

    s_core_mutex = xSemaphoreCreateMutexStatic(&s_core_mutex_storage);
    s_message_wake = xSemaphoreCreateBinaryStatic(&s_message_wake_storage);
    s_tx_mutex = xSemaphoreCreateMutexStatic(&s_tx_mutex_storage);
    if (s_core_mutex == NULL || s_message_wake == NULL ||
        s_tx_mutex == NULL) {
        return P4_HID_ERR_STATE;
    }

    p4_ctaphid_core_init(&s_core);
    memset(&s_claim, 0, sizeof(s_claim));
    s_message_usb_generation = 0;
    s_reset_epoch = 0;
    s_reset_requested = false;

    int error = usb_start();
    if (error != P4_USB_OK) {
        return map_usb_error(error);
    }

    s_seen_usb_generation = usb_unmount_generation();
    s_started = true;
    TaskHandle_t task = xTaskCreateStatic(
        transport_task,
        "p4_ctaphid",
        sizeof(s_transport_stack) / sizeof(s_transport_stack[0]),
        NULL,
        tskIDLE_PRIORITY + 2,
        s_transport_stack,
        &s_transport_task_storage);
    if (task == NULL) {
        s_started = false;
        return P4_HID_ERR_STATE;
    }
    return P4_HID_OK;
}


int hid_take_msg(uint32_t *cid,
                 uint8_t *cmd,
                 uint8_t *data,
                 size_t cap,
                 size_t *data_len,
                 uint32_t wait_ms)
{
    if (!s_started || cid == NULL || cmd == NULL || data_len == NULL ||
        (data == NULL && cap != 0)) {
        return P4_HID_ERR_ARG;
    }

    TimeOut_t timeout;
    TickType_t remaining = wait_ticks(wait_ms);
    vTaskSetTimeOutState(&timeout);

    for (;;) {
        if (xSemaphoreTake(s_core_mutex,
                           wait_ticks(P4_CTAPHID_LOCK_MS)) != pdTRUE) {
            return P4_HID_ERR_TIMEOUT;
        }

        int result = P4_HID_ERR_TIMEOUT;
        if (transport_reset_pending()) {
            result = P4_HID_ERR_DISCONNECTED;
        } else if (s_claim.valid) {
            result = P4_HID_ERR_STATE;
        } else if (!usb_ready() ||
                   usb_unmount_generation() != s_seen_usb_generation) {
            result = P4_HID_ERR_DISCONNECTED;
        } else if (s_core.message_ready &&
                   usb_unmount_generation() != s_message_usb_generation) {
            (void)reset_core_locked();
            result = P4_HID_ERR_DISCONNECTED;
        } else {
            uint32_t operation_generation = 0;
            int core_error = p4_ctaphid_core_take_message(
                &s_core, cid, cmd, data, cap, data_len,
                &operation_generation);
            if (core_error == P4_CTAPHID_CORE_OK) {
                s_claim.valid = true;
                s_claim.cid = *cid;
                s_claim.operation_generation = operation_generation;
                s_claim.usb_generation = s_message_usb_generation;
                s_claim.command = *cmd;
                s_claim.owner = xTaskGetCurrentTaskHandle();
                s_message_usb_generation = 0;
                result = P4_HID_OK;
            } else if (core_error == P4_CTAPHID_CORE_SMALL) {
                result = P4_HID_ERR_SMALL;
            } else if (core_error != P4_CTAPHID_CORE_EMPTY) {
                result = P4_HID_ERR_ARG;
            }
        }
        (void)xSemaphoreGive(s_core_mutex);

        if (result != P4_HID_ERR_TIMEOUT) {
            if (result == P4_HID_OK) {
                drain_message_wake();
            }
            return result;
        }
        if (remaining == 0 ||
            xTaskCheckForTimeOut(&timeout, &remaining) == pdTRUE) {
            return P4_HID_ERR_TIMEOUT;
        }
        if (xSemaphoreTake(s_message_wake, remaining) != pdTRUE) {
            return P4_HID_ERR_TIMEOUT;
        }
    }
}


int hid_send_msg(uint32_t cid,
                 uint8_t cmd,
                 const uint8_t *data,
                 size_t data_len)
{
    if (!s_started || cid == 0 || (cmd & 0x80U) == 0 ||
        data_len > P4_CTAPHID_MAX_PAYLOAD ||
        (data == NULL && data_len != 0)) {
        return P4_HID_ERR_ARG;
    }
    if (xSemaphoreTake(s_core_mutex,
                       wait_ticks(P4_CTAPHID_LOCK_MS)) != pdTRUE) {
        return P4_HID_ERR_TIMEOUT;
    }

    if (!claim_matches_locked(cid, true) || s_claim.command != cmd) {
        (void)xSemaphoreGive(s_core_mutex);
        return P4_HID_ERR_STATE;
    }

    uint8_t cancel_result = CTAP2_ERR_KEEPALIVE_CANCEL;
    const uint8_t *response_data = data;
    size_t response_len = data_len;
    if (cmd == CTAPHID_CBOR &&
        p4_ctaphid_core_cancelled(&s_core, cid,
                                  s_claim.operation_generation)) {
        // make the final cancel decision under the same lock as transmission
        response_data = &cancel_result;
        response_len = 1;
    }

    uint32_t operation_generation = s_claim.operation_generation;
    int result = send_locked(cid, cmd, response_data, response_len,
                             s_claim.usb_generation);
    p4_ctaphid_core_finish_response(&s_core, cid, operation_generation);
    (void)clear_claim_locked();
    (void)xSemaphoreGive(s_core_mutex);
    return result;
}


int hid_keepalive(uint32_t cid, uint8_t status)
{
    if (!s_started ||
        (status != CTAPHID_KEEPALIVE_PROCESSING &&
         status != CTAPHID_KEEPALIVE_UP_NEEDED)) {
        return P4_HID_ERR_ARG;
    }
    if (xSemaphoreTake(s_core_mutex,
                       wait_ticks(P4_CTAPHID_LOCK_MS)) != pdTRUE) {
        return P4_HID_ERR_TIMEOUT;
    }

    if (!claim_matches_locked(cid, true) ||
        s_claim.command != CTAPHID_CBOR ||
        p4_ctaphid_core_cancelled(&s_core, cid,
                                  s_claim.operation_generation)) {
        (void)xSemaphoreGive(s_core_mutex);
        return P4_HID_ERR_STATE;
    }

    p4_ctaphid_channel_t *channel = p4_ctaphid_chan_find(&s_core, cid);
    uint32_t current_ms = now_ms();
    if (channel == NULL ||
        (channel->keepalive_sent &&
         channel->last_keepalive_status == status &&
         !p4_ctaphid_time_expired(current_ms, channel->last_keepalive_ms,
                                  P4_CTAPHID_KEEPALIVE_MS))) {
        (void)xSemaphoreGive(s_core_mutex);
        return P4_HID_ERR_RATE;
    }

    int result = send_locked(cid, CTAPHID_KEEPALIVE, &status, 1,
                             s_claim.usb_generation);
    if (result == P4_HID_OK) {
        channel->keepalive_sent = true;
        channel->last_keepalive_ms = now_ms();
        channel->last_keepalive_status = status;
    }
    (void)xSemaphoreGive(s_core_mutex);
    return result;
}


bool hid_cancelled(uint32_t cid)
{
    if (!s_started ||
        xSemaphoreTake(s_core_mutex,
                       wait_ticks(P4_CTAPHID_LOCK_MS)) != pdTRUE) {
        return true;
    }

    bool cancelled = !claim_matches_locked(cid, true) ||
        p4_ctaphid_core_cancelled(&s_core, cid,
                                  s_claim.operation_generation);
    (void)xSemaphoreGive(s_core_mutex);
    return cancelled;
}


void hid_clear_cancel(uint32_t cid)
{
    if (!s_started ||
        xSemaphoreTake(s_core_mutex,
                       wait_ticks(P4_CTAPHID_LOCK_MS)) != pdTRUE) {
        return;
    }

    if (claim_matches_locked(cid, true)) {
        p4_ctaphid_core_clear_cancel(&s_core, cid,
                                     s_claim.operation_generation);
    }
    (void)xSemaphoreGive(s_core_mutex);
}
