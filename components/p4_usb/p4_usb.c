#include "p4_usb.h"

#include "p4_board.h"
#include "p4_usb_desc_private.h"
#include "p4_usb_queue.h"

#include <inttypes.h>
#include <limits.h>
#include <string.h>

#include "esp_err.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "tinyusb.h"
#include "tinyusb_default_config.h"
#include "tusb.h"

typedef struct {
    uint32_t mounted;
    uint32_t unmounted;
    uint32_t suspended;
    uint32_t resumed;
    uint32_t bad_report_length;
    uint32_t unexpected_report_id;
    uint32_t receive_queue_full;
    uint32_t send_timeout;
} p4_usb_diag_t;

static const char *tag = "p4_usb";

static portMUX_TYPE s_lock = portMUX_INITIALIZER_UNLOCKED;
static p4_usb_queue_t s_rx_queue;
static p4_usb_diag_t s_diag;

static StaticSemaphore_t s_rx_wake_storage;
static StaticSemaphore_t s_tx_wake_storage;
static StaticSemaphore_t s_tx_mutex_storage;
static SemaphoreHandle_t s_rx_wake;
static SemaphoreHandle_t s_tx_wake;
static SemaphoreHandle_t s_tx_mutex;

static bool s_started;
static bool s_mounted;
static bool s_ready;
static uint32_t s_generation;
static bool s_have_take_generation;
static uint32_t s_take_generation;

typedef enum {
    P4_USB_SEND_LEGACY = 0,
    P4_USB_SEND_GENERATION,
} p4_usb_send_auth_t;


static void count_one(uint32_t *counter)
{
    if (*counter != UINT32_MAX) {
        (*counter)++;
    }
}


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


static void wake(SemaphoreHandle_t semaphore)
{
    if (semaphore != NULL) {
        (void)xSemaphoreGive(semaphore);
    }
}


static void count_send_timeout(void)
{
    taskENTER_CRITICAL(&s_lock);
    count_one(&s_diag.send_timeout);
    taskEXIT_CRITICAL(&s_lock);
}


static bool send_state(uint32_t *generation, bool *take_matches)
{
    bool ready;

    taskENTER_CRITICAL(&s_lock);
    ready = s_started && s_ready;
    *generation = s_generation;
    *take_matches = s_have_take_generation &&
                    s_take_generation == s_generation;
    taskEXIT_CRITICAL(&s_lock);
    return ready;
}


static void usb_event(tinyusb_event_t *event, void *arg)
{
    (void)arg;
    if (event == NULL) {
        return;
    }

    taskENTER_CRITICAL(&s_lock);
    switch (event->id) {
    case TINYUSB_EVENT_ATTACHED:
        p4_usb_queue_reset(&s_rx_queue);
        s_have_take_generation = false;
        s_mounted = true;
        s_ready = true;
        // every configured host connection gets a fresh response token
        s_generation++;
        count_one(&s_diag.mounted);
        break;

    case TINYUSB_EVENT_DETACHED:
        s_mounted = false;
        s_ready = false;
        s_generation++;
        s_have_take_generation = false;
        p4_usb_queue_reset(&s_rx_queue);
        count_one(&s_diag.unmounted);
        break;

#ifdef CONFIG_TINYUSB_SUSPEND_CALLBACK
    case TINYUSB_EVENT_SUSPENDED:
        s_ready = false;
        // this separately powered board has no routed VBUS monitor
        // treat suspend as a disconnect boundary for held reports
        s_generation++;
        s_have_take_generation = false;
        p4_usb_queue_reset(&s_rx_queue);
        count_one(&s_diag.suspended);
        break;
#endif

#ifdef CONFIG_TINYUSB_RESUME_CALLBACK
    case TINYUSB_EVENT_RESUMED:
        // bus resume alone does not prove the HID configuration is mounted
        s_ready = s_mounted;
        count_one(&s_diag.resumed);
        break;
#endif

    default:
        break;
    }
    taskEXIT_CRITICAL(&s_lock);

    // wake tasks so they can observe the new bus state
    wake(s_rx_wake);
    wake(s_tx_wake);
}


int usb_start(void)
{
    taskENTER_CRITICAL(&s_lock);
    if (s_started) {
        taskEXIT_CRITICAL(&s_lock);
        return P4_USB_ERR_STATE;
    }

    p4_usb_queue_init(&s_rx_queue);
    memset(&s_diag, 0, sizeof(s_diag));
    s_mounted = false;
    s_ready = false;
    s_generation = 0;
    s_have_take_generation = false;
    s_started = true;
    taskEXIT_CRITICAL(&s_lock);

    s_rx_wake = xSemaphoreCreateBinaryStatic(&s_rx_wake_storage);
    s_tx_wake = xSemaphoreCreateBinaryStatic(&s_tx_wake_storage);
    s_tx_mutex = xSemaphoreCreateMutexStatic(&s_tx_mutex_storage);
    if (s_rx_wake == NULL || s_tx_wake == NULL || s_tx_mutex == NULL) {
        taskENTER_CRITICAL(&s_lock);
        s_started = false;
        taskEXIT_CRITICAL(&s_lock);
        return P4_USB_ERR_STATE;
    }

    esp_err_t err = p4_board_usb_prepare();
    if (err != ESP_OK) {
        taskENTER_CRITICAL(&s_lock);
        s_started = false;
        taskEXIT_CRITICAL(&s_lock);
        ESP_LOGE(tag, "native USB PHY route failed: %s", esp_err_to_name(err));
        return P4_USB_ERR_DRIVER;
    }

    // select the OTG1.1 controller after routing it to the Type-C PHY
    tinyusb_config_t config = TINYUSB_CONFIG_FULL_SPEED(usb_event, NULL);
    config.descriptor.device = &p4_usb_device_desc;
    config.descriptor.qualifier = NULL;
    config.descriptor.string = p4_usb_string_desc;
    config.descriptor.string_count = p4_usb_string_desc_count;
    config.descriptor.full_speed_config = p4_usb_config_desc;
    config.descriptor.high_speed_config = NULL;

    err = tinyusb_driver_install(&config);
    if (err != ESP_OK) {
        taskENTER_CRITICAL(&s_lock);
        s_started = false;
        taskEXIT_CRITICAL(&s_lock);
        ESP_LOGE(tag, "TinyUSB full speed start failed: %s",
                 esp_err_to_name(err));
        return P4_USB_ERR_DRIVER;
    }

    ESP_LOGI(tag, "full speed HID ready on native USB connector");
    return P4_USB_OK;
}


static int usb_take_common(uint8_t report[P4_USB_REPORT_BYTES],
                           uint32_t wait_ms,
                           uint32_t *out_generation,
                           bool remember_for_legacy_send)
{
    if (report == NULL ||
        (out_generation == NULL && !remember_for_legacy_send)) {
        return P4_USB_ERR_ARG;
    }

    TimeOut_t timeout;
    TickType_t remaining = wait_ticks(wait_ms);
    vTaskSetTimeOutState(&timeout);

    taskENTER_CRITICAL(&s_lock);
    bool started = s_started;
    if (remember_for_legacy_send) {
        s_have_take_generation = false;
    }
    taskEXIT_CRITICAL(&s_lock);
    if (!started) {
        return P4_USB_ERR_STATE;
    }

    for (;;) {
        p4_usb_queue_item_t item;
        bool have_item;
        bool ready;
        uint32_t generation;

        taskENTER_CRITICAL(&s_lock);
        have_item = p4_usb_queue_pop(&s_rx_queue, &item);
        ready = s_ready;
        generation = s_generation;
        taskEXIT_CRITICAL(&s_lock);

        if (have_item) {
            if (!ready || item.generation != generation) {
                return P4_USB_ERR_STALE;
            }

            taskENTER_CRITICAL(&s_lock);
            if (!s_ready || s_generation != item.generation) {
                taskEXIT_CRITICAL(&s_lock);
                return P4_USB_ERR_STALE;
            }
            if (remember_for_legacy_send) {
                s_take_generation = item.generation;
                s_have_take_generation = true;
            }
            taskEXIT_CRITICAL(&s_lock);

            // copy only after every failure path so errors preserve the caller buffer
            memcpy(report, item.report, P4_USB_REPORT_BYTES);
            if (out_generation != NULL) {
                *out_generation = item.generation;
            }
            return P4_USB_OK;
        }

        if (!ready) {
            return P4_USB_ERR_DISCONNECTED;
        }
        if (remaining == 0 ||
            xTaskCheckForTimeOut(&timeout, &remaining) == pdTRUE) {
            return P4_USB_ERR_TIMEOUT;
        }

        if (xSemaphoreTake(s_rx_wake, remaining) != pdTRUE ||
            xTaskCheckForTimeOut(&timeout, &remaining) == pdTRUE) {
            return P4_USB_ERR_TIMEOUT;
        }
    }
}


int usb_take(uint8_t report[P4_USB_REPORT_BYTES], uint32_t wait_ms)
{
    return usb_take_common(report, wait_ms, NULL, true);
}


int usb_take_with_generation(uint8_t report[P4_USB_REPORT_BYTES],
                             uint32_t wait_ms,
                             uint32_t *generation)
{
    return usb_take_common(report, wait_ms, generation, false);
}


static int usb_send_common(const uint8_t report[P4_USB_REPORT_BYTES],
                           uint32_t expected_generation,
                           uint32_t wait_ms,
                           p4_usb_send_auth_t auth)
{
    if (report == NULL) {
        return P4_USB_ERR_ARG;
    }

    TimeOut_t timeout;
    TickType_t remaining = wait_ticks(wait_ms);
    vTaskSetTimeOutState(&timeout);

    if (s_tx_mutex == NULL) {
        return P4_USB_ERR_STATE;
    }
    if (xSemaphoreTake(s_tx_mutex, remaining) != pdTRUE) {
        count_send_timeout();
        return P4_USB_ERR_TIMEOUT;
    }

    int result = P4_USB_ERR_TIMEOUT;
    uint32_t current_generation = 0;
    bool take_matches = false;
    bool ready = send_state(&current_generation, &take_matches);
    if (!ready) {
        result = P4_USB_ERR_DISCONNECTED;
        goto done;
    }
    if (auth == P4_USB_SEND_LEGACY) {
        expected_generation = current_generation;
    }
    if (current_generation != expected_generation ||
        (auth == P4_USB_SEND_LEGACY && !take_matches)) {
        result = P4_USB_ERR_STALE;
        goto done;
    }

    bool zero_wait = wait_ms == 0;
    if (!zero_wait &&
        xTaskCheckForTimeOut(&timeout, &remaining) == pdTRUE) {
        count_send_timeout();
        result = P4_USB_ERR_TIMEOUT;
        goto done;
    }

    for (;;) {
        uint32_t generation;
        ready = send_state(&generation, &take_matches);
        if (!ready) {
            result = P4_USB_ERR_DISCONNECTED;
            break;
        }
        if (generation != expected_generation ||
            (auth == P4_USB_SEND_LEGACY && !take_matches)) {
            result = P4_USB_ERR_STALE;
            break;
        }

        if (tud_hid_n_ready(0) &&
            tud_hid_n_report(0, 0, report, P4_USB_REPORT_BYTES)) {
            result = P4_USB_OK;
            break;
        }

        if (zero_wait || remaining == 0) {
            count_send_timeout();
            result = P4_USB_ERR_TIMEOUT;
            break;
        }

        if (xSemaphoreTake(s_tx_wake, remaining) != pdTRUE ||
            xTaskCheckForTimeOut(&timeout, &remaining) == pdTRUE) {
            count_send_timeout();
            result = P4_USB_ERR_TIMEOUT;
            break;
        }
    }

done:
    (void)xSemaphoreGive(s_tx_mutex);
    return result;
}


int usb_send(const uint8_t report[P4_USB_REPORT_BYTES], uint32_t wait_ms)
{
    return usb_send_common(report, 0, wait_ms, P4_USB_SEND_LEGACY);
}


int usb_send_for_generation(const uint8_t report[P4_USB_REPORT_BYTES],
                            uint32_t generation,
                            uint32_t wait_ms)
{
    return usb_send_common(report, generation, wait_ms,
                           P4_USB_SEND_GENERATION);
}


bool usb_ready(void)
{
    bool ready;
    taskENTER_CRITICAL(&s_lock);
    ready = s_started && s_ready;
    taskEXIT_CRITICAL(&s_lock);
    return ready;
}


void usb_drop_pending(void)
{
    taskENTER_CRITICAL(&s_lock);
    p4_usb_queue_reset(&s_rx_queue);
    s_have_take_generation = false;
    taskEXIT_CRITICAL(&s_lock);
}


uint32_t usb_unmount_generation(void)
{
    uint32_t generation;
    taskENTER_CRITICAL(&s_lock);
    generation = s_generation;
    taskEXIT_CRITICAL(&s_lock);
    return generation;
}


void usb_diag_print(void)
{
    p4_usb_diag_t diag;
    taskENTER_CRITICAL(&s_lock);
    diag = s_diag;
    taskEXIT_CRITICAL(&s_lock);

    ESP_LOGI(tag,
             "diag mount=%" PRIu32 " unmount=%" PRIu32
             " suspend=%" PRIu32 " resume=%" PRIu32
             " bad_len=%" PRIu32 " bad_id=%" PRIu32
             " rx_full=%" PRIu32 " send_timeout=%" PRIu32,
             diag.mounted, diag.unmounted, diag.suspended, diag.resumed,
             diag.bad_report_length, diag.unexpected_report_id,
             diag.receive_queue_full, diag.send_timeout);
}


uint8_t const *tud_hid_descriptor_report_cb(uint8_t instance)
{
    return instance == 0 ? p4_usb_report_desc : NULL;
}


uint16_t tud_hid_get_report_cb(uint8_t instance, uint8_t report_id,
                               hid_report_type_t report_type, uint8_t *buffer,
                               uint16_t reqlen)
{
    (void)instance;
    (void)report_id;
    (void)report_type;
    (void)buffer;
    (void)reqlen;

    // no control input or feature reports
    return 0;
}


void tud_hid_set_report_cb(uint8_t instance, uint8_t report_id,
                           hid_report_type_t report_type,
                           uint8_t const *buffer, uint16_t bufsize)
{
    if (instance != 0 || report_id != 0) {
        taskENTER_CRITICAL(&s_lock);
        count_one(&s_diag.unexpected_report_id);
        taskEXIT_CRITICAL(&s_lock);
        return;
    }
    if (report_type != HID_REPORT_TYPE_OUTPUT) {
        return;
    }
    if (buffer == NULL || bufsize != P4_USB_REPORT_BYTES) {
        taskENTER_CRITICAL(&s_lock);
        count_one(&s_diag.bad_report_length);
        taskEXIT_CRITICAL(&s_lock);
        return;
    }

    bool queued = false;
    taskENTER_CRITICAL(&s_lock);
    if (s_ready) {
        queued = p4_usb_queue_push(&s_rx_queue, buffer, s_generation);
        if (!queued) {
            // preserve every unread report and reject this newest report
            count_one(&s_diag.receive_queue_full);
        }
    }
    taskEXIT_CRITICAL(&s_lock);

    if (queued) {
        wake(s_rx_wake);
    }
}


void tud_hid_report_complete_cb(uint8_t instance, uint8_t const *report,
                                uint16_t len)
{
    (void)instance;
    (void)report;
    (void)len;
    wake(s_tx_wake);
}


void tud_hid_report_failed_cb(uint8_t instance,
                              hid_report_type_t report_type,
                              uint8_t const *report, uint16_t xferred_bytes)
{
    (void)instance;
    (void)report;
    (void)xferred_bytes;
    if (report_type == HID_REPORT_TYPE_INPUT) {
        wake(s_tx_wake);
    }
}
