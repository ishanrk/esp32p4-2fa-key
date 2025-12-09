#include "p4_board.h"
#include "p4_cred.h"
#if CONFIG_P4KEY_CRED_REBOOT_TEST
#include "p4_cred_test.h"
#endif
#include "p4_ctaphid.h"
#include "p4_crypto.h"
#include "p4_crypto_check.h"
#if CONFIG_P4KEY_CRYPTO_SELFTEST
#include "p4_crypto_test.h"
#endif
#include "p4_state.h"
#include "p4_usb.h"
#include "ctap_stub.h"

#include "esp_err.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#if CONFIG_P4KEY_USB_BRINGUP
#include <string.h>

#define USB_BRINGUP_STACK_BYTES 3072

static StaticTask_t s_usb_bringup_task_storage;
static StackType_t
    s_usb_bringup_stack[USB_BRINGUP_STACK_BYTES / sizeof(StackType_t)];

static const uint8_t s_usb_bringup_request[P4_USB_REPORT_BYTES] =
    "P4KEY USB BRINGUP REQUEST v1";
static const uint8_t s_usb_bringup_response[P4_USB_REPORT_BYTES] =
    "P4KEY USB BRINGUP RESPONSE v1";

_Static_assert(USB_BRINGUP_STACK_BYTES % sizeof(StackType_t) == 0,
               "USB bringup stack alignment");
#endif

static const char *tag = "p4key";


#if CONFIG_P4KEY_USB_BRINGUP
static void usb_bringup_task(void *arg)
{
    (void)arg;
    uint8_t report[P4_USB_REPORT_BYTES];

    for (;;) {
        int err = usb_take(report, 1000);
        if (err == P4_USB_ERR_DISCONNECTED) {
            vTaskDelay(pdMS_TO_TICKS(100));
            continue;
        }
        if (err != P4_USB_OK) {
            continue;
        }

        if (memcmp(report, s_usb_bringup_request, sizeof(report)) != 0) {
            continue;
        }

        err = usb_send(s_usb_bringup_response, 1000);
        if (err == P4_USB_OK) {
            ESP_LOGI(tag, "fixed USB bringup exchange complete");
        } else {
            ESP_LOGW(tag, "fixed USB bringup response failed (%d)", err);
        }
        usb_diag_print();
    }
}


static bool usb_bringup_start(void)
{
    TaskHandle_t task = xTaskCreateStatic(
        usb_bringup_task,
        "usb_bringup",
        sizeof(s_usb_bringup_stack) / sizeof(s_usb_bringup_stack[0]),
        NULL,
        tskIDLE_PRIORITY + 2,
        s_usb_bringup_stack,
        &s_usb_bringup_task_storage);
    return task != NULL;
}
#endif


void app_main(void)
{
    esp_log_level_set("*", ESP_LOG_INFO);

    // baseline facts only
    // no device identity or secret bytes here
    ESP_ERROR_CHECK(p4_state_log_boot());

    int crypto_err = crypto_init();
    if (crypto_err != P4_CRYPTO_OK) {
        ESP_LOGE(tag, "crypto initialization failed (%d)", crypto_err);
        return;
    }

#if CONFIG_P4KEY_CRYPTO_SELFTEST
    if (p4_crypto_selftest_run() != 0) {
        ESP_LOGE(tag, "crypto self test failed");
        return;
    }
#endif

    int cred_err = p4_cred_init();
    if (cred_err != P4_CRED_OK) {
        ESP_LOGE(tag, "credential root initialization failed (%d)", cred_err);
        return;
    }

#if CONFIG_P4KEY_CRED_REBOOT_TEST
    if (p4_cred_reboot_test_run() != 0) {
        ESP_LOGE(tag, "credential reboot test failed");
        return;
    }
#endif

    esp_err_t err = p4_board_init();
    if (err != ESP_OK) {
        ESP_LOGW(tag, "button input unavailable: %s", esp_err_to_name(err));
    }

    ESP_LOGI(tag, "board profile %s", p4_board_profile());
    ESP_LOGI(tag, "native USB device connector %s",
             p4_board_usb_connector());

    if (p4_board_button_ready()) {
        ESP_LOGI(tag, "BOOT button GPIO %d active %s raw %d",
                 p4_board_button_gpio(),
                 p4_board_button_active_low() ? "low" : "high",
                 p4_board_button_raw());
    } else {
        ESP_LOGW(tag, "button GPIO is not configured");
    }

#if CONFIG_P4KEY_USB_BRINGUP
    int transport_err = usb_start();
    if (transport_err != P4_USB_OK) {
        ESP_LOGE(tag, "USB initialization failed (%d)", transport_err);
        return;
    }

    if (!usb_bringup_start()) {
        ESP_LOGE(tag, "USB bringup task creation failed");
        return;
    }
    ESP_LOGW(tag, "fixed USB bringup exchange is enabled");
#else
    int transport_err = hid_start();
    if (transport_err != P4_HID_OK) {
        ESP_LOGE(tag, "CTAPHID initialization failed (%d)", transport_err);
        return;
    }
    if (!p4_ctap_stub_start()) {
        ESP_LOGE(tag, "CTAP stub task creation failed");
        return;
    }
#endif

    for (;;) {
        vTaskDelay(pdMS_TO_TICKS(1000));
    }
}
