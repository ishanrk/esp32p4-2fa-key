#include "p4_board.h"
#include "p4_crypto.h"
#include "p4_crypto_check.h"
#include "p4_state.h"

#include "esp_err.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

static const char *tag = "p4key";


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

    for (;;) {
        vTaskDelay(pdMS_TO_TICKS(1000));
    }
}
