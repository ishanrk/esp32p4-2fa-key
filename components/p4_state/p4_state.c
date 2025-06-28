#include "p4_state.h"

#include <inttypes.h>
#include <stddef.h>

#include "esp_chip_info.h"
#include "esp_flash.h"
#include "esp_idf_version.h"
#include "esp_log.h"
#include "esp_psram.h"
#include "sdkconfig.h"

static const char *tag = "p4_state";


esp_err_t p4_state_log_boot(void)
{
    esp_chip_info_t chip;
    uint32_t flash_bytes = 0;

    esp_chip_info(&chip);
    esp_err_t err = esp_flash_get_size(NULL, &flash_bytes);
    if (err != ESP_OK) {
        ESP_LOGE(tag, "flash size query failed: %s", esp_err_to_name(err));
        return err;
    }

    // plain shared facts for each physical run
    // no MAC eFuse or key material
    ESP_LOGI(tag, "ESP32-P4 2FA Key development baseline");
    ESP_LOGI(tag, "ESP-IDF %s", esp_get_idf_version());
    ESP_LOGI(tag, "chip %s revision %u.%u cores %u",
             CONFIG_IDF_TARGET,
             (unsigned)(chip.revision / 100),
             (unsigned)(chip.revision % 100),
             (unsigned)chip.cores);
    ESP_LOGI(tag, "flash bytes %" PRIu32, flash_bytes);

    if (esp_psram_is_initialized()) {
        ESP_LOGI(tag, "PSRAM bytes %zu", esp_psram_get_size());
    } else {
        ESP_LOGW(tag, "PSRAM is not initialized");
    }

    return ESP_OK;
}
