#include "p4_board.h"
#include "p4_button.h"

#include <stdint.h>

#include "driver/gpio.h"
#include "hal/usb_wrap_ll.h"
#include "sdkconfig.h"

#if !defined(USB_WRAP_LL_SELECT_PHY_SUPPORTED) || !USB_WRAP_LL_SELECT_PHY_SUPPORTED
#error "ESP32-P4 software USB full-speed PHY selection is required"
#endif

#ifndef CONFIG_USJ_ENABLE_USB_SERIAL_JTAG
#error "ESP32-P4 pre-v3 full-speed PHY0 clock source is required"
#endif

enum {
    // Waveshare H2 USB Type-C is FS PHY0 on GPIO24 D- and GPIO25 D+.
    P4_BOARD_USB_FS_PHY_INDEX = 0,
    P4_BOARD_USB_DM_GPIO = GPIO_NUM_24,
    P4_BOARD_USB_DP_GPIO = GPIO_NUM_25,
};

static bool button_ready;


esp_err_t p4_board_init(void)
{
    button_ready = false;
    int gpio = CONFIG_P4KEY_BUTTON_GPIO;
    if (!p4_button_configured(gpio)) {
        return ESP_ERR_NOT_SUPPORTED;
    }

    // schematic has the key closing to ground
    // hold idle high inside the chip
    gpio_config_t config = {
        .pin_bit_mask = UINT64_C(1) << gpio,
        .mode = GPIO_MODE_INPUT,
        .pull_up_en = CONFIG_P4KEY_BUTTON_ACTIVE_LOW
                          ? GPIO_PULLUP_ENABLE
                          : GPIO_PULLUP_DISABLE,
        .pull_down_en = CONFIG_P4KEY_BUTTON_ACTIVE_LOW
                            ? GPIO_PULLDOWN_DISABLE
                            : GPIO_PULLDOWN_ENABLE,
        .intr_type = GPIO_INTR_DISABLE,
    };

    esp_err_t err = gpio_config(&config);
    if (err == ESP_OK) {
        button_ready = true;
    }
    return err;
}


esp_err_t p4_board_usb_prepare(void)
{
    // usb_phy sets 40 mA only on the default PHY1 GPIOs, so mirror it here.
    esp_err_t err = gpio_set_drive_capability(
        P4_BOARD_USB_DM_GPIO, GPIO_DRIVE_CAP_3);
    if (err != ESP_OK) {
        return err;
    }
    err = gpio_set_drive_capability(P4_BOARD_USB_DP_GPIO, GPIO_DRIVE_CAP_3);
    if (err != ESP_OK) {
        return err;
    }

    // Route OTG1.1 USB_WRAP to H2's PHY0 before TinyUSB claims the controller.
    usb_wrap_ll_phy_select(&USB_WRAP, P4_BOARD_USB_FS_PHY_INDEX);
    return ESP_OK;
}


bool p4_board_button_ready(void)
{
    return button_ready;
}


int p4_board_button_gpio(void)
{
    return CONFIG_P4KEY_BUTTON_GPIO;
}


bool p4_board_button_active_low(void)
{
    return CONFIG_P4KEY_BUTTON_ACTIVE_LOW;
}


int p4_board_button_raw(void)
{
    if (!button_ready) {
        return -1;
    }

    return gpio_get_level((gpio_num_t)CONFIG_P4KEY_BUTTON_GPIO);
}


const char *p4_board_profile(void)
{
    return CONFIG_P4KEY_BOARD_PROFILE;
}


const char *p4_board_usb_connector(void)
{
    return CONFIG_P4KEY_USB_CONNECTOR;
}
