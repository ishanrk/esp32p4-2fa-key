#include "p4_press.h"

#include <stdbool.h>

#include "p4_board.h"
#include "p4_ctaphid.h"
#include "p4_ctaphid_wire.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

enum {
    PRESS_SAMPLE_MS = 10,
    PRESS_DEBOUNCE_MS = 40,
    PRESS_TIMEOUT_MS = 30000,
};


int press_wait(uint32_t cid)
{
    if (!p4_board_button_ready()) {
        return P4_PRESS_DENIED;
    }

    bool need_release = p4_board_button_pressed();
    uint32_t stable_ms = 0;
    for (uint32_t elapsed_ms = 0;
         elapsed_ms < PRESS_TIMEOUT_MS;
         elapsed_ms += PRESS_SAMPLE_MS) {
        if (hid_cancelled(cid)) {
            return P4_PRESS_CANCEL;
        }
        if (elapsed_ms % P4_CTAPHID_KEEPALIVE_MS == 0) {
            int error = hid_keepalive(cid, CTAPHID_KEEPALIVE_UP_NEEDED);
            if (error != P4_HID_OK && error != P4_HID_ERR_RATE) {
                return hid_cancelled(cid)
                           ? P4_PRESS_CANCEL
                           : P4_PRESS_DENIED;
            }
        }

        bool pressed = p4_board_button_pressed();
        bool wanted = need_release ? !pressed : pressed;
        stable_ms = wanted ? stable_ms + PRESS_SAMPLE_MS : 0;
        if (stable_ms >= PRESS_DEBOUNCE_MS) {
            if (!need_release) {
                return hid_cancelled(cid)
                           ? P4_PRESS_CANCEL
                           : P4_PRESS_OK;
            }
            need_release = false;
            stable_ms = 0;
        }
        vTaskDelay(pdMS_TO_TICKS(PRESS_SAMPLE_MS));
    }
    return P4_PRESS_DENIED;
}
