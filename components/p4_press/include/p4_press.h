#pragma once

#include <stdbool.h>
#include <stdint.h>

enum {
    P4_PRESS_OK = 0,
    P4_PRESS_CANCEL = -1,
    P4_PRESS_DENIED = -2,
    P4_PRESS_TIMEOUT = -3,
};

int press_wait(uint32_t cid);
bool press_cancelled(uint32_t cid);
