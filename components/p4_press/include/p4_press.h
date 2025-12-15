#pragma once

#include <stdint.h>

enum {
    P4_PRESS_OK = 0,
    P4_PRESS_CANCEL = -1,
    P4_PRESS_DENIED = -2,
};

int press_wait(uint32_t cid);
