#pragma once

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

enum {
    P4_AAGUID_LEN = 16,
};

extern const uint8_t p4_aaguid[P4_AAGUID_LEN];

#ifdef __cplusplus
}
#endif
