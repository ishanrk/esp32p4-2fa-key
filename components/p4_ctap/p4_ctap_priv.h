#pragma once

#include <stddef.h>
#include <stdint.h>


int p4_ctap_get_info(uint8_t *response,
                     size_t response_cap,
                     size_t *response_len);
