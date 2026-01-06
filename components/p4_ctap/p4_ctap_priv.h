#pragma once

#include <stddef.h>
#include <stdint.h>


int p4_ctap_get_info(uint8_t *response,
                     size_t response_cap,
                     size_t *response_len);

int p4_ctap_make_credential(uint32_t cid,
                            const uint8_t *request,
                            size_t request_len,
                            uint8_t *response,
                            size_t response_cap,
                            size_t *response_len);

int p4_ctap_get_assertion(uint32_t cid,
                          const uint8_t *request,
                          size_t request_len,
                          uint8_t *response,
                          size_t response_cap,
                          size_t *response_len);
