#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

enum {
    P4_CTAP_MAX_MESSAGE = 2048,
    P4_CTAP_MAX_CREDENTIALS_IN_LIST = 16,
    P4_CTAP_MAX_CREDENTIAL_ID_LEN = 128,

    P4_CTAP_CMD_MAKE_CREDENTIAL = 0x01,
    P4_CTAP_CMD_GET_ASSERTION = 0x02,
    P4_CTAP_CMD_GET_INFO = 0x04,

    P4_CTAP_STATUS_OK = 0x00,
    P4_CTAP_STATUS_INVALID_COMMAND = 0x01,
    P4_CTAP_STATUS_INVALID_PARAMETER = 0x02,
    P4_CTAP_STATUS_INVALID_LENGTH = 0x03,
    P4_CTAP_STATUS_CBOR_UNEXPECTED_TYPE = 0x11,
    P4_CTAP_STATUS_INVALID_CBOR = 0x12,
    P4_CTAP_STATUS_MISSING_PARAMETER = 0x14,
    P4_CTAP_STATUS_LIMIT_EXCEEDED = 0x15,
    P4_CTAP_STATUS_CREDENTIAL_EXCLUDED = 0x19,
    P4_CTAP_STATUS_UNSUPPORTED_ALGORITHM = 0x26,
    P4_CTAP_STATUS_OPERATION_DENIED = 0x27,
    P4_CTAP_STATUS_UNSUPPORTED_OPTION = 0x2b,
    P4_CTAP_STATUS_KEEPALIVE_CANCEL = 0x2d,
    P4_CTAP_STATUS_NO_CREDENTIALS = 0x2e,
    P4_CTAP_STATUS_USER_ACTION_TIMEOUT = 0x2f,
    P4_CTAP_STATUS_OTHER = 0x7f,
};

enum {
    P4_CTAP_OK = 0,
    P4_CTAP_ERR_ARG = -1,
    P4_CTAP_ERR_SMALL = -2,
};

// request begins with one CTAP command byte
// response begins with one CTAP status byte
int p4_ctap_dispatch(uint32_t cid,
                     const uint8_t *request,
                     size_t request_len,
                     uint8_t *response,
                     size_t response_cap,
                     size_t *response_len);

#ifdef __cplusplus
}
#endif
