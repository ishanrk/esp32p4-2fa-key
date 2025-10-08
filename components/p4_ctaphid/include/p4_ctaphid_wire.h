#pragma once

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

enum {
    P4_CTAPHID_REPORT_BYTES = 64,
    P4_CTAPHID_INIT_DATA_BYTES = 57,
    P4_CTAPHID_CONT_DATA_BYTES = 59,
    P4_CTAPHID_MAX_PAYLOAD = 2048,
    P4_CTAPHID_CHANNEL_COUNT = 4,
    P4_CTAPHID_MAX_SEQUENCE = 0x7f,

    // ctap 2.2 leaves this numeric timeout to the device
    P4_CTAPHID_MESSAGE_TIMEOUT_MS = 500,
    P4_CTAPHID_KEEPALIVE_MS = 100,
};

#define CTAPHID_BROADCAST_CID UINT32_C(0xffffffff)

// keep the complete command byte used in an initialization packet
enum {
    CTAPHID_PING = 0x81,
    CTAPHID_INIT = 0x86,
    CTAPHID_CBOR = 0x90,
    CTAPHID_CANCEL = 0x91,
    CTAPHID_KEEPALIVE = 0xbb,
    CTAPHID_ERROR = 0xbf,
};

enum {
    CTAPHID_ERR_INVALID_CMD = 0x01,
    CTAPHID_ERR_INVALID_PAR = 0x02,
    CTAPHID_ERR_INVALID_LEN = 0x03,
    CTAPHID_ERR_INVALID_SEQ = 0x04,
    CTAPHID_ERR_MSG_TIMEOUT = 0x05,
    CTAPHID_ERR_CHANNEL_BUSY = 0x06,
    CTAPHID_ERR_LOCK_REQUIRED = 0x0a,
    CTAPHID_ERR_INVALID_CHANNEL = 0x0b,
    CTAPHID_ERR_OTHER = 0x7f,
};

enum {
    CTAPHID_KEEPALIVE_PROCESSING = 0x01,
    CTAPHID_KEEPALIVE_UP_NEEDED = 0x02,
};

enum {
    CTAPHID_PROTOCOL_VERSION = 2,
    CTAPHID_CAPABILITY_WINK = 0x01,
    CTAPHID_CAPABILITY_CBOR = 0x04,
    CTAPHID_CAPABILITY_NMSG = 0x08,
    CTAPHID_CAPABILITIES = CTAPHID_CAPABILITY_CBOR |
                           CTAPHID_CAPABILITY_NMSG,
};

enum {
    CTAP1_ERR_INVALID_COMMAND = 0x01,
    CTAP2_ERR_KEEPALIVE_CANCEL = 0x2d,
};

_Static_assert(P4_CTAPHID_INIT_DATA_BYTES ==
               P4_CTAPHID_REPORT_BYTES - 7,
               "CTAPHID initial packet payload size");
_Static_assert(P4_CTAPHID_CONT_DATA_BYTES ==
               P4_CTAPHID_REPORT_BYTES - 5,
               "CTAPHID continuation packet payload size");
_Static_assert(P4_CTAPHID_MAX_PAYLOAD <= UINT16_MAX,
               "CTAPHID payload length fits on the wire");
_Static_assert(P4_CTAPHID_CHANNEL_COUNT >= 4,
               "CTAPHID needs at least four channel records");

#ifdef __cplusplus
}
#endif
