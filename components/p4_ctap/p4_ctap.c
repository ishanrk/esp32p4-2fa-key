#include "p4_ctap.h"


int p4_ctap_dispatch(const uint8_t *request,
                     size_t request_len,
                     uint8_t *response,
                     size_t response_cap,
                     size_t *response_len)
{
    if (response_len == NULL) {
        return P4_CTAP_ERR_ARG;
    }
    *response_len = 0;
    if ((request == NULL && request_len != 0) ||
        request_len > P4_CTAP_MAX_MESSAGE || response == NULL) {
        return P4_CTAP_ERR_ARG;
    }
    if (response_cap < 1) {
        return P4_CTAP_ERR_SMALL;
    }

    response[0] = P4_CTAP_STATUS_INVALID_COMMAND;
    *response_len = 1;
    return P4_CTAP_OK;
}
