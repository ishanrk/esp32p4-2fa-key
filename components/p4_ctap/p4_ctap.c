#include "p4_ctap.h"

#include "p4_ctap_priv.h"


int p4_ctap_dispatch(uint32_t cid,
                     const uint8_t *request,
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

    if (request_len == 0) {
        response[0] = P4_CTAP_STATUS_INVALID_LENGTH;
        *response_len = 1;
        return P4_CTAP_OK;
    }
    size_t cbor_cap = response_cap - 1;
    if (cbor_cap > P4_CTAP_MAX_MESSAGE - 1U) {
        cbor_cap = P4_CTAP_MAX_MESSAGE - 1U;
    }

    if (request[0] == P4_CTAP_CMD_MAKE_CREDENTIAL) {
        size_t cbor_len = 0;
        int status = p4_ctap_make_credential(
            cid, request + 1, request_len - 1,
            response + 1, cbor_cap, &cbor_len);
        if (status < 0) {
            return status;
        }
        response[0] = (uint8_t)status;
        *response_len = status == P4_CTAP_STATUS_OK ? cbor_len + 1 : 1;
        return P4_CTAP_OK;
    }
    if (request[0] != P4_CTAP_CMD_GET_INFO) {
        response[0] = P4_CTAP_STATUS_INVALID_COMMAND;
        *response_len = 1;
        return P4_CTAP_OK;
    }
    if (request_len != 1) {
        response[0] = P4_CTAP_STATUS_INVALID_CBOR;
        *response_len = 1;
        return P4_CTAP_OK;
    }

    size_t cbor_len = 0;
    int error = p4_ctap_get_info(response + 1, cbor_cap,
                                 &cbor_len);
    if (error != P4_CTAP_OK) {
        return error;
    }
    response[0] = P4_CTAP_STATUS_OK;
    *response_len = cbor_len + 1;
    return P4_CTAP_OK;
}
