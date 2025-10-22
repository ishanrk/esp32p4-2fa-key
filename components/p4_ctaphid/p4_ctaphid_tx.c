#include "p4_ctaphid_priv.h"

#include <string.h>


static void store_u32(uint8_t *out, uint32_t value)
{
    out[0] = (uint8_t)(value >> 24);
    out[1] = (uint8_t)(value >> 16);
    out[2] = (uint8_t)(value >> 8);
    out[3] = (uint8_t)value;
}


static int emit_initial(uint32_t cid,
                        uint8_t command,
                        const uint8_t *data,
                        size_t data_len,
                        p4_ctaphid_emit_fn emit,
                        void *emit_ctx)
{
    uint8_t report[P4_CTAPHID_REPORT_BYTES] = {0};
    store_u32(report, cid);
    report[4] = command;
    report[5] = (uint8_t)(data_len >> 8);
    report[6] = (uint8_t)data_len;

    size_t take = data_len < P4_CTAPHID_INIT_DATA_BYTES ?
                  data_len : P4_CTAPHID_INIT_DATA_BYTES;
    if (take != 0) {
        memcpy(&report[7], data, take);
    }
    return emit(emit_ctx, report);
}


int p4_ctaphid_tx_send(uint32_t cid,
                       uint8_t command,
                       const uint8_t *data,
                       size_t data_len,
                       p4_ctaphid_emit_fn emit,
                       void *emit_ctx)
{
    if (cid == 0 || (command & 0x80U) == 0 ||
        data_len > P4_CTAPHID_MAX_PAYLOAD ||
        (data == NULL && data_len != 0) || emit == NULL) {
        return P4_CTAPHID_TX_ARG;
    }

    if (emit_initial(cid, command, data, data_len, emit, emit_ctx) != 0) {
        return P4_CTAPHID_TX_SEND;
    }

    size_t offset = data_len < P4_CTAPHID_INIT_DATA_BYTES ?
                    data_len : P4_CTAPHID_INIT_DATA_BYTES;
    uint8_t sequence = 0;
    while (offset < data_len) {
        uint8_t report[P4_CTAPHID_REPORT_BYTES] = {0};
        store_u32(report, cid);
        report[4] = sequence;

        size_t take = data_len - offset;
        if (take > P4_CTAPHID_CONT_DATA_BYTES) {
            take = P4_CTAPHID_CONT_DATA_BYTES;
        }
        memcpy(&report[5], &data[offset], take);
        if (emit(emit_ctx, report) != 0) {
            return P4_CTAPHID_TX_SEND;
        }
        offset += take;
        sequence++;
    }

    return P4_CTAPHID_TX_OK;
}
