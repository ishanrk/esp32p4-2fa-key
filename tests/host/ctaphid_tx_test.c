#include "p4_ctaphid_priv.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum {
    MAX_FRAMES = 35,
};

typedef struct {
    uint8_t frames[MAX_FRAMES][P4_CTAPHID_REPORT_BYTES];
    size_t count;
    size_t fail_at;
} capture_t;


static void fail(const char *name, int line)
{
    fprintf(stderr, "FAIL %s line %d\n", name, line);
    exit(1);
}

#define CHECK(value) do { if (!(value)) fail(__func__, __LINE__); } while (0)


static uint32_t load_u32(const uint8_t *in)
{
    return ((uint32_t)in[0] << 24) |
           ((uint32_t)in[1] << 16) |
           ((uint32_t)in[2] << 8) |
           in[3];
}


static int capture(void *ctx, const uint8_t report[64])
{
    capture_t *out = ctx;
    if (out->count == out->fail_at) {
        return -1;
    }
    CHECK(out->count < MAX_FRAMES);
    memcpy(out->frames[out->count], report, 64);
    out->count++;
    return 0;
}


static void boundary(size_t len)
{
    uint8_t input[P4_CTAPHID_MAX_PAYLOAD];
    uint8_t output[P4_CTAPHID_MAX_PAYLOAD];
    for (size_t i = 0; i < len; i++) {
        input[i] = (uint8_t)(i * 31U + len);
    }
    memset(output, 0, sizeof(output));

    capture_t out = {.fail_at = SIZE_MAX};
    uint32_t cid = 0x10203040;
    CHECK(p4_ctaphid_tx_send(cid, CTAPHID_PING, input, len,
                             capture, &out) == 0);

    size_t expected = 1;
    if (len > 57) {
        expected += (len - 57 + 58) / 59;
    }
    CHECK(out.count == expected);
    CHECK(load_u32(out.frames[0]) == cid);
    CHECK(out.frames[0][4] == CTAPHID_PING);
    CHECK(out.frames[0][5] == (uint8_t)(len >> 8));
    CHECK(out.frames[0][6] == (uint8_t)len);

    size_t offset = 0;
    size_t take = len < 57 ? len : 57;
    memcpy(output, &out.frames[0][7], take);
    offset += take;
    for (size_t frame = 1; frame < out.count; frame++) {
        CHECK(load_u32(out.frames[frame]) == cid);
        CHECK(out.frames[frame][4] == frame - 1);
        take = len - offset;
        if (take > 59) {
            take = 59;
        }
        memcpy(&output[offset], &out.frames[frame][5], take);
        offset += take;
        for (size_t i = 5 + take; i < 64; i++) {
            CHECK(out.frames[frame][i] == 0);
        }
    }

    size_t initial_used = 7 + (len < 57 ? len : 57);
    for (size_t i = initial_used; i < 64; i++) {
        CHECK(out.frames[0][i] == 0);
    }
    CHECK(offset == len);
    CHECK(memcmp(input, output, len) == 0);
}


static void test_boundaries(void)
{
    static const size_t lengths[] = {0, 1, 57, 58, 116, 117, 2048};
    for (size_t i = 0; i < sizeof(lengths) / sizeof(lengths[0]); i++) {
        boundary(lengths[i]);
    }
}


static void test_validation_and_emit_failure(void)
{
    uint8_t data[P4_CTAPHID_MAX_PAYLOAD + 1] = {0};
    capture_t out = {.fail_at = SIZE_MAX};
    CHECK(p4_ctaphid_tx_send(0, CTAPHID_PING, data, 1,
                             capture, &out) == P4_CTAPHID_TX_ARG);
    CHECK(p4_ctaphid_tx_send(1, 0x01, data, 1,
                             capture, &out) == P4_CTAPHID_TX_ARG);
    CHECK(p4_ctaphid_tx_send(1, CTAPHID_PING, NULL, 1,
                             capture, &out) == P4_CTAPHID_TX_ARG);
    CHECK(p4_ctaphid_tx_send(1, CTAPHID_PING, data, sizeof(data),
                             capture, &out) == P4_CTAPHID_TX_ARG);
    CHECK(p4_ctaphid_tx_send(1, CTAPHID_PING, data, 1,
                             NULL, &out) == P4_CTAPHID_TX_ARG);

    out.fail_at = 0;
    CHECK(p4_ctaphid_tx_send(1, CTAPHID_PING, data, 1,
                             capture, &out) == P4_CTAPHID_TX_SEND);
    CHECK(out.count == 0);

    memset(&out, 0, sizeof(out));
    out.fail_at = 2;
    CHECK(p4_ctaphid_tx_send(1, CTAPHID_PING, data, 117,
                             capture, &out) == P4_CTAPHID_TX_SEND);
    CHECK(out.count == 2);

    memset(&out, 0, sizeof(out));
    out.fail_at = SIZE_MAX;
    CHECK(p4_ctaphid_tx_send(CTAPHID_BROADCAST_CID, CTAPHID_INIT,
                             data, 8, capture, &out) == 0);
    CHECK(out.count == 1);
}


static void test_keepalive_statuses(void)
{
    static const uint8_t statuses[] = {
        CTAPHID_KEEPALIVE_PROCESSING,
        CTAPHID_KEEPALIVE_UP_NEEDED,
    };
    for (size_t i = 0; i < sizeof(statuses); i++) {
        capture_t out = {.fail_at = SIZE_MAX};
        CHECK(p4_ctaphid_tx_send(1, CTAPHID_KEEPALIVE,
                                 &statuses[i], 1, capture, &out) == 0);
        CHECK(out.count == 1);
        CHECK(out.frames[0][4] == CTAPHID_KEEPALIVE);
        CHECK(out.frames[0][5] == 0 && out.frames[0][6] == 1);
        CHECK(out.frames[0][7] == statuses[i]);
        for (size_t byte = 8; byte < P4_CTAPHID_REPORT_BYTES; byte++) {
            CHECK(out.frames[0][byte] == 0);
        }
    }
}


int main(void)
{
    test_boundaries();
    test_validation_and_emit_failure();
    test_keepalive_statuses();
    puts("PASS ctaphid send frames");
    return 0;
}
