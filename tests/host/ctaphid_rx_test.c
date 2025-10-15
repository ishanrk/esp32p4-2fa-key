#include "p4_ctaphid_priv.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>


typedef struct {
    uint32_t next;
    bool fail;
} fake_random_t;

typedef struct {
    uint32_t value;
    size_t calls;
} fixed_random_t;


static void fail(const char *name, int line)
{
    fprintf(stderr, "FAIL %s line %d\n", name, line);
    exit(1);
}

#define CHECK(value) do { if (!(value)) fail(__func__, __LINE__); } while (0)


static void store_u32(uint8_t *out, uint32_t value)
{
    out[0] = (uint8_t)(value >> 24);
    out[1] = (uint8_t)(value >> 16);
    out[2] = (uint8_t)(value >> 8);
    out[3] = (uint8_t)value;
}


static uint32_t load_u32(const uint8_t *in)
{
    return ((uint32_t)in[0] << 24) |
           ((uint32_t)in[1] << 16) |
           ((uint32_t)in[2] << 8) |
           in[3];
}


static int fake_random(void *ctx, uint8_t *out, size_t len)
{
    fake_random_t *random = ctx;
    if (random->fail || len != 4) {
        return -1;
    }
    store_u32(out, random->next++);
    return 0;
}


static int fixed_random(void *ctx, uint8_t *out, size_t len)
{
    fixed_random_t *random = ctx;
    if (len != 4) {
        return -1;
    }
    random->calls++;
    store_u32(out, random->value);
    return 0;
}


static void initial(uint8_t report[64], uint32_t cid, uint8_t command,
                    uint16_t len, const uint8_t *data, size_t take)
{
    memset(report, 0, 64);
    store_u32(report, cid);
    report[4] = command;
    report[5] = (uint8_t)(len >> 8);
    report[6] = (uint8_t)len;
    if (take != 0) {
        memcpy(&report[7], data, take);
    }
}


static void continuation(uint8_t report[64], uint32_t cid, uint8_t sequence,
                         const uint8_t *data, size_t take)
{
    memset(report, 0, 64);
    store_u32(report, cid);
    report[4] = sequence;
    if (take != 0) {
        memcpy(&report[5], data, take);
    }
}


static uint32_t allocate(p4_ctaphid_core_t *core, fake_random_t *random,
                         uint8_t nonce_seed)
{
    uint8_t nonce[8];
    for (size_t i = 0; i < sizeof(nonce); i++) {
        nonce[i] = (uint8_t)(nonce_seed + i);
    }

    uint8_t report[64];
    p4_ctaphid_action_t action;
    initial(report, CTAPHID_BROADCAST_CID, CTAPHID_INIT, 8,
            nonce, sizeof(nonce));
    CHECK(p4_ctaphid_core_feed(core, report, 1, fake_random, random,
                               &action) == 0);
    CHECK(action.kind == P4_CTAPHID_ACTION_SEND);
    CHECK(action.cid == CTAPHID_BROADCAST_CID);
    CHECK(action.command == CTAPHID_INIT);
    CHECK(action.data_len == 17);
    CHECK(memcmp(action.data, nonce, 8) == 0);
    CHECK(action.data[12] == 2);
    CHECK(action.data[13] == 0);
    CHECK(action.data[14] == 1);
    CHECK(action.data[15] == 0);
    CHECK(action.data[16] == 0x0c);
    uint32_t cid = load_u32(&action.data[8]);
    CHECK(cid != 0 && cid != CTAPHID_BROADCAST_CID);
    return cid;
}


static void ping_length(p4_ctaphid_core_t *core, fake_random_t *random,
                        uint32_t cid, size_t len, uint32_t now_ms)
{
    uint8_t input[P4_CTAPHID_MAX_PAYLOAD];
    for (size_t i = 0; i < len; i++) {
        input[i] = (uint8_t)(i * 29U + len);
    }

    uint8_t report[64];
    p4_ctaphid_action_t action;
    size_t first = len < 57 ? len : 57;
    initial(report, cid, CTAPHID_PING, (uint16_t)len, input, first);
    p4_ctaphid_core_feed(core, report, now_ms, fake_random, random, &action);

    size_t offset = first;
    uint8_t sequence = 0;
    while (offset < len) {
        size_t take = len - offset;
        if (take > 59) {
            take = 59;
        }
        continuation(report, cid, sequence, &input[offset], take);
        p4_ctaphid_core_feed(core, report, now_ms + 1 + sequence,
                             fake_random, random, &action);
        offset += take;
        sequence++;
    }

    CHECK(action.kind == P4_CTAPHID_ACTION_SEND);
    CHECK(action.command == CTAPHID_PING && action.data_len == len);
    CHECK(memcmp(action.data, input, len) == 0);
    CHECK(action.generation != 0);
    p4_ctaphid_core_finish_response(core, cid, action.generation);
    CHECK(core->phase == P4_CTAPHID_PHASE_IDLE);
}


static void test_init_and_resync(void)
{
    p4_ctaphid_core_t core;
    fake_random_t random = {.next = 0};
    p4_ctaphid_core_init(&core);

    uint32_t cid = allocate(&core, &random, 0x20);
    CHECK(cid == 1);

    uint8_t data[58];
    memset(data, 0xa5, sizeof(data));
    uint8_t report[64];
    p4_ctaphid_action_t action;
    initial(report, cid, CTAPHID_PING, sizeof(data), data, 57);
    p4_ctaphid_core_feed(&core, report, 10, fake_random, &random, &action);
    CHECK(action.kind == P4_CTAPHID_ACTION_NONE);
    CHECK(core.phase == P4_CTAPHID_PHASE_RX);

    uint8_t nonce[8] = {9, 8, 7, 6, 5, 4, 3, 2};
    initial(report, cid, CTAPHID_INIT, 8, nonce, 8);
    p4_ctaphid_core_feed(&core, report, 11, fake_random, &random, &action);
    CHECK(action.kind == P4_CTAPHID_ACTION_SEND);
    CHECK(action.cid == cid && action.command == CTAPHID_INIT);
    CHECK(load_u32(&action.data[8]) == cid);
    CHECK(core.phase == P4_CTAPHID_PHASE_IDLE);
}


static void test_fragment_and_padding(void)
{
    p4_ctaphid_core_t core;
    fake_random_t random = {.next = 0x10203040};
    p4_ctaphid_core_init(&core);
    uint32_t cid = allocate(&core, &random, 1);

    uint8_t data[58];
    for (size_t i = 0; i < sizeof(data); i++) {
        data[i] = (uint8_t)i;
    }
    uint8_t report[64];
    p4_ctaphid_action_t action;
    initial(report, cid, CTAPHID_PING, sizeof(data), data, 57);
    p4_ctaphid_core_feed(&core, report, 10, fake_random, &random, &action);
    CHECK(action.kind == P4_CTAPHID_ACTION_NONE);

    uint8_t tail[59];
    memset(tail, 0xcc, sizeof(tail));
    tail[0] = data[57];
    continuation(report, cid, 0, tail, sizeof(tail));
    p4_ctaphid_core_feed(&core, report, 11, fake_random, &random, &action);
    CHECK(action.kind == P4_CTAPHID_ACTION_SEND);
    CHECK(action.command == CTAPHID_PING && action.data_len == sizeof(data));
    CHECK(memcmp(action.data, data, sizeof(data)) == 0);
    p4_ctaphid_core_finish_response(&core, cid, action.generation);
    CHECK(core.phase == P4_CTAPHID_PHASE_IDLE);
}


static void test_ping_boundary_lengths(void)
{
    static const size_t lengths[] = {0, 1, 57, 58, 116, 117, 2048};
    p4_ctaphid_core_t core;
    fake_random_t random = {.next = 0x11223344};
    p4_ctaphid_core_init(&core);
    uint32_t cid = allocate(&core, &random, 0x30);

    for (size_t i = 0; i < sizeof(lengths) / sizeof(lengths[0]); i++) {
        ping_length(&core, &random, cid, lengths[i],
                    (uint32_t)(1000 + i * 100));
    }
}


static void test_zero_and_maximum_messages(void)
{
    p4_ctaphid_core_t core;
    fake_random_t random = {.next = 0x20304050};
    p4_ctaphid_core_init(&core);
    uint32_t cid = allocate(&core, &random, 7);
    uint8_t report[64];
    p4_ctaphid_action_t action;

    initial(report, cid, CTAPHID_PING, 0, NULL, 0);
    p4_ctaphid_core_feed(&core, report, 1, fake_random, &random, &action);
    CHECK(action.kind == P4_CTAPHID_ACTION_SEND);
    CHECK(action.data_len == 0);
    p4_ctaphid_core_finish_response(&core, cid, action.generation);

    initial(report, cid, CTAPHID_CBOR, 0, NULL, 0);
    p4_ctaphid_core_feed(&core, report, 2, fake_random, &random, &action);
    CHECK(action.kind == P4_CTAPHID_ACTION_SEND);
    CHECK(action.data[0] == CTAPHID_ERR_INVALID_LEN);

    uint8_t input[P4_CTAPHID_MAX_PAYLOAD];
    for (size_t i = 0; i < sizeof(input); i++) {
        input[i] = (uint8_t)(i * 17U + 3U);
    }
    initial(report, cid, CTAPHID_CBOR, sizeof(input), input, 57);
    p4_ctaphid_core_feed(&core, report, 10, fake_random, &random, &action);
    CHECK(action.kind == P4_CTAPHID_ACTION_NONE);

    size_t offset = 57;
    uint8_t sequence = 0;
    while (offset < sizeof(input)) {
        size_t take = sizeof(input) - offset;
        if (take > 59) {
            take = 59;
        }
        continuation(report, cid, sequence, &input[offset], take);
        p4_ctaphid_core_feed(&core, report, 11 + sequence,
                             fake_random, &random, &action);
        offset += take;
        sequence++;
    }
    CHECK(action.kind == P4_CTAPHID_ACTION_MESSAGE);
    CHECK(action.data_len == sizeof(input));

    uint8_t output[P4_CTAPHID_MAX_PAYLOAD];
    uint32_t out_cid = 0;
    uint8_t out_command = 0;
    size_t out_len = 0;
    uint32_t generation = 0;
    CHECK(p4_ctaphid_core_take_message(&core, &out_cid, &out_command,
                                       output, sizeof(output), &out_len,
                                       &generation) == 0);
    CHECK(out_cid == cid && out_command == CTAPHID_CBOR);
    CHECK(out_len == sizeof(input));
    CHECK(memcmp(input, output, sizeof(input)) == 0);
    p4_ctaphid_core_finish_response(&core, cid, generation);
}


static void test_spurious_wrong_sequence_and_second_initial(void)
{
    p4_ctaphid_core_t core;
    fake_random_t random = {.next = 4};
    p4_ctaphid_core_init(&core);
    uint32_t cid = allocate(&core, &random, 2);
    uint32_t other = allocate(&core, &random, 3);
    uint8_t report[64];
    p4_ctaphid_action_t action;
    uint8_t data[58] = {0};

    continuation(report, 0x44556677, 0, data, 1);
    p4_ctaphid_core_feed(&core, report, 10, fake_random, &random, &action);
    CHECK(action.kind == P4_CTAPHID_ACTION_NONE);

    initial(report, cid, CTAPHID_PING, 58, data, 57);
    p4_ctaphid_core_feed(&core, report, 20, fake_random, &random, &action);
    initial(report, other, CTAPHID_PING, 0, NULL, 0);
    p4_ctaphid_core_feed(&core, report, 20, fake_random, &random, &action);
    CHECK(action.kind == P4_CTAPHID_ACTION_SEND);
    CHECK(action.data[0] == CTAPHID_ERR_CHANNEL_BUSY);
    CHECK(core.phase == P4_CTAPHID_PHASE_RX && core.active_cid == cid);
    continuation(report, cid, 1, data, 1);
    p4_ctaphid_core_feed(&core, report, 21, fake_random, &random, &action);
    CHECK(action.kind == P4_CTAPHID_ACTION_SEND);
    CHECK(action.command == CTAPHID_ERROR);
    CHECK(action.data[0] == CTAPHID_ERR_INVALID_SEQ);
    CHECK(core.phase == P4_CTAPHID_PHASE_IDLE);

    continuation(report, cid, 0, data, 1);
    p4_ctaphid_core_feed(&core, report, 22, fake_random, &random, &action);
    CHECK(action.kind == P4_CTAPHID_ACTION_NONE);

    initial(report, cid, CTAPHID_PING, 58, data, 57);
    p4_ctaphid_core_feed(&core, report, 30, fake_random, &random, &action);
    initial(report, cid, CTAPHID_PING, 0, NULL, 0);
    p4_ctaphid_core_feed(&core, report, 31, fake_random, &random, &action);
    CHECK(action.kind == P4_CTAPHID_ACTION_SEND);
    CHECK(action.data[0] == CTAPHID_ERR_INVALID_SEQ);
    CHECK(core.phase == P4_CTAPHID_PHASE_IDLE);
}


static void test_errors_and_timeout(void)
{
    p4_ctaphid_core_t core;
    fake_random_t random = {.next = 8};
    p4_ctaphid_core_init(&core);
    uint32_t cid = allocate(&core, &random, 3);
    uint8_t report[64];
    p4_ctaphid_action_t action;
    uint8_t data[57] = {0};

    initial(report, 0xabcdef01, CTAPHID_PING, 0, NULL, 0);
    p4_ctaphid_core_feed(&core, report, 1, fake_random, &random, &action);
    CHECK(action.data[0] == CTAPHID_ERR_INVALID_CHANNEL);

    initial(report, CTAPHID_BROADCAST_CID, CTAPHID_PING, 0, NULL, 0);
    p4_ctaphid_core_feed(&core, report, 2, fake_random, &random, &action);
    CHECK(action.data[0] == CTAPHID_ERR_INVALID_CHANNEL);

    initial(report, cid, 0x82, 0, NULL, 0);
    p4_ctaphid_core_feed(&core, report, 3, fake_random, &random, &action);
    CHECK(action.data[0] == CTAPHID_ERR_INVALID_CMD);

    initial(report, cid, CTAPHID_PING, 2049, data, 57);
    p4_ctaphid_core_feed(&core, report, 4, fake_random, &random, &action);
    CHECK(action.data[0] == CTAPHID_ERR_INVALID_LEN);

    initial(report, CTAPHID_BROADCAST_CID, CTAPHID_INIT, 7, data, 7);
    p4_ctaphid_core_feed(&core, report, 5, fake_random, &random, &action);
    CHECK(action.data[0] == CTAPHID_ERR_INVALID_LEN);

    initial(report, cid, CTAPHID_PING, 58, data, 57);
    p4_ctaphid_core_feed(&core, report, 10, fake_random, &random, &action);
    p4_ctaphid_core_cleanup(&core, 509);
    CHECK(core.phase == P4_CTAPHID_PHASE_RX);
    p4_ctaphid_core_cleanup(&core, 510);
    CHECK(core.phase == P4_CTAPHID_PHASE_IDLE);
    continuation(report, cid, 0, data, 1);
    p4_ctaphid_core_feed(&core, report, 511, fake_random, &random, &action);
    CHECK(action.data[0] == CTAPHID_ERR_MSG_TIMEOUT);
    continuation(report, cid, 0, data, 1);
    p4_ctaphid_core_feed(&core, report, 512, fake_random, &random, &action);
    CHECK(action.kind == P4_CTAPHID_ACTION_NONE);

    initial(report, cid, CTAPHID_PING, 58, data, 57);
    p4_ctaphid_core_feed(&core, report, 1000, fake_random, &random, &action);
    continuation(report, cid, 0, data, 1);
    p4_ctaphid_core_feed(&core, report, 1500, fake_random, &random, &action);
    CHECK(action.data[0] == CTAPHID_ERR_MSG_TIMEOUT);

    initial(report, cid, CTAPHID_PING, 58, data, 57);
    p4_ctaphid_core_feed(&core, report, 2000, fake_random, &random, &action);
    initial(report, cid, CTAPHID_PING, 0, NULL, 0);
    p4_ctaphid_core_feed(&core, report, 2500, fake_random, &random, &action);
    CHECK(action.kind == P4_CTAPHID_ACTION_SEND);
    CHECK(action.command == CTAPHID_PING && action.data_len == 0);
    p4_ctaphid_core_finish_response(&core, cid, action.generation);

    initial(report, cid, CTAPHID_PING, 58, data, 57);
    p4_ctaphid_core_feed(&core, report, UINT32_MAX - 250U,
                         fake_random, &random, &action);
    p4_ctaphid_core_cleanup(&core, 248);
    CHECK(core.phase == P4_CTAPHID_PHASE_RX);
    p4_ctaphid_core_cleanup(&core, 249);
    CHECK(core.phase == P4_CTAPHID_PHASE_IDLE);
}


static void test_message_busy_cancel_and_handoff(void)
{
    p4_ctaphid_core_t core;
    fake_random_t random = {.next = 20};
    p4_ctaphid_core_init(&core);
    uint32_t first = allocate(&core, &random, 4);
    uint32_t second = allocate(&core, &random, 5);
    uint8_t report[64];
    p4_ctaphid_action_t action;
    uint8_t request = 0x04;

    initial(report, first, CTAPHID_CBOR, 1, &request, 1);
    p4_ctaphid_core_feed(&core, report, 10, fake_random, &random, &action);
    CHECK(action.kind == P4_CTAPHID_ACTION_MESSAGE);
    CHECK(core.message_ready);

    uint32_t third = allocate(&core, &random, 9);
    CHECK(third != first && third != second);
    CHECK(core.active_cid == first && core.message_ready);

    uint8_t nonce[8] = {1, 3, 5, 7, 9, 11, 13, 15};
    initial(report, second, CTAPHID_INIT, 8, nonce, 8);
    p4_ctaphid_core_feed(&core, report, 10, fake_random, &random, &action);
    CHECK(action.kind == P4_CTAPHID_ACTION_SEND);
    CHECK(action.data[0] == CTAPHID_ERR_CHANNEL_BUSY);
    CHECK(core.active_cid == first && core.message_ready);

    initial(report, second, CTAPHID_PING, 0, NULL, 0);
    p4_ctaphid_core_feed(&core, report, 11, fake_random, &random, &action);
    CHECK(action.kind == P4_CTAPHID_ACTION_SEND);
    CHECK(action.data[0] == CTAPHID_ERR_CHANNEL_BUSY);
    CHECK(core.queue_full_count == 2);

    initial(report, second, CTAPHID_CANCEL, 0, NULL, 0);
    p4_ctaphid_core_feed(&core, report, 12, fake_random, &random, &action);
    CHECK(action.kind == P4_CTAPHID_ACTION_NONE);

    initial(report, first, CTAPHID_CANCEL, 0, NULL, 0);
    p4_ctaphid_core_feed(&core, report, 13, fake_random, &random, &action);
    CHECK(action.kind == P4_CTAPHID_ACTION_CANCEL);
    uint32_t generation = action.generation;
    CHECK(p4_ctaphid_core_cancelled(&core, first, generation));

    initial(report, first, CTAPHID_CANCEL, 1, &request, 1);
    p4_ctaphid_core_feed(&core, report, 14, fake_random, &random, &action);
    CHECK(action.kind == P4_CTAPHID_ACTION_NONE);
    CHECK(p4_ctaphid_core_cancelled(&core, first, generation));
    p4_ctaphid_core_clear_cancel(&core, first, generation);
    CHECK(!p4_ctaphid_core_cancelled(&core, first, generation));

    initial(report, CTAPHID_BROADCAST_CID, CTAPHID_CANCEL, 1,
            &request, 1);
    p4_ctaphid_core_feed(&core, report, 15, fake_random, &random, &action);
    CHECK(action.kind == P4_CTAPHID_ACTION_NONE);
    initial(report, 0xabcdef01, CTAPHID_CANCEL, 0, NULL, 0);
    p4_ctaphid_core_feed(&core, report, 16, fake_random, &random, &action);
    CHECK(action.kind == P4_CTAPHID_ACTION_NONE);

    uint32_t cid = 0;
    uint8_t command = 0;
    uint8_t out[1] = {0};
    size_t out_len = 0;
    uint32_t taken_generation = 0;
    CHECK(p4_ctaphid_core_take_message(&core, &cid, &command,
                                       NULL, 0, &out_len,
                                       &taken_generation) ==
          P4_CTAPHID_CORE_SMALL);
    CHECK(core.message_ready);
    CHECK(p4_ctaphid_core_take_message(&core, &cid, &command,
                                       out, sizeof(out), &out_len,
                                       &taken_generation) == 0);
    CHECK(cid == first && command == CTAPHID_CBOR);
    CHECK(out_len == 1 && out[0] == request);
    CHECK(!core.message_ready);
    p4_ctaphid_core_finish_response(&core, first, taken_generation);
    CHECK(p4_ctaphid_core_cancelled(&core, first, taken_generation));
}


static void test_queue_full_preserves_complete_buffer(void)
{
    p4_ctaphid_core_t core;
    fake_random_t random = {.next = 30};
    p4_ctaphid_core_init(&core);
    uint32_t cid = allocate(&core, &random, 6);

    core.message_ready = true;
    core.complete_buffer = 1;
    core.complete_cid = cid;
    core.complete_command = CTAPHID_CBOR;
    core.complete_len = 1;
    core.complete_generation = 99;
    core.buffers[1][0] = 0x5a;
    core.rx_buffer = 0;

    uint8_t report[64];
    p4_ctaphid_action_t action;
    uint8_t request = 0x04;
    initial(report, cid, CTAPHID_CBOR, 1, &request, 1);
    p4_ctaphid_core_feed(&core, report, 1, fake_random, &random, &action);
    CHECK(action.kind == P4_CTAPHID_ACTION_SEND);
    CHECK(action.data[0] == CTAPHID_ERR_CHANNEL_BUSY);
    CHECK(core.queue_full_count == 1);
    CHECK(core.message_ready && core.complete_buffer == 1);
    CHECK(core.buffers[1][0] == 0x5a);

    uint8_t output = 0;
    uint32_t out_cid = 0;
    uint32_t out_generation = 0;
    uint8_t out_command = 0;
    size_t out_len = 0;
    CHECK(p4_ctaphid_core_take_message(&core, &out_cid, &out_command,
                                       &output, 1, &out_len,
                                       &out_generation) == 0);
    CHECK(out_cid == cid && out_command == CTAPHID_CBOR);
    CHECK(out_len == 1 && output == 0x5a && out_generation == 99);
}


static void test_resync_generation_blocks_stale_finish(void)
{
    p4_ctaphid_core_t core;
    fake_random_t random = {.next = 40};
    p4_ctaphid_core_init(&core);
    uint32_t cid = allocate(&core, &random, 8);
    uint8_t report[64];
    p4_ctaphid_action_t action;
    uint8_t request = 0x04;

    initial(report, cid, CTAPHID_CBOR, 1, &request, 1);
    p4_ctaphid_core_feed(&core, report, 1, fake_random, &random, &action);
    CHECK(core.message_ready);

    uint8_t nonce[8] = {0};
    initial(report, cid, CTAPHID_INIT, 8, nonce, 8);
    p4_ctaphid_core_feed(&core, report, 2, fake_random, &random, &action);
    CHECK(action.kind == P4_CTAPHID_ACTION_SEND);
    CHECK(!core.message_ready && core.phase == P4_CTAPHID_PHASE_IDLE);

    uint32_t out_cid = 0;
    uint32_t old_generation = 0;
    uint8_t out_command = 0;
    uint8_t output = 0;
    size_t out_len = 0;
    CHECK(p4_ctaphid_core_take_message(&core, &out_cid, &out_command,
                                       &output, 1, &out_len,
                                       &old_generation) ==
          P4_CTAPHID_CORE_EMPTY);

    initial(report, cid, CTAPHID_CBOR, 1, &request, 1);
    p4_ctaphid_core_feed(&core, report, 3, fake_random, &random, &action);
    CHECK(p4_ctaphid_core_take_message(&core, &out_cid, &out_command,
                                       &output, 1, &out_len,
                                       &old_generation) == 0);

    initial(report, cid, CTAPHID_INIT, 8, nonce, 8);
    p4_ctaphid_core_feed(&core, report, 4, fake_random, &random, &action);
    initial(report, cid, CTAPHID_CBOR, 1, &request, 1);
    p4_ctaphid_core_feed(&core, report, 5, fake_random, &random, &action);
    uint32_t new_generation = 0;
    CHECK(p4_ctaphid_core_take_message(&core, &out_cid, &out_command,
                                       &output, 1, &out_len,
                                       &new_generation) == 0);
    CHECK(old_generation != new_generation);

    p4_ctaphid_core_finish_response(&core, cid, old_generation);
    CHECK(core.phase == P4_CTAPHID_PHASE_PROCESSING);
    CHECK(p4_ctaphid_core_cancelled(&core, cid, old_generation));
    CHECK(!p4_ctaphid_core_cancelled(&core, cid, new_generation));
    p4_ctaphid_core_finish_response(&core, cid, new_generation);
    CHECK(core.phase == P4_CTAPHID_PHASE_IDLE);
}


static void test_reset_and_allocator_failures(void)
{
    p4_ctaphid_core_t core;
    fake_random_t random = {.next = 1};
    p4_ctaphid_core_init(&core);
    for (size_t i = 0; i < P4_CTAPHID_CHANNEL_COUNT; i++) {
        (void)allocate(&core, &random, (uint8_t)i);
    }

    uint8_t nonce[8] = {0};
    uint8_t report[64];
    p4_ctaphid_action_t action;
    initial(report, CTAPHID_BROADCAST_CID, CTAPHID_INIT, 8, nonce, 8);
    p4_ctaphid_core_feed(&core, report, 1, fake_random, &random, &action);
    CHECK(action.data[0] == CTAPHID_ERR_CHANNEL_BUSY);

    p4_ctaphid_core_reset(&core);
    CHECK(core.phase == P4_CTAPHID_PHASE_IDLE);
    CHECK(!core.message_ready);
    for (size_t i = 0; i < P4_CTAPHID_CHANNEL_COUNT; i++) {
        CHECK(!core.channels[i].allocated);
    }

    random.fail = true;
    p4_ctaphid_core_feed(&core, report, 2, fake_random, &random, &action);
    CHECK(action.data[0] == CTAPHID_ERR_OTHER);

    p4_ctaphid_core_reset(&core);
    random.fail = false;
    random.next = 50;
    uint32_t cid = allocate(&core, &random, 9);
    uint8_t request = 0x04;
    initial(report, cid, CTAPHID_CBOR, 1, &request, 1);
    p4_ctaphid_core_feed(&core, report, 3, fake_random, &random, &action);
    CHECK(core.message_ready);
    p4_ctaphid_core_reset(&core);
    uint32_t out_cid = 0;
    uint32_t generation = 0;
    uint8_t out_command = 0;
    uint8_t output = 0;
    size_t out_len = 0;
    CHECK(p4_ctaphid_core_take_message(&core, &out_cid, &out_command,
                                       &output, 1, &out_len,
                                       &generation) ==
          P4_CTAPHID_CORE_EMPTY);
    for (size_t i = 0; i < sizeof(core.buffers); i++) {
        CHECK(((const uint8_t *)core.buffers)[i] == 0);
    }
}


static void test_allocator_retries_are_bounded(void)
{
    p4_ctaphid_core_t core;
    p4_ctaphid_core_init(&core);
    fixed_random_t fixed = {.value = 42};
    uint32_t cid = 0;
    CHECK(p4_ctaphid_chan_allocate(&core, fixed_random, &fixed, &cid) == 0);
    CHECK(cid == 42 && fixed.calls == 1);
    CHECK(p4_ctaphid_chan_allocate(&core, fixed_random, &fixed, &cid) ==
          P4_CTAPHID_CORE_CID);
    CHECK(fixed.calls == 1 + P4_CTAPHID_CID_RETRIES);

    p4_ctaphid_core_reset(&core);
    fixed.value = CTAPHID_BROADCAST_CID;
    fixed.calls = 0;
    CHECK(p4_ctaphid_chan_allocate(&core, fixed_random, &fixed, &cid) ==
          P4_CTAPHID_CORE_CID);
    CHECK(fixed.calls == P4_CTAPHID_CID_RETRIES);

    fake_random_t retry = {.next = 0};
    CHECK(p4_ctaphid_chan_allocate(&core, fake_random, &retry, &cid) == 0);
    CHECK(cid == 1 && retry.next == 2);
    retry.next = 1;
    CHECK(p4_ctaphid_chan_allocate(&core, fake_random, &retry, &cid) == 0);
    CHECK(cid == 2 && retry.next == 3);
}


int main(void)
{
    test_init_and_resync();
    test_fragment_and_padding();
    test_ping_boundary_lengths();
    test_zero_and_maximum_messages();
    test_spurious_wrong_sequence_and_second_initial();
    test_errors_and_timeout();
    test_message_busy_cancel_and_handoff();
    test_queue_full_preserves_complete_buffer();
    test_resync_generation_blocks_stale_finish();
    test_reset_and_allocator_failures();
    test_allocator_retries_are_bounded();
    puts("PASS ctaphid receive paths");
    return 0;
}
