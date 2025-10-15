#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "p4_ctaphid_wire.h"

enum {
    P4_CTAPHID_BUFFER_COUNT = 2,
    P4_CTAPHID_INIT_REPLY_BYTES = 17,
    P4_CTAPHID_CID_RETRIES = 16,
};

typedef int (*p4_ctaphid_rand_fn)(void *ctx, uint8_t *out, size_t len);

typedef enum {
    P4_CTAPHID_PHASE_IDLE = 0,
    P4_CTAPHID_PHASE_RX,
    P4_CTAPHID_PHASE_PROCESSING,
} p4_ctaphid_phase_t;

typedef struct {
    uint32_t cid;
    uint32_t last_packet_ms;
    uint32_t last_keepalive_ms;
    uint32_t generation;
    uint16_t declared_len;
    uint16_t received;
    uint8_t command;
    uint8_t next_sequence;
    uint8_t last_keepalive_status;
    bool allocated;
    bool partial_active;
    bool cancel;
    bool timeout_pending;
    bool keepalive_sent;
} p4_ctaphid_channel_t;

typedef struct {
    p4_ctaphid_channel_t channels[P4_CTAPHID_CHANNEL_COUNT];
    uint8_t buffers[P4_CTAPHID_BUFFER_COUNT][P4_CTAPHID_MAX_PAYLOAD];
    uint8_t control[P4_CTAPHID_INIT_REPLY_BYTES];
    uint8_t rx_buffer;
    uint8_t complete_buffer;
    uint16_t complete_len;
    uint32_t complete_cid;
    uint32_t complete_generation;
    uint8_t complete_command;
    p4_ctaphid_phase_t phase;
    uint32_t active_cid;
    uint8_t active_command;
    bool message_ready;
    uint32_t queue_full_count;
} p4_ctaphid_core_t;

typedef enum {
    P4_CTAPHID_ACTION_NONE = 0,
    P4_CTAPHID_ACTION_SEND,
    P4_CTAPHID_ACTION_MESSAGE,
    P4_CTAPHID_ACTION_CANCEL,
} p4_ctaphid_action_kind_t;

typedef struct {
    p4_ctaphid_action_kind_t kind;
    uint32_t cid;
    uint8_t command;
    uint32_t generation;
    const uint8_t *data;
    size_t data_len;
} p4_ctaphid_action_t;

enum {
    P4_CTAPHID_CORE_OK = 0,
    P4_CTAPHID_CORE_ARG = -1,
    P4_CTAPHID_CORE_EMPTY = -2,
    P4_CTAPHID_CORE_SMALL = -3,
    P4_CTAPHID_CORE_RANDOM = -4,
    P4_CTAPHID_CORE_FULL = -5,
    P4_CTAPHID_CORE_CID = -6,
};

void p4_ctaphid_core_init(p4_ctaphid_core_t *core);
void p4_ctaphid_core_reset(p4_ctaphid_core_t *core);

int p4_ctaphid_core_feed(
    p4_ctaphid_core_t *core,
    const uint8_t report[P4_CTAPHID_REPORT_BYTES],
    uint32_t now_ms,
    p4_ctaphid_rand_fn rand_fn,
    void *rand_ctx,
    p4_ctaphid_action_t *action);

void p4_ctaphid_core_cleanup(p4_ctaphid_core_t *core, uint32_t now_ms);
void p4_ctaphid_core_finish_response(p4_ctaphid_core_t *core,
                                     uint32_t cid,
                                     uint32_t generation);

int p4_ctaphid_core_take_message(
    p4_ctaphid_core_t *core,
    uint32_t *cid,
    uint8_t *command,
    uint8_t *data,
    size_t cap,
    size_t *data_len,
    uint32_t *generation);

bool p4_ctaphid_core_cancelled(const p4_ctaphid_core_t *core,
                               uint32_t cid,
                               uint32_t generation);
void p4_ctaphid_core_clear_cancel(p4_ctaphid_core_t *core,
                                  uint32_t cid,
                                  uint32_t generation);

p4_ctaphid_channel_t *p4_ctaphid_chan_find(p4_ctaphid_core_t *core,
                                            uint32_t cid);
const p4_ctaphid_channel_t *p4_ctaphid_chan_find_const(
    const p4_ctaphid_core_t *core,
    uint32_t cid);
int p4_ctaphid_chan_allocate(p4_ctaphid_core_t *core,
                             p4_ctaphid_rand_fn rand_fn,
                             void *rand_ctx,
                             uint32_t *cid);
void p4_ctaphid_wipe(void *data, size_t len);
bool p4_ctaphid_time_expired(uint32_t now_ms, uint32_t then_ms,
                             uint32_t timeout_ms);

_Static_assert(P4_CTAPHID_BUFFER_COUNT == 2,
               "one assembly buffer and one complete handoff buffer");
