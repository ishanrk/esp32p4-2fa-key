#include "p4_ctaphid_priv.h"

#include <limits.h>
#include <string.h>

#include "p4key_version.h"


static uint32_t load_u32(const uint8_t *in)
{
    return ((uint32_t)in[0] << 24) |
           ((uint32_t)in[1] << 16) |
           ((uint32_t)in[2] << 8) |
           in[3];
}


static uint16_t load_u16(const uint8_t *in)
{
    return ((uint16_t)in[0] << 8) | in[1];
}


static void store_u32(uint8_t *out, uint32_t value)
{
    out[0] = (uint8_t)(value >> 24);
    out[1] = (uint8_t)(value >> 16);
    out[2] = (uint8_t)(value >> 8);
    out[3] = (uint8_t)value;
}


static void no_action(p4_ctaphid_action_t *action)
{
    memset(action, 0, sizeof(*action));
}


static void send_action(p4_ctaphid_core_t *core,
                        p4_ctaphid_action_t *action,
                        uint32_t cid,
                        uint8_t command,
                        const uint8_t *data,
                        size_t data_len)
{
    (void)core;
    action->kind = P4_CTAPHID_ACTION_SEND;
    action->cid = cid;
    action->command = command;
    action->generation = 0;
    action->data = data;
    action->data_len = data_len;
}


static void error_action(p4_ctaphid_core_t *core,
                         p4_ctaphid_action_t *action,
                         uint32_t cid,
                         uint8_t error)
{
    // transport errors always have one response byte
    core->control[0] = error;
    send_action(core, action, cid, CTAPHID_ERROR, core->control, 1);
}


static void count_queue_full(p4_ctaphid_core_t *core)
{
    if (core->queue_full_count != UINT32_MAX) {
        core->queue_full_count++;
    }
}


static void clear_channel_rx(p4_ctaphid_channel_t *channel)
{
    channel->partial_active = false;
    channel->command = 0;
    channel->declared_len = 0;
    channel->received = 0;
    channel->next_sequence = 0;
    channel->last_packet_ms = 0;
}


static void clear_active(p4_ctaphid_core_t *core, bool drop_complete)
{
    // an aborted transaction never leaves request bytes for later reuse
    p4_ctaphid_channel_t *channel =
        p4_ctaphid_chan_find(core, core->active_cid);
    if (channel != NULL) {
        clear_channel_rx(channel);
        channel->cancel = false;
        channel->keepalive_sent = false;
        channel->last_keepalive_ms = 0;
        channel->last_keepalive_status = 0;
    }

    p4_ctaphid_wipe(core->buffers[core->rx_buffer],
                    P4_CTAPHID_MAX_PAYLOAD);
    if (drop_complete && core->message_ready &&
        core->complete_buffer < P4_CTAPHID_BUFFER_COUNT) {
        p4_ctaphid_wipe(core->buffers[core->complete_buffer],
                        P4_CTAPHID_MAX_PAYLOAD);
        core->message_ready = false;
        core->complete_buffer = UINT8_MAX;
        core->complete_cid = 0;
        core->complete_command = 0;
        core->complete_len = 0;
        core->complete_generation = 0;
    }
    core->phase = P4_CTAPHID_PHASE_IDLE;
    core->active_cid = 0;
    core->active_command = 0;
}


void p4_ctaphid_core_finish_response(p4_ctaphid_core_t *core,
                                     uint32_t cid,
                                     uint32_t generation)
{
    if (core == NULL || core->phase != P4_CTAPHID_PHASE_PROCESSING ||
        core->active_cid != cid) {
        return;
    }

    const p4_ctaphid_channel_t *channel =
        p4_ctaphid_chan_find_const(core, cid);
    if (channel == NULL || channel->generation != generation) {
        return;
    }
    clear_active(core, true);
}


static void begin_message(p4_ctaphid_core_t *core,
                          p4_ctaphid_channel_t *channel,
                          uint8_t command,
                          uint16_t declared_len,
                          uint32_t now_ms)
{
    // one channel owns the shared assembly buffer until its response
    core->phase = P4_CTAPHID_PHASE_RX;
    core->active_cid = channel->cid;
    core->active_command = command;
    channel->partial_active = true;
    channel->command = command;
    channel->declared_len = declared_len;
    channel->received = 0;
    channel->next_sequence = 0;
    channel->last_packet_ms = now_ms;
    channel->cancel = false;
    channel->timeout_pending = false;
    channel->keepalive_sent = false;
    channel->generation++;
    p4_ctaphid_wipe(core->buffers[core->rx_buffer],
                    P4_CTAPHID_MAX_PAYLOAD);
}


static void complete_message(p4_ctaphid_core_t *core,
                             p4_ctaphid_channel_t *channel,
                             p4_ctaphid_action_t *action)
{
    channel->partial_active = false;
    core->phase = P4_CTAPHID_PHASE_PROCESSING;

    if (channel->command == CTAPHID_PING) {
        send_action(core, action, channel->cid, CTAPHID_PING,
                    core->buffers[core->rx_buffer], channel->declared_len);
        action->generation = channel->generation;
        return;
    }

    if (core->message_ready) {
        count_queue_full(core);
        uint32_t cid = channel->cid;
        clear_active(core, false);
        error_action(core, action, cid, CTAPHID_ERR_CHANNEL_BUSY);
        return;
    }

    // hand the filled buffer over without a second internal payload copy
    core->complete_buffer = core->rx_buffer;
    core->complete_cid = channel->cid;
    core->complete_command = channel->command;
    core->complete_len = channel->declared_len;
    core->complete_generation = channel->generation;
    core->rx_buffer = (uint8_t)(1U - core->rx_buffer);
    core->message_ready = true;
    action->kind = P4_CTAPHID_ACTION_MESSAGE;
    action->cid = channel->cid;
    action->command = channel->command;
    action->generation = channel->generation;
    action->data = core->buffers[core->complete_buffer];
    action->data_len = channel->declared_len;
}


static void init_reply(p4_ctaphid_core_t *core,
                       p4_ctaphid_action_t *action,
                       uint32_t response_cid,
                       uint32_t assigned_cid,
                       const uint8_t nonce[8])
{
    memcpy(core->control, nonce, 8);
    store_u32(&core->control[8], assigned_cid);
    core->control[12] = CTAPHID_PROTOCOL_VERSION;
    core->control[13] = P4KEY_VERSION_MAJOR;
    core->control[14] = P4KEY_VERSION_MINOR;
    core->control[15] = P4KEY_VERSION_BUILD;
    core->control[16] = CTAPHID_CAPABILITIES;
    send_action(core, action, response_cid, CTAPHID_INIT,
                core->control, P4_CTAPHID_INIT_REPLY_BYTES);
}


static void handle_init(p4_ctaphid_core_t *core,
                        p4_ctaphid_action_t *action,
                        uint32_t cid,
                        uint16_t declared_len,
                        const uint8_t *nonce,
                        p4_ctaphid_rand_fn rand_fn,
                        void *rand_ctx)
{
    if (declared_len != 8) {
        error_action(core, action, cid, CTAPHID_ERR_INVALID_LEN);
        return;
    }

    if (cid == CTAPHID_BROADCAST_CID) {
        // allocation stays responsive and never disturbs another CID
        uint32_t new_cid = 0;
        int err = p4_ctaphid_chan_allocate(core, rand_fn, rand_ctx, &new_cid);
        if (err == P4_CTAPHID_CORE_FULL) {
            error_action(core, action, cid, CTAPHID_ERR_CHANNEL_BUSY);
        } else if (err != P4_CTAPHID_CORE_OK) {
            error_action(core, action, cid, CTAPHID_ERR_OTHER);
        } else {
            init_reply(core, action, cid, new_cid, nonce);
        }
        return;
    }

    p4_ctaphid_channel_t *channel = p4_ctaphid_chan_find(core, cid);
    if (channel == NULL) {
        error_action(core, action, cid, CTAPHID_ERR_INVALID_CHANNEL);
        return;
    }
    if (core->phase != P4_CTAPHID_PHASE_IDLE &&
        core->active_cid != cid) {
        if (core->message_ready) {
            count_queue_full(core);
        }
        error_action(core, action, cid, CTAPHID_ERR_CHANNEL_BUSY);
        return;
    }

    if (core->active_cid == cid) {
        clear_active(core, true);
    }
    clear_channel_rx(channel);
    channel->cancel = false;
    channel->timeout_pending = false;
    channel->generation++;
    init_reply(core, action, cid, cid, nonce);
}


static void handle_cancel(p4_ctaphid_core_t *core,
                          p4_ctaphid_action_t *action,
                          uint32_t cid,
                          uint16_t declared_len)
{
    if (declared_len != 0) {
        // CANCEL itself never gets a response even when malformed
        return;
    }

    if (core->phase != P4_CTAPHID_PHASE_PROCESSING ||
        core->active_cid != cid || core->active_command != CTAPHID_CBOR) {
        return;
    }

    p4_ctaphid_channel_t *channel = p4_ctaphid_chan_find(core, cid);
    if (channel == NULL) {
        return;
    }
    channel->cancel = true;
    action->kind = P4_CTAPHID_ACTION_CANCEL;
    action->cid = cid;
    action->command = CTAPHID_CANCEL;
    action->generation = channel->generation;
}


static void feed_initial(p4_ctaphid_core_t *core,
                         const uint8_t *report,
                         uint32_t now_ms,
                         p4_ctaphid_rand_fn rand_fn,
                         void *rand_ctx,
                         p4_ctaphid_action_t *action)
{
    uint32_t cid = load_u32(report);
    uint8_t command = report[4];
    uint16_t declared_len = load_u16(&report[5]);

    if (command == CTAPHID_CANCEL) {
        handle_cancel(core, action, cid, declared_len);
        return;
    }
    if (command == CTAPHID_INIT) {
        handle_init(core, action, cid, declared_len, &report[7],
                    rand_fn, rand_ctx);
        return;
    }

    if (cid == 0 || cid == CTAPHID_BROADCAST_CID) {
        error_action(core, action, cid, CTAPHID_ERR_INVALID_CHANNEL);
        return;
    }

    p4_ctaphid_channel_t *channel = p4_ctaphid_chan_find(core, cid);
    if (channel == NULL) {
        error_action(core, action, cid, CTAPHID_ERR_INVALID_CHANNEL);
        return;
    }
    channel->timeout_pending = false;

    if (core->phase != P4_CTAPHID_PHASE_IDLE) {
        // only one request owns the transport until its response finishes
        if (core->message_ready) {
            count_queue_full(core);
        }
        if (core->active_cid != cid) {
            error_action(core, action, cid, CTAPHID_ERR_CHANNEL_BUSY);
        } else if (core->phase == P4_CTAPHID_PHASE_RX) {
            clear_active(core, true);
            error_action(core, action, cid, CTAPHID_ERR_INVALID_SEQ);
        } else {
            error_action(core, action, cid, CTAPHID_ERR_CHANNEL_BUSY);
        }
        return;
    }

    if (declared_len > P4_CTAPHID_MAX_PAYLOAD) {
        error_action(core, action, cid, CTAPHID_ERR_INVALID_LEN);
        return;
    }
    if (command != CTAPHID_PING && command != CTAPHID_CBOR) {
        error_action(core, action, cid, CTAPHID_ERR_INVALID_CMD);
        return;
    }
    if (command == CTAPHID_CBOR && declared_len == 0) {
        error_action(core, action, cid, CTAPHID_ERR_INVALID_LEN);
        return;
    }

    begin_message(core, channel, command, declared_len, now_ms);
    size_t take = declared_len < P4_CTAPHID_INIT_DATA_BYTES ?
                  declared_len : P4_CTAPHID_INIT_DATA_BYTES;
    // ignore report padding beyond the declared request length
    if (take != 0) {
        memcpy(core->buffers[core->rx_buffer], &report[7], take);
    }
    channel->received = (uint16_t)take;
    if (channel->received == channel->declared_len) {
        complete_message(core, channel, action);
    }
}


static void feed_continuation(p4_ctaphid_core_t *core,
                              const uint8_t *report,
                              uint32_t now_ms,
                              p4_ctaphid_action_t *action)
{
    uint32_t cid = load_u32(report);
    p4_ctaphid_channel_t *channel = p4_ctaphid_chan_find(core, cid);
    if (channel != NULL && channel->timeout_pending) {
        // periodic cleanup keeps only this small response tombstone
        channel->timeout_pending = false;
        error_action(core, action, cid, CTAPHID_ERR_MSG_TIMEOUT);
        return;
    }

    if (channel == NULL || !channel->partial_active ||
        core->phase != P4_CTAPHID_PHASE_RX || core->active_cid != cid) {
        // spurious continuations never allocate or disturb another channel
        return;
    }

    if (p4_ctaphid_time_expired(now_ms, channel->last_packet_ms,
                                P4_CTAPHID_MESSAGE_TIMEOUT_MS)) {
        clear_active(core, true);
        error_action(core, action, cid, CTAPHID_ERR_MSG_TIMEOUT);
        return;
    }

    uint8_t sequence = report[4];
    if (sequence != channel->next_sequence) {
        clear_active(core, true);
        error_action(core, action, cid, CTAPHID_ERR_INVALID_SEQ);
        return;
    }

    size_t remaining = channel->declared_len - channel->received;
    size_t take = remaining < P4_CTAPHID_CONT_DATA_BYTES ?
                  remaining : P4_CTAPHID_CONT_DATA_BYTES;
    if (take != 0) {
        // copy only the remaining declared bytes never continuation padding
        memcpy(&core->buffers[core->rx_buffer][channel->received],
               &report[5], take);
    }
    channel->received += (uint16_t)take;
    channel->last_packet_ms = now_ms;
    channel->next_sequence++;

    if (channel->received == channel->declared_len) {
        complete_message(core, channel, action);
    }
}


int p4_ctaphid_core_feed(
    p4_ctaphid_core_t *core,
    const uint8_t report[P4_CTAPHID_REPORT_BYTES],
    uint32_t now_ms,
    p4_ctaphid_rand_fn rand_fn,
    void *rand_ctx,
    p4_ctaphid_action_t *action)
{
    if (core == NULL || report == NULL || action == NULL) {
        return P4_CTAPHID_CORE_ARG;
    }

    no_action(action);
    // expire stale input before classifying the packet that follows it
    p4_ctaphid_core_cleanup(core, now_ms);
    if ((report[4] & 0x80U) != 0) {
        feed_initial(core, report, now_ms, rand_fn, rand_ctx, action);
    } else {
        feed_continuation(core, report, now_ms, action);
    }
    return P4_CTAPHID_CORE_OK;
}


void p4_ctaphid_core_cleanup(p4_ctaphid_core_t *core, uint32_t now_ms)
{
    if (core == NULL || core->phase != P4_CTAPHID_PHASE_RX) {
        return;
    }

    p4_ctaphid_channel_t *channel =
        p4_ctaphid_chan_find(core, core->active_cid);
    if (channel == NULL ||
        !p4_ctaphid_time_expired(now_ms, channel->last_packet_ms,
                                 P4_CTAPHID_MESSAGE_TIMEOUT_MS)) {
        return;
    }

    channel->timeout_pending = true;
    clear_channel_rx(channel);
    p4_ctaphid_wipe(core->buffers[core->rx_buffer],
                    P4_CTAPHID_MAX_PAYLOAD);
    core->phase = P4_CTAPHID_PHASE_IDLE;
    core->active_cid = 0;
    core->active_command = 0;
}
