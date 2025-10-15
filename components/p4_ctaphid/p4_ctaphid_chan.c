#include "p4_ctaphid_priv.h"

#include <limits.h>
#include <string.h>


void p4_ctaphid_wipe(void *data, size_t len)
{
    // keep the clear visible even under release optimization
    volatile uint8_t *out = data;
    if (out == NULL) {
        return;
    }

    while (len > 0) {
        *out++ = 0;
        len--;
    }
}


void p4_ctaphid_core_init(p4_ctaphid_core_t *core)
{
    if (core == NULL) {
        return;
    }

    p4_ctaphid_wipe(core, sizeof(*core));
    core->complete_buffer = UINT8_MAX;
}


void p4_ctaphid_core_reset(p4_ctaphid_core_t *core)
{
    if (core == NULL) {
        return;
    }

    // later stages carry request data here so reset always scrubs the pool
    p4_ctaphid_wipe(core, sizeof(*core));
    core->complete_buffer = UINT8_MAX;
}


p4_ctaphid_channel_t *p4_ctaphid_chan_find(p4_ctaphid_core_t *core,
                                            uint32_t cid)
{
    if (core == NULL || cid == 0 || cid == CTAPHID_BROADCAST_CID) {
        return NULL;
    }

    for (size_t i = 0; i < P4_CTAPHID_CHANNEL_COUNT; i++) {
        p4_ctaphid_channel_t *channel = &core->channels[i];
        if (channel->allocated && channel->cid == cid) {
            return channel;
        }
    }
    return NULL;
}


const p4_ctaphid_channel_t *p4_ctaphid_chan_find_const(
    const p4_ctaphid_core_t *core,
    uint32_t cid)
{
    if (core == NULL || cid == 0 || cid == CTAPHID_BROADCAST_CID) {
        return NULL;
    }

    for (size_t i = 0; i < P4_CTAPHID_CHANNEL_COUNT; i++) {
        const p4_ctaphid_channel_t *channel = &core->channels[i];
        if (channel->allocated && channel->cid == cid) {
            return channel;
        }
    }
    return NULL;
}


static uint32_t load_cid(const uint8_t raw[4])
{
    return ((uint32_t)raw[0] << 24) |
           ((uint32_t)raw[1] << 16) |
           ((uint32_t)raw[2] << 8) |
           raw[3];
}


int p4_ctaphid_chan_allocate(p4_ctaphid_core_t *core,
                             p4_ctaphid_rand_fn rand_fn,
                             void *rand_ctx,
                             uint32_t *cid)
{
    if (core == NULL || rand_fn == NULL || cid == NULL) {
        return P4_CTAPHID_CORE_ARG;
    }

    p4_ctaphid_channel_t *free_channel = NULL;
    for (size_t i = 0; i < P4_CTAPHID_CHANNEL_COUNT; i++) {
        if (!core->channels[i].allocated) {
            free_channel = &core->channels[i];
            break;
        }
    }
    if (free_channel == NULL) {
        return P4_CTAPHID_CORE_FULL;
    }

    for (size_t attempt = 0; attempt < P4_CTAPHID_CID_RETRIES; attempt++) {
        // retry zero broadcast and collisions without unbounded work
        uint8_t raw[4];
        if (rand_fn(rand_ctx, raw, sizeof(raw)) != 0) {
            p4_ctaphid_wipe(raw, sizeof(raw));
            return P4_CTAPHID_CORE_RANDOM;
        }

        uint32_t candidate = load_cid(raw);
        p4_ctaphid_wipe(raw, sizeof(raw));
        if (candidate == 0 || candidate == CTAPHID_BROADCAST_CID ||
            p4_ctaphid_chan_find(core, candidate) != NULL) {
            continue;
        }

        memset(free_channel, 0, sizeof(*free_channel));
        free_channel->cid = candidate;
        free_channel->allocated = true;
        *cid = candidate;
        return P4_CTAPHID_CORE_OK;
    }

    return P4_CTAPHID_CORE_CID;
}


int p4_ctaphid_core_take_message(
    p4_ctaphid_core_t *core,
    uint32_t *cid,
    uint8_t *command,
    uint8_t *data,
    size_t cap,
    size_t *data_len,
    uint32_t *generation)
{
    if (core == NULL || cid == NULL || command == NULL ||
        data_len == NULL || generation == NULL ||
        (data == NULL && cap != 0)) {
        return P4_CTAPHID_CORE_ARG;
    }
    if (!core->message_ready ||
        core->complete_buffer >= P4_CTAPHID_BUFFER_COUNT) {
        return P4_CTAPHID_CORE_EMPTY;
    }

    if (core->complete_len > cap) {
        return P4_CTAPHID_CORE_SMALL;
    }

    *cid = core->complete_cid;
    *command = core->complete_command;
    *data_len = core->complete_len;
    *generation = core->complete_generation;
    // the public consumer gets one bounded copy then releases this pool slot
    if (core->complete_len != 0) {
        memcpy(data, core->buffers[core->complete_buffer],
               core->complete_len);
    }

    p4_ctaphid_wipe(core->buffers[core->complete_buffer],
                    P4_CTAPHID_MAX_PAYLOAD);
    core->message_ready = false;
    core->complete_buffer = UINT8_MAX;
    core->complete_cid = 0;
    core->complete_command = 0;
    core->complete_len = 0;
    core->complete_generation = 0;
    return P4_CTAPHID_CORE_OK;
}


bool p4_ctaphid_core_cancelled(const p4_ctaphid_core_t *core,
                               uint32_t cid,
                               uint32_t generation)
{
    if (core == NULL || core->phase != P4_CTAPHID_PHASE_PROCESSING ||
        core->active_cid != cid) {
        return true;
    }

    const p4_ctaphid_channel_t *channel =
        p4_ctaphid_chan_find_const(core, cid);
    return channel == NULL || channel->generation != generation ||
           channel->cancel;
}


void p4_ctaphid_core_clear_cancel(p4_ctaphid_core_t *core,
                                  uint32_t cid,
                                  uint32_t generation)
{
    if (core == NULL || core->phase != P4_CTAPHID_PHASE_PROCESSING ||
        core->active_cid != cid) {
        return;
    }

    p4_ctaphid_channel_t *channel = p4_ctaphid_chan_find(core, cid);
    if (channel != NULL && channel->generation == generation) {
        channel->cancel = false;
    }
}
