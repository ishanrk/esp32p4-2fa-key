#include "p4_ctaphid_priv.h"


bool p4_ctaphid_time_expired(uint32_t now_ms, uint32_t then_ms,
                             uint32_t timeout_ms)
{
    return (uint32_t)(now_ms - then_ms) >= timeout_ms;
}
