#include "p4_press.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include "p4_ctaphid.h"
#include "p4_ctaphid_wire.h"
#include "freertos/task.h"


static bool s_ready;
static const bool *s_levels;
static size_t s_level_count;
static size_t s_tick;
static size_t s_cancel_tick;
static size_t s_keepalives;


static void fail(const char *name, int line)
{
    fprintf(stderr, "FAIL %s line %d\n", name, line);
    exit(1);
}

#define CHECK(value) do { if (!(value)) fail(__func__, __LINE__); } while (0)


bool p4_board_button_ready(void)
{
    return s_ready;
}


bool p4_board_button_pressed(void)
{
    if (s_level_count == 0) {
        return false;
    }
    size_t index = s_tick < s_level_count ? s_tick : s_level_count - 1;
    return s_levels[index];
}


bool hid_cancelled(uint32_t cid)
{
    CHECK(cid == UINT32_C(0x10203040));
    return s_tick >= s_cancel_tick;
}


int hid_keepalive(uint32_t cid, uint8_t status)
{
    CHECK(cid == UINT32_C(0x10203040));
    CHECK(status == CTAPHID_KEEPALIVE_UP_NEEDED);
    s_keepalives++;
    return P4_HID_OK;
}


void vTaskDelay(TickType_t ticks)
{
    CHECK(ticks == 10);
    s_tick++;
}


static void reset(const bool *levels, size_t level_count)
{
    s_ready = true;
    s_levels = levels;
    s_level_count = level_count;
    s_tick = 0;
    s_cancel_tick = SIZE_MAX;
    s_keepalives = 0;
}


static void test_held_press_needs_release(void)
{
    static const bool levels[] = {
        true, true, true, true,
        false, false, false, false, false,
        true, true, true, true,
    };
    reset(levels, sizeof(levels) / sizeof(levels[0]));
    CHECK(press_wait(UINT32_C(0x10203040)) == P4_PRESS_OK);
    CHECK(s_tick >= 12);
    CHECK(s_keepalives >= 1);
}


static void test_cancel_and_missing_button(void)
{
    static const bool released[] = {false};
    reset(released, sizeof(released) / sizeof(released[0]));
    s_cancel_tick = 3;
    CHECK(press_wait(UINT32_C(0x10203040)) == P4_PRESS_CANCEL);
    CHECK(s_tick == 3);

    reset(released, sizeof(released) / sizeof(released[0]));
    s_ready = false;
    CHECK(press_wait(UINT32_C(0x10203040)) == P4_PRESS_DENIED);
    CHECK(s_keepalives == 0);
}


int main(void)
{
    test_held_press_needs_release();
    test_cancel_and_missing_button();
    puts("PASS fresh button presence");
    return 0;
}
