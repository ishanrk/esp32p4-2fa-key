#include "p4_button.h"

#include <stdbool.h>
#include <stdio.h>


static int expect(const char *name, bool actual, bool expected)
{
    if (actual == expected) {
        return 0;
    }

    fprintf(stderr, "FAIL %s expected %d got %d\n",
            name, expected, actual);
    return 1;
}


int main(void)
{
    int failed = 0;

    failed += expect("gpio minus one is unconfigured",
                     p4_button_configured(-1), false);
    failed += expect("gpio zero is configured",
                     p4_button_configured(0), true);

    failed += expect("active low press",
                     p4_button_pressed(0, true), true);
    failed += expect("active low release",
                     p4_button_pressed(1, true), false);
    failed += expect("active high press",
                     p4_button_pressed(1, false), true);
    failed += expect("active high release",
                     p4_button_pressed(0, false), false);

    if (failed) {
        return 1;
    }

    puts("PASS button level conversion");
    return 0;
}
