#include "p4_button.h"


bool p4_button_configured(int gpio)
{
    return gpio >= 0;
}


bool p4_button_pressed(int raw_level, bool active_low)
{
    if (active_low) {
        return raw_level == 0;
    }

    return raw_level != 0;
}
