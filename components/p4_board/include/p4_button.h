#ifndef P4_BUTTON_H
#define P4_BUTTON_H

#include <stdbool.h>

bool p4_button_configured(int gpio);
bool p4_button_pressed(int raw_level, bool active_low);

#endif
