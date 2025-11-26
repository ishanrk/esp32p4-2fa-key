#pragma once

void root_test_log_warning(const char *tag, const char *message);

#define ESP_LOGW(tag, message) root_test_log_warning((tag), (message))
