#include "p4_cred.h"
#include "p4_cred_priv.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "esp_err.h"
#include "nvs.h"
#include "p4_crypto.h"


enum scenario {
    SCENARIO_MISSING,
    SCENARIO_EXISTING,
    SCENARIO_SHORT,
    SCENARIO_LONG,
    SCENARIO_READ_ERROR,
    SCENARIO_LOAD_ERROR,
    SCENARIO_INIT_ERROR,
    SCENARIO_COMMIT_ERROR,
};


static enum scenario s_scenario;
static uint8_t s_stored[P4_CRYPTO_AES256_KEY_LEN];
static bool s_has_blob;
static size_t s_blob_len;
static unsigned s_init_calls;
static unsigned s_get_calls;
static unsigned s_rand_calls;
static unsigned s_set_calls;
static unsigned s_commit_calls;
static unsigned s_close_calls;
static unsigned s_warning_calls;
static unsigned s_clear_root_calls;


static void fail(const char *name, int line)
{
    fprintf(stderr, "FAIL %s line %d\n", name, line);
    exit(1);
}

#define CHECK(value) do { if (!(value)) fail(__func__, __LINE__); } while (0)


void root_test_log_warning(const char *tag, const char *message)
{
    CHECK(strcmp(tag, "p4_root") == 0);
    CHECK(strstr(message, "physical flash extraction") != NULL);
    s_warning_calls++;
}


esp_err_t nvs_flash_init(void)
{
    s_init_calls++;
    return s_scenario == SCENARIO_INIT_ERROR ? ESP_FAIL : ESP_OK;
}


esp_err_t nvs_open(const char *name, nvs_open_mode_t mode,
                   nvs_handle_t *out_handle)
{
    CHECK(strcmp(name, "p4key") == 0);
    CHECK(mode == NVS_READWRITE || mode == NVS_READONLY);
    *out_handle = 1;
    return ESP_OK;
}


esp_err_t nvs_get_blob(nvs_handle_t handle, const char *key,
                       void *out_value, size_t *length)
{
    CHECK(handle == 1);
    CHECK(strcmp(key, "dev_root") == 0);
    CHECK(out_value != NULL);
    CHECK(length != NULL);
    s_get_calls++;

    if (s_scenario == SCENARIO_READ_ERROR) {
        return ESP_ERR_NVS_TYPE_MISMATCH;
    }
    if (!s_has_blob) {
        return ESP_ERR_NVS_NOT_FOUND;
    }
    if (*length < s_blob_len) {
        *length = s_blob_len;
        return ESP_ERR_NVS_INVALID_LENGTH;
    }
    memcpy(out_value, s_stored, s_blob_len);
    *length = s_blob_len;
    return ESP_OK;
}


esp_err_t nvs_set_blob(nvs_handle_t handle, const char *key,
                       const void *value, size_t length)
{
    CHECK(handle == 1);
    CHECK(strcmp(key, "dev_root") == 0);
    CHECK(value != NULL);
    CHECK(length == sizeof(s_stored));
    memcpy(s_stored, value, length);
    s_blob_len = length;
    s_has_blob = true;
    s_set_calls++;
    return ESP_OK;
}


esp_err_t nvs_commit(nvs_handle_t handle)
{
    CHECK(handle == 1);
    s_commit_calls++;
    return s_scenario == SCENARIO_COMMIT_ERROR ? ESP_FAIL : ESP_OK;
}


void nvs_close(nvs_handle_t handle)
{
    CHECK(handle == 1);
    s_close_calls++;
}


int rand_fill(uint8_t *out, size_t out_len)
{
    CHECK(out != NULL);
    CHECK(out_len == P4_CRYPTO_AES256_KEY_LEN);
    s_rand_calls++;
    for (size_t index = 0; index < out_len; index++) {
        out[index] = (uint8_t)(0xa0U + index);
    }
    return P4_CRYPTO_OK;
}


void secret_clear(void *ptr, size_t len)
{
    if (ptr != NULL && len != 0) {
        if (len == P4_CRYPTO_AES256_KEY_LEN) {
            s_clear_root_calls++;
        }
        volatile uint8_t *bytes = ptr;
        while (len-- != 0) {
            *bytes++ = 0;
        }
    }
}


static void seed_existing(size_t len)
{
    CHECK(len <= sizeof(s_stored));
    s_has_blob = true;
    s_blob_len = len;
    for (size_t index = 0; index < len; index++) {
        s_stored[index] = (uint8_t)(index + 1U);
    }
}


static void test_success(bool generated)
{
    uint8_t expected[sizeof(s_stored)];
    if (!generated) {
        memcpy(expected, s_stored, sizeof(expected));
    }

    CHECK(p4_cred_init() == P4_CRED_OK);
    if (generated) {
        memcpy(expected, s_stored, sizeof(expected));
        CHECK(s_rand_calls == 1);
        CHECK(s_set_calls == 1);
        CHECK(s_commit_calls == 1);
    } else {
        CHECK(s_rand_calls == 0);
        CHECK(s_set_calls == 0);
        CHECK(s_commit_calls == 0);
    }
    CHECK(s_warning_calls == 1);

    uint8_t loaded[sizeof(s_stored)];
    memset(loaded, 0x55, sizeof(loaded));
    CHECK(p4_root_load(loaded) == P4_CRED_OK);
    CHECK(memcmp(loaded, expected, sizeof(loaded)) == 0);
    secret_clear(loaded, sizeof(loaded));

    CHECK(p4_cred_init() == P4_CRED_OK);
    CHECK(s_init_calls == 1);
    CHECK(s_warning_calls == 1);
    CHECK(s_get_calls == 2);
    CHECK(s_close_calls == 2);
    CHECK(s_clear_root_calls >= 3);
}


static void test_failure(void)
{
    CHECK(p4_cred_init() == P4_CRED_ERR_ROOT);
    CHECK(s_rand_calls == 0);
    CHECK(s_set_calls == 0);
    CHECK(s_commit_calls == 0);
    CHECK(s_warning_calls == 0);

    uint8_t loaded[sizeof(s_stored)];
    memset(loaded, 0x55, sizeof(loaded));
    CHECK(p4_root_load(loaded) == P4_CRED_ERR_ROOT);
    for (size_t index = 0; index < sizeof(loaded); index++) {
        CHECK(loaded[index] == 0);
    }
    CHECK(p4_cred_init() == P4_CRED_ERR_ROOT);
    CHECK(s_init_calls <= 1);
}


static enum scenario parse_scenario(const char *name)
{
    if (strcmp(name, "missing") == 0) return SCENARIO_MISSING;
    if (strcmp(name, "existing") == 0) return SCENARIO_EXISTING;
    if (strcmp(name, "short") == 0) return SCENARIO_SHORT;
    if (strcmp(name, "long") == 0) return SCENARIO_LONG;
    if (strcmp(name, "read_error") == 0) return SCENARIO_READ_ERROR;
    if (strcmp(name, "load_error") == 0) return SCENARIO_LOAD_ERROR;
    if (strcmp(name, "init_error") == 0) return SCENARIO_INIT_ERROR;
    if (strcmp(name, "commit_error") == 0) return SCENARIO_COMMIT_ERROR;
    fail(__func__, __LINE__);
    return SCENARIO_MISSING;
}


int main(int argc, char **argv)
{
    CHECK(argc == 2);
    s_scenario = parse_scenario(argv[1]);

    if (s_scenario == SCENARIO_EXISTING) {
        seed_existing(sizeof(s_stored));
        test_success(false);
    } else if (s_scenario == SCENARIO_MISSING) {
        test_success(true);
    } else if (s_scenario == SCENARIO_SHORT) {
        seed_existing(sizeof(s_stored) - 1);
        test_failure();
    } else if (s_scenario == SCENARIO_LONG) {
        s_has_blob = true;
        s_blob_len = sizeof(s_stored) + 1;
        test_failure();
    } else if (s_scenario == SCENARIO_COMMIT_ERROR) {
        CHECK(p4_cred_init() == P4_CRED_ERR_ROOT);
        CHECK(s_rand_calls == 1);
        CHECK(s_set_calls == 1);
        CHECK(s_commit_calls == 1);
        CHECK(s_warning_calls == 0);
        CHECK(p4_cred_init() == P4_CRED_ERR_ROOT);
        CHECK(s_rand_calls == 1);
    } else if (s_scenario == SCENARIO_LOAD_ERROR) {
        seed_existing(sizeof(s_stored));
        CHECK(p4_cred_init() == P4_CRED_OK);
        s_scenario = SCENARIO_READ_ERROR;
        uint8_t loaded[sizeof(s_stored)];
        memset(loaded, 0x55, sizeof(loaded));
        CHECK(p4_root_load(loaded) == P4_CRED_ERR_ROOT);
        for (size_t index = 0; index < sizeof(loaded); index++) {
            CHECK(loaded[index] == 0);
        }
        CHECK(p4_root_load(loaded) == P4_CRED_ERR_ROOT);
        CHECK(s_get_calls == 2);
        CHECK(p4_cred_init() == P4_CRED_ERR_ROOT);
    } else {
        test_failure();
    }

    CHECK(s_clear_root_calls != 0);
    puts("PASS fail closed development credential root");
    return 0;
}
