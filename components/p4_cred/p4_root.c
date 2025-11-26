#include "p4_cred.h"
#include "p4_cred_priv.h"

#include <stdbool.h>
#include <string.h>

#include "esp_log.h"
#include "nvs.h"
#include "nvs_flash.h"
#include "p4_crypto.h"


#define ROOT_NAMESPACE "p4key"
#define ROOT_KEY "dev_root"


static const char *tag = "p4_root";
static bool s_root_ready;
static bool s_root_failed;


static int root_fail(nvs_handle_t handle,
                     uint8_t root[P4_CRYPTO_AES256_KEY_LEN])
{
    secret_clear(root, P4_CRYPTO_AES256_KEY_LEN);
    if (handle != 0) {
        nvs_close(handle);
    }
    s_root_failed = true;
    return P4_CRED_ERR_ROOT;
}


int p4_cred_init(void)
{
    if (s_root_failed) {
        return P4_CRED_ERR_ROOT;
    }
    if (s_root_ready) {
        return P4_CRED_OK;
    }

    uint8_t root[P4_CRYPTO_AES256_KEY_LEN] = {0};
    nvs_handle_t handle = 0;
    esp_err_t err = nvs_flash_init();
    if (err != ESP_OK) {
        return root_fail(handle, root);
    }

    err = nvs_open(ROOT_NAMESPACE, NVS_READWRITE, &handle);
    if (err != ESP_OK) {
        return root_fail(handle, root);
    }

    size_t root_len = sizeof(root);
    err = nvs_get_blob(handle, ROOT_KEY, root, &root_len);
    if (err == ESP_ERR_NVS_NOT_FOUND) {
        if (rand_fill(root, sizeof(root)) != P4_CRYPTO_OK) {
            return root_fail(handle, root);
        }
        err = nvs_set_blob(handle, ROOT_KEY, root, sizeof(root));
        if (err != ESP_OK) {
            return root_fail(handle, root);
        }
        err = nvs_commit(handle);
        if (err != ESP_OK) {
            return root_fail(handle, root);
        }
    } else if (err != ESP_OK || root_len != sizeof(root)) {
        return root_fail(handle, root);
    }

    secret_clear(root, sizeof(root));
    nvs_close(handle);
    s_root_ready = true;
    ESP_LOGW(tag, "development wrapping root is stored in flash and is not "
                  "resistant to physical flash extraction");
    return P4_CRED_OK;
}


int p4_root_load(uint8_t root[P4_CRYPTO_AES256_KEY_LEN])
{
    if (root == NULL) {
        return P4_CRED_ERR_ARG;
    }
    secret_clear(root, P4_CRYPTO_AES256_KEY_LEN);
    if (!s_root_ready || s_root_failed) {
        return P4_CRED_ERR_ROOT;
    }

    uint8_t stored[P4_CRYPTO_AES256_KEY_LEN] = {0};
    nvs_handle_t handle = 0;
    esp_err_t err = nvs_open(ROOT_NAMESPACE, NVS_READONLY, &handle);
    if (err == ESP_OK) {
        size_t stored_len = sizeof(stored);
        err = nvs_get_blob(handle, ROOT_KEY, stored, &stored_len);
        if (err == ESP_OK && stored_len == sizeof(stored)) {
            memcpy(root, stored, sizeof(stored));
        } else {
            err = ESP_FAIL;
        }
    }

    secret_clear(stored, sizeof(stored));
    if (handle != 0) {
        nvs_close(handle);
    }
    if (err != ESP_OK) {
        secret_clear(root, P4_CRYPTO_AES256_KEY_LEN);
        s_root_ready = false;
        s_root_failed = true;
        return P4_CRED_ERR_ROOT;
    }
    return P4_CRED_OK;
}
