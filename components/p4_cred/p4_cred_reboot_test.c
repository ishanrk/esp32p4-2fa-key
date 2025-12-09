#include "p4_cred_test.h"

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "esp_attr.h"
#include "esp_cache.h"
#include "esp_err.h"
#include "esp_log.h"
#include "esp_system.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "p4_cred.h"
#include "p4_crypto.h"


#define REBOOT_MAGIC 0x50344352U
#define REBOOT_MAGIC_INVERSE (~REBOOT_MAGIC)


typedef struct {
    uint32_t magic;
    uint32_t magic_inverse;
    uint8_t credential_id[P4_CRED_ID_LEN];
    uint8_t public_fingerprint[P4_CRYPTO_SHA256_LEN];
} p4_cred_reboot_state_t;


static const char *tag = "p4_cred_test";
static const uint8_t s_test_rp_id[] = "p4key credential reboot test";
static __NOINIT_ATTR p4_cred_reboot_state_t s_reboot_state
    __attribute__((aligned(64)));


static bool equal_fixed(const uint8_t *left,
                        const uint8_t *right,
                        size_t len)
{
    uint32_t different = 0;
    for (size_t index = 0; index < len; index++) {
        different |= (uint32_t)(left[index] ^ right[index]);
    }
    return different == 0;
}


static int state_sync(void)
{
    int flags = ESP_CACHE_MSYNC_FLAG_DIR_C2M |
                ESP_CACHE_MSYNC_FLAG_UNALIGNED;
    return esp_cache_msync(&s_reboot_state,
                           sizeof(s_reboot_state), flags) == ESP_OK
               ? 0
               : -1;
}


static void clear_locals(uint8_t rp_hash[P4_CRED_RP_ID_HASH_LEN],
                         uint8_t private_scalar[P4_CRED_PRIVATE_SCALAR_LEN],
                         uint8_t opened[P4_CRED_PRIVATE_SCALAR_LEN],
                         uint8_t x[P4_CRYPTO_P256_SCALAR_LEN],
                         uint8_t y[P4_CRYPTO_P256_SCALAR_LEN],
                         uint8_t public_bytes[2 * P4_CRYPTO_P256_SCALAR_LEN],
                         uint8_t fingerprint[P4_CRYPTO_SHA256_LEN],
                         uint8_t credential_id[P4_CRED_ID_LEN])
{
    secret_clear(rp_hash, P4_CRED_RP_ID_HASH_LEN);
    secret_clear(private_scalar, P4_CRED_PRIVATE_SCALAR_LEN);
    secret_clear(opened, P4_CRED_PRIVATE_SCALAR_LEN);
    secret_clear(x, P4_CRYPTO_P256_SCALAR_LEN);
    secret_clear(y, P4_CRYPTO_P256_SCALAR_LEN);
    secret_clear(public_bytes, 2 * P4_CRYPTO_P256_SCALAR_LEN);
    secret_clear(fingerprint, P4_CRYPTO_SHA256_LEN);
    secret_clear(credential_id, P4_CRED_ID_LEN);
}


static int test_fail(int step,
                     uint8_t rp_hash[P4_CRED_RP_ID_HASH_LEN],
                     uint8_t private_scalar[P4_CRED_PRIVATE_SCALAR_LEN],
                     uint8_t opened[P4_CRED_PRIVATE_SCALAR_LEN],
                     uint8_t x[P4_CRYPTO_P256_SCALAR_LEN],
                     uint8_t y[P4_CRYPTO_P256_SCALAR_LEN],
                     uint8_t public_bytes[2 * P4_CRYPTO_P256_SCALAR_LEN],
                     uint8_t fingerprint[P4_CRYPTO_SHA256_LEN],
                     uint8_t credential_id[P4_CRED_ID_LEN])
{
    clear_locals(rp_hash, private_scalar, opened, x, y,
                 public_bytes, fingerprint, credential_id);
    ESP_LOGE(tag, "CRED_REBOOT_TEST FAIL step=%d", step);
    return -1;
}


int p4_cred_reboot_test_run(void)
{
    uint8_t rp_hash[P4_CRED_RP_ID_HASH_LEN] = {0};
    uint8_t private_scalar[P4_CRED_PRIVATE_SCALAR_LEN] = {0};
    uint8_t opened[P4_CRED_PRIVATE_SCALAR_LEN] = {0};
    uint8_t x[P4_CRYPTO_P256_SCALAR_LEN] = {0};
    uint8_t y[P4_CRYPTO_P256_SCALAR_LEN] = {0};
    uint8_t public_bytes[2 * P4_CRYPTO_P256_SCALAR_LEN] = {0};
    uint8_t fingerprint[P4_CRYPTO_SHA256_LEN] = {0};
    uint8_t credential_id[P4_CRED_ID_LEN] = {0};

    if (sha256_sum(s_test_rp_id, sizeof(s_test_rp_id) - 1,
                   rp_hash) != P4_CRYPTO_OK) {
        return test_fail(1, rp_hash, private_scalar, opened, x, y,
                         public_bytes, fingerprint, credential_id);
    }

    bool reboot_open =
        s_reboot_state.magic == REBOOT_MAGIC &&
        s_reboot_state.magic_inverse == REBOOT_MAGIC_INVERSE;
    if (!reboot_open) {
        /* Let the bounded UART checker attach after the test image is flashed. */
        vTaskDelay(pdMS_TO_TICKS(3000));
        if (p256_make(private_scalar, x, y) != P4_CRYPTO_OK) {
            return test_fail(2, rp_hash, private_scalar, opened, x, y,
                             public_bytes, fingerprint, credential_id);
        }
        memcpy(public_bytes, x, sizeof(x));
        memcpy(public_bytes + sizeof(x), y, sizeof(y));
        if (sha256_sum(public_bytes, sizeof(public_bytes),
                       fingerprint) != P4_CRYPTO_OK) {
            return test_fail(3, rp_hash, private_scalar, opened, x, y,
                             public_bytes, fingerprint, credential_id);
        }
        if (cred_wrap(rp_hash, sizeof(rp_hash),
                      private_scalar, sizeof(private_scalar),
                      credential_id, sizeof(credential_id)) != P4_CRED_OK) {
            return test_fail(4, rp_hash, private_scalar, opened, x, y,
                             public_bytes, fingerprint, credential_id);
        }
        if (cred_open(rp_hash, sizeof(rp_hash),
                      credential_id, sizeof(credential_id),
                      opened, sizeof(opened)) != P4_CRED_OK ||
            !equal_fixed(opened, private_scalar, sizeof(opened))) {
            return test_fail(5, rp_hash, private_scalar, opened, x, y,
                             public_bytes, fingerprint, credential_id);
        }

        secret_clear(&s_reboot_state, sizeof(s_reboot_state));
        memcpy(s_reboot_state.credential_id,
               credential_id, sizeof(credential_id));
        memcpy(s_reboot_state.public_fingerprint,
               fingerprint, sizeof(fingerprint));
        s_reboot_state.magic_inverse = REBOOT_MAGIC_INVERSE;
        s_reboot_state.magic = REBOOT_MAGIC;
        if (state_sync() != 0) {
            secret_clear(&s_reboot_state, sizeof(s_reboot_state));
            (void)state_sync();
            return test_fail(6, rp_hash, private_scalar, opened, x, y,
                             public_bytes, fingerprint, credential_id);
        }

        clear_locals(rp_hash, private_scalar, opened, x, y,
                     public_bytes, fingerprint, credential_id);
        ESP_LOGI(tag, "CRED_REBOOT_TEST wrap_open PASS");
        ESP_LOGI(tag, "CRED_REBOOT_TEST software reboot");
        vTaskDelay(pdMS_TO_TICKS(2000));
        esp_restart();
    }

    if (cred_open(rp_hash, sizeof(rp_hash),
                  s_reboot_state.credential_id,
                  sizeof(s_reboot_state.credential_id),
                  private_scalar, sizeof(private_scalar)) != P4_CRED_OK) {
        return test_fail(7, rp_hash, private_scalar, opened, x, y,
                         public_bytes, fingerprint, credential_id);
    }
    if (p256_pub(private_scalar, x, y) != P4_CRYPTO_OK) {
        return test_fail(8, rp_hash, private_scalar, opened, x, y,
                         public_bytes, fingerprint, credential_id);
    }
    memcpy(public_bytes, x, sizeof(x));
    memcpy(public_bytes + sizeof(x), y, sizeof(y));
    if (sha256_sum(public_bytes, sizeof(public_bytes),
                   fingerprint) != P4_CRYPTO_OK ||
        !equal_fixed(fingerprint,
                     s_reboot_state.public_fingerprint,
                     sizeof(fingerprint))) {
        return test_fail(9, rp_hash, private_scalar, opened, x, y,
                         public_bytes, fingerprint, credential_id);
    }

    secret_clear(&s_reboot_state, sizeof(s_reboot_state));
    if (state_sync() != 0) {
        return test_fail(10, rp_hash, private_scalar, opened, x, y,
                         public_bytes, fingerprint, credential_id);
    }
    clear_locals(rp_hash, private_scalar, opened, x, y,
                 public_bytes, fingerprint, credential_id);
    ESP_LOGI(tag, "CRED_REBOOT_TEST persistence PASS");
    return 0;
}
