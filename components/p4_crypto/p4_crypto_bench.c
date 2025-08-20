#include "p4_crypto_bench.h"

#include "p4_crypto.h"
#include "p4_crypto_priv.h"

#include <stdint.h>
#include <string.h>

#include "esp_log.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

static const char *bench_tag = "p4crypto";

// fixed work buffers live only in the benchmark image
static uint8_t bench_input[4096];
static uint8_t bench_cipher[1024];
static uint8_t bench_plain[1024];

static const uint8_t bench_hash[P4_CRYPTO_SHA256_LEN] = {
    0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
    0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
    0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
    0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
};

static void bench_pass(const char *name, int64_t minimum, unsigned reps)
{
    // timing is supporting data and not route proof
    ESP_LOGI(bench_tag,
             "CRYPTO_BENCH %s PASS min_us=%lld reps=%u",
             name, (long long)minimum, reps);
}


static int bench_fail(const char *name, int status, unsigned reps)
{
    ESP_LOGE(bench_tag,
             "CRYPTO_BENCH %s FAIL code=%d detail=%d reps=%u",
             name, status, p4_crypto_last_detail(), reps);
    return 1;
}

static void bench_yield(unsigned iteration)
{
    // short periodic yields avoid watchdog pressure
    if ((iteration & 7u) == 7u) {
        vTaskDelay(1);
    }
}

static int bench_sha(const char *name, size_t len, unsigned reps)
{
    // retain only the least interrupted sample
    uint8_t digest[P4_CRYPTO_SHA256_LEN] = {0};
    int64_t minimum = INT64_MAX;

    for (unsigned i = 0; i < reps; ++i) {
        int64_t start = esp_timer_get_time();
        int status = sha256_sum(bench_input, len, digest);
        int64_t elapsed = esp_timer_get_time() - start;
        if (status != P4_CRYPTO_OK) {
            secret_clear(digest, sizeof(digest));
            return bench_fail(name, status, reps);
        }
        if (elapsed < minimum) {
            minimum = elapsed;
        }
        bench_yield(i);
    }

    secret_clear(digest, sizeof(digest));
    bench_pass(name, minimum, reps);
    return 0;
}

static int bench_gcm_seal(const char *name, size_t len, unsigned reps)
{
    // separate public nonce domains by payload size
    uint8_t key[P4_CRYPTO_AES256_KEY_LEN] = {0};
    uint8_t nonce[P4_CRYPTO_GCM_NONCE_LEN] = {0};
    uint8_t tag[P4_CRYPTO_GCM_TAG_LEN] = {0};
    int64_t minimum = INT64_MAX;
    int result = 0;

    nonce[0] = (uint8_t)(len >> 8);
    nonce[1] = (uint8_t)len;
    for (unsigned i = 0; i < reps; ++i) {
        nonce[10] = (uint8_t)(i >> 8);
        nonce[11] = (uint8_t)i;
        int64_t start = esp_timer_get_time();
        int status = gcm_seal(
            key, nonce, NULL, 0, bench_input, len, bench_cipher, tag);
        int64_t elapsed = esp_timer_get_time() - start;
        if (status != P4_CRYPTO_OK) {
            result = bench_fail(name, status, reps);
            goto cleanup;
        }
        if (elapsed < minimum) {
            minimum = elapsed;
        }
        bench_yield(i);
    }

    bench_pass(name, minimum, reps);

cleanup:
    secret_clear(key, sizeof(key));
    secret_clear(nonce, sizeof(nonce));
    secret_clear(tag, sizeof(tag));
    secret_clear(bench_cipher, len);
    return result;
}


static int bench_gcm_open(const char *name, size_t len, unsigned reps)
{
    uint8_t key[P4_CRYPTO_AES256_KEY_LEN] = {0};
    uint8_t nonce[P4_CRYPTO_GCM_NONCE_LEN] = {0};
    uint8_t tag[P4_CRYPTO_GCM_TAG_LEN] = {0};
    int64_t minimum = INT64_MAX;
    int result = 0;

    nonce[0] = (uint8_t)(len >> 8);
    nonce[1] = (uint8_t)len;
    int status = gcm_seal(
        key, nonce, NULL, 0, bench_input, len, bench_cipher, tag);
    if (status != P4_CRYPTO_OK) {
        result = bench_fail(name, status, reps);
        goto cleanup;
    }

    for (unsigned i = 0; i < reps; ++i) {
        int64_t start = esp_timer_get_time();
        status = gcm_open(
            key, nonce, NULL, 0, bench_cipher, len, tag, bench_plain);
        int64_t elapsed = esp_timer_get_time() - start;
        if (status != P4_CRYPTO_OK) {
            result = bench_fail(name, status, reps);
            goto cleanup;
        }
        if (elapsed < minimum) {
            minimum = elapsed;
        }
        bench_yield(i);
    }

    bench_pass(name, minimum, reps);

cleanup:
    secret_clear(key, sizeof(key));
    secret_clear(nonce, sizeof(nonce));
    secret_clear(tag, sizeof(tag));
    secret_clear(bench_cipher, len);
    secret_clear(bench_plain, len);
    return result;
}

static int bench_p256_make(unsigned reps)
{
    // clear each generated scalar before yielding
    uint8_t priv[32] = {0};
    uint8_t x[32] = {0};
    uint8_t y[32] = {0};
    int64_t minimum = INT64_MAX;
    int result = 0;

    for (unsigned i = 0; i < reps; ++i) {
        int64_t start = esp_timer_get_time();
        int status = p256_make(priv, x, y);
        int64_t elapsed = esp_timer_get_time() - start;
        if (status != P4_CRYPTO_OK) {
            result = bench_fail("p256_keygen", status, reps);
            goto cleanup;
        }
        if (elapsed < minimum) {
            minimum = elapsed;
        }
        secret_clear(priv, sizeof(priv));
        secret_clear(x, sizeof(x));
        secret_clear(y, sizeof(y));
        bench_yield(i);
    }

    bench_pass("p256_keygen", minimum, reps);

cleanup:
    secret_clear(priv, sizeof(priv));
    secret_clear(x, sizeof(x));
    secret_clear(y, sizeof(y));
    return result;
}


static int bench_p256_sign(unsigned reps)
{
    uint8_t priv[32] = {0};
    uint8_t x[32] = {0};
    uint8_t y[32] = {0};
    uint8_t sig[P4_CRYPTO_P256_DER_MAX] = {0};
    int64_t minimum = INT64_MAX;
    int result = 0;

    int status = p256_make(priv, x, y);
    if (status != P4_CRYPTO_OK) {
        result = bench_fail("p256_sign", status, reps);
        goto cleanup;
    }

    for (unsigned i = 0; i < reps; ++i) {
        size_t sig_len = 0;
        int64_t start = esp_timer_get_time();
        status = p256_sign_hash(
            priv, bench_hash, sig, sizeof(sig), &sig_len);
        int64_t elapsed = esp_timer_get_time() - start;
        if (status != P4_CRYPTO_OK) {
            result = bench_fail("p256_sign", status, reps);
            goto cleanup;
        }
        if (elapsed < minimum) {
            minimum = elapsed;
        }
        secret_clear(sig, sizeof(sig));
        bench_yield(i);
    }

    bench_pass("p256_sign", minimum, reps);

cleanup:
    secret_clear(priv, sizeof(priv));
    secret_clear(x, sizeof(x));
    secret_clear(y, sizeof(y));
    secret_clear(sig, sizeof(sig));
    return result;
}


static int bench_p256_verify(unsigned reps)
{
    uint8_t priv[32] = {0};
    uint8_t x[32] = {0};
    uint8_t y[32] = {0};
    uint8_t sig[P4_CRYPTO_P256_DER_MAX] = {0};
    size_t sig_len = 0;
    int64_t minimum = INT64_MAX;
    int result = 0;

    int status = p256_make(priv, x, y);
    if (status == P4_CRYPTO_OK) {
        status = p256_sign_hash(
            priv, bench_hash, sig, sizeof(sig), &sig_len);
    }
    if (status != P4_CRYPTO_OK) {
        result = bench_fail("p256_verify", status, reps);
        goto cleanup;
    }

    for (unsigned i = 0; i < reps; ++i) {
        int64_t start = esp_timer_get_time();
        status = p256_verify_hash(x, y, bench_hash, sig, sig_len);
        int64_t elapsed = esp_timer_get_time() - start;
        if (status != P4_CRYPTO_OK) {
            result = bench_fail("p256_verify", status, reps);
            goto cleanup;
        }
        if (elapsed < minimum) {
            minimum = elapsed;
        }
        bench_yield(i);
    }

    bench_pass("p256_verify", minimum, reps);

cleanup:
    secret_clear(priv, sizeof(priv));
    secret_clear(x, sizeof(x));
    secret_clear(y, sizeof(y));
    secret_clear(sig, sizeof(sig));
    return result;
}

int p4_crypto_bench_run(void)
{
    // bounded repetitions keep the boot diagnostic responsive
    int failed = 0;

    memset(bench_input, 0x5a, sizeof(bench_input));
    ESP_LOGI(bench_tag, "CRYPTO_BENCHMARK START");

    failed += bench_sha("sha256_32", 32, 64);
    failed += bench_sha("sha256_4096", 4096, 24);
    failed += bench_gcm_seal("gcm_seal_64", 64, 32);
    failed += bench_gcm_open("gcm_open_64", 64, 32);
    failed += bench_gcm_seal("gcm_seal_1024", 1024, 16);
    failed += bench_gcm_open("gcm_open_1024", 1024, 16);
    failed += bench_p256_make(8);
    failed += bench_p256_sign(16);
    failed += bench_p256_verify(16);

    secret_clear(bench_input, sizeof(bench_input));
    secret_clear(bench_cipher, sizeof(bench_cipher));
    secret_clear(bench_plain, sizeof(bench_plain));

    if (failed != 0) {
        ESP_LOGE(bench_tag, "CRYPTO_BENCHMARK FAIL count=%d", failed);
        return 1;
    }

    ESP_LOGI(bench_tag, "CRYPTO_BENCHMARK PASS tests=9");
    return 0;
}
