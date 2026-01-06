#include "p4_ctap_priv.h"

#include <stdbool.h>
#include <string.h>

#include "p4_cbor.h"
#include "p4_cred.h"
#include "p4_crypto.h"
#include "p4_ctap.h"
#include "p4_press.h"

enum {
    ASSERT_AUTH_DATA_LEN = 37,
    ASSERT_SIGN_INPUT_LEN = 69,
    ASSERT_RESPONSE_MAX = 239,
};


typedef struct {
    const uint8_t *id;
    size_t len;
    bool public_key;
} assert_desc_t;


typedef struct {
    const uint8_t *rp_id;
    size_t rp_id_len;
    const uint8_t *client_hash;
    assert_desc_t allow[P4_CTAP_MAX_CREDENTIALS_IN_LIST];
    size_t allow_count;
    bool unsupported_option;
} assert_request_t;


typedef struct {
    uint8_t rp_hash[P4_CRYPTO_SHA256_LEN];
    uint8_t private_scalar[P4_CRYPTO_P256_SCALAR_LEN];
    uint8_t auth_data[ASSERT_AUTH_DATA_LEN];
    uint8_t sign_input[ASSERT_SIGN_INPUT_LEN];
    uint8_t digest[P4_CRYPTO_SHA256_LEN];
    uint8_t signature[P4_CRYPTO_P256_DER_MAX];
    size_t signature_len;
} assert_work_t;


_Static_assert(ASSERT_SIGN_INPUT_LEN ==
               ASSERT_AUTH_DATA_LEN + P4_CRYPTO_SHA256_LEN,
               "assertion signing input size");


static bool text_is(const char *text, size_t len, const char *expected)
{
    size_t expected_len = strlen(expected);
    return len == expected_len && memcmp(text, expected, len) == 0;
}


static int read_allow(p4_cbor_reader_t *reader, assert_request_t *request)
{
    size_t count = 0;
    if (!p4_cbor_get_array(reader, &count)) {
        return P4_CTAP_STATUS_CBOR_UNEXPECTED_TYPE;
    }
    if (count > P4_CTAP_MAX_CREDENTIALS_IN_LIST) {
        return P4_CTAP_STATUS_LIMIT_EXCEEDED;
    }
    request->allow_count = count;

    for (size_t index = 0; index < count; index++) {
        size_t pairs = 0;
        if (!p4_cbor_get_map(reader, &pairs)) {
            return P4_CTAP_STATUS_CBOR_UNEXPECTED_TYPE;
        }
        bool have_type = false;
        bool have_id = false;
        for (size_t pair = 0; pair < pairs; pair++) {
            const char *key = NULL;
            size_t key_len = 0;
            if (!p4_cbor_get_text(reader, &key, &key_len)) {
                return P4_CTAP_STATUS_CBOR_UNEXPECTED_TYPE;
            }
            if (text_is(key, key_len, "type")) {
                const char *type = NULL;
                size_t type_len = 0;
                if (have_type) {
                    return P4_CTAP_STATUS_INVALID_CBOR;
                }
                if (!p4_cbor_get_text(reader, &type, &type_len)) {
                    return P4_CTAP_STATUS_CBOR_UNEXPECTED_TYPE;
                }
                request->allow[index].public_key =
                    text_is(type, type_len, "public-key");
                have_type = true;
            } else if (text_is(key, key_len, "id")) {
                if (have_id) {
                    return P4_CTAP_STATUS_INVALID_CBOR;
                }
                if (!p4_cbor_get_bytes(reader,
                        &request->allow[index].id,
                        &request->allow[index].len)) {
                    return P4_CTAP_STATUS_CBOR_UNEXPECTED_TYPE;
                }
                have_id = true;
            } else if (!p4_cbor_skip(reader)) {
                return P4_CTAP_STATUS_INVALID_CBOR;
            }
        }
        if (!have_type || !have_id) {
            return P4_CTAP_STATUS_MISSING_PARAMETER;
        }
    }
    return P4_CTAP_STATUS_OK;
}


static int read_ignored_map(p4_cbor_reader_t *reader)
{
    size_t pairs = 0;
    if (!p4_cbor_get_map(reader, &pairs)) {
        return P4_CTAP_STATUS_CBOR_UNEXPECTED_TYPE;
    }
    for (size_t index = 0; index < pairs; index++) {
        const char *key = NULL;
        size_t key_len = 0;
        if (!p4_cbor_get_text(reader, &key, &key_len)) {
            return P4_CTAP_STATUS_CBOR_UNEXPECTED_TYPE;
        }
        if (!p4_cbor_skip(reader)) {
            return P4_CTAP_STATUS_INVALID_CBOR;
        }
    }
    return P4_CTAP_STATUS_OK;
}


static int read_options(p4_cbor_reader_t *reader,
                        assert_request_t *request)
{
    size_t pairs = 0;
    if (!p4_cbor_get_map(reader, &pairs)) {
        return P4_CTAP_STATUS_CBOR_UNEXPECTED_TYPE;
    }
    bool have_up = false;
    bool have_uv = false;
    for (size_t index = 0; index < pairs; index++) {
        const char *key = NULL;
        size_t key_len = 0;
        if (!p4_cbor_get_text(reader, &key, &key_len)) {
            return P4_CTAP_STATUS_CBOR_UNEXPECTED_TYPE;
        }
        if (text_is(key, key_len, "up") || text_is(key, key_len, "uv")) {
            bool is_up = text_is(key, key_len, "up");
            bool value = false;
            if (is_up ? have_up : have_uv) {
                return P4_CTAP_STATUS_INVALID_CBOR;
            }
            if (!p4_cbor_get_bool(reader, &value)) {
                return P4_CTAP_STATUS_CBOR_UNEXPECTED_TYPE;
            }
            have_up = have_up || is_up;
            have_uv = have_uv || !is_up;
            request->unsupported_option |= !is_up && value;
        } else if (!p4_cbor_skip(reader)) {
            return P4_CTAP_STATUS_INVALID_CBOR;
        }
    }
    return P4_CTAP_STATUS_OK;
}


static int read_request(const uint8_t *data, size_t len,
                        assert_request_t *request)
{
    p4_cbor_reader_t reader;
    p4_cbor_reader_init(&reader, data, len);
    size_t pairs = 0;
    if (!p4_cbor_get_map(&reader, &pairs)) {
        return P4_CTAP_STATUS_INVALID_CBOR;
    }

    uint32_t seen = 0;
    for (size_t index = 0; index < pairs; index++) {
        uint64_t key = 0;
        if (!p4_cbor_get_uint(&reader, &key)) {
            return P4_CTAP_STATUS_CBOR_UNEXPECTED_TYPE;
        }
        if (key <= 32 &&
            !p4_cbor_known_key_once(&seen, (uint8_t)key)) {
            return P4_CTAP_STATUS_INVALID_CBOR;
        }

        int status = P4_CTAP_STATUS_OK;
        if (key == 1) {
            const char *rp_id = NULL;
            if (!p4_cbor_get_text(&reader, &rp_id,
                                  &request->rp_id_len)) {
                return P4_CTAP_STATUS_CBOR_UNEXPECTED_TYPE;
            }
            if (request->rp_id_len == 0) {
                return P4_CTAP_STATUS_INVALID_PARAMETER;
            }
            request->rp_id = (const uint8_t *)rp_id;
        } else if (key == 2) {
            size_t client_hash_len = 0;
            if (!p4_cbor_get_bytes(&reader, &request->client_hash,
                                   &client_hash_len)) {
                return P4_CTAP_STATUS_CBOR_UNEXPECTED_TYPE;
            }
            if (client_hash_len != P4_CRYPTO_SHA256_LEN) {
                return P4_CTAP_STATUS_INVALID_PARAMETER;
            }
        } else if (key == 3) {
            status = read_allow(&reader, request);
        } else if (key == 4) {
            status = read_ignored_map(&reader);
        } else if (key == 5) {
            status = read_options(&reader, request);
        } else if (key == 6) {
            const uint8_t *pin = NULL;
            size_t pin_len = 0;
            if (!p4_cbor_get_bytes(&reader, &pin, &pin_len)) {
                status = P4_CTAP_STATUS_CBOR_UNEXPECTED_TYPE;
            } else {
                request->unsupported_option = true;
            }
        } else if (key == 7) {
            uint64_t protocol = 0;
            if (!p4_cbor_get_uint(&reader, &protocol)) {
                status = P4_CTAP_STATUS_CBOR_UNEXPECTED_TYPE;
            } else {
                request->unsupported_option = true;
            }
        } else if (!p4_cbor_skip(&reader)) {
            status = P4_CTAP_STATUS_INVALID_CBOR;
        }
        if (status != P4_CTAP_STATUS_OK) {
            return status;
        }
    }

    if (!p4_cbor_reader_done(&reader)) {
        return P4_CTAP_STATUS_INVALID_CBOR;
    }
    if ((seen & UINT32_C(0x03)) != UINT32_C(0x03)) {
        return P4_CTAP_STATUS_MISSING_PARAMETER;
    }
    return request->unsupported_option
               ? P4_CTAP_STATUS_UNSUPPORTED_OPTION
               : P4_CTAP_STATUS_OK;
}


static int find_cred(const assert_request_t *request,
                     const uint8_t rp_hash[P4_CRYPTO_SHA256_LEN],
                     const uint8_t **credential_id,
                     uint8_t private_scalar[P4_CRYPTO_P256_SCALAR_LEN])
{
    for (size_t index = 0; index < request->allow_count; index++) {
        const assert_desc_t *item = &request->allow[index];
        if (!item->public_key || item->len != P4_CRED_ID_LEN) {
            continue;
        }
        int error = cred_open(rp_hash, P4_CRYPTO_SHA256_LEN,
                              item->id, item->len,
                              private_scalar,
                              P4_CRYPTO_P256_SCALAR_LEN);
        if (error == P4_CRED_OK) {
            *credential_id = item->id;
            return P4_CTAP_STATUS_OK;
        }
        secret_clear(private_scalar, P4_CRYPTO_P256_SCALAR_LEN);
        if (error != P4_CRED_ERR_MISMATCH) {
            return P4_CTAP_STATUS_OTHER;
        }
    }
    return P4_CTAP_STATUS_NO_CREDENTIALS;
}


static int presence_status(uint32_t cid)
{
    int result = press_wait(cid);
    if (result == P4_PRESS_OK) {
        return P4_CTAP_STATUS_OK;
    }
    if (result == P4_PRESS_CANCEL) {
        return P4_CTAP_STATUS_KEEPALIVE_CANCEL;
    }
    return result == P4_PRESS_TIMEOUT
               ? P4_CTAP_STATUS_USER_ACTION_TIMEOUT
               : P4_CTAP_STATUS_OPERATION_DENIED;
}


static bool put_response(const uint8_t credential_id[P4_CRED_ID_LEN],
                         const assert_work_t *work,
                         uint8_t *response,
                         size_t response_cap,
                         size_t *response_len)
{
    p4_cbor_writer_t writer;
    p4_cbor_writer_init(&writer, response, response_cap);
    bool ok = p4_cbor_put_map(&writer, 3) &&
        p4_cbor_put_uint(&writer, 1) &&
        p4_cbor_put_map(&writer, 2) &&
        p4_cbor_put_text(&writer, "id", sizeof("id") - 1) &&
        p4_cbor_put_bytes(&writer, credential_id, P4_CRED_ID_LEN) &&
        p4_cbor_put_text(&writer, "type", sizeof("type") - 1) &&
        p4_cbor_put_text(&writer, "public-key",
                         sizeof("public-key") - 1) &&
        p4_cbor_put_uint(&writer, 2) &&
        p4_cbor_put_bytes(&writer, work->auth_data,
                          sizeof(work->auth_data)) &&
        p4_cbor_put_uint(&writer, 3) &&
        p4_cbor_put_bytes(&writer, work->signature,
                          work->signature_len);
    *response_len = p4_cbor_writer_len(&writer);
    return ok;
}


int p4_ctap_get_assertion(uint32_t cid,
                          const uint8_t *request,
                          size_t request_len,
                          uint8_t *response,
                          size_t response_cap,
                          size_t *response_len)
{
    if (response_len == NULL || response == NULL ||
        (request == NULL && request_len != 0)) {
        return P4_CTAP_ERR_ARG;
    }
    *response_len = 0;
    if (response_cap < ASSERT_RESPONSE_MAX) {
        return P4_CTAP_ERR_SMALL;
    }

    assert_request_t parsed = {0};
    int status = read_request(request, request_len, &parsed);
    if (status != P4_CTAP_STATUS_OK) {
        return status;
    }

    assert_work_t work = {0};
    const uint8_t *credential_id = NULL;
    if (sha256_sum(parsed.rp_id, parsed.rp_id_len,
                   work.rp_hash) != P4_CRYPTO_OK) {
        status = P4_CTAP_STATUS_OTHER;
        goto out;
    }
    status = find_cred(&parsed, work.rp_hash, &credential_id,
                       work.private_scalar);
    if (status != P4_CTAP_STATUS_OK) {
        goto out;
    }

    status = presence_status(cid);
    if (status != P4_CTAP_STATUS_OK) {
        goto out;
    }
    if (press_cancelled(cid)) {
        status = P4_CTAP_STATUS_KEEPALIVE_CANCEL;
        goto out;
    }

    memcpy(work.auth_data, work.rp_hash, sizeof(work.rp_hash));
    work.auth_data[32] = 0x01;
    // zero counter means this MVP has no cloning detection
    memcpy(work.sign_input, work.auth_data, sizeof(work.auth_data));
    memcpy(work.sign_input + sizeof(work.auth_data),
           parsed.client_hash, P4_CRYPTO_SHA256_LEN);
    if (sha256_sum(work.sign_input, sizeof(work.sign_input),
                   work.digest) != P4_CRYPTO_OK) {
        status = P4_CTAP_STATUS_OTHER;
        goto out;
    }
    if (press_cancelled(cid)) {
        status = P4_CTAP_STATUS_KEEPALIVE_CANCEL;
        goto out;
    }

    int sign_error = p256_sign_hash(
        work.private_scalar, work.digest,
        work.signature, sizeof(work.signature), &work.signature_len);
    secret_clear(work.private_scalar, sizeof(work.private_scalar));
    secret_clear(work.sign_input, sizeof(work.sign_input));
    secret_clear(work.digest, sizeof(work.digest));
    if (sign_error != P4_CRYPTO_OK || work.signature_len == 0 ||
        work.signature_len > sizeof(work.signature)) {
        status = P4_CTAP_STATUS_OTHER;
        goto out;
    }
    if (press_cancelled(cid)) {
        status = P4_CTAP_STATUS_KEEPALIVE_CANCEL;
        goto out;
    }

    if (!put_response(credential_id, &work, response,
                      response_cap, response_len)) {
        status = P4_CTAP_STATUS_OTHER;
        goto out;
    }
    if (press_cancelled(cid)) {
        secret_clear(response, *response_len);
        *response_len = 0;
        status = P4_CTAP_STATUS_KEEPALIVE_CANCEL;
        goto out;
    }

out:
    secret_clear(&work, sizeof(work));
    if (status != P4_CTAP_STATUS_OK) {
        *response_len = 0;
    }
    return status;
}
