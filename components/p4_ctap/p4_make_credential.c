#include "p4_ctap_priv.h"

#include <stdbool.h>
#include <string.h>

#include "p4_aaguid.h"
#include "p4_cbor.h"
#include "p4_cred.h"
#include "p4_crypto.h"
#include "p4_ctap.h"
#include "p4_press.h"

enum {
    MAKE_COSE_OFFSET = 155,
    MAKE_COSE_LEN = 77,
    MAKE_AUTH_DATA_LEN = 232,
    MAKE_RESPONSE_LEN = 244,
};


typedef struct {
    const uint8_t *id;
    size_t len;
    bool public_key;
} make_desc_t;


typedef struct {
    const uint8_t *rp_id;
    size_t rp_id_len;
    make_desc_t exclude[P4_CTAP_MAX_CREDENTIALS_IN_LIST];
    size_t exclude_count;
    bool es256;
    bool unsupported_option;
} make_request_t;


typedef struct {
    uint8_t rp_hash[P4_CRYPTO_SHA256_LEN];
    uint8_t private_scalar[P4_CRYPTO_P256_SCALAR_LEN];
    uint8_t x[P4_CRYPTO_P256_SCALAR_LEN];
    uint8_t y[P4_CRYPTO_P256_SCALAR_LEN];
    uint8_t credential_id[P4_CRED_ID_LEN];
    uint8_t auth_data[MAKE_AUTH_DATA_LEN];
} make_work_t;


_Static_assert(MAKE_COSE_OFFSET + MAKE_COSE_LEN == MAKE_AUTH_DATA_LEN,
               "make credential auth data size");


static bool text_is(const char *text, size_t len, const char *expected)
{
    size_t expected_len = strlen(expected);
    return len == expected_len && memcmp(text, expected, len) == 0;
}


static int read_rp(p4_cbor_reader_t *reader, make_request_t *request)
{
    size_t pairs = 0;
    if (!p4_cbor_get_map(reader, &pairs)) {
        return P4_CTAP_STATUS_CBOR_UNEXPECTED_TYPE;
    }
    bool have_id = false;
    for (size_t index = 0; index < pairs; index++) {
        const char *key = NULL;
        size_t key_len = 0;
        if (!p4_cbor_get_text(reader, &key, &key_len)) {
            return P4_CTAP_STATUS_CBOR_UNEXPECTED_TYPE;
        }
        if (text_is(key, key_len, "id")) {
            const char *rp_id = NULL;
            if (have_id) {
                return P4_CTAP_STATUS_INVALID_CBOR;
            }
            if (!p4_cbor_get_text(reader, &rp_id,
                                  &request->rp_id_len)) {
                return P4_CTAP_STATUS_CBOR_UNEXPECTED_TYPE;
            }
            if (request->rp_id_len == 0) {
                return P4_CTAP_STATUS_INVALID_PARAMETER;
            }
            request->rp_id = (const uint8_t *)rp_id;
            have_id = true;
        } else if (!p4_cbor_skip(reader)) {
            return P4_CTAP_STATUS_INVALID_CBOR;
        }
    }
    return have_id ? P4_CTAP_STATUS_OK
                   : P4_CTAP_STATUS_MISSING_PARAMETER;
}


static int read_user(p4_cbor_reader_t *reader)
{
    size_t pairs = 0;
    if (!p4_cbor_get_map(reader, &pairs)) {
        return P4_CTAP_STATUS_CBOR_UNEXPECTED_TYPE;
    }
    bool have_id = false;
    for (size_t index = 0; index < pairs; index++) {
        const char *key = NULL;
        size_t key_len = 0;
        if (!p4_cbor_get_text(reader, &key, &key_len)) {
            return P4_CTAP_STATUS_CBOR_UNEXPECTED_TYPE;
        }
        if (text_is(key, key_len, "id")) {
            const uint8_t *id = NULL;
            size_t id_len = 0;
            if (have_id) {
                return P4_CTAP_STATUS_INVALID_CBOR;
            }
            if (!p4_cbor_get_bytes(reader, &id, &id_len)) {
                return P4_CTAP_STATUS_CBOR_UNEXPECTED_TYPE;
            }
            if (id_len == 0) {
                return P4_CTAP_STATUS_INVALID_PARAMETER;
            }
            have_id = true;
        } else if (!p4_cbor_skip(reader)) {
            return P4_CTAP_STATUS_INVALID_CBOR;
        }
    }
    return have_id ? P4_CTAP_STATUS_OK
                   : P4_CTAP_STATUS_MISSING_PARAMETER;
}


static int read_algs(p4_cbor_reader_t *reader, make_request_t *request)
{
    size_t count = 0;
    if (!p4_cbor_get_array(reader, &count)) {
        return P4_CTAP_STATUS_CBOR_UNEXPECTED_TYPE;
    }
    if (count == 0) {
        return P4_CTAP_STATUS_INVALID_PARAMETER;
    }

    for (size_t index = 0; index < count; index++) {
        size_t pairs = 0;
        if (!p4_cbor_get_map(reader, &pairs)) {
            return P4_CTAP_STATUS_CBOR_UNEXPECTED_TYPE;
        }
        bool have_type = false;
        bool have_alg = false;
        bool public_key = false;
        int64_t algorithm = 0;
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
                public_key = text_is(type, type_len, "public-key");
                have_type = true;
            } else if (text_is(key, key_len, "alg")) {
                if (have_alg) {
                    return P4_CTAP_STATUS_INVALID_CBOR;
                }
                if (!p4_cbor_get_int(reader, &algorithm)) {
                    return P4_CTAP_STATUS_CBOR_UNEXPECTED_TYPE;
                }
                have_alg = true;
            } else if (!p4_cbor_skip(reader)) {
                return P4_CTAP_STATUS_INVALID_CBOR;
            }
        }
        if (!have_type || !have_alg) {
            return P4_CTAP_STATUS_MISSING_PARAMETER;
        }
        if (public_key && algorithm == -7) {
            request->es256 = true;
        }
    }
    return P4_CTAP_STATUS_OK;
}


static int read_exclude(p4_cbor_reader_t *reader, make_request_t *request)
{
    size_t count = 0;
    if (!p4_cbor_get_array(reader, &count)) {
        return P4_CTAP_STATUS_CBOR_UNEXPECTED_TYPE;
    }
    if (count > P4_CTAP_MAX_CREDENTIALS_IN_LIST) {
        return P4_CTAP_STATUS_LIMIT_EXCEEDED;
    }
    request->exclude_count = count;

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
                request->exclude[index].public_key =
                    text_is(type, type_len, "public-key");
                have_type = true;
            } else if (text_is(key, key_len, "id")) {
                if (have_id) {
                    return P4_CTAP_STATUS_INVALID_CBOR;
                }
                if (!p4_cbor_get_bytes(
                        reader, &request->exclude[index].id,
                        &request->exclude[index].len)) {
                    return P4_CTAP_STATUS_CBOR_UNEXPECTED_TYPE;
                }
                if (request->exclude[index].len == 0) {
                    return P4_CTAP_STATUS_INVALID_PARAMETER;
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


static int read_options(p4_cbor_reader_t *reader, make_request_t *request)
{
    size_t pairs = 0;
    if (!p4_cbor_get_map(reader, &pairs)) {
        return P4_CTAP_STATUS_CBOR_UNEXPECTED_TYPE;
    }
    bool have_rk = false;
    bool have_uv = false;
    for (size_t index = 0; index < pairs; index++) {
        const char *key = NULL;
        size_t key_len = 0;
        if (!p4_cbor_get_text(reader, &key, &key_len)) {
            return P4_CTAP_STATUS_CBOR_UNEXPECTED_TYPE;
        }
        if (text_is(key, key_len, "rk") || text_is(key, key_len, "uv")) {
            bool is_rk = text_is(key, key_len, "rk");
            bool value = false;
            if (is_rk ? have_rk : have_uv) {
                return P4_CTAP_STATUS_INVALID_CBOR;
            }
            if (!p4_cbor_get_bool(reader, &value)) {
                return P4_CTAP_STATUS_CBOR_UNEXPECTED_TYPE;
            }
            have_rk = have_rk || is_rk;
            have_uv = have_uv || !is_rk;
            request->unsupported_option |= value;
        } else if (!p4_cbor_skip(reader)) {
            return P4_CTAP_STATUS_INVALID_CBOR;
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


static int read_request(const uint8_t *data, size_t len,
                        make_request_t *request)
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
            const uint8_t *client_hash = NULL;
            size_t client_hash_len = 0;
            if (!p4_cbor_get_bytes(
                    &reader, &client_hash, &client_hash_len)) {
                return P4_CTAP_STATUS_CBOR_UNEXPECTED_TYPE;
            }
            if (client_hash_len != P4_CRYPTO_SHA256_LEN) {
                return P4_CTAP_STATUS_INVALID_PARAMETER;
            }
        } else if (key == 2) {
            status = read_rp(&reader, request);
        } else if (key == 3) {
            status = read_user(&reader);
        } else if (key == 4) {
            status = read_algs(&reader, request);
        } else if (key == 5) {
            status = read_exclude(&reader, request);
        } else if (key == 6) {
            status = read_ignored_map(&reader);
        } else if (key == 7) {
            status = read_options(&reader, request);
        } else if (key == 8) {
            const uint8_t *pin = NULL;
            size_t pin_len = 0;
            if (!p4_cbor_get_bytes(&reader, &pin, &pin_len)) {
                status = P4_CTAP_STATUS_CBOR_UNEXPECTED_TYPE;
            } else {
                request->unsupported_option = true;
            }
        } else if (key == 9 || key == 10) {
            uint64_t value = 0;
            if (!p4_cbor_get_uint(&reader, &value)) {
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
    if ((seen & UINT32_C(0x0f)) != UINT32_C(0x0f)) {
        return P4_CTAP_STATUS_MISSING_PARAMETER;
    }
    if (request->unsupported_option) {
        return P4_CTAP_STATUS_UNSUPPORTED_OPTION;
    }
    return request->es256 ? P4_CTAP_STATUS_OK
                          : P4_CTAP_STATUS_UNSUPPORTED_ALGORITHM;
}


static int check_exclude(const make_request_t *request,
                         const uint8_t rp_hash[P4_CRYPTO_SHA256_LEN],
                         bool *excluded,
                         uint8_t private_scalar[P4_CRYPTO_P256_SCALAR_LEN])
{
    *excluded = false;
    for (size_t index = 0; index < request->exclude_count; index++) {
        const make_desc_t *item = &request->exclude[index];
        if (!item->public_key || item->len != P4_CRED_ID_LEN) {
            continue;
        }
        int error = cred_open(rp_hash, P4_CRYPTO_SHA256_LEN,
                              item->id, item->len,
                              private_scalar, P4_CRYPTO_P256_SCALAR_LEN);
        secret_clear(private_scalar, P4_CRYPTO_P256_SCALAR_LEN);
        if (error == P4_CRED_OK) {
            *excluded = true;
        } else if (error != P4_CRED_ERR_MISMATCH) {
            return P4_CTAP_STATUS_OTHER;
        }
    }
    return P4_CTAP_STATUS_OK;
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


static bool put_cose(make_work_t *work)
{
    p4_cbor_writer_t writer;
    p4_cbor_writer_init(&writer,
                        work->auth_data + MAKE_COSE_OFFSET,
                        MAKE_COSE_LEN);
    return p4_cbor_put_map(&writer, 5) &&
           p4_cbor_put_uint(&writer, 1) &&
           p4_cbor_put_uint(&writer, 2) &&
           p4_cbor_put_uint(&writer, 3) &&
           p4_cbor_put_int(&writer, -7) &&
           p4_cbor_put_int(&writer, -1) &&
           p4_cbor_put_uint(&writer, 1) &&
           p4_cbor_put_int(&writer, -2) &&
           p4_cbor_put_bytes(&writer, work->x, sizeof(work->x)) &&
           p4_cbor_put_int(&writer, -3) &&
           p4_cbor_put_bytes(&writer, work->y, sizeof(work->y)) &&
           p4_cbor_writer_len(&writer) == MAKE_COSE_LEN;
}


static bool put_response(const make_work_t *work,
                         uint8_t *response,
                         size_t response_cap,
                         size_t *response_len)
{
    p4_cbor_writer_t writer;
    p4_cbor_writer_init(&writer, response, response_cap);

    // CTAP response fields use integer keys 1 through 3.
    bool ok = p4_cbor_put_map(&writer, 3) &&
        p4_cbor_put_uint(&writer, 1) &&
        p4_cbor_put_text(&writer, "none", sizeof("none") - 1) &&
        p4_cbor_put_uint(&writer, 2) &&
        p4_cbor_put_bytes(&writer, work->auth_data,
                          sizeof(work->auth_data)) &&
        p4_cbor_put_uint(&writer, 3) &&
        p4_cbor_put_map(&writer, 0);
    *response_len = p4_cbor_writer_len(&writer);
    return ok && *response_len == MAKE_RESPONSE_LEN;
}


int p4_ctap_make_credential(uint32_t cid,
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
    if (response_cap < MAKE_RESPONSE_LEN) {
        return P4_CTAP_ERR_SMALL;
    }

    make_request_t parsed = {0};
    int status = read_request(request, request_len, &parsed);
    if (status != P4_CTAP_STATUS_OK) {
        return status;
    }

    make_work_t work = {0};
    if (sha256_sum(parsed.rp_id, parsed.rp_id_len,
                   work.rp_hash) != P4_CRYPTO_OK) {
        status = P4_CTAP_STATUS_OTHER;
        goto out;
    }

    bool excluded = false;
    status = check_exclude(&parsed, work.rp_hash, &excluded,
                           work.private_scalar);
    if (status != P4_CTAP_STATUS_OK) {
        goto out;
    }
    status = presence_status(cid);
    if (status != P4_CTAP_STATUS_OK) {
        goto out;
    }
    if (excluded) {
        status = P4_CTAP_STATUS_CREDENTIAL_EXCLUDED;
        goto out;
    }
    if (press_cancelled(cid)) {
        status = P4_CTAP_STATUS_KEEPALIVE_CANCEL;
        goto out;
    }

    if (p256_make(work.private_scalar, work.x, work.y) != P4_CRYPTO_OK) {
        status = P4_CTAP_STATUS_OTHER;
        goto out;
    }
    if (press_cancelled(cid)) {
        status = P4_CTAP_STATUS_KEEPALIVE_CANCEL;
        goto out;
    }
    int wrap_error = cred_wrap(
        work.rp_hash, sizeof(work.rp_hash),
        work.private_scalar, sizeof(work.private_scalar),
        work.credential_id, sizeof(work.credential_id));
    secret_clear(work.private_scalar, sizeof(work.private_scalar));
    if (wrap_error != P4_CRED_OK) {
        status = P4_CTAP_STATUS_OTHER;
        goto out;
    }
    if (press_cancelled(cid)) {
        status = P4_CTAP_STATUS_KEEPALIVE_CANCEL;
        goto out;
    }

    memcpy(work.auth_data, work.rp_hash, sizeof(work.rp_hash));
    work.auth_data[32] = 0x41;
    memcpy(work.auth_data + 37, p4_aaguid, P4_AAGUID_LEN);
    work.auth_data[53] = (uint8_t)(P4_CRED_ID_LEN >> 8);
    work.auth_data[54] = (uint8_t)P4_CRED_ID_LEN;
    memcpy(work.auth_data + 55,
           work.credential_id, sizeof(work.credential_id));
    if (!put_cose(&work) ||
        !put_response(&work, response, response_cap, response_len)) {
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
