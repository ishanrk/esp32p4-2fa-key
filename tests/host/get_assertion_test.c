#include "get_assertion_fakes.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "p4_cbor.h"
#include "p4_cred.h"
#include "p4_ctap.h"
#include "p4_press.h"


enum {
    TEST_CID = 0x10203040,
    TEST_MAKE_AUTH_DATA_LEN = 232,
    TEST_MAKE_COSE_OFFSET = 155,
    TEST_ASSERT_AUTH_DATA_LEN = 37,
};


static const char s_rp_id[] = "example.com";
static const uint8_t s_client_hash[P4_CRYPTO_SHA256_LEN] = {
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x08,
    0x19, 0x2a, 0x3b, 0x4c, 0x5d, 0x6e, 0x7f, 0x10,
    0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x07, 0x18,
    0x29, 0x3a, 0x4b, 0x5c, 0x6d, 0x7e, 0x0f, 0x20,
};


typedef struct {
    uint8_t credential_id[P4_CRED_ID_LEN];
    uint8_t x[P4_CRYPTO_P256_SCALAR_LEN];
    uint8_t y[P4_CRYPTO_P256_SCALAR_LEN];
} registration_t;


static void fail(const char *name, int line)
{
    fprintf(stderr, "FAIL %s line %d\n", name, line);
    exit(1);
}

#define CHECK(value) do { if (!(value)) fail(__func__, __LINE__); } while (0)
#define PUT(value) CHECK(value)


static size_t make_credential_request(uint8_t *out, size_t cap)
{
    static const uint8_t user_id[] = {0x71, 0x72, 0x73, 0x74};
    p4_cbor_writer_t writer;
    p4_cbor_writer_init(&writer, out, cap);
    PUT(p4_cbor_put_map(&writer, 4));

    PUT(p4_cbor_put_uint(&writer, 1));
    PUT(p4_cbor_put_bytes(&writer, s_client_hash,
                          sizeof(s_client_hash)));

    PUT(p4_cbor_put_uint(&writer, 2));
    PUT(p4_cbor_put_map(&writer, 1));
    PUT(p4_cbor_put_text(&writer, "id", 2));
    PUT(p4_cbor_put_text(&writer, s_rp_id, sizeof(s_rp_id) - 1));

    PUT(p4_cbor_put_uint(&writer, 3));
    PUT(p4_cbor_put_map(&writer, 1));
    PUT(p4_cbor_put_text(&writer, "id", 2));
    PUT(p4_cbor_put_bytes(&writer, user_id, sizeof(user_id)));

    PUT(p4_cbor_put_uint(&writer, 4));
    PUT(p4_cbor_put_array(&writer, 1));
    PUT(p4_cbor_put_map(&writer, 2));
    PUT(p4_cbor_put_text(&writer, "type", 4));
    PUT(p4_cbor_put_text(&writer, "public-key", 10));
    PUT(p4_cbor_put_text(&writer, "alg", 3));
    PUT(p4_cbor_put_int(&writer, -7));

    CHECK(p4_cbor_writer_ok(&writer));
    return p4_cbor_writer_len(&writer);
}


static bool text_is(const char *text, size_t len, const char *expected)
{
    return len == strlen(expected) && memcmp(text, expected, len) == 0;
}


static void expect_int(p4_cbor_reader_t *reader, int64_t expected)
{
    int64_t actual = 0;
    CHECK(p4_cbor_get_int(reader, &actual));
    CHECK(actual == expected);
}


static void read_make_cose(const uint8_t *encoded,
                           size_t encoded_len,
                           registration_t *registration)
{
    p4_cbor_reader_t reader;
    p4_cbor_reader_init(&reader, encoded, encoded_len);
    size_t pairs = 0;
    CHECK(p4_cbor_get_map(&reader, &pairs));
    CHECK(pairs == 5);

    expect_int(&reader, 1);
    expect_int(&reader, 2);
    expect_int(&reader, 3);
    expect_int(&reader, -7);
    expect_int(&reader, -1);
    expect_int(&reader, 1);

    expect_int(&reader, -2);
    const uint8_t *x = NULL;
    size_t x_len = 0;
    CHECK(p4_cbor_get_bytes(&reader, &x, &x_len));
    CHECK(x_len == sizeof(registration->x));
    memcpy(registration->x, x, x_len);

    expect_int(&reader, -3);
    const uint8_t *y = NULL;
    size_t y_len = 0;
    CHECK(p4_cbor_get_bytes(&reader, &y, &y_len));
    CHECK(y_len == sizeof(registration->y));
    memcpy(registration->y, y, y_len);
    CHECK(p4_cbor_reader_done(&reader));
    CHECK(memcmp(registration->x, assert_fake_x,
                 sizeof(registration->x)) == 0);
    CHECK(memcmp(registration->y, assert_fake_y,
                 sizeof(registration->y)) == 0);
}


static void run_make_credential(registration_t *registration)
{
    uint8_t request[512];
    request[0] = P4_CTAP_CMD_MAKE_CREDENTIAL;
    size_t request_len = 1 + make_credential_request(
        request + 1, sizeof(request) - 1);
    uint8_t response[P4_CTAP_MAX_MESSAGE] = {0};
    size_t response_len = 0;
    CHECK(p4_ctap_dispatch(TEST_CID, request, request_len,
                           response, sizeof(response), &response_len) ==
          P4_CTAP_OK);
    CHECK(response_len > 1);
    CHECK(response[0] == P4_CTAP_STATUS_OK);

    p4_cbor_reader_t reader;
    p4_cbor_reader_init(&reader, response + 1, response_len - 1);
    size_t pairs = 0;
    CHECK(p4_cbor_get_map(&reader, &pairs));
    CHECK(pairs == 3);

    uint64_t key = 0;
    CHECK(p4_cbor_get_uint(&reader, &key) && key == 1);
    const char *format = NULL;
    size_t format_len = 0;
    CHECK(p4_cbor_get_text(&reader, &format, &format_len));
    CHECK(text_is(format, format_len, "none"));

    CHECK(p4_cbor_get_uint(&reader, &key) && key == 2);
    const uint8_t *auth_data = NULL;
    size_t auth_data_len = 0;
    CHECK(p4_cbor_get_bytes(&reader, &auth_data, &auth_data_len));
    CHECK(auth_data_len == TEST_MAKE_AUTH_DATA_LEN);
    CHECK(auth_data[53] == 0 && auth_data[54] == P4_CRED_ID_LEN);
    memcpy(registration->credential_id, auth_data + 55,
           sizeof(registration->credential_id));
    read_make_cose(auth_data + TEST_MAKE_COSE_OFFSET,
                   auth_data_len - TEST_MAKE_COSE_OFFSET,
                   registration);

    CHECK(p4_cbor_get_uint(&reader, &key) && key == 3);
    size_t statement_pairs = 1;
    CHECK(p4_cbor_get_map(&reader, &statement_pairs));
    CHECK(statement_pairs == 0);
    CHECK(p4_cbor_reader_done(&reader));
}


static size_t assertion_request(uint8_t *out,
                                size_t cap,
                                const char *rp_id,
                                const uint8_t client_hash[
                                    P4_CRYPTO_SHA256_LEN],
                                const uint8_t *credential_id,
                                size_t credential_id_len)
{
    out[0] = P4_CTAP_CMD_GET_ASSERTION;
    p4_cbor_writer_t writer;
    p4_cbor_writer_init(&writer, out + 1, cap - 1);
    PUT(p4_cbor_put_map(&writer, 3));

    PUT(p4_cbor_put_uint(&writer, 1));
    PUT(p4_cbor_put_text(&writer, rp_id, strlen(rp_id)));

    PUT(p4_cbor_put_uint(&writer, 2));
    PUT(p4_cbor_put_bytes(&writer, client_hash,
                          P4_CRYPTO_SHA256_LEN));

    PUT(p4_cbor_put_uint(&writer, 3));
    PUT(p4_cbor_put_array(&writer, 1));
    PUT(p4_cbor_put_map(&writer, 2));
    PUT(p4_cbor_put_text(&writer, "type", 4));
    PUT(p4_cbor_put_text(&writer, "public-key", 10));
    PUT(p4_cbor_put_text(&writer, "id", 2));
    PUT(p4_cbor_put_bytes(&writer, credential_id,
                          credential_id_len));

    CHECK(p4_cbor_writer_ok(&writer));
    return p4_cbor_writer_len(&writer) + 1;
}


static int run_assertion(const char *rp_id,
                         const uint8_t client_hash[P4_CRYPTO_SHA256_LEN],
                         const uint8_t *credential_id,
                         size_t credential_id_len,
                         uint8_t *response,
                         size_t *response_len)
{
    uint8_t request[256];
    size_t request_len = assertion_request(
        request, sizeof(request), rp_id, client_hash,
        credential_id, credential_id_len);
    *response_len = 0;
    CHECK(p4_ctap_dispatch(TEST_CID, request, request_len,
                           response, P4_CTAP_MAX_MESSAGE,
                           response_len) == P4_CTAP_OK);
    CHECK(*response_len != 0);
    return response[0];
}


static void read_credential(p4_cbor_reader_t *reader,
                            const uint8_t expected[P4_CRED_ID_LEN])
{
    size_t pairs = 0;
    CHECK(p4_cbor_get_map(reader, &pairs));
    CHECK(pairs == 2);
    bool have_id = false;
    bool have_type = false;
    for (size_t index = 0; index < pairs; index++) {
        const char *key = NULL;
        size_t key_len = 0;
        CHECK(p4_cbor_get_text(reader, &key, &key_len));
        if (text_is(key, key_len, "id")) {
            const uint8_t *id = NULL;
            size_t id_len = 0;
            CHECK(!have_id);
            CHECK(p4_cbor_get_bytes(reader, &id, &id_len));
            CHECK(id_len == P4_CRED_ID_LEN);
            CHECK(memcmp(id, expected, id_len) == 0);
            have_id = true;
        } else if (text_is(key, key_len, "type")) {
            const char *type = NULL;
            size_t type_len = 0;
            CHECK(!have_type);
            CHECK(p4_cbor_get_text(reader, &type, &type_len));
            CHECK(text_is(type, type_len, "public-key"));
            have_type = true;
        } else {
            CHECK(false);
        }
    }
    CHECK(have_id && have_type);
}


static void read_assertion(const uint8_t *response,
                           size_t response_len,
                           const registration_t *registration,
                           const uint8_t rp_hash[P4_CRYPTO_SHA256_LEN],
                           uint8_t auth_data[TEST_ASSERT_AUTH_DATA_LEN],
                           uint8_t signature[P4_CRYPTO_P256_DER_MAX],
                           size_t *signature_len)
{
    CHECK(response_len > 1 && response[0] == P4_CTAP_STATUS_OK);
    p4_cbor_reader_t reader;
    p4_cbor_reader_init(&reader, response + 1, response_len - 1);
    size_t pairs = 0;
    CHECK(p4_cbor_get_map(&reader, &pairs));
    CHECK(pairs == 3);

    bool have_credential = false;
    bool have_auth_data = false;
    bool have_signature = false;
    for (size_t index = 0; index < pairs; index++) {
        uint64_t key = 0;
        CHECK(p4_cbor_get_uint(&reader, &key));
        if (key == 1) {
            CHECK(!have_credential);
            read_credential(&reader, registration->credential_id);
            have_credential = true;
        } else if (key == 2) {
            const uint8_t *encoded = NULL;
            size_t len = 0;
            CHECK(!have_auth_data);
            CHECK(p4_cbor_get_bytes(&reader, &encoded, &len));
            CHECK(len == TEST_ASSERT_AUTH_DATA_LEN);
            memcpy(auth_data, encoded, len);
            have_auth_data = true;
        } else if (key == 3) {
            const uint8_t *encoded = NULL;
            size_t len = 0;
            CHECK(!have_signature);
            CHECK(p4_cbor_get_bytes(&reader, &encoded, &len));
            CHECK(len <= P4_CRYPTO_P256_DER_MAX);
            memcpy(signature, encoded, len);
            *signature_len = len;
            have_signature = true;
        } else {
            CHECK(false);
        }
    }
    CHECK(have_credential && have_auth_data && have_signature);
    CHECK(p4_cbor_reader_done(&reader));
    CHECK(memcmp(auth_data, rp_hash, P4_CRYPTO_SHA256_LEN) == 0);
    CHECK(auth_data[32] == 0x01);
    CHECK(auth_data[33] == 0 && auth_data[34] == 0 &&
          auth_data[35] == 0 && auth_data[36] == 0);
}


static void print_hex(const char *label, const uint8_t *data, size_t len)
{
    printf("%s ", label);
    for (size_t index = 0; index < len; index++) {
        printf("%02x", data[index]);
    }
    putchar('\n');
}


int main(void)
{
    assert_fakes_reset();

    registration_t registration = {0};
    run_make_credential(&registration);

    uint8_t rp_hash[P4_CRYPTO_SHA256_LEN] = {0};
    assert_fake_hash((const uint8_t *)s_rp_id,
                     sizeof(s_rp_id) - 1, rp_hash);
    uint8_t response[P4_CTAP_MAX_MESSAGE] = {0};
    size_t response_len = 0;

    unsigned press_before = assert_fake_press_calls;
    unsigned sign_before = assert_fake_sign_calls;
    CHECK(run_assertion("wrong.example", s_client_hash,
                        registration.credential_id,
                        sizeof(registration.credential_id),
                        response, &response_len) ==
          P4_CTAP_STATUS_NO_CREDENTIALS);
    CHECK(response_len == 1);
    CHECK(assert_fake_press_calls == press_before);
    CHECK(assert_fake_sign_calls == sign_before);

    uint8_t tampered[P4_CRED_ID_LEN];
    memcpy(tampered, registration.credential_id, sizeof(tampered));
    tampered[60] ^= 0x80;
    CHECK(run_assertion(s_rp_id, s_client_hash,
                        tampered, sizeof(tampered),
                        response, &response_len) ==
          P4_CTAP_STATUS_NO_CREDENTIALS);
    CHECK(response_len == 1);
    CHECK(assert_fake_press_calls == press_before);
    CHECK(assert_fake_sign_calls == sign_before);

    assert_fake_set_press_result(P4_PRESS_TIMEOUT);
    CHECK(run_assertion(s_rp_id, s_client_hash,
                        registration.credential_id,
                        sizeof(registration.credential_id),
                        response, &response_len) ==
          P4_CTAP_STATUS_USER_ACTION_TIMEOUT);
    CHECK(response_len == 1);
    CHECK(assert_fake_press_calls == press_before + 1);
    CHECK(assert_fake_sign_calls == sign_before);

    assert_fake_set_press_result(P4_PRESS_OK);
    CHECK(run_assertion(s_rp_id, s_client_hash,
                        registration.credential_id,
                        sizeof(registration.credential_id),
                        response, &response_len) == P4_CTAP_STATUS_OK);
    CHECK(assert_fake_press_calls == press_before + 2);
    CHECK(assert_fake_sign_calls == sign_before + 1);

    uint8_t auth_data[TEST_ASSERT_AUTH_DATA_LEN] = {0};
    uint8_t signature[P4_CRYPTO_P256_DER_MAX] = {0};
    size_t signature_len = 0;
    read_assertion(response, response_len, &registration, rp_hash,
                   auth_data, signature, &signature_len);

    print_hex("PUBLIC_X", registration.x, sizeof(registration.x));
    print_hex("PUBLIC_Y", registration.y, sizeof(registration.y));
    print_hex("AUTH_DATA", auth_data, sizeof(auth_data));
    print_hex("SIGNATURE", signature, signature_len);
    puts("PASS dispatcher make credential and get assertion");

    secret_clear(&registration, sizeof(registration));
    secret_clear(rp_hash, sizeof(rp_hash));
    secret_clear(response, sizeof(response));
    secret_clear(tampered, sizeof(tampered));
    secret_clear(auth_data, sizeof(auth_data));
    secret_clear(signature, sizeof(signature));
    return 0;
}
