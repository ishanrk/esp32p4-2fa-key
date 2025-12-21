#include "make_cred_fakes.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "p4_aaguid.h"
#include "p4_cbor.h"
#include "p4_cred.h"
#include "p4_ctap.h"


enum {
    TEST_CID = 0x10203040,
    TEST_AUTH_DATA_LEN = 232,
    TEST_COSE_OFFSET = 155,
    TEST_COSE_LEN = 77,
};


typedef enum {
    TEST_OPTION_NONE = 0,
    TEST_OPTION_RK,
    TEST_OPTION_UV,
} test_option_t;


static void fail(const char *name, int line)
{
    fprintf(stderr, "FAIL %s line %d\n", name, line);
    exit(1);
}

#define CHECK(value) do { if (!(value)) fail(__func__, __LINE__); } while (0)
#define PUT(value) CHECK(value)


static size_t make_request(uint8_t *out,
                           size_t cap,
                           int64_t algorithm,
                           test_option_t option,
                           const uint8_t *exclude,
                           size_t exclude_len)
{
    static const uint8_t client_hash[P4_CRYPTO_SHA256_LEN] = {
        0x11, 0x22, 0x33, 0x44,
    };
    static const uint8_t user_id[] = {0x71, 0x72, 0x73, 0x74};
    size_t pairs = 4 + (exclude != NULL ? 1U : 0U) +
                   (option != TEST_OPTION_NONE ? 1U : 0U);

    p4_cbor_writer_t writer;
    p4_cbor_writer_init(&writer, out, cap);
    PUT(p4_cbor_put_map(&writer, pairs));

    PUT(p4_cbor_put_uint(&writer, 1));
    PUT(p4_cbor_put_bytes(&writer, client_hash, sizeof(client_hash)));

    PUT(p4_cbor_put_uint(&writer, 2));
    PUT(p4_cbor_put_map(&writer, 1));
    PUT(p4_cbor_put_text(&writer, "id", 2));
    PUT(p4_cbor_put_text(&writer, "example.com", 11));

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
    PUT(p4_cbor_put_int(&writer, algorithm));

    if (exclude != NULL) {
        PUT(p4_cbor_put_uint(&writer, 5));
        PUT(p4_cbor_put_array(&writer, 1));
        PUT(p4_cbor_put_map(&writer, 2));
        PUT(p4_cbor_put_text(&writer, "type", 4));
        PUT(p4_cbor_put_text(&writer, "public-key", 10));
        PUT(p4_cbor_put_text(&writer, "id", 2));
        PUT(p4_cbor_put_bytes(&writer, exclude, exclude_len));
    }

    if (option != TEST_OPTION_NONE) {
        const char *name = option == TEST_OPTION_RK ? "rk" : "uv";
        PUT(p4_cbor_put_uint(&writer, 7));
        PUT(p4_cbor_put_map(&writer, 1));
        PUT(p4_cbor_put_text(&writer, name, 2));
        PUT(p4_cbor_put_bool(&writer, true));
    }

    CHECK(p4_cbor_writer_ok(&writer));
    return p4_cbor_writer_len(&writer);
}


static void expect_int(p4_cbor_reader_t *reader, int64_t expected)
{
    int64_t actual = 0;
    CHECK(p4_cbor_get_int(reader, &actual));
    CHECK(actual == expected);
}


static void check_cose(const uint8_t *encoded, size_t len)
{
    p4_cbor_reader_t reader;
    p4_cbor_reader_init(&reader, encoded, len);
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
    CHECK(x_len == P4_CRYPTO_P256_SCALAR_LEN);
    CHECK(memcmp(x, make_fake_x, x_len) == 0);

    expect_int(&reader, -3);
    const uint8_t *y = NULL;
    size_t y_len = 0;
    CHECK(p4_cbor_get_bytes(&reader, &y, &y_len));
    CHECK(y_len == P4_CRYPTO_P256_SCALAR_LEN);
    CHECK(memcmp(y, make_fake_y, y_len) == 0);
    CHECK(p4_cbor_reader_done(&reader));
}


static void check_success_response(const uint8_t *response,
                                   size_t response_len,
                                   uint8_t credential_id[P4_CRED_ID_LEN])
{
    p4_cbor_reader_t reader;
    p4_cbor_reader_init(&reader, response, response_len);
    size_t pairs = 0;
    CHECK(p4_cbor_get_map(&reader, &pairs));
    CHECK(pairs == 3);

    uint64_t key = 0;
    CHECK(p4_cbor_get_uint(&reader, &key) && key == 1);
    const char *format = NULL;
    size_t format_len = 0;
    CHECK(p4_cbor_get_text(&reader, &format, &format_len));
    CHECK(format_len == 4 && memcmp(format, "none", 4) == 0);

    CHECK(p4_cbor_get_uint(&reader, &key) && key == 2);
    const uint8_t *auth_data = NULL;
    size_t auth_data_len = 0;
    CHECK(p4_cbor_get_bytes(&reader, &auth_data, &auth_data_len));
    CHECK(auth_data_len == TEST_AUTH_DATA_LEN);
    CHECK(memcmp(auth_data, make_fake_rp_hash,
                 P4_CRYPTO_SHA256_LEN) == 0);
    CHECK(auth_data[32] == 0x41);
    CHECK(auth_data[33] == 0 && auth_data[34] == 0 &&
          auth_data[35] == 0 && auth_data[36] == 0);
    CHECK(memcmp(auth_data + 37, p4_aaguid, P4_AAGUID_LEN) == 0);
    CHECK(auth_data[53] == 0 && auth_data[54] == P4_CRED_ID_LEN);

    memcpy(credential_id, auth_data + 55, P4_CRED_ID_LEN);
    static const uint8_t header[8] = {
        'P', '4', 'K', '1', 1, 1, 0, 0,
    };
    CHECK(memcmp(credential_id, header, sizeof(header)) == 0);
    check_cose(auth_data + TEST_COSE_OFFSET, TEST_COSE_LEN);

    CHECK(p4_cbor_get_uint(&reader, &key) && key == 3);
    size_t statement_pairs = 1;
    CHECK(p4_cbor_get_map(&reader, &statement_pairs));
    CHECK(statement_pairs == 0);
    CHECK(p4_cbor_reader_done(&reader));
}


static void expect_status(int64_t algorithm,
                          test_option_t option,
                          int expected)
{
    uint8_t request[512];
    request[0] = P4_CTAP_CMD_MAKE_CREDENTIAL;
    size_t request_len = 1 + make_request(
        request + 1, sizeof(request) - 1,
        algorithm, option, NULL, 0);
    uint8_t response[P4_CTAP_MAX_MESSAGE];
    size_t response_len = sizeof(response);
    CHECK(p4_ctap_dispatch(TEST_CID, request, request_len,
                           response, sizeof(response), &response_len) ==
          P4_CTAP_OK);
    CHECK(response_len == 1);
    CHECK(response[0] == expected);
}


int main(void)
{
    make_fakes_reset();

    uint8_t request[512];
    request[0] = P4_CTAP_CMD_MAKE_CREDENTIAL;
    size_t request_len = 1 + make_request(
        request + 1, sizeof(request) - 1,
        -7, TEST_OPTION_NONE, NULL, 0);
    uint8_t response[P4_CTAP_MAX_MESSAGE];
    size_t response_len = 0;
    CHECK(p4_ctap_dispatch(TEST_CID, request, request_len,
                           response, sizeof(response), &response_len) ==
          P4_CTAP_OK);
    CHECK(response_len > 1);
    CHECK(response[0] == P4_CTAP_STATUS_OK);
    CHECK(make_fake_sha_calls == 1);
    CHECK(make_fake_press_calls == 1);
    CHECK(make_fake_key_calls == 1);
    CHECK(make_fake_rand_calls == 1);
    CHECK(make_fake_seal_calls == 1);

    uint8_t credential_id[P4_CRED_ID_LEN];
    check_success_response(response + 1, response_len - 1, credential_id);

    uint8_t opened[P4_CRED_PRIVATE_SCALAR_LEN];
    CHECK(cred_open(make_fake_rp_hash, sizeof(make_fake_rp_hash),
                    credential_id, sizeof(credential_id),
                    opened, sizeof(opened)) == P4_CRED_OK);
    CHECK(memcmp(opened, make_fake_private, sizeof(opened)) == 0);
    uint8_t opened_x[P4_CRYPTO_P256_SCALAR_LEN];
    uint8_t opened_y[P4_CRYPTO_P256_SCALAR_LEN];
    CHECK(p256_pub(opened, opened_x, opened_y) == P4_CRYPTO_OK);
    CHECK(memcmp(opened_x, make_fake_x, sizeof(opened_x)) == 0);
    CHECK(memcmp(opened_y, make_fake_y, sizeof(opened_y)) == 0);
    secret_clear(opened, sizeof(opened));
    secret_clear(opened_x, sizeof(opened_x));
    secret_clear(opened_y, sizeof(opened_y));

    unsigned press_before = make_fake_press_calls;
    unsigned keys_before = make_fake_key_calls;
    unsigned rand_before = make_fake_rand_calls;
    unsigned seals_before = make_fake_seal_calls;
    expect_status(-257, TEST_OPTION_NONE,
                  P4_CTAP_STATUS_UNSUPPORTED_ALGORITHM);
    expect_status(-7, TEST_OPTION_RK,
                  P4_CTAP_STATUS_UNSUPPORTED_OPTION);
    expect_status(-7, TEST_OPTION_UV,
                  P4_CTAP_STATUS_UNSUPPORTED_OPTION);
    CHECK(make_fake_press_calls == press_before);
    CHECK(make_fake_key_calls == keys_before);
    CHECK(make_fake_rand_calls == rand_before);
    CHECK(make_fake_seal_calls == seals_before);

    request[0] = P4_CTAP_CMD_MAKE_CREDENTIAL;
    request_len = 1 + make_request(
        request + 1, sizeof(request) - 1,
        -7, TEST_OPTION_NONE, credential_id, sizeof(credential_id));
    response_len = sizeof(response);
    CHECK(p4_ctap_dispatch(TEST_CID, request, request_len,
                           response, sizeof(response), &response_len) ==
          P4_CTAP_OK);
    CHECK(response_len == 1);
    CHECK(response[0] == P4_CTAP_STATUS_CREDENTIAL_EXCLUDED);
    CHECK(make_fake_press_calls == press_before + 1);
    CHECK(make_fake_key_calls == keys_before);
    CHECK(make_fake_rand_calls == rand_before);
    CHECK(make_fake_seal_calls == seals_before);

    secret_clear(credential_id, sizeof(credential_id));
    secret_clear(response, sizeof(response));
    puts("PASS minimal make credential response and errors");
    return 0;
}
