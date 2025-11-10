#include "p4_cbor.h"
#include "p4_ctap.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>


static const uint8_t s_expected[] = {
    0x00, 0xa8,
    0x01, 0x81, 0x68, 'F', 'I', 'D', 'O', '_', '2', '_', '0',
    0x03, 0x50,
    0xe9, 0xc0, 0x17, 0x41, 0x4d, 0x6d, 0x4a, 0x49,
    0x9e, 0x89, 0xb4, 0xb3, 0x6f, 0x5c, 0x21, 0xa2,
    0x04, 0xa2,
    0x62, 'r', 'k', 0xf4,
    0x62, 'u', 'p', 0xf5,
    0x05, 0x19, 0x08, 0x00,
    0x07, 0x10,
    0x08, 0x18, 0x80,
    0x09, 0x81, 0x63, 'u', 's', 'b',
    0x0a, 0x81, 0xa2,
    0x63, 'a', 'l', 'g', 0x26,
    0x64, 't', 'y', 'p', 'e',
    0x6a, 'p', 'u', 'b', 'l', 'i', 'c', '-', 'k', 'e', 'y',
};


static void fail(const char *name, int line)
{
    fprintf(stderr, "FAIL %s line %d\n", name, line);
    exit(1);
}

#define CHECK(value) do { if (!(value)) fail(__func__, __LINE__); } while (0)


static void check_text(p4_cbor_reader_t *reader, const char *expected)
{
    const char *text = NULL;
    size_t len = 0;
    CHECK(p4_cbor_get_text(reader, &text, &len));
    CHECK(len == strlen(expected));
    CHECK(memcmp(text, expected, len) == 0);
}


static void check_key(p4_cbor_reader_t *reader, uint32_t *seen,
                      uint8_t expected)
{
    uint64_t key = 0;
    CHECK(p4_cbor_get_uint(reader, &key));
    CHECK(key == expected);
    CHECK(p4_cbor_known_key_once(seen, (uint8_t)key));
}


static void check_get_info_semantics(const uint8_t *response,
                                     size_t response_len)
{
    CHECK(response_len == sizeof(s_expected));
    CHECK(response[0] == P4_CTAP_STATUS_OK);

    p4_cbor_reader_t reader;
    p4_cbor_reader_init(&reader, response + 1, response_len - 1);
    size_t count = 0;
    CHECK(p4_cbor_get_map(&reader, &count) && count == 8);
    uint32_t seen = 0;

    check_key(&reader, &seen, 1);
    CHECK(p4_cbor_get_array(&reader, &count) && count == 1);
    check_text(&reader, "FIDO_2_0");

    check_key(&reader, &seen, 3);
    const uint8_t *aaguid = NULL;
    size_t aaguid_len = 0;
    CHECK(p4_cbor_get_bytes(&reader, &aaguid, &aaguid_len));
    CHECK(aaguid_len == 16);
    CHECK(memcmp(aaguid, &s_expected[15], aaguid_len) == 0);

    check_key(&reader, &seen, 4);
    CHECK(p4_cbor_get_map(&reader, &count) && count == 2);
    check_text(&reader, "rk");
    bool option = true;
    CHECK(p4_cbor_get_bool(&reader, &option) && !option);
    check_text(&reader, "up");
    CHECK(p4_cbor_get_bool(&reader, &option) && option);

    uint64_t value = 0;
    check_key(&reader, &seen, 5);
    CHECK(p4_cbor_get_uint(&reader, &value) && value == 2048);
    check_key(&reader, &seen, 7);
    CHECK(p4_cbor_get_uint(&reader, &value) && value == 16);
    check_key(&reader, &seen, 8);
    CHECK(p4_cbor_get_uint(&reader, &value) && value == 128);

    check_key(&reader, &seen, 9);
    CHECK(p4_cbor_get_array(&reader, &count) && count == 1);
    check_text(&reader, "usb");

    check_key(&reader, &seen, 10);
    CHECK(p4_cbor_get_array(&reader, &count) && count == 1);
    CHECK(p4_cbor_get_map(&reader, &count) && count == 2);
    check_text(&reader, "alg");
    int64_t algorithm = 0;
    CHECK(p4_cbor_get_int(&reader, &algorithm) && algorithm == -7);
    check_text(&reader, "type");
    check_text(&reader, "public-key");

    CHECK(seen == 0x000003ddU);
    CHECK(p4_cbor_reader_done(&reader));
}


static void test_get_info_exact_and_repeated(void)
{
    const uint8_t request[] = {P4_CTAP_CMD_GET_INFO};
    uint8_t response[128];
    for (size_t attempt = 0; attempt < 5; attempt++) {
        memset(response, 0xaa, sizeof(response));
        size_t response_len = 0;
        CHECK(p4_ctap_dispatch(request, sizeof(request),
                               response, sizeof(response),
                               &response_len) == P4_CTAP_OK);
        CHECK(response_len == sizeof(s_expected));
        CHECK(memcmp(response, s_expected, sizeof(s_expected)) == 0);
        check_get_info_semantics(response, response_len);
    }
}


static void test_dispatch_errors_and_recovery(void)
{
    uint8_t response[128] = {0};
    size_t response_len = 0;
    const uint8_t malformed[] = {P4_CTAP_CMD_GET_INFO, 0xff};
    CHECK(p4_ctap_dispatch(malformed, sizeof(malformed),
                           response, sizeof(response),
                           &response_len) == P4_CTAP_OK);
    CHECK(response_len == 1 &&
          response[0] == P4_CTAP_STATUS_INVALID_CBOR);

    const uint8_t valid[] = {P4_CTAP_CMD_GET_INFO};
    CHECK(p4_ctap_dispatch(valid, sizeof(valid),
                           response, sizeof(response),
                           &response_len) == P4_CTAP_OK);
    CHECK(response_len == sizeof(s_expected));
    CHECK(memcmp(response, s_expected, sizeof(s_expected)) == 0);

    const uint8_t unsupported[] = {P4_CTAP_CMD_MAKE_CREDENTIAL};
    CHECK(p4_ctap_dispatch(unsupported, sizeof(unsupported),
                           response, sizeof(response),
                           &response_len) == P4_CTAP_OK);
    CHECK(response_len == 1 &&
          response[0] == P4_CTAP_STATUS_INVALID_COMMAND);

    CHECK(p4_ctap_dispatch(NULL, 0, response, sizeof(response),
                           &response_len) == P4_CTAP_OK);
    CHECK(response_len == 1 &&
          response[0] == P4_CTAP_STATUS_INVALID_LENGTH);

    CHECK(p4_ctap_dispatch(valid, sizeof(valid),
                           response, sizeof(s_expected) - 1,
                           &response_len) == P4_CTAP_ERR_SMALL);
    CHECK(response_len == 0);

    static uint8_t larger_than_protocol[P4_CTAP_MAX_MESSAGE + 32];
    CHECK(p4_ctap_dispatch(valid, sizeof(valid), larger_than_protocol,
                           sizeof(larger_than_protocol), &response_len) ==
          P4_CTAP_OK);
    CHECK(response_len == sizeof(s_expected));
    CHECK(memcmp(larger_than_protocol, s_expected, sizeof(s_expected)) == 0);
}


int main(void)
{
    test_get_info_exact_and_repeated();
    test_dispatch_errors_and_recovery();
    puts("PASS minimal authenticator get info");
    return 0;
}
