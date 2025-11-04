#include "p4_cbor.h"
#include "p4_ctap.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>


static void fail(const char *name, int line)
{
    fprintf(stderr, "FAIL %s line %d\n", name, line);
    exit(1);
}

#define CHECK(value) do { if (!(value)) fail(__func__, __LINE__); } while (0)


static void test_writer_and_reader(void)
{
    static const uint8_t expected[] = {
        0xa3,
        0x01, 0x81, 0x68, 'F', 'I', 'D', 'O', '_', '2', '_', '0',
        0x03, 0x43, 0x00, 0x01, 0x02,
        0x04, 0xa2, 0x62, 'r', 'k', 0xf4, 0x62, 'u', 'p', 0xf5,
    };
    uint8_t encoded[64];
    p4_cbor_writer_t writer;
    p4_cbor_writer_init(&writer, encoded, sizeof(encoded));
    CHECK(p4_cbor_put_map(&writer, 3));
    CHECK(p4_cbor_put_uint(&writer, 1));
    CHECK(p4_cbor_put_array(&writer, 1));
    CHECK(p4_cbor_put_text(&writer, "FIDO_2_0", 8));
    CHECK(p4_cbor_put_uint(&writer, 3));
    const uint8_t bytes[] = {0, 1, 2};
    CHECK(p4_cbor_put_bytes(&writer, bytes, sizeof(bytes)));
    CHECK(p4_cbor_put_uint(&writer, 4));
    CHECK(p4_cbor_put_map(&writer, 2));
    CHECK(p4_cbor_put_text(&writer, "rk", 2));
    CHECK(p4_cbor_put_bool(&writer, false));
    CHECK(p4_cbor_put_text(&writer, "up", 2));
    CHECK(p4_cbor_put_bool(&writer, true));
    CHECK(p4_cbor_writer_ok(&writer));
    CHECK(p4_cbor_writer_len(&writer) == sizeof(expected));
    CHECK(memcmp(encoded, expected, sizeof(expected)) == 0);

    p4_cbor_reader_t reader;
    p4_cbor_reader_init(&reader, encoded, sizeof(expected));
    size_t count = 0;
    CHECK(p4_cbor_get_map(&reader, &count) && count == 3);
    uint32_t seen = 0;
    uint64_t key = 0;
    CHECK(p4_cbor_get_uint(&reader, &key) && key == 1);
    CHECK(p4_cbor_known_key_once(&seen, (uint8_t)key));
    CHECK(p4_cbor_get_array(&reader, &count) && count == 1);
    const char *text = NULL;
    size_t len = 0;
    CHECK(p4_cbor_get_text(&reader, &text, &len));
    CHECK(len == 8 && memcmp(text, "FIDO_2_0", len) == 0);
    CHECK(p4_cbor_get_uint(&reader, &key) && key == 3);
    CHECK(p4_cbor_known_key_once(&seen, (uint8_t)key));
    const uint8_t *decoded = NULL;
    CHECK(p4_cbor_get_bytes(&reader, &decoded, &len));
    CHECK(len == sizeof(bytes) && memcmp(decoded, bytes, len) == 0);
    CHECK(p4_cbor_get_uint(&reader, &key) && key == 4);
    CHECK(p4_cbor_known_key_once(&seen, (uint8_t)key));
    CHECK(p4_cbor_get_map(&reader, &count) && count == 2);
    bool value = true;
    CHECK(p4_cbor_get_text(&reader, &text, &len));
    CHECK(len == 2 && memcmp(text, "rk", len) == 0);
    CHECK(p4_cbor_get_bool(&reader, &value) && !value);
    CHECK(p4_cbor_get_text(&reader, &text, &len));
    CHECK(len == 2 && memcmp(text, "up", len) == 0);
    CHECK(p4_cbor_get_bool(&reader, &value) && value);
    CHECK(p4_cbor_reader_done(&reader));
}


static void test_skip_and_duplicate_key(void)
{
    static const uint8_t encoded[] = {
        0xa3,
        0x01, 0xf5,
        0x09, 0x82, 0x41, 0xaa, 0xa1, 0x02, 0x26,
        0x01, 0xf4,
    };
    p4_cbor_reader_t reader;
    p4_cbor_reader_init(&reader, encoded, sizeof(encoded));
    size_t pairs = 0;
    uint64_t key = 0;
    bool value = false;
    uint32_t seen = 0;
    CHECK(p4_cbor_get_map(&reader, &pairs) && pairs == 3);
    CHECK(p4_cbor_get_uint(&reader, &key) && key == 1);
    CHECK(p4_cbor_known_key_once(&seen, (uint8_t)key));
    CHECK(p4_cbor_get_bool(&reader, &value) && value);
    CHECK(p4_cbor_get_uint(&reader, &key) && key == 9);
    CHECK(p4_cbor_skip(&reader));
    CHECK(p4_cbor_get_uint(&reader, &key) && key == 1);
    CHECK(!p4_cbor_known_key_once(&seen, (uint8_t)key));
    CHECK(p4_cbor_get_bool(&reader, &value) && !value);
    CHECK(p4_cbor_reader_done(&reader));
}


static void test_rejects_malformed_bounds(void)
{
    static const uint8_t indefinite[] = {0x9f, 0xff};
    static const uint8_t impossible[] = {0x59, 0x08, 0x01};
    static const uint8_t non_minimal[] = {0x18, 0x17};
    static const uint8_t trailing[] = {0xf5, 0xf4};
    p4_cbor_reader_t reader;
    size_t count = 0;
    p4_cbor_reader_init(&reader, indefinite, sizeof(indefinite));
    CHECK(!p4_cbor_get_array(&reader, &count));
    p4_cbor_reader_init(&reader, impossible, sizeof(impossible));
    const uint8_t *data = NULL;
    size_t len = 0;
    CHECK(!p4_cbor_get_bytes(&reader, &data, &len));
    p4_cbor_reader_init(&reader, non_minimal, sizeof(non_minimal));
    uint64_t integer = 0;
    CHECK(!p4_cbor_get_uint(&reader, &integer));
    p4_cbor_reader_init(&reader, trailing, sizeof(trailing));
    bool value = false;
    CHECK(p4_cbor_get_bool(&reader, &value) && value);
    CHECK(!p4_cbor_reader_done(&reader));

    uint8_t encoded[1];
    p4_cbor_writer_t writer;
    p4_cbor_writer_init(&writer, encoded, sizeof(encoded));
    CHECK(!p4_cbor_put_text(&writer, "x", P4_CBOR_MAX_BYTES + 1U));
    CHECK(!p4_cbor_writer_ok(&writer));
}


static void test_dispatch_default(void)
{
    uint8_t request = P4_CTAP_CMD_MAKE_CREDENTIAL;
    uint8_t response[2] = {0xaa, 0xaa};
    size_t response_len = 99;
    CHECK(p4_ctap_dispatch(&request, 1, response, sizeof(response),
                           &response_len) == P4_CTAP_OK);
    CHECK(response_len == 1);
    CHECK(response[0] == P4_CTAP_STATUS_INVALID_COMMAND);
    CHECK(response[1] == 0xaa);

    response_len = 99;
    CHECK(p4_ctap_dispatch(&request, 1, response, 0, &response_len) ==
          P4_CTAP_ERR_SMALL);
    CHECK(response_len == 0);
}


int main(void)
{
    test_writer_and_reader();
    test_skip_and_duplicate_key();
    test_rejects_malformed_bounds();
    test_dispatch_default();
    puts("PASS minimal cbor and ctap core");
    return 0;
}
