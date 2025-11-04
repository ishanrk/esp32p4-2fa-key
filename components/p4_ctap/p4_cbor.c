#include "p4_cbor.h"

#include <limits.h>
#include <string.h>


static bool writer_add(p4_cbor_writer_t *writer,
                       const void *data,
                       size_t len)
{
    if (writer == NULL || writer->failed ||
        writer->len > writer->cap ||
        len > writer->cap - writer->len ||
        (data == NULL && len != 0)) {
        if (writer != NULL) {
            writer->failed = true;
        }
        return false;
    }
    if (len != 0) {
        memcpy(&writer->data[writer->len], data, len);
    }
    writer->len += len;
    return true;
}


static bool writer_head(p4_cbor_writer_t *writer,
                        uint8_t major,
                        uint64_t value)
{
    uint8_t encoded[9];
    size_t len = 1;
    encoded[0] = (uint8_t)(major << 5);
    if (value < 24) {
        encoded[0] |= (uint8_t)value;
    } else if (value <= UINT8_MAX) {
        encoded[0] |= 24;
        encoded[1] = (uint8_t)value;
        len = 2;
    } else if (value <= UINT16_MAX) {
        encoded[0] |= 25;
        encoded[1] = (uint8_t)(value >> 8);
        encoded[2] = (uint8_t)value;
        len = 3;
    } else if (value <= UINT32_MAX) {
        encoded[0] |= 26;
        for (size_t i = 0; i < 4; i++) {
            encoded[1 + i] = (uint8_t)(value >> (24 - i * 8));
        }
        len = 5;
    } else {
        encoded[0] |= 27;
        for (size_t i = 0; i < 8; i++) {
            encoded[1 + i] = (uint8_t)(value >> (56 - i * 8));
        }
        len = 9;
    }
    return writer_add(writer, encoded, len);
}


void p4_cbor_writer_init(p4_cbor_writer_t *writer,
                         uint8_t *data,
                         size_t cap)
{
    if (writer == NULL) {
        return;
    }
    writer->data = data;
    writer->cap = cap;
    writer->len = 0;
    writer->failed = (data == NULL && cap != 0) || cap > P4_CBOR_MAX_BYTES;
}


bool p4_cbor_put_map(p4_cbor_writer_t *writer, size_t pairs)
{
    if (pairs > P4_CBOR_MAX_CONTAINER_ITEMS) {
        if (writer != NULL) {
            writer->failed = true;
        }
        return false;
    }
    return writer_head(writer, 5, pairs);
}


bool p4_cbor_put_array(p4_cbor_writer_t *writer, size_t items)
{
    if (items > P4_CBOR_MAX_CONTAINER_ITEMS) {
        if (writer != NULL) {
            writer->failed = true;
        }
        return false;
    }
    return writer_head(writer, 4, items);
}


bool p4_cbor_put_uint(p4_cbor_writer_t *writer, uint64_t value)
{
    return writer_head(writer, 0, value);
}


bool p4_cbor_put_int(p4_cbor_writer_t *writer, int64_t value)
{
    if (value >= 0) {
        return writer_head(writer, 0, (uint64_t)value);
    }
    return writer_head(writer, 1, (uint64_t)(-(value + 1)));
}


bool p4_cbor_put_bytes(p4_cbor_writer_t *writer,
                       const uint8_t *data,
                       size_t len)
{
    if (len > P4_CBOR_MAX_BYTES) {
        if (writer != NULL) {
            writer->failed = true;
        }
        return false;
    }
    return writer_head(writer, 2, len) && writer_add(writer, data, len);
}


bool p4_cbor_put_text(p4_cbor_writer_t *writer,
                      const char *text,
                      size_t len)
{
    if (len > P4_CBOR_MAX_BYTES) {
        if (writer != NULL) {
            writer->failed = true;
        }
        return false;
    }
    return writer_head(writer, 3, len) && writer_add(writer, text, len);
}


bool p4_cbor_put_bool(p4_cbor_writer_t *writer, bool value)
{
    uint8_t encoded = value ? 0xf5 : 0xf4;
    return writer_add(writer, &encoded, 1);
}


bool p4_cbor_writer_ok(const p4_cbor_writer_t *writer)
{
    return writer != NULL && !writer->failed;
}


size_t p4_cbor_writer_len(const p4_cbor_writer_t *writer)
{
    return p4_cbor_writer_ok(writer) ? writer->len : 0;
}


static bool reader_take(p4_cbor_reader_t *reader,
                        const uint8_t **data,
                        size_t len)
{
    if (reader == NULL || reader->failed || reader->offset > reader->len ||
        len > reader->len - reader->offset) {
        if (reader != NULL) {
            reader->failed = true;
        }
        return false;
    }
    if (data != NULL) {
        *data = reader->data == NULL ? NULL : reader->data + reader->offset;
    }
    reader->offset += len;
    return true;
}


static bool reader_head(p4_cbor_reader_t *reader,
                        uint8_t *major,
                        uint64_t *value)
{
    const uint8_t *first;
    if (major == NULL || value == NULL || !reader_take(reader, &first, 1)) {
        return false;
    }

    *major = first[0] >> 5;
    uint8_t additional = first[0] & 0x1f;
    if (additional < 24) {
        *value = additional;
        return true;
    }
    size_t bytes;
    if (additional == 24) {
        bytes = 1;
    } else if (additional == 25) {
        bytes = 2;
    } else if (additional == 26) {
        bytes = 4;
    } else if (additional == 27) {
        bytes = 8;
    } else {
        reader->failed = true;
        return false;
    }

    const uint8_t *encoded;
    if (!reader_take(reader, &encoded, bytes)) {
        return false;
    }
    uint64_t decoded = 0;
    for (size_t i = 0; i < bytes; i++) {
        decoded = (decoded << 8) | encoded[i];
    }
    if ((bytes == 1 && decoded < 24) ||
        (bytes == 2 && decoded <= UINT8_MAX) ||
        (bytes == 4 && decoded <= UINT16_MAX) ||
        (bytes == 8 && decoded <= UINT32_MAX)) {
        reader->failed = true;
        return false;
    }
    *value = decoded;
    return true;
}


static bool reader_container(p4_cbor_reader_t *reader,
                             uint8_t expected_major,
                             size_t *count)
{
    uint8_t major;
    uint64_t value;
    if (count == NULL || !reader_head(reader, &major, &value) ||
        major != expected_major || value > P4_CBOR_MAX_CONTAINER_ITEMS) {
        if (reader != NULL) {
            reader->failed = true;
        }
        return false;
    }
    *count = (size_t)value;
    return true;
}


static bool reader_data(p4_cbor_reader_t *reader,
                        uint8_t expected_major,
                        const uint8_t **data,
                        size_t *len)
{
    uint8_t major;
    uint64_t value;
    if (data == NULL || len == NULL ||
        !reader_head(reader, &major, &value) || major != expected_major ||
        value > P4_CBOR_MAX_BYTES) {
        if (reader != NULL) {
            reader->failed = true;
        }
        return false;
    }
    *len = (size_t)value;
    return reader_take(reader, data, *len);
}


void p4_cbor_reader_init(p4_cbor_reader_t *reader,
                         const uint8_t *data,
                         size_t len)
{
    if (reader == NULL) {
        return;
    }
    reader->data = data;
    reader->len = len;
    reader->offset = 0;
    reader->failed = (data == NULL && len != 0) || len > P4_CBOR_MAX_BYTES;
}


bool p4_cbor_get_map(p4_cbor_reader_t *reader, size_t *pairs)
{
    return reader_container(reader, 5, pairs);
}


bool p4_cbor_get_array(p4_cbor_reader_t *reader, size_t *items)
{
    return reader_container(reader, 4, items);
}


bool p4_cbor_get_uint(p4_cbor_reader_t *reader, uint64_t *value)
{
    uint8_t major;
    if (value == NULL || !reader_head(reader, &major, value) || major != 0) {
        if (reader != NULL) {
            reader->failed = true;
        }
        return false;
    }
    return true;
}


bool p4_cbor_get_int(p4_cbor_reader_t *reader, int64_t *value)
{
    uint8_t major;
    uint64_t encoded;
    if (value == NULL || !reader_head(reader, &major, &encoded) ||
        (major != 0 && major != 1) ||
        (major == 0 && encoded > INT64_MAX) ||
        (major == 1 && encoded > (uint64_t)INT64_MAX)) {
        if (reader != NULL) {
            reader->failed = true;
        }
        return false;
    }
    *value = major == 0 ? (int64_t)encoded : -1 - (int64_t)encoded;
    return true;
}


bool p4_cbor_get_bytes(p4_cbor_reader_t *reader,
                       const uint8_t **data,
                       size_t *len)
{
    return reader_data(reader, 2, data, len);
}


bool p4_cbor_get_text(p4_cbor_reader_t *reader,
                      const char **text,
                      size_t *len)
{
    const uint8_t *encoded = NULL;
    if (text == NULL || !reader_data(reader, 3, &encoded, len)) {
        return false;
    }
    *text = (const char *)encoded;
    return true;
}


bool p4_cbor_get_bool(p4_cbor_reader_t *reader, bool *value)
{
    uint8_t major;
    uint64_t encoded;
    if (value == NULL || !reader_head(reader, &major, &encoded) ||
        major != 7 || (encoded != 20 && encoded != 21)) {
        if (reader != NULL) {
            reader->failed = true;
        }
        return false;
    }
    *value = encoded == 21;
    return true;
}


static bool reader_skip(p4_cbor_reader_t *reader, size_t depth)
{
    if (reader == NULL || depth > P4_CBOR_MAX_DEPTH) {
        if (reader != NULL) {
            reader->failed = true;
        }
        return false;
    }

    uint8_t major;
    uint64_t value;
    if (!reader_head(reader, &major, &value)) {
        return false;
    }
    if (major == 0 || major == 1) {
        return true;
    }
    if (major == 2 || major == 3) {
        return value <= P4_CBOR_MAX_BYTES &&
               reader_take(reader, NULL, (size_t)value);
    }
    if (major == 4 || major == 5) {
        if (value > P4_CBOR_MAX_CONTAINER_ITEMS) {
            reader->failed = true;
            return false;
        }
        size_t count = (size_t)value * (major == 5 ? 2U : 1U);
        for (size_t i = 0; i < count; i++) {
            if (!reader_skip(reader, depth + 1)) {
                return false;
            }
        }
        return true;
    }
    if (major == 7 && (value == 20 || value == 21)) {
        return true;
    }
    reader->failed = true;
    return false;
}


bool p4_cbor_skip(p4_cbor_reader_t *reader)
{
    return reader_skip(reader, 0);
}


bool p4_cbor_reader_done(const p4_cbor_reader_t *reader)
{
    return reader != NULL && !reader->failed && reader->offset == reader->len;
}


bool p4_cbor_known_key_once(uint32_t *seen, uint8_t key)
{
    if (seen == NULL || key == 0 || key > 32) {
        return false;
    }
    uint32_t bit = UINT32_C(1) << (key - 1);
    if ((*seen & bit) != 0) {
        return false;
    }
    *seen |= bit;
    return true;
}
