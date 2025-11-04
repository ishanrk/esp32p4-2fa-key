#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

enum {
    P4_CBOR_MAX_BYTES = 2048,
    P4_CBOR_MAX_CONTAINER_ITEMS = 32,
    P4_CBOR_MAX_DEPTH = 8,
};

typedef struct {
    uint8_t *data;
    size_t cap;
    size_t len;
    bool failed;
} p4_cbor_writer_t;

typedef struct {
    const uint8_t *data;
    size_t len;
    size_t offset;
    bool failed;
} p4_cbor_reader_t;

void p4_cbor_writer_init(p4_cbor_writer_t *writer,
                         uint8_t *data,
                         size_t cap);
bool p4_cbor_put_map(p4_cbor_writer_t *writer, size_t pairs);
bool p4_cbor_put_array(p4_cbor_writer_t *writer, size_t items);
bool p4_cbor_put_uint(p4_cbor_writer_t *writer, uint64_t value);
bool p4_cbor_put_int(p4_cbor_writer_t *writer, int64_t value);
bool p4_cbor_put_bytes(p4_cbor_writer_t *writer,
                       const uint8_t *data,
                       size_t len);
bool p4_cbor_put_text(p4_cbor_writer_t *writer,
                      const char *text,
                      size_t len);
bool p4_cbor_put_bool(p4_cbor_writer_t *writer, bool value);
bool p4_cbor_writer_ok(const p4_cbor_writer_t *writer);
size_t p4_cbor_writer_len(const p4_cbor_writer_t *writer);

void p4_cbor_reader_init(p4_cbor_reader_t *reader,
                         const uint8_t *data,
                         size_t len);
bool p4_cbor_get_map(p4_cbor_reader_t *reader, size_t *pairs);
bool p4_cbor_get_array(p4_cbor_reader_t *reader, size_t *items);
bool p4_cbor_get_uint(p4_cbor_reader_t *reader, uint64_t *value);
bool p4_cbor_get_int(p4_cbor_reader_t *reader, int64_t *value);
bool p4_cbor_get_bytes(p4_cbor_reader_t *reader,
                       const uint8_t **data,
                       size_t *len);
bool p4_cbor_get_text(p4_cbor_reader_t *reader,
                      const char **text,
                      size_t *len);
bool p4_cbor_get_bool(p4_cbor_reader_t *reader, bool *value);
bool p4_cbor_skip(p4_cbor_reader_t *reader);
bool p4_cbor_reader_done(const p4_cbor_reader_t *reader);

// caller invokes this only for known integer map keys 1 through 32
bool p4_cbor_known_key_once(uint32_t *seen, uint8_t key);

#ifdef __cplusplus
}
#endif
