#include "p4_ctap_priv.h"

#include "p4_aaguid.h"
#include "p4_cbor.h"
#include "p4_ctap.h"


#define PUT(value) do { if (!(value)) return P4_CTAP_ERR_SMALL; } while (0)


int p4_ctap_get_info(uint8_t *response,
                     size_t response_cap,
                     size_t *response_len)
{
    if (response_len == NULL || response == NULL ||
        response_cap > P4_CBOR_MAX_BYTES) {
        return P4_CTAP_ERR_ARG;
    }
    *response_len = 0;

    p4_cbor_writer_t writer;
    p4_cbor_writer_init(&writer, response, response_cap);

    PUT(p4_cbor_put_map(&writer, 8));

    PUT(p4_cbor_put_uint(&writer, 1));
    PUT(p4_cbor_put_array(&writer, 1));
    PUT(p4_cbor_put_text(&writer, "FIDO_2_0", sizeof("FIDO_2_0") - 1));

    PUT(p4_cbor_put_uint(&writer, 3));
    PUT(p4_cbor_put_bytes(&writer, p4_aaguid, P4_AAGUID_LEN));

    PUT(p4_cbor_put_uint(&writer, 4));
    PUT(p4_cbor_put_map(&writer, 2));
    PUT(p4_cbor_put_text(&writer, "rk", sizeof("rk") - 1));
    PUT(p4_cbor_put_bool(&writer, false));
    PUT(p4_cbor_put_text(&writer, "up", sizeof("up") - 1));
    PUT(p4_cbor_put_bool(&writer, true));

    PUT(p4_cbor_put_uint(&writer, 5));
    PUT(p4_cbor_put_uint(&writer, P4_CTAP_MAX_MESSAGE));

    PUT(p4_cbor_put_uint(&writer, 7));
    PUT(p4_cbor_put_uint(&writer, 16));

    PUT(p4_cbor_put_uint(&writer, 8));
    PUT(p4_cbor_put_uint(&writer, 128));

    PUT(p4_cbor_put_uint(&writer, 9));
    PUT(p4_cbor_put_array(&writer, 1));
    PUT(p4_cbor_put_text(&writer, "usb", sizeof("usb") - 1));

    PUT(p4_cbor_put_uint(&writer, 10));
    PUT(p4_cbor_put_array(&writer, 1));
    PUT(p4_cbor_put_map(&writer, 2));
    PUT(p4_cbor_put_text(&writer, "alg", sizeof("alg") - 1));
    PUT(p4_cbor_put_int(&writer, -7));
    PUT(p4_cbor_put_text(&writer, "type", sizeof("type") - 1));
    PUT(p4_cbor_put_text(&writer, "public-key",
                         sizeof("public-key") - 1));

    if (!p4_cbor_writer_ok(&writer)) {
        return P4_CTAP_ERR_SMALL;
    }
    *response_len = p4_cbor_writer_len(&writer);
    return P4_CTAP_OK;
}


#undef PUT
