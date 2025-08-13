#include "p4_crypto_p256_util.h"


static const uint8_t p256_order[32] = {
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84,
    0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
};


bool p4_p256_scalar_valid(const uint8_t scalar[32])
{
    if (scalar == NULL) {
        return false;
    }

    uint32_t nonzero = 0;
    uint32_t less = 0;
    uint32_t greater = 0;

    // fixed width compare avoids a secret dependent early exit
    for (size_t i = 0; i < 32; ++i) {
        uint32_t a = scalar[i];
        uint32_t b = p256_order[i];
        uint32_t undecided = 1u ^ (less | greater);
        uint32_t a_less = (a - b) >> 31;
        uint32_t a_greater = (b - a) >> 31;

        nonzero |= a;
        less |= undecided & a_less;
        greater |= undecided & a_greater;
    }

    return nonzero != 0 && less != 0;
}


static bool strict_integer(const uint8_t *der, size_t end, size_t *offset)
{
    size_t pos = *offset;
    if (pos > end || end - pos < 2 || der[pos] != 0x02) {
        return false;
    }

    size_t value_len = der[pos + 1];
    pos += 2;

    // p256 values use only short form lengths and at most one sign pad
    if (value_len == 0 || value_len > 33 || value_len > end - pos) {
        return false;
    }
    if ((der[pos] & 0x80u) != 0) {
        return false;
    }
    if (value_len == 33) {
        if (der[pos] != 0 || (der[pos + 1] & 0x80u) == 0) {
            return false;
        }
    } else if (value_len > 1 && der[pos] == 0 &&
               (der[pos + 1] & 0x80u) == 0) {
        return false;
    }

    *offset = pos + value_len;
    return true;
}


bool p4_p256_der_strict(const uint8_t *der, size_t der_len)
{
    if (der == NULL || der_len < 8 || der_len > 72) {
        return false;
    }
    if (der[0] != 0x30 || (der[1] & 0x80u) != 0 ||
        (size_t)der[1] != der_len - 2) {
        return false;
    }

    size_t offset = 2;
    if (!strict_integer(der, der_len, &offset) ||
        !strict_integer(der, der_len, &offset)) {
        return false;
    }

    return offset == der_len;
}
