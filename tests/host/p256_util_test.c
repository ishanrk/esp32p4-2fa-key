#include "p4_crypto_p256_util.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>


static int scalar_tests(void)
{
    static const uint8_t order[32] = {
        0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84,
        0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
    };
    uint8_t scalar[32] = {0};

    if (p4_p256_scalar_valid(scalar)) {
        return 1;
    }
    scalar[31] = 1;
    if (!p4_p256_scalar_valid(scalar)) {
        return 1;
    }
    memcpy(scalar, order, sizeof(scalar));
    scalar[31]--;
    if (!p4_p256_scalar_valid(scalar)) {
        return 1;
    }
    memcpy(scalar, order, sizeof(scalar));
    if (p4_p256_scalar_valid(scalar)) {
        return 1;
    }
    memset(scalar, 0xff, sizeof(scalar));
    if (p4_p256_scalar_valid(scalar)) {
        return 1;
    }

    return 0;
}


static int der_tests(void)
{
    static const uint8_t valid[] = {
        0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01,
    };
    static const uint8_t padded[] = {
        0x30, 0x07, 0x02, 0x02, 0x00, 0x80, 0x02, 0x01, 0x01,
    };
    static const uint8_t trailing[] = {
        0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x00,
    };
    static const uint8_t redundant[] = {
        0x30, 0x07, 0x02, 0x02, 0x00, 0x01, 0x02, 0x01, 0x01,
    };
    static const uint8_t negative[] = {
        0x30, 0x06, 0x02, 0x01, 0x80, 0x02, 0x01, 0x01,
    };
    static const uint8_t long_length[] = {
        0x30, 0x81, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01,
    };

    if (!p4_p256_der_strict(valid, sizeof(valid)) ||
        !p4_p256_der_strict(padded, sizeof(padded)) ||
        p4_p256_der_strict(trailing, sizeof(trailing)) ||
        p4_p256_der_strict(redundant, sizeof(redundant)) ||
        p4_p256_der_strict(negative, sizeof(negative)) ||
        p4_p256_der_strict(long_length, sizeof(long_length))) {
        return 1;
    }

    return 0;
}


int main(void)
{
    if (scalar_tests() != 0 || der_tests() != 0) {
        return 1;
    }

    puts("PASS p256 scalar and strict DER helpers");
    return 0;
}
