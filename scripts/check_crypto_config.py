#!/usr/bin/env python3

import argparse
from pathlib import Path


REQUIRED = (
    "CONFIG_ESP32P4_SELECTS_REV_LESS_V3",
    "CONFIG_MBEDTLS_SHA256_C",
    "CONFIG_MBEDTLS_HARDWARE_SHA",
    "CONFIG_MBEDTLS_AES_C",
    "CONFIG_MBEDTLS_GCM_C",
    "CONFIG_MBEDTLS_HARDWARE_AES",
    "CONFIG_MBEDTLS_HARDWARE_GCM",
    "CONFIG_MBEDTLS_ECP_C",
    "CONFIG_MBEDTLS_ECDH_C",
    "CONFIG_MBEDTLS_ECDSA_C",
    "CONFIG_MBEDTLS_ECP_DP_SECP256R1_ENABLED",
    "CONFIG_MBEDTLS_HARDWARE_ECC",
)

DISABLED = (
    "CONFIG_MBEDTLS_AES_ONLY_128_BIT_KEY_LENGTH",
    "CONFIG_MBEDTLS_AES_SOFT_FALLBACK",
    "CONFIG_MBEDTLS_GCM_SUPPORT_NON_AES_CIPHER",
    "CONFIG_MBEDTLS_ECC_OTHER_CURVES_SOFT_FALLBACK",
    "CONFIG_MBEDTLS_HARDWARE_ECDSA_SIGN",
    "CONFIG_MBEDTLS_HARDWARE_ECDSA_VERIFY",
)


def read_config(path):
    values = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if line.startswith("# CONFIG_") and line.endswith(" is not set"):
            values[line[2:-11]] = "n"
        elif line.startswith("CONFIG_") and "=" in line:
            name, value = line.split("=", 1)
            values[name] = value
    return values


def check(path):
    if not path.is_file():
        print(f"FAIL sdkconfig not found: {path}")
        return 1

    values = read_config(path)
    failed = False

    for name in REQUIRED:
        value = values.get(name, "missing")
        if value == "y":
            print(f"PASS {name}=y")
        else:
            print(f"FAIL {name} expected y got {value}")
            failed = True

    for name in DISABLED:
        value = values.get(name, "missing")
        if value == "n":
            print(f"PASS {name}=n")
        else:
            print(f"FAIL {name} expected n got {value}")
            failed = True

    if failed:
        return 1

    print("PASS required hardware paths enabled without project fallbacks")
    print("PASS dedicated eFuse ECDSA sign and verify paths disabled")
    return 0


def main():
    parser = argparse.ArgumentParser(
        description="verify P4Key hardware crypto sdkconfig"
    )
    parser.add_argument(
        "--sdkconfig",
        type=Path,
        default=Path(__file__).resolve().parent.parent / "sdkconfig",
    )
    arguments = parser.parse_args()
    return check(arguments.sdkconfig)


if __name__ == "__main__":
    raise SystemExit(main())
