# ESP32-P4 2FA Key

This is a USB FIDO2/WebAuthn second-factor authenticator for the Waveshare ESP32-P4-Module-DEV-KIT.

## Features

- `FIDO_2_0`
- CTAP2 over USB HID
- ES256 / P-256
- Non-discoverable credentials
- BOOT GPIO35 user-presence button
- 100-byte AES-GCM wrapped credential IDs

## Board and USB

The tested board uses ESP32-P4 revision v1.3 with the ESP-IDF pre-v3 silicon path. Use the Type-C port labeled `PWR USB TO UART` for flashing and serial logs. For normal authenticator use, connect the separate native Type-C port labeled `USB`.

The `BOOT` button is active-low on GPIO35. Firmware requires the button to be released before each request, then accepts a fresh debounced press as user presence.

## Hardware crypto

- Random generation uses the ESP32-P4 entropy source through `esp_fill_random`.
- SHA-256 uses the PSA API and ESP hardware SHA driver.
- AES-256-GCM uses the PSA API and ESP hardware AES/GCM path. Multipart GCM still performs GHASH in software.
- ES256 uses PSA/Mbed TLS with the ESP general P-256 ECC accelerator.

These paths accelerate cryptographic operations; they do not make per-credential private keys hardware-protected.

## Architecture

`website/browser → USB HID → CTAPHID → CTAP2 → wrapped credential → hardware crypto`

## Build

Requires ESP-IDF v6.0.2.

```sh
. /path/to/esp-idf/export.sh
./scripts/build.sh
```

Install the host dependencies and run the tests with:

```sh
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install -r requirements-host.txt
python3 -m unittest discover -s tests/host -v
```

## Usage

Connect the port labeled `PWR USB TO UART`, then flash:

```sh
./scripts/flash.sh PORT
```

For normal use, connect the separate Type-C port labeled `USB`, register the device as a security key, and press `BOOT` when prompted.

A real `python-fido2` MakeCredential + GetAssertion cycle with two physical BOOT presses has passed.

## Limitations

- No passkeys or resident credentials
- No PIN or user verification
- Development wrapping root stored in NVS
- Per-credential private scalars are transiently visible to software
- No eFuse-backed credential root; firmware does not provision or modify eFuses
- No physical flash-extraction protection yet
- Not FIDO certified
- Secure Boot and flash encryption are not enabled
- Development USB VID/PID `0x303A:0x4004` must not be used for a shipped product
