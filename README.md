# ESP32-P4 2FA Key

This is a USB FIDO2/WebAuthn second-factor authenticator for the Waveshare ESP32-P4-Module-DEV-KIT.

## Features

- `FIDO_2_0`
- CTAP2 over USB HID
- ES256 / P-256
- Non-discoverable credentials
- BOOT GPIO35 user-presence button
- 100-byte AES-GCM wrapped credential IDs

## Hardware crypto

- Hardware RNG
- Hardware SHA-256
- Hardware AES-256-GCM path
- Hardware P-256 ECC acceleration

## Architecture

`website/browser → USB HID → CTAPHID → CTAP2 → wrapped credential → hardware crypto`

## Build

Requires ESP-IDF v6.0.2.

```sh
. /path/to/esp-idf/export.sh
./scripts/build.sh
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
- No physical flash-extraction protection yet
- Not FIDO certified
- Secure Boot and flash encryption are not enabled
