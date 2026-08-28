# Custom Microcontroller 2FA Security Key

This is a USB FIDO2 2 factor authenticator for the Waveshare ESP32-P4-Module-DEV-KIT.

**I personally use this 2 Factor Auth for my github logins**



https://github.com/user-attachments/assets/a30b94ad-aff3-4bb2-8cbb-00eaf5deac2f



## Some Features

a) `FIDO_2_0` 2fa 

b_CTAP2 over USB HID

c) ES256 / P-256 key generation

d) Non-discoverable credentials (i.e no-one can find my passkey if they don't have my private key)

e) BOOT GPIO35 button programmable

f) 100 byte AES-GCM wrapped credential IDs

## Board and USB

The tested board uses ESP32-P4 revision v1.3 with the ESP-IDF pre-v3 silicon path. Use the Type-C port labeled `PWR USB TO UART` for flashing and serial logs. For normal authenticator use, connect the separate native Type-C port labeled `USB`.

Firmware requires the button to be released before each request, then accepts a fresh debounced press as user presence.

## Hardware crypto accelerators (cool :))

a) Random generation uses the ESP32-P4 entropy source through `esp_fill_random`.

b) SHA-256 uses the PSA API and ESP hardware SHA driver.

c) AES-256-GCM uses the PSA API and ESP hardware AES/GCM path. Multipart GCM still performs GHASH in software.

d) ES256 uses PSA/Mbed TLS with the ESP general P-256 ECC accelerator.

These functions are genuinely accelerated on this chip due to having specialized hardware.

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
