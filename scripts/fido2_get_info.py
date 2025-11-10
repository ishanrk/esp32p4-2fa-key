#!/usr/bin/env python3

import sys

from fido2.ctap2 import Ctap2
from fido2.hid import CtapHidDevice


VID = 0x303A
PID = 0x4004
AAGUID = bytes.fromhex("e9c017414d6d4a499e89b4b36f5c21a2")


class Fido2GetInfoError(ValueError):
    pass


def check_info(info):
    if info.versions != ["FIDO_2_0"]:
        raise Fido2GetInfoError("versions were not exactly FIDO_2_0")
    if bytes(info.aaguid) != AAGUID or len(info.aaguid) != 16:
        raise Fido2GetInfoError("AAGUID was not the source controlled value")
    if info.options != {"rk": False, "up": True}:
        raise Fido2GetInfoError("options advertised an unsupported feature")
    if info.max_msg_size != 2048:
        raise Fido2GetInfoError("maxMsgSize was not 2048")
    if info.max_creds_in_list != 16:
        raise Fido2GetInfoError("maxCredentialCountInList was not 16")
    if info.max_cred_id_length is None or info.max_cred_id_length < 100:
        raise Fido2GetInfoError("maxCredentialIdLength was below 100")
    if info.transports != ["usb"]:
        raise Fido2GetInfoError("transport was not exactly usb")
    if info.algorithms != [{"alg": -7, "type": "public-key"}]:
        raise Fido2GetInfoError("algorithm was not exactly ES256")
    if info.extensions or info.pin_uv_protocols:
        raise Fido2GetInfoError("extensions or PIN UV were advertised")


def run(output=sys.stdout):
    devices = list(CtapHidDevice.list_devices())
    selected = [
        device for device in devices
        if device.descriptor.vid == VID and device.descriptor.pid == PID
    ]
    for device in devices:
        if device not in selected:
            device.close()
    if len(selected) != 1:
        for device in selected:
            device.close()
        raise Fido2GetInfoError("expected exactly one P4Key FIDO device")

    device = selected[0]
    try:
        ctap = Ctap2(device)
        infos = [ctap.info]
        infos.extend(ctap.get_info() for unused_attempt in range(4))
        for info in infos:
            check_info(info)
    finally:
        device.close()

    print("PASS python-fido2 recognized one P4Key authenticator", file=output)
    print("PASS five strict canonical GetInfo responses", file=output)
    print("PASS only FIDO_2_0 ES256 usb rk false up true", file=output)


def main():
    try:
        run()
        return 0
    except Exception as error:
        print(f"FAIL {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
