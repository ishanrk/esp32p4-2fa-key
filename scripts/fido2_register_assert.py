#!/usr/bin/env python3

import argparse
import hashlib
import sys
import time
from pathlib import Path

from fido2.ctap import CtapError, STATUS
from fido2.ctap2 import Ctap2
from fido2.hid import CtapHidDevice


VID = 0x303A
PID = 0x4004
RP_ID = "p4key.test"


class RegisterAssertError(ValueError):
    pass


def marker_callback(path, label, output):
    marked = False

    def on_keepalive(status):
        nonlocal marked
        if status == STATUS.UPNEEDED and not marked:
            with path.open("x", encoding="ascii") as marker:
                marker.write("up_needed\n")
            marked = True
            print(label, file=output, flush=True)

    def was_marked():
        return marked

    return on_keepalive, was_marked


def check_registration(response):
    if response.fmt != "none" or response.att_stmt != {}:
        raise RegisterAssertError("registration attestation")

    credential = response.auth_data.credential_data
    if credential is None or len(credential.credential_id) != 100:
        raise RegisterAssertError("registration credential")

    key = credential.public_key
    if set(key) != {1, 3, -1, -2, -3}:
        raise RegisterAssertError("registration key fields")
    if key[1] != 2 or key[3] != -7 or key[-1] != 1:
        raise RegisterAssertError("registration key parameters")
    if len(key[-2]) != 32 or len(key[-3]) != 32:
        raise RegisterAssertError("registration key coordinates")
    return credential.credential_id, key


def check_assertion(response, credential_id, public_key, client_data_hash):
    descriptor = response.credential
    if descriptor is None or descriptor.get("type") != "public-key":
        raise RegisterAssertError("assertion descriptor")
    if descriptor.get("id") != credential_id:
        raise RegisterAssertError("assertion credential")

    auth_data = bytes(response.auth_data)
    if len(auth_data) != 37:
        raise RegisterAssertError("assertion auth data length")
    if auth_data[:32] != hashlib.sha256(RP_ID.encode("utf-8")).digest():
        raise RegisterAssertError("assertion RP hash")
    if auth_data[32] != 0x01 or auth_data[33:37] != b"\x00" * 4:
        raise RegisterAssertError("assertion auth data fields")

    try:
        public_key.verify(auth_data + client_data_hash, response.signature)
    except Exception as error:
        raise RegisterAssertError("assertion signature") from error


def select_device():
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
        raise RegisterAssertError("device count")
    return selected[0]


def wait_for_assertion_start(path, output):
    print("REGISTRATION_PASS_WAITING_ASSERTION", file=output, flush=True)
    for _ in range(12000):
        if path.is_file():
            return
        time.sleep(0.05)
    raise RegisterAssertError("assertion start timeout")


def run(registration_marker, assertion_marker, assertion_start_gate,
        output=sys.stdout):
    registration_keepalive, registration_marked = marker_callback(
        registration_marker, "REGISTRATION_UP_NEEDED", output
    )
    assertion_keepalive, assertion_marked = marker_callback(
        assertion_marker, "ASSERTION_UP_NEEDED", output
    )

    device = select_device()
    try:
        ctap = Ctap2(device)
        registration = ctap.make_credential(
            hashlib.sha256(b"p4key register assert registration v1").digest(),
            {"id": RP_ID, "name": "P4Key test"},
            {
                "id": b"p4key-register-assert-user-v1",
                "name": "p4key-test",
                "displayName": "P4Key Test",
            },
            [{"type": "public-key", "alg": -7}],
            options={"rk": False, "uv": False},
            on_keepalive=registration_keepalive,
        )
        if not registration_marked():
            raise RegisterAssertError("registration user presence wait")
        credential_id, public_key = check_registration(registration)
        wait_for_assertion_start(assertion_start_gate, output)

        assertion_hash = hashlib.sha256(
            b"p4key register assert assertion v1"
        ).digest()
        assertion = ctap.get_assertion(
            RP_ID,
            assertion_hash,
            [{"type": "public-key", "id": credential_id}],
            options={"up": True, "uv": False},
            on_keepalive=assertion_keepalive,
        )
        if not assertion_marked():
            raise RegisterAssertError("assertion user presence wait")
        check_assertion(assertion, credential_id, public_key, assertion_hash)
    finally:
        device.close()

    print("PASS registration returned one ES256 credential", file=output)
    print("PASS assertion authData length 37 flags 0x01 counter 0", file=output)
    print("PASS assertion DER signature verified", file=output)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--registration-up-marker", required=True, type=Path)
    parser.add_argument("--assertion-up-marker", required=True, type=Path)
    parser.add_argument("--assertion-start-gate", required=True, type=Path)
    args = parser.parse_args()
    paths = {
        args.registration_up_marker,
        args.assertion_up_marker,
        args.assertion_start_gate,
    }
    if len(paths) != 3:
        print("FAIL marker paths must differ", file=sys.stderr)
        return 1
    try:
        run(args.registration_up_marker, args.assertion_up_marker,
            args.assertion_start_gate)
        return 0
    except CtapError as error:
        print(f"FAIL CTAP status 0x{int(error.code):02x}", file=sys.stderr)
    except RegisterAssertError as error:
        print(f"FAIL validation {error}", file=sys.stderr)
    except FileExistsError:
        print("FAIL marker already exists", file=sys.stderr)
    except Exception as error:
        print(f"FAIL {type(error).__name__}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
