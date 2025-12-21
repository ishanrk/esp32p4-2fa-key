#!/usr/bin/env python3

import argparse
import hashlib
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ec
from fido2.ctap import CtapError, STATUS
from fido2.ctap2 import Ctap2
from fido2.hid import CtapHidDevice


VID = 0x303A
PID = 0x4004
AAGUID = bytes.fromhex("e9c017414d6d4a499e89b4b36f5c21a2")
RP_ID = "p4key.test"


class MakeCredentialProbeError(ValueError):
    pass


def check_response(response):
    if response.fmt != "none" or response.att_stmt != {}:
        raise MakeCredentialProbeError("attestation")

    auth_data = response.auth_data
    if len(auth_data) != 232:
        raise MakeCredentialProbeError("auth data length")
    if auth_data.rp_id_hash != hashlib.sha256(RP_ID.encode()).digest():
        raise MakeCredentialProbeError("RP hash")
    if int(auth_data.flags) != 0x41 or auth_data.counter != 0:
        raise MakeCredentialProbeError("auth data fields")

    credential = auth_data.credential_data
    if credential is None or bytes(credential.aaguid) != AAGUID:
        raise MakeCredentialProbeError("attested data")
    if len(credential.credential_id) != 100:
        raise MakeCredentialProbeError("credential ID length")

    key = credential.public_key
    if set(key) != {1, 3, -1, -2, -3}:
        raise MakeCredentialProbeError("COSE fields")
    if key[1] != 2 or key[3] != -7 or key[-1] != 1:
        raise MakeCredentialProbeError("COSE parameters")
    x = key[-2]
    y = key[-3]
    if not isinstance(x, bytes) or not isinstance(y, bytes) or \
            len(x) != 32 or len(y) != 32:
        raise MakeCredentialProbeError("COSE coordinates")
    ec.EllipticCurvePublicNumbers(
        int.from_bytes(x, "big"),
        int.from_bytes(y, "big"),
        ec.SECP256R1(),
    ).public_key()


def run(up_marker, output=sys.stdout):
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
        raise MakeCredentialProbeError("device count")

    marked = False

    def on_keepalive(status):
        nonlocal marked
        if status == STATUS.UPNEEDED and not marked:
            with up_marker.open("x", encoding="ascii") as marker:
                marker.write("up_needed\n")
            marked = True
            print("UP_NEEDED", file=output, flush=True)

    device = selected[0]
    try:
        ctap = Ctap2(device)
        response = ctap.make_credential(
            hashlib.sha256(b"p4key make credential probe v1").digest(),
            {"id": RP_ID, "name": "P4Key test"},
            {
                "id": b"p4key-test-user-v1",
                "name": "p4key-test",
                "displayName": "P4Key Test",
            },
            [{"type": "public-key", "alg": -7}],
            options={"rk": False, "uv": False},
            on_keepalive=on_keepalive,
        )
        check_response(response)
    finally:
        device.close()

    if not marked:
        raise MakeCredentialProbeError("missing user presence wait")
    print("PASS MakeCredential returned none attestation", file=output)
    print("PASS credential ID length 100", file=output)
    print("PASS authData RP hash flags counter and AAGUID", file=output)
    print("PASS valid ES256 EC2 public key", file=output)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--up-marker", required=True, type=Path)
    args = parser.parse_args()
    try:
        run(args.up_marker)
        return 0
    except CtapError as error:
        print(f"FAIL CTAP status 0x{int(error.code):02x}", file=sys.stderr)
    except MakeCredentialProbeError as error:
        print(f"FAIL validation {error}", file=sys.stderr)
    except Exception as error:
        print(f"FAIL {type(error).__name__}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
