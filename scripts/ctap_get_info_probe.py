#!/usr/bin/env python3

import argparse
import secrets
import sys

from ctaphid_mvp_probe import (
    BROADCAST_CID,
    CTAPHID_CBOR,
    CTAPHID_INIT,
    MvpProbeError,
    exchange,
    timeout_ms,
)
from usb_common import (
    UsbCheckError,
    check_report_descriptor,
    fido_hid_devices,
    load_hid,
    open_hid_path,
    project_vid_pid,
    select_hid_device,
)
from usb_find import usb_id


GET_INFO_REQUEST = b"\x04"
INVALID_CBOR = b"\x12"
EXPECTED_GET_INFO = bytes.fromhex(
    "00a80181684649444f5f325f300350"
    "e9c017414d6d4a499e89b4b36f5c21a2"
    "04a262726bf4627570f5051908000710081880"
    "0981637573620a81a263616c67266474797065"
    "6a7075626c69632d6b6579"
)


class GetInfoProbeError(ValueError):
    pass


def check_get_info_response(response):
    if bytes(response) != EXPECTED_GET_INFO:
        raise GetInfoProbeError("GetInfo response was not the canonical MVP map")


def run_smoke(handle, wait_ms, output=sys.stdout, exchange_fn=exchange):
    nonce = secrets.token_bytes(8)
    init = exchange_fn(
        handle, BROADCAST_CID, CTAPHID_INIT, nonce, wait_ms
    )
    if len(init) != 17 or init[:8] != nonce:
        raise GetInfoProbeError("INIT did not echo its nonce")
    cid = int.from_bytes(init[8:12], "big")
    if cid in (0, BROADCAST_CID) or init[16] & 0x04 == 0:
        raise GetInfoProbeError("INIT did not allocate a CBOR channel")

    for unused_attempt in range(5):
        check_get_info_response(
            exchange_fn(handle, cid, CTAPHID_CBOR,
                        GET_INFO_REQUEST, wait_ms)
        )
    print("PASS five canonical GetInfo responses", file=output)

    malformed = exchange_fn(
        handle, cid, CTAPHID_CBOR, GET_INFO_REQUEST + b"\xff", wait_ms
    )
    if malformed != INVALID_CBOR:
        raise GetInfoProbeError("malformed GetInfo did not return invalid CBOR")
    check_get_info_response(
        exchange_fn(handle, cid, CTAPHID_CBOR, GET_INFO_REQUEST, wait_ms)
    )
    print("PASS malformed GetInfo failed and the next request recovered",
          file=output)


def probe(vid, pid, wait_ms, selected_path=None,
          hid_module=None, output=sys.stdout):
    handle = None
    try:
        hid_module = hid_module or load_hid()
        records = fido_hid_devices(hid_module, vid, pid)
        record = select_hid_device(records, selected_path)
        handle = open_hid_path(hid_module, record)
        descriptor = bytes(handle.get_report_descriptor())
        unused_facts, errors = check_report_descriptor(
            descriptor, require_exact=False
        )
        if errors:
            raise GetInfoProbeError("selected HID descriptor is not FIDO shaped")
        run_smoke(handle, wait_ms, output)
        return 0
    except (GetInfoProbeError, MvpProbeError, UsbCheckError) as error:
        print(f"FAIL {error}", file=output)
        return 1
    except Exception:
        print("FAIL HID access failed", file=output)
        return 1
    finally:
        if handle is not None:
            try:
                handle.close()
            except Exception:
                pass


def build_parser():
    default_vid, default_pid = project_vid_pid()
    parser = argparse.ArgumentParser(
        description="direct P4Key CTAPHID CBOR GetInfo probe"
    )
    parser.add_argument("--vid", type=usb_id, default=default_vid)
    parser.add_argument("--pid", type=usb_id, default=default_pid)
    parser.add_argument("--path", help="select one matching HID path")
    parser.add_argument("--timeout-ms", type=timeout_ms, default=2000)
    return parser


def main():
    arguments = build_parser().parse_args()
    return probe(
        arguments.vid,
        arguments.pid,
        arguments.timeout_ms,
        arguments.path,
    )


if __name__ == "__main__":
    raise SystemExit(main())
