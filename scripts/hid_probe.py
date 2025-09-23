#!/usr/bin/env python3

import argparse
import sys

from usb_common import (
    BRINGUP_REQUEST,
    BRINGUP_RESPONSE,
    REPORT_BYTES,
    UsbCheckError,
    check_report_descriptor,
    fido_hid_devices,
    load_hid,
    open_hid_path,
    project_vid_pid,
    select_hid_device,
)
from usb_find import usb_id


def timeout_ms(value):
    parsed = int(value, 10)
    if parsed < 1 or parsed > 60000:
        raise argparse.ArgumentTypeError("timeout must be between 1 and 60000 ms")
    return parsed


def probe(vid, pid, mode, wait_ms, selected_path=None,
          hid_module=None, output=sys.stdout):
    handle = None
    try:
        if mode not in ("bringup", "normal-no-response"):
            raise UsbCheckError("probe mode must be explicit")
        hid_module = hid_module or load_hid()
        records = fido_hid_devices(hid_module, vid, pid)
        record = select_hid_device(records, selected_path)
        handle = open_hid_path(hid_module, record)

        descriptor = bytes(handle.get_report_descriptor())
        unused_facts, descriptor_errors = check_report_descriptor(
            descriptor, require_exact=False
        )
        if descriptor_errors:
            raise UsbCheckError("selected HID descriptor is not FIDO shaped")

        # HIDAPI requires a host-only zero prefix when the descriptor has no ID
        written = handle.write(b"\0" + BRINGUP_REQUEST)
        if written != REPORT_BYTES + 1:
            print("FAIL HIDAPI did not accept one complete output report", file=output)
            return 1
        response = bytes(handle.read(REPORT_BYTES, wait_ms))

        if mode == "bringup":
            if len(response) != REPORT_BYTES:
                print("FAIL fixed bringup response timed out", file=output)
                return 1
            if response != BRINGUP_RESPONSE:
                print("FAIL fixed bringup response did not match", file=output)
                return 1
            print("PASS exact 64 byte bringup request and response", file=output)
            return 0

        if response:
            print("FAIL normal firmware answered the private bringup report", file=output)
            return 1
        print("PASS normal firmware did not answer the private bringup report", file=output)
        return 0
    except Exception as error:
        print(f"FAIL HID probe {error}", file=output)
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
        description="explicit P4Key 64 byte HID bringup probe"
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument(
        "--bringup", action="store_true",
        help="expect the opt-in bringup firmware's exact response",
    )
    mode.add_argument(
        "--normal-no-response", action="store_true",
        help="expect normal firmware not to implement the private exchange",
    )
    parser.add_argument("--vid", type=usb_id, default=default_vid)
    parser.add_argument("--pid", type=usb_id, default=default_pid)
    parser.add_argument("--path", help="select one matching HID path")
    parser.add_argument("--timeout-ms", type=timeout_ms, default=2000)
    return parser


def main():
    arguments = build_parser().parse_args()
    mode = "bringup" if arguments.bringup else "normal-no-response"
    return probe(
        arguments.vid, arguments.pid, mode, arguments.timeout_ms,
        arguments.path,
    )


if __name__ == "__main__":
    raise SystemExit(main())
