#!/usr/bin/env python3

import argparse
import sys

from usb_common import (
    UsbCheckError,
    check_report_descriptor,
    fido_hid_devices,
    load_hid,
    open_hid_path,
    path_text,
    project_vid_pid,
)


def usb_id(value):
    parsed = int(value, 0)
    if parsed < 1 or parsed > 0xFFFE:
        raise argparse.ArgumentTypeError("USB IDs must be between 1 and 0xfffe")
    return parsed


def find_devices(vid, pid, hid_module=None, output=sys.stdout):
    try:
        hid_module = hid_module or load_hid()
        devices = fido_hid_devices(hid_module, vid, pid)
    except UsbCheckError as error:
        print(f"FAIL {error}", file=output)
        return 2

    print(f"matching HID devices {len(devices)}", file=output)
    for index, record in enumerate(devices):
        print(f"device {index}", file=output)
        print(f"path {path_text(record.get('path', 'UNAVAILABLE'))}", file=output)
        print(
            f"interface {record.get('interface_number', 'UNAVAILABLE')}",
            file=output,
        )
        usage_page = record.get("usage_page")
        usage = record.get("usage")
        print(
            "usage page "
            + (f"0x{usage_page:04x}" if isinstance(usage_page, int) else "UNAVAILABLE"),
            file=output,
        )
        print(
            "usage " + (f"0x{usage:02x}" if isinstance(usage, int) else "UNAVAILABLE"),
            file=output,
        )

        handle = None
        try:
            handle = open_hid_path(hid_module, record)
            descriptor = bytes(handle.get_report_descriptor())
            facts, errors = check_report_descriptor(descriptor, require_exact=False)
            if errors:
                print("input report bytes INVALID", file=output)
                print("output report bytes INVALID", file=output)
            else:
                print(
                    f"input report bytes {facts['input report bytes']}",
                    file=output,
                )
                print(
                    f"output report bytes {facts['output report bytes']}",
                    file=output,
                )
        except Exception:
            print("input report bytes UNAVAILABLE", file=output)
            print("output report bytes UNAVAILABLE", file=output)
        finally:
            if handle is not None:
                try:
                    handle.close()
                except Exception:
                    pass

    if not devices:
        print(f"FAIL no HID device matches {vid:04x}:{pid:04x}", file=output)
        return 1
    return 0


def build_parser():
    default_vid, default_pid = project_vid_pid()
    parser = argparse.ArgumentParser(
        description="find only the P4Key development HID device"
    )
    parser.add_argument("--vid", type=usb_id, default=default_vid)
    parser.add_argument("--pid", type=usb_id, default=default_pid)
    return parser


def main():
    arguments = build_parser().parse_args()
    return find_devices(arguments.vid, arguments.pid)


if __name__ == "__main__":
    raise SystemExit(main())
