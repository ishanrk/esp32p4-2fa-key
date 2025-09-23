#!/usr/bin/env python3

import argparse
import os
import sys
from pathlib import Path

from usb_common import (
    REPO,
    UsbCheckError,
    check_project_source,
    check_report_descriptor,
    fido_hid_devices,
    load_hid,
    open_hid_path,
    parse_lsusb_verbose,
    project_vid_pid,
    read_text,
    run_lsusb,
    select_hid_device,
)
from usb_find import usb_id


def show_source(root, output):
    facts, errors = check_project_source(root)
    expected = (
        ("VID", 0x303A, "04x"),
        ("PID", 0x4004, "04x"),
        ("descriptor bytes", 34, None),
        ("application collections", 1, None),
        ("usage page", 0xF1D0, "04x"),
        ("application usage", 0x01, "02x"),
        ("report IDs", 0, None),
        ("input usage", 0x20, "02x"),
        ("input report bytes", 64, None),
        ("output usage", 0x21, "02x"),
        ("output report bytes", 64, None),
        ("configuration bytes", 41, None),
        ("interface class", 3, None),
        ("endpoints", [(0x01, 3, 64, 5), (0x81, 3, 64, 5)], None),
    )
    print("source descriptor", file=output)
    for label, wanted, formatting in expected:
        observed = facts.get(label)
        if formatting and isinstance(observed, int):
            observed_text = f"0x{observed:{formatting}}"
            wanted_text = f"0x{wanted:{formatting}}"
        else:
            observed_text = str(observed) if observed is not None else "UNAVAILABLE"
            wanted_text = str(wanted)
        status = "PASS" if observed == wanted else "FAIL"
        print(
            f"{status} {label} expected {wanted_text} observed {observed_text}",
            file=output,
        )
    for error in errors:
        print(f"FAIL source policy {error}", file=output)
    if not errors:
        print("PASS one HID interface and no other USB class", file=output)
        print("PASS finite USB deadlines and mount gated resume", file=output)
    return not errors


def show_hid(vid, pid, selected_path, hid_module, output):
    print("live HID descriptor", file=output)
    handle = None
    try:
        devices = fido_hid_devices(hid_module, vid, pid)
        record = select_hid_device(devices, selected_path)
        page = record.get("usage_page")
        usage = record.get("usage")
        if page is None:
            print("UNAVAILABLE enumeration usage page", file=output)
        else:
            print(
                f"{'PASS' if page == 0xf1d0 else 'FAIL'} usage page "
                f"expected 0xf1d0 observed 0x{page:04x}",
                file=output,
            )
        if usage is None:
            print("UNAVAILABLE enumeration usage", file=output)
        else:
            print(
                f"{'PASS' if usage == 1 else 'FAIL'} usage "
                f"expected 0x01 observed 0x{usage:02x}",
                file=output,
            )
        handle = open_hid_path(hid_module, record)
        descriptor = bytes(handle.get_report_descriptor())
        facts, errors = check_report_descriptor(descriptor, require_exact=False)
        if errors:
            for error in errors:
                print(f"FAIL live report descriptor {error}", file=output)
            return False
        print(f"PASS input report bytes {facts['input report bytes']}", file=output)
        print(f"PASS output report bytes {facts['output report bytes']}", file=output)
        platform_note = (
            "Windows HIDAPI reconstructed descriptor"
            if os.name == "nt"
            else "host HIDAPI descriptor"
        )
        print(f"PASS {platform_note}", file=output)
        return page in (None, 0xF1D0) and usage in (None, 1)
    except Exception as error:
        print(f"UNAVAILABLE live HID facts {error}", file=output)
        return False
    finally:
        if handle is not None:
            try:
                handle.close()
            except Exception:
                pass


def show_lsusb(text, vid, pid, output):
    print("Linux lsusb descriptor", file=output)
    facts, errors = parse_lsusb_verbose(text, vid, pid)
    expected = {
        "VID": vid,
        "PID": pid,
        "device class": 0,
        "configurations": 1,
        "interface classes": [3],
        "report descriptor bytes": 34,
        "endpoints": [(0x01, 3, 64, 5), (0x81, 3, 64, 5)],
    }
    for label, wanted in expected.items():
        value = facts.get(label)
        if value is None:
            print(f"UNAVAILABLE {label}", file=output)
        else:
            status = "PASS" if value == wanted else "FAIL"
            print(
                f"{status} {label} expected {wanted} observed {value}",
                file=output,
            )
    for error in errors:
        print(f"FAIL lsusb {error}", file=output)
    if not errors:
        print("PASS lsusb shows one HID interface and no CDC", file=output)
    return not errors


def build_parser():
    default_vid, default_pid = project_vid_pid()
    parser = argparse.ArgumentParser(
        description="validate source and optional observed P4Key USB descriptors"
    )
    parser.add_argument("--root", type=Path, default=REPO)
    parser.add_argument("--vid", type=usb_id, default=default_vid)
    parser.add_argument("--pid", type=usb_id, default=default_pid)
    parser.add_argument(
        "--live-hid", action="store_true",
        help="open only the matching HID device and validate its report descriptor",
    )
    parser.add_argument("--path", help="select one matching HID path")
    lsusb = parser.add_mutually_exclusive_group()
    lsusb.add_argument("--lsusb", type=Path, help="parse saved filtered lsusb -v output")
    lsusb.add_argument(
        "--live-lsusb", action="store_true",
        help="run filtered lsusb -v for the requested VID PID",
    )
    return parser


def main():
    arguments = build_parser().parse_args()
    passed = show_source(arguments.root, sys.stdout)

    if arguments.live_hid:
        try:
            hid_module = load_hid()
        except UsbCheckError as error:
            print(f"UNAVAILABLE live HID facts {error}")
            passed = False
        else:
            passed = show_hid(
                arguments.vid, arguments.pid, arguments.path,
                hid_module, sys.stdout,
            ) and passed
    else:
        print("UNAVAILABLE live HID facts not requested")

    if arguments.lsusb is not None:
        try:
            text = read_text(arguments.lsusb)
        except UsbCheckError as error:
            print(f"UNAVAILABLE Linux lsusb descriptor {error}")
            passed = False
        else:
            passed = show_lsusb(text, arguments.vid, arguments.pid, sys.stdout) and passed
    elif arguments.live_lsusb:
        try:
            text = run_lsusb(arguments.vid, arguments.pid)
        except UsbCheckError as error:
            print(f"UNAVAILABLE Linux lsusb descriptor {error}")
            passed = False
        else:
            passed = show_lsusb(text, arguments.vid, arguments.pid, sys.stdout) and passed
    else:
        print("UNAVAILABLE Linux lsusb descriptor not requested")
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
