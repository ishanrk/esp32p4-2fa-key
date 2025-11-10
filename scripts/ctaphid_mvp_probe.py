#!/usr/bin/env python3

import argparse
import secrets
import sys
import time

from usb_common import (
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


INIT_DATA_BYTES = 57
CONT_DATA_BYTES = 59
MAX_PAYLOAD = 2048
BROADCAST_CID = 0xFFFFFFFF

CTAPHID_PING = 0x81
CTAPHID_INIT = 0x86
CTAPHID_CBOR = 0x90
CTAP_OK = 0x00


class MvpProbeError(ValueError):
    pass


def timeout_ms(value):
    parsed = int(value, 10)
    if parsed < 1 or parsed > 60000:
        raise argparse.ArgumentTypeError("timeout must be between 1 and 60000 ms")
    return parsed


def encode_reports(cid, command, data):
    payload = bytes(data)
    if cid == 0 or command & 0x80 == 0 or len(payload) > MAX_PAYLOAD:
        raise MvpProbeError("invalid outbound CTAPHID message")

    initial = bytearray(REPORT_BYTES)
    initial[0:4] = cid.to_bytes(4, "big")
    initial[4] = command
    initial[5:7] = len(payload).to_bytes(2, "big")
    initial[7:7 + min(len(payload), INIT_DATA_BYTES)] = payload[:INIT_DATA_BYTES]
    reports = [bytes(initial)]

    offset = INIT_DATA_BYTES
    sequence = 0
    while offset < len(payload):
        report = bytearray(REPORT_BYTES)
        report[0:4] = cid.to_bytes(4, "big")
        report[4] = sequence
        chunk = payload[offset:offset + CONT_DATA_BYTES]
        report[5:5 + len(chunk)] = chunk
        reports.append(bytes(report))
        offset += len(chunk)
        sequence += 1
    return reports


def send_message(handle, cid, command, data):
    for report in encode_reports(cid, command, data):
        # report id zero is host only and is not one of the 64 wire bytes
        if handle.write(b"\0" + report) != REPORT_BYTES + 1:
            raise MvpProbeError("HIDAPI rejected a complete output report")


def _read_report(handle, deadline):
    remaining_ms = int((deadline - time.monotonic()) * 1000)
    if remaining_ms < 1:
        raise MvpProbeError("CTAPHID response timed out")
    report = bytes(handle.read(REPORT_BYTES, remaining_ms))
    if len(report) != REPORT_BYTES:
        raise MvpProbeError("CTAPHID response timed out or was not 64 bytes")
    return report


def read_message(handle, expected_cid, wait_ms):
    deadline = time.monotonic() + wait_ms / 1000
    report = _read_report(handle, deadline)
    cid = int.from_bytes(report[0:4], "big")
    command = report[4]
    declared_len = int.from_bytes(report[5:7], "big")
    if cid != expected_cid or command & 0x80 == 0:
        raise MvpProbeError("unexpected CTAPHID initial response")
    if declared_len > MAX_PAYLOAD:
        raise MvpProbeError("CTAPHID response exceeds the transport maximum")

    payload = bytearray(report[7:7 + min(declared_len, INIT_DATA_BYTES)])
    sequence = 0
    while len(payload) < declared_len:
        report = _read_report(handle, deadline)
        if int.from_bytes(report[0:4], "big") != expected_cid:
            raise MvpProbeError("CTAPHID continuation used another channel")
        if report[4] != sequence:
            raise MvpProbeError("CTAPHID continuation sequence is wrong")
        take = min(CONT_DATA_BYTES, declared_len - len(payload))
        payload.extend(report[5:5 + take])
        sequence += 1
    return command, bytes(payload)


def exchange(handle, cid, command, data, wait_ms):
    send_message(handle, cid, command, data)
    response_command, response = read_message(handle, cid, wait_ms)
    if response_command != command:
        raise MvpProbeError("CTAPHID response command did not match")
    return response


def run_smoke(handle, wait_ms, output=sys.stdout):
    nonce = secrets.token_bytes(8)
    response = exchange(handle, BROADCAST_CID, CTAPHID_INIT, nonce, wait_ms)
    if len(response) != 17 or response[:8] != nonce:
        raise MvpProbeError("INIT did not echo its nonce")
    cid = int.from_bytes(response[8:12], "big")
    if cid in (0, BROADCAST_CID):
        raise MvpProbeError("INIT returned an invalid channel")
    if response[12] != 2 or response[16] & 0x04 == 0:
        raise MvpProbeError("INIT protocol or CBOR capability is wrong")
    print("PASS INIT allocated a valid channel and echoed the nonce", file=output)

    short_ping = b"p4key mvp"
    if exchange(handle, cid, CTAPHID_PING, short_ping, wait_ms) != short_ping:
        raise MvpProbeError("short PING did not echo")
    print("PASS short PING echoed 9 bytes", file=output)

    multi_ping = bytes((index * 17 + 3) & 0xFF for index in range(117))
    if exchange(handle, cid, CTAPHID_PING, multi_ping, wait_ms) != multi_ping:
        raise MvpProbeError("multi frame PING did not echo")
    print("PASS multi frame PING echoed 117 bytes", file=output)

    response = exchange(handle, cid, CTAPHID_CBOR, b"\x04", wait_ms)
    if len(response) < 2 or response[0] != CTAP_OK:
        raise MvpProbeError("CBOR GetInfo did not reach the application")
    print("PASS CBOR GetInfo reached the application", file=output)


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
            raise MvpProbeError("selected HID descriptor is not FIDO shaped")
        run_smoke(handle, wait_ms, output)
        return 0
    except (MvpProbeError, UsbCheckError) as error:
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
        description="minimal P4Key CTAPHID MVP smoke probe"
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
