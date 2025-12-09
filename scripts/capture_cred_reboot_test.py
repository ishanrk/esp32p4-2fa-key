#!/usr/bin/env python3

import argparse
import sys
import time

import serial


EXPECTED = (
    "CRED_REBOOT_TEST wrap_open PASS",
    "CRED_REBOOT_TEST software reboot",
    "CRED_REBOOT_TEST persistence PASS",
)
FAILURE = "CRED_REBOOT_TEST FAIL"


def open_serial(port: str, deadline: float) -> serial.Serial:
    last_error = None
    while time.monotonic() < deadline:
        try:
            return serial.Serial(port, 115200, timeout=0.25)
        except serial.SerialException as error:
            last_error = error
            time.sleep(0.1)
    raise RuntimeError(f"could not open {port}: {last_error}")


def capture(port: str, timeout: float) -> int:
    deadline = time.monotonic() + timeout
    try:
        link = open_serial(port, deadline)
    except RuntimeError as error:
        print(f"FAIL {error}", file=sys.stderr)
        return 1

    next_marker = 0
    with link:
        while time.monotonic() < deadline:
            line = link.readline().decode("utf-8", errors="replace")
            if FAILURE in line:
                print("FAIL target reported CRED_REBOOT_TEST failure",
                      file=sys.stderr)
                return 1
            if EXPECTED[next_marker] in line:
                print(f"observed {EXPECTED[next_marker]}")
                next_marker += 1
                if next_marker == len(EXPECTED):
                    print("credential reboot target test PASS")
                    return 0

    missing = ", ".join(EXPECTED[next_marker:])
    print(f"FAIL missing target markers: {missing}", file=sys.stderr)
    return 1


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Capture the bounded wrapped credential reboot result"
    )
    parser.add_argument("--port", default="COM7")
    parser.add_argument("--timeout", type=float, default=20.0)
    args = parser.parse_args()
    if args.timeout <= 0:
        parser.error("--timeout must be positive")
    return capture(args.port, args.timeout)


if __name__ == "__main__":
    raise SystemExit(main())
