#!/usr/bin/env python3

import argparse
import re
from pathlib import Path


FILES = (
    "PROJECT_STATE.txt",
    "CHALLENGES_AND_ERRORS.txt",
    "DECISIONS.txt",
)

REQUIRED_VALUES = (
    "repository path",
    "branch",
    "upstream",
    "ESP IDF",
    "target",
)

COMPLETED_VALUES = (
    "exact Waveshare model",
    "ESP32 P4 chip revision",
    "native USB device connector",
    "button GPIO",
    "button active level",
)

PLACEHOLDERS = {"unknown", "not started", "todo", "tbd", "none"}
SECRET_PATTERN = re.compile(
    r"(?i)(private\s+key|root\s+key|private\s+scalar|secret)"
    r"\s*(?::|=|\n)\s*(?:0x)?[0-9a-f]{16,}"
)


def value_after(text, label):
    lines = text.splitlines()
    for index, line in enumerate(lines):
        if line.strip() != label:
            continue
        for value in lines[index + 1 :]:
            value = value.strip()
            if value:
                return value
    return None


def check_state(text):
    errors = []
    stage_status = value_after(text, "stage status") or ""
    labels = list(REQUIRED_VALUES)
    if "complete" in stage_status.lower():
        labels.extend(COMPLETED_VALUES)

    for label in labels:
        value = value_after(text, label)
        if value is None:
            errors.append(f"PROJECT_STATE.txt missing value after {label}")
        elif value.lower() in PLACEHOLDERS:
            errors.append(
                f"PROJECT_STATE.txt has placeholder after {label}: {value}"
            )
    return errors


def check_root(root):
    errors = []
    texts = {}

    for name in FILES:
        path = root / name
        if not path.is_file():
            errors.append(f"missing continuity file: {name}")
            continue
        texts[name] = path.read_text(encoding="utf-8")

    if errors:
        return errors

    if not texts["PROJECT_STATE.txt"].startswith("P4KEY PROJECT STATE\n"):
        errors.append("PROJECT_STATE.txt heading changed")
    if not texts["CHALLENGES_AND_ERRORS.txt"].startswith(
        "P4KEY CHALLENGES AND ERRORS\n\nappend only\n"
    ):
        errors.append("CHALLENGES_AND_ERRORS.txt append only heading changed")
    if not texts["DECISIONS.txt"].startswith(
        "P4KEY DECISIONS\n\nappend only\n"
    ):
        errors.append("DECISIONS.txt append only heading changed")

    errors.extend(check_state(texts["PROJECT_STATE.txt"]))

    for name, text in texts.items():
        if SECRET_PATTERN.search(text):
            errors.append(f"likely secret material in {name}")

    return errors


def main():
    parser = argparse.ArgumentParser(
        description="check P4Key continuity files"
    )
    parser.add_argument(
        "--root",
        type=Path,
        default=Path(__file__).resolve().parent.parent,
        help="repository or test fixture root",
    )
    arguments = parser.parse_args()

    errors = check_root(arguments.root)
    if errors:
        for error in errors:
            print(f"FAIL {error}")
        return 1

    print("PASS continuity files are structurally valid")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
