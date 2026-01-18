#!/usr/bin/env bash

set -euo pipefail

repo_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repo_dir"

port=${1:-${P4KEY_PORT:-}}
if [[ -z "$port" ]]; then
    echo "usage: scripts/flash.sh PORT" >&2
    echo "or set P4KEY_PORT" >&2
    exit 2
fi

if ! command -v idf.py >/dev/null 2>&1; then
    echo "idf.py not found" >&2
    echo "run: . /path/to/esp-idf/export.sh" >&2
    exit 1
fi

echo "flashing ESP32-P4 2FA Key on $port"
idf.py -p "$port" flash
