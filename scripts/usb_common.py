#!/usr/bin/env python3

import importlib
import re
import subprocess
from pathlib import Path


REPO = Path(__file__).resolve().parent.parent

DEFAULT_VID = 0x303A
DEFAULT_PID = 0x4004
REPORT_BYTES = 64
QUEUE_DEPTH = 8
REPORT_DESC_BYTES = 34
CONFIG_DESC_BYTES = 41

BRINGUP_REQUEST = b"P4KEY USB BRINGUP REQUEST v1".ljust(REPORT_BYTES, b"\0")
BRINGUP_RESPONSE = b"P4KEY USB BRINGUP RESPONSE v1".ljust(REPORT_BYTES, b"\0")

EXPECTED_REPORT_DESCRIPTOR = bytes.fromhex(
    "06 d0 f1 09 01 a1 01 "
    "09 20 15 00 26 ff 00 75 08 95 40 81 02 "
    "09 21 15 00 26 ff 00 75 08 95 40 91 02 c0"
)

EXPECTED_CONSTANTS = {
    "P4_USB_REPORT_BYTES": REPORT_BYTES,
    "P4_USB_RX_QUEUE_DEPTH": QUEUE_DEPTH,
    "P4_USB_REPORT_DESC_BYTES": REPORT_DESC_BYTES,
    "P4_USB_CONFIG_DESC_BYTES": CONFIG_DESC_BYTES,
    "P4_USB_EP_OUT": 0x01,
    "P4_USB_EP_IN": 0x81,
    "P4_USB_POLL_INTERVAL_MS": 5,
}

EXPECTED_DEFAULTS = {
    "CONFIG_ESP32P4_SELECTS_REV_LESS_V3": "y",
    "CONFIG_ESP_CONSOLE_UART_DEFAULT": "y",
    "CONFIG_ESP_CONSOLE_SECONDARY_NONE": "y",
    "CONFIG_TINYUSB_DEBUG_LEVEL": "0",
    "CONFIG_TINYUSB_MODE_DMA": "y",
    "CONFIG_TINYUSB_SUSPEND_CALLBACK": "y",
    "CONFIG_TINYUSB_RESUME_CALLBACK": "y",
    "CONFIG_TINYUSB_HID_COUNT": "1",
    "CONFIG_TINYUSB_MSC_ENABLED": "n",
    "CONFIG_TINYUSB_CDC_ENABLED": "n",
    "CONFIG_TINYUSB_MIDI_COUNT": "0",
    "CONFIG_TINYUSB_DFU_MODE_NONE": "y",
    "CONFIG_TINYUSB_BTH_ENABLED": "n",
    "CONFIG_TINYUSB_NET_MODE_NONE": "y",
    "CONFIG_TINYUSB_VENDOR_COUNT": "0",
    "CONFIG_P4KEY_USB_BRINGUP": "n",
    "CONFIG_SECURE_BOOT": "n",
    "CONFIG_SECURE_FLASH_ENC_ENABLED": "n",
}

CONFIG_SYMBOLS = {
    "TUSB_DESC_CONFIGURATION": 0x02,
    "TUSB_DESC_INTERFACE": 0x04,
    "TUSB_CLASS_HID": 0x03,
    "HID_DESC_TYPE_HID": 0x21,
    "HID_DESC_TYPE_REPORT": 0x22,
    "TUSB_DESC_ENDPOINT": 0x05,
    "TUSB_XFER_INTERRUPT": 0x03,
    **EXPECTED_CONSTANTS,
}


class UsbCheckError(ValueError):
    pass


def read_text(path):
    try:
        return path.read_text(encoding="utf-8", errors="strict")
    except (OSError, UnicodeError) as error:
        raise UsbCheckError(f"cannot read {path}") from error


def strip_c_comments(text):
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)
    return re.sub(r"//[^\n]*", "", text)


def parse_integer(token):
    token = token.strip()
    if not re.fullmatch(r"(?:0[xX][0-9a-fA-F]+|[0-9]+)", token):
        raise UsbCheckError(f"nonliteral integer token {token!r}")
    return int(token, 0)


def _initializer_body(text, name, array=True):
    clean = strip_c_comments(text)
    suffix = r"\s*\[[^\]]*\]" if array else r""
    pattern = re.compile(rf"\b{re.escape(name)}{suffix}\s*=\s*\{{")
    matches = list(pattern.finditer(clean))
    if len(matches) != 1:
        raise UsbCheckError(f"expected one initializer for {name}")

    opening = matches[0].end() - 1
    depth = 0
    for offset in range(opening, len(clean)):
        byte = clean[offset]
        if byte == "{":
            depth += 1
        elif byte == "}":
            depth -= 1
            if depth == 0:
                return clean[opening + 1 : offset]
    raise UsbCheckError(f"unterminated initializer for {name}")


def extract_c_array(text, name, symbols=None):
    body = _initializer_body(text, name, array=True)
    values = []
    symbols = symbols or {}
    for raw in body.split(","):
        token = raw.strip()
        if not token:
            continue
        if token in symbols:
            values.append(symbols[token])
        else:
            values.append(parse_integer(token))
    if any(value < 0 or value > 0xFF for value in values):
        raise UsbCheckError(f"{name} contains a value outside one byte")
    return bytes(values)


def read_c_array(path, name):
    """Read one strict project byte array from a C source file."""
    return extract_c_array(read_text(Path(path)), name, CONFIG_SYMBOLS)


def load_source_descriptors(root=REPO):
    """Return the source-controlled HID report and USB configuration bytes."""
    source = read_text(Path(root) / "components/p4_usb/p4_usb_desc.c")
    return (
        extract_c_array(source, "p4_usb_report_desc"),
        extract_c_array(source, "p4_usb_config_desc", CONFIG_SYMBOLS),
    )


def parse_header_constants(text):
    clean = strip_c_comments(text)
    matches = list(re.finditer(r"\benum\s*\{(.*?)\}\s*;", clean, re.DOTALL))
    if len(matches) != 1:
        raise UsbCheckError("expected one USB constant enum")

    values = {}
    for raw in matches[0].group(1).split(","):
        token = raw.strip()
        if not token:
            continue
        match = re.fullmatch(r"([A-Z][A-Z0-9_]*)\s*=\s*(.+)", token)
        if match is None:
            raise UsbCheckError(f"malformed USB constant {token!r}")
        name = match.group(1)
        if name in values:
            raise UsbCheckError(f"duplicate USB constant {name}")
        values[name] = parse_integer(match.group(2))
    return values


def parse_sdkconfig(text):
    values = {}
    duplicates = set()
    for raw in text.splitlines():
        line = raw.strip()
        name = None
        value = None
        if line.startswith("# CONFIG_") and line.endswith(" is not set"):
            name = line[2:-11]
            value = "n"
        elif line.startswith("CONFIG_") and "=" in line:
            name, value = line.split("=", 1)
        if name is None:
            continue
        if name in values:
            duplicates.add(name)
        else:
            values[name] = value
    return values, duplicates


def kconfig_default(text, name):
    clean = strip_c_comments(text)
    starts = list(re.finditer(r"(?m)^config\s+([A-Z0-9_]+)\s*$", clean))
    found = [index for index, match in enumerate(starts) if match.group(1) == name]
    if len(found) != 1:
        raise UsbCheckError(f"expected one Kconfig entry for {name}")
    index = found[0]
    start = starts[index].end()
    end = starts[index + 1].start() if index + 1 < len(starts) else len(clean)
    defaults = re.findall(r"(?m)^\s*default\s+([^\s]+)\s*$", clean[start:end])
    if len(defaults) != 1:
        raise UsbCheckError(f"expected one unconditional default for {name}")
    return parse_integer(defaults[0])


def _signed(value, size):
    if size == 0:
        return 0
    sign = 1 << (size * 8 - 1)
    return value - (1 << (size * 8)) if value & sign else value


def parse_hid_descriptor(data):
    position = 0
    usage_page = None
    logical_minimum = None
    logical_maximum = None
    report_size = None
    report_count = None
    global_stack = []
    local_usages = []
    usage_minimum = None
    usage_maximum = None
    collections = []
    collection_count = 0
    application_collections = []
    reports = []
    report_ids = []

    while position < len(data):
        prefix = data[position]
        position += 1
        if prefix == 0xFE:
            raise UsbCheckError("long HID items are not allowed")
        size_code = prefix & 0x03
        size = 4 if size_code == 3 else size_code
        if position + size > len(data):
            raise UsbCheckError("truncated HID item")
        raw = data[position : position + size]
        position += size
        value = int.from_bytes(raw, "little") if raw else 0
        item_type = (prefix >> 2) & 0x03
        tag = (prefix >> 4) & 0x0F

        if item_type == 1:
            if tag == 0:
                usage_page = value
            elif tag == 1:
                logical_minimum = _signed(value, size)
            elif tag == 2:
                logical_maximum = (
                    _signed(value, size)
                    if logical_minimum is not None and logical_minimum < 0
                    else value
                )
            elif tag == 7:
                report_size = value
            elif tag == 8:
                report_ids.append(value)
            elif tag == 9:
                report_count = value
            elif tag == 10:
                if size != 0:
                    raise UsbCheckError("HID global push has data")
                global_stack.append(
                    (
                        usage_page,
                        logical_minimum,
                        logical_maximum,
                        report_size,
                        report_count,
                    )
                )
            elif tag == 11:
                if size != 0 or not global_stack:
                    raise UsbCheckError("unbalanced HID global pop")
                (
                    usage_page,
                    logical_minimum,
                    logical_maximum,
                    report_size,
                    report_count,
                ) = global_stack.pop()
            continue

        if item_type == 2:
            if tag == 0:
                local_usages.append(value)
            elif tag == 1:
                usage_minimum = value
            elif tag == 2:
                usage_maximum = value
            continue

        if item_type != 0:
            continue

        usage = None
        usage_is_single = False
        if len(local_usages) == 1 and usage_minimum is None and \
           usage_maximum is None:
            usage = local_usages[0]
            usage_is_single = True
        elif not local_usages and usage_minimum is not None and \
             usage_minimum == usage_maximum:
            usage = usage_minimum
            usage_is_single = True
        if tag == 10:
            collection_count += 1
            collections.append((value, usage_page, usage, usage_is_single))
            if value == 1:
                application_collections.append(
                    (usage_page, usage) if usage_is_single else (None, None)
                )
        elif tag == 12:
            if size != 0 or not collections:
                raise UsbCheckError("unbalanced HID end collection")
            collections.pop()
        elif tag in (8, 9, 11):
            application = next(
                (
                    (page, app_usage)
                    for collection_type, page, app_usage, valid in reversed(collections)
                    if collection_type == 1 and valid
                ),
                None,
            )
            reports.append(
                {
                    "kind": {8: "input", 9: "output", 11: "feature"}[tag],
                    "usage_page": usage_page,
                    "usage": usage,
                    "logical_minimum": logical_minimum,
                    "logical_maximum": logical_maximum,
                    "report_size": report_size,
                    "report_count": report_count,
                    "flags": value,
                    "usage_is_single": usage_is_single,
                    "application_collection": application,
                }
            )
        local_usages = []
        usage_minimum = None
        usage_maximum = None

    if collections:
        raise UsbCheckError("unterminated HID collection")
    if global_stack:
        raise UsbCheckError("unterminated HID global push")
    return {
        "collection_count": collection_count,
        "application_collections": application_collections,
        "reports": reports,
        "report_ids": report_ids,
    }


def check_report_descriptor(data, require_exact=True):
    errors = []
    facts = {}
    try:
        parsed = parse_hid_descriptor(data)
    except UsbCheckError as error:
        return facts, [str(error)]

    facts["descriptor bytes"] = len(data)
    facts["application collections"] = len(parsed["application_collections"])
    facts["report IDs"] = len(parsed["report_ids"])
    if len(parsed["application_collections"]) == 1:
        facts["usage page"] = parsed["application_collections"][0][0]
        facts["application usage"] = parsed["application_collections"][0][1]
    if require_exact and len(data) != REPORT_DESC_BYTES:
        errors.append(f"report descriptor length is {len(data)} not 34")
    if require_exact and data != EXPECTED_REPORT_DESCRIPTOR:
        errors.append("report descriptor bytes differ from the pinned FIDO form")
    if parsed["collection_count"] != 1:
        errors.append("report descriptor does not have exactly one collection")
    if parsed["application_collections"] != [(0xF1D0, 0x01)]:
        errors.append("application usage page or usage is not FIDO CTAPHID")
    if parsed["report_ids"]:
        errors.append("report descriptor contains a report ID item")

    expected = {
        "input": (0x20, 0, 255, 8, 64, 0x02),
        "output": (0x21, 0, 255, 8, 64, 0x02),
    }
    for kind, wanted in expected.items():
        matching = [report for report in parsed["reports"] if report["kind"] == kind]
        if len(matching) != 1:
            errors.append(f"report descriptor does not have exactly one {kind} item")
            continue
        report = matching[0]
        observed = (
            report["usage"],
            report["logical_minimum"],
            report["logical_maximum"],
            report["report_size"],
            report["report_count"],
            report["flags"],
        )
        facts[f"{kind} usage"] = report["usage"]
        facts[f"{kind} report bytes"] = (
            report["report_size"] * report["report_count"] // 8
            if report["report_size"] is not None
            and report["report_count"] is not None
            else None
        )
        if report["usage_page"] != 0xF1D0 or observed != wanted:
            errors.append(f"{kind} report fields do not match the FIDO descriptor")
        if not report["usage_is_single"]:
            errors.append(f"{kind} report does not have one unambiguous usage")
        if report["application_collection"] != (0xF1D0, 0x01):
            errors.append(f"{kind} report is outside the FIDO application collection")
    if any(report["kind"] == "feature" for report in parsed["reports"]):
        errors.append("report descriptor contains a feature report")
    return facts, errors


def validate_fido_report_descriptor(data):
    """Validate one exact FIDO HID descriptor and return parsed facts."""
    facts, errors = check_report_descriptor(bytes(data), require_exact=True)
    if errors:
        raise UsbCheckError("; ".join(errors))
    return facts


def check_configuration_descriptor(data):
    errors = []
    records = []
    position = 0
    while position < len(data):
        if position + 2 > len(data):
            return {}, ["truncated USB descriptor header"]
        length = data[position]
        if length < 2 or position + length > len(data):
            return {}, ["invalid USB descriptor length"]
        records.append(data[position : position + length])
        position += length

    facts = {"configuration bytes": len(data)}
    if len(data) != CONFIG_DESC_BYTES:
        errors.append(f"configuration descriptor length is {len(data)} not 41")
    configs = [record for record in records if record[1] == 0x02]
    interfaces = [record for record in records if record[1] == 0x04]
    hids = [record for record in records if record[1] == 0x21]
    endpoints = [record for record in records if record[1] == 0x05]
    if len(configs) != 1 or len(configs[0]) != 9:
        errors.append("configuration descriptor header count or size is wrong")
    else:
        config = configs[0]
        if int.from_bytes(config[2:4], "little") != len(data):
            errors.append("configuration total length does not match its bytes")
        if config[4] != 1:
            errors.append("configuration does not advertise one interface")
        if config[5] != 1:
            errors.append("configuration value is not one")
    if len(interfaces) != 1 or len(interfaces[0]) != 9:
        errors.append("configuration does not contain exactly one interface")
    else:
        interface = interfaces[0]
        facts["interface class"] = interface[5]
        if interface[2:8] != bytes((0, 0, 2, 3, 0, 0)):
            errors.append(
                "interface is not number zero alternate zero with two HID 3/0/0 endpoints"
            )
    if len(hids) != 1 or len(hids[0]) != 9:
        errors.append("configuration does not contain exactly one HID descriptor")
    elif hids[0][2:9] != bytes((0x11, 0x01, 0x00, 0x01, 0x22, 34, 0)):
        errors.append("HID 1.11 subordinate report descriptor fields are wrong")
    if len(endpoints) != 2:
        errors.append("configuration does not contain two endpoints")
    else:
        endpoint_facts = []
        for endpoint in endpoints:
            if len(endpoint) != 7:
                errors.append("endpoint descriptor size is not seven")
                continue
            endpoint_facts.append(
                (
                    endpoint[2],
                    endpoint[3],
                    int.from_bytes(endpoint[4:6], "little"),
                    endpoint[6],
                )
            )
        wanted = [(0x01, 3, 64, 5), (0x81, 3, 64, 5)]
        facts["endpoints"] = endpoint_facts
        if endpoint_facts != wanted:
            errors.append("interrupt endpoints do not match OUT 01 IN 81 size 64 interval 5")
    allowed_types = (0x02, 0x04, 0x21, 0x05)
    if any(record[1] not in allowed_types for record in records):
        errors.append("configuration contains a non-HID descriptor type")
    return facts, errors


def _function_body(text, name):
    matches = list(re.finditer(rf"\b{re.escape(name)}\s*\([^;]*?\)\s*\{{", text, re.DOTALL))
    if len(matches) != 1:
        raise UsbCheckError(f"expected one definition for {name}")
    opening = matches[0].end() - 1
    depth = 0
    for offset in range(opening, len(text)):
        if text[offset] == "{":
            depth += 1
        elif text[offset] == "}":
            depth -= 1
            if depth == 0:
                return text[opening + 1 : offset]
    raise UsbCheckError(f"unterminated function {name}")


def check_source_policy(usb_source, main_source):
    errors = []
    try:
        take = re.sub(r"\s+", " ", _function_body(usb_source, "usb_take"))
        take_token = re.sub(
            r"\s+", " ", _function_body(usb_source, "usb_take_with_generation")
        )
        take_common = re.sub(
            r"\s+", " ", _function_body(usb_source, "usb_take_common")
        )
        send = re.sub(r"\s+", " ", _function_body(usb_source, "usb_send"))
        send_token = re.sub(
            r"\s+", " ", _function_body(usb_source, "usb_send_for_generation")
        )
        send_common = re.sub(
            r"\s+", " ", _function_body(usb_source, "usb_send_common")
        )
        event = re.sub(r"\s+", " ", _function_body(usb_source, "usb_event"))
        callback = re.sub(
            r"\s+", " ", _function_body(usb_source, "tud_hid_set_report_cb")
        )
    except UsbCheckError as error:
        return [str(error)]

    rx_gate = (
        "xSemaphoreTake(s_rx_wake, remaining) != pdTRUE || "
        "xTaskCheckForTimeOut(&timeout, &remaining) == pdTRUE"
    )
    if rx_gate not in take_common:
        errors.append("usb_take receive wake can bypass its overall deadline")
    if "usb_take_common(report, wait_ms, NULL, true)" not in take or \
       "usb_take_common(report, wait_ms, generation, false)" not in take_token:
        errors.append("USB legacy and generation take paths are not distinct")
    if "*out_generation = item.generation" not in take_common:
        errors.append("USB generation take does not return the dequeued report token")

    mutex = "xSemaphoreTake(s_tx_mutex, remaining)"
    post_mutex = (
        "if (!zero_wait && xTaskCheckForTimeOut(&timeout, &remaining) == pdTRUE)"
    )
    loop = "for (;;)"
    if not (mutex in send_common and post_mutex in send_common and
            loop in send_common):
        errors.append("usb_send lacks the post-mutex deadline gate")
    elif not (send_common.index(mutex) < send_common.index(post_mutex) <
              send_common.index(loop)):
        errors.append("usb_send post-mutex deadline gate is out of order")
    tx_gate = (
        "xSemaphoreTake(s_tx_wake, remaining) != pdTRUE || "
        "xTaskCheckForTimeOut(&timeout, &remaining) == pdTRUE"
    )
    if tx_gate not in send_common:
        errors.append("usb_send endpoint wake can bypass its overall deadline")
    if "P4_USB_SEND_LEGACY" not in send or \
       "P4_USB_SEND_GENERATION" not in send_token:
        errors.append("USB send paths do not separate legacy and saved generation")
    if "generation != expected_generation" not in send_common:
        errors.append("USB saved generation is not checked during endpoint waits")

    required_event_fragments = (
        "case TINYUSB_EVENT_ATTACHED: p4_usb_queue_reset(&s_rx_queue); "
        "s_have_take_generation = false; s_mounted = true; s_ready = true;",
        "case TINYUSB_EVENT_DETACHED: s_mounted = false; s_ready = false;",
        "case TINYUSB_EVENT_SUSPENDED: s_ready = false;",
        "case TINYUSB_EVENT_RESUMED:",
        "s_ready = s_mounted;",
    )
    for fragment in required_event_fragments:
        if fragment not in event:
            errors.append("USB suspend resume readiness is not gated by mount state")
            break
    if "case TINYUSB_EVENT_RESUMED: s_ready = true;" in event:
        errors.append("USB resume marks ready without a mounted configuration")

    forbidden_callback = ("ESP_LOG", "malloc", "calloc", "usb_send(", "crypto_", "nvs_")
    if any(token in callback for token in forbidden_callback):
        errors.append("HID OUT callback performs forbidden work")
    for required in (
        "report_id != 0",
        "bufsize != P4_USB_REPORT_BYTES",
        "p4_usb_queue_push(&s_rx_queue, buffer, s_generation)",
    ):
        if required not in callback:
            errors.append("HID OUT callback lacks a bounded receive policy")
            break

    if "#if CONFIG_P4KEY_USB_BRINGUP" not in main_source:
        errors.append("bringup exchange is not compile-time gated")
    if "memcmp(report, s_usb_bringup_request" not in main_source or \
       "usb_send(s_usb_bringup_response" not in main_source:
        errors.append("bringup task does not require the exact fixed request")
    if "usb_send(report" in main_source:
        errors.append("normal source contains an arbitrary packet echo")
    return errors


def check_native_usb_route(board_source, usb_source, defaults_text):
    errors = []
    board = re.sub(r"\s+", " ", strip_c_comments(board_source))
    required = (
        "P4_BOARD_USB_FS_PHY_INDEX = 0",
        "P4_BOARD_USB_DM_GPIO = GPIO_NUM_24",
        "P4_BOARD_USB_DP_GPIO = GPIO_NUM_25",
        "usb_wrap_ll_phy_select(&USB_WRAP, P4_BOARD_USB_FS_PHY_INDEX);",
    )
    if any(fragment not in board for fragment in required):
        errors.append("native Type-C is not routed to OTG1.1 FS PHY0")
    if board.count("GPIO_DRIVE_CAP_3") != 2:
        errors.append("native Type-C PHY pins do not both request 40 mA drive")
    if "#ifndef CONFIG_USJ_ENABLE_USB_SERIAL_JTAG" not in board_source:
        errors.append("native Type-C PHY0 clock lacks a compile guard")
    if "CONFIG_USJ_ENABLE_USB_SERIAL_JTAG=y" not in defaults_text:
        errors.append("native Type-C PHY0 clock source is not pinned")

    try:
        start = re.sub(r"\s+", " ", _function_body(usb_source, "usb_start"))
        prepare = start.index("p4_board_usb_prepare()")
        install = start.index("tinyusb_driver_install(&config)")
        if prepare >= install:
            errors.append("native Type-C PHY route is selected after TinyUSB starts")
    except (UsbCheckError, ValueError):
        errors.append("USB start does not prepare the native Type-C PHY route")
    return errors


def check_project_source(root=REPO):
    root = Path(root)
    facts = {}
    errors = []
    try:
        header = read_text(root / "components/p4_usb/include/p4_usb_desc.h")
        desc_source = read_text(root / "components/p4_usb/p4_usb_desc.c")
        usb_source = read_text(root / "components/p4_usb/p4_usb.c")
        board_source = read_text(root / "components/p4_board/p4_board.c")
        main_source = read_text(root / "main/app_main.c")
        kconfig = read_text(root / "components/p4_usb/Kconfig")
        defaults_text = read_text(root / "sdkconfig.defaults")
        bringup_defaults_text = read_text(root / "sdkconfig.usb-bringup.defaults")

        constants = parse_header_constants(header)
        for name, expected in EXPECTED_CONSTANTS.items():
            observed = constants.get(name)
            facts[name] = observed
            if observed != expected:
                errors.append(f"{name} expected {expected} got {observed}")

        vid = kconfig_default(kconfig, "P4KEY_USB_VID")
        pid = kconfig_default(kconfig, "P4KEY_USB_PID")
        facts["VID"] = vid
        facts["PID"] = pid
        if vid != DEFAULT_VID or pid != DEFAULT_PID:
            errors.append("Kconfig VID PID defaults are not 303a:4004")

        defaults, duplicates = parse_sdkconfig(defaults_text)
        if duplicates:
            errors.append("sdkconfig.defaults contains duplicate assignments")
        for name, expected in EXPECTED_DEFAULTS.items():
            observed = defaults.get(name, "missing")
            if observed != expected:
                errors.append(f"{name} expected {expected} got {observed}")

        bringup_defaults, bringup_duplicates = parse_sdkconfig(
            bringup_defaults_text
        )
        if bringup_duplicates or bringup_defaults != {
            "CONFIG_P4KEY_USB_BRINGUP": "y"
        }:
            errors.append(
                "sdkconfig.usb-bringup.defaults must contain only the bringup flag"
            )

        report = extract_c_array(desc_source, "p4_usb_report_desc")
        report_facts, report_errors = check_report_descriptor(report, True)
        facts.update(report_facts)
        errors.extend(report_errors)

        config = extract_c_array(desc_source, "p4_usb_config_desc", CONFIG_SYMBOLS)
        config_facts, config_errors = check_configuration_descriptor(config)
        facts.update(config_facts)
        errors.extend(config_errors)

        if not re.search(r"\.iSerialNumber\s*=\s*0x00\s*,", desc_source):
            errors.append("device descriptor does not explicitly omit the serial string")
        if not re.search(r"\.bDeviceClass\s*=\s*0x00\s*,", desc_source):
            errors.append("USB class is not kept on the interface")
        if not re.search(r"\.bNumConfigurations\s*=\s*0x01\s*,", desc_source):
            errors.append("device descriptor does not advertise one configuration")
        guard = re.sub(r"\s+", " ", strip_c_comments(desc_source))
        for symbol in (
            "CFG_TUD_CDC", "CFG_TUD_MSC", "CFG_TUD_MIDI", "CFG_TUD_VENDOR",
            "CFG_TUD_ECM_RNDIS", "CFG_TUD_NCM", "CFG_TUD_DFU",
            "CFG_TUD_DFU_RUNTIME", "CFG_TUD_BTH",
        ):
            if symbol not in guard:
                errors.append(f"descriptor compile guard omits {symbol}")

        errors.extend(check_source_policy(usb_source, main_source))
        errors.extend(check_native_usb_route(
            board_source, usb_source, defaults_text))
    except UsbCheckError as error:
        errors.append(str(error))
    return facts, sorted(set(errors))


def project_vid_pid(root=REPO):
    text = read_text(Path(root) / "components/p4_usb/Kconfig")
    return (
        kconfig_default(text, "P4KEY_USB_VID"),
        kconfig_default(text, "P4KEY_USB_PID"),
    )


def load_hid():
    try:
        return importlib.import_module("hid")
    except ImportError as error:
        raise UsbCheckError(
            "hidapi is unavailable; install requirements-host.txt"
        ) from error


def matching_hid_devices(hid_module, vid, pid):
    try:
        devices = hid_module.enumerate(vid, pid)
    except Exception as error:
        raise UsbCheckError("HID enumeration failed") from error
    return [
        device
        for device in devices
        if device.get("vendor_id") == vid and device.get("product_id") == pid
    ]


def fido_hid_devices(hid_module, vid, pid):
    candidates = []
    for device in matching_hid_devices(hid_module, vid, pid):
        interface = device.get("interface_number")
        usage_page = device.get("usage_page")
        usage = device.get("usage")
        if interface not in (None, -1, 0):
            continue
        if usage_page is not None and usage_page != 0xF1D0:
            continue
        if usage is not None and usage != 0x01:
            continue
        candidates.append(device)
    return candidates


def path_text(path):
    if isinstance(path, bytes):
        return path.decode("utf-8", errors="backslashreplace")
    return str(path)


def select_hid_device(devices, selected_path=None):
    if selected_path is not None:
        matches = [
            device for device in devices
            if path_text(device.get("path", "")) == selected_path
        ]
        if len(matches) != 1:
            raise UsbCheckError("the requested matching HID path was not found")
        return matches[0]
    if len(devices) != 1:
        raise UsbCheckError(
            f"expected one matching HID device and found {len(devices)}; use --path"
        )
    return devices[0]


def open_hid_path(hid_module, record):
    path = record.get("path")
    if not isinstance(path, (bytes, str)) or not path:
        raise UsbCheckError("matching HID record has no usable path")
    device = hid_module.device()
    try:
        device.open_path(path)
    except Exception as error:
        try:
            device.close()
        except Exception:
            pass
        raise UsbCheckError("matching HID device could not be opened") from error
    return device


def parse_lsusb_verbose(text, expected_vid=DEFAULT_VID, expected_pid=DEFAULT_PID):
    facts = {}
    errors = []

    def one(pattern, label, base=10):
        matches = re.findall(pattern, text, re.MULTILINE)
        if len(matches) != 1:
            errors.append(f"lsusb field {label} is unavailable or duplicated")
            return None
        value = int(matches[0], base)
        facts[label] = value
        return value

    vid = one(r"^\s*idVendor\s+0x([0-9a-fA-F]{4})\b", "VID", 16)
    pid = one(r"^\s*idProduct\s+0x([0-9a-fA-F]{4})\b", "PID", 16)
    device_class = one(r"^\s*bDeviceClass\s+([0-9]+)\b", "device class")
    configurations = one(
        r"^\s*bNumConfigurations\s+([0-9]+)\b", "configurations"
    )
    interfaces = re.findall(r"^\s*bInterfaceClass\s+([0-9]+)\b", text, re.MULTILINE)
    subclasses = re.findall(r"^\s*bInterfaceSubClass\s+([0-9]+)\b", text, re.MULTILINE)
    protocols = re.findall(r"^\s*bInterfaceProtocol\s+([0-9]+)\b", text, re.MULTILINE)
    endpoint_counts = re.findall(r"^\s*bNumEndpoints\s+([0-9]+)\b", text, re.MULTILINE)
    facts["interface classes"] = [int(value) for value in interfaces]

    if vid != expected_vid or pid != expected_pid:
        errors.append("lsusb VID PID does not match the project")
    if device_class != 0 or configurations != 1:
        errors.append("lsusb device class or configuration count is wrong")
    if interfaces != ["3"] or subclasses != ["0"] or protocols != ["0"]:
        errors.append("lsusb does not show exactly one HID 3/0/0 interface")
    if endpoint_counts != ["2"]:
        errors.append("lsusb HID interface does not show two endpoints")

    endpoint_blocks = re.split(r"(?m)^\s*Endpoint Descriptor:\s*$", text)[1:]
    endpoints = []
    for block in endpoint_blocks:
        block = re.split(
            r"(?m)^\s*(?:Endpoint|Interface|Device Qualifier|Configuration) Descriptor:\s*$",
            block,
            maxsplit=1,
        )[0]
        address = re.search(r"(?m)^\s*bEndpointAddress\s+0x([0-9a-fA-F]{2})\b", block)
        attributes = re.search(r"(?m)^\s*bmAttributes\s+([0-9]+)\b", block)
        packet = re.search(
            r"(?m)^\s*wMaxPacketSize\s+0x[0-9a-fA-F]+\s+(?:[0-9]+x\s+)?([0-9]+) bytes",
            block,
        )
        interval = re.search(r"(?m)^\s*bInterval\s+([0-9]+)\b", block)
        if None in (address, attributes, packet, interval):
            errors.append("lsusb endpoint facts are unavailable")
            continue
        endpoints.append(
            (
                int(address.group(1), 16),
                int(attributes.group(1)) & 0x03,
                int(packet.group(1)),
                int(interval.group(1)),
            )
        )
    facts["endpoints"] = endpoints
    if endpoints != [(0x01, 3, 64, 5), (0x81, 3, 64, 5)]:
        errors.append("lsusb endpoints do not match OUT 01 IN 81 size 64 interval 5")

    report_lengths = re.findall(
        r"(?m)^\s*wDescriptorLength\s+([0-9]+)\b", text
    )
    if report_lengths != ["34"]:
        errors.append("lsusb HID report descriptor length is unavailable or not 34")
    else:
        facts["report descriptor bytes"] = 34
    return facts, sorted(set(errors))


def run_lsusb(vid, pid):
    try:
        result = subprocess.run(
            ["lsusb", "-v", "-d", f"{vid:04x}:{pid:04x}"],
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise UsbCheckError("filtered lsusb command is unavailable") from error
    if result.returncode != 0 or not result.stdout.strip():
        raise UsbCheckError("filtered lsusb found no readable matching device")
    return result.stdout
