import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]
SCRIPTS = REPO / "scripts"
USB_SOURCE = REPO / "components" / "p4_usb" / "p4_usb.c"
BOARD_SOURCE = REPO / "components" / "p4_board" / "p4_board.c"
SDKCONFIG_DEFAULTS = REPO / "sdkconfig.defaults"
DESC_SOURCE = REPO / "components" / "p4_usb" / "p4_usb_desc.c"
DESC_HEADER = REPO / "components" / "p4_usb" / "include" / "p4_usb_desc.h"
QUEUE_SOURCE = REPO / "components" / "p4_usb" / "p4_usb_queue.c"
QUEUE_INCLUDE = REPO / "components" / "p4_usb"
PUBLIC_INCLUDE = REPO / "components" / "p4_usb" / "include"

sys.path.insert(0, str(SCRIPTS))
import usb_common  # noqa: E402


EXPECTED_REPORT_DESCRIPTOR = bytes.fromhex(
    "06 d0 f1 09 01 a1 01 "
    "09 20 15 00 26 ff 00 75 08 95 40 81 02 "
    "09 21 15 00 26 ff 00 75 08 95 40 91 02 c0"
)


def c_case_body(source, case_name):
    match = re.search(
        rf"case\s+{re.escape(case_name)}\s*:(.*?)(?:\bbreak\s*;)",
        source,
        flags=re.DOTALL,
    )
    if match is None:
        raise AssertionError(f"missing case {case_name}")
    return re.sub(r"\s+", " ", match.group(1))


FAKE_HID = r'''
import json
import os


MATCH_PATH = b"p4key-match-path"
OTHER_PATH = b"unrelated-path"
SAME_ID_WRONG_USAGE_PATH = b"same-id-wrong-usage"
RESPONSE = b"P4KEY USB BRINGUP RESPONSE v1".ljust(64, b"\0")
REPORT_DESCRIPTOR = bytes.fromhex(
    "06 d0 f1 09 01 a1 01 "
    "09 20 15 00 26 ff 00 75 08 95 40 81 02 "
    "09 21 15 00 26 ff 00 75 08 95 40 91 02 c0"
)


def _safe(value):
    if isinstance(value, bytes):
        return {"bytes_hex": value.hex(), "bytes_text": value.decode("utf-8", "replace")}
    if isinstance(value, (list, tuple)):
        return [_safe(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _safe(item) for key, item in value.items()}
    return value


def _record(event, **fields):
    path = os.environ.get("HID_FAKE_LOG")
    if not path:
        return
    row = {"event": event, **{key: _safe(value) for key, value in fields.items()}}
    with open(path, "a", encoding="utf-8") as output:
        output.write(json.dumps(row, sort_keys=True) + "\n")


def enumerate(vendor_id=0, product_id=0):
    _record("enumerate", vendor_id=vendor_id, product_id=product_id)
    # deliberately return an unrelated record too
    # callers must retain their own VID PID filter
    return [
        {
            "path": OTHER_PATH,
            "vendor_id": 0x9999,
            "product_id": 0x8888,
            "interface_number": 7,
            "usage_page": 0x0001,
            "usage": 0x0002,
            "max_input_report_len": 8,
            "max_output_report_len": 8,
        },
        {
            "path": MATCH_PATH,
            "vendor_id": 0x303A,
            "product_id": 0x4004,
            "interface_number": 0,
            "usage_page": 0xF1D0,
            "usage": 0x01,
            "max_input_report_len": 64,
            "max_output_report_len": 64,
            "manufacturer_string": "P4Key project",
            "product_string": "P4Key Dev",
        },
        {
            "path": SAME_ID_WRONG_USAGE_PATH,
            "vendor_id": 0x303A,
            "product_id": 0x4004,
            "interface_number": 0,
            "usage_page": 0x0001,
            "usage": 0x0002,
            "max_input_report_len": 64,
            "max_output_report_len": 64,
        },
    ]


class device:
    def __init__(self, *args, **kwargs):
        self.closed = False
        _record("construct")
        path = kwargs.get("path")
        if path is not None:
            self.open_path(path)

    def open_path(self, path):
        _record("open_path", path=path)
        if path != MATCH_PATH and path != MATCH_PATH.decode("ascii"):
            raise OSError("refusing unrelated HID path")
        if os.environ.get("HID_FAKE_MODE") == "open-error":
            raise OSError("planted open failure")

    def write(self, data):
        raw = bytes(data)
        _record("write", data=raw, length=len(raw))
        if os.environ.get("HID_FAKE_MODE") == "write-error":
            raise OSError("planted write failure")
        return len(raw)

    def read(self, length, timeout_ms=None):
        _record("read", length=length, timeout_ms=timeout_ms)
        mode = os.environ.get("HID_FAKE_MODE", "success")
        if mode == "read-error":
            raise OSError("planted read failure")
        if mode == "timeout":
            return []
        if mode == "short":
            return list(RESPONSE[:-1])
        if mode == "wrong-response":
            return list(b"X" + RESPONSE[1:])
        return list(RESPONSE)

    def get_report_descriptor(self, *args):
        _record("get_report_descriptor", args=args)
        if os.environ.get("HID_FAKE_MODE") == "wrong-descriptor":
            return list(REPORT_DESCRIPTOR.replace(b"\x09\x21", b"\x09\x22", 1))
        return list(REPORT_DESCRIPTOR)

    def close(self):
        if not self.closed:
            self.closed = True
            _record("close")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()


class Device(device):
    pass
'''


QUEUE_HARNESS = r'''
#include "p4_usb_queue.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>


static int report_is(const uint8_t report[P4_USB_REPORT_BYTES], uint8_t value)
{
    for (size_t i = 0; i < P4_USB_REPORT_BYTES; i++) {
        if (report[i] != value) {
            return 0;
        }
    }
    return 1;
}


int main(void)
{
    p4_usb_queue_t queue;
    p4_usb_queue_item_t item;
    uint8_t report[P4_USB_REPORT_BYTES];

    p4_usb_queue_init(&queue);
    if (p4_usb_queue_count(&queue) != 0 ||
        p4_usb_queue_pop(&queue, &item)) {
        return 1;
    }

    for (uint8_t value = 0; value < P4_USB_RX_QUEUE_DEPTH; value++) {
        memset(report, value, sizeof(report));
        if (!p4_usb_queue_push(&queue, report, 100u + value)) {
            return 2;
        }
    }
    if (p4_usb_queue_count(&queue) != 8) {
        return 3;
    }

    memset(report, 0xee, sizeof(report));
    if (p4_usb_queue_push(&queue, report, 999u) ||
        p4_usb_queue_count(&queue) != 8) {
        return 4;
    }

    for (uint8_t value = 0; value < 3; value++) {
        if (!p4_usb_queue_pop(&queue, &item) ||
            !report_is(item.report, value) ||
            item.generation != 100u + value) {
            return 5;
        }
    }

    for (uint8_t value = 20; value < 23; value++) {
        memset(report, value, sizeof(report));
        if (!p4_usb_queue_push(&queue, report, 200u + value)) {
            return 6;
        }
    }

    for (uint8_t value = 3; value < 8; value++) {
        if (!p4_usb_queue_pop(&queue, &item) ||
            !report_is(item.report, value) ||
            item.generation != 100u + value) {
            return 7;
        }
    }
    for (uint8_t value = 20; value < 23; value++) {
        if (!p4_usb_queue_pop(&queue, &item) ||
            !report_is(item.report, value) ||
            item.generation != 200u + value) {
            return 8;
        }
    }
    if (p4_usb_queue_count(&queue) != 0 ||
        p4_usb_queue_pop(&queue, &item)) {
        return 9;
    }

    memset(report, 0x5a, sizeof(report));
    if (!p4_usb_queue_push(&queue, report, 77u)) {
        return 10;
    }
    p4_usb_queue_reset(&queue);
    if (p4_usb_queue_count(&queue) != 0 ||
        p4_usb_queue_pop(&queue, &item)) {
        return 11;
    }

    puts("PASS USB queue depth overflow order empty reset");
    return 0;
}
'''


class UsbSourceTests(unittest.TestCase):
    def test_report_descriptor_has_exact_fido_shape(self):
        report, unused_config = usb_common.load_source_descriptors(REPO)
        self.assertEqual(report, EXPECTED_REPORT_DESCRIPTOR)
        facts = usb_common.validate_fido_report_descriptor(report)
        self.assertEqual(facts["descriptor bytes"], 34)
        self.assertEqual(facts["application collections"], 1)
        self.assertEqual(facts["usage page"], 0xF1D0)
        self.assertEqual(facts["application usage"], 0x01)
        self.assertEqual(facts["report IDs"], 0)
        self.assertEqual(facts["input usage"], 0x20)
        self.assertEqual(facts["output usage"], 0x21)
        self.assertEqual(facts["input report bytes"], 64)
        self.assertEqual(facts["output report bytes"], 64)

    def test_report_descriptor_rejects_required_negative_mutations(self):
        report, unused_config = usb_common.load_source_descriptors(REPO)
        mutations = {
            "planted report ID": (
                report[:18] + b"\x85\x01" + report[18:],
                "contains a report ID item",
            ),
            "report count 63": (
                report.replace(b"\x95\x40", b"\x95\x3f", 1),
                "input report fields",
            ),
            "missing output usage": (
                report.replace(b"\x09\x21", b"\x09\x22", 1),
                "output report fields",
            ),
            "truncated collection": (
                report[:-1],
                "unterminated HID collection",
            ),
            "reports outside collection": (
                report[:7] + b"\xc0" + report[7:-1],
                "outside the FIDO application collection",
            ),
            "global pop restores wrong usage page": (
                report[:7]
                + bytes.fromhex("05 01 a4 06 d0 f1 b4")
                + report[7:],
                "input report fields",
            ),
        }
        for label, (mutated, semantic_error) in mutations.items():
            with self.subTest(label=label):
                with self.assertRaises(ValueError):
                    usb_common.validate_fido_report_descriptor(mutated)
                unused_facts, errors = usb_common.check_report_descriptor(
                    mutated, require_exact=False
                )
                self.assertTrue(
                    any(semantic_error in error for error in errors),
                    errors,
                )

    def test_live_check_accepts_semantically_equivalent_reconstruction(self):
        report, unused_config = usb_common.load_source_descriptors(REPO)
        reconstructed = report.replace(
            b"\x09\x20", b"\x19\x20\x29\x20", 1
        ).replace(
            b"\x09\x21", b"\x19\x21\x29\x21", 1
        )
        reconstructed = reconstructed[:7] + bytes.fromhex(
            "a4 05 01 b4"
        ) + reconstructed[7:]

        facts, errors = usb_common.check_report_descriptor(
            reconstructed, require_exact=False
        )
        self.assertEqual(errors, [])
        self.assertEqual(facts["descriptor bytes"], 42)
        with self.assertRaises(ValueError):
            usb_common.validate_fido_report_descriptor(reconstructed)

    def test_configuration_is_one_fido_hid_with_two_interrupt_endpoints(self):
        report, config = usb_common.load_source_descriptors(REPO)
        self.assertEqual(len(config), 41)
        facts, errors = usb_common.check_configuration_descriptor(config)
        self.assertEqual(errors, [])
        self.assertEqual(facts["configuration bytes"], 41)
        self.assertEqual(facts["interface class"], 3)
        self.assertEqual(
            facts["endpoints"],
            [(0x01, 3, 64, 5), (0x81, 3, 64, 5)],
        )
        self.assertEqual(int.from_bytes(config[2:4], "little"), len(config))
        self.assertEqual(config[4], 1)
        self.assertEqual(config[13:17], bytes((2, 3, 0, 0)))
        self.assertEqual(int.from_bytes(config[25:27], "little"), len(report))
        self.assertEqual([config[1], config[10], config[19], config[28], config[35]],
                         [0x02, 0x04, 0x21, 0x05, 0x05])

    def test_configuration_rejects_strict_field_mutations(self):
        unused_report, config = usb_common.load_source_descriptors(REPO)
        mutations = {
            "configuration value zero": (5, 0),
            "interface number seven": (11, 7),
            "alternate setting one": (12, 1),
            "HID subordinate type feature": (24, 0x23),
            "reserved endpoint attributes": (30, 0xFF),
        }
        for label, (offset, value) in mutations.items():
            with self.subTest(label=label):
                mutated = bytearray(config)
                mutated[offset] = value
                unused_facts, errors = usb_common.check_configuration_descriptor(
                    bytes(mutated)
                )
                self.assertTrue(errors)

    def test_constants_and_kconfig_keep_only_one_hid_class(self):
        constants = usb_common.parse_header_constants(
            DESC_HEADER.read_text(encoding="utf-8")
        )
        self.assertEqual(
            constants,
            {
                "P4_USB_REPORT_BYTES": 64,
                "P4_USB_RX_QUEUE_DEPTH": 8,
                "P4_USB_REPORT_DESC_BYTES": 34,
                "P4_USB_CONFIG_DESC_BYTES": 41,
                "P4_USB_EP_OUT": 0x01,
                "P4_USB_EP_IN": 0x81,
                "P4_USB_POLL_INTERVAL_MS": 5,
            },
        )

        defaults, duplicates = usb_common.parse_sdkconfig(
            (REPO / "sdkconfig.defaults").read_text(encoding="utf-8")
        )
        self.assertEqual(duplicates, set())
        expected = {
            "CONFIG_TINYUSB_HID_COUNT": "1",
            "CONFIG_TINYUSB_MSC_ENABLED": "n",
            "CONFIG_TINYUSB_CDC_ENABLED": "n",
            "CONFIG_TINYUSB_MIDI_COUNT": "0",
            "CONFIG_TINYUSB_DFU_MODE_NONE": "y",
            "CONFIG_TINYUSB_BTH_ENABLED": "n",
            "CONFIG_TINYUSB_NET_MODE_NONE": "y",
            "CONFIG_TINYUSB_VENDOR_COUNT": "0",
        }
        self.assertEqual(
            {name: defaults.get(name) for name in expected},
            expected,
        )

        descriptor_source = DESC_SOURCE.read_text(encoding="utf-8")
        self.assertRegex(descriptor_source, r"#if\s+CFG_TUD_HID\s*!=\s*1")
        for symbol in (
            "CFG_TUD_CDC",
            "CFG_TUD_MSC",
            "CFG_TUD_MIDI",
            "CFG_TUD_VENDOR",
            "CFG_TUD_ECM_RNDIS",
            "CFG_TUD_NCM",
            "CFG_TUD_DFU",
            "CFG_TUD_DFU_RUNTIME",
            "CFG_TUD_BTH",
        ):
            self.assertIn(symbol, descriptor_source)

    def test_actual_fixed_queue_depth_overflow_order_and_empty(self):
        compiler = shutil.which("cc")
        self.assertIsNotNone(compiler, "host C compiler not found")
        with tempfile.TemporaryDirectory() as temporary:
            temporary_path = Path(temporary)
            harness = temporary_path / "usb_queue_test.c"
            binary = temporary_path / "usb_queue_test"
            harness.write_text(QUEUE_HARNESS, encoding="utf-8")
            compile_result = subprocess.run(
                [
                    compiler,
                    "-std=c11",
                    "-Wall",
                    "-Wextra",
                    "-Werror",
                    "-I",
                    str(PUBLIC_INCLUDE),
                    "-I",
                    str(QUEUE_INCLUDE),
                    str(QUEUE_SOURCE),
                    str(harness),
                    "-o",
                    str(binary),
                ],
                capture_output=True,
                text=True,
                timeout=20,
            )
            self.assertEqual(
                compile_result.returncode,
                0,
                compile_result.stdout + compile_result.stderr,
            )
            run_result = subprocess.run(
                [str(binary)],
                capture_output=True,
                text=True,
                timeout=10,
            )
            self.assertEqual(
                run_result.returncode,
                0,
                run_result.stdout + run_result.stderr,
            )
            self.assertIn("PASS USB queue", run_result.stdout)

    def test_deadline_and_suspend_regression_policies(self):
        source = USB_SOURCE.read_text(encoding="utf-8")
        main_source = (REPO / "main/app_main.c").read_text(encoding="utf-8")
        self.assertEqual(usb_common.check_source_policy(source, main_source), [])

        source_without_comments = usb_common.strip_c_comments(source)
        compact = re.sub(r"\s+", " ", source_without_comments)
        self.assertIn(
            "xSemaphoreTake(s_rx_wake, remaining) != pdTRUE || "
            "xTaskCheckForTimeOut(&timeout, &remaining) == pdTRUE",
            compact,
        )
        self.assertIn(
            "xSemaphoreTake(s_tx_wake, remaining) != pdTRUE || "
            "xTaskCheckForTimeOut(&timeout, &remaining) == pdTRUE",
            compact,
        )
        send_start = compact.index("int usb_send(")
        send_loop = compact.index("for (;;)", send_start)
        mutex_wait = compact.index("xSemaphoreTake(s_tx_mutex, remaining)", send_start)
        mutex_deadline = compact.index(
            "xTaskCheckForTimeOut(&timeout, &remaining) == pdTRUE", mutex_wait
        )
        self.assertLess(mutex_wait, mutex_deadline)
        self.assertLess(mutex_deadline, send_loop)

        attached = c_case_body(source_without_comments, "TINYUSB_EVENT_ATTACHED")
        detached = c_case_body(source_without_comments, "TINYUSB_EVENT_DETACHED")
        suspended = c_case_body(source_without_comments, "TINYUSB_EVENT_SUSPENDED")
        resumed = c_case_body(source_without_comments, "TINYUSB_EVENT_RESUMED")
        self.assertIn("s_mounted = true;", attached)
        self.assertIn("s_mounted = false;", detached)
        self.assertIn("s_ready = false;", suspended)
        self.assertIn("s_generation++;", suspended)
        self.assertIn("p4_usb_queue_reset(&s_rx_queue);", suspended)
        self.assertIn("s_ready = s_mounted;", resumed)
        self.assertNotIn("s_ready = true;", resumed)

    def test_native_type_c_uses_otg_on_fs_phy_zero(self):
        board_source = usb_common.strip_c_comments(
            BOARD_SOURCE.read_text(encoding="utf-8")
        )
        board_compact = re.sub(r"\s+", " ", board_source)
        self.assertIn(
            "usb_wrap_ll_phy_select(&USB_WRAP, P4_BOARD_USB_FS_PHY_INDEX);",
            board_compact,
        )
        self.assertIn("P4_BOARD_USB_FS_PHY_INDEX = 0", board_compact)
        self.assertIn("P4_BOARD_USB_DM_GPIO = GPIO_NUM_24", board_compact)
        self.assertIn("P4_BOARD_USB_DP_GPIO = GPIO_NUM_25", board_compact)
        self.assertEqual(board_compact.count("GPIO_DRIVE_CAP_3"), 2)
        self.assertIn(
            "#ifndef CONFIG_USJ_ENABLE_USB_SERIAL_JTAG", board_source
        )
        self.assertIn(
            "CONFIG_USJ_ENABLE_USB_SERIAL_JTAG=y",
            SDKCONFIG_DEFAULTS.read_text(encoding="utf-8"),
        )

        usb_source = usb_common.strip_c_comments(
            USB_SOURCE.read_text(encoding="utf-8")
        )
        usb_start = re.sub(
            r"\s+", " ", usb_common._function_body(usb_source, "usb_start")
        )
        prepare = usb_start.index("p4_board_usb_prepare()")
        install = usb_start.index("tinyusb_driver_install(&config)")
        self.assertLess(prepare, install)

    def test_complete_project_source_checker_passes(self):
        facts, errors = usb_common.check_project_source(REPO)
        self.assertEqual(errors, [])
        self.assertEqual(facts["VID"], 0x303A)
        self.assertEqual(facts["PID"], 0x4004)


class UsbCliTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.fake_modules = self.root / "modules"
        self.fake_modules.mkdir()
        (self.fake_modules / "hid.py").write_text(FAKE_HID, encoding="utf-8")
        self.log = self.root / "hid-events.jsonl"

    def tearDown(self):
        self.temporary.cleanup()

    def run_script(self, name, arguments, mode="success", fake_hid=True):
        self.log.write_text("", encoding="utf-8")
        environment = os.environ.copy()
        environment["HID_FAKE_LOG"] = str(self.log)
        environment["HID_FAKE_MODE"] = mode
        if fake_hid:
            old_path = environment.get("PYTHONPATH")
            environment["PYTHONPATH"] = (
                str(self.fake_modules)
                if not old_path
                else str(self.fake_modules) + os.pathsep + old_path
            )
        return subprocess.run(
            [sys.executable, str(SCRIPTS / name), *arguments],
            cwd=REPO,
            env=environment,
            capture_output=True,
            text=True,
            timeout=10,
        )

    def events(self):
        return [
            json.loads(line)
            for line in self.log.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]

    def test_usb_find_filters_vid_pid_and_never_lists_unrelated_device(self):
        result = self.run_script(
            "usb_find.py",
            ["--vid", "0x303a", "--pid", "0x4004"],
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("p4key-match-path", result.stdout)
        self.assertNotIn("unrelated-path", result.stdout)
        self.assertNotIn("same-id-wrong-usage", result.stdout)
        events = self.events()
        self.assertEqual(
            [event for event in events if event["event"] == "enumerate"],
            [{"event": "enumerate", "product_id": 0x4004,
              "vendor_id": 0x303A}],
        )
        opens = [event for event in events if event["event"] == "open_path"]
        self.assertEqual(len(opens), 1)
        self.assertEqual(opens[0]["path"]["bytes_text"], "p4key-match-path")
        self.assertEqual(
            len([event for event in events if event["event"] == "close"]), 1
        )

    def test_bringup_probe_writes_no_id_plus_64_and_reads_64_finitely(self):
        result = self.run_script(
            "hid_probe.py",
            [
                "--bringup",
                "--vid",
                "0x303a",
                "--pid",
                "0x4004",
                "--timeout-ms",
                "40",
            ],
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        events = self.events()
        open_events = [event for event in events if event["event"] == "open_path"]
        self.assertEqual(len(open_events), 1)
        self.assertEqual(open_events[0]["path"]["bytes_text"], "p4key-match-path")

        writes = [event for event in events if event["event"] == "write"]
        self.assertEqual(len(writes), 1)
        wire = bytes.fromhex(writes[0]["data"]["bytes_hex"])
        self.assertEqual(len(wire), 65)
        self.assertEqual(wire[0], 0)
        self.assertEqual(
            wire[1:],
            b"P4KEY USB BRINGUP REQUEST v1".ljust(64, b"\0"),
        )

        reads = [event for event in events if event["event"] == "read"]
        self.assertGreaterEqual(len(reads), 1)
        for read in reads:
            self.assertEqual(read["length"], 64)
            self.assertIsInstance(read["timeout_ms"], int)
            self.assertGreater(read["timeout_ms"], 0)
            self.assertLessEqual(read["timeout_ms"], 40)
        self.assertEqual(
            len([event for event in events if event["event"] == "close"]), 1
        )

    def test_probe_closes_handle_on_descriptor_write_error_and_timeout(self):
        for mode in ("wrong-descriptor", "write-error", "timeout"):
            with self.subTest(mode=mode):
                result = self.run_script(
                    "hid_probe.py",
                    [
                        "--bringup",
                        "--vid",
                        "0x303a",
                        "--pid",
                        "0x4004",
                        "--timeout-ms",
                        "20",
                    ],
                    mode=mode,
                )
                self.assertNotEqual(
                    result.returncode, 0, result.stdout + result.stderr
                )
                events = self.events()
                self.assertEqual(
                    len([event for event in events if event["event"] == "close"]),
                    1,
                )
                if mode == "wrong-descriptor":
                    self.assertFalse(
                        any(event["event"] == "write" for event in events)
                    )

    def test_normal_no_response_mode_accepts_only_a_finite_timeout(self):
        arguments = [
            "--normal-no-response",
            "--vid",
            "0x303a",
            "--pid",
            "0x4004",
            "--timeout-ms",
            "20",
        ]
        timeout_result = self.run_script(
            "hid_probe.py", arguments, mode="timeout"
        )
        self.assertEqual(
            timeout_result.returncode,
            0,
            timeout_result.stdout + timeout_result.stderr,
        )
        timeout_events = self.events()
        self.assertEqual(
            len([event for event in timeout_events if event["event"] == "close"]),
            1,
        )

        response_result = self.run_script(
            "hid_probe.py", arguments, mode="success"
        )
        self.assertNotEqual(
            response_result.returncode,
            0,
            response_result.stdout + response_result.stderr,
        )
        response_events = self.events()
        self.assertEqual(
            len([event for event in response_events if event["event"] == "close"]),
            1,
        )

    def test_probe_requires_explicit_firmware_mode_before_opening(self):
        result = self.run_script(
            "hid_probe.py",
            ["--vid", "0x303a", "--pid", "0x4004"],
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(
            any(event["event"] == "open_path" for event in self.events())
        )

    def test_source_descriptor_check_does_not_require_hidapi(self):
        environment = os.environ.copy()
        environment.pop("PYTHONPATH", None)
        result = subprocess.run(
            [sys.executable, "-S", str(SCRIPTS / "usb_desc_check.py")],
            cwd=REPO,
            env=environment,
            capture_output=True,
            text=True,
            timeout=10,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("PASS one HID interface", result.stdout)
        self.assertIn("UNAVAILABLE live HID facts not requested", result.stdout)


if __name__ == "__main__":
    unittest.main()
