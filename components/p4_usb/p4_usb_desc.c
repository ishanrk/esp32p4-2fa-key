#include "p4_usb_desc.h"
#include "p4_usb_desc_private.h"

#include "sdkconfig.h"

#if CFG_TUD_HID != 1
#error "P4Key requires exactly one TinyUSB HID interface"
#endif

#if CFG_TUD_CDC || CFG_TUD_MSC || CFG_TUD_MIDI || CFG_TUD_VENDOR || \
    CFG_TUD_ECM_RNDIS || CFG_TUD_NCM || CFG_TUD_DFU || \
    CFG_TUD_DFU_RUNTIME || CFG_TUD_BTH
#error "P4Key Prompt 03 permits only the HID device class"
#endif


// class is declared on the one interface
// no serial means no chip or efuse identity leaks to the host
const tusb_desc_device_t p4_usb_device_desc = {
    .bLength = sizeof(tusb_desc_device_t),
    .bDescriptorType = TUSB_DESC_DEVICE,
    .bcdUSB = 0x0200,
    .bDeviceClass = 0x00,
    .bDeviceSubClass = 0x00,
    .bDeviceProtocol = 0x00,
    .bMaxPacketSize0 = 64,
    .idVendor = CONFIG_P4KEY_USB_VID,
    .idProduct = CONFIG_P4KEY_USB_PID,
    .bcdDevice = 0x0100,
    .iManufacturer = 0x01,
    .iProduct = 0x02,
    .iSerialNumber = 0x00,
    .bNumConfigurations = 0x01,
};


// fido usage page with one 64 byte input and output report
// no report id item is present
const uint8_t p4_usb_report_desc[P4_USB_REPORT_DESC_BYTES] = {
    0x06, 0xd0, 0xf1,       // usage page 0xf1d0
    0x09, 0x01,             // usage fido authenticator device
    0xa1, 0x01,             // application collection
    0x09, 0x20,             // input report data usage
    0x15, 0x00,             // logical minimum 0
    0x26, 0xff, 0x00,       // logical maximum 255
    0x75, 0x08,             // report size 8 bits
    0x95, 0x40,             // report count 64
    0x81, 0x02,             // input data variable absolute
    0x09, 0x21,             // output report data usage
    0x15, 0x00,             // logical minimum 0
    0x26, 0xff, 0x00,       // logical maximum 255
    0x75, 0x08,             // report size 8 bits
    0x95, 0x40,             // report count 64
    0x91, 0x02,             // output data variable absolute
    0xc0,                   // end collection
};


// full speed only on the Type-C connector labeled USB
// config, HID interface, HID descriptor, OUT endpoint, IN endpoint
const uint8_t p4_usb_config_desc[P4_USB_CONFIG_DESC_BYTES] = {
    0x09, TUSB_DESC_CONFIGURATION,
    P4_USB_CONFIG_DESC_BYTES, 0x00,
    0x01,                   // one interface
    0x01,                   // configuration value
    0x00,                   // no configuration string
    0x80,                   // bus powered
    0x32,                   // 100 mA

    0x09, TUSB_DESC_INTERFACE,
    0x00,                   // interface zero
    0x00,                   // alternate setting zero
    0x02,                   // two endpoints
    TUSB_CLASS_HID,
    0x00,                   // no boot subclass
    0x00,                   // no boot protocol
    0x03,                   // interface string

    0x09, HID_DESC_TYPE_HID,
    0x11, 0x01,             // HID 1.11
    0x00,                   // country code
    0x01,                   // one subordinate descriptor
    HID_DESC_TYPE_REPORT,
    P4_USB_REPORT_DESC_BYTES, 0x00,

    0x07, TUSB_DESC_ENDPOINT,
    P4_USB_EP_OUT,
    TUSB_XFER_INTERRUPT,
    P4_USB_REPORT_BYTES, 0x00,
    P4_USB_POLL_INTERVAL_MS,

    0x07, TUSB_DESC_ENDPOINT,
    P4_USB_EP_IN,
    TUSB_XFER_INTERRUPT,
    P4_USB_REPORT_BYTES, 0x00,
    P4_USB_POLL_INTERVAL_MS,
};


// language entry is encoded as the two raw LANGID bytes expected by esp_tinyusb
const char *p4_usb_string_desc[] = {
    (const char[]){0x09, 0x04},
    "P4Key project",
    "P4Key Dev",
    "P4Key FIDO HID",
};

const int p4_usb_string_desc_count =
    sizeof(p4_usb_string_desc) / sizeof(p4_usb_string_desc[0]);

_Static_assert(sizeof(tusb_desc_device_t) == 18, "USB device descriptor size");
_Static_assert(P4_USB_CONFIG_DESC_BYTES ==
               TUD_CONFIG_DESC_LEN + TUD_HID_INOUT_DESC_LEN,
               "TinyUSB full speed descriptor template size");
_Static_assert(P4_USB_REPORT_BYTES == CFG_TUD_HID_EP_BUFSIZE,
               "TinyUSB HID endpoint buffer size");
_Static_assert(sizeof(p4_usb_report_desc) == P4_USB_REPORT_DESC_BYTES,
               "FIDO HID report descriptor size");
_Static_assert(sizeof(p4_usb_config_desc) == P4_USB_CONFIG_DESC_BYTES,
               "full speed configuration descriptor size");
