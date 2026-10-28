# Coverage matrix — advisory CVE → report → PoC

## CONFIRMED FINDINGS (binary-decoded — read these first)

| CVE(s) | Confirmed report | Evidence level | PoC |
| :----- | :--------------- | :------------- | :-- |
| 112477 | `CONFIRMED_IOSurface_CVE-2026-112477.md` | **instruction** | `pocs/iosurface_state_race.c` |
| 112696, 84494 | `CONFIRMED_ANE_CVE-2026-112696.md` | string + bounds idiom | `pocs/ane_oob_scaffold.c` |
| 112469 + 5 siblings | `CONFIRMED_AVEVideoEncoder_CVE-2026-112469.md` | string (27 new checks) | `pocs/ave_paramset_oob.py` (**ready**) |
| 112515 | `CONFIRMED_IOHIDFamily_CVE-2026-112515.md` | **instruction** | `pocs/hid_index_oob.py` (**ready**) |
| kernel (several) | `CONFIRMED_Kernel_Symbols.md` | exported symbol delta | — |
| kernel (several) | `CONFIRMED_Kernel_Cluster.md` | string + negative results | — |

## Legend

- **Report**: file under `reports/`.
- **PoC**: file under `pocs/`.
- **Localizable?**: can this workspace's size-only diffs narrow the CVE to a
  module? `yes` / `partial` / `no`.

## Reports produced

| CVE(s) | Report | PoC | Localizable? |
| :----- | :----- | :-- | :----------- |
| 112696, 84494 | `reports/ANE_H11ANEInterface_CVE-2026-112696.md` | `pocs/ane_oob_scaffold.c` | yes |
| 112469, 112468, 112466, 112470, 112689, 112705 | `reports/AVEVideoEncoder_CVE-2026-112469.md` | `pocs/ave_encoder_oob_scaffold.m` | yes |
| 112477 | `reports/IOSurface_CVE-2026-112477.md` | `pocs/iosurface_race_scaffold.c` | yes |
| 112507, 84495, 112514, 65350, 112679, 112517, 112516, 112474, 112476, 112501, 112606, 112665, 112624, 112698 | `reports/Kernel_Cluster_CVE-2026-112507.md` | (fuzzing plan) | partial |
| 112576 | `reports/Kernel_COW_CVE-2026-112576.md` | `pocs/cow_integrity_scaffold.c` | partial |
| 112515 | `reports/IOHIDFamily_CVE-2026-112515.md` | `pocs/hid_report_oob_scaffold.py` | yes |
| 112459 | `reports/IOMobileFrameBuffer_CVE-2026-112459.md` | `pocs/mbfb_race_scaffold.c` | partial |
| 112479 | `reports/USB_CVE-2026-112479.md` | `pocs/usb_desc_oob_scaffold.c` | partial |
| 113910 | `reports/Compression_CVE-2026-113910.md` | `pocs/compression_leak_scaffold.c` | yes |
| 113909, 112622, 112620 | `reports/WiFi_Cluster_CVE-2026-113909.md` | `pocs/wifi_ie_fuzz/beacon_ie_overflow.py` | no |
| 113897, 112639, 112690 | `reports/WebKitProcessModel_CVE-2026-113897.md` | `pocs/webkit_uaf_scaffolds.html` | no |
| 112697, 112655, 112651, 112623, 112640, 112626, 112637, 86974, 112659, 113949, 112673, 112699, 112680, 113904, 112599, 86986, 112693, 86985, 112686, 112684, 112695, 112666, 112654, 112653, 112615, 113952 | `reports/WebKit_UAF_CVE-2026-112697.md` | `pocs/webkit_uaf_scaffolds.html` | no |
| 112461, 112449, 112565, 112485, 112486, 112413 | `reports/ModelIO_Cluster_CVE-2026-112461.md` | `pocs/modelio_malicious_models/gen_modelio_models.py` | yes |
| 112619 | `reports/Calendar_CVE-2026-112619.md` | `pocs/gen_ics_oob.py` | partial |
| 113950, 112610, 112611 (+86988, 112656, 112571, 112561, 112627, 112632, 112630, 112653, 112629, 112614, 112625, 112642, 112683, 86970) | `reports/CoreGraphics_Font_CVE-2026-113950.md` | `pocs/fontgen/gen_truetype_oob.py`, `pocs/pdfgen/gen_pdf_sampledfunc_overflow.py` | partial |
| 112488, 112633, 112614, 112634, 112629, 112561, 112627, 112571, 112632, 112630, 112625 | `reports/ImageIO_Cluster_CVE-2026-112488.md` | `pocs/imagegen/gen_imageio_underflow.py` | partial |
| 2022-26704 | `reports/Spotlight_Symlink_CVE-2022-26704.md` | `pocs/spotlight_symlink_scaffold.c` | no |
| 112446, 112692, 86987, 112676, 112681, 113914, 112701, 65397, 112660, 86925, 112559, 112455, 112685, 112616, 86989, 84605, 112678, 112706, 112618, 86978, 112609, 86968, 113898, 112432, 113908, 112707 | `reports/Entitlement_Cluster_CVE-2026-112446.md` | `pocs/entitlement_scaffold.m`, `pocs/log_redaction_check.sh` | no |

## Remaining advisory CVEs not yet in a dedicated report

These are lower-severity or single-CVE subsystems where the diff corpus offers
no distinguishing evidence beyond the subsystem name. They are listed here so
nothing in the advisory is silently dropped.

| CVE | Subsystem | Impact class | Note |
| :-- | :-------- | :----------- | :--- |
| 86971 | Accelerate Framework | OOB write, image processing | Accelerate framework in `DYLIBS`; same parser class as ImageIO |
| 84493 | AccessorySetupKit | BT access without consent | privacy, entitlement |
| 112546 | Audio | OOB read, crafted file | CoreAudio family |
| 113907, 113912, 86972, 86969, 112638 | CoreAudio | buffer overflow / OOB / heap overflow | `IOAudioCodecs`, `AppleAOPAudio` updated |
| 86992, 112706, 112688, 86990 | CoreMedia | memory handling / camera access | `VideoProcessing` / camera kexts updated |
| 112566, 113906 | Bluetooth | NULL deref, proximity DoS | BT kexts updated (`AppleBluetoothModule`) |
| 112701 | CloudKit | authorization | see entitlement cluster |
| 113896 | FileProvider | race condition | `fileproviderd` in filesystem list |
| 112518 | Heimdal | signature validation | Kerberos |
| 112456 | HFS | OOB write, heap corruption | filesystem; `AppleFSCompression` updated |
| 86978, 112596 | HomeKit | privacy / integer overflow | `HomeKit` frameworks |
| 65385 | IOKit | OOB write | generic IOKit |
| 112554 | IOStorageFamily | OOB read | kext updated |
| 112522 | libarchive | OOB write | archive parser |
| 112621 | LinkPresentation | OOB write image | link preview parser |
| 112500, 112671, 112414 | Mail | Hide My Email leak / DoS / stack overflow | Mail app |
| 112707 | Maps | installed-app fingerprint | privacy |
| 112607 | mDNSResponder | OOB read leak | network |
| 113915 | MediaAnalysis | race, data access | privacy |
| 112687 | MediaRemote | removed vulnerable code | network |
| 112682 | Messages | input validation | messaging |
| 86989 | MobileGestalt | fingerprint | privacy |
| 112547 | ReplayKit | type confusion | screen capture |
| 112609 | Safety Check | privacy | app |
| 112425, 112423, 112464, 86991 | SceneKit | OOB read / write / overflow in 3D | same 3D parser family as ModelIO |
| 112616 | Screen Time | authorization | app |
| 113913 | Security | web content info leak | Security.framework |
| 112652 | Security | cert validation bypass | Security.framework |
| 112455, 112559 | Shortcuts | authorization | app |
| 112658, 112685 | Siri | input validation / authorization | Siri frameworks |
| 112567, 112628 | Spotlight | privacy bypass / data access | app |
| 112646 | SpringBoard | OOB write | SpringBoard |
| 112691 | SwiftUI | OOB write | framework |
| 86968 | System Preferences | access control | app |
| 84605 | TextKit | device name read | framework |
| 112595 | Thread | authentication bypass (Thread network) | network |
| 113901, 86973 | WebRTC | UAF / OOB read | WebKit |
| 113909, 112620 | Wi-Fi | DoS | Wi-Fi cluster |

## Highest-value next actions

1. **Extract both kernelcaches** and run a per-function version diff on
   `AppleH11ANEInterface` (biggest signal: +141 functions).
2. **Dump `__DATA_CONST.__assert` strings** from both kernels — the new
   assertion messages likely name several of the 18 kernel CVEs.
3. **Diff `__DATA_CONST.__kalloc_type`** to name the new typed object in the
   UAF cluster.
4. **Enumerate `AppleAVE2` property setters** to map the six encoder CVEs.
5. **Extract the dyld shared cache** to localize WebKit, ImageIO,
   CoreGraphics — currently the weakest coverage.
6. **Run the behaviour-only scaffolds** (COW integrity, compression leak,
   Spotlight symlink) on a 27.0.1 test device; these need no disassembly and
   could confirm three bug classes outright.
