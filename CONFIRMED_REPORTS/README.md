# CVE Candidate Reports — iOS 27.0.1 (24A446) vs 27.2 (24B119)

## UPDATE — reports are now BINARY-CONFIRMED

A second analysis pass used the actual IPSWs with `ipsw` 3.1.710, `objdump`,
and `angr` 10.0.5 to extract the kernelcache, pull individual kexts, and read
the real machine code. **Five CVEs are now decoded at instruction or string
level.** Read these first:

| File | What was decoded |
| :--- | :--------------- |
| `CONFIRMED_IOSurface_CVE-2026-112477.md` | 2 of 1329 functions changed; a state-flag guard `ldrb/tbz` added inside the lock, and a companion function that sets the flag `strb #1` at `object+0xf1`. Mark/guard protocol for a UAF race. |
| `CONFIRMED_ANE_CVE-2026-112696.md` | +141 functions, 4594 functions resized (recompile). 27 new validation strings naming `BACK_CHANNEL_RPC` declared-item count, shared-memory/endpoint message sizes, procedure/symbol indices, `kANEMaxBars`. Bounds idiom `adds/b.hs/cmp/b.hi` located. |
| `CONFIRMED_AVEVideoEncoder_CVE-2026-112469.md` | 486 changed strings, 27 new checks. HEVC VPS/SPS/PPS/RPS counts, AVC PPS count, MCTF strength count, `too many parameter sets`, `source and destination alias`. Six check groups for six CVEs. |
| `CONFIRMED_IOHIDFamily_CVE-2026-112515.md` | Two functions +24 bytes. Inserted `ldr w9,[x20,#0x40]; cmp w8,w9; b.ge` — index-vs-count check; zeroed output on reject. Old code did `array + index*20 + 8` unbounded → 20-byte strided OOB read returned to caller. |
| `CONFIRMED_Kernel_Symbols.md` | 4 new exported symbols, 0 removed: `_exclaves_indicator_system_state_change`, `_proc_coalitionids`, `_task_coalition_role_for_type`, `_vfs_context_allows_unmunged_atime`. |
| `CONFIRMED_Kernel_Cluster.md` | String-level kernel evidence: `A5AC3PassThrough` packet bounds, RTBuddy metric offsets, `map_block_buf` size check, APFS crypto refcount. Plus negative result: CVE-2026-112576 has no new strings. |

**Corrections to the original theories** (documented in each CONFIRMED file):
IOSurface is a missing state-flag check (not a lock extension); IOHIDFamily has
no new error string (it silently returns zeros); AVEVideoEncoder counts are
bitstream parameter sets (not ROI arrays); ANE is a whole boundary rewrite.

`COVERAGE.md` has the full CVE → report → PoC matrix. `pocs/ave_paramset_oob.py`
and `pocs/hid_index_oob.py` are the two PoCs that are genuinely ready to run,
because their triggers are now known exactly.

---

## Original caveat — historical context for the reports/ folder

This section describes the limits of the first analysis pass, which worked
only from the section-size diffs. The CONFIRMED files supersede it.

The workspace diffs are **Mach-O structural summaries only**. Each `.md` file
under `KEXTS/`, `MACHOS/`, and `DYLIBS/` contains:

- the bundle/module version string (`-old` / `+new`),
- per-section size deltas (`__TEXT.__text`, `__TEXT.__const`, `__DATA_CONST.*`,
  `__DATA.__kalloc_type`, etc.),
- `Functions:` counts when the tooling could recover them,
- and, for a small number of Mach-O files, a list of *"Sections with Same Size
  but Changed Content"* (content changed, no disassembly or byte level data).

The diffs **do not contain disassembly, symbol names, strings, or byte
patches**. Therefore none of the reports below can name a specific function,
offset, or register. What they *can* do — and do — is:

1. Correlate each CVE's advisory metadata (subsystem, vulnerability class,
   attacker position, "addressed with ..." phrasing) against the module(s) that
   changed and the *shape* of the change (text growth, kalloc_type growth,
   const/assert growth, function count delta).
2. Derive, from the fix's observable footprint, what the pre-fix code must have
   looked like (missing bound, missing lock, missing entitlement gate, etc.).
3. Produce a PoC **harness/plan** that is honest about the missing binary
   detail: the PoC files are self-contained generators for the malicious
   input (image/font/3GP/archive/calendar/3D model) or trigger sequences, not
   offset-precise exploits.

Do not treat any PoC here as a working exploit. They are reproduction scaffolds
that become offset-accurate only once disassembly of the two IPsw binaries is
performed (e.g. `jtool2`, `Ghidra`, `ida`, or `diff` on the extracted
`__TEXT_EXEC.__text`).

## How candidates were ranked

Candidate score (0–10) = advisory specificity × diff attributability ×
reachability by an unprivileged attacker × fix-footprint distinctiveness.

| Rank | CVE | Subsystem | Why it was selected | Report |
| :-- | :-- | :-------- | :------------------ | :----- |
| 1 | CVE-2026-112696 | Apple Neural Engine (H11ANEInterface) | "OOB write → kernel memory", app-reachable, kext grew **+141 functions / +0x9B5C text / kalloc_type +0x200** | [reports/ANE_H11ANEInterface_CVE-2026-112696.md](reports/ANE_H11ANEInterface_CVE-2026-112696.md) |
| 2 | CVE-2026-112469 | AVEVideoEncoder (AppleAVE2) | "OOB write → kernel memory", kext grew **+3 functions / +0x3ED0 text** | [reports/AVEVideoEncoder_CVE-2026-112469.md](reports/AVEVideoEncoder_CVE-2026-112469.md) |
| 3 | CVE-2026-112477 | IOSurface | "race → kernel memory corruption", text +0x18, module version bumped | [reports/IOSurface_CVE-2026-112477.md](reports/IOSurface_CVE-2026-112477.md) |
| 4 | CVE-2026-112507 / 84495 / 112514 / 65350 | Kernel (com.apple.kernel) | multiple UAF/OOB in kernel; assert +0x104, kalloc_type +0x40, text +0x4DC C | [reports/Kernel_Cluster_CVE-2026-112507.md](reports/Kernel_Cluster_CVE-2026-112507.md) |
| 5 | CVE-2026-112459 | IOMobileFrameBuffer | "race → kernel memory", version bump | [reports/IOMobileFrameBuffer_CVE-2026-112459.md](reports/IOMobileFrameBuffer_CVE-2026-112459.md) |
| 6 | CVE-2026-113909 / 112622 / 112620 | Wi-Fi | proximity attacker, OOB read / memory corruption / DoS | [reports/WiFi_Cluster_CVE-2026-113909.md](reports/WiFi_Cluster_CVE-2026-113909.md) |
| 7 | CVE-2026-112479 | USB | malicious USB device → OOB read of kernel memory | [reports/USB_CVE-2026-112479.md](reports/USB_CVE-2026-112479.md) |
| 8 | CVE-2026-113910 | Compression (kec.Compression) | kernel memory disclosure via uninitialized memory | [reports/Compression_CVE-2026-113910.md](reports/Compression_CVE-2026-113910.md) |
| 9 | CVE-2026-112576 | Kernel COW integrity | unusual class — COW page tampering | [reports/Kernel_COW_CVE-2026-112576.md](reports/Kernel_COW_CVE-2026-112576.md) |
| 10 | CVE-2026-113897 | WebKit Process Model | WebContent sandbox escape, "removed vulnerable code" | [reports/WebKitProcessModel_CVE-2026-113897.md](reports/WebKitProcessModel_CVE-2026-113897.md) |
| 11 | CVE-2026-112697 (and WebKit cluster) | WebKit | UAF → RCE, full WebKit version bump | [reports/WebKit_UAF_CVE-2026-112697.md](reports/WebKit_UAF_CVE-2026-112697.md) |
| 12 | CVE-2026-112619 | Calendar | OOB write parsing calendar invitation | [reports/Calendar_CVE-2026-112619.md](reports/Calendar_CVE-2026-112619.md) |
| 13 | CVE-2026-113950 | CoreGraphics font | OOB write parsing font | [reports/CoreGraphics_Font_CVE-2026-113950.md](reports/CoreGraphics_Font_CVE-2026-113950.md) |
| 14 | CVE-2026-112488 / 112633 / 112625 | ImageIO | buffer overflow, OOB write, integer underflow | [reports/ImageIO_Cluster_CVE-2026-112488.md](reports/ImageIO_Cluster_CVE-2026-112488.md) |
| 15 | CVE-2022-26704 | Spotlight | symlink validation → privilege escalation | [reports/Spotlight_Symlink_CVE-2022-26704.md](reports/Spotlight_Symlink_CVE-2022-26704.md) |

Reports not listed here exist only for CVEs whose subsystem had **no
corresponding binary change** in this workspace corpus (e.g. Wi-Fi firmware
blobs are not part of the Mach-O diff set), and those are covered collectively
in `reports/_unmapped.md` if generated.

## Directory layout

```
CVE_REPORTS/
  README.md                          <- this file
  METHODOLOGY.md                     <- how to read a diff, and scoring rubric
  reports/                           <- one detailed report per CVE/cluster
  pocs/                              <- reproduction scaffolds (not exploits)
```

## Suggested workflow once the IPsws are available locally

1. Extract `kernelcache.release.iphone14,5` from both `.ipsw` archives.
2. Decompress and split with `jtool2 -e` (or `ipsw` utility).
3. For each target kext (e.g. `com.apple.driver.AppleH11ANEInterface`),
   compute a per-function fingerprint with `radiff2 -A` or Ghidra's Version
   Tracking, and match the `Functions:` delta from the report to the actual
   changed functions.
4. In each changed function, look for the patterns predicted in the report
   (bound check, lock acquisition, entitlement gate, memset of a struct, etc.).
5. Turn the PoC scaffold into an offset-accurate reproducer.