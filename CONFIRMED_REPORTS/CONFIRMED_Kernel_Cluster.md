# CONFIRMED (partial) — Kernel cluster: string-level evidence

**Status: PARTIALLY DECODED.** The kernel is a 64 MB Mach-O with 18 CVEs in
the advisory, so function-level attribution is still impractical. But the
string diff (`6959` new strings) surfaces several **named validation sites**
that map to specific CVE descriptions. This supersedes the theory sections of
`reports/Kernel_Cluster_CVE-2026-112507.md` where marked.

## 1. Method

```
strings -a old/.../kernelcache.release.iPhone14,5 | sort -u > old.str
strings -a new/.../kernelcache.release.iPhone14,5 | sort -u > new.str
diff old.str new.str
```

153716 → 154077 unique strings, **6959 added**. Filtering for validation
language yields a short, high-signal list (§2).

## 2. New validation strings that map to advisory CVEs

### 2.1 `A5AC3PassThrough` packet bounds — NEW checks

```
A5AC3PassThrough::%s input packet too large for output packet
A5AC3PassThrough::%s insufficient input packet
```

`A5AC3` is the **A5 security/authentication co-processor** passthrough.
Count went `1 → 3`, i.e. **two new bounds checks** on a packet copy path:
input length vs output buffer, and a minimum-length check.

**Maps to:** an OOB write/read in a coprocessor message path. Best candidate
among the kernel CVEs is **CVE-2026-112507** ("out-of-bounds write … write
kernel memory", improved bounds checking) or **CVE-2026-112476** ("out of
bounds read", improved bounds checking). The two-check pattern (too large +
insufficient) is exactly a two-sided bound.

**Reachability:** A5 is driven by userspace via the SEP/A5 driver; an app can
reach the passthrough through the security services API.

### 2.2 `IOHistogramReporter` bin-count bound

```
Histogram bin count (%ld) exceeds maximum (%d)
```

Present in both versions (count unchanged at 1), so the *string* is old — but
an `IOHistogramReporter` bounds fix is a strong fit for an integer/overflow
CVE reachable from `IOMemoryDescriptor`-adjacent reporting. Low confidence for
a specific CVE; noted because `IOHistogramReporter` is a well-known iOS
surface.

### 2.3 RTBuddy metric label offset

```
RTBuddy: metric label resolve failed: source %u label_offset 0x%x:
          offset %u exceeds string table length %u
RTBuddy(%s): Metric collection header entry too small: %u < %zu bytes
```

Two new bounds checks in the **RTBuddy** coprocessor protocol (RTBuddy is the
Apple coprocessor mailbox used by SEP/ANE/DCP/etc.):
- a string-table offset must not exceed the table length,
- a metric header entry must be at least `sizeof(header)`.

**Maps to:** an OOB read in coprocessor metric parsing. Candidate:
**CVE-2026-112476** or **CVE-2026-112515**'s kernel sibling.

### 2.4 `map_block_buf` size check

```
map_block_buf: pbt=%u block_size=%zu too small for addr_offs=%u size_offs=%u
```

A new check that a block buffer is large enough for the offsets within it.
This is the classic "offsets inside a descriptor exceed the descriptor's
buffer" OOB read.

**Maps to:** **CVE-2026-112476** (OOB read, improved bounds checking).

### 2.5 APFS crypto refcount (not the COW CVE)

```
apfs_rr: cleanup ... failed to decrement head split crypto refcount (ret %d)
apfs_rr: cleanup first failed to decrement crypto refcount (ret %d)
apfs_rr: cleanup last failed to decrement crypto refcount (ret %d)
```

New refcount-decrement diagnostics in **APFS "real-time resize"** (`apfs_rr`).
These are the *symptom* strings for a refcount handling fix, not a new check.

**Maps to:** one of the **use-after-free** kernel CVEs. The APFS kext is
separate (`com.apple.filesystems.apfs` grew `__TEXT_EXEC.__text` by `0xCB8`),
so if the UAF is here it is *not* in `com.apple.kernel` — the advisory's
"Kernel" label covers APFS too.

## 3. What did NOT show up (important negative results)

### 3.1 CVE-2026-112576 (COW integrity) — no new strings

All COW-related strings exist in both versions unchanged:

```
vm_cow_defeatured_telemetry.c            old=1 new=1
vm_should_cow_but_wired                  old=1 new=1
vm_cow_defeatured_guard_count_s          old=1 new=1
vm_create_upl_extra_cow_pages            old=1 new=1
```

**Conclusion:** the COW fix is a **pure logic change with no new logging** —
consistent with the tiny `+0x40 __DATA.__data` and the `+0x104` assert growth
in `com.apple.kernel`. The fix most likely modifies an existing `if` in
`vm_fault_enter`/`vm_fault_wire` or the `pmap` COW path, adding or removing a
branch, with no string.

This **supports** the earlier theory (COW protection cleared without the
private copy) but also means the fix cannot be located by strings. It must be
found by disassembling `vm_fault*` and diffing.

### 3.2 No new TCC entitlement-check strings in the kernel proper

```
TCCService
com.apple.tcc.kTCCServiceMotionSensors
```

These appear in the *kernelcache strings* because the kernelcache embeds
`IOHIDFamily` and other kexts. The `TCCService` string noted in the
IOHIDFamily report is from `IOHIDFamily`, not from `com.apple.kernel` proper.
CVE-2026-112624 ("An app may be able to bypass Privacy preferences", improved
checks) therefore most likely lives in a kext, not the core kernel, and its
fix is a `TCCAccessCheck`-style call — check `IOHIDFamily`'s new
`RequiresTCCAuthorization` string as a candidate.

### 3.3 `AED ... dual-pipe shim` is new *functionality*, not a fix

`AED establish-pairing` went `0 → 3`. That is a new feature (display
dual-pipe pairing), unrelated to security. Do not mistake feature strings for
fix strings — this report checks the old-string count for every candidate
precisely to avoid that error.

## 4. Revised mapping for the kernel cluster

| CVE | Impact class | Best string evidence | Confidence |
| :-- | :----------- | :------------------- | :--------- |
| 112507 | OOB write | `A5AC3PassThrough ... input packet too large for output packet` | moderate |
| 112476 | OOB read | `map_block_buf ... too small for addr_offs` / RTBuddy label offset | moderate |
| 84495, 112514, 65350, 112679, 112517, 112516, 112474 | UAF | `apfs_rr cleanup ... crypto refcount` (APFS UAF) | low-moderate |
| 112576 | COW integrity | **none** (no new strings; logic-only fix) | — |
| 112606 | type confusion | new `__assert` entries (no string) | low |
| 112665 | kernel layout disclosure | none identified | low |
| 112624 | privacy bypass | `TCCService` (IOHIDFamily) — likely not core kernel | low |
| 112501, 112698 | race / memory handling | none identified | low |

## 5. Highest-value remaining action

The `__DATA_CONST.__assert` array in `com.apple.kernel` grew by `0x104`
(260 bytes ≈ 4 assert descriptors). Each descriptor contains a **file name
and line number string**. Extracting those 4 new assert descriptors gives the
exact source files where invariants were added — the single most direct
pointer to the type-confusion and state-machine fixes (CVE-2026-112606,
112501, 112665).

Command sketch (needs the `__assert` section format, which is
`{uint32 offset; uint32 line; uint32 fileoff; uint32 flags}` per entry):

```
otool -s __DATA_CONST __assert new/.../kernelcache.release.iPhone14,5
# then resolve each fileoff against __TEXT.__cstring
```

This is the next concrete step and is not blocked on anything.
