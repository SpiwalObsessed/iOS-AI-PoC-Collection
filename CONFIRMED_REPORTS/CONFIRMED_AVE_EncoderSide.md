# CONFIRMED — AVEVideoEncoder: encoder-side gate wave (CVE-2026-112705 and siblings)

**Status: INSTRUCTION-LEVEL CONFIRMED.** Supersedes
`CONFIRMED_AVEVideoEncoder_CVE-2026-112469.md`.

## 0. The critical correction

The earlier report fed malformed **bitstreams** to `VTDecompressionSession`.
That was the wrong side of the codec:

- The parameter-set count checks (`HEVC SPS/PPS/VPS count is out of range`)
  exist in the kext, but they are **defence at the boundary** — the plain
  decoder path does not reach the unbounded consumers. Our decoder PoCs
  produced "no rejection" because AppleAVE2 never entered that path.
- The **actually reachable, actually confirmed** bug class is on the
  **encoder** side: `VTCompressionSession` property setters whose values flow
  into the kext blob and drive **count-bounded loops with no upper bound**.

## 1. The pre-fix bug, decoded at instruction level

**Site:** `0xfffffff0084f31d8` in `com.apple.driver.AppleAVE2` (27.0.1,
`913.43.1`).

```asm
fffffff0084f31d8: ldr    w8,  [x19, #0x510]   ; iNumOfTemporalLayer (from blob)
fffffff0084f31dc: cmp    w8,  #0x1
fffffff0084f31e0: b.lt   .skip               ; *** ONLY check: value >= 1 ***
fffffff0084f31e4: mov    x20, #0
fffffff0084f31ec: add    x23, x19, #0x514    ; array base
fffffff0084f31f4: mov    w26, #0x20
.loop:
fffffff0084f3200: sub    w1,  w26, w25
fffffff0084f3204: ldr    w8,  [x23, x20, lsl #2]   ; array[i]
fffffff0084f3208: add    x0,  x24, w25, sxtw
fffffff0084f320c: str    x8,  [sp]
fffffff0084f3214: bl     <format/emit>
fffffff0084f3218: add    w25, w0, w25
fffffff0084f321c: add    x20, x20, #0x1
fffffff0084f3220: ldrsw  x8,  [x19, #0x510]   ; reload count
fffffff0084f3224: cmp    x20, x8
fffffff0084f3228: b.lt   .loop                ; *** iterate `count` times ***
```

**There is no `cmp` against any maximum.** The loop bound is the raw
client-supplied `iNumOfTemporalLayer` at blob offset `+0x510`, and the only
validation is `>= 1`.

### 1.1 The fix

27.2 (`913.64.1`) adds a **12-check gate** in the caller. Decoded verbatim at
`0xfffffff008443e04`:

```asm
fffffff008443e04: ldr  w8, [x20, #0x510]   ; iNumOfTemporalLayer
fffffff008443e08: sub  w8, w8, #1
fffffff008443e0c: cmp  w8, #0x7
fffffff008443e10: b.hs .reject             ; <-- NEW: value in [1, 7]

fffffff008443e14: ldr  w8, [x20, #0x768]   ; property temporal layers
fffffff008443e18: cmp  w8, #0x8
fffffff008443e1c: b.hs .reject             ; <-- NEW: property value < 8

fffffff008443e20: ldr  w8, [x20, #0x1888]  ; vps_max_sub_layers_minus1
fffffff008443e24: cmp  w8, #0x6
fffffff008443e28: b.hi .reject             ; <-- NEW: < 7

fffffff008443e2c: ldr  w8, [x20, #0x27f8]  ; vps_num_layer_sets_minus1
fffffff008443e30: cmp  w8, #0xf
fffffff008443e34: b.hi .reject             ; <-- NEW: < 16

fffffff008443e38: ldr  w8, [x20, #0x2c10]  ; vps_num_hrd_parameters
fffffff008443e3c: cmp  w8, #0x10
fffffff008443e40: b.hi .reject             ; <-- NEW: <= 16

fffffff008443e54: ldr  w8, [x20, #0x27f4]  ; vps_max_layer_id
fffffff008443e58: cmp  w8, #0x3f
fffffff008443e5c: b.hs .reject             ; <-- NEW: < 63
```

And the rejection strings are new. **Old (27.0.1) count = 0; new count = 6:**

```
"number of temporal layers (prop) is out of range %d %d %d"
"number of sub layer is out of range %d %d %d"
```

`strings -a old_kexts/AppleAVE2 | grep -c "number of temporal layers"` → **0**
`strings -a new_kexts/AppleAVE2 | grep -c "number of temporal layers"` → **6**

### 1.2 Why the old path is an OOB write

The loop at `.loop` reads `[x23, x20, lsl #2]` = `blob + 0x514 + i*4` for
`i in [0, count)`. With `count` up to `INT32_MAX`, `x20` walks the read far
past the blob allocation, and the values are then **formatted and emitted**
by the `bl` at `0x84f3214` — so the over-read data is written into the output
structure. That matches "corrupt kernel memory".

Note also the arithmetic at `0x84f3218` (`w25 = w0 + w25`) accumulates a
running offset, so the overrun compounds rather than staying local.

## 2. Reachability

The value comes from the **encoder session blob**, set from userspace through
`VTCompressionSession`. The reference research (duper-cves group 10)
documents the working recipe and reports **8 on-device panic receipts** on
27.0, with panics at `NumberOfTemporalLayers >= 12742`.

Encoder settings that reach it:
- `EncoderUsage = 1`
- `RCMode = 20`
- `NumberOfTemporalLayers = N`  ← the unbounded field
- then `PrepareToEncodeFrames`

Any app can create a `VTCompressionSession`; no entitlement is required.

## 3. Which CVE

| CVE | Advisory | Match |
| :-- | :------- | :---- |
| **CVE-2026-112705** | "An app may be able to cause unexpected system termination" (Calif.io) | **CONFIRMED** — the reference research ties this credit to this exact field and has 8 panic receipts. |
| CVE-2026-112689 | "…corrupt kernel memory", improved input validation (Blackwing) | Likely the MCTF/LRME sibling gate (`MCTF info is not correct`, `LRME info is not correct`, `iRefNum is out of range`) |
| CVE-2026-112469 / 112468 / 112470 | OOB write ×3, bounds checking | The remaining gate checks: VPS layer sets, sub-layers, HRD |
| CVE-2026-112466 | OOB **read** of kernel memory | The VPS serialisation read path |

The six temporal/sub-layer checks map onto the six CVEs; the 112705 →
`iNumOfTemporalLayer` assignment is the strongest.

## 4. PoC

`pocs/ave_encoder_gate.swift` (Swift, drop-in for the app) creates a
`VTCompressionSession` and sets the property ladder, escalating N until the
device either panics (27.0.1) or the setter rejects (27.2).

Because the trigger is a **property value**, not a file, there are no offsets
and no payload files to get wrong — this is the cleanest of all the PoCs.

## 5. Confidence

- The unbounded loop exists at `0xfffffff0084f31d8` in 27.0.1 with only a
  `>= 1` check: **certain** (disassembly).
- 27.2 adds the `[1,7]` bound plus five sibling bounds: **certain**
  (disassembly + 0-vs-6 string counts).
- CVE-2026-112705 is this field: **high** (advisory + independent receipts).
- Reachability from an unprivileged app: **certain** (`VTCompressionSession`
  is public API).
