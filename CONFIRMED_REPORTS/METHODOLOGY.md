# Methodology — from fix footprint to vulnerability theory

## 1. What a diff file in this workspace actually encodes

Example (`KEXTS/com.apple.driver.AppleAVE2.md`):

```diff
-913.43.1.0.0
-  __TEXT.__const: 0x4b6f0
-  __TEXT.__cstring: 0x4804a
-  __TEXT.__os_log: 0x5cabd
-  __TEXT_EXEC.__text: 0x1d0028
+913.64.1.0.0
+  __TEXT.__const: 0x4b6c0
+  __TEXT.__cstring: 0x49270
+  __TEXT.__os_log: 0x5e03a
+  __TEXT_EXEC.__text: 0x1d3ef8
   __TEXT_EXEC.__auth_stubs: 0x7b0
   ...
-  __DATA_CONST.__const: 0xae10
+  __DATA_CONST.__const: 0xad60
   __DATA_CONST.__kalloc_type: 0x5300
   __DATA_CONST.__kalloc_var: 0x1e00
   ...
-  Functions: 2995
+  Functions: 2998
```

Interpretation rules used throughout the reports:

| Section | Meaning of change | Security inference |
| :------ | :---------------- | :----------------- |
| `__TEXT_EXEC.__text` growth | new / expanded code | fix added logic, often a check |
| `__TEXT_EXEC.__text` shrink | removed code | "addressed by removing the vulnerable code" advisory wording |
| `__TEXT.__cstring` growth | new C strings / format / assert messages | new error paths, new class/bound names |
| `__TEXT.__os_log` growth | new logging | new rejection branches |
| `__DATA_CONST.__const` growth | new constant tables / descriptor structs | new bound tables, new method descriptor |
| `__DATA_CONST.__kalloc_type` growth | new `Zalloc` type descriptors (size/alignment tuple) | new kernel object type or struct grew |
| `__DATA_CONST.__assert` growth | new `assert` sites | invariant added where unchecked |
| `Functions: N` delta | exact number of added/removed functions | positive ⇒ fix added helper; negative ⇒ code removed |
| "Sections with Same Size but Changed Content" | bytes changed in place | likely patched branch/constant inside existing function |

**Hard limitation:** no instruction-level data. Any claim of the form "the
missing check is at +0x…" is impossible from this corpus and is not made.

## 2. Advisory-to-module mapping

`PatchNotes.json` carries, for every CVE, three fields that drive the mapping:

- `title` — Apple's internal subsystem name (not always the kext name),
- `notes[impact]` — the attacker model and primitive,
- `notes[description]` — the *class* of the fix ("out-of-bounds write issue
  was addressed with improved bounds checking", "a race condition was
  addressed with improved locking", "addressed with additional entitlement
  checks", "addressed by removing the vulnerable code", etc.).

The description phrase is the single strongest signal. It tells us the
*shape* of the pre-fix bug:

| Fix phrase | Pre-fix bug class | Where to look after disassembly |
| :--------- | :---------------- | :------------------------------ |
| "improved bounds checking" | missing/misordered length check | loop condition, memcpy size, index compare |
| "improved input validation" | absent validation of attacker field | ioctl/struct parser entry |
| "improved memory handling" | uninitialised / lifetime bug | alloc path, memset, free order |
| "improved memory management" | UAF / over-retain | retain/release, refcount |
| "race condition … improved locking" | TOCTOU / double-fetch | lock scope, copyin order |
| "race condition … improved state handling" | state machine transition race | state enum transitions |
| "additional entitlement checks" | TCC/entitlement gate too weak | `IOCurrentTaskHasEntitlement` / `TCCAccessCheck` |
| "additional restrictions" | permission check missing | file/port perms |
| "removing the vulnerable code" | unsafe feature deleted | symbol absent in new binary |
| "improved data redaction" | log leaks PII | os_log format string |
| "improved checks" | generic logic bug | assertion / type check |

## 3. Scoring rubric

Each candidate report records four scores:

- **S1 Attribution** (0–3): how confidently the CVE maps to a module with a
  diff. 3 = unambiguous subsystem name in diff path + matching size-change
  shape; 2 = plausible; 1 = weak; 0 = no diff.
- **S2 Reachability** (0–3): 3 = unprivileged app or remote content;
  2 = local network / physical proximity; 1 = physical access to a paired
  device; 0 = kernel/SEP only.
- **S3 Primitive severity** (0–2): 2 = kernel R/W or RCE; 1 = info leak or
  DoS; 0 = privacy/logic only.
- **S4 Footprint distinctiveness** (0–2): how well the size deltas explain the
  fix.

Total /10.

## 4. Report template

Each `reports/*.md` uses:

1. **CVE metadata** — ID, subsystem, impact, description, acknowledgment.
2. **Diff evidence** — quoted numbers from the relevant `.md` files.
3. **Attribution argument** — why this module is the CVE's home.
4. **Pre-fix reconstruction** — falsifiable theory of the bug from the fix's
   footprint.
5. **Attacker reachability & constraints** — sandbox, entitlements, checks.
6. **PoC plan** — what input/sequence triggers it, and where in the target
   binary to aim once disassembly is available.
7. **Verification checklist** — binary-level confirmations required before the
   theory is upgraded to "confirmed".
8. **Confidence & open questions.**

## 5. Honesty rules

- No fabricated offsets, addresses, or symbol names.
- Every numeric claim is traceable to a file in the workspace.
- PoCs are labelled `scaffold` unless they have been executed and confirmed.
- When a CVE's subsystem has no diff in this corpus, that is stated explicitly.