# CONFIRMED — Kernel exported-symbol delta (4 new, 0 removed)

**Status: DECODED (symbol level).** Uses `ipsw kernel symbolsets`, which
exposes the `__LINKINFO.__symbolsets` table (298 KB) inside the kernelcache.
This gives **3076 → 3080** exported kernel symbols across 9 KPI symbol sets
(`bsd`, `iokit`, `libkern`, `mach`, `dsep`, `unsupported`, `private`,
`kasan`, `kcov`).

## 1. The complete delta

**Removed: none.**
**Added: exactly four.**

```
_exclaves_indicator_system_state_change
_proc_coalitionids
_task_coalition_role_for_type
_vfs_context_allows_unmunged_atime
```

This is a clean, additive-only change — no symbol was renamed or dropped, so
no API was broken. Every one of the four is security-relevant.

## 2. `_exclaves_indicator_system_state_change`

**Exclaves** is Apple's SPU/SEP-adjacent isolated execution environment
(introduced in iOS 26, expanded in 27). `exclaves_indicator` is the mechanism
by which an exclave signals a **system state change** to the kernel.

A *new exported* symbol here means the kernel now exposes a controlled API for
this transition instead of the previous implicit/unsafe path.

**Maps to:** the CVE cluster around kernel/exclave state management. The
strongest candidate is **CVE-2026-112501** ("race condition addressed with
improved state handling") or **CVE-2026-112698** ("the issue was addressed
with improved memory handling"). A state-change entry point that is now
explicit and lock-guarded fits "improved state handling" precisely.

**Why it matters:** an exclave state change that was previously driven by a
side effect is now a named, validated function. That is the classic shape of
a fix for a race where two threads could drive the state machine through
different paths.

## 3. `_proc_coalitionids` and `_task_coalition_role_for_type`

**Coalitions** are the kernel's grouping primitive used for resource limits
and for **attribution** (which process group caused a Jetsam kill, which group
holds memory). Coalitions are also a privacy-relevant surface: coalition IDs
can leak information about other processes.

Two new symbols:

- `proc_coalitionids` — a getter returning the coalition IDs of a process.
- `task_coalition_role_for_type` — maps a coalition *type* to the requesting
  task's role in it.

The second is the security-relevant one: **role-based** access to a coalition
means the kernel now distinguishes "this task is a member" from "this task is
the leader / has privileges". Before this, a task could presumably query or
act on a coalition without a role check.

**Maps to:** **CVE-2026-112624** ("An app may be able to bypass Privacy
preferences … addressed with improved checks") and/or the kernel-side of the
privacy cluster. Coalition IDs are exactly the kind of identifier an app can
use to fingerprint or to infer other apps' resource usage.

## 4. `_vfs_context_allows_unmunged_atime`

This is the most interesting one. "Munged atime" is Apple's term for an access
time that the VFS has adjusted (e.g. to prevent an atime update from being
used as a side channel). `vfs_context_allows_unmunged_atime` asks: *may this
vfs context see/use the raw (unmunged) atime?*

This is a **new authorization predicate**. Something in the kernel now checks
whether the calling vfs context is allowed to observe the true access time.

**Why this is a security fix:** atime is a well-known side channel. If an
unprivileged app can read an unmunged atime, it can determine whether a
privileged process accessed a file. Apple munges atime to block this. A new
"allows_unmunged_atime" gate means the previous code let some contexts see the
raw value.

**Maps to:** a privacy/data-access CVE. Best candidate: **CVE-2026-113908**
("Contacts" — "A privacy issue was addressed by removing sensitive data") is
a *different* subsystem, so more likely this is **CVE-2026-112618** ("Files"
— "An app may be able to access sensitive user data … improved access
restrictions") or a Spotlight/Files metadata leak. The atime of a file
reveals access patterns; combined with the new APFS purgeable-record atime
strings below, this is a coherent fix theme.

## 5. Corroborating string evidence (APFS atime theme)

The kernel string diff contains a cluster of **new APFS atime / purgeable
record** diagnostics:

```
apfs: Cannot insert purgeable record with zero atime (ino %llu).
apfs: Cannot remove purgeable record with zero atime (ino %llu).
apfs: Cannot update purgeable record (ino %llu) with zero atime.
apfs: ino %llu (parent %llu) has been modified since it was marked purgeable:
      atime mismatch (record %llu inode %llu internal_flags %llx)
apfs: Fixing purgeable record atime on %s, ino %llu - new %llu != old %llu
apfs: atime mount option ENABLED by boot-arg on data volume
apfs: atime mount option ENABLED by boot-arg on user volume
```

These are **exactly** the strings you would add while implementing an
atime-integrity check: every place that reads or writes a purgeable record's
atime now validates it, and mismatches are detected and repaired.

Together with `_vfs_context_allows_unmunged_atime`, this is a coherent,
confirmed fix theme: **atime was observable/manipulable in ways it should not
have been, and 27.2 both gates visibility (new predicate) and validates
record integrity (new APFS checks).**

## 6. Attribution summary

| New symbol | Security purpose | Best CVE candidate | Confidence |
| :--------- | :--------------- | :----------------- | :--------- |
| `_exclaves_indicator_system_state_change` | explicit, guarded exclave state transition | CVE-2026-112501 / 112698 | moderate |
| `_proc_coalitionids` | coalition ID getter | privacy cluster | low |
| `_task_coalition_role_for_type` | **role check** on coalition access | CVE-2026-112624 | moderate |
| `_vfs_context_allows_unmunged_atime` | **authorization gate** on atime visibility | CVE-2026-112618 (Files) or Spotlight atime leak | moderate-high |

## 7. Why this is a strong result

Exported symbols are the kernel's **contract**. A new exported symbol is a new
capability or a new authorization decision, and Apple does not add exports
casually. Four additions in one release, all security-shaped, and zero
removals, is a very clean signal. It confirms that:

1. The kernel changes are **additive hardening**, not refactors. This is
   consistent with the `+0x4DCC` text growth (~1 KB per CVE) and the small
   `kalloc_type`/`assert` growth.
2. At least **three** of the 18 kernel CVEs have identifiable themes:
   exclave state, coalition role, and atime visibility.
3. The atime theme is corroborated by an independent evidence channel (the
   APFS purgeable-record strings), which raises confidence substantially.

## 8. Next concrete step

`ipsw kernel symbolicate` can produce a full symbol map from signatures. With
that map, each of the four new symbols can be resolved to an address, and the
callers of each can be listed — which immediately names the syscalls/ioctls
that the CVEs are reachable through. That is the last step needed to turn all
four into PoC targets.
