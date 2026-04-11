# Darwin/macOS Security Audit Methodology
### A practitioner's guide to systematic, responsible kernel and daemon research

[![Licence: CC BY 4.0](https://img.shields.io/badge/Licence-CC%20BY%204.0-lightgrey.svg)](https://creativecommons.org/licenses/by/4.0/)

---

> **This document is published for educational and defensive security purposes.** It describes a methodology for conducting lawful vulnerability research against software you are authorised to examine. It does not disclose specific vulnerabilities, exploits, or information that could enable attacks against systems you do not own or have explicit written authorisation to test. Readers are responsible for understanding the legal framework applicable in their jurisdiction before conducting any security research.

---

## Legal framework (England and Wales)

This section is provided in good faith as an overview of the relevant legal landscape. **It is not legal advice.** If you are uncertain about the legality of any specific activity, consult a qualified solicitor.

### Computer Misuse Act 1990 (as amended)

The Computer Misuse Act 1990 (CMA) is the primary legislation governing computer security research in England and Wales. It establishes three core offences:

- **Section 1 — Unauthorised access:** Accessing a computer or data without authorisation, or exceeding authorised access. *All research described in this document is conducted against systems the researcher owns or controls, or against code published openly by Apple. No section 1 activity is involved.*
- **Section 3 — Unauthorised acts with intent to impair:** Modifying or impairing data on a system you are not authorised to modify. *Not applicable — no third-party systems are touched.*
- **Section 3A (inserted by the Police and Justice Act 2006) — Making or supplying articles for computer misuse:** An offence to make, supply, or obtain an article knowing it is likely to be used to commit a CMA s.1 or s.3 offence. *See below.*

**On Section 3A and the PoC skeleton code in this document:** The generic network probe code in §4.2 is clearly dual-use: it is identical in function to legitimate diagnostic tools (`nc`, `telnet`, Python's socket library). The Crown Prosecution Service guidance on cybercrime offences (updated 2019) states that where an article has a primarily legitimate use and is not targeted at a specific victim system, prosecution under s.3A is unlikely to be in the public interest. This document accompanies that code with explicit requirements that it be used only against authorised systems, and the code itself contains no exploit payload — it sends a minimal binary message and observes the response.

**The authorisation requirement:** Under the CMA, "authorisation" flows from consent of the person entitled to control access. Researchers testing on their own virtual machines, their own physical hardware, or systems for which they hold written authorisation are within lawful bounds. Apple's Security Research Device (SRD) programme provides a formal authorisation framework for more invasive kernel research.

### Relevant legislation and guidance

| Instrument | Relevance to this workflow |
|---|---|
| Computer Misuse Act 1990 | Primary offence framework; §1, §3, §3A |
| Police and Justice Act 2006 | Inserted CMA §3A on tool supply |
| Serious Crime Act 2015 | Inserted CMA §3ZA (serious damage); not applicable here |
| Data Protection Act 2018 / UK GDPR | Relevant if research surfaces personal data; document does not instruct researchers to collect or retain third-party personal data |
| Human Rights Act 1998, Article 10 | Freedom of expression supports publication of security research methodology as matter of public interest |
| Investigatory Powers Act 2016 | Not applicable; no interception of communications |

### NCSC guidance

The National Cyber Security Centre (NCSC) — the UK government's authority on cyber security — publishes guidance on responsible vulnerability disclosure aligned with ISO/IEC 29147 (Vulnerability Disclosure) and ISO/IEC 30111 (Vulnerability Handling Processes). The workflow in §7 of this document follows those principles: notify the vendor, allow reasonable time to respond, and do not release technical details before a fix is available.

NCSC guidance: [https://www.ncsc.gov.uk/information/vulnerability-reporting](https://www.ncsc.gov.uk/information/vulnerability-reporting)

CPS cybercrime prosecution guidance: [https://www.cps.gov.uk/legal-guidance/cybercrime](https://www.cps.gov.uk/legal-guidance/cybercrime)

### Intellectual property

Apple's open-source code is published under a variety of licences, principally the Apple Public Source Licence 2.0 (APSL-2.0), the BSD 2-Clause and 3-Clause licences, and the MIT licence. Reading and studying this code for security research purposes is explicitly permitted under all of these licences. This document does not reproduce Apple source code verbatim; it describes methodology and contains only researcher-authored code.

---

## 1. Why Darwin?

Apple publishes a substantial portion of the XNU kernel, core daemons, and system frameworks at [apple-oss-distributions](https://github.com/apple-oss-distributions). This is a rare window: most platform vendors ship closed binaries with no source. The OSS releases let you read the exact C that runs on shipping macOS, audit it offline, and then verify hypotheses against the real binary on a test VM — a tight feedback loop that most platform security work cannot achieve.

The surface is large. A non-exhaustive list of interesting targets in any release cycle:

| Layer | Examples |
|---|---|
| Kernel kexts | NFS client, SMBClient, network filter kexts |
| System daemons | `bootpd`, `tftpd`, `mDNSResponder`, `fskitd`, `netbiosd` |
| SUID/privileged binaries | `ping`, `traceroute`, `mount_*` |
| Security frameworks | MAC framework hooks, TCC, Sandbox |
| IPC surfaces | XPC endpoints, MIG calls, `/dev` nodes |

---

## 2. Procurement and triage

### 2.1 Obtaining source

```bash
# Clone from apple-oss-distributions — these are Apple's own public releases
git clone https://github.com/apple-oss-distributions/NFS
git clone https://github.com/apple-oss-distributions/mDNSResponder
git clone https://github.com/apple-oss-distributions/network_cmds
# etc.
```

Tag your clone to the shipped release. Apple tags releases in the format `NFS-<build>`. Match this to the macOS build string from `sw_vers -buildVersion` on your test VM.

### 2.2 Confirming source-to-binary correspondence

Open-source code is useless if the shipped binary diverges. Always confirm:

```bash
# Extract symbol list from the shipped binary
nm -U /sbin/ping | grep -E "^[0-9a-f]+ [Tt]" | head -40

# Cross-reference against the open-source file you intend to audit
grep -r "function_name_of_interest" ./source_tree/
```

For kexts the binary is in `/System/Library/Extensions/` or `/Library/Extensions/`. For daemons check `/usr/sbin/`, `/usr/libexec/`, and LaunchDaemon plists:

```bash
# Find all network-facing LaunchDaemons on a researcher-owned test system
grep -rl "SockType\|KeepAlive\|MachServices\|SockServiceName" \
  /System/Library/LaunchDaemons/ | xargs grep -l "ProgramArguments"
```

### 2.3 Network attack surface mapping

For pre-authentication network attack surfaces, enumerate what is actually listening on your **own test system**:

```bash
# All TCP/UDP listeners
sudo lsof -nP -iTCP -iUDP | grep LISTEN

# Cross-reference with process entitlements
codesign -d --entitlements - /path/to/binary 2>&1 | xmllint --format -
```

Prioritise daemons that:
- Listen on externally reachable interfaces (not `127.0.0.1` only)
- Accept connections before any authentication step
- Parse complex binary protocols (DNS wire format, RPC/XDR, SMB2, NFS)
- Run as root or with significant entitlements

---

## 3. Static analysis with AI-assisted agents

### 3.1 The agent-as-first-pass model

Large codebases (NFS kext: ~20,000 LOC; SMBClient: ~50,000 LOC) are too slow to audit line-by-line in a single session. A productive pattern is to deploy a focused AI coding agent as a first-pass reader, then apply human judgment to anything it flags.

The agent is given:
- A specific set of files (not the whole tree)
- A concrete threat model ("malicious server sends a crafted RPC reply")
- A list of vulnerability classes to look for

The agent returns candidate locations. The human then verifies each one. This splits the work: the agent handles breadth; the human handles depth and correctness.

**What agents find reliably:**
- Integer arithmetic that *looks* dangerous in isolation
- Patterns matching known vulnerability classes (unbounded copies, sign/unsign confusion)
- Missing input validation before use

**Where agents produce false positives:**
- Variable-length record patterns where the allocation is correctly sized but the struct's fixed-size field appears to be the boundary
- Arithmetic that is safe because of protocol-level constraints the agent doesn't know about
- Guards present in a different compilation unit than the dangerous-looking code

Every agent finding must be hand-verified before it is treated as a real issue.

### 3.2 Useful vulnerability classes per layer

**Protocol parsing daemons:**
- Integer underflow/overflow when computing message lengths from wire data (e.g., `(uint16_t message_length) - (int HEADER_SIZE)` — the subtraction promotes to signed, and if length < header size, the result silently becomes a large unsigned value when stored)
- Off-by-one in name/string field bounds
- Mishandled `skiplen` / truncation paths that leave the parser misaligned

**Kernel kexts (malicious-server model):**
- XDR/RPC record framing accumulation overflow before the `MAX_PACKET` guard
- Struct packing into variable-length buffer regions — carefully distinguish between "past the struct's fixed field" and "past the allocation"; these are not the same thing when records are variable-length slices of a larger buffer
- Integer wraparound in `nfsm_rndup`-style alignment helpers

**Privileged SUID binaries:**
- Global BSS/data segment array bounds with command-line controllable indices
- `getopt`-driven flows where multiple option combinations produce unexpected arithmetic

**MAC Framework (MACF) hooks:**
- Enumerate `mac_proc_check_*`, `mac_vnode_check_*`, etc. in `security/mac_framework.h`
- For each sensitive syscall, verify the corresponding hook is called before privilege is exercised
- Missing hooks allow operations to bypass security policies that assume hook coverage is complete

---

## 4. Verification methodology

### 4.1 Static: struct layout arithmetic

When an agent flags a write that may exceed a field boundary, calculate the layout by hand before filing anything. The example below is based on a generic variable-length record pattern common in kernel filesystem code and is included to illustrate the verification technique, not to describe any specific vulnerability.

```python
# Generic struct layout and record-size verification
# Adapt field sizes and formula to the target struct
import math

MAXPATHLEN = 1024  # typical Darwin constant

# Example struct layout (adapt to your target):
#   field_a:   uint64_t  — 8 bytes, offset 0
#   field_b:   uint64_t  — 8 bytes, offset 8
#   field_c:   uint16_t  — 2 bytes, offset 16
#   field_d:   uint16_t  — 2 bytes, offset 18
#   field_e:   uint8_t   — 1 byte,  offset 20
#   varfield:  char[MAXPATHLEN] — 1024 bytes, offset 21
# sizeof(struct) = ceil(1045 / 8) * 8 = 1048  (8-byte alignment)

sizeof_struct   = math.ceil((8+8+2+2+1+MAXPATHLEN) / 8) * 8   # 1048
offsetof_var    = 8+8+2+2+1                                      # 21

def record_len(total_vardata):
    """Variable-length record allocation formula — equivalent to NFS_DIRENTRY_LEN."""
    return (sizeof_struct + total_vardata - (MAXPATHLEN - 1) + 7) & ~7

# Verify worst case: maximum name + maximum extra payload
namlen = MAXPATHLEN - 1   # 1023 (truncated to fit the fixed array field)
xlen   = 137               # extra payload (e.g. file handle + timestamp)
reclen = record_len(namlen + xlen)          # total allocation
avail  = reclen - offsetof_var              # bytes available from varfield[0]
needed = namlen + 1 + xlen                  # bytes actually written
print(f"reclen={reclen}, avail={avail}, needed={needed}, safe={avail >= needed}")
# → reclen=1192, avail=1171, needed=1161, safe=True
# The writes land within the allocated record, not just within the fixed array field.
```

This kind of verification takes five minutes and definitively rules in or out a class of agent findings. The key insight: in variable-length record patterns, the struct's fixed field size is not the allocation boundary. The `reclen` is.

### 4.2 Empirical: VM-based hypothesis testing

Static analysis tells you what *should* happen; a test VM tells you what *does* happen. All probes below are run against **your own test VM only.**

```python
import socket, struct

# Generic TCP probe skeleton for a length-prefixed binary protocol.
# Run ONLY against systems you own or have written authorisation to test.
def send_probe(host, port, payload):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(3)
    s.connect((host, port))
    # Length-prefixed framing — adjust header format for target protocol
    s.send(struct.pack(">H", len(payload)) + payload)
    try:
        resp = s.recv(4096)
        print(f"[+] Response received: {resp[:32].hex()}")
    except socket.timeout:
        print("[!] Timeout — no response")
    except ConnectionResetError:
        print("[!] RST — daemon closed connection (check syslog)")
    finally:
        s.close()

# Example: probe with a payload shorter than the minimum protocol header
# Replace host and port with your own VM's address
send_probe("192.168.64.X", TARGET_PORT, b"\x00\x01\x02")
```

After each probe, check logs on the test VM:

```bash
log show --last 1m --predicate 'process == "targetdaemon"' \
  | grep -iE "error|crash|assert|abort"
sudo dmesg | tail -20
ls -lt ~/Library/Logs/DiagnosticReports/ | head -10
```

### 4.3 Distinguishing DoS from memory corruption

A daemon restart after a probe does *not* mean memory corruption. Triage by crashlog, not by symptom alone.

| Symptom | Likely cause | Signal strength |
|---|---|---|
| Daemon exits cleanly after probe | Assertion / `abort()` | Check crashlog — may be intentional |
| Connection reset, no crash | Parser returned error and closed | Weak — usually clean rejection |
| Daemon silently drops connection | Timeout or framing error | Weak |
| Kernel panic with fault address | Kext memory corruption | Strong — investigate thoroughly |
| Malformed output in subsequent call | State corruption | Investigate |

---

## 5. Dead-end tracking

Every ruled-out target should be documented with the *reason* it was ruled out. Without this, the same targets get re-examined in future sessions.

A minimal dead-end record:

```
## tftpd — RULED OUT 2026-04

Disabled by default (no LaunchDaemon plist active on clean install).
Only reachable on explicitly-configured servers. Not a viable
pre-authentication attack surface for general-population devices.
```

```
## bootpd — RULED OUT 2026-04

Listens only on 255.255.255.255 broadcast. Source review of
bootpd.c handle_client_packet() shows the dhcp_packet struct is
stack-allocated at a fixed size and all field accesses are bounds-checked
via the 'end' pointer passed through the call chain. No viable overflow path.
```

Keeping this log prevents revisiting dead ends and surfaces patterns — if several daemons in a row are clean in the same way, reconsider the target class rather than continuing through the list mechanically.

---

## 6. The AI agent feedback loop

The most efficient workflow structure found:

```
1. Human selects target + defines threat model
        ↓
2. Agent reads source files, flags candidate locations
        ↓
3. Human triages agent output:
   a. Obvious false positive (struct layout, protocol constraint) → document + discard
   b. Plausible → hand-verify (layout math, empirical VM probe)
   c. Confirmed → write up for disclosure
        ↓
4. Human updates dead-end log, selects next target
        ↓
   repeat
```

Calibrations learned through this workflow:

- **Agents over-flag integer arithmetic.** Any subtraction involving a field read from the wire will be flagged. Most are safe because of upstream guards in a different function. Always trace the full guard chain before concluding.
- **Agents under-flag missing features.** An agent reading a syscall implementation will not notice that a MAC framework hook is absent — it only sees what is there, not what *must* be there. Auditing completeness requires the human to hold the mental model of what the framework requires.
- **Threat model precision matters.** An agent asked "find bugs" returns noise. An agent asked "given a malicious server controls all wire-format fields, can any arithmetic produce a value that bypasses the bounds check at line N?" returns actionable output.

---

## 7. Responsible disclosure

All findings from this workflow are handled through Apple's responsible disclosure process. Practical notes:

- File through the web form at `security.apple.com/research` with a clear title, affected component, macOS version, reproduction steps, and impact assessment.
- Apple assigns an `OE` tracking number. Response times vary; expect 2–12 weeks for initial triage acknowledgement.
- Do not disclose publicly until Apple has shipped a fix and assigned a CVE, or 90 days have elapsed — whichever comes first — unless Apple requests an extension with a credible timeline.
- Follow NCSC coordinated disclosure guidance: [https://www.ncsc.gov.uk/information/vulnerability-reporting](https://www.ncsc.gov.uk/information/vulnerability-reporting)
- The [Apple Security Research Device (SRD) programme](https://security.apple.com/research/#program) provides modified hardware with relaxed security for sustained kernel research. Worth applying for if this is ongoing work.

---

## 8. Tooling summary

| Task | Tool |
|---|---|
| Source triage | `grep`, `nm`, `otool -tV` |
| Network surface mapping | `lsof -nP -iTCP -iUDP` (own system only) |
| Entitlement inspection | `codesign -d --entitlements -` |
| Protocol probe skeleton | Python `socket` + `struct` (own system only) |
| Kernel log monitoring | `log show`, `dmesg`, `sudo dtrace` |
| Struct layout verification | Python arithmetic (see §4.1) |
| AI-assisted first-pass audit | Claude Code with focused agent prompts |
| Dead-end tracking | Plain Markdown in the research repository |

---

## 9. Closing thoughts

The combination of Apple's open-source releases and AI-assisted code reading has substantially changed the economics of platform security research. Work that would previously require weeks of reverse engineering can now begin with a readable source tree and a focused agent prompt.

The bottleneck has shifted from *finding* candidate locations to *verifying* them rigorously. False positives from automated tools cost time and erode confidence in the toolchain. The verification discipline in §4 — struct-layout arithmetic and the empirical VM loop — is what separates filed bugs from wasted effort. In practice, a well-structured agent first-pass followed by careful human verification produces a lower false-positive rate than either approach alone.

The most productive mindset: treat every agent finding as a hypothesis, not a result. The agent reads code; the human understands systems.

---

## References and credits

### Primary source material

| Source | URL | Notes |
|---|---|---|
| apple-oss-distributions | https://github.com/apple-oss-distributions | Apple's open-source releases — primary audit target |
| XNU kernel source | https://github.com/apple-oss-distributions/xnu | Core kernel, MAC framework, syscall table |
| NFS kext source | https://github.com/apple-oss-distributions/NFS | NFS client/server kernel extension |
| mDNSResponder source | https://github.com/apple-oss-distributions/mDNSResponder | Bonjour / DNS-SD / DoT proxy daemon |
| network_cmds source | https://github.com/apple-oss-distributions/network_cmds | `ping`, `traceroute`, `netstat`, et al. |
| SMBClient source | https://github.com/apple-oss-distributions/SMBClient | SMB2/3 kernel client |

### Responsible disclosure programmes and legal guidance

| Resource | URL |
|---|---|
| Apple Security Bounty | https://security.apple.com/bounty/ |
| Apple Security Research Device Programme | https://security.apple.com/research/#program |
| Google Chrome Vulnerability Reward Programme | https://g.co/chrome/vrp |
| NCSC Vulnerability Reporting Guidance | https://www.ncsc.gov.uk/information/vulnerability-reporting |
| CPS Cybercrime Prosecution Guidance | https://www.cps.gov.uk/legal-guidance/cybercrime |
| Computer Misuse Act 1990 (legislation.gov.uk) | https://www.legislation.gov.uk/ukpga/1990/18/contents |
| Police and Justice Act 2006 (legislation.gov.uk) | https://www.legislation.gov.uk/ukpga/2006/48/contents |
| ISO/IEC 29147 — Vulnerability Disclosure | https://www.iso.org/standard/72311.html |
| ISO/IEC 30111 — Vulnerability Handling Processes | https://www.iso.org/standard/69725.html |

### Protocol specifications (IETF RFCs)

All RFCs are freely available at [https://www.rfc-editor.org](https://www.rfc-editor.org).

| RFC | Title | Authors | Year | Relevance |
|---|---|---|---|---|
| RFC 1035 | Domain Names — Implementation and Specification | Mockapetris | 1987 | DNS wire format |
| RFC 7858 | Specification for DNS over TLS | Hu, Zhu, Heidemann, Mankin, Wessels, Hoffman | 2016 | TCP 853 framing |
| RFC 1813 | NFS Version 3 Protocol Specification | Callaghan, Pawlowski, Staubach | 1995 | READDIR+, XDR types |
| RFC 4506 | XDR: External Data Representation Standard | Eisler (ed.) | 2006 | Wire encoding for NFS/RPC |
| RFC 5531 | RPC: Remote Procedure Call Protocol Specification Version 2 | Thurlow | 2009 | TCP record framing |
| RFC 7530 | Network File System (NFS) Version 4 Protocol | Haynes, Noveck | 2015 | File handle size limits |
| RFC 2131 | Dynamic Host Configuration Protocol | Droms | 1997 | DHCP packet structure |

### Academic and technical foundations

| Work | Authors | Publisher / Venue | Year |
|---|---|---|---|
| [The TrustedBSD MAC Framework](https://www.usenix.org/legacy/event/usenix03/tech/full_papers/watson/watson.pdf) | R. Watson, W. Morrison, C. Vance, B. Feldman | USENIX Annual Technical Conference | 2003 |
| [Exploiting the Linux Kernel via Packet Sockets](https://googleprojectzero.blogspot.com/2017/05/exploiting-linux-kernel-via-packet.html) | A. Sotirov | Google Project Zero blog | 2017 |
| [The Mac Hacker's Handbook](https://www.wiley.com/en-us/The+Mac+Hacker%27s+Handbook-p-9780470395363) | C. Miller, D. Dai Zovi | Wiley | 2009 |
| [iOS Hacker's Handbook](https://www.wiley.com/en-us/iOS+Hacker%27s+Handbook-p-9781118204122) | C. Miller, D. Blazakis, D. DaiZovi, S. Esser, V. Iozzo, R. Weinmann | Wiley | 2012 |
| [A Guide to Kernel Exploitation](https://www.elsevier.com/books/a-guide-to-kernel-exploitation/perla/978-1-59749-557-5) | E. Perla, M. Oldani | Elsevier / No Starch Press | 2010 |

### Community and prior art

The broader security research community whose published work informed this approach — credit and gratitude to:

- **Google Project Zero** — [googleprojectzero.blogspot.com](https://googleprojectzero.blogspot.com) — methodology standards, disclosure policy, and detailed write-ups that remain the gold standard for kernel vulnerability research documentation
- **Ian Beer** — XNU and IOKit vulnerability research; his Project Zero posts on iOS kernel exploitation are among the most instructive publicly available resources for Darwin internals
- **Jann Horn** — integer overflow and race condition analysis in kernel code; his review methodology is a model for the verification approach in §4
- **Natalie Silvanovich** — XPC, IPC, and browser attack surface research
- **Brandon Azad** — macOS/iOS privilege escalation and MACF analysis
- **Stefan Esser** — early macOS kernel and iOS jailbreak research establishing much of the baseline understanding of Darwin security boundaries

Where possible, read the original bug reports and Project Zero issue tracker entries rather than secondary summaries. The reasoning documented there is as valuable as the finding itself.

### Tools and frameworks

| Tool | Source / Attribution | Purpose |
|---|---|---|
| `nm` | LLVM Project / Apple (bundled with Xcode) | Symbol extraction from Mach-O binaries |
| `otool` | Apple (bundled with Xcode) | Mach-O disassembly and load command inspection |
| `codesign` | Apple (bundled with Xcode) | Entitlement and code signature inspection |
| `lsof` | V. Abell — [github.com/lsof-org/lsof](https://github.com/lsof-org/lsof) | Network socket and file descriptor enumeration |
| DTrace | Sun Microsystems / Oracle; [OpenDTrace](https://github.com/opendtrace) | Dynamic kernel tracing |
| `log` (Unified Logging) | Apple | macOS structured system log query |
| Python `socket` / `struct` | Python Software Foundation — [docs.python.org](https://docs.python.org/3/library/struct.html) | Binary protocol framing in probe scripts |
| Claude Code | Anthropic — [claude.ai/code](https://claude.ai/code) | AI-assisted static analysis agent framework |

---

### A note on AI-assisted research

The agent-assisted audit workflow described in §3 uses [Claude Code](https://claude.ai/code) (Anthropic, 2024). The role of the AI is that of a fast, tireless first-pass reader — not an authority. Every candidate location it surfaces requires human verification. The false-positive examples in this document (§3.1, §4.1) arose from exactly this workflow: the agent correctly identified code that *looked* dangerous; the human verified it was safe. Both outcomes are useful. The discipline of verification is what makes the tool productive rather than noisy.

AI assistance in security research is new enough that norms are still forming. This document's position: the AI is a junior analyst. It reads fast, misses context, and is confidently wrong about allocation patterns. The human is the senior engineer who understands the system model, traces the guard chain, and takes responsibility for any filing.

---

## Licence

This document is licensed under the **Creative Commons Attribution 4.0 International (CC BY 4.0)** licence.

[![Licence: CC BY 4.0](https://img.shields.io/badge/Licence-CC%20BY%204.0-lightgrey.svg)](https://creativecommons.org/licenses/by/4.0/)

You are free to:
- **Share** — copy and redistribute the material in any medium or format
- **Adapt** — remix, transform, and build upon the material for any purpose, including commercially

Under the following terms:
- **Attribution** — You must give appropriate credit, provide a link to the licence, and indicate if changes were made. You may do so in any reasonable manner, but not in any way that suggests the licensor endorses you or your use.

Full licence text: [https://creativecommons.org/licenses/by/4.0/legalcode](https://creativecommons.org/licenses/by/4.0/legalcode)

**Suggested attribution:**
> *Darwin/macOS Security Audit Methodology* by Stuart Thomas, published under CC BY 4.0. Available at: [repository URL]

---

*This document describes lawful security research methodology conducted against researcher-owned systems and code published openly under open-source licences. Nothing herein constitutes legal advice. All findings arising from this workflow are handled through vendor responsible-disclosure programmes. Readers outside England and Wales should consult the equivalent legislation in their jurisdiction — in particular the Computer Fraud and Abuse Act (USA), §202a StGB (Germany), and analogous provisions elsewhere.*
