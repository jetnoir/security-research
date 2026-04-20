# Security Research — Publications

Public research papers and methodology documents by **Stuart Thomas** ([@jetnoir](https://github.com/jetnoir)).

These documents cover applied security research, audit methodology, and updated editions of earlier published work. All content is educational. Proof-of-concept code is for defensive use only — see each document's legal notice.

---

## Documents

### [Spectral Complexity Screening for Binary Security Analysis — 2026](triageforge-2026.md) · [PDF](triageforge-2026.pdf)

**A Random Matrix Theory Approach to Automated Vulnerability Triage**

Original research applying spectral methods from quantum physics and network science to binary vulnerability analysis. Introduces TriageForge, a four-stage pipeline:

- **C1** — SAT backbone proximity score (3-SAT phase transition at α_c ≈ 4.267)
- **C2** — Random Matrix Theory spectral screen (Wigner semicircle, Tracy–Widom, graph energy, eigenvalue entropy z-scored against configuration-model null)
- **C3** — Template dataflow analysis with cyclomatic complexity gate
- **C6** — Symbolic taint analysis via angr

Empirically validated on 335 macOS 26 PrivateFrameworks ARM64e binaries. 96.4% corpus reduction, characteristic false-positive taxonomy (cryptographic S-box tables, standard library sorting, no-network-surface binaries). First published application of RMT universality results and SAT backbone theory to binary security triage.

---

### [ICMP: Crafting and Other Uses — 2026 Edition](icmp-tunneling-2026.md) · [PDF](icmp-tunneling-2026.pdf)

Updated edition of the author's 2001 GIAC GSEC paper, listed in the external links of the [Wikipedia ICMP tunnel article](https://en.wikipedia.org/wiki/ICMP_tunnel).

The original paper introduced ICMP covert channel theory, the LOKI tool, and hypothetical gateway scenarios. The 2026 edition adds:

- Full Python PoC (server + client + shared library) with session framing
- Scapy-based packet crafting equivalents
- ICMPv6 extension
- Modern C2 tooling landscape (nping, ptunnel-ng, icmptunnel)
- Suricata detection rules + eBPF XDP enforcement
- Legal framework (CMA 1990, CFAA, EU Directive 2013/40/EU)

---

### [Why SQL Injection Won't Go Away — 2026 Edition](sql-injection-2026.md) · [PDF](sql-injection-2026.pdf)

Updated edition of the author's c.2006 paper, listed in the external links of the [Wikipedia SQL injection article](https://en.wikipedia.org/wiki/SQL_injection).

The original paper framed SQL injection as a dual business and technical problem, citing Rain Forest Puppy's 1998 Phrack article and Ross Anderson's economic asymmetry argument. The 2026 edition adds:

- Full attack taxonomy (classic, blind, time-based, error-based, OOB, second-order, NoSQL, ORM, GraphQL)
- Python detection script (`sql_probe.py`) and log monitor (`sql_log_monitor.py`)
- sqlmap command reference and parameterised query fixes (Python, Django, SQLAlchemy)
- LLM-generated vulnerable code as a new 2026 attack surface
- UK GDPR / DPA 2018 legal framework with ICO enforcement analysis
- Business case ROI table (prevention vs breach cost)

---

## Licence

All documents: **Author retains full rights.**

The methodology document and 2026 editions are additionally released under [Creative Commons Attribution 4.0 International (CC BY 4.0)](https://creativecommons.org/licenses/by/4.0/) — you may adapt and redistribute with attribution.

---

## Legal Notice

Proof-of-concept code is published for educational and defensive security purposes only. Use only on systems you own, control, or have **explicit written authorisation** to test. Unauthorised use may constitute a criminal offence under the Computer Misuse Act 1990 or equivalent legislation in your jurisdiction. Nothing in this repository constitutes legal advice.

---

*Stuart Thomas · [@jetnoir](https://github.com/jetnoir) · April 2026*
