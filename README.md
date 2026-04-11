# Security Research — Publications

Public research papers and methodology documents by **Stuart Thomas** ([@jetnoir](https://github.com/jetnoir)).

These documents cover applied security research, audit methodology, and updated editions of earlier published work. All content is educational. Proof-of-concept code is for defensive use only — see each document's legal notice.

---

## Documents

### [Darwin/macOS Audit Methodology](darwin-audit-methodology.md) · [PDF](darwin-audit-methodology.pdf)

A show-and-tell methodology document covering the techniques used to systematically audit Darwin/XNU kernel and macOS system components for security vulnerabilities. Topics include:

- Legal framework (Computer Misuse Act 1990)
- Attack surface enumeration (XPC services, kernel extensions, entitlements)
- AI-assisted source audit and struct layout verification
- Empirical VM-based testing with DTrace and fs_usage
- Responsible disclosure and Apple Security Bounty

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
