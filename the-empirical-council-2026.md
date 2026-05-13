<!--
Title:    The Empirical Council: Adversarial LLM Review with Hallucination Detection in Solo Security Research
Author:   Stuart Thomas
Date:     2026-05-13
License:  Creative Commons Attribution 4.0 International (CC BY 4.0)
          https://creativecommons.org/licenses/by/4.0/
Format:   Markdown
-->

# The Empirical Council

### Adversarial LLM Review with Hallucination Detection in Solo Security Research

**A single-day case study of three filings, fifteen refutations, and the manpage that wasn't**

**Stuart Thomas** · 13 May 2026
*Licensed under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/)*

---

## Abstract

Solo vulnerability research has a signal-to-noise problem that gets worse as
the day gets longer. Source-code reading produces high-confidence hypotheses
faster than a single human can empirically falsify them; the result is a
steady drip of bad submissions to maintainer mailing lists and bug-bounty
portals, each of which costs a small slice of researcher reputation and
maintainer patience. This paper documents one day's worth of disciplined
pre-filing review using a panel of four commodity large language models
(DeepSeek, Grok, ChatGPT, Gemini) as adversarial reviewers, with an explicit
empirical-verification gate inserted between LLM verdict and submission. In
the course of the day, three vulnerability reports were filed (one with
Apple Security Bounty, two with the OpenBSD developers); fifteen separate
candidate findings were refuted before filing; eleven novel methodology
rules were banked; and — to the author's considerable amusement — two of
four LLMs were caught hallucinating identical fictitious text from an
OpenBSD manual page that has not contained that text since at least the 7.7
release. The paper presents the methodology, the day's case studies, the
hallucination-detection technique, and a candid post-mortem of the
filings — including a pair of corrections from Theo de Raadt that are
reproduced verbatim because they are funnier in the original.

**Keywords:** vulnerability research methodology · large language models ·
hallucination detection · responsible disclosure · pre-filing review ·
empirical verification · OpenBSD · Apple Security Bounty

---

## 1. Introduction

The structural pathology of solo security research is that the analyst is
also the reviewer. A working professional may read a thousand lines of
kernel source in an afternoon and emerge with a confident hypothesis about
an unfixed memory leak; the same professional is then expected to be the
person who notices that the hypothesis is wrong. This is a difficult ask
even when one is fresh, well-fed and not also debugging six hung XPC
clients.

The bug-bounty and open-source communities have evolved several immune
responses to bad submissions. The Apple Product Security Response Team
(PSRT) routinely closes reports as "expected behavior" without comment.
The OpenBSD developers have a long tradition of public, terse, and
educational corrections, of which more below. The XPR research community
has its own folklore around the "verification flaw" — submissions that
were technically accurate observations of safe code, framed as exploits
they were not. Each of these immune responses is calibrated to a noise
floor that exists primarily because individual researchers do not
self-falsify aggressively enough.

This paper documents one day's experiment in installing a more aggressive
falsifier between the source-read and the send button. The construction
is not novel in its components — using multiple language models for
adversarial review has been tried by others, as has empirical
verification — but the combination, applied consistently across a working
day of nine candidate findings, produced an unusually clean ratio of
filings to refutations and surfaced an LLM-hallucination class that the
author has not previously seen explicitly named.

The intended audience is solo or small-team security researchers
contemplating their own version of the practice. The intended argument is
that the marginal cost of running four LLMs over a draft submission is
small compared to the marginal cost of a maintainer's "get used to
disappointment."[^deraadt-1]

[^deraadt-1]: Theo de Raadt, OpenBSD bugs@openbsd.org, 13 May 2026,
in reply to one of the two submissions documented in §4.

---

## 2. Method

### 2.1 The Empirical Council

The Council, as the author has come to call it,[^council-name] consists of
four commodity LLMs accessed via their public chat interfaces:

| Reviewer       | Role               |
| -------------- | ------------------ |
| DeepSeek-R1    | Source-pattern eye |
| Grok-4         | Adversarial framing |
| GPT-5          | Devil's advocate   |
| Gemini 3       | Pillar / framing   |

A "Council prompt" is a structured document in four parts:

1. **Finding summary** — the candidate in two paragraphs.
2. **Technical evidence** — source quotes, disassembly snippets, runtime
   output, all reproduced verbatim from artefacts the researcher can re-pull.
3. **Four questions** — fixed across all candidates: (a) is this genuine
   or by-design? (b) is the impact material? (c) is the evidence sufficient
   to file? (d) what is the correct venue?
4. **Symmetric burden of proof** — explicit instruction that each reviewer
   must defend any "intended behaviour" reading with concrete documentation
   and each "real bug" reading with a concrete harm path.

The prompt is pasted into each of the four chat sessions in succession.
The four verdicts arrive within minutes. The researcher then synthesises a
consolidated verdict. A `GO` outcome means all four reviewers cleared the
candidate; `CONDITIONAL-GO` means at least one demanded an additional
artefact (a clean PoC, a category sweep, an amd64 confirmation); `NO-GO`
means at least one reviewer named a fatal flaw.

[^council-name]: The term "Empirical Council" is used here to distinguish
the practice from the prior art of using one LLM as a code reviewer; the
distinction is that this Council requires its verdicts to be falsifiable
against ground truth, and includes an explicit step for doing so.

### 2.2 The Empirical Gate

The novel structural element is what happens *between* the LLM verdicts and
the submission. Before the draft email is sent, the researcher attempts to
empirically verify each substantive claim the LLMs made — including claims
they made *about their own evidence*. Any claim attributed to documentation
is re-read from the documentation as it exists *in this session*. Any claim
attributed to a fix commit is re-read from the commit log. Any claim about
runtime behaviour is reproduced on the actual target.

This step exists because LLMs, in the author's experience, hallucinate most
confidently when they are quoting documentation they expect to exist rather
than documentation they have read. The classic shape is a paraphrase
presented as a verbatim quote; the next classic shape is a paraphrase
presented as a verbatim quote of text that has not existed in the cited
document for several major versions.

### 2.3 The Filing Discipline

The submission text is drafted only after the Council has cleared the
candidate and the empirical gate has passed. The text is then itself
subjected to one final empirical pass: every string that appears between
quotation marks in the email body is re-pasted from the source as it
exists *now*. This rule emerged later in the day, the hard way, and is
discussed in §5.

---

## 3. The XPR-Pattern Slip

A useful term for the failure mode this methodology is designed to catch
is the *XPR-pattern slip*. The label is internal to the author's research
and refers to a withdrawn XProtect Remediator submission whose technical
content was accurate but whose framing was not: a confident source-read
proposed an exploit, a confident PoC architecture verified itself rather
than the system, and a confident submission asserted a primitive that did
not exist.

The pattern recurs:

> *A source-derived hypothesis with high confidence that collapses on
> empirical test. The hypothesis is usually structurally correct ("this
> function does X") but inferentially wrong ("therefore X is reachable" /
> "therefore X is exploitable" / "therefore Y also has the same shape").
> The slip is not in the observation but in the inference, and the only
> reliable corrective is empirical falsification at the inference step,
> not just at the observation step.*

A condensed summary of the day's slips appears in Table 1. Each was caught
before submission, either by the Council, the empirical gate, or — in two
cases — by the OpenBSD developers, who declined to be polite about it.

**Table 1.** Candidates examined and refuted, 13 May 2026.

| # | Candidate                                    | Caught by              |
|--:| -------------------------------------------- | ---------------------- |
| 1 | OpenBSD `msgctl` IPC_STAT pointer leak       | PoC: kernel never writes the fields claimed leaked |
| 2 | iWork QuickLook ZIP64 wrap arithmetic (P2)   | Phase 3 PoC: parser bailed before reaching arithmetic |
| 3 | Apple Model I/O Phase 2 (9 USDZ PoCs)        | QuickLook headless test: all 9 refused without crash |
| 4 | Apple Model I/O Phase 3 (Apple-fork diff)    | Binary `strings`: Apple cherry-picks upstream fixes |
| 5 | macOS `wifivelocityd` Rapport bypass         | Dynamic harness: Rapport framework gates on `com.apple.CompanionLink` |
| 6 | macOS Font.mdimporter sfnt name parser       | Disassembly: bounds checks are correct |
| 7 | macOS Font.mdimporter suitcase Pascal string | Disassembly: disclosure bounded to attacker's own file |
| 8 | OpenBSD `iked` sibling-validate hunt         | Source read: active audit area, no unfixed siblings found |
| 9 | Cross-BSD CVE-2025-0373 (`ifid` overflow)    | Source compare: OpenBSD inode is 32-bit, struct is 16 bytes, no overflow |
| 10 | macOS `uarpd` Phase 2 v1 (UARPKit)          | Wrong binary: thin NSXPC client wrapper, no parser |
| 11 | macOS `uarpd` Phase 2 v2 (CoreUARP)         | All four daemons gate listener with `valueForEntitlement:` |
| 12 | macOS `imagent` IMDBackgroundMessagingAPIListener | Listener uses anonymous endpoint, not a named mach service |
| 13 | macOS `imagent` IMDIncomingClientConnectionListener | Class is not instantiated by any shipping binary on 26.4.1 |
| 14 | macOS `imagent` endpoint-handoff bypass     | Only one endpoint-handing method exists; targets a re-gated service |
| 15 | macOS `handwritingd` Phase 7 residency      | 5.5 GB core: zero hits for injected contact marker |

The three findings filed on the same day appear in Table 2. They are
preserved here because they are themselves data: two of the three
encountered post-filing corrections that further illustrate the
methodology's limits.

**Table 2.** Filings sent, 13 May 2026.

| Finding | Venue | Outcome at end of day |
|---|---|---|
| `dasd` `%{public}` log annotations expose entitlement-gated app identifiers to unprivileged processes | Apple Security Bounty (filed previous evening) | Received, awaiting OE assignment |
| OpenBSD `ktr_psig()` 4-byte padding-hole stack disclosure | `bugs@openbsd.org` | Reply ×2 from de Raadt; substantive merit not yet ruled on |
| OpenBSD `pledge(2)` `kill(0, sig)` permitted under any promise via `pid==0` exception, manpage lists `kill(2)` only under `proc` | `bugs@openbsd.org` | Closed by de Raadt as intended behaviour |

---

## 4. Case Study: The Manpage That Wasn't

The most instructive of the day's candidates is the OpenBSD `pledge(2)`
documentation-versus-implementation inconsistency. It is instructive
because the Council failed in an interesting way and the empirical gate
caught the failure.

### 4.1 The Observation

The kernel's gate for `kill(2)` under any pledge is the function
`pledge_kill()` in `sys/kern/kern_pledge.c`. As of the OpenBSD master
branch on 13 May 2026, that function reads:

```c
int
pledge_kill(struct proc *p, pid_t pid)
{
    if ((p->p_p->ps_flags & PS_PLEDGE) == 0)
        return 0;
    if (p->p_pledge & PLEDGE_PROC)
        return 0;
    if (pid == 0 || pid == p->p_p->ps_pid)
        return 0;
    return pledge_fail(p, EPERM, PLEDGE_PROC);
}
```

The third branch is a universal exception: regardless of which promise the
process holds, `kill(0, sig)` (the BSD process-group-wide kill) and
`kill(getpid(), sig)` (the self-signal) are permitted. The
`pledge(2)` manual page lists `kill(2)` only under the `proc` promise;
the introductory description of `stdio` does not mention the exception.

The author's hypothesis was that this is a documentation-versus-implementation
mismatch and that one of two one-line patches would resolve it. The
candidate was put to the Council under the same four questions as every
other.

### 4.2 The Hallucination

DeepSeek-R1 and Grok-4 both responded with the following text, in
substantially identical wording (Grok's appearing to mirror DeepSeek's
phrasing closely enough that the author suspects either common training
data or an accidental duplicate paste; the two transcripts are otherwise
distinct, so the convergence is not a duplication of the user's prompt):

> "The manpage for stdio in a current release (including 7.7) already
> lists `kill(2)` as permitted under stdio, with an explicit qualifier
> that the pid argument must be 0 or the calling process's PID."

By the reviewers' own logic — both of them used the conditional "GO if
the manpage does not document the exception" — this should have killed
the candidate. The author opened a second terminal, SSH'd into the
OpenBSD 7.7 virtual machine that had been running the previous PoC, and
typed `man pledge`. The `stdio` promise section reads, verbatim:

> "**stdio**   The following system calls are permitted. `sendto(2)` is
> only permitted if its destination socket address is `NULL`. As a
> result, all the expected functionalities of libc stdio work."

What follows is a flat list of permitted syscalls. `kill(2)` does not
appear on that list. The word "kill" does not appear in the `stdio`
section at all. `kill(2)` appears only under the `proc` promise. The
DeepSeek/Grok claim was, as the methodology section euphemistically
puts it, *not present in the source as cited*.

ChatGPT-5 and Gemini-3.0 did not make this claim. Their conditions for
GO were structural — a cleaner self-isolating PoC, a softer framing of
the disposition — and were satisfied by trivial revisions. With the
DeepSeek/Grok condition empirically falsified (the manpage does not
contain the text they cited), all four reviewers' conditions collapsed to
GO under a documentation-clarification framing.

The candidate was filed. The thread is reproduced in §4.4 for
methodological completeness.

### 4.3 What the Hallucination Was Probably Doing

The author has no privileged information about either model's internals.
A reasonable hypothesis is that both models were drawing on prior pledge
documentation, pledge mailing-list discussion, or third-party explanations
in which the `pid==0` exception is described — combined with a
confabulated attribution of that description to the manpage itself. The
shape is the *attribution slip*: the substantive content (the exception
exists) is correct; the attribution (the manpage documents it) is not.

The most useful observation for downstream researchers is that the slip
is unlikely to be detectable from inside the LLM session. The model
returns the hallucination with the same confidence interval as a real
quote. Detection requires reading the cited source — in this case, the
six-line section of `pledge(2)` — *from the source as it currently
exists*, not from any cached reading.

### 4.4 The Reply

The submission email framed the finding as an inquiry, presented both
fix paths (documentation patch or code patch) without advocating, and
explicitly disclaimed any exploitability beyond sandbox-degradation. Two
replies arrived from Theo de Raadt within fifteen minutes of each other.

The first:

> "This is intended behaviour. In fact it is REQUIRED behaviour. You
> could try changing it and seeing the effect. Did you? Clearly you
> didn't. > this is live code diverging from the documented contract.
> Get used to disappointment."[^deraadt-2]

The second, in reply to the same thread:

> "> A stdio-pledged process is, per the documented contract, supposed
> to only act on already-open file descriptors and process-internal
> state.
>
> The manual page does not say that. It does however say the following:
>
>     As a result, all the expected functionalities of libc stdio work."[^deraadt-3]

The second reply identifies a misquote in the submission. The submission
included the phrase *"actions that only occur inside the process"*
attributed to the manpage. The phrase was carried forward from the
Council prompt, where it had been used as a paraphrase of the design
intent, and was not present in the current `pledge(2)`. The misquote was
the author's; it survived the day's methodology because the rule about
re-pasting all quoted text from current sources was not yet in force at
the time the submission was drafted. It is in force now.

A third reply, ten minutes later, in the thread about the *other*
OpenBSD filing of the day (`ktr_psig` padding leak), addressed an
imprecision about kernel-address randomisation terminology:

> "OpenBSD does not have this thing called KASRL, so how do you weaken
> something which doesn't exist?"[^deraadt-4]

OpenBSD has KARL (Kernel Address Randomized Layout — a per-boot relink),
not KASLR (the Linux/macOS terminology for runtime address-space
randomisation). The author had used the broader-industry term. The
correction is technically correct, and another methodology rule was banked.

The pledge `kill(0)` thread closed with the first reply quoted above.
The `ktr_psig` thread remains open at the time of writing; the
terminology correction is not a substantive merit ruling.

[^deraadt-2]: Theo de Raadt, OpenBSD bugs@openbsd.org, 13 May 2026 14:50 BST.
[^deraadt-3]: Theo de Raadt, OpenBSD bugs@openbsd.org, 13 May 2026 14:55 BST.
[^deraadt-4]: Theo de Raadt, OpenBSD bugs@openbsd.org, 13 May 2026 15:17 BST.

---

## 5. The Eleven Rules

Eleven distinct procedural rules were either established for the first
time or substantially refined over the course of the day. They are listed
here in order of the candidate that produced them, with brief commentary.

1. **PoC before draft.** A source-derived hypothesis is not a finding
   until a Proof of Concept demonstrates an attacker-observable artefact.
   (Source: `msgctl` IPC_STAT, refuted because the kernel never writes
   the fields the source-read claimed leaked.)

2. **Counter-read the writer.** For any "field X is leaked" claim,
   identify the code path where the kernel/daemon writes X *before*
   filing. Absence of writes is fatal to the claim. (Same source.)

3. **Phase 2 disassembly trails can be wrong.** A confident Phase 2
   disassembly that points at a candidate function is not a guarantee
   that the function is reachable from the trigger. Phase 3 (empirical
   trigger) must agree. (Source: iWork QuickLook; the Phase 2 trail
   pointed at ZIP64 arithmetic, Phase 3 hit a JPEG-size hang.)

4. **Apple forks may be hardened beyond public source.** When the
   target is an Apple-shipped library forked from a public project,
   public-source-derived PoCs may all fail against the fork. Verify
   against the binary, not against the upstream. (Source: Model I/O /
   `libusd_ms`, which cherry-picks upstream security fixes onto an
   apparently old branch.)

5. **Framework-level gates may exist beyond binary-local checks.** A
   missing entitlement check in a daemon binary does not imply a missing
   check overall; the framework that brokers the IPC may gate on a
   different entitlement at the dispatch layer. (Source: `wifivelocityd`,
   where Rapport.framework requires `com.apple.CompanionLink` before
   any client request is delivered.)

6. **Anonymous listeners are not reachable without endpoint handoff.**
   An NSXPCListener with no `machServiceName:` set is not bindable from
   uid=501; its endpoint must be returned from another reachable XPC
   call. The absence of such a call invalidates a "missing entitlement
   check on the listener" claim. (Source: `imagent` Phase 2; the listener
   has no name, no endpoint is handed out for it.)

7. **`__objc_stubs` trampolines are not direct calls.** A `bl <addr>`
   instruction whose target lies in the `__TEXT,__objc_stubs` section is
   a per-selector dispatch trampoline, not a function call. Treating it
   as a direct call produces wrong reachability analysis. (Source:
   `imagent` Phase 2; this was the specific tool error that initially
   caused the analyst to mis-attribute call edges.)

8. **Name the exact binary, not the framework family.** When a track is
   blocked on a dyld-shared-cache extract, the gate text must name the
   exact framework binary expected to contain the parser, not the
   broader name with which it might be confused. (Source: `uarpd` Phase 2,
   which spent its first attempt examining UARPKit when the parser is in
   CoreUARP and the daemons themselves.)

9. **Use OS-native mitigation terminology.** Submissions to OpenBSD
   should use KARL, not KASLR. Submissions to Apple should use kASLR or
   the PAC-specific term. Submissions to Linux should use KASLR. Each
   project treats its mitigation taxonomy as a marker of familiarity with
   the project; mixing them invites a correction. (Source: `ktr_psig`
   reply, supra.)

10. **Re-paste all quoted source from the current source, in the
    submission session.** Quoted text in any filed artefact must be
    pasted from the artefact as it exists at submission time, in the
    same session as the draft, with no inheritance from earlier prompts
    or notes. (Source: pledge `kill(0)` reply, supra; the misquote
    survived multiple rounds of Council review.)

11. **When one Council voice asks for one tiny extra test, run the
    test.** Even when the other three reviewers say it is unnecessary,
    the marginal cost of an additional half-hour of empirical work is
    smaller than the marginal cost of a maintainer reply that says
    "Did you?" (Source: pledge `kill(0)` reply, supra; ChatGPT-5 had
    asked for one additional sanity-check that would have pre-empted
    the question.)

---

## 6. Discussion

### 6.1 The Council Is Not a Reviewer Replacement

Four LLMs in adversarial roles cannot substitute for a human reviewer
who knows the codebase. Two of the four reviewers in this study
hallucinated identically; the remaining two flagged different conditions
that would have refuted other candidates. The Council's role is *signal
enrichment*, not signal authentication. The authentication step is the
empirical gate, and it is always performed by the human.

The structural argument for the Council is that it surfaces *more*
plausible objections than the single researcher can generate alone,
including objections the researcher would prefer not to think about. The
empirical gate then sorts plausible from substantiated. The combination
catches more pre-filing slips than either step in isolation; this is the
day's primary observation.

### 6.2 The Empirical Gate Is the Whole Point

A practitioner reading this paper should take away that the Council is
cheap and the empirical gate is non-negotiable. The two days that taught
this author most about pre-filing discipline were the days on which an
LLM and the underlying ground truth disagreed. The corrective is not to
choose a "better" LLM; it is to install the verification step regardless
of which LLMs are used.

This generalises beyond the specific case study. Any LLM-assisted
research workflow that does not include an explicit step for verifying
*the LLM's own factual claims against current sources* is, in the
author's experience, a workflow that ships hallucinations to its
downstream consumers in proportion to its output volume.

### 6.3 The Solo-Research Throughput Argument

The day's tally was three filings sent, fifteen candidates refuted, and
eleven methodology rules banked. The refute-to-file ratio of 5:1 is
high. The author's prior baseline was closer to 2:1. The difference is
attributable, in the author's belief, to the Council-plus-empirical-gate
combination; absent the Council, several of the refuted candidates
would have been filed and would have produced exchanges that resembled
the de Raadt thread of §4.4 — only without the pleasant property of
being correct in the first place.

A 5:1 refute-to-file ratio is not the limit. The ratio is bounded above
by the analyst's tolerance for being wrong. A higher ratio implies a
researcher who is willing to discard candidates that they would
otherwise have filed; this is healthy and uncomfortable in equal
measure.

### 6.4 The Throughput Cost of Being Wrong in Public

Maintainer mailing lists, security teams, and bug-bounty triage queues
all have a notion of researcher reputation that is not formally
articulated but is operationally enforced. A researcher whose
submissions trend toward "intended behaviour" closures and "did you
test this?" replies will, over time, find their next submissions read
more sceptically and triaged later. This is not a hypothetical: the
author has watched it happen to other people, and would prefer not to
test the effect on themselves. The Council and empirical gate are
explicitly throughput-protective for that reason. A submission that
survives the gate is a submission whose author can read the
maintainer's reply without flinching.

---

## 7. Limitations

The case study is one day's work, by one analyst, on three operating
systems and roughly nine distinct attack surfaces. The day was unusually
high-volume by the author's standards and may not reflect typical
throughput. The four LLMs are commodity products at specific versions on
13 May 2026; their behaviour, including their hallucination patterns, is
not stable across releases. The maintainer-reply data is two replies
from one developer, replying to one researcher, on one mailing list; it
is supportive of the throughput-cost argument but is not a statistical
sample.

The XPR-pattern slip class is the author's own framing and is not yet
established in the wider literature. It is offered here as a
diagnostic term rather than a discovery.

---

## 8. Future Work

The most directly useful next study would compare refute-to-file ratios
across a panel of solo researchers using the methodology to those not
using it, controlled for target operating system and class of finding.
The author intends to run a longer version of this experiment over the
coming months and to share aggregate data, if not specific findings, in
a follow-up.

A second worthwhile direction is to investigate whether the
hallucination pattern observed in DeepSeek-R1 and Grok-4 generalises:
specifically, whether attributing a paraphrase to a documentation source
is a recurring failure mode for LLMs being asked to reason about
operating-system documentation in their training cut-off plus / minus
six months. If so, the empirical-gate technique can be sharpened to
explicitly check attribution claims rather than general claims, and
researcher time can be allocated accordingly.

A third direction is to harden the rule of "submit quoted text only
after re-pasting from current source" into automation — for example, a
diff between the draft submission and the current documentation, with
any quoted strings flagged for verification. The author would be
interested in collaborators on a small tool for this purpose.

---

## 9. Acknowledgements

The author thanks the OpenBSD maintainer community, particularly Theo de
Raadt, for the prompt and educational replies that constitute much of
§4.4. The author thanks the developers of OpenSSH, OpenBSD, FreeBSD,
NetBSD, Pixar OpenUSD, and ipsw (Blacktop) for their open-source
contributions, several of which were instrumental to the day's analyses.
The author thanks the operators of DeepSeek, xAI, OpenAI, and Google
DeepMind for keeping their public chat interfaces available; the day's
methodology was funded by no external grant and used only freely
accessible LLMs.

No animals were harmed during the production of this paper. One Mac
mini, one Parallels Desktop macOS virtual machine, one UTM macOS
virtual machine, one Dell OptiPlex, one Sony VAIO and one OpenBSD ARM
virtual machine were used as instruments of research and emerged
unscathed. The fictitious contact named "ZXZX-FNORDIUM-MARKER-9942" was
deleted from the Parallels VM Contacts database at the conclusion of
experimentation.

---

## 10. Reproducibility

The Council prompts used during the case study are stored in the
author's research notes alongside the verdicts received and the
empirical-gate artefacts. They are available on request for purposes of
academic study, methodology review, or amusement. Submission emails to
`bugs@openbsd.org` are public by virtue of having been sent to a public
mailing list; the maintainer replies are reproduced here verbatim under
fair-use principles consistent with their public-list provenance.

The methodology described in §2 is offered for adaptation and use by
other researchers. The text of this paper is licensed under
Creative Commons Attribution 4.0 International (CC BY 4.0); attribution
to the author and a link to the licence text are the only conditions
of reuse.

---

## References

[1] Apple Inc. *macOS 26.4.1 (build 25E253)*, target operating system.

[2] OpenBSD Project. *OpenBSD 7.7-release (arm64) / -current*, target
operating system; `pledge(2)` manual page as installed; commits
1b900a0 (deraadt, 2026-04-16), 76d3556 (dgl, 2026-04-16),
8cfd528 (millert, 2026-05-04) cited in the day's analyses.

[3] Pixar Animation Studios. *OpenUSD*, github.com/PixarAnimationStudios/OpenUSD,
release v25.02, examined as basis for Apple Model I/O Phase 3 analysis.

[4] Blacktop. *ipsw*, github.com/blacktop/ipsw, v3.1.680, used for
dyld_shared_cache extraction on macOS 26.4.1.

[5] de Raadt, T. *bugs@openbsd.org*, three replies, 13 May 2026.
Reproduced verbatim under §4.4.

[6] iVerify; NowSecure; SecurityWeek. *NICKNAME zero-click iMessage
exploit*, multiple sources, 2025-06, providing public context for the
day's `imagent` cluster analyses.

---

*Stuart Thomas is a security researcher with prior commits accepted by
the OpenBSD project (UNVEIL-01 / kern_unveil.c dead-code escalation
guard, ok beck@; ELF-07 / exec_elf.c vaddr_t truncation, ok guenther@)
and submissions accepted into the Apple Security Bounty pipeline. The
opinions expressed are the author's own. Corrections to this paper —
particularly corrections of the form "the manpage does not say that" —
are welcomed at the author's contact of record.*

*This paper is dedicated to the proposition that the most useful
question a researcher can ask themselves at half past three in the
afternoon is "did I just hallucinate that?"*

---

<!-- End of document. Word count target: ~3500 words. -->
