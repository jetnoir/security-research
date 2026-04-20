# Spectral Complexity Screening for Binary Security Analysis: A Random Matrix Theory Approach

**Stuart Thomas**  
*Independent Security Research — Whitby, North Yorkshire, United Kingdom*

---

## Plain Language Summary

Finding security vulnerabilities in compiled software is slow, expensive, and demands rare expertise. A skilled analyst examining a macOS system binary must sift through hundreds of thousands of machine instructions, looking for the handful of code paths that could be exploited by an attacker. This paper describes TriageForge, a system that uses ideas from mathematics and physics to automate the first stages of that search.

The central insight is that most software, when viewed as a graph of function calls, has a predictable statistical structure — one that mirrors behaviour studied in quantum physics and network science. Malicious or buggy code tends to break that structure in measurable ways. TriageForge quantifies the *spectral* properties of a binary's call graph (how its eigenvalues are distributed), compares those properties against a mathematically calibrated baseline, and flags the binaries and functions most likely to reward human investigation.

A second observation, drawn from the theory of constraint satisfaction, is that hard computational problems cluster at a sharp *phase transition*. Functions whose logical structure puts them near that transition are disproportionately complex and disproportionately likely to harbour subtle errors. TriageForge uses this to rank functions before passing them to deeper, more expensive analysis tools.

Applied to 335 macOS system binaries, the pipeline reduced the candidate space by 96.4% and correctly classified all anomalous candidates through further automated and manual analysis.

---

## Abstract

Automated vulnerability triage of compiled binaries presents a combinatorial challenge that scales poorly with binary size and architectural complexity. We present TriageForge, a four-stage analysis pipeline applying techniques from random matrix theory (RMT), Boolean satisfiability phase-transition analysis, cyclomatic complexity gating, and symbolic execution to identify anomalous code structure in macOS ARM64 binaries. The spectral screen (C2) models a binary's call graph as a weighted adjacency matrix and computes z-scores for three spectral statistics — largest eigenvalue (λ\_max), graph energy, and eigenvalue entropy — against a configuration-model null distribution calibrated to the observed degree sequence. Functions passing the spectral screen are prioritised by a SAT backbone proximity score (C1) derived from chi-squared analysis of clause ratio relative to the empirical 3-SAT phase transition at α\_c ≈ 4.267. A cyclomatic complexity gate (C3) applies five structural dataflow templates, and high-priority candidates receive full symbolic taint analysis (C6) via the angr binary analysis framework. Applied to 335 macOS 26 PrivateFrameworks binaries, the pipeline yielded a 3.6% anomaly detection rate with zero exploitable buffer overflows confirmed. False positives arise characteristically from cryptographic lookup tables and standard library sorting algorithms. We present the theoretical grounding for each stage, practical engineering decisions for ARM64e Mach-O binaries, and discuss the inherent limitations of spectral methods in security triage contexts.

**Keywords:** binary analysis, random matrix theory, SAT phase transitions, symbolic execution, vulnerability triage, call graph spectral analysis

---

## 1. Introduction

Security researchers face an adversarial triage problem: given a large corpus of compiled binaries — system daemons, frameworks, kernel extensions — identify the small fraction containing exploitable vulnerabilities, and within those binaries, identify the precise functions that warrant the costly process of symbolic execution, fuzzing, or manual reverse engineering.

The state of practice relies heavily on human expertise. A skilled analyst will examine cross-references, memory operation patterns, and entitlement checks, forming intuitions developed over years of experience. This approach does not scale: macOS 26 ships with over 3,000 Mach-O binaries in its framework and private framework directories alone, and the mean binary contains several hundred functions. Exhaustive manual analysis is infeasible.

Automated approaches exist — static analysis tools, fuzzers, symbolic execution engines — but each has characteristic failure modes at scale. Static analysers generate large volumes of false positives. Symbolic execution suffers from path explosion. Fuzzers require well-formed corpus inputs and extended run times. None provides a principled first-pass filter capable of reducing thousands of binaries to tens.

This paper describes TriageForge, a pipeline built around the observation that *call graph spectral properties discriminate between typical and atypical code structure in a statistically principled way*. The approach draws on three bodies of mathematical theory:

1. **Random matrix theory** [1,2] predicts the eigenvalue distributions of matrices drawn from structured random ensembles. Call graphs of well-structured software binaries generate adjacency matrices whose eigenvalue distributions conform closely to these predictions; anomalous code structure produces measurable deviations.

2. **SAT phase transition theory** [6,10] establishes that random 3-SAT instances undergo a sharp satisfiability phase transition at clause-to-variable ratio α\_c ≈ 4.267. Near this transition, backbone fractions — variables forced to specific values in all satisfying assignments — are high, correlating with computational hardness. Functions whose constraint graphs place them near this transition are disproportionately complex.

3. **Symbolic execution** [13], as implemented in the angr framework [8], provides a sound basis for taint tracking and PoC synthesis on functions that survive earlier pipeline stages.

The contributions of this paper are:
- A formal characterisation of call graph spectral statistics as a triage signal.
- A chi-squared backbone proximity score for function-level prioritisation.
- An empirical evaluation on 335 macOS PrivateFrameworks binaries.
- A taxonomy of false positive sources in spectral binary screening.

---

## 2. Background

### 2.1 Binary Vulnerability Analysis

Binary vulnerability analysis — the process of identifying exploitable defects in compiled code without source access — divides broadly into static and dynamic approaches. Static approaches include pattern matching (signature-based tools such as YARA), data-flow analysis (taint propagation at the IR level), and type-theoretic methods. Dynamic approaches include fuzzing [14], concolic execution [15], and trace-based analysis.

Spectral approaches to code analysis are less common. Previous work has applied graph-theoretic measures — betweenness centrality, clustering coefficients — to call graphs as complexity proxies [16], but statistically grounded spectral screening against calibrated null models is, to our knowledge, a novel application in the security domain.

### 2.2 Random Matrix Theory

Random matrix theory, initiated by Wigner in the study of nuclear energy levels [1,2], characterises the statistical properties of eigenvalue spectra of large random matrices. The central result relevant here is the **Wigner semicircle law**: for an n×n symmetric matrix with independent and identically distributed entries of mean zero and finite variance σ², the empirical spectral distribution converges, as n→∞, to the semicircular density

```
ρ(x) = (2 / πR²) √(R² − x²),  |x| ≤ R,  R = 2σ√n
```

The **Tracy–Widom distribution** [3] characterises the limiting distribution of the largest eigenvalue. Specifically, the normalised quantity n^(2/3) (λ\_max/(σ√n) − 2) converges in distribution to the Tracy–Widom law of order 1 for the Gaussian Orthogonal Ensemble (GOE).

**Graph energy** — defined by Gutman [9] as the sum of absolute eigenvalues of the adjacency matrix, E(G) = Σᵢ |λᵢ| — provides a second spectral summary statistic capturing total spectral mass. For a random graph, E(G) scales as O(n) with concentration properties determined by the degree distribution.

**Eigenvalue entropy**, H = −Σᵢ pᵢ log pᵢ where pᵢ = |λᵢ| / Σⱼ |λⱼ|, measures the dispersion of spectral mass across eigenvalue modes and is sensitive to structural regularities absent from random models.

### 2.3 The Configuration Model

For call graphs with prescribed (non-uniform) degree sequences, the appropriate null distribution is the **configuration model** [4]: the maximum-entropy random graph ensemble consistent with the observed degree sequence. The expected spectral statistics of the configuration model can be approximated analytically [17] or estimated by Monte Carlo sampling of degree-sequence-preserving rewiring of the observed graph. TriageForge uses the analytical approximation for λ\_max and graph energy, calibrated against empirical benchmarks.

### 2.4 SAT Phase Transitions

The Boolean satisfiability problem (SAT) exhibits a sharp phase transition in the random ensemble [6]. For random 3-SAT instances with n variables and m clauses, the probability of satisfiability undergoes a transition from near-1 to near-0 as the clause-to-variable ratio α = m/n crosses a critical threshold α\_c. Extensive numerical studies [6,10] place this threshold at α\_c ≈ 4.267. The cavity method of statistical mechanics provides a theoretical framework for this prediction [7].

Near the phase transition, **backbone variables** — those taking the same value in all satisfying assignments — constitute a positive fraction of all variables [10]. Functions whose logical structure maps to constraint graphs near α\_c exhibit high backbone fractions, correlating with the presence of intricate, tightly-coupled computation that resists straightforward verification.

### 2.5 Cyclomatic Complexity

McCabe [5] defined cyclomatic complexity V(G) for a program control flow graph G = (N, E) as

```
V(G) = E − N + 2P
```

where N is the number of nodes, E the number of edges, and P the number of connected components (for a single function, P = 1). McCabe proposed V(G) > 10 as a threshold for functions of high complexity warranting modular decomposition. The measure is widely used as a proxy for testability and defect likelihood [18].

---

## 3. The TriageForge Pipeline

### 3.1 Architecture

TriageForge processes binaries through four sequential stages with aggressive early termination:

```
Binary Input
     │
     ▼
[C1] SAT Backbone Score
     │  (ranks functions by structural complexity)
     ▼
[C2] RMT Spectral Screen
     │  (z-scores vs. configuration model null)
     │  z < 2.0: NORMAL → discard
     │  z ≥ 2.0: ANOMALOUS → continue
     ▼
[C3] Template Dataflow Analysis
     │  (5 vulnerability class templates)
     │  (cyclomatic complexity gate)
     │  No hits: discard
     │  Hits: continue
     ▼
[C6] Symbolic Taint Analysis
     │  (angr symbolic execution)
     │  (PoC synthesis)
     ▼
Findings Report
```

Each stage is independently useful: C2 alone provides a binary-level triage signal in under 30 seconds; the full pipeline from C1 through C6 typically completes within 15 minutes for binaries below 10 MB.

### 3.2 Stage C1: SAT Backbone Prioritisation

The C1 stage ranks functions within a binary by a backbone proximity score. The function's control flow graph is encoded as a set of 3-SAT-like constraints over path reachability variables. The clause-to-variable ratio α of this encoding is computed and compared against the critical threshold α\_c ≈ 4.267.

A chi-squared statistic χ²(f) = (α(f) − α\_c)² / α\_c measures deviation from the phase transition. Functions with small χ² — those whose constraint graphs lie near the transition — are assigned high priority scores. The rationale is that proximity to the phase transition correlates with the presence of a large backbone fraction, which in turn correlates with tightly constrained computational paths that are difficult to verify and disproportionately likely to harbour subtle errors.

Priority scores are normalised across the binary and used to order functions for subsequent pipeline stages.

### 3.3 Stage C2: RMT Spectral Screen

The C2 stage operates at the binary level. The call graph is extracted using the lief library [11] for Mach-O parsing and the capstone disassembly engine [12] for control-flow reconstruction. For ARM64e binaries, authenticated pointer chains are resolved through the DYLD chained fixup map to correctly identify call targets through GOT/stub indirection.

The call graph is represented as an unweighted directed adjacency matrix A. Three spectral statistics are computed:

- **λ\_max**: the largest eigenvalue of (A + Aᵀ)/2 (the symmetrised adjacency matrix)
- **Graph energy**: E(G) = Σᵢ |λᵢ| / n (normalised)
- **Eigenvalue entropy**: H = −Σᵢ pᵢ log pᵢ, pᵢ = |λᵢ| / Σⱼ |λⱼ|

Each statistic is z-scored against the configuration model null:

```
z_stat = (stat_observed − μ_null) / σ_null
```

where μ\_null and σ\_null are the expected value and standard deviation of the statistic under the configuration model with the same degree sequence. A binary is flagged as ANOMALOUS if |z| > 2.0 for any statistic, or |z| > 2.5 for λ\_max (which carries the greatest false positive cost).

**ARM64e engineering note.** The lief library reports fat-binary slice offsets relative to the slice start rather than the absolute fat-file offset. Correct parsing requires selecting the target architecture slice (`fat[0]` for the first slice) rather than operating on the fat binary object directly.

**Swift and Objective-C binaries** produce degenerate z=0 results because BLR (branch-to-register) indirect calls are unresolvable without dynamic execution, yielding a near-complete call graph with near-zero out-degree variance. This is an expected limitation, not a fault.

### 3.4 Stage C3: Template Dataflow Analysis

The C3 stage applies five structural dataflow templates to functions ranked by C1 scores:

| Template | Vulnerability Class |
|----------|-------------------|
| MACH\_OOB | Out-of-bounds access via Mach port message |
| XPC\_TYPE | XPC type confusion in deserialization |
| INT\_OVF | Integer overflow in size computation |
| PORT\_UAF | Use-after-free via Mach port rights |
| IOKIT\_OOB | Out-of-bounds via IOKit user client |

Each template specifies a source (attacker-controlled input), a sink (memory operation), and a set of barrier conditions (bounds checks, type validations) that would neutralise the path. A function is flagged if a source-to-sink path exists without all barriers.

A cyclomatic complexity gate V(G) > 10 is applied: templates are not evaluated on functions with V(G) ≤ 10, as low-complexity functions with attacker-controlled data paths are empirically unlikely to contain exploitable logic errors in the macOS system binary corpus.

### 3.5 Stage C6: Symbolic Taint Analysis

The C6 stage applies symbolic execution via the angr framework [8]. Taint marks are placed at identified source operations (XPC message receipt, Mach port data extraction) and propagated symbolically through the function. The stage terminates when a taint-bearing symbolic value reaches a sink operation (memcpy, memmove, stack allocation) without an intervening concretising bounds check, or when symbolic state space exceeds configurable limits.

On termination with a finding, angr's constraint solver (Z3) is invoked to synthesise a concrete input satisfying all path conditions — producing a candidate proof-of-concept payload.

On Apple ARM64e binaries, Pointer Authentication Codes (PAC) block function pointer hijacking even where write primitives exist. The C6 stage notes PAC presence and adjusts impact classification accordingly.

---

## 4. Theoretical Analysis

### 4.1 Why Spectral Statistics Discriminate

The core hypothesis of the C2 stage is that the call graphs of well-structured software binaries are drawn from a distribution whose spectral properties are well-approximated by the configuration model null, and that anomalous code structure (unusual dispatch tables, non-standard calling conventions, cryptographic primitives) produces statistically significant deviations.

This hypothesis has theoretical support from two directions.

**Universality.** RMT universality results [2,3] establish that the spectral statistics of many random matrix ensembles are governed by the same limiting distributions, independent of the specific entry distribution. This suggests that the configuration model null, while not exactly matching any particular binary's call graph distribution, provides a robust reference point.

**Expander graphs.** Cryptographic and sorting routines often implement near-regular or structured graphs (S-boxes have uniform out-degree; merge-sort implementations are nearly binary trees). Near-regular graphs have λ\_max close to the mean degree and low spectral entropy; for a call graph with heterogeneous degree distribution, this structure produces large *negative* z-scores on energy and entropy (spectral mass is more concentrated than the null predicts). This is exactly the pattern observed for OpenLDAP S-box lookup tables and standard library sorting implementations in our empirical evaluation.

Conversely, anomalous dispatch tables — large switch statements over message types, or complex XPC message routers — generate hub nodes with high in-degree, shifting λ\_max upward. These produce large *positive* z-scores on λ\_max. Both patterns are correctly flagged by the pipeline, though for different physical reasons.

### 4.2 Backbone Proximity as a Complexity Proxy

The mapping from function control flow graphs to SAT-like constraint systems follows naturally from symbolic execution [13]: the control flow graph induces reachability constraints between basic blocks, and encoding these constraints in conjunctive normal form yields a clause-to-variable ratio α characterising the function's logical density.

The empirical correlation between α proximity to α\_c and function complexity is well-motivated but not theoretically tight: the 3-SAT phase transition is a property of *random* instances at fixed n, and the constraint graphs of software functions are far from random. The C1 score should be understood as a heuristic prioritisation signal rather than a rigorous phase-transition argument. It performs well in practice because the functions that score highly tend to be those implementing complex protocol parsing or message dispatch — precisely the functions of security interest.

### 4.3 Symbolic Execution Completeness

Symbolic execution is theoretically sound for bounded programs: if a vulnerable path exists, angr will find it, given sufficient resources. In practice, path explosion limits completeness severely. TriageForge mitigates this by applying symbolic execution only to functions pre-screened by C1–C3, limiting the symbolic search to functions with both high complexity (C1) and structural vulnerability patterns (C3).

The use of angr's exploration techniques (loop bounding, state merging) further constrains path explosion at the cost of completeness. The C6 stage should be understood as a *generator* of candidate PoCs rather than a sound vulnerability prover.

---

## 5. Empirical Validation

### 5.1 Dataset

The evaluation corpus comprises 335 Mach-O binaries from the `/System/Library/PrivateFrameworks/` directory of macOS 26.4.1 (build 25E253) on Apple Silicon (ARM64e). This corpus was selected because it represents Apple's highest-density attack surface for inter-process communication: most PrivateFrameworks binaries expose XPC services and receive data from less-privileged processes.

Binary sizes ranged from 47 KB to 84 MB. All binaries are universal Mach-O (fat binaries); the ARM64e slice was selected for all analyses.

### 5.2 C2 Screening Results

The C2 stage flagged 12 of 335 binaries (3.6%) as ANOMALOUS, meeting the |z| > 2.0 threshold on at least one statistic. The remaining 323 binaries (96.4%) were classified NORMAL and required no further analysis.

For the 12 anomalous binaries, deeper analysis was completed through manual reverse engineering and C3 template evaluation. Key findings:

| Binary | Primary z-score anomaly | Verdict |
|--------|------------------------|---------|
| AMPDeviceDiscoveryAgent | λ\_max (FourCC dispatch) | CLOSED — protocol sizes hardcoded safe |
| AppleCredentialManagerDaemon | Energy, entropy | CLOSED — entitlement gate; memcpy bounds checked |
| DesktopServicesHelper | Entropy (−7.22) | CLOSED — SecTask entitlement gate |
| FindMyMacd | Energy, entropy | CLOSED — all 37 memcpy callers guarded |
| mediasharingd | Entropy (−8.44) | CLOSED — DMAP/DAAP TLV source = constant global |
| ecosystemd | λ\_max (+2.56) | CLOSED — Swift runtime sorting/tagging |
| catutil | λ\_max | CLOSED — no network attack surface |
| VoiceBankingDiagnostics | Entropy | CLOSED — no network attack surface |
| slapadd/slapacl/slapauth/slapcat | λ\_max, energy | ARTIFACT — OpenLDAP S-box tables |

### 5.3 False Positive Taxonomy

Three categories of false positive were observed:

**Category 1: Cryptographic lookup tables** (slapadd, slapacl, slapauth, slapcat). OpenLDAP S-box lookup tables for LDAP protocol encoding produce near-regular call graphs with extreme negative z-scores on energy and entropy. The pattern is diagnostic: all four slapd binaries are third-party code bundled with macOS and their S-box structure produces near-identical anomaly signatures. Detection heuristic: all four flags are from the same binary family (slap\*) with z\_entropy in range (−0.61, −1.55). Future pipeline versions should include a binary provenance check.

**Category 2: Standard library sorting** (ecosystemd, VoiceBankingDiagnostics). The Swift runtime's tagged-pointer merge sort produces a near-regular subgraph within the call graph, shifting entropy downward. This is indistinguishable from cryptographic regularity at the spectral level. Detection heuristic: Swift runtime binaries can be identified by the presence of `swift_retain`/`swift_release` import symbols and de-prioritised.

**Category 3: No network attack surface** (catutil, VoiceBankingDiagnostics). Anomalous spectral properties in these binaries reflect unusual code structure — complex animation template parsing (catutil) and diagnostic collection (VoiceBankingDiagnostics) — but neither binary receives data from unprivileged network sources. The pipeline correctly flags structural anomaly but lacks an automatic assessment of attack surface reachability. This requires manual verification.

### 5.4 Throughput and Performance

On a Linux workstation with 64 GB RAM and an AMD Ryzen 9 processor, the C2 stage processes a 3 MB ARM64e binary in approximately 28 seconds using the FastC2 path (lief+capstone, no symbolic execution). Full C1–C6 analysis of a flagged binary averages 8–12 minutes. The 335-binary sweep completed in approximately 156 hours of wall-clock time (distributed over a multi-day campaign with parallel workers).

The dominant cost is C2 call graph extraction for large binaries (> 10 MB), particularly those with large PLT stubs tables. The FastC2 optimisation (bypassing angr CFGFast in favour of direct capstone disassembly) reduced per-binary analysis time by approximately 60% for binaries above 3.5 MB.

---

## 6. Discussion

### 6.1 Limitations of Spectral Methods

The configuration model null is calibrated to the degree sequence of the observed call graph. It correctly captures first-order structural properties (degree distribution) but does not account for higher-order structure (clustering, modularity, hierarchical organisation). Software call graphs exhibit significant clustering — utility functions tend to be called from within the same module — which can produce systematic biases in spectral statistics.

A more accurate null would condition on both degree sequence and local clustering coefficient [20]. This extension is computationally feasible but adds complexity to the calibration procedure; it is a direction for future work.

The z=0 degenerate case for Objective-C and Swift binaries (BLR indirect calls) is a fundamental limitation of static call graph analysis. Dynamic profiling or binary instrumentation would resolve this at the cost of requiring an execution environment.

### 6.2 The Phase Transition Mapping

The mapping of function control flow graphs to SAT-like constraint systems is an approximation. Real software functions are not random constraint instances: they have structured dependencies, bounded complexity, and are written by humans with specific semantic intent. The α\_c threshold is derived from random 3-SAT theory [6,7] and its relevance to non-random instances is heuristic rather than proven.

Empirically, the C1 ranking correlates with manually-assessed function complexity (high-ranking functions are consistently the most complex, with the most XPC message handlers and most memory operations), but this has not been formally validated with a ground truth corpus of known-vulnerable functions.

### 6.3 Security Research Context

The pipeline was developed and validated as a prioritisation tool for security research, not as a production vulnerability scanner. The distinction matters: a security researcher can tolerate false positives (functions that look interesting but are not vulnerable), provided false negatives (vulnerable functions that are missed) are kept low. The C2 threshold of |z| > 2.0 is deliberately conservative — accepting more false positives — to reduce false negatives.

The empirical false negative rate is unknown without a corpus of ground truth vulnerabilities in macOS PrivateFrameworks binaries. All closed findings were verified by full manual analysis; the pipeline was not deployed on any binary subsequently found to contain an exploitable vulnerability. This leaves open the question of whether the pipeline would have flagged such binaries.

### 6.4 Future Directions

Several extensions are under consideration:

- **Binary provenance heuristics**: Identifying third-party code (OpenLDAP, libxml2, OpenSSH) to suppress known-artifact false positive signatures.
- **Dynamic call graph enrichment**: Using DTrace or LLDB to add dynamic edges to the static call graph, resolving BLR indirect calls.
- **Conditioned null distributions**: Calibrating against clustering coefficient as well as degree sequence.
- **Framework sweep**: Applying the pipeline to `/System/Library/Frameworks/` for comparison with the PrivateFrameworks corpus.

---

## 7. Conclusion

We have presented TriageForge, a binary vulnerability triage pipeline grounded in random matrix theory, SAT phase transition analysis, cyclomatic complexity theory, and symbolic execution. The key contribution is the C2 spectral screen, which provides a statistically principled binary-level triage signal in approximately 28 seconds per binary, reducing a 335-binary corpus to 12 candidates (3.6%) for deeper analysis.

All 12 candidates were fully analysed through manual reverse engineering and automated C3 template evaluation; zero exploitable buffer overflows were found. The false positive taxonomy — cryptographic lookup tables, standard library sorting, and no-network-surface binaries — provides actionable guidance for pipeline improvement.

The theoretical grounding in RMT universality results and SAT backbone theory gives the pipeline a principled foundation, while the empirical validation on a realistic corpus demonstrates practical utility. We believe spectral complexity screening represents a promising direction for large-scale binary security analysis and will continue to develop the approach as part of ongoing macOS security research.

---

## Acknowledgements

The author is neurodivergent (autism, ADHD). Claude (Anthropic) was used as **assistive technology** during the preparation of this paper: for drafting and proofreading, structural editing, formatting of equations, tables and citations, and discussion of mathematical clarity. The underlying research — problem formulation, pipeline design, software implementation, empirical evaluation on the 335-binary corpus, theoretical analysis, and interpretation of results — is the author's own work.

The use of AI assistive technology is consistent with the principles of the *Equality Act 2010*: disability is defined as a protected characteristic under Section 6; reasonable adjustments are contemplated by Sections 20–21; and discrimination arising from disability is addressed by Section 15. This acknowledgement is provided in the spirit of transparent and accessible research practice.

---

## References

[1] E. P. Wigner, "On the distribution of the roots of certain symmetric matrices," *Annals of Mathematics*, vol. 67, no. 2, pp. 325–327, 1958.

[2] E. P. Wigner, "Characteristic vectors of bordered matrices with infinite dimensions," *Annals of Mathematics*, vol. 62, no. 3, pp. 548–564, 1955.

[3] C. A. Tracy and H. Widom, "Level-spacing distributions and the Airy kernel," *Communications in Mathematical Physics*, vol. 159, pp. 151–174, 1994.

[4] M. Molloy and B. Reed, "A critical point for random graphs with a given degree sequence," *Random Structures and Algorithms*, vol. 6, no. 2–3, pp. 161–179, 1995.

[5] T. J. McCabe, "A complexity measure," *IEEE Transactions on Software Engineering*, vol. SE-2, no. 4, pp. 308–320, 1976.

[6] S. Kirkpatrick and B. Selman, "Critical behavior in the satisfiability of random Boolean expressions," *Science*, vol. 264, no. 5163, pp. 1297–1301, 1994.

[7] M. Mézard, G. Parisi, and R. Zecchina, "Analytic and algorithmic solution of random satisfiability problems," *Science*, vol. 297, no. 5582, pp. 812–815, 2002.

[8] Y. Shoshitaishvili *et al.*, "SOK: (State of) The art of war: Offensive techniques in binary analysis," in *Proc. 37th IEEE Symposium on Security and Privacy (S&P)*, San Jose, CA, 2016, pp. 138–157.

[9] I. Gutman, "The energy of a graph," *Berichte der Mathematisch-Statistischen Sektion im Forschungszentrum Graz*, vol. 103, pp. 1–22, 1978.

[10] R. Monasson, R. Zecchina, S. Kirkpatrick, B. Selman, and L. Troyansky, "Determining computational complexity from characteristic 'phase transitions'," *Nature*, vol. 400, no. 6740, pp. 133–137, 1999.

[11] T. Romain, "LIEF — Library to Instrument Executable Formats," Open Source Software, 2017. [Online]. Available: https://lief-project.github.io/

[12] "Capstone: A lightweight multi-platform, multi-architecture disassembly framework." [Online]. Available: http://www.capstone-engine.org/

[13] J. C. King, "Symbolic execution and program testing," *Communications of the ACM*, vol. 19, no. 7, pp. 385–394, 1976.

[14] M. Böhme, V.-T. Pham, and A. Roychoudhury, "Coverage-based greybox fuzzing as Markov chain," *IEEE Transactions on Software Engineering*, vol. 45, no. 5, pp. 489–506, 2019.

[15] C. Cadar, D. Dunbar, and D. Engler, "KLEE: Unassisted and automatic generation of high-coverage tests for complex systems programs," in *Proc. 8th USENIX Symposium on Operating Systems Design and Implementation (OSDI)*, San Diego, CA, 2008, pp. 209–224.

[16] F. Zimmermann *et al.*, "Automatic bug finding for the kernel," in *Proc. ACSAC*, 2020.

[17] F. Chung and L. Lu, "The spectra of random graphs with given expected degrees," *Internet Mathematics*, vol. 1, no. 3, pp. 257–275, 2003.

[18] N. E. Fenton and M. Neil, "A critique of software defect prediction models," *IEEE Transactions on Software Engineering*, vol. 25, no. 5, pp. 675–689, 1999.

[19] M. Davis, G. Logemann, and D. Loveland, "A machine program for theorem-proving," *Communications of the ACM*, vol. 5, no. 7, pp. 394–397, 1962.

[20] M. E. J. Newman, "The structure and function of complex networks," *SIAM Review*, vol. 45, no. 2, pp. 167–256, 2003.
