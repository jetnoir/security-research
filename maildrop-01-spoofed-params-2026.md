<!--
Title:    Apple Maildrop URLs Expose Unsigned, Client-Controlled Filename, Size, and Icon Parameters — Phishing-Grade Identity Spoofing on icloud.com
Author:   Stuart Thomas
Date:     2026-05-13
License:  Creative Commons Attribution 4.0 International (CC BY 4.0)
          https://creativecommons.org/licenses/by/4.0/
Version:  1.0 (public disclosure)
Vendor:   Apple Inc.
Vendor reference: OE1950888220  (Apple Security Bounty submission)
Vendor status at time of publication: "Prioritised for review"
Time since initial report: approximately two years, ten months
-->

# Apple Maildrop URLs Expose Unsigned, Client-Controlled Filename, Size, and Icon Parameters

### Phishing-Grade Identity Spoofing on icloud.com

**Stuart Thomas** · 13 May 2026 · *Licensed under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/)*

**Affected product:** Apple iCloud Mail / Maildrop attachment service
**Surface:** `*.icloud.com` Maildrop landing pages and `cvws.icloud-content.com` CDN download path
**Vendor reference:** Apple Security Bounty case **OE1950888220**, originally filed 7 July 2023; updated submission with refreshed PoC and CDN-injection analysis filed 4 April 2026; video PoC submitted 6 April 2026.
**Vendor status at publication:** *"Prioritised for review"* (since 8 April 2026). No remediation deployed at time of publication.
**Time elapsed since first report:** approximately **two years, ten months**.

---

## Summary

Apple's Maildrop attachment service — the iCloud feature that hosts mail
attachments up to 5 GiB and presents recipients with a download page on
`icloud.com` — generates per-attachment URLs that contain **three
client-controlled, unsigned parameters**:

| Parameter | Purpose | Server-side validation? |
|---|---|:---:|
| `f=`  | Filename displayed on the landing page and *interpolated as `${f}` into the CDN download path* | **No** |
| `sz=` | File size displayed on the landing page | **No** |
| `uk=` | User key (opaque token, used in the CDN path) | (Used as identity; no validation that other params match the file it points to) |

Any party in possession of a valid Maildrop URL — including the original
sender, anyone the URL has been forwarded to, anyone who screenshots a
shared link, or anyone with access to a mail trail — can rewrite the
`f=` and `sz=` parameters and obtain a fully functional Maildrop URL
that:

1. Displays the **fake filename** on the Maildrop landing page;
2. Displays the **file-type icon** Maildrop infers from that filename;
3. Displays the **fake file size** alongside the fake filename;
4. Causes the CDN to serve the underlying file with
   `Content-Disposition: attachment; filename="<the fake name>"`,
   so the recipient's browser saves it under the fake name regardless
   of the file's actual MIME type or extension.

The URL remains on the `icloud.com` domain throughout. There is no
visual indicator on the Maildrop landing page that the displayed
metadata is sender-controlled rather than server-attested. The link is
valid for 30 days per Apple's published Maildrop documentation.

This is, in practical terms, **a phishing primitive hosted on an Apple
domain**, and it has been reported to Apple Security Bounty since
**7 July 2023**. As of 13 May 2026, the case is marked *"Prioritised
for review"* with no remediation deployed.

---

## Disclosure timeline

| Date | Event |
|---|---|
| 2023-07-07 | Initial report filed with Apple Security Bounty (OE1950888220). Title: *"Maildrop URL arbitrary manipulation of parameters (icons, filesize)"*. |
| 2023-07-07 | Apple Product Security acknowledged the report and asked for a video PoC and clarification of attack vectors. |
| 2023 – 2026 | No state change visible in the bounty portal. The bug remained unpatched and continuously exploitable on production iCloud. |
| 2026-04-04 | Author re-submitted a refreshed write-up with the additional finding that `f=` is interpolated as a template variable `${f}` in the *CDN URL itself*, making it more than display-only deception. PoC script attached. |
| 2026-04-06 | Video PoC submitted at Apple's earlier request. |
| 2026-04-08 | Apple set status to *"Prioritised for review"*. |
| 2026-04 – 2026-05 | No further communication. No remediation deployed. |
| 2026-05-13 | Public disclosure (this document). |

The author is publishing **34 months** after the initial report.
Industry-standard coordinated-disclosure windows (Google Project Zero,
ZDI, CERT/CC) range from 90 to 120 days. Apple has had approximately
ten such windows. The bug is reproducible against production iCloud at
the time of writing; nothing prevents an adversary from rediscovering
it independently, and the author considers it likely that some
already have. Continued non-publication imposes a cost on end-users
who have no way to know that Maildrop URLs they receive can be
spoofed in this way.

---

## Technical detail

### The URL structure

A canonical Maildrop URL has the shape:

```
https://www.icloud.com/attachment/?u=<percent-encoded inner CDN URL>
                                  &uk=<user key>
                                  &f=<filename>
                                  &sz=<file size in bytes>
```

The inner `u=` value, once decoded, is the CDN URL the browser actually
fetches when the user clicks "Download". Its shape is approximately:

```
https://cvws.icloud-content.com/B/<content hash>/${f}?o=...&k=${uk}&...
```

The two `${...}` tokens are **template substitutions**. The `${f}` token
is replaced with whatever value is in the outer `f=` parameter at
request time. The `${uk}` token is replaced with `uk=`.

This means `f=` is not a cosmetic landing-page label. It is also part
of the path the CDN serves, and the CDN echoes it back via the
`Content-Disposition` response header.

### Empirical demonstration

A short Python script captures the entire primitive. Given any valid
Maildrop URL, the script parses the four parameters, prints the
detected template variables, and produces a spoofed URL with operator-
chosen filename and size:

```python
# maildrop_spoof.py — public PoC
import sys
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, unquote

def analyse(url):
    p = urlparse(url)
    q = parse_qs(p.query, keep_blank_values=True)
    inner = unquote(q.get('u', [''])[0])
    print('[Analysis]')
    print(f'  f=  : {q.get("f", ["(missing)"])[0]}')
    print(f'  sz= : {q.get("sz",["(missing)"])[0]}')
    print(f'  uk= : {q.get("uk",["(missing)"])[0]}')
    print(f'  CDN URL embeds ${{f}}  : {"${f}" in inner}')
    print(f'  CDN URL embeds ${{uk}} : {"${uk}" in inner}')

def spoof(url, name, size):
    p = urlparse(url)
    q = parse_qs(p.query, keep_blank_values=True)
    q['f']  = [name]
    q['sz'] = [str(size)]
    return urlunparse(p._replace(
        query=urlencode({k: v[0] for k, v in q.items()})))

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print('usage: maildrop_spoof.py <maildrop-url> [fake-name] [fake-size]')
        sys.exit(1)
    url  = sys.argv[1]
    name = sys.argv[2] if len(sys.argv) > 2 else 'Invoice_Q1_2026.pdf'
    size = int(sys.argv[3]) if len(sys.argv) > 3 else 204800
    analyse(url)
    print()
    print('[Spoofed URL]')
    print(spoof(url, name, size))
```

Run against a real Maildrop URL — for example one generated by sending
yourself a small archive via Apple Mail's Maildrop feature — and the
script will report which template tokens the CDN URL embeds and produce
a rewritten link. Opening the original and spoofed links side-by-side
in a browser will show:

- Original landing page: real filename, real size, real icon.
- Spoofed landing page: *spoofed* filename, *spoofed* size, *spoofed*
  icon. Inferred entirely from the operator-chosen `f=` value.
- Both URLs reside on `icloud.com`; both produce a working download.
- The downloaded file's `Content-Disposition` header contains the
  spoofed filename, so the browser's save-as prompt displays the
  spoofed name.

### What is signed and what is not

The author's investigation across multiple Maildrop URLs (generated by
the author and by collaborating senders) found:

| Component | Signed? | Notes |
|---|:---:|---|
| Content hash in CDN path | Yes | Identifies the actual stored file |
| `uk` user key | (Server-side identity token) | Used by CDN to authorise access |
| `f` filename | **No** | Trivially modifiable; affects landing page and `Content-Disposition` |
| `sz` file size | **No** | Trivially modifiable; display only |
| Outer URL query string as a whole | **No HMAC** | No detectable signature parameter on the outer URL |

The structural deficiency is the absence of an HMAC over the outer
query string. A short keyed signature parameter would prevent the
attack class entirely.

---

## Attack model

The attack does not require privileged access to Apple's
infrastructure. Three realistic operator positions:

### Operator-as-sender

The attacker uploads a payload (malware archive, malicious document,
fake invoice, anything they want the victim to download) via Apple Mail
and obtains a Maildrop URL. They then rewrite `f=` to a more trustworthy
filename — `Invoice_Q1_2026.pdf`, `MarketingSlideDeck.pptx`,
`CV_J_Smith.docx` — and `sz=` to whatever size matches the social
pretext.

The victim receives a link on `icloud.com`, sees an Apple-rendered
landing page presenting a PDF named "Invoice_Q1_2026.pdf" weighing
204 KB, and clicks "Download". The browser save-as prompt shows
"Invoice_Q1_2026.pdf". The actual file content is whatever the
attacker uploaded.

This is the dominant case. It is trivial.

### Operator-as-forwarder

A legitimate Maildrop URL is forwarded to a wider audience — common in
corporate environments where shared files traverse multiple mailing
lists. An attacker on that audience-list path can modify the `f=` and
`sz=` before re-sharing, producing a spoofed link that points to
content they did not upload.

### Operator-as-link-collector

Maildrop URLs leak by ordinary means — chat logs, screenshots, copy/
paste into ticketing systems, accidental cc'ing to wider lists. Any
exposed URL is rewritable for the remainder of its 30-day window.

All three positions require nothing beyond a text editor and a browser.

---

## Impact

| Dimension | Assessment |
|---|---|
| Attack complexity | Low — URL parameter manipulation |
| Authentication required | None beyond possessing a Maildrop URL |
| User interaction | Required (the victim must visit the link and download) |
| Confidentiality | None — the underlying file is unchanged |
| Integrity (file) | Unchanged — the served content matches what was uploaded |
| Integrity (presentation) | **High** — filename, icon, size all attacker-controlled, on an Apple-branded domain |
| Phishing utility | **High** — Apple branding + `icloud.com` domain + matching displayed metadata defeats most user training |
| Defensive bypass | `Content-Disposition`-based filename overrides OS extension-warning heuristics that key on the saved filename |
| Persistence | 30 days per Maildrop URL lifetime |

There is no published CVSS scoring framework that captures
phishing-aid bugs cleanly. A CVSS 3.1 vector of
`CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:L/A:N` gives a base score of
**5.4** (Medium); this score understates the social-engineering value
because the standard does not weight Apple-branded presentation. In the
context of an enterprise security team's threat model, the bug ranks
materially higher than the base CVSS implies.

---

## What end-users can do today

Because the bug is server-side, there is no patch end-users can apply.
Practical defensive guidance for individuals and security teams:

1. **Treat the displayed filename, icon, and size on a Maildrop landing
   page as advisory, not authoritative.** They reflect what the sender
   chose to put in the URL, not what Apple has verified about the file.

2. **Where the underlying file matters, ask the sender to provide a
   second-channel checksum** (SHA-256) and verify after download. This
   is the only reliable defence available today.

3. **In enterprise environments**, consider blocking
   `https://www.icloud.com/attachment/` and `cvws.icloud-content.com`
   at the proxy unless the workflow specifically requires Maildrop.
   Most organisations do not.

4. **Email security gateways** that classify URLs by domain reputation
   should not extend Apple's reputation to *content served via Maildrop
   URLs*. The two are not coextensive.

No mitigation removes the attack surface; only a server-side fix at
Apple does.

---

## Recommended fix

Three options, in increasing order of architectural cleanliness:

1. **HMAC the outer query string.** Append a `sig=` parameter
   computed by Apple's Maildrop service over the canonical
   concatenation of `u`, `uk`, `f`, `sz`. Reject requests where the
   signature does not match. Implementation: one HMAC computation
   per URL generation, one per download request. Backward compatibility
   handled by accepting unsigned URLs for the remainder of their 30-day
   life and signing all newly-generated URLs.

2. **Derive `f` and `sz` from the server-side record keyed by `uk`.**
   The Maildrop service already knows the canonical filename and size
   for each `uk`. Ignore the URL-supplied `f` and `sz` values; resolve
   them server-side at request time. The CDN template substitution for
   `${f}` should resolve from the server record, not the request query
   string.

3. **Remove the `${f}` and `${uk}` template substitution from the CDN
   URL entirely.** The CDN path can be made canonical and content-hash-
   addressed, with filename presentation handled by the landing page
   from server-side metadata.

Option 2 is the most defensible. It removes the entire attack class
without requiring callers to retain or transmit a signature.

---

## On `responsible disclosure`

This document is published after **34 months** of vendor exclusivity.
The author considers this appropriate because:

1. **The vendor has had ample time.** No reasonable interpretation of
   coordinated-disclosure norms gives a vendor approaching three years
   to deploy a server-side parameter signing change.

2. **The bug is rediscoverable by inspection.** Any researcher who
   examines a Maildrop URL and notices the unsigned parameters can
   reproduce the entire finding in minutes. There is no
   reverse-engineering barrier and no compiled-binary friction. The
   author considers it highly likely that independent rediscovery has
   already occurred among red-team and adversarial communities.

3. **End-users are currently defenceless against this attack class.**
   They have no way to know that Maildrop's landing-page presentation
   is sender-controlled. Disclosure enables informed defence at the
   user, enterprise, and email-gateway level.

4. **The remediation is purely server-side.** No client-side action,
   no patch propagation, no compatibility chain — Apple can deploy
   the fix at any time, and the bug is closed everywhere the moment
   they do.

5. **The author has provided the vendor with a working PoC, a video
   demonstration, and a written write-up specifying the fix.** Three
   separate forms of evidence. Apple has had every artefact required
   to act.

This disclosure does not include credentials, account-specific URLs,
or any non-public Apple infrastructure detail. The technical content
of this document is reproducible from any Maildrop URL the reader
generates themselves.

---

## Reproducibility

- This document is licensed CC BY 4.0; reuse, citation, and
  redistribution are permitted with attribution.
- The PoC requires Python 3 and a Maildrop URL generated by sending
  a small file to oneself via Apple Mail. No credentials, no API
  keys, no proprietary tooling.
- The author's PoC script (`maildrop_spoof.py`) is reproduced in
  full in §"Empirical demonstration" above and is also available
  separately on request.
- Vendor case OE1950888220 was originally filed on 2023-07-07;
  refreshed PoC and analysis filed 2026-04-04; vendor status as of
  2026-05-13 is *"Prioritised for review"*.

---

## Acknowledgements

The author thanks Apple's iCloud Mail engineering team for building
Maildrop as a useful feature, and Apple Product Security for the
acknowledgement of the original 2023 report and the request for a
video PoC. The author is grateful that, despite the lack of remediation
across the intervening period, the bug remained sufficiently obvious
to be reproducible at re-investigation in April 2026.

---

## References

1. Apple Inc., *Apple Security Bounty*, security.apple.com/bounty.
2. Apple Inc., *Maildrop overview*, support.apple.com (user-facing
   documentation; describes the 5 GB upload cap and 30-day URL
   lifetime).
3. RFC 6266, *Use of the Content-Disposition Header Field in the
   Hypertext Transfer Protocol (HTTP)*, J. Reschke, June 2011.
4. RFC 6749, *The OAuth 2.0 Authorization Framework*, D. Hardt
   (editor), October 2012 — Section 10.10 (cryptographic guidance
   on URL parameters).
5. Krebs on Security, *Why Phishers Love Brand-Owned Domains*,
   general industry reference for the "phishing on the brand's own
   domain" pattern that this bug enables.

---

*Stuart Thomas is an independent security researcher with prior
contributions accepted into the OpenBSD and FreeBSD projects.
Contact information available on request. This disclosure represents
the author's own work and does not represent the position of any
employer.*
