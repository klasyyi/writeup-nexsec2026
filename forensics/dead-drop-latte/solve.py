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
        ct_and_tag = raw[12:]

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
