#!/usr/bin/env python3
"""Mirror Image solver: CRT + // 2^1024 + CJLOSS lattice via python-flint."""
import ast, socket, sys, time
from hashlib import sha256
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from flint import fmpz_mat, fmpz

HOST, PORT = "koala.nexsec.my", 36354
CASTER_BITS = 1024

def fetch_data():
    if len(sys.argv) > 1:
        return open(sys.argv[1]).read()
    print(f"[*] Connecting to {HOST}:{PORT}...")
    s = socket.create_connection((HOST, PORT), timeout=15)
    data = b""
    while True:
        chunk = s.recv(4096)
        if not chunk: break
        data += chunk
    s.close()
    return data.decode(errors="replace")

def solve():
    raw = fetch_data()
    mirrors = [ast.literal_eval(l.split("=", 1)[1]) for l in raw.splitlines() if l.startswith("mirror =")]
    ward = [ast.literal_eval(l.split("=", 1)[1]) for l in raw.splitlines() if l.startswith("ward =")][0]
    nonce, ct = bytes.fromhex(ward[0]), bytes.fromhex(ward[1])

    n = len(mirrors)
    mods = [m[0] for m in mirrors]
    a_list = [m[1][0] for m in mirrors]
    d_list = [(m[1][1] - m[1][0]) % m[0] for m in mirrors]

    M = 1
    for m in mods: M *= m

    # 1. CRT weights
    W = []
    for i in range(n):
        Mi = M // mods[i]
        W.append((Mi * pow(Mi % mods[i], -1, mods[i])) % M)

    A = sum(a * w for a, w in zip(a_list, W)) % M
    U = [(d * w) % M for d, w in zip(d_list, W)]

    # 2. Divide by 2^1024 (s vanishes because s < 2^1024)
    bar_M = M >> CASTER_BITS
    bar_A = A >> CASTER_BITS
    bar_U = [u >> CASTER_BITS for u in U]

    # 3. Build 114x114 CJLOSS lattice
    dim = n + 2
    B = fmpz_mat(dim, dim)
    for i in range(n):
        B[i, i] = fmpz(1)
        B[i, n] = fmpz(bar_U[i])
    B[n, n] = fmpz(bar_M)
    B[n + 1, n] = fmpz(-bar_A % bar_M)
    B[n + 1, n + 1] = fmpz(1)

    print("[+] Running LLL reduction...")
    t0 = time.time()
    Br = B.lll()
    print(f"[+] LLL completed in {time.time() - t0:.2f}s")

    # 4. Extract solution bits from Row 0
    found_s = None
    for r in range(dim):
        row = [int(Br[r, c]) for c in range(dim)]
        es = row[:n]
        if all(x in (0, 1) for x in es) and abs(row[n + 1]) == 1:
            e_bits = es if row[n + 1] == 1 else [-x for x in es]
            s_cand = (A + sum(b * u for b, u in zip(e_bits, U))) % M
            if s_cand.bit_length() <= CASTER_BITS:
                found_s = s_cand; break
        elif all(x in (0, -1) for x in es) and abs(row[n + 1]) == 1:
            e_bits = [-x for x in es] if row[n + 1] == 1 else es
            s_cand = (A + sum(b * u for b, u in zip(e_bits, U))) % M
            if s_cand.bit_length() <= CASTER_BITS:
                found_s = s_cand; break

    assert found_s is not None, "Failed to recover s"
    assert all(found_s % m in (r0, r1) for m, (r0, r1) in mirrors), "Residue check failed"

    # 5. Decrypt
    key = sha256(found_s.to_bytes(128, "big")).digest()
    flag = AESGCM(key).decrypt(nonce, ct, None).decode()
    print(f"\n[+] FLAG: {flag}\n")

if __name__ == "__main__":
    solve()
