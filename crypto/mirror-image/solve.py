#!/usr/bin/env python3
"""
NexSec 2026 - Mirror Image Solve Script
Vulnerability: Low-Density Subset-Sum over CRT residues with s < M.
Exploit: Bit-truncation (// 2^1024) + CJLOSS / Kannan embedding + LLL reduction.
"""
import ast
import socket
import sys
import time
from hashlib import sha256
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from flint import fmpz_mat, fmpz

HOST = "koala.nexsec.my"
PORT = 36354
CASTER_BITS = 1024
SHIFT = CASTER_BITS

def fetch_challenge(host, port):
    """Connects to the challenge server and retrieves the mirror/ward parameters."""
    print(f"[*] Connecting to {host}:{port}...")
    sock = socket.create_connection((host, port), timeout=15)
    raw = b""
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            break
        raw += chunk
    sock.close()
    return raw.decode(errors="replace")

def solve_challenge(data_str):
    lines = [line.strip() for line in data_str.strip().splitlines() if line.strip()]
    mirrors = []
    ward = None

    for line in lines:
        if line.startswith("mirror ="):
            mirrors.append(ast.literal_eval(line.split("=", 1)[1].strip()))
        elif line.startswith("ward ="):
            ward = ast.literal_eval(line.split("=", 1)[1].strip())

    if not mirrors or not ward:
        raise ValueError("Failed to parse challenge output.")

    n = len(mirrors)
    nonce = bytes.fromhex(ward[0])
    ciphertext = bytes.fromhex(ward[1])
    print(f"[+] Loaded {n} mirrors. Moduli size: ~{mirrors[0][0].bit_length()} bits each.")

    # -------------------------------------------------------------
    # 1. Compute Chinese Remainder Theorem (CRT) parameters
    # -------------------------------------------------------------
    mods = [m[0] for m in mirrors]
    a_list = [m[1][0] for m in mirrors]              # shadow 0 (reference)
    d_list = [(m[1][1] - m[1][0]) % m[0] for m in mirrors]  # shadow 1 - shadow 0

    M = 1
    for m in mods:
        M *= m
    print(f"[+] Modulus product M bit-length: {M.bit_length()} bits (slack: {M.bit_length() - CASTER_BITS} bits)")

    # Standard CRT basis weights: W_i = (M / m_i) * [(M / m_i)^-1 mod m_i] mod M
    W = []
    for i in range(n):
        M_i = M // mods[i]
        inv = pow(M_i % mods[i], -1, mods[i])
        W.append((M_i * inv) % M)

    A = 0
    U = []
    for i in range(n):
        A = (A + a_list[i] * W[i]) % M
        U.append((d_list[i] * W[i]) % M)

    # -------------------------------------------------------------
    # 2. Divide by 2^1024 to eliminate unknown s
    # -------------------------------------------------------------
    bar_M = M >> SHIFT
    bar_A = A >> SHIFT
    bar_U = [u >> SHIFT for u in U]

    # -------------------------------------------------------------
    # 3. Construct CJLOSS / Kannan Embedding Lattice Matrix (114 x 114)
    # -------------------------------------------------------------
    dim = n + 2
    B = fmpz_mat(dim, dim)

    # Row 0 to n-1: Identity weights and truncated subset sum weights
    for i in range(n):
        B[i, i] = fmpz(1)
        B[i, n] = fmpz(bar_U[i])

    # Row n: Modulus row for k * bar_M
    B[n, n] = fmpz(bar_M)

    # Row n+1: Target row (-bar_A mod bar_M) and embedding coordinate 1
    B[n + 1, n] = fmpz(-bar_A % bar_M)
    B[n + 1, n + 1] = fmpz(1)

    print(f"[+] Lattice constructed ({dim}x{dim}). Executing LLL reduction...")
    t0 = time.time()
    B_red = B.lll()
    print(f"[+] LLL completed in {time.time() - t0:.2f} seconds.")

    # -------------------------------------------------------------
    # 4. Extract solution vector and reconstruct s
    # -------------------------------------------------------------
    found_s = None
    for r in range(dim):
        row = [int(B_red[r, c]) for c in range(dim)]
        es = row[:n]

        # Check for uncentered binary vector (or its negation)
        if all(x in (0, 1) for x in es) and abs(row[n + 1]) == 1:
            e_bits = es if row[n + 1] == 1 else [-x for x in es]
            s_cand = (A + sum(b * u for b, u in zip(e_bits, U))) % M
            if s_cand.bit_length() <= CASTER_BITS:
                found_s = s_cand
                print(f"[+] Solution discovered in LLL Row {r}!")
                break
        elif all(x in (0, -1) for x in es) and abs(row[n + 1]) == 1:
            e_bits = [-x for x in es] if row[n + 1] == 1 else es
            s_cand = (A + sum(b * u for b, u in zip(e_bits, U))) % M
            if s_cand.bit_length() <= CASTER_BITS:
                found_s = s_cand
                print(f"[+] Solution discovered in LLL Row {r} (negated basis)!")
                break

    if not found_s:
        raise RuntimeError("[-] Failed to extract valid secret s from LLL reduced basis.")

    # Verify secret against all mirrors
    for m, (r0, r1) in mirrors:
        assert found_s % m in (r0, r1), "Validation failed on mirror residue!"
    print(f"[+] Secret s successfully validated against all 112 mirrors ({found_s.bit_length()} bits).")

    # -------------------------------------------------------------
    # 5. Decrypt flag with AES-GCM
    # -------------------------------------------------------------
    key = sha256(found_s.to_bytes(CASTER_BITS // 8, "big")).digest()
    flag = AESGCM(key).decrypt(nonce, ciphertext, None)
    return flag.decode(errors="replace")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        with open(sys.argv[1], "r") as f:
            data = f.read()
    else:
        data = fetch_challenge(HOST, PORT)

    flag = solve_challenge(data)
    print("\n" + "=" * 30 + " FLAG " + "=" * 30)
    print(flag)
    print("=" * 66 + "\n")
