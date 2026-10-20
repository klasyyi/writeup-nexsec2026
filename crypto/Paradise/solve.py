#!/usr/bin/env python3
"""
NexSec 2026 - Mersenne Twister Solve Script
Author: klasyyi
"""

import socket
import time
import struct
import random
from z3 import *

# ==============================================================================
# 1. MT19937 Bit Inversion Helpers & CPython Primitives
# ==============================================================================

def invert_f(z):
    """
    Invert the MT19937 twist transformation f(y) = (y >> 1) ^ (A if y & 1 else 0).
    Because bit 31 of (y >> 1) is 0 and bit 31 of 0x9908b0df is 1,
    the 31st bit of z uniquely dictates the parity bit (y & 1).
    """
    A = 0x9908b0df
    b0 = (z >> 31) & 1
    mag = A if b0 else 0
    y_shifted = z ^ mag
    return (((y_shifted << 1) | b0) & 0xffffffff)

def f2(x):
    """Loop 2 mixing polynomial: (x ^ (x >> 30)) * 1566083941"""
    return ((x ^ (x >> 30)) * 1566083941) & 0xffffffff

def f1(x):
    """Loop 1 mixing polynomial: (x ^ (x >> 30)) * 1664525"""
    return ((x ^ (x >> 30)) * 1664525) & 0xffffffff

def init_genrand(s):
    """Standard MT19937 initialization from integer seed (19650218)"""
    N = 624
    mt = [0] * N
    mt[0] = s & 0xffffffff
    for i in range(1, N):
        mt[i] = (1812433253 * (mt[i-1] ^ (mt[i-1] >> 30)) + i) & 0xffffffff
    return mt

def twist_linear_inplace(mt):
    """Symbolic model of CPython's in-place MT19937 twist"""
    N, M, A = 624, 397, 0x9908b0df
    next_mt = list(mt)
    for i in range(N - M):
        mti, mti1, mtim = next_mt[i], next_mt[i + 1], next_mt[i + M]
        y = (mti & 0x80000000) ^ (mti1 & 0x7fffffff)
        mag = SignExt(31, Extract(0, 0, mti1)) & A
        next_mt[i] = mtim ^ LShR(y, 1) ^ mag
    for i in range(N - M, N - 1):
        mti, mti1, mtim = next_mt[i], next_mt[i + 1], next_mt[i + (M - N)]
        y = (mti & 0x80000000) ^ (mti1 & 0x7fffffff)
        mag = SignExt(31, Extract(0, 0, mti1)) & A
        next_mt[i] = mtim ^ LShR(y, 1) ^ mag
    mti, mti1, mtim = next_mt[N - 1], next_mt[0], next_mt[M - 1]
    y = (mti & 0x80000000) ^ (mti1 & 0x7fffffff)
    mag = SignExt(31, Extract(0, 0, mti1)) & A
    next_mt[N - 1] = mtim ^ LShR(y, 1) ^ mag
    return next_mt

def temper(y):
    """MT19937 output tempering transform"""
    y ^= LShR(y, 11)
    y ^= (y << 7) & 0x9d2c5680
    y ^= (y << 15) & 0xefc60000
    y ^= LShR(y, 18)
    return y

# ==============================================================================
# 2. Main Exploit Routine
# ==============================================================================

def solve_server(host, port):
    print(f"[*] Connecting to {host}:{port}...")
    s = socket.socket()
    s.settimeout(60)
    s.connect((host, port))

    buf = b""
    while b"Seed (hex):" not in buf:
        chunk = s.recv(4096)
        if not chunk:
            break
        buf += chunk

    print("[*] Received challenge banner and leaked outputs.")
    part = buf.split(b"hehe\n--------------------------------------------------------------------------------------------------------------------------------\n")[1]
    arr_str = part.split(b"\nYou only have")[0].decode().strip()
    something = eval(arr_str)
    print(f"[*] Parsed {len(something)} truncated 16-bit outputs.")

    # Step 1: Solve State 1 (S1) via Z3
    print("[*] Setting up Z3 constraints for S1...")
    t0 = time.time()
    S1 = [BitVec(f"s1_{i}", 32) for i in range(624)]
    solver = Solver()

    # S1 outputs: 623 outputs (words 1..623)
    for i in range(623):
        solver.add(LShR(temper(S1[i + 1]), 16) == something[i])

    # S2 outputs: 343 outputs (words 0..342 of S2)
    S2 = twist_linear_inplace(S1)
    for i in range(len(something) - 623):
        solver.add(LShR(temper(S2[i]), 16) == something[623 + i])

    print(f"[*] Constraints built in {round(time.time() - t0, 2)}s. Solving...")
    t1 = time.time()
    if solver.check() != sat:
        print("[-] Z3 UNSAT! Equations are inconsistent.")
        return
    print(f"[*] Solved S1 in {round(time.time() - t1, 2)}s!")

    m = solver.model()
    s1_solved = [m[S1[i]].as_long() if m[S1[i]] is not None else 0 for i in range(624)]

    # Step 2: Pure Python Untwist to recover S0[229..341]
    y_vals = {}
    for k in range(228, 342):
        z = s1_solved[k] ^ s1_solved[k - 227]
        y_vals[k] = invert_f(z)

    recovered_s0 = {}
    for k in range(229, 342):
        top_bit = y_vals[k] & 0x80000000
        lower_31 = y_vals[k - 1] & 0x7fffffff
        recovered_s0[k] = top_bit | lower_31

    # Step 3: Reverse Loop 2 of init_by_array
    s0_loop1 = {}
    for k in range(230, 342):
        s0_loop1[k] = ((recovered_s0[k] + k) & 0xffffffff) ^ f2(recovered_s0[k - 1])

    # Step 4: Reverse Loop 1 of init_by_array
    mt_init = init_genrand(19650218)
    recovered_keys = {}
    for k in range(231, 342):
        j = (k - 1) % 18
        kj = (s0_loop1[k] - j - (mt_init[k] ^ f1(s0_loop1[k - 1]))) & 0xffffffff
        recovered_keys[j] = kj

    # Extract key words 16 and 17 (the raw 64-bit seed)
    k16 = recovered_keys[16]
    k17 = recovered_keys[17]
    seed_bytes = struct.pack(">2I", k17, k16)
    seed_hex = seed_bytes.hex()

    # Step 5: Regenerate the secret
    rng = random.Random(seed_bytes)
    secret = rng.getrandbits(32)

    print(f"[+] Recovered Seed (hex): {seed_hex}")
    print(f"[+] Recovered Secret:     {secret}")

    # Step 6: Send answers to remote server
    print("[*] Sending answers to server...")
    s.sendall(seed_hex.encode() + b"\n")
    time.sleep(0.5)
    s.sendall(str(secret).encode() + b"\n")

    response = b""
    while True:
        try:
            chunk = s.recv(4096)
            if not chunk:
                break
            response += chunk
        except Exception:
            break
    s.close()

    print("[*] Server Response:")
    print("-" * 64)
    print(response.decode(errors="replace").strip())
    print("-" * 64)

if __name__ == "__main__":
    solve_server("koala.nexsec.my", 36589)
