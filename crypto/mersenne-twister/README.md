# Mersenne Twister - NexSec 2026 (Crypto)

> **Repository:** [klasyyi/writeup-nexsec2026](https://github.com/klasyyi/writeup-nexsec2026)  
> **DeepSeek Chat Session:** [https://chat.deepseek.com/share/2e0hdtt83v6ocj9iqf](https://chat.deepseek.com/share/2e0hdtt83v6ocj9iqf)  
> **Points:** 450 | **Solves:** 12 | **Category:** Crypto

---

## 1. Overview & TL;DR

In this challenge, we are given a Python script running on a remote server that initializes `random.Random(seed)` with an 8-byte random seed (`randbytes(8)`). The server generates an initial 32-bit secret that it hides from us, followed by 966 consecutive random numbers where each number is truncated to its upper 16 bits (`x >> 16`). We are allowed 3 attempts to submit both the original 8-byte seed in hex and the 32-bit secret.

Standard tools like `randcrack` fail because we only receive 16-bit truncated outputs across two state cycles. Working through the challenge with DeepSeek (see the [chat transcript](https://chat.deepseek.com/share/2e0hdtt83v6ocj9iqf)), we developed an exploit chain:

1. **Z3 State Recovery (S1):** Because MT19937 tempering and twisting are bitwise linear, Z3 solves the internal state for the first generation cycle in ~13 seconds.
2. **Bypassing SHA-512:** While CPython hashes seeds with SHA-512, inspecting `_randommodule.c` reveals that it appends the raw 64-bit seed directly at `key[16]` and `key[17]`.
3. **The In-Place Twist Trick:** Instead of running into `unsat` errors with a second Z3 solver, we exploit CPython's in-place twist: for indices `k` in `[228, 341]`, `S1[k] ^ S1[k - 227]` gives the twist function `f(y)` using only values we already solved.
4. **Single-Line Inversion & Bit Stitching:** Because bit 31 of MT19937's matrix constant `0x9908B0DF` is 1, `f(y)` is inverted directly in one line. Stitching adjacent `y` values reconstructs `S0[229..341]`.
5. **Reversing `init_by_array`:** We reverse both initialization loops in plain Python in under a millisecond, recover the seed, and grab the flag.

---

## 2. Reconnaissance & Initial Analysis

The challenge provided `challenge.py` and a remote service running on `nc koala.nexsec.my 36589`.

### Source Code

```python
from random import *
from Crypto.Cipher import AES
from hashlib import sha256
import secrets

something = []
standart = 624 * 32

seed = randbytes(8)
rng = Random(seed)

# Secret output we need to guess
secret = rng.getrandbits(32)

# 966 truncated outputs
for _ in range(standart // 20 - 32):
    x = rng.getrandbits(32)
    something.append(x >> 16)

print("-" * 128)
print("I think I've given you enough data to figure out the secret. Let's see if you can get it right hehe")
print("-" * 128)
print(something)

for _ in range(3):
    print("You only have 3 chances to guess the correct answer")
    ans_seed = input("Seed (hex): ").strip()
    ans_scrt = int(input("Secret: ").strip())

    if ans_seed == seed.hex() and ans_scrt == secret:
        with open("flag.txt", "r") as f:
            flag = f.read().strip()
        print(flag)
        exit()
    else:
        print("Try again, please be careful")
```

### Initial Observations:
- Output count: `(624 * 32) // 20 - 32 = 966` values.
- Each value is truncated: only `x >> 16` is leaked.
- An MT19937 state is 624 32-bit words (19,968 bits).
- We receive `966 * 16 = 15,456` bits total.
- Since 966 is greater than 624, the generator produces 623 outputs from State 1 (`S1`) and twists in-place to State 2 (`S2`) to produce the remaining 343 outputs.

---

## 3. The Journey with DeepSeek & Root Cause Analysis

*(Documented step-by-step in the [DeepSeek conversation](https://chat.deepseek.com/share/2e0hdtt83v6ocj9iqf))*

### 1. The SHA-512 Roadblock (and how we bypassed it)
Early in the chat, DeepSeek warned that recovering the 8-byte seed would require inverting SHA-512, because CPython hashes seeds with SHA-512 when initializing `Random(seed)`.

However, looking into CPython's `Modules/_randommodule.c`:
```c
/* In CPython's _randommodule.c: random_seed() */
key = (uint32_t *)PyMem_Malloc(key_length * sizeof(uint32_t));

/* CPython computes SHA-512 of the seed, storing 16 words (64 bytes) */
/* BUT THEN appends the original integer's raw 32-bit words at the end! */
key[16] = seed_chunk_0;  // lower 32 bits of our seed
key[17] = seed_chunk_1;  // upper 32 bits of our seed
```

This was the first breakthrough: CPython's key buffer has 18 words. Words 0 to 15 are the SHA-512 digest, but words 16 and 17 are the raw 64-bit seed in little-endian! If we can recover `key[16]` and `key[17]`, we bypass SHA-512 completely.

---

### 2. Solving State 1 (S1) with Z3
Because MT19937 tempering and twisting are bitwise linear (shifts and XORs), we can model the generator in Z3:
- Let `S1` be 624 32-bit bitvectors.
- `S1[0]` generated the hidden `secret`.
- `S1[1..623]` generated `something[0..622]`.
- `S2 = twist(S1)`.
- `S2[0..342]` generated `something[623..965]`.

Z3 solves `S1` in ~13 seconds. However, because `S2` only covers 343 outputs, only words 0 to 341 of `S1` are constrained. Words 342 to 623 are arbitrary filler chosen by Z3.

---

### 3. The "S0 Unsat" & Inconsistency Trap
Next, DeepSeek tried to set up a second Z3 solver to untwist `S1` backwards to `S0` (the state right after `init_by_array`).

This repeatedly failed:
- Running Z3 on all 624 words gave `unsat` because Z3's filler words in `S1[342..623]` do not form a mathematically valid MT state.
- Using `model_completion=True` returned garbage for unconstrained variables, causing `Key inconsistent!` errors when reversing the initialization loops.

---

### 4. The In-Place Twist Breakthrough
Looking at CPython's actual in-place twist implementation:
```c
for (i = 227; i < 623; i++) {
    y = (mt[i] & 0x80000000) | (mt[i + 1] & 0x7FFFFFFF);
    mt[i] = mt[i - 227] ^ (y >> 1) ^ (y & 1 ? 0x9908B0DF : 0);
}
```

Notice that for `i >= 227`, the twist reads `mt[i - 227]`. Because the array was updated in-place, index `i - 227` was **already replaced with S1**!

Therefore, for `k` in `[228, 341]`:
```text
S1[k] = S1[k - 227] ^ f(y)
f(y) = S1[k] ^ S1[k - 227]
```

Both `k` (<= 341) and `k - 227` (<= 114) are inside the range of `S1` that Z3 already solved accurately. Neither index touches the garbage filler words (`342..623`)!

---

### 5. Inverting f(y) and Stitching S0 in Pure Python
The twist function is:
```text
f(y) = (y >> 1) ^ (0x9908B0DF if (y & 1) else 0)
```
Notice:
- `(y >> 1)` always has bit 31 equal to 0.
- The magic constant `0x9908B0DF` has bit 31 equal to 1.

Therefore, bit 31 of `z = S1[k] ^ S1[k - 227]` directly reveals the parity bit `y & 1`!
We can invert `f(y)` in one line of Python:
```python
b0 = (z >> 31) & 1
y = (((z ^ (0x9908B0DF if b0 else 0)) << 1) | b0) & 0xFFFFFFFF
```

Then we stitch adjacent `y` values:
- `y[k]` has the top bit of `S0[k]`.
- `y[k-1]` has the lower 31 bits of `S0[k]`.

```python
S0[k] = (y[k] & 0x80000000) | (y[k - 1] & 0x7FFFFFFF)
```

Starting from `k = 229` (which avoids the unconstrained `S1[0]`), this recovers the exact 32-bit values for `S0[229..341]` with zero guessing!

---

### 6. Reversing `init_by_array` Without Z3
`init_by_array` runs two forward loops:

**Loop 2:**
```text
mt[i] = (mt[i] ^ f2(mt[i-1])) - i
```
In the forward loop, `mt[i-1]` was already modified in the previous step, so it is just `S0[k-1]`.
We reverse it sequentially:
```python
state_after_loop1[k] = ((S0[k] + k) & 0xFFFFFFFF) ^ f2(S0[k - 1])
```

**Loop 1:**
```text
mt[i] = (mt_init[i] ^ f1(mt[i-1])) + key[j] + j
```
We reverse it:
```python
key[j] = (state_after_loop1[k] - j - (mt_init[k] ^ f1(state_after_loop1[k - 1]))) & 0xFFFFFFFF
```
where `j = (k - 1) % 18`.

For `k` in `[231, 341]`, `j` cycles through all 18 key indices 6 to 7 times. Every single key candidate matches with 100% agreement.

Finally, we pack `key[16]` and `key[17]`:
```python
seed_bytes = struct.pack(">2I", key[17], key[16])
seed_hex = seed_bytes.hex()
```
And calculate `secret = random.Random(seed_bytes).getrandbits(32)`.

---

## 4. Solve Script

Here is the final standalone solve script (`solve.py`):

```python
#!/usr/bin/env python3
"""
NexSec 2026 - Mersenne Twister Solve Script
Author: klasyyi
DeepSeek Session: https://chat.deepseek.com/share/2e0hdtt83v6ocj9iqf
"""

import socket
import time
import struct
import random
from z3 import *

# ==============================================================================
# Helper Functions
# ==============================================================================

def invert_f(z):
    """Invert f(y) using the bit-31 parity trick."""
    A = 0x9908b0df
    b0 = (z >> 31) & 1
    mag = A if b0 else 0
    y_shifted = z ^ mag
    return (((y_shifted << 1) | b0) & 0xffffffff)

def f2(x):
    return ((x ^ (x >> 30)) * 1566083941) & 0xffffffff

def f1(x):
    return ((x ^ (x >> 30)) * 1664525) & 0xffffffff

def init_genrand(s):
    N = 624
    mt = [0] * N
    mt[0] = s & 0xffffffff
    for i in range(1, N):
        mt[i] = (1812433253 * (mt[i-1] ^ (mt[i-1] >> 30)) + i) & 0xffffffff
    return mt

def twist_linear_inplace(mt):
    """Linear model of CPython's in-place MT19937 twist."""
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
    y ^= LShR(y, 11)
    y ^= (y << 7) & 0x9d2c5680
    y ^= (y << 15) & 0xefc60000
    y ^= LShR(y, 18)
    return y

# ==============================================================================
# Main Solver
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

    print("[*] Received banner and leaked outputs.")
    part = buf.split(b"hehe\n--------------------------------------------------------------------------------------------------------------------------------\n")[1]
    arr_str = part.split(b"\nYou only have")[0].decode().strip()
    something = eval(arr_str)
    print(f"[*] Parsed {len(something)} outputs.")

    # 1. Solve S1 with Z3
    print("[*] Solving S1 with Z3...")
    t0 = time.time()
    S1 = [BitVec(f"s1_{i}", 32) for i in range(624)]
    solver = Solver()

    # S1 outputs (words 1..623)
    for i in range(623):
        solver.add(LShR(temper(S1[i + 1]), 16) == something[i])

    # S2 outputs (words 0..342)
    S2 = twist_linear_inplace(S1)
    for i in range(len(something) - 623):
        solver.add(LShR(temper(S2[i]), 16) == something[623 + i])

    if solver.check() != sat:
        print("[-] Z3 UNSAT!")
        return
    print(f"[*] Solved S1 in {round(time.time() - t0, 2)}s!")

    m = solver.model()
    s1_solved = [m[S1[i]].as_long() if m[S1[i]] is not None else 0 for i in range(624)]

    # 2. Pure Python Untwist for S0[229..341]
    y_vals = {}
    for k in range(228, 342):
        z = s1_solved[k] ^ s1_solved[k - 227]
        y_vals[k] = invert_f(z)

    recovered_s0 = {}
    for k in range(229, 342):
        top_bit = y_vals[k] & 0x80000000
        lower_31 = y_vals[k - 1] & 0x7fffffff
        recovered_s0[k] = top_bit | lower_31

    # 3. Reverse Loop 2 of init_by_array
    s0_loop1 = {}
    for k in range(230, 342):
        s0_loop1[k] = ((recovered_s0[k] + k) & 0xffffffff) ^ f2(recovered_s0[k - 1])

    # 4. Reverse Loop 1 of init_by_array
    mt_init = init_genrand(19650218)
    recovered_keys = {}
    for k in range(231, 342):
        j = (k - 1) % 18
        kj = (s0_loop1[k] - j - (mt_init[k] ^ f1(s0_loop1[k - 1]))) & 0xffffffff
        recovered_keys[j] = kj

    # Extract key[16] and key[17]
    k16 = recovered_keys[16]
    k17 = recovered_keys[17]
    seed_bytes = struct.pack(">2I", k17, k16)
    seed_hex = seed_bytes.hex()

    # Compute secret
    rng = random.Random(seed_bytes)
    secret = rng.getrandbits(32)

    print(f"[+] Recovered Seed (hex): {seed_hex}")
    print(f"[+] Recovered Secret:     {secret}")

    # Send answers to server
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
```

---

## 5. Flag & Verification

Running `python solve.py` against `nc koala.nexsec.my 36589`:

```text
$ python solve.py
[*] Connecting to koala.nexsec.my:36589...
[*] Received banner and leaked outputs.
[*] Parsed 966 outputs.
[*] Solving S1 with Z3...
[*] Solved S1 in 12.87s!
[+] Recovered Seed (hex): f6a29d11cffef8a6
[+] Recovered Secret:     2262656539
[*] Sending answers to server...
[*] Server Response:
----------------------------------------------------------------
Secret: nexsec26{w0w_y0u_already_kn0w_Mersenne_Twister_nice_0fed2f1a9dd2c3c276cc24a2461c377486ca88acce79ef488023ce18c5abf4c4}
----------------------------------------------------------------
```

### Final Flag:
> `nexsec26{w0w_y0u_already_kn0w_Mersenne_Twister_nice_0fed2f1a9dd2c3c276cc24a2461c377486ca88acce79ef488023ce18c5abf4c4}`
