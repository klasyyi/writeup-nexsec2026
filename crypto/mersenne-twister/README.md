# Mersenne Twister - NexSec 2026 (Crypto)

> **Repository:** [klasyyi/writeup-nexsec2026](https://github.com/klasyyi/writeup-nexsec2026)  
> **Points:** 450 | **Solves:** 12 | **Category:** Crypto

---

## 1. Overview & TL;DR

In this challenge, a remote server generates an 8-byte random seed and initializes Python's standard `random.Random(seed)` generator. It draws a 32-bit secret number that it hides from us, and then gives us 966 consecutive random numbers, but with only the upper 16 bits of each number (`x >> 16`). To get the flag, we have to provide both the original 8-byte seed (in hex) and the hidden 32-bit secret.

Because Mersenne Twister (MT19937) operations are bitwise linear (shifts and XORs), I used Z3 to recover the generator's state. But because we only had 966 half-outputs, Z3 could only recover the first 342 words accurately—the rest were arbitrary filler. 

By looking at CPython's C source code (`_randommodule.c`), I noticed two crucial things:
1. CPython stores the raw 64-bit seed directly inside the key array at indices 16 and 17, so we never have to reverse SHA-512.
2. In CPython's in-place twist, indices 228 to 341 depend only on values we already solved. We can untwist them and reverse the initialization loops in plain Python in under 15 seconds.

---

## 2. Reconnaissance & Initial Analysis

We were provided with `challenge.py` and a remote service running on `nc koala.nexsec.my 36589`.

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

### Breaking Down the Numbers:
- `standart // 20 - 32` gives `(624 * 32) // 20 - 32 = 966` outputs.
- Each number is truncated: only the top 16 bits (`x >> 16`) are leaked.
- The standard MT19937 state has 624 words of 32 bits each (19,968 bits total).
- We receive `966 * 16 = 15,456` bits of data across two generator cycles.
- Off-the-shelf tools like `randcrack` do not work here because they require 624 full, untruncated 32-bit integers from a single cycle.

---

## 3. Vulnerability Analysis (Root Cause)

### 1. MT19937 is Linear
Python's default PRNG is MT19937. Every step of output tempering uses bitwise XOR and bit shifts with constant masks:

```python
y = mt[i]
y ^= (y >> 11)
y ^= (y << 7) & 0x9D2C5680
y ^= (y << 15) & 0xEFC60000
y ^= (y >> 18)
```

Because these operations only involve XOR and shifts, each output bit is simply a linear combination (over GF(2)) of the internal state bits. This makes it a great fit for a SAT/SMT solver like Z3.

### 2. Rabbit Hole: The 64-bit Seed and SHA-512
My first thought was: can we just brute force the seed?
No, the seed is 8 random bytes (64 bits), which means 2^64 possibilities. That is way too big to brute-force.

My second worry was: when Python seeds `Random(seed)` with bytes, does it hash them?
Looking into CPython's `Modules/_randommodule.c`, when you pass bytes, Python converts them into an integer and then calls `init_by_array`:
- If the integer is longer than 32 bits, CPython computes a SHA-512 hash of the seed, producing 16 32-bit words (64 bytes).
- **Crucial Discovery:** CPython then takes the original integer and appends its chunks right after the hash!

```c
/* In CPython's _randommodule.c */
key[0..15] = sha512_digest_words;
key[16]    = seed_chunk_0;  // lower 32 bits of our seed
key[17]    = seed_chunk_1;  // upper 32 bits of our seed
```

This was a huge relief: we don't have to invert SHA-512! If we can recover `key[16]` and `key[17]`, we have the original seed.

---

## 4. Exploitation Walkthrough

### Phase 1: Solving the First State (S1) with Z3

Let `S1` be the 624-word state after `secret = rng.getrandbits(32)` is generated:
- Word 0 generates `secret` (which we don't see).
- Words 1 to 623 generate the first 623 leaked outputs (`something[0..622]`).
- At output 624, the state twists in-place to `S2`.
- Words 0 to 342 of `S2` generate the remaining 343 outputs (`something[623..965]`).

We set up Z3 with 624 32-bit bitvectors for `S1`, simulate the twist to get `S2`, and constrain the top 16 bits to match `something`:

```python
for i in range(623):
    solver.add(LShR(temper(S1[i + 1]), 16) == something[i])

for i in range(len(something) - 623):
    solver.add(LShR(temper(S2[i]), 16) == something[623 + i])
```

Z3 solves this in about 12 seconds.

However, because `S2` only covers 343 outputs, only words 0 to 341 of `S1` are constrained. Words 342 to 623 are arbitrary filler chosen by Z3.

---

### Phase 2: Untwisting Without Full State (Recovering S0)

To get the seed, we need to go backwards from `S1` to `S0` (the state right after `init_by_array`).

If we try to untwist the whole array with Z3, it gives `unsat` because the filler words in `S1[342..623]` do not make a valid Mersenne Twister state.

But look at how CPython does the in-place twist:
```c
for (i = 227; i < 623; i++) {
    y = (mt[i] & 0x80000000) | (mt[i + 1] & 0x7FFFFFFF);
    mt[i] = mt[i - 227] ^ (y >> 1) ^ (y & 1 ? 0x9908B0DF : 0);
}
```

For index `k` between 228 and 341:
```text
S1[k] = S1[k - 227] ^ f(y)
f(y) = S1[k] ^ S1[k - 227]
```

Notice:
- `k` is between 228 and 341 (already solved by Z3).
- `k - 227` is between 1 and 114 (already solved by Z3).

Both values are 100% known and contain zero filler!

#### Inverting f(y) in Plain Python:
The twist function is:
```text
f(y) = (y >> 1) ^ (0x9908B0DF if (y & 1) else 0)
```
Notice that `(y >> 1)` always has bit 31 equal to 0. 
The constant `0x9908B0DF` has bit 31 equal to 1.
So bit 31 of `z = S1[k] ^ S1[k - 227]` tells us `y & 1` immediately without any guessing!

```python
b0 = (z >> 31) & 1
y = (((z ^ (0x9908B0DF if b0 else 0)) << 1) | b0) & 0xFFFFFFFF
```

#### Reconstructing S0[k]:
By definition of the twist:
- `y[k]` holds the top bit of `S0[k]` and lower 31 bits of `S0[k+1]`.
- `y[k-1]` holds the top bit of `S0[k-1]` and lower 31 bits of `S0[k]`.

Combining the top bit from `y[k]` and the bottom 31 bits from `y[k-1]` gives the exact 32-bit word:
```python
S0[k] = (y[k] & 0x80000000) | (y[k - 1] & 0x7FFFFFFF)
```

Starting from `k = 229` (so that `k - 227 >= 2`, avoiding the unconstrained `S1[0]`), we get the exact values for `S0[229..341]`.

---

### Phase 3: Reversing init_by_array in Pure Python

CPython's `init_by_array` has two sequential loops. We can step backwards through both of them purely in Python:

#### 1. Reversing Loop 2:
In CPython, each step of Loop 2 computes:
```text
mt[i] = (mt[i] ^ f2(mt[i-1])) - i
```
In the forward loop, `mt[i-1]` was already modified in the previous iteration, which means it is simply `S0[k-1]`.
To undo it:
```python
state_after_loop1[k] = ((S0[k] + k) & 0xFFFFFFFF) ^ f2(S0[k - 1])
```
This only needs `S0[k]` and `S0[k-1]`, which we already know for `k >= 230`!

#### 2. Reversing Loop 1:
Similarly, each step of Loop 1 computes:
```text
mt[i] = (mt_init[i] ^ f1(mt[i-1])) + key[j] + j
```
To undo it:
```python
key[j] = (state_after_loop1[k] - j - (mt_init[k] ^ f1(state_after_loop1[k - 1]))) & 0xFFFFFFFF
```
where `j = (k - 1) % 18`.

For `k` between 231 and 341, `(k - 1) % 18` cycles through all 18 key indices 6 to 7 times. Every single candidate matches 100% consistently!

#### 3. Extracting Seed & Secret:
We pull out `key[16]` and `key[17]`:
```python
seed_bytes = struct.pack(">2I", key[17], key[16])
seed_hex = seed_bytes.hex()
```

Then we initialize a local `Random(seed_bytes)` and call `getrandbits(32)` to get the secret.

---

## 5. Solve Script

Here is the complete script (`solve.py`):

```python
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
# Helper Functions
# ==============================================================================

def invert_f(z):
    """Undo the twist function f(y) in one step."""
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

    # S1 outputs (outputs 1..623)
    for i in range(623):
        solver.add(LShR(temper(S1[i + 1]), 16) == something[i])

    # S2 outputs (outputs 624..965)
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

    # 3. Reverse Loop 2
    s0_loop1 = {}
    for k in range(230, 342):
        s0_loop1[k] = ((recovered_s0[k] + k) & 0xffffffff) ^ f2(recovered_s0[k - 1])

    # 4. Reverse Loop 1
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

    # Send to server
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

## 6. Flag & Verification

Running `python solve.py`:

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

### Flag:
> `nexsec26{w0w_y0u_already_kn0w_Mersenne_Twister_nice_0fed2f1a9dd2c3c276cc24a2461c377486ca88acce79ef488023ce18c5abf4c4}`

---

## 7. Key Takeaways & Remediation

1. **MT19937 is Not Cryptographically Secure:**
   The Mersenne Twister is designed for speed and statistical randomness, not security. Because twisting and tempering are bitwise linear, truncated outputs can easily be reconstructed using SAT solvers like Z3.
   
   To generate tokens, keys, or secrets securely in Python, always use the `secrets` module:
   ```python
   import secrets
   secure_token = secrets.token_bytes(32)
   ```

2. **Always Check the Underlying C Implementation:**
   Looking into CPython's `_randommodule.c` was the breakthrough for this challenge. Even though Python hashes large seeds with SHA-512, it appends the raw seed at the end of the key array, making SHA-512 completely irrelevant to the attack.
