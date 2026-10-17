# Mersenne Twister - NexSec 2026 (Crypto)

> **Repository:** [klasyyi/writeup-nexsec2026](https://github.com/klasyyi/writeup-nexsec2026)  
> **Points:** 450 | **Solves:** 12 | **Category:** Crypto

---

## 1. Overview & TL;DR

In this challenge, the service initializes Python's standard `random.Random(seed)` PRNG using an unknown 8-byte seed (`randbytes(8)`). It generates an initial 32-bit `secret` (which is kept hidden), followed by 966 outputs where each 32-bit random number is truncated to its upper 16 bits (`x >> 16`). To get the flag, the server requires us to recover both the original 8-byte seed in hex and the hidden 32-bit `secret`.

Because MT19937 tempering and twist operations are $\mathbb{F}_2$-linear, I modeled the two generation cycles ($S_1$ and $S_2$) in Z3 to recover the internal state. While Z3 successfully solved $S_1$, the 966 16-bit outputs only constrain words $0 \dots 341$, leaving words $342 \dots 623$ as arbitrary filler. 

By analyzing CPython's `_randommodule.c`, I discovered that:
1. Python's seed expansion places the raw 64-bit seed directly at `key[16]` and `key[17]`, bypassing SHA-512 completely.
2. CPython's in-place twist creates a local window ($k \in [228, 341]$) where $S_1[k] \oplus S_1[k - 227]$ yields the twist transformation $f(y)$ without depending on any unconstrained filler words.
3. Because bit 31 of MT19937's matrix $A$ (`0x9908B0DF`) is 1, $f(y)$ can be inverted in pure Python in one line. Stitched adjacent $y$ values reconstruct $S_0[229..341]$, and reversing CPython's `init_by_array` yields the exact seed and secret in ~13 seconds.

---

## 2. Reconnaissance & Initial Analysis

The challenge provided a single Python script (`challenge.py`) and a remote network service running on `nc koala.nexsec.my 36589`.

### Source Code Inspection

```python
from random import *
from Crypto.Cipher import AES
from hashlib import sha256
import secrets

something = []
standart = 624 * 32

seed = randbytes(8)
rng = Random(seed)

# hmm
secret = rng.getrandbits(32)

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

print("I'm quite disappointed that you couldn't guess it correctly")
```

### Key Observations:
1. **Output Count:** `standart // 20 - 32 = (624 * 32) // 20 - 32 = 998 - 32 = 966` outputs.
2. **Output Truncation:** Only the upper 16 bits of each 32-bit output are provided: `x >> 16`.
3. **The Target:**
   - `seed.hex()`: The 8-byte (`64-bit`) random seed used to initialize `Random(seed)`.
   - `secret`: The first 32-bit output generated right after initialization (`rng.getrandbits(32)`).
4. **Information Budget:**
   A full MT19937 state is $624 \times 32 = 19,968$ bits.
   We receive $966 \times 16 = 15,456$ bits.
   Standard MT state recovery tools (like `randcrack`) require 624 full, untruncated 32-bit words ($19,968$ bits) from a single state cycle. Here, we have truncated bits spanning across two different state twist cycles.

---

## 3. Vulnerability Analysis (Root Cause)

### 1. Linearity of MT19937 and Tempering
Python's standard PRNG is the Mersenne Twister (MT19937). An MT state consists of $N = 624$ words of 32 bits each ($mt[0 \dots 623]$). 
When generating a number:
```python
y = mt[i]
y ^= (y >> 11)
y ^= (y << 7) & 0x9D2C5680
y ^= (y << 15) & 0xEFC60000
y ^= (y >> 18)
```
Every step of tempering is an $\mathbb{F}_2$-linear operation (XOR and bit shifts with constant masks). 

When the state runs out after 624 outputs, it undergoes a "twist":
$$y = (mt[i] \ \& \ \text{0x80000000}) \mid (mt[(i+1) \bmod 624] \ \& \ \text{0x7FFFFFFF})$$
$$mt[i] = mt[(i + 397) \bmod 624] \oplus (y \gg 1) \oplus (y \ \& \ 1 \ ? \ \text{0x9908B0DF} : 0)$$

Because this transformation is linear over $\text{GF}(2)$, a system of bit-level linear equations can be formulated and solved with Z3.

### 2. Rabbit Hole 1: Brute-forcing the Seed
The seed is `randbytes(8)`, which is a 64-bit value ($2^{64}$ possibilities). A brute force search is completely infeasible.

### 3. Rabbit Hole 2: CPython's Seed Hashing & SHA-512
When you initialize `random.Random(seed)` with bytes in Python:
```python
# CPython Modules/_randommodule.c
static PyObject *
random_seed(RandomObject *self, PyObject *args)
{
    ...
    // If seed is bytes, CPython converts it to an arbitrary-precision integer:
    // _PyLong_FromByteArray(bytes, len, little_endian=0, signed=0)
}
```
Then CPython initializes the MT state with `init_by_array`.
Looking into `init_by_array` in `_randommodule.c`:
If the integer has more than 32 bits, CPython passes it to a hashing function:
```c
/* Modules/_randommodule.c */
_Py_HashBytes(seed_bytes, len) // Uses SHA-512
```
At first glance, this looked catastrophic: does CPython hash the 8-byte seed with SHA-512? If so, how can we recover `seed` from the MT state without inverting SHA-512?

I dug directly into CPython's implementation of `init_by_array` and found how key words are prepared:
```c
static PyObject *
_random_Random_seed_impl(RandomObject *self, PyObject *arg)
{
    ...
    /* For a Python integer, CPython converts it into 32-bit chunks */
    key = (uint32_t *)PyMem_Malloc(key_length * sizeof(uint32_t));
    ...
    /* CPython computes SHA-512 of the integer, generating 16 words (64 bytes) */
    /* AND THEN appends the original integer chunks at the end! */
    key[16] = seed_chunk_0;
    key[17] = seed_chunk_1;
}
```
In CPython, the key array passed to `init_by_array` has length 18:
- `key[0..15]`: 16 words containing the SHA-512 digest.
- `key[16..17]`: **The original 64-bit seed unpacked as two 32-bit integers in little-endian!**

Specifically:
```python
seed_bytes = struct.pack(">2I", key[17], key[16])
```
We do not need to invert SHA-512! If we can recover `key[16]` and `key[17]`, we have the exact original seed.

---

## 4. Exploitation Walkthrough

### Phase 1: Solving State 1 ($S_1$) with Z3

Let $S_1$ be the 624-word state after `secret = rng.getrandbits(32)` is drawn.
- Word $0$ of $S_1$ generates `secret` (which is not in `something`).
- Words $1 \dots 623$ of $S_1$ generate `something[0 ... 622]` (623 outputs).
- At output 624, the state twists in-place to $S_2 = \text{twist}(S_1)$.
- Words $0 \dots 342$ of $S_2$ generate `something[623 ... 965]` (343 outputs).

We set up Z3 with 624 32-bit bitvectors for $S_1$, apply an in-place twist to form $S_2$, and add constraints on the upper 16 bits:

```python
solver.add(LShR(temper(S1[i + 1]), 16) == something[i])      # i in 0..622
solver.add(LShR(temper(S2[i]), 16) == something[623 + i])    # i in 0..342
```

Z3 solves this system in ~12 seconds. 

However, because $S_2$ outputs only go up to index 342, only words $0 \dots 341$ of $S_1$ are fully constrained. Words $342 \dots 623$ of $S_1$ are arbitrary filler assigned by Z3.

### Phase 2: The In-Place Twist Miracle (Recovering $S_0$)

To get the seed, we must reverse from $S_1$ back to $S_0$ (the state before the first twist).

Attempting to run a global untwist or asking Z3 to find $S_0$ fails with `unsat` because Z3's filler words in $S_1[342..623]$ do not correspond to any valid MT state.

However, notice how CPython performs the twist:
```c
for (i = 0; i < N - M; i++) {
    y = (mt[i] & UPPER_MASK) | (mt[i + 1] & LOWER_MASK);
    mt[i] = mt[i + M] ^ (y >> 1) ^ mag01[y & 1];
}
for (; i < N - 1; i++) {
    y = (mt[i] & UPPER_MASK) | (mt[i + 1] & LOWER_MASK);
    mt[i] = mt[i + (M - N)] ^ (y >> 1) ^ mag01[y & 1]; // M - N = 397 - 624 = -227
}
```

For $i \ge N - M$ ($i \ge 227$), `i + (M - N)` is $i - 227$.
Because the twist is in-place, index $i - 227$ has **already been updated to $S_1$**!
Therefore, for $k \in [228, 341]$:
$$S_1[k] = S_1[k - 227] \oplus f(y_k)$$
$$f(y_k) = S_1[k] \oplus S_1[k - 227]$$

Look at the indices:
- $k \in [228, 341]$ is within the known, solved range of $S_1$ ($\le 341$).
- $k - 227 \in [1, 114]$ is also within the known, solved range of $S_1$.

Neither term touches the unconstrained filler words ($342 \dots 623$)!

#### Inverting $f(y)$
$$f(y) = (y \gg 1) \oplus (\text{0x9908B0DF if } y \ \& \ 1 \text{ else } 0)$$
Notice that $(y \gg 1)$ always has bit 31 equal to 0. 
The magic constant `0x9908B0DF` has bit 31 equal to 1.
Therefore, the most significant bit of $z = S_1[k] \oplus S_1[k - 227]$ directly reveals $y \ \& \ 1$:
```python
b0 = (z >> 31) & 1
y = (((z ^ (0x9908B0DF if b0 else 0)) << 1) | b0) & 0xFFFFFFFF
```
$f(y)$ is a 1-to-1 bijection and is inverted in pure Python with zero guessing!

#### Stitching $S_0[k]$
By definition of the twist:
$$y_k = (S_0[k] \ \& \ \text{0x80000000}) \mid (S_0[k+1] \ \& \ \text{0x7FFFFFFF})$$
$$y_{k-1} = (S_0[k-1] \ \& \ \text{0x80000000}) \mid (S_0[k] \ \& \ \text{0x7FFFFFFF})$$

Taking the upper bit from $y_k$ and the lower 31 bits from $y_{k-1}$ gives the exact 32-bit word:
```python
S0[k] = (y_k & 0x80000000) | (y_prev & 0x7FFFFFFF)
```
Because $S_1[0]$ generated the unobserved `secret`, it is unconstrained. Thus we begin from $k = 229$ where all inputs $S_1[k], S_1[k-227], S_1[k-1], S_1[k-228]$ are fully constrained. This gives us exact values for $S_0[229 \dots 341]$!

### Phase 3: Reversing CPython's `init_by_array`

CPython's `init_by_array` modifies `mt` in two sequential loops:

#### Reversing Loop 2:
```c
for (k = N - 1; k; k--) {
    mt[i] = (mt[i] ^ ((mt[i-1] ^ (mt[i-1] >> 30)) * 1566083941UL)) - i;
    i++;
}
```
Notice that when step $i$ executes, `mt[i-1]` was already updated in step $i-1$. Thus `mt[i-1]` in the formula is simply $S_0[i-1]$!
To invert it:
```python
state_after_loop1[k] = ((S0[k] + k) & 0xFFFFFFFF) ^ f2(S0[k - 1])
```
This formula only requires $S_0[k]$ and $S_0[k-1]$. For $k \ge 230$, both are known!

#### Reversing Loop 1:
```c
for (k = ...; k; k--) {
    mt[i] = (mt[i] ^ ((mt[i-1] ^ (mt[i-1] >> 30)) * 1664525UL)) + key[j] + j;
    i++;
    j++;
}
```
Similarly, `mt[i-1]` is `state_after_loop1[k-1]`.
To invert it:
```python
key[j] = (state_after_loop1[k] - j - (mt_init[k] ^ f1(state_after_loop1[k - 1]))) & 0xFFFFFFFF
```
where $j = (k - 1) \bmod 18$.

For $k \in [231, 341]$, each key index $j \in [0, 17]$ is visited 6 to 7 times. Every single occurrence produces the identical value with 100% agreement!

We extract `key[16]` and `key[17]`:
```python
seed_bytes = struct.pack(">2I", key[17], key[16])
seed_hex = seed_bytes.hex()
```

Finally, we re-instantiate `random.Random(seed_bytes)` and call `getrandbits(32)` to recover `secret`.

---

## 5. Solve Script

Save as `solve.py`:

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
```

---

## 6. Flag & Verification

Running `solve.py` against the active remote instance:

```text
$ python solve.py
[*] Connecting to koala.nexsec.my:36589...
[*] Received challenge banner and leaked outputs.
[*] Parsed 966 truncated 16-bit outputs.
[*] Setting up Z3 constraints for S1...
[*] Constraints built in 2.62s. Solving...
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

---

## 7. Key Takeaways & Remediation

### 1. Insecure PRNGs in Security Contexts
The Mersenne Twister (MT19937) was explicitly designed for Monte Carlo simulations and statistical sampling, **not** cryptography. Because all internal state transitions (both twisting and tempering) are linear over $\text{GF}(2)$, truncated outputs do not provide security. Given sufficiently many outputs across state twists, Z3 or Gaussian elimination will reconstruct the full state in seconds.

**Remediation:**
For generating secrets, tokens, keys, or nonces, always use a cryptographically secure pseudorandom number generator (CSPRNG):
```python
import secrets
token = secrets.token_bytes(32)
```

### 2. CPython Implementation Nuances
An essential takeaway from this challenge is that understanding the runtime implementation matters just as much as understanding the abstract algorithm. Even though CPython's `random` module hashes large seeds using SHA-512, its internal integer unpacking scheme preserves the raw 64-bit seed in plaintext within the key buffer (`key[16]` and `key[17]`), completely neutralizing SHA-512's one-way property.
