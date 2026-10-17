# Mirror Image - NexSec 2026 (Crypto)

> **Repository:** [klasyyi/writeup-nexsec2026](https://github.com/klasyyi/writeup-nexsec2026)  
> **DeepSeek Chat Session:** [https://chat.deepseek.com/share/uk97mksa8d2tucubvz](https://chat.deepseek.com/share/uk97mksa8d2tucubvz)  
> **Points:** 450 | **Solves:** 14 | **Category:** Crypto

---

## 1. Overview & TL;DR

**Mirror Image** is a cryptography challenge centered around recovering a 1024-bit hidden secret $s$ from a system of ambiguous modular constraints. We are given $n = 112$ distinct 16-bit prime moduli $m_i \in [2^{15}, 2^{16})$. For each modulus $m_i$, the remote server provides two residues $(r_{i, 0}, r_{i, 1})$: one is the genuine residue $s \bmod m_i$, while the other is an illusion (a uniform random value). Once the residues are dumped, the server outputs an AES-GCM ciphertext whose key is $\text{SHA-256}(s)$ and terminates the connection.

### TL;DR
Because each modulus presents two choices, brute-forcing the $2^{112}$ combinations is impossible. However, the product of all 112 primes $M = \prod m_i \approx 2^{1743}$ is substantially larger than the secret $s < 2^{1024}$, leaving $\approx 719$ bits of slack. Formulating the Chinese Remainder Theorem (CRT) over the integers gives $A + \sum e_i U_i - kM = s$ with independent binary choices $e_i \in \{0, 1\}$. By performing integer division by $2^{1024}$ (dropping the lower 1024 bits), the unknown secret $s$ vanishes completely ($s // 2^{1024} = 0$), transforming the system into a low-density subset-sum problem over 719-bit integers. Using a $114 \times 114$ CJLOSS/Kannan-style lattice reduced via LLL in `python-flint`, the exact binary vector was recovered on Row 0 in under 2 seconds, revealing $s$ and decrypting the flag.

---

## 2. Reconnaissance & Initial Analysis

### Provided Artifacts
We were provided with a single Python source file, `challenge.py`, and a remote endpoint:
```text
nc koala.nexsec.my 35951
```

### Initial Inspection of `challenge.py`

```python
import signal
import sys
from hashlib import sha256
from secrets import randbelow, randbits, token_bytes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MIRRORS = 112          
BITS = 16              
SHADOWS = 2            
CASTER = 1024          
LIMIT = 120

def hall(lo, hi):
    sieve = bytearray([1]) * (hi + 1)
    sieve[0:2] = b"\x00\x00"
    for i in range(2, int(hi ** 0.5) + 1):
        if sieve[i]:
            sieve[i * i::i] = bytearray(len(range(i * i, hi + 1, i)))
    return [p for p in range(lo, hi + 1) if sieve[p]]

def pick(pool, count):
    pool = list(pool)
    return [pool.pop(randbelow(len(pool))) for _ in range(count)]

def shuffle(xs):
    for i in range(len(xs) - 1, 0, -1):
        j = randbelow(i + 1)
        xs[i], xs[j] = xs[j], xs[i]

def main():
    flag = open("flag.txt").read().strip().encode()
    mirrors = pick(hall(1 << (BITS - 1), (1 << BITS) - 1), MIRRORS)
    s = randbits(CASTER)

    print("The archmage steps into the hall of mirrors and casts Mirror Image.")
    print("Each mirror throws back a few shadows; exactly one shadow per mirror is the real one.")
    for m in mirrors:
        shadows = [s % m]
        while len(shadows) < SHADOWS:
            r = randbelow(m)
            if r not in shadows:
                shadows.append(r)
        shuffle(shadows)
        print("mirror =", (m, tuple(shadows)))

    key = sha256(s.to_bytes(CASTER // 8, "big")).digest()
    nonce = token_bytes(12)
    print("ward =", (nonce.hex(), AESGCM(key).encrypt(nonce, flag, None).hex()))
    sys.stdout.flush()

if __name__ == "__main__":
    signal.alarm(LIMIT)
    main()
```

### Runtime Behavior
Connecting to the remote service produces output formatted as follows:
```text
The archmage steps into the hall of mirrors and casts Mirror Image.
Each mirror throws back a few shadows; exactly one shadow per mirror is the real one.
mirror = (53939, (33810, 6770))
mirror = (41113, (12984, 30122))
... [110 more mirrors] ...
ward = ('2b99f03db2dfcd3b495c60a8', '96788b16f9e1e6da6c90a356e863e5ee...')
```
The server emits 112 tuples of `(modulus, (shadow0, shadow1))` followed by `(nonce_hex, ciphertext_hex)` and terminates the socket connection. The service is entirely non-interactive: it requires no input from us. All information needed to recover $s$ is emitted upfront.

---

## 3. Vulnerability Analysis (Root Cause)

### Mathematical Parameters & Information Asymmetry
Let's analyze the bit-lengths and information content:
- Secret $s \in [0, 2^{1024})$.
- There are $n = 112$ moduli $m_0, m_1, \dots, m_{111}$.
- Each modulus $m_i$ is a distinct prime in $[2^{15}, 2^{16}-1]$.
- Total modulus product:
  $$M = \prod_{i=0}^{111} m_i \approx (2^{15.5})^{112} \approx 2^{1743}$$
- If we knew the correct shadow for every mirror, standard CRT reconstruction would yield:
  $$s \equiv \sum_{i=0}^{111} r_i M_i (M_i^{-1} \bmod m_i) \pmod M$$
  Because $s < 2^{1024} < M$, the CRT reconstruction over $[0, M)$ is **exact over the integers** without wrap-around ($s \bmod M = s$).

### Formulating the Ambiguity
For each mirror $i$, let $a_i = r_{i, 0}$ and $b_i = r_{i, 1}$. The genuine residue $r_i$ satisfies:
$$r_i = a_i + e_i (b_i - a_i), \quad e_i \in \{0, 1\}$$
Using standard CRT basis weights $W_i = M_i \cdot (M_i^{-1} \bmod m_i) \bmod M$:
$$s \equiv \sum_{i=0}^{111} \left(a_i + e_i (b_i - a_i)\right) W_i \pmod M$$
Let:
$$A = \sum_{i=0}^{111} a_i W_i \bmod M$$
$$U_i = (b_i - a_i) W_i \bmod M$$
Then:
$$s \equiv A + \sum_{i=0}^{111} e_i U_i \pmod M$$
Over the integers $\mathbb{Z}$, there exists an integer quotient $k \in \{0, 1, \dots, 111\}$ such that:
$$A + \sum_{i=0}^{111} e_i U_i - kM = s, \quad \text{where } 0 \le s < 2^{1024}$$

### Rabbit Holes & Failed Approaches

During my exploration and brainstorming with DeepSeek (see the [chat transcript](https://chat.deepseek.com/share/uk97mksa8d2tucubvz)), several intuitive approaches broke down:

#### 1. Polynomial Root Finding Modulo $M$
I noticed that $(s - a_i)(s - b_i) \equiv 0 \pmod{m_i}$ holds unconditionally regardless of which shadow is real. By CRT, this lifts to:
$$s^2 - A' s + B' \equiv 0 \pmod M$$
However, this quadratic has $2^{112}$ roots in $\mathbb{Z}_M$. Coppersmith's theorem for univariate modular polynomials only guarantees finding roots $x_0 < M^{1/d} = M^{1/2} \approx 2^{871}$. Because $s \approx 2^{1024} > 2^{871}$, standard Coppersmith root bounds fail.

#### 2. The Shared Scalar Fallacy in CVP
An initial formulation considered setting up a matrix with rows $m_i$ and a single row containing all difference terms:
$$\begin{pmatrix} d_0 & d_1 & \dots & d_{111} & 1 \end{pmatrix}$$
This was fundamentally flawed: each mirror has an **independent choice bit** $e_i \in \{0, 1\}$. Multiplying a single row by a scalar $c$ forces all mirrors to share the exact same multiplier $c \cdot d_i$, completely failing to model 112 independent binary decisions.

#### 3. Gigantic Embedding Constants Blowing up LLL
Another attempt constructed a lattice scaling the last column by $K = 2^{1024}$ and adding a target row with $C = 2^{2049}$ to balance against $s$. This backfired:
- The basis vectors in the first 112 columns had norm $\approx 1$.
- The embedding columns had magnitudes $K \cdot M \approx 2^{2767}$ and $C = 2^{2049}$.
Because these values were astronomically larger than the identity block, LLL treated the last two columns as "unreachable", outputting vectors where the last coordinates were `0, 0` and the first coordinates blew up to $33,000+$.

---

## 4. Exploitation Walkthrough

### Phase 1: Eliminating the Unknown Secret via Integer Division
Recall the integer identity:
$$A + \sum_{i=0}^{111} e_i U_i - kM = s$$
We know $0 \le s < 2^{1024}$, but $s$ itself is unknown. How do we eliminate $s$?
We divide the entire equation by $2^{1024}$ using integer floor division:
$$\left\lfloor \frac{A + \sum_{i=0}^{111} e_i U_i - kM}{2^{1024}} \right\rfloor = \left\lfloor \frac{s}{2^{1024}} \right\rfloor = 0$$

Let:
$$\bar{A} = \lfloor A / 2^{1024} \rfloor, \quad \bar{U}_i = \lfloor U_i / 2^{1024} \rfloor, \quad \bar{M} = \lfloor M / 2^{1024} \rfloor$$
Because floor division satisfies $\lfloor \sum X_j \rfloor = \sum \lfloor X_j \rfloor + \delta$ where $|\delta| \le \text{number of terms}$, we have:
$$\bar{A} + \sum_{i=0}^{111} e_i \bar{U}_i - k \bar{M} = \epsilon$$
where $|\epsilon| \le 113$ is a tiny integer representing accumulated floor truncation errors!

Notice what just happened:
- $\bar{M} \approx 2^{1743 - 1024} = 2^{719}$ (a 719-bit modulus).
- $\bar{U}_i$ and $\bar{A}$ are known 719-bit integers.
- The unknown $s$ is **completely gone**.
- We are left with a linear equation in $112$ binary variables $e_i \in \{0, 1\}$ and one integer $k \in [0, 112]$.

The density of this subset-sum instance is:
$$d = \frac{n}{\log_2(\bar{M})} \approx \frac{112}{719} \approx 0.155 \ll 0.64$$
Low-density knapsacks with density $< 0.64$ (and even $< 0.9408$) are provably solvable via LLL.

### Phase 2: Constructing the CJLOSS / Kannan Lattice
We want to find binary coefficients $e_0, \dots, e_{111} \in \{0, 1\}$ such that:
$$\sum_{i=0}^{111} e_i \bar{U}_i - k \bar{M} \equiv -\bar{A} \pmod{\bar{M}} \quad (\text{with error } \epsilon)$$

We construct a $(112 + 2) \times (112 + 2) = 114 \times 114$ integer lattice basis $B$:

$$\mathbf{B} = \begin{pmatrix}
1 & 0 & \dots & 0 & 0 & \bar{U}_0 & 0 \\
0 & 1 & \dots & 0 & 0 & \bar{U}_1 & 0 \\
\vdots & \vdots & \ddots & \vdots & \vdots & \vdots & \vdots \\
0 & 0 & \dots & 1 & 0 & \bar{U}_{111} & 0 \\
0 & 0 & \dots & 0 & 0 & \bar{M} & 0 \\
0 & 0 & \dots & 0 & 0 & (-\bar{A} \bmod \bar{M}) & 1
\end{pmatrix}$$

#### What linear combination produces the short vector?
Consider taking the row combination with coefficients:
$$\mathbf{v} = \sum_{i=0}^{111} e_i \mathbf{b}_i - k \mathbf{b}_{112} + 1 \cdot \mathbf{b}_{113}$$
The resulting vector coordinates are:
$$\mathbf{v} = \Big(e_0, \; e_1, \; \dots, \; e_{111}, \; \underbrace{\sum_{i=0}^{111} e_i \bar{U}_i - k \bar{M} + (-\bar{A} \bmod \bar{M})}_{\text{error } \epsilon \approx 10}, \; 1\Big)$$

Let's inspect the magnitude of each coordinate:
- Coordinates $0 \dots 111$: $e_i \in \{0, 1\}$ (magnitude $\le 1$).
- Coordinate $112$: $\epsilon$ (empirically $|\epsilon| \approx 10$).
- Coordinate $113$: $1$.

The Euclidean norm of this target vector is:
$$\|\mathbf{v}\| \approx \sqrt{\sum_{i=0}^{111} e_i^2 + \epsilon^2 + 1^2} \le \sqrt{112 \times 1 + 10^2 + 1} \approx \sqrt{213} \approx 14.6$$

#### Comparing to Gaussian Heuristic
The determinant of this $114 \times 114$ lattice is:
$$\det(B) = 1^{112} \cdot \bar{M} \cdot 1 = \bar{M} \approx 2^{719}$$
The expected length of the shortest vector in a random 114-dimensional lattice with this determinant is given by the Gaussian heuristic:
$$\sigma \approx \sqrt{\frac{114}{2\pi e}} \cdot (\det B)^{1/114} \approx 2.58 \cdot (2^{719})^{1/114} \approx 2.58 \cdot 2^{6.307} \approx 204$$
Our target vector has length $\approx 14.6$, which is **over 14 times shorter** than the Gaussian heuristic! It is an exceptionally prominent shortest vector.

### Phase 3: Lattice Reduction & Solution Extraction
When LLL reduces this lattice basis, the target vector appears directly on **Row 0**.

One crucial implementation pitfall occurred during extraction:
Because the bits were left uncentered ($e_i \in \{0, 1\}$), approximately half of the coordinates in Row 0 are $0$, while the rest are $-1$ (due to LLL returning the negated vector $-\mathbf{v}$). An extraction check requiring `all(abs(x) == 1)` fails because of the zeros. 

The correct extraction logic checks:
```python
if all(x in (0, 1) for x in es):
    e_bits = es
elif all(x in (0, -1) for x in es):
    e_bits = [-x for x in es]
```

### Phase 4: Key Derivation & AES-GCM Decryption
Once the true bits $\mathbf{e} = (e_0, \dots, e_{111})$ are identified:
1. Reconstruct $s$:
   $$s = \left(A + \sum_{i=0}^{111} e_i U_i\right) \bmod M$$
2. Verify that $s < 2^{1024}$ and that $s \bmod m_i \in \{a_i, b_i\}$ for all 112 mirrors.
3. Derive the AES-GCM key:
   $$\text{key} = \text{SHA-256}(s.\text{to\_bytes}(128, \text{"big"}))$$
4. Decrypt the ward ciphertext using AES-GCM with the provided 12-byte nonce.

---

## 5. Solve Script

Below is the complete, self-contained solve script written in Python using `python-flint` for high-performance LLL reduction:

```python
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
```

---

## 6. Flag & Verification

Running the script directly against the active instance yielded the flag in under 2 seconds:

```text
C:\Users\syara\Downloads> python solve.py
[*] Connecting to koala.nexsec.my:36354...
[+] Loaded 112 mirrors. Moduli size: ~16 bits each.
[+] Modulus product M bit-length: 1744 bits (slack: 720 bits)
[+] Lattice constructed (114x114). Executing LLL reduction...
[+] LLL completed in 1.94 seconds.
[+] Solution discovered in LLL Row 0 (negated basis)!
[+] Secret s successfully validated against all 112 mirrors (1023 bits).

============================== FLAG ==============================
nexsec26{YOU_WILL_NEVER_CATCH_ME_HIDING_BETWEEN_ALL_OF_THESE_MIRRORS_D20_I_CAST_MIRROR_IMAGE_b0ee1ac48ad31cb4ad5e6365759c5b6ab274b884e9edc5c8b88341bd17ea6b34}
==================================================================
```

> **Captured Flag:**  
> `nexsec26{YOU_WILL_NEVER_CATCH_ME_HIDING_BETWEEN_ALL_OF_THESE_MIRRORS_D20_I_CAST_MIRROR_IMAGE_b0ee1ac48ad31cb4ad5e6365759c5b6ab274b884e9edc5c8b88341bd17ea6b34}`

---

## 7. Key Takeaways & Remediation

### Remediation
1. **Reduce Slack / Information Leakage:**  
   The vulnerability exists because $\prod m_i \approx 2^{1743}$ leaks 1743 bits of modular constraints on a secret of only 1024 bits. If the challenge author had set `MIRRORS = 60` (such that $\prod m_i \approx 2^{930} < 2^{1024}$), the Chinese Remainder Theorem would have multiple full integer wrap-arounds ($k$ would not be small), and the linear relation modulo $M$ would be insufficient to uniquely constrain $s$.
2. **Increase Shadow Count:**  
   Increasing `SHADOWS` from 2 to 4 or 8 increases the search space per mirror from 1 bit to 2–3 bits, rapidly multiplying the lattice dimension and combinatorial complexity beyond the capability of basic LLL reduction.

### Key Technical Insights
- **Truncation as an Elimination Tool:** When an unknown variable $s$ is bounded ($s < 2^B$) in an exact integer relation $X = s$, dividing the equation by $2^B$ eliminates $s$ entirely ($\lfloor s / 2^B \rfloor = 0$), turning a system with an unknown variable into an inhomogeneous subset-sum with tiny rounding error.
- **Lattice Balance is Paramount:** LLL minimizes Euclidean norm across all coordinates simultaneously. Introducing artificially large weights ($K = 2^{1024}, C = 2^{2049}$) causes LLL to zero out those columns and fail. Scaling all coordinates to the same order of magnitude ($\sim 1$) allows the short vector to emerge effortlessly.
