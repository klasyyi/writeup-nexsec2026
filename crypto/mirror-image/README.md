# Mirror Image - NexSec 2026 (Crypto)

> **Repository:** [klasyyi/writeup-nexsec2026](https://github.com/klasyyi/writeup-nexsec2026)  
> **DeepSeek Chat Session:** [https://chat.deepseek.com/share/uk97mksa8d2tucubvz](https://chat.deepseek.com/share/uk97mksa8d2tucubvz)  
> **Points:** 450 | **Solves:** 14 | **Category:** Crypto

---

## 1. Overview & TL;DR

In **Mirror Image**, a remote server generates a random 1024-bit secret $s$, picks 112 16-bit prime moduli $m_i$, and gives us two possible residues per mirror: the true residue $s \bmod m_i$ and a fake one. At the end, it encrypts the flag using AES-GCM with key $\text{SHA-256}(s)$.

### TL;DR
Brute-forcing $2^{112}$ shadow combinations is impossible. However, the product of the primes $M = \prod m_i \approx 2^{1743}$ is much larger than $s < 2^{1024}$. Writing the Chinese Remainder Theorem (CRT) sum over integers gives $A + \sum e_i U_i - kM = s$ with $e_i \in \{0, 1\}$. By dividing the whole equation by $2^{1024}$, the unknown secret $s$ drops to $0$ ($\lfloor s / 2^{1024} \rfloor = 0$). This leaves a low-density subset-sum problem over 719-bit integers that LLL solves in under 2 seconds.

---

## 2. Reconnaissance & Initial Analysis

We are given `challenge.py` and a remote netcat service.

### Challenge Logic
1. Generates 112 primes $m_i \in [2^{15}, 2^{16})$.
2. Picks secret $s = \text{randbits}(1024)$.
3. For each mirror, prints $(m_i, (r_{i,0}, r_{i,1}))$, where one residue is $s \bmod m_i$ and the other is random.
4. Encrypts `flag.txt` with AES-GCM using `key = sha256(s.to_bytes(128, 'big')).digest()` and prints `ward = (nonce, ciphertext)`.

```python
for m in mirrors:
    shadows = [s % m]
    while len(shadows) < 2:
        r = randbelow(m)
        if r not in shadows:
            shadows.append(r)
    shuffle(shadows)
    print("mirror =", (m, tuple(shadows)))

key = sha256(s.to_bytes(128, "big")).digest()
nonce = token_bytes(12)
print("ward =", (nonce.hex(), AESGCM(key).encrypt(nonce, flag, None).hex()))
```

---

## 3. Vulnerability Analysis (Root Cause)

### The Core Problem
For each mirror $i$, let $a_i = r_{i,0}$ and $b_i = r_{i,1}$. The real residue is:
$$r_i = a_i + e_i (b_i - a_i), \quad e_i \in \{0, 1\}$$

By Chinese Remainder Theorem with weights $W_i = (M/m_i) \cdot [(M/m_i)^{-1} \bmod m_i] \bmod M$:
$$s \equiv \sum_{i=0}^{111} a_i W_i + \sum_{i=0}^{111} e_i (b_i - a_i) W_i \pmod M$$

Let $A = \sum a_i W_i \bmod M$ and $U_i = (b_i - a_i) W_i \bmod M$. Over the integers:
$$A + \sum_{i=0}^{111} e_i U_i - kM = s$$
where $k \in \{0, 1, \dots, 111\}$ and $0 \le s < 2^{1024}$.

### The Key Insight: Dropping the Unknown $s$
Because $s$ is strictly smaller than $2^{1024}$, we perform integer floor division by $2^{1024}$:
$$\lfloor s / 2^{1024} \rfloor = 0$$

Dividing the entire equation by $2^{1024}$ gives:
$$\bar{A} + \sum_{i=0}^{111} e_i \bar{U}_i - k \bar{M} \approx 0$$
where $\bar{X} = X \gg 1024$.

- The unknown $s$ is completely eliminated.
- $\bar{M} \approx 2^{719}$ and $\bar{U}_i \approx 2^{719}$ are known 719-bit numbers.
- The unknowns are simply the 112 binary bits $e_i \in \{0, 1\}$.
- Density $d \approx 112 / 719 \approx 0.155$, which is well within the low-density knapsack threshold solvable by LLL.

### Common Pitfalls We Hit
Working through the challenge with DeepSeek ([chat transcript](https://chat.deepseek.com/share/uk97mksa8d2tucubvz)), we hit three main pitfalls before getting the clean solve:
1. **Shared row in CVP**: Trying to put all $d_i$ into one row forced all mirrors to share one scalar, ignoring that each mirror has an independent bit.
2. **Gigantic scaling weights**: Scaling columns by $K = 2^{1024}$ made LLL ignore the subset-sum column entirely because the weights were too huge.
3. **Uncentered coordinate check**: The bits $e_i$ are $0$ or $1$. Checking `all(abs(x) == 1)` failed because half the coordinates in the solution vector are $0$. The check must accept $0$ and $1$.

---

## 4. Exploitation Walkthrough

### 1. Lattice Construction
We build a $(112 + 2) \times (112 + 2) = 114 \times 114$ integer matrix:

$$\mathbf{B} = \begin{pmatrix}
1 & 0 & \dots & 0 & \bar{U}_0 & 0 \\
0 & 1 & \dots & 0 & \bar{U}_1 & 0 \\
\vdots & \vdots & \ddots & \vdots & \vdots & \vdots \\
0 & 0 & \dots & 1 & \bar{U}_{111} & 0 \\
0 & 0 & \dots & 0 & \bar{M} & 0 \\
0 & 0 & \dots & 0 & (-\bar{A} \bmod \bar{M}) & 1
\end{pmatrix}$$

Taking row combination $\sum e_i \mathbf{b}_i - k \mathbf{b}_{112} + 1 \cdot \mathbf{b}_{113}$ yields:
$$\mathbf{v} = (e_0, e_1, \dots, e_{111}, \epsilon, 1)$$
where $|\epsilon| \approx 10$ is the tiny truncation error from the floors.

### 2. Norm vs. Gaussian Heuristic
- **Target vector length**: $\|\mathbf{v}\| \le \sqrt{112 \times 1^2 + 10^2 + 1^2} \approx 14.6$.
- **Gaussian heuristic**: $\sigma \approx 2.58 \cdot (2^{719})^{1/114} \approx 204$.

The target vector is **14 times shorter** than any random vector in the lattice. LLL finds it on **Row 0** instantly.

### 3. Extracting $s$ & Decrypting
1. Check Row 0 for coordinates in $\{0, 1\}$ (or $\{0, -1\}$ if negated).
2. Set $e_i$ accordingly and reconstruct:
   $$s = \left(A + \sum_{i=0}^{111} e_i U_i\right) \bmod M$$
3. Derive AES key: $\text{key} = \text{SHA-256}(s.\text{to\_bytes}(128, \text{'big'}))$.
4. Decrypt the ward ciphertext using AES-GCM.

---

## 5. Solve Script

```python
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
```

---

## 6. Flag & Verification

Running `solve.py` against the challenge server:

```text
[*] Connecting to koala.nexsec.my:36354...
[+] Running LLL reduction...
[+] LLL completed in 1.94s

[+] FLAG: nexsec26{YOU_WILL_NEVER_CATCH_ME_HIDING_BETWEEN_ALL_OF_THESE_MIRRORS_D20_I_CAST_MIRROR_IMAGE_b0ee1ac48ad31cb4ad5e6365759c5b6ab274b884e9edc5c8b88341bd17ea6b34}
```

> **Flag:**  
> `nexsec26{YOU_WILL_NEVER_CATCH_ME_HIDING_BETWEEN_ALL_OF_THESE_MIRRORS_D20_I_CAST_MIRROR_IMAGE_b0ee1ac48ad31cb4ad5e6365759c5b6ab274b884e9edc5c8b88341bd17ea6b34}`

---

## 7. Key Takeaways & Remediation

- **Remediation**: If the author reduced `MIRRORS` so that $\prod m_i < 2^{1024}$, the modular relations would not uniquely constrain $s$ over $\mathbb{Z}$, breaking the exact CRT knapsack.
- **Bit-Truncation Trick**: In modular equations with a bounded secret $s < 2^B$, dividing by $2^B$ forces $\lfloor s / 2^B \rfloor = 0$, completely removing the unknown variable and exposing a clean low-density knapsack.
- **Keep Lattice Weights Uniform**: Never inflate lattice embedding weights unnecessarily. Setting the embedding coordinate to 1 balances all coordinates to $O(1)$, letting LLL detect the short vector effortlessly.
