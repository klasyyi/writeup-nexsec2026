# матрёшка (Matryoshka) - NexSec 2026 (Reverse Engineering)

> **Repository:** [klasyyi/writeup-nexsec2026](https://github.com/klasyyi/writeup-nexsec2026)  
> **DeepSeek Chat Session:** [https://chat.deepseek.com/share/pfw85puth4sur5t0sx](https://chat.deepseek.com/share/pfw85puth4sur5t0sx)  
> **Category:** Reverse Engineering

---

## 1. Overview & TL;DR

In this challenge, we are provided with a 32-bit Windows executable named `matryoshka.exe` and a cryptic hint: `recurse(recurse(recurse(recurse)))`. Running the binary directly crashes immediately due to a corrupted .NET metadata token (`MissingMethodException` on `RuntimeHelpers.InitializeArray`).

Collaborating through the reverse engineering process with DeepSeek (documented in the [chat session](https://chat.deepseek.com/share/pfw85puth4sur5t0sx)), I discovered that the challenge implements a 4-level deep binary decision tree of nested, AES-encrypted .NET assemblies (Russian nesting dolls: `doll-0`/`doll-1` down to `doll-0000` through `doll-1111`). While the program enforces a 16-character password check at the end of execution, the encryption keys used to unpack the dolls are derived purely from static hashes and path strings (`SHA256(parentKey + path)`). By automating the tree traversal offline, I reached leaf node `doll-1111`, extracted the encrypted payload, and decrypted the flag using the static password hash already baked into the root executable.

---

## 2. Reconnaissance & Initial Analysis

### 2.1 File Triage

I started by inspecting the file headers using standard Linux/WSL utilities:

```bash
$ file matryoshka.exe
matryoshka.exe: PE32 executable (console) Intel 80386 Mono/.Net assembly, for MS Windows

$ ls -lh matryoshka.exe
-rwxr-xr-x 1 user user 236K Oct 17 21:27 matryoshka.exe
```

The binary is a PE32 .NET CLR assembly (`v4.0.30319`) of approximately 235 KB.

### 2.2 Dynamic Execution Failure

When attempting to run `matryoshka.exe` directly in Windows PowerShell, it failed before reaching the user prompt:

```text
Unhandled Exception: System.TypeInitializationException: The type initializer for 'A.A' threw an exception. ---> 
System.TypeInitializationException: The type initializer for '<PrivateImplementationDetails>{6F571695-3AC6-4BED-94DB-5CD82B72F7F1}.E89CC75B-4443-4C17-A450-8651971BBC3A' threw an exception. ---> 
System.MissingMethodException: Method not found: 'Void System.Runtime.CompilerServices.RuntimeHelpers.InitializeArray(System.Array, IntPtr)'.
   at <PrivateImplementationDetails>{6F571695-3AC6-4BED-94DB-5CD82B72F7F1}.E89CC75B-4443-4C17-A450-8651971BBC3A..cctor()
   --- End of inner exception stack trace ---
   at <PrivateImplementationDetails>{6F571695-3AC6-4BED-94DB-5CD82B72F7F1}.E89CC75B-4443-4C17-A450-8651971BBC3A.C()
   at A.A..cctor()
   --- End of inner exception stack trace ---
   at A.A.A(String[] )
```

Under the ECMA-335 specification, `RuntimeHelpers.InitializeArray` expects `(Array, RuntimeFieldHandle)`. The obfuscator corrupted the metadata `MemberRef` token so that it looked for `(System.Array, IntPtr)`. This deliberate flaw prevented dynamic execution or attached debugging.

### 2.3 Decompilation in dnSpy

Because dynamic execution was blocked, I moved to static analysis using **dnSpyEx** (which parses .NET metadata tables without running the code).

Examining the Assembly Explorer revealed:
* Class `A.A`: Contains the entry point `A(string[])` and helper cryptographic routines.
* Class `<PrivateImplementationDetails>...`: Houses string decryption methods `C()`, `c()`, `D()`, `d()`, `E()`, etc.
* Manifest Resources: Two large embedded blobs named `doll-0` (116,256 bytes) and `doll-1` (116,768 bytes), comprising almost the entire binary.

---

## 3. Vulnerability Analysis (Root Cause)

### 3.1 Unpacking the String Decryption Routine

In the static constructor (`.cctor`) of `<PrivateImplementationDetails>`, I located the code responsible for the crash:

```cil
// Token: 0x0600001B RID: 27 RVA: 0x000027F4
.method private hidebysig specialname rtspecialname static void .cctor () cil managed 
{
    .maxstack 5
    .locals init (int32 V_0)

    ldc.i4.s   13
    newarr     [mscorlib]System.String
    stsfld     string[] ...::field_strings
    ldc.i4     489
    newarr     [mscorlib]System.Byte
    dup
    ldtoken    field ...::field_raw_data // Token 0x0400000A
    call       void [mscorlib]System.Runtime.CompilerServices.RuntimeHelpers::InitializeArray(...)
    stsfld     uint8[] ...::field_bytes
    ldc.i4.0
    stloc.0
    br.s       IL_0045

IL_002A: // Loop body
    ldsfld     uint8[] ...::field_bytes
    ldloc.0
    ldsfld     uint8[] ...::field_bytes
    ldloc.0
    ldelem.u1
    ldloc.0
    xor
    ldc.i4     0xAA
    xor
    conv.u1
    stelem.i1
    ldloc.0
    ldc.i4.1
    add
    stloc.0

IL_0045: // Loop test
    ldloc.0
    ldsfld     uint8[] ...::field_bytes
    ldlen
    conv.i4
    clt
    brtrue.s   IL_002A
    ret
}
```

The method allocates a 489-byte buffer, initializes it from raw PE data, and decodes every byte:
```text
dec[i] = raw[i] ^ (i & 0xFF) ^ 0xAA
```

Inspecting the `FieldRVA` table (Table `0x1D`) showed token `0x0400000A` mapped to RVA `0x3B6A0` (file offset `0x398A0` in the `.text` section). I wrote a Python script to carve and decode the 489 bytes:

| Index | Method | Decrypted Value | Purpose |
|:---:|:---:|:---|:---|
| 0 | `A()` | `a sister is missing from her nesting` | Exception message |
| 1 | `a()` | `this sister does not open` | Exception message |
| 2 | `B()` | `0` | Branch ID '0' |
| 3 | `b()` | `1` | Branch ID '1' |
| 4 | `C()` | `matryoshka` | Module name |
| 5 | `c()` | `328c8951475e0d2c71a84c2f619af94727bef60eaadbe557cf5f82afd98d531b` | Hash component 1 |
| 6 | `D()` | `1a685de80dadec0efc1a32e0d07fc450e68f1c348c9c00ad8a39395b380911ba` | Hash component 2 |
| 7 | `d()` | `0641f85debb485f588745a946b1cbfd76257b2b18504b40ff60f304bbded9bc1` | Hash component 3 |
| 8 | `E()` | `77aa4d230ca164172ea2c972e207cb93dae2d0bd5e5fd3234ff4b5ea8874e345` | **Target Password SHA-256** |
| 9 | `e()` | `The old doll sighs as her lacquer cracks open: 'So. You have come to be sorted.'` | Doll open message |
| 10 | `F()` | `The old doll stays shut. 'Sixteen seeds, planter. No more. No less.'` | Doll shut error |
| 11 | `f()` | `doll-0` | Resource name 0 |
| 12 | `G()` | `doll-1` | Resource name 1 |

### 3.2 The Flawed Cryptographic Gatekeeper

In `A.A..cctor()`, the binary derives a master root key by XORing the three 32-byte hashes:
```text
Key_root = Hex(c()) ^ Hex(D()) ^ Hex(d())
         = 2ea52ce4a14764d705c6245bdaf982c0a366588ba34351f5b3698bbf5c69d960
```

Next, I analyzed the main verification and doll-dispatching logic:

```csharp
// Decompiled from A.A::A(string[] args)
string pw = args.Length > 0 ? args[0] : Console.ReadLine();
if (pw.Length != 16 || !IsPrintableAscii(pw)) {
    Console.WriteLine("The old doll stays shut. 'Sixteen seeds, planter. No more. No less.'");
    Environment.Exit(1);
}

// Bit testing: bit 0 of each character determines which branch is touched
bool flag0 = false, flag1 = false;
for (int i = 0; i < 16; i++) {
    if ((pw[i] & 1) == 0) flag0 = true;
    else flag1 = true;
}

if (flag0) Method9(true, "doll-0", "0", KeyRoot, pw, storyList, failMsg);
if (flag1) Method9(true, "doll-1", "1", KeyRoot, pw, storyList, failMsg);

// Final password check
if (!ConstEq(SHA256(pw), TargetHash_E)) {
    Console.WriteLine(failMsg);
    Environment.Exit(1);
}
PrintStory(storyList);
```

When inspecting `Method9`, I realized the vulnerability:
```csharp
void Method9(bool needed, string resName, string dollId, byte[] parentKey, string pw, List<string> story, string failMsg)
{
    if (!needed) return;

    // Notice: parentKey and dollId ("0" or "1") are hashed, NOT pw!
    byte[] childKey = SHA256(parentKey.Concat(Encoding.ASCII.GetBytes(dollId)).ToArray());

    byte[] cipherData = ReadResource(resName); // Reads doll-0 or doll-1
    byte[] decryptedAssembly = DecryptAES(cipherData, childKey); // AES-CBC, IV is first 16 bytes

    Assembly childAsm = Assembly.Load(decryptedAssembly);
    MethodInfo entry = FindEntryMethod(childAsm);
    entry.Invoke(null, new object[] { dollId, childKey, story });
}
```

**The Vulnerability:**  
The 16-character password `pw` is **never used to derive the decryption keys of the nested dolls**. The child key is derived deterministically from:
```text
Key_child = SHA256(Key_parent || ASCII(childPath))
```

Furthermore, the flag decryption method in the leaf dolls was defined as:
```csharp
string DecryptFlag(string pw) {
    byte[] key = SHA256(Encoding.ASCII.GetBytes(pw));
    return Encoding.UTF8.GetString(DecryptAES(FromHex(FLAG_ENC), key));
}
```
Because the binary requires `SHA256(pw) == TargetHash_E`, the AES key for the flag is already known: it is literally `TargetHash_E` (`77aa4d230ca1...`). There was no need to crack the 16-character password to unpack the payloads or decrypt the flag.

---

## 4. Exploitation Walkthrough

### Phase 1: Decrypting the First Layer (`doll-0` and `doll-1`)

Extracting the embedded resources `doll-0` and `doll-1` from `matryoshka.exe` and applying AES-256-CBC with keys:
* `K_0 = SHA256(Key_root || "0")`
* `K_1 = SHA256(Key_root || "1")`

Both payloads cleanly decrypted into valid PE32 .NET DLL files (`decrypted_doll-0.dll` and `decrypted_doll-1.dll`).

### Phase 2: Unpacking the Binary Decision Tree

Decompiling `decrypted_doll-0.dll` in dnSpy exposed the recursive class `Matryoshka.Doll`:

```csharp
namespace Matryoshka
{
    public class Doll
    {
        public static string ASM_NAME = "doll-0";
        public static string PATH = "0";
        public static int[] INDICES = new int[] { 0, 1, 4, 6, 8, 11, 14, 15 };
        public static string[] HMACS = new string[] { ... };
        public static bool CARRIES_FLAG = false;
        public static string FLAG_ENC = null;
        public static string CHILD0_RES = "doll-00";
        public static string CHILD1_RES = "doll-01";
        
        public static void Check(string pw, byte[] key, List<string> story) { ... }
    }
}
```

The challenge implements a **binary tree of depth 4** (2⁴ = 16 leaves):
* **Level 0 (Root):** `matryoshka.exe` branches on bit 0 of password characters.
* **Level 1:** `doll-0` and `doll-1` branch on bit 1.
* **Level 2:** 4 dolls (`doll-00`, `doll-01`, `doll-10`, `doll-11`) branch on bit 2.
* **Level 3:** 8 dolls (`doll-000` to `doll-111`) branch on bit 3.
* **Level 4 (Leaves):** 16 leaf dolls (`doll-0000` through `doll-1111`).

```
                              [ matryoshka.exe ]
                             /                  \
                       [ doll-0 ]            [ doll-1 ]
                       /        \            /        \
                   doll-00    doll-01    doll-10    doll-11
                    /   \      /   \      /   \      /   \
                   ...  ...   ...  ...   ...  ...   ...  ...
                  16 Leaf Dolls: doll-0000 through doll-1111
```

### Phase 3: Automated Traversal & The UTF-16LE Gotcha

When writing the automated recursive unpacker with DeepSeek, we encountered two notable technical gotchas:

1. **dnfile HeapItemString Type Error:**  
   In `dnfile`, resource names are wrapped in a `HeapItemString` class. Checking `if res_name in res.name` caused:
   ```text
   TypeError: argument of type 'HeapItemString' is not a container or iterable
   ```
   This was resolved by casting: `str(res.name)`.

2. **UTF-16LE Encoding in the `#US` Stream:**  
   When scanning the leaf DLLs for `FLAG_ENC`, a standard ASCII regex (`rb'[0-9a-fA-F]{128}'`) failed to match. In .NET binaries, all user strings in the `#US` heap are encoded in **UTF-16LE** (two bytes per character, with interleaved null bytes: `5\x003\x001\x00...`).  
   The regex had to be updated to match the null-interleaved pattern:
   ```python
   re.compile(rb'(?:[0-9a-fA-F]\x00){128}')
   ```

Running the traversal down to the leaves, node **`doll-1111`** had `CARRIES_FLAG = true` and contained the 128-character ciphertext:

```text
5311cf63109a5a9082d797f0e917433f58f6c3b79bb1dd8925a4d82d95754aef3865420feea10448db156277d2ea54f89ea4fee7b65f87cdf10dc9863329da93
```

### Phase 4: Flag Decryption

Using `FLAG_KEY = bytes.fromhex("77aa4d230ca164172ea2c972e207cb93dae2d0bd5e5fd3234ff4b5ea8874e345")`:
* **IV:** First 16 bytes (`5311cf63109a5a9082d797f0e917433f`)
* **Ciphertext:** Remaining 48 bytes
* **Cipher:** AES-256-CBC with PKCS7 unpadding

Decrypting the payload produced the flag:
```text
nexsec26{nexsec26{nexsec26{🚩}}}
```

---

### Bonus: Recovering the 16-Character Password

Although not strictly required, each leaf doll verified characters using HMAC-SHA256:
```text
HMAC-SHA256(K_leaf, [index, ASCII(c)]) == target_hmac
```

Because each index was tested across only 95 printable ASCII characters (`0x20` - `0x7E`), I brute-forced all 16 characters in under a second:

```text
Leaf doll '0000': index 11 -> 'P'
Leaf doll '0001': index  1 -> 'h'
Leaf doll '0010': index  4 -> 'D'
Leaf doll '0011': index 14 -> 'l'
Leaf doll '0100': index  0 -> 'r'
Leaf doll '0101': index 15 -> 'z'
Leaf doll '0110': index  6 -> 'f'
Leaf doll '0111': index  8 -> 'n'
Leaf doll '1000': index  3 -> 'a'
Leaf doll '1001': index  7 -> 'i'
Leaf doll '1010': index 10 -> 'e'
Leaf doll '1011': index  9 -> 'M'
Leaf doll '1100': index 12 -> 'c'
Leaf doll '1101': index  2 -> 'k'
Leaf doll '1110': index  5 -> 'w'
Leaf doll '1111': index 13 -> 'o'
```

Ordering the characters by index yielded:
```text
pw = "rhkaDwfinMePcolz"
```

Verifying against the target hash:
```text
SHA256("rhkaDwfinMePcolz") == 77aa4d230ca164172ea2c972e207cb93dae2d0bd5e5fd3234ff4b5ea8874e345  [MATCH]
```

---

## 5. Solve Script

The complete Python solve script ([`solve.py`](solve.py)) extracts resources, navigates the tree, and recovers the flag:

```python
#!/usr/bin/env python3
"""
NexSec 2026 - матрёшка (Matryoshka) Solve Script
Author: klasyyi
DeepSeek Session: https://chat.deepseek.com/share/pfw85puth4sur5t0sx
Description: Recursively unpacks the .NET doll tree and decrypts the flag.
"""

import hashlib
import os
import re
import sys
import dnfile
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

# Ensure terminal can print multi-byte Unicode emojis without encoding crashes
sys.stdout.reconfigure(encoding='utf-8')

# Root values recovered from matryoshka.exe
PARENT_KEY = bytes.fromhex("2ea52ce4a14764d705c6245bdaf982c0a366588ba34351f5b3698bbf5c69d960")
FLAG_HASH  = "77aa4d230ca164172ea2c972e207cb93dae2d0bd5e5fd3234ff4b5ea8874e345"
FLAG_KEY   = bytes.fromhex(FLAG_HASH)

def decrypt_aes(cipher_data: bytes, key: bytes) -> bytes:
    """Standard AES-256-CBC decryption with PKCS7 unpadding."""
    iv = cipher_data[:16]
    ciphertext = cipher_data[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = cipher.decrypt(ciphertext)
    try:
        return unpad(decrypted, AES.block_size)
    except ValueError:
        return decrypted

def get_embedded_resource(pe: dnfile.dnPE, res_name: str) -> bytes:
    """Extracts an embedded manifest resource from a dnfile object."""
    if pe.net.resources is None:
        return None
    for res in pe.net.resources:
        # Cast HeapItemString to native str
        if res.name and res_name in str(res.name):
            return bytes(res.data)
    return None

def check_for_flag(dll_path: str, current_path: str) -> bool:
    """Scans the raw PE for 128-char UTF-16LE hex strings and attempts flag decryption."""
    with open(dll_path, "rb") as f:
        raw_data = f.read()

    # UTF-16LE encoded 128 hex characters (256 bytes)
    hex_pattern = re.compile(rb'(?:[0-9a-fA-F]\x00){128}')

    for match in hex_pattern.finditer(raw_data):
        hex_str = match.group(0).decode('utf-16le').replace('\x00', '')
        try:
            flag_cipher = bytes.fromhex(hex_str)
            flag_decrypted = decrypt_aes(flag_cipher, FLAG_KEY)
            dec_str = flag_decrypted.decode('utf-8')

            if "{" in dec_str and "}" in dec_str:
                print(f"\n[🏁] FLAG FOUND in {dll_path} at path {current_path}:\n{dec_str}\n")
                return True
        except Exception:
            pass
    return False

def traverse_doll(dll_path: str, current_key: bytes, current_path: str) -> bool:
    """Recursively extracts and unpacks child doll assemblies."""
    print(f"[*] Loading {dll_path} (Path: {current_path})")

    try:
        pe = dnfile.dnPE(dll_path)
    except Exception as e:
        print(f"[-] Failed to parse {dll_path}: {e}")
        return False

    # Check if this node carries the flag
    if check_for_flag(dll_path, current_path):
        return True

    # Recurse down children "0" and "1"
    for child_index in ["0", "1"]:
        child_path = current_path + child_index
        res_name = f"doll-{child_path}"

        # Derive child key: SHA256(parentKey + ASCII(childPath))
        child_key = hashlib.sha256(current_key + child_path.encode('ascii')).digest()

        cipher_data = get_embedded_resource(pe, res_name)
        if not cipher_data:
            continue

        decrypted_dll = decrypt_aes(cipher_data, child_key)
        child_dll_path = f"doll_{child_path}.dll"
        with open(child_dll_path, "wb") as f:
            f.write(decrypted_dll)

        if traverse_doll(child_dll_path, child_key, child_path):
            return True

    return False

if __name__ == "__main__":
    print("=" * 60)
    print("     MATRYOSHKA CTF SOLVER - RECURSIVE TREE TRAVERSAL")
    print("=" * 60)

    # Derive keys for the initial two dolls
    key_0 = hashlib.sha256(PARENT_KEY + b"0").digest()
    key_1 = hashlib.sha256(PARENT_KEY + b"1").digest()

    if not traverse_doll("decrypted_doll-0.dll", key_0, "0"):
        traverse_doll("decrypted_doll-1.dll", key_1, "1")
```

---

## 6. Flag & Verification

Executing `solve.py` against the carved root assemblies traverses the binary decision tree and captures the flag:

```text
$ python solve.py
============================================================
     MATRYOSHKA CTF SOLVER - RECURSIVE TREE TRAVERSAL
============================================================
[*] Loading decrypted_doll-0.dll (Path: 0)
[*] Loading doll_00.dll (Path: 00)
[*] Loading doll_000.dll (Path: 000)
[*] Loading doll_0000.dll (Path: 0000)
[*] Loading doll_0001.dll (Path: 0001)
[*] Loading doll_001.dll (Path: 001)
[*] Loading doll_0010.dll (Path: 0010)
[*] Loading doll_0011.dll (Path: 0011)
[*] Loading doll_01.dll (Path: 01)
[*] Loading doll_010.dll (Path: 010)
[*] Loading doll_0100.dll (Path: 0100)
[*] Loading doll_0101.dll (Path: 0101)
[*] Loading doll_011.dll (Path: 011)
[*] Loading doll_0110.dll (Path: 0110)
[*] Loading doll_0111.dll (Path: 0111)
[*] Loading decrypted_doll-1.dll (Path: 1)
[*] Loading doll_10.dll (Path: 10)
[*] Loading doll_100.dll (Path: 100)
[*] Loading doll_1000.dll (Path: 1000)
[*] Loading doll_1001.dll (Path: 1001)
[*] Loading doll_101.dll (Path: 101)
[*] Loading doll_1010.dll (Path: 1010)
[*] Loading doll_1011.dll (Path: 1011)
[*] Loading doll_11.dll (Path: 11)
[*] Loading doll_110.dll (Path: 110)
[*] Loading doll_1100.dll (Path: 1100)
[*] Loading doll_1101.dll (Path: 1101)
[*] Loading doll_111.dll (Path: 111)
[*] Loading doll_1110.dll (Path: 1110)
[*] Loading doll_1111.dll (Path: 1111)

[🏁] FLAG FOUND in doll_1111.dll at path 1111:
nexsec26{nexsec26{nexsec26{🚩}}}
```

### Captured Flag:
> `nexsec26{nexsec26{nexsec26{🚩}}}`

