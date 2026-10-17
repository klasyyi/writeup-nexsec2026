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
