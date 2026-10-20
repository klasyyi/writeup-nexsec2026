from random import *
from Crypto.Cipher import AES
from hashlib import sha256
import secrets

something = []
standart = 624*32

seed = randbytes(8)
rng = Random(seed)

# hmm
secret = rng.getrandbits(32)

for _ in range(standart//20 - 32):
    x = rng.getrandbits(32)
    something.append(x >> 16)

print("-"*128)
print("I think I've given you enough data to figure out the secret. Let's see if you can get it right hehe")
print("-"*128)
print(something)

for _ in range(3):
    print("You only have 3 chances to guess the correct answer")
    ans_seed = (input("Seed (hex): ").strip())
    ans_scrt = int(input("Secret: ").strip())

    if ans_seed == seed.hex() and ans_scrt == secret:
        with open("flag.txt", "r") as f:
            flag = f.read().strip()

        print(flag)
        exit()
    else:
        print("Try again, please be careful")

print("I'm quite disappointed that you couldn't guess it correctly")
