#!/usr/bin/python3
import secrets
from Crypto.Cipher import AES
from Crypto.Hash import SHA3_256
from Crypto.Util.Padding import pad

class LCG:
    def __init__(self, seed, m, a, c):
        self._state = seed
        self.m = m
        self.a = a
        self.c = c
        
    def next(self):
        self._state = (self.a * self._state + self.c) % self.m
        return self._state


def main():
    m = 672257317069504227
    while True:
        a = secrets.randbits(48)
        c = secrets.randbits(48)
        seed = secrets.randbits(48)
        lcg = LCG(seed, m, a, c)
        states = [lcg.next() for _ in range(6)]
        key_state = lcg.next()
        key = SHA3_256.new(str(key_state).encode()).digest()
        iv = secrets.token_bytes(16)
        flag = open("flag.txt", "rb").read().strip()
        cipher = AES.new(key, AES.MODE_CBC, iv)
        ciphertext = cipher.encrypt(pad(flag, AES.block_size))
        print(f"Duck, Duck, Goose... Get it?! No? Just get the flag (o_O)")
        print(f"m={m}")
        print(f"[+] States: {states}")
        print(f"[+] IV: {iv.hex()}")
        print(f"[+] Ciphertext: {ciphertext.hex()}")
        break
    





if __name__ == "__main__":
    main()
