#!/usr/bin/python3
import os
from pwn import xor
import sys
FLAG = open('flag.txt').read().strip()
HEADER_ART = """
*************************************************
*                                               *
*   Welcome to the XOR Madness Challenge!       *
*                                               *
*************************************************
"""

FOOTER_ART = """
*************************************************
*                                               *
*         Good luck! Don't forget about         *
*         the properties of XOR.                *
*************************************************
"""

def main():

    global FLAG
    fl = len(FLAG.encode('utf-8'))
    k1, k2, k3, k4 = os.urandom(fl), os.urandom(fl), os.urandom(fl), os.urandom(fl)
    ec = xor(FLAG.encode('utf-8'), k1, k2, k3, k4)

    r1 = xor(k1, k2)
    r2 = xor(k2, k3)
    r3 = xor(k3, k4)
    r4 = xor(k4, k1)
    r5 = xor(k2, k4)

    print(f"[+] XOR Madness Challenge Results:")
    print(f"[+] k1 = {k1.hex()}")
    print(f"[+] k1 ^ k2 = {r1.hex()}")
    print(f"[+] k2 ^ k3 = {r2.hex()}")
    print(f"[+] k3 ^ k4 = {r3.hex()}")
    print(f"[+] k4 ^ k1 = {r4.hex()}")
    print(f"[+] k2 ^ k4 = {r5.hex()}")
    print(f"[+] FLAG ^ k1 ^ k2 ^ k3 ^ k4 = {ec.hex()}")
    print(FOOTER_ART, flush=True)
    sys.exit(0)
if __name__ == '__main__':
    main()
