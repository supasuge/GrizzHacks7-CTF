#!/usr/bin/env sage
from Crypto.Util.number import long_to_bytes, bytes_to_long
from sage.all import *
import os
length_N = 4096  
Kbits = 200      
e = 3            
FLAG = next((open(f, 'rb').read().strip() for f in ['flag.txt', 'flag.example'] if os.path.isfile(f)), b"GrizzCTF{FAKE_FLAG_LOL!!}")
K = bytes_to_long(FLAG)   
if K.bit_length() > Kbits:
    raise ValueError("You done goofed... Think about what you have done.")
p = next_prime(2^(length_N//2))
q = next_prime(p)
N = p*q
M = (2^length_N) - (2^Kbits) + K
assert M < N
C = pow(M, e, N)

print(f"N = {N}")
print(f"e = {e}")
print(f"C = {C}")
print(f"length_N = {length_N}")
print(f"Kbits = {Kbits}")

HINT = """

[+]-----------------------------------------------------------------------------------------------[+]
[+]                     Hint:                                                                     [+]
[+] - We constructed M as M = 2^length_N - 2^Kbits + K, where K encodes the flag.                 [+]
[+] - Your goal: Given N, e, C, and the knowledge of M's structure, recover K (and thus the flag).[+]
[+]-----------------------------------------------------------------------------------------------[+]

"""
print(HINT)
