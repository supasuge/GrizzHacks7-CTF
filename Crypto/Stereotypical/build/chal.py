#!/usr/bin/python3
from Crypto.Util.number import *
from Crypto.Random import *
import re
flag = open("flag.txt", "rb").read().strip()
fmt_flag = re.sub(rb'\{(.*?)\}', lambda m: b'{' + b'*' * len(m.group(1)) + b'}', flag)
message = b"Hello, This is another typical RSA challenge! I'm giving you this plaintext message for safe keeping. Here is the flag: "
p,q = getPrime(2048), getPrime(2048)
n = p*q
e = 3
c = pow(bytes_to_long(message+flag), e, n)
out = f"n = {n}\ne = {e}\nc = {c}\r\n\n{message.decode()+fmt_flag.decode()}"
open("output.txt", "w").write(out)
