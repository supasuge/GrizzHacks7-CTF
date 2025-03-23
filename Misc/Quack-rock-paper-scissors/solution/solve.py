import randcrack
from pwn import *
import sys

if len(sys.argv) > 1:
    p = remote(sys.argv[1], sys.argv[2])
else:
    p = process("./chall.py")

cracker = randcrack.RandCrack()

p.recvuntil(b"Select an option:")
p.sendline(b"2")
p.recvuntil(b"Here are your quacks (624 32-bit integers):")
p.recvline()
quacks =  p.recvline().decode().split('[')[1].split(']')[0]
quacks = [int(q) for q in quacks.split(',')]
print(quacks)

for i in range(len(quacks)):
    cracker.submit(quacks[i])


choices = ["quackrock", "quackpaper", "quackscissors"]
winning_choices = {
    "quackrock": "quackpaper",
    "quackpaper": "quackscissors",
    "quackscissors": "quackrock"
}

correct_choices = [winning_choices[choices[cracker.predict_randint(0, 2)]] for _ in range(10)]


p.sendline(b"1")
for i in range(len(correct_choices)):
    p.recvuntil(b"Choose (quackrock, quackpaper, quackscissors):")
    p.sendline(correct_choices[i].encode())

p.recvline()
print(p.recvline().decode().strip())
print(p.recvline().decode().strip())