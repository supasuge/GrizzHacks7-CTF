#!/usr/bin/python3
import string
import secrets
import sys

def main():
    rand = secrets.SystemRandom()
    message = open("message.txt", "r").read().strip()
    uppers = string.ascii_uppercase
    n = rand.randint(6, 30)
    key = ''.join(rand.choices(uppers, k=n))
    encrypt = lambda pt, key: ''.join([uppers[(uppers.index(char.upper()) + uppers.index(key[j % len(key)]))%26] if char.isupper() else uppers[(uppers.index(char.upper()) + uppers.index(key[j % len(key)]))%26].lower() if char.isalpha() else char for char, j in [(pt[i], len([x for x in pt[:i] if x.isalpha()])) for i in range(len(pt))]])
    ct = encrypt(message, key)
    hint = "The flag is all uppercase letters, starts with GRIZZCTF, and '{}' has been removed from the flag."
    print(f"------------------------------------------------Vigenere Strikes Back------------------------------------------------\n\n", flush=True)
    print(ct, flush=True)
    print(f"\n\nHint: {hint}", flush=True)
    sys.stdout.flush()
    sys.exit(0)

if __name__ == "__main__":
    main()
    
