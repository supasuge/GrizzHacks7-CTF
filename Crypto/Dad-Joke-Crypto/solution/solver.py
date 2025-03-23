#!/usr/bin/env python3
import requests
from bs4 import BeautifulSoup
from Crypto.Cipher import AES
from Crypto.Util.number import long_to_bytes, inverse, GCD
from Crypto.Util.Padding import unpad
from hashlib import sha256
import string
import itertools
import time
from dataclasses import dataclass

@dataclass
class COLORS:
    HEADER: str = '\033[95m'
    OKBLUE: str = '\033[94m'
    OKCYAN: str = '\033[96m'
    OKGREEN: str = '\033[92m'
    WARNING: str = '\033[93m'
    FAIL: str = '\033[91m'
    ENDC: str = '\033[0m'
    BOLD: str = '\033[1m'
    UNDERLINE: str = '\033[4m'

def solve_pow(challenge: str, difficulty: int = 6) -> str:
    target: str = '0' * difficulty
    print(f"{COLORS.OKBLUE}[+] Solving PoW for challenge: {challenge}{COLORS.ENDC}")
    charset: str = string.ascii_lowercase + string.digits
    start_time: float = time.time()
    for length in range(1, 10):
        for candidate in itertools.product(charset, repeat=length):
            x: str = ''.join(candidate)
            h: str = sha256((challenge + x).encode()).hexdigest()
            if h.startswith(target):
                total_time: float = time.time() - start_time
                print(f"{COLORS.OKGREEN}[+] Found PoW solution: {x} (Hash: {h}) in {total_time:.2f}s{COLORS.ENDC}")
                return x
    print(f"{COLORS.FAIL}[-] No PoW solution found! This should not happen.{COLORS.ENDC}")
    return ""

def main():
    base_url = "http://localhost:5000"
    s = requests.Session()
    
    resp = s.get(f"{base_url}/")
    soup = BeautifulSoup(resp.text, "html.parser")
    csrf_token = None
    csrf_input = soup.find('input', {'name': 'csrf_token'})
    if csrf_input:
        csrf_token = csrf_input.get('value')
        print(f"{COLORS.OKBLUE}[+] Found CSRF token: {csrf_token}{COLORS.ENDC}")
    

    print(f"{COLORS.HEADER}=== Step 1: Retrieve PoW Challenge ==={COLORS.ENDC}")
    pow_url = f"{base_url}/pow"
    resp = s.get(pow_url)
    resp.raise_for_status()
    soup = BeautifulSoup(resp.text, "html.parser")


    pow_csrf_token = None
    csrf_input = soup.find('input', {'name': 'csrf_token'})
    if csrf_input:
        pow_csrf_token = csrf_input.get('value')

    challenge = None
    code_element = soup.select_one("div.code-highlight code")
    if code_element:
        line = code_element.get_text().strip()
        start_idx = line.find('sha256("') + len('sha256("')
        end_idx = line.find('"+x')
        if start_idx != -1 and end_idx != -1:
            challenge = line[start_idx:end_idx]

    if not challenge:
        print(f"{COLORS.FAIL}[-] Could not find the PoW challenge in /pow page.{COLORS.ENDC}")
        return

    x = solve_pow(challenge)
    if not x:
        print(f"{COLORS.FAIL}[-] PoW solution could not be found, aborting.{COLORS.ENDC}")
        return

    
    print(f"{COLORS.HEADER}=== Step 2: Submit PoW Solution ==={COLORS.ENDC}")
    data = {
        "solution": x
    }
    if pow_csrf_token:
        data["csrf_token"] = pow_csrf_token
    
    resp = s.post(pow_url, data=data)
    resp.raise_for_status()
    
    if "Incorrect proof-of-work solution" in resp.text:
        print(f"{COLORS.FAIL}[-] PoW solution was not accepted{COLORS.ENDC}")
        return
    print(f"{COLORS.OKGREEN}[+] PoW solved! Authenticated session obtained.{COLORS.ENDC}")

    
    print(f"{COLORS.HEADER}=== Step 3: Fetch Challenge Parameters and Ciphertext ==={COLORS.ENDC}")
    challenge_url = f"{base_url}/challenge"
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json"
    }
    resp = s.get(challenge_url, headers=headers)
    resp.raise_for_status()
    
    try:
        data = resp.json()
    except requests.exceptions.JSONDecodeError as e:
        print(f"{COLORS.FAIL}[-] JSON decode error. Response content: {resp.text[:200]}{COLORS.ENDC}")
        return

    n_str = data["alice"]["n"]
    vka_str = data["alice"]["vka"]
    vkakb_str = data["alice"]["vkakb"]
    vkb_str = data["bob"]["vkb"]
    c_hex = data["ciphertext"]  # ciphertext from the same response

    n = int(n_str)
    vka = int(vka_str)
    vkakb = int(vkakb_str)
    vkb = int(vkb_str)

    print(f"{COLORS.OKBLUE}[+] Retrieved parameters. n={len(n_str)} digits{COLORS.ENDC}")
    print(f"{COLORS.OKBLUE}[+] Encrypted flag retrieved: {c_hex[:60]}...{COLORS.ENDC}")

    # Step 4: Factorization and Key Recovery
    print(f"{COLORS.HEADER}=== Step 4: Factorization and Key Recovery ==={COLORS.ENDC}")
    # Attempt to find p from gcd with vka, vkakb, vkb
    p = GCD(n, vka)
    if p == 1:
        p = GCD(n, vkakb)
    if p == 1:
        p = GCD(n, vkb)
    if p == 1:
        print(f"{COLORS.FAIL}[-] Could not factor n from given parameters.{COLORS.ENDC}")
        return
    q = n // p

    # Derive the keys as per the algebra from the code
    vka_prime = vka // p
    vkakb_prime = vkakb // p
    vkb_prime = vkb // p

    modulus = q

    inv_vka_prime = inverse(vka_prime, modulus)
    k_B = (vkakb_prime * inv_vka_prime) % modulus

    inv_vkb_prime = inverse(vkb_prime, modulus)
    k_A = (vkakb_prime * inv_vkb_prime) % modulus

    inv_k_A = inverse(k_A, modulus)
    r = (vka_prime * inv_k_A) % modulus

    # Compute v = p * r
    v = p * r

    key = sha256(long_to_bytes(v)).digest()

    # Decrypt the flag
    c_bytes: bytes = bytes.fromhex(c_hex)
    iv_bytes: bytes = c_bytes[:AES.block_size]
    ciphertext_bytes: bytes = c_bytes[AES.block_size:]

    cipher = AES.new(key, AES.MODE_CBC, iv=iv_bytes)
    decrypted = cipher.decrypt(ciphertext_bytes)

    try:
        flag = unpad(decrypted, 16)
        print(f"{COLORS.OKGREEN}[+] Flag recovered: {flag.decode()}{COLORS.ENDC}")
    except ValueError:
        print(f"{COLORS.WARNING}[!] Padding incorrect - either key or ciphertext mismatch.{COLORS.ENDC}")
        print(f"{COLORS.WARNING}[!] The server may have regenerated parameters. Try again quickly.{COLORS.ENDC}")

    print(f"{COLORS.OKCYAN}[+] All done!{COLORS.ENDC}")

if __name__ == "__main__":
    main()
