from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from Crypto.Hash import SHA3_256
from pwn import *


class LCG:
    def __init__(self, seed, m, a, c):
        
        self._state = seed
        self.m = m
        self.a = a
        self.c = c
        
    def next(self):
       
        self._state = (self.a * self._state + self.c) % self.m
        return self._state
def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)

def modinv(b, n):
    
  
    g, x, _ = egcd(b, n)
    if g != 1:
        return None
    return x % n


def crack_a_c_known_m(states, modulus):
    n = len(states)
    if n < 3:
        return None, None, None
    for i in range(n-1):
        for j in range(i+1, n-1):
            s_i   = states[i]
            s_i1  = states[i+1]
            s_j   = states[j]
            s_j1  = states[j+1]
            diff_i = (s_i1 - s_i) % modulus
            diff_j = (s_j1 - s_j) % modulus
            if diff_i == 0 or diff_j == 0:
                continue
            inv_s_i = modinv(s_i, modulus)
            inv_s_j = modinv(s_j, modulus)
            if inv_s_i is None or inv_s_j is None:
                continue
            possible_a = []
            inv_diff_i = modinv(diff_i, modulus)
            if inv_diff_i is not None:
                a1 = (diff_j * inv_diff_i) % modulus
                possible_a.append(a1)
            if i + 1 < j:  
                mid_diff = (s_j - s_i1) % modulus
                inv_mid = modinv(mid_diff, modulus)
                if inv_mid is not None:
                    a2 = (diff_j * inv_mid) % modulus
                    possible_a.append(a2)

            
            for a in set(possible_a):  # Remove duplicates
            
                c = (s_i1 - a * s_i) % modulus

            
                inv_a = modinv(a, modulus)
                if inv_a is None:
                    continue
                    
                pre_seed = ((s_i - c) * inv_a) % modulus

            
                test_lcg = LCG(pre_seed, modulus, a, c)
                valid = True
                
                for state in states:
                    if test_lcg.next() != state:
                        valid = False
                        break
                        
                if valid:
                    return modulus, a, c

    return None, None, None


def solve_challenge(states):
    m = 672257317069504227
    IV= "fd7bc164f152fd35c641db160edb166a"
    Ciphertext = "b1e9c5b405459e0dc31db0c96f152a90f27b3afa5d6d13e42043bdac2b5b5e8f4d782c5f74823bd00d65f4a18a99927b"

    
    cracked_m, a, c = crack_a_c_known_m(states, m)
    if None in (cracked_m, a, c):
        print("[!] Could not crack a,c.")
        return None
    print(f"[+] cracked_m= {cracked_m} a= {a} c= {c}")

    
    inv_a = modinv(a, m)
    if inv_a is None:
        print("[!] gcd(a,m)!=1, can't proceed.")
        return None
    pre_seed = ((states[0] - c) % m) * inv_a % m

    print(f"[+] pre_seed= {pre_seed}")
    solver_lcg = LCG(pre_seed, m, a, c)
    

    for _ in range(len(states)):
        solver_lcg.next()
    key_state = solver_lcg.next()
    print(f"[+] Derived key_state= {key_state}")
    m=672257317069504227
    
    key = SHA3_256.new(str(key_state).encode()).digest()
    iv = bytes.fromhex(IV)
    ciphertext = bytes.fromhex(Ciphertext)

    try:
        cipher = AES.new(key, AES.MODE_CBC, iv)
        plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
        return plaintext
    except Exception as e:
        print(f"[!] Decryption failed: {e}")
        return None
    
def main():
    States = [176605986966266107, 437730346450152792, 263647228976173700, 663553061960501818, 538864627927490529, 553238633738772809]
    print(solve_challenge(States))

if __name__ == "__main__":
    main()
