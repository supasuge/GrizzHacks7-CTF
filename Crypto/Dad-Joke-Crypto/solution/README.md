# Writeup for Dad Joke Cryptosystem Challenge

## Overview

This challenge presents a whimsical cryptosystem wrapped in dad jokes and a playful Proof-of-Work (PoW) gate. While humor abounds, the underlying cryptography setup is non-trivial and requires careful factorization and key derivation to recover the encrypted flag. The challenge is reminiscent of classical RSA-style factorization attacks and Diffie-Hellman-like manipulations, albeit wrapped in a more contrived setup.

To break it down, we have:

1. A **Proof-of-Work (PoW)** challenge to gain authenticated access.
2. A **"Dad Joke Cryptosystem"** that returns certain "v" values (`vka`, `vkakb`, `vkb`) derived from prime factors `p` and `q`.
3. An encrypted flag that uses a derived key from these parameters.
4. The ultimate goal: **Decrypt the given ciphertext** and obtain the flag.

This problem cleverly distracts you with humor while essentially presenting a factoring and key recovery exercise.

---

## High-Level Steps

1. **Solving the Proof-of-Work (PoW)**:
   The server challenges you to find a string `x` such that `sha256(challenge + x)` starts with 6 zeros. This is straightforward brute force: iterate over candidate suffixes until one produces the desired hash prefix. This step ensures you understand how to automate simple hashing puzzles. After solving the PoW, you gain an authenticated session.

2. **Retrieving Challenge Parameters**:
   Once authenticated, you query the `/challenge` endpoint with an `Accept: application/json` header. The server responds with:
   - `alice`: Contains `n`, `vka`, and `vkakb`
   - `bob`: Contains `vkb`
   - `ciphertext`: The AES-CBC encrypted flag.
   
   Here, `n = p*q` is a 1024-bit composite number (since `p` and `q` are 512-bit primes). The values `vka`, `vkakb`, and `vkb` are multiplicative combinations of `p`, `q`, and the secret keys `k_A`, `k_B`, and `r`.

3. **Core Cryptanalysis**:
   The interesting part: `v`, `vka`, `vkakb`, and `vkb` appear to be products involving `p`, `q`, and ephemeral secrets. By design, at least one of these values shares enough factors that you can compute a GCD with `n` to retrieve `p`. Specifically:
   - `p` divides `vka`, `vkakb`, or `vkb`.
   - Extracting `p` from a GCD with `n` is straightforward: `p = GCD(n, vka)`, or if that fails, `p = GCD(n, vkakb)`, etc.
   Once you have `p`, you get `q = n / p`.

   With `p` and `q` known, you can start unraveling the algebraic relationships:
   - `v` is defined as `(p*r) mod n`, but once factoring `n` gives you both `p` and `q`, you can "lift" the operations into the reduced residue system modulo `q`.
   - From `vka`, `vkakb`, `vkb`, and knowledge of `p` and `q`, you determine the secret keys `k_A`, `k_B`, and `r`.

   The provided `solver.py` script does the math:
   - Factor `n` by GCD checks.
   - Compute `k_A`, `k_B`, and `r` by modular inversion and division.
   - Finally, compute `v = p*r` and derive the AES key from `sha256(long_to_bytes(v))`.

4. **Decrypting the Flag**:
   With the recovered AES key:
   - Extract the IV from the first AES block in `ciphertext`.
   - Use AES-CBC decryption to retrieve the plaintext.
   - Unpad and reveal the flag: `GrizzCTF{dad_jokes_and_faulty_crypto!}`.
