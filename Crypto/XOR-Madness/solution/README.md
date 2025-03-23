# Xor Madness
- **Author**: [supasuge](https://github.com/supasuge)
- **Description**: XOR is just a concept, trust me bro.


## Solution

```bash
./solve.py --solve ca3212184af232b94354810c488b6cae1db021649a82006dbf203928f3 26e0bb36c7c266cdc83bb77d51f3001a977eae875c58c9b8e24a6260ae b94a52e2f498e74d08f5cc729870a8ee5be14fe55723abd09cf0e30c68 bf86e55fefb64b8749ecf3e6b11f6bd057c7ecb0ba7985602249570100 de1437135237790cfa8f74e992855bb89fce764594107caa9f654116d3
Recovered Plaintext: GrizzCTF{X0rri0r_w4rr10r_ftw}
```

Function to solve the challenge + explaination:

```python
def solve_chal(k1_hex, k1_xor_k2_hex, k2_xor_k3_hex, k3_xor_k4_hex, ciphertext_hex):
    """
    Given the hex-encoded K1, (K1 ⊕ K2), (K2 ⊕ K3), (K3 ⊕ K4), and Ciphertext,
    recover the plaintext.
    """
    K1 = bytes.fromhex(k1_hex)
    k1_xor_k2 = bytes.fromhex(k1_xor_k2_hex)
    k2_xor_k3 = bytes.fromhex(k2_xor_k3_hex)
    k3_xor_k4 = bytes.fromhex(k3_xor_k4_hex)
    ciphertext = bytes.fromhex(ciphertext_hex)

    # Derive K2, K3, K4:
    #   K2 = K1 ⊕ (K1 ⊕ K2)
    #   K3 = K2 ⊕ (K2 ⊕ K3)
    #   K4 = K3 ⊕ (K3 ⊕ K4)
    K2 = xor(K1, k1_xor_k2)
    K3 = xor(K2, k2_xor_k3)
    K4 = xor(K3, k3_xor_k4)

    # Compute the plaintext by XORing ciphertext with K1, K2, K3, K4
    plaintext = xor(ciphertext, K1, K2, K3, K4)
    return plaintext
```

### Explanation

**XOR Basics and Properties**:

- Commutative: $a \oplus b = b \oplus a$
  - This implies we can swap operands when XOR'ing without affecting the result.

- Associative: $(a \oplus b) \oplus c = a \oplus (b \oplus c)$
  - Allows us to reorder the XOR operations without changing the result.

- Identity: $a \oplus 0 = a$

- Self-Inverse: for any $x$ we have: $x \oplus x = 0$
    - and crucially: $a \oplus x = b \implies a = b \oplus x$

- Distributive: $a \oplus (b \oplus c) = (a \oplus b) \oplus (a \oplus c)$


#### Reconstructing K2, K3, K4

Given $K_1$ (known random key) and $(K_1 \oplus K_2)$ (known XOR of $K_1$ and $K_2$), we can derive $K_2$ as follows:

$$
K_2 = K_1 \oplus (K_1 \oplus K_2)
$$

Why does this work? If we let:

$$ 
K_1 \oplus K_2 = A
$$

then

$$
K_2 = K_1 \oplus A
$$

We do the same logic repeatedly to recover the original flag:

1. Recover $K_2$

$$
K_2 = K_1 \oplus (K_1 \oplus K_2)
$$

2. Recover $K_3$
$$
K_3 = K_2 \oplus (K_2 \oplus K_3)
$$

3. Recover $K_4$
$$
K_4 = K_3 \oplus (K_3 \oplus K_4)
$$

Each subsequent key is a simple XOR of the previously recovered key and the given XOR difference.
