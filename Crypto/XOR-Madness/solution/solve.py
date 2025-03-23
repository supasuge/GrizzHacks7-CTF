#!/usr/bin/env python3
import argparse
import sys
from pwn import xor

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

def test():
    runs = [
        {
            "k1"            : "a44ac580f535e87f3e6decaa328db774ee1573c271a99b4c22cdcdacea",
            "k1_xor_k2"     : "51a1d218f0870fc871f860ee581815aa01dbd63192318280b3880c34aa",
            "k2_xor_k3"     : "fc17d1df9821edda43f422fb343a13c3a58f6f9f17c844f90bd9f724b5",
            "k3_xor_k4"     : "44ae454c5fb2b22aa23e307f7e9c2de6d37aa3ad2bec0238a39839dc6d",
            "ciphertext"    : "527dfe2ed576e9a4a89e60e354ed083e8dd641eecbecb0ca4f76419fba"
        },
        {
            "k1"            : "2ff8da74d9628cd036ab57efd39ec4f0778cd1c947c7ec9993b2038433",
            "k1_xor_k2"     : "4eedab884d9724faf0bd6fd94d8f825cd0cb74e1beb4060e2e9edb7aa7",
            "k2_xor_k3"     : "2c2d6dd2e1190063e6069ebe82fe8c5db516a01bf4155fea226cd686e1",
            "k3_xor_k4"     : "0fd3a4cf2b8be461e815a0228cfc1727d56170ab3a768fa28bcb0e1fa5",
            "ciphertext"    : "064c663d1c5f94dd63f0ff89b31aa5095add3038f6f3b9defa33a1127f"
        },
        {
            "k1"            : "bd20d28aa2b325479a67b923cca2b8c52f303c8ebceb7474d75e385dfa",
            "k1_xor_k2"     : "54266d933b7132d46ddc2e3dd5b9a1156e15922e4596beeb9d074a36a5",
            "k2_xor_k3"     : "9aad2eb4ea92cd510c256aabfe98061da8a6939f1441e27bfc17c9e962",
            "k3_xor_k4"     : "aa37263f5a128dfe00723416e0f8bd17ed6b105005cdd8c5d1f35336b7",
            "ciphertext"    : "b96322d61b20eb6c16f62a5947282c70dc09b60c326a565c13926d776f"
        },
        {
            "k1"            : "5be48c7d4218308c035ad0432fb99371e40c8ae7edfb5fda339deae093",
            "k1_xor_k2"     : "5eb0e4c791197748ba18a20ecd79b3c84390bdaaeb85738114fc524676",
            "k2_xor_k3"     : "b7e9fa3a605d45a20710b8fc5f64d80737fd619b0df84c3af831ee4fb9",
            "k3_xor_k4"     : "43349f0377f7a0460043c665deedd3c1c7daabf9dda64baa3235b224bb",
            "ciphertext"    : "5af612be9cad8348c103541961fd507bdb3d22214412085979af9415b0",
        },
    ]

    for i, data in enumerate(runs):
        recovered = solve_chal(
            data["k1"],
            data["k1_xor_k2"],
            data["k2_xor_k3"],
            data["k3_xor_k4"],
            data["ciphertext"]
        )
        try:
            recovered_text = recovered.decode("utf-8")
            print(f"[Run {i}] Recovered plaintext: {recovered_text}")
        except UnicodeDecodeError:
            print(f"[Run {i}] Recovered plaintext (hex): {recovered.hex()}")

def main():
    parser = argparse.ArgumentParser(
        description="XOR Madness Solver",
        epilog="Example usage: python3 solve.py --solve 5be48c7d42... 5eb0e4c7... b7e9fa3a... 43349f03... 5af612be..."
    )
    parser.add_argument("--test", action="store_true", help="Run test cases")
    parser.add_argument("--solve", action="store_true", help="Solve the challenge")
    
    
    parser.add_argument("k1", nargs="?", help="K1 (hex-encoded)")
    parser.add_argument("k1_xor_k2", nargs="?", help="(K1 ⊕ K2) (hex-encoded)")
    parser.add_argument("k2_xor_k3", nargs="?", help="(K2 ⊕ K3) (hex-encoded)")
    parser.add_argument("k3_xor_k4", nargs="?", help="(K3 ⊕ K4) (hex-encoded)")
    parser.add_argument("ciphertext", nargs="?", help="Ciphertext (hex-encoded)")

    args = parser.parse_args()

    if args.test:
        # Run test cases
        test()
        sys.exit(0)

    if args.solve:
        # Make sure all required positional args are provided
        required_args = [args.k1, args.k1_xor_k2, args.k2_xor_k3, args.k3_xor_k4, args.ciphertext]
        if any(a is None for a in required_args):
            parser.error("When using --solve, you must provide k1, k1_xor_k2, k2_xor_k3, k3_xor_k4, and ciphertext.")
        
        # Solve the challenge
        plaintext = solve_chal(
            args.k1,
            args.k1_xor_k2,
            args.k2_xor_k3,
            args.k3_xor_k4,
            args.ciphertext
        )
        # Attempt to decode as UTF-8; if not possible, print hex
        try:
            print("Recovered Plaintext:", plaintext.decode('utf-8'))
        except UnicodeDecodeError:
            print("Recovered Plaintext (hex):", plaintext.hex())
        sys.exit(0)

    # If neither --test nor --solve is used, print usage
    parser.print_help()

if __name__ == "__main__":
    main()
