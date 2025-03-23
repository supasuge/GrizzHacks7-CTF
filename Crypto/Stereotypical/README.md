# Stereotypical

- **Author:** Evan Pardon [GitHub](https://github.com/supasuge)
- **Category:** Crypto
- **Difficulty:** Easy

## Description:

RSA... I know, pretty **stereotypical** huh? Well just find the missing bits and small root's and this challenge is yours! Good luck!

## Flag format:

`GrizzCTF{...}`

## Build instructions 

None, static challenge.

**Files:**

The main file to distribute is `dist/stereotypical.tax.xz`. This tarball contains the files list below + `flag.example` (to use for local testing).

- `chal.py`: Challenge source code used to generate the output.txt file.
- `output.txt`: Contains the necessary paramaters for the challenge ($n$, $e$, $c$; the Public modulus, public exponent, and ciphertext respectively).



## Dist

- `dist/stereotypical.tax.xz`: Contains a tarball of `chal.py`, `output.txt`, and `flag.example` (to use for testing).
  
This is the file to upload to CTFd and distribute to participants.

You can find the *actual* flag in `dist/flag.txt`.

#### Solution

[Solve Script](./solution/solve.sage) - Contains the SageMath script used to solve the challenge.

- Main functionality of the script is from the sage module `lbc_toolkit`. Which contains many different functions and wrapper's for [lattice based cryptanalysis](https://github.com/josephsurin/lattice-based-cryptanalysis).



