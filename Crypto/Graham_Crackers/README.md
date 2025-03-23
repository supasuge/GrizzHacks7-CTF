# Graham Crackers 🍘

- **Author:** Evan Pardon - ([supasuge](https://github.com/supasuge))
- **Category:** Crypto
- **Difficulty:** Hard
- **Points:** 500

## Description

After years of research into perfectly square crackers, the Graham Crackers Corporation R&D team accidentally stumbled upon a groundbreaking discovery: their manufacturing process was somehow flawed, and was encoding secret messages into the dimensions of their crackers! The issue?! Their quality control systems uses RSA to verify the authenticity of each cracker's dimensions. Recently, the quality control system has seem to have gone a bit stale...

A whistleblower from the Cryptographic Snack Division has provided us with some import data that may help to solve this mystery once and for all. Can you help us recover the secret message?

## Challenge Files

- `chal.sage`: This is the Sage script with the source code to generate the challenge.
- `out.txt`: This is the output of the Sage script when run -> (`N`, `e`, `C`, `length_N`, `Kbits`). Contains the ciphertext of the flag, the public key, and the bit length of the modulus as well as the bit length of the secret message.
- `flag.example`: This is an example of the flag and is given to the players for local testing.

## Build

Nothing, static challenge.

## Run

Nothing, static challenge.

## Dist

**Files to Distribute to the players:**
- `graham-crackers-crypto.tar.xz`: This contains the challenge files: `chal.sage`, `out.txt`, and `flag.example` (To show flag format and to test the script locally to generate the challenge).

## Flag Format
```txt
GrizzCTF{<secret_message>}
```

## Solution

You can find the SageMath solution script right here in the directory [`solution/solve.sage`](../solution/solve.sage).

#### Hint

```
"Life is full of lattices, just like a graham cracker. Sometimes you just need to find the right angle to break them and dunk em' in milk!"
  - Nicholas Howgrave-Graham (probably never said this, but it's a good quote c'mon now)
```

This challenge is based off of the Howgrave-Graham version of Coppersmith's Attack.

