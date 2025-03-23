# bbDuckLCG

- **Author:** Evan Pardon | ([GitHub](https://github.com/supasuge))
- **Category:** Crypto
- **Difficulty:** Medium

## Description:

Recover the two unknown parameters from this LCG, then predict the next state to get the correct key to decrypt the flag.

## Flag format:

`GrizzCTF{...}`

## Build instructions (if any):

**None** static challenge

## Running the challenge container:

**None** static challenge

## Distributable files:

- `bb-duck-lcg.tar.xz`
  - `output.txt`
  - `chal.py`
  - `flag.txt`: Redacted flag for local testing

### Solution

[`solve.py`](solution/solve.py) - Recovers the unknown multiplier and constant from the LCG, then predicts the next state to get the key to decrypt the flag.
