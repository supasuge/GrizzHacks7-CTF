# Vigenère Cipher Auto-Solver: A Comprehensive CTF Write-Up

## Introduction

The Vigenère cipher is a classical encryption method that utilizes a repeating key to encode text, making it resistant to simple frequency analysis. This write-up demonstrates how our Python-based auto-solver cracks the Vigenère cipher, even with unknown key lengths, leveraging techniques like the Index of Coincidence (IoC), Kasiski examination, and frequency analysis. We'll explore how each step contributes to solving the cipher, culminating in the extraction of the flag.

---

To test the solver, run `python3 solve.py out.txt` in which `out.txt` contains the ciphertext to be solved wrapper in """{}""" to use as a delimiter because I'm lazy.

The error correction is not perfect, it can use some work... but it's close enough all things considered.

## Step-by-Step Walkthrough

### Step 1: Preprocessing the Ciphertext

We start by parsing and cleaning the ciphertext using the `CiphertextParser` class. This ensures that only the relevant text is processed. Here's what happens:

- **Parsing:** The file is read line-by-line to identify blocks of ciphertext, ignoring empty lines and extra quotes.
- **Cleaning:** Removes non-alphabetic characters, preserving the original format for later use.

### Step 2: Initial Cryptanalysis

#### 2.1 Index of Coincidence (IoC)

The IoC helps us estimate the key length. It is defined as:

where:

- $f_i$ is the frequency of each letter.
- $N$ is the total number of letters.

A higher IoC indicates more alignment with English text. This analysis is run across multiple possible key lengths, and the results guide our search.

#### 2.2 Kasiski Examination

The Kasiski method identifies repeating sequences in the ciphertext and calculates the distances between them. These distances are factored to suggest potential key lengths. For example:

- **Sequence:** "XYZ"
- **Distances:** 12, 24, 36 (factors are 12, 6, 4, 3, etc.)

We prioritize key lengths with the most common factors.

---

### Step 3: Frequency Analysis

Once the key length is hypothesized, the ciphertext is divided into "cosets" based on the key length. Each coset corresponds to a Caesar cipher, which is solved using chi-squared analysis:

where:

- $O_i$ is the observed frequency.
- $E_i$ is the expected frequency based on English.

The character shift yielding the lowest $chi^2$ is selected as part of the key.

---

### Step 4: Decryption

Using the derived key, the ciphertext is decrypted. Each character is shifted back by the key's corresponding value:

where:

- $P_i$ is the plaintext character.
- $C_i$ is the ciphertext character.
- $K_i$ is the key character.

---

## Step 5: Error Correction

The for the last step in the processing of the ciphertext, for the highest scored plaintext (most likely full english) it will go through and attempt to fix bigram's according to the diction's defined and other common mistakes I was getting during testing. It's not much but it gets the job done that's all that matters.

---

### Flag Extraction

The solver uses regular expressions to extract the flag from the processed text. For example:

```python
pattern = re.compile(r'GRIZZCTF.*FLAG')
```

If a match is found, it is displayed as the flag.

---

## Output Example

Here is what the final output looks like:

```
Processing Ciphertext 144/148
--------------------------------------------------------------------------------
Starting Vigenère cipher analysis...

Text length: 667 characters

Performing Kasiski examination...
Testing key lengths: [6, 8, 9, 10, 11, 12, 14, 15, 16, 18, 20, 22, 24, 26, 28, 30]

New best result found:
Key length: 12
Key: JNIGRZZRFGCU
Score: 336.4273

New best result found:
Key length: 18
Key: CZQVCQZNCFRCIRVGIW
Score: 262.1787

New best result found:
Key length: 15
Key: CJPJGFVYCGGYALV
Score: 211.8389

New best result found:
Key length: 24
Key: OIUKRJYUQNWLJNVTZZTLFHLU
Score: 150.6974

New best result found:
Key length: 30
Key: CLPKRBORCNGOANVONCYGFVINGYQGEX
Score: 134.3655

New best result found:
Key length: 11
Key: CMICUNNAFKG
Score: 26.0409
Flag found: GRIZZCTFVIGENERESTRIKESAGAINFLAG

Analysis complete! Time taken: 0.09s

Results for Ciphertext 144:
Key Length: 11
Key: CMICUNNAFKG

Flag Found: GRIZZCTFVIGENERESTRIKESAGAINFLAG

Decrypted Text:
51/144
DEAREST FRIEND,

I HOPE THIS MISSIVE FINDS YOU IN GOOD HEALTH, GOOD BEER, AND HIGH SPIRITS. THE DAYS HAVE GROWN LONG AND THE NIGHTS EVEN LONGER AS WE TOIL UNDER THE WATCHFUL EYES OF OUR SUPERIORS. THE WORK IS ARDUOUS, TEDIOUS, AND BORING, BUT WE FIND SOLACE IN THE ALMIGHTY PAPER.

THE FIELDS ARE RIPE WITH THE FRUITS OF OUR LABOR, AND SOON WE SHALL REAP THE REWARDS. THE HARVEST FESTIVAL IS UPON US, AND THE VILLAGE IS ABUZZ WITH PREPARATIONS. THE AIR IS FILLED WITH THE SCENT OF FRESHLY BAKED BREAD AND THE SOUND OF LAUGHTER ECHOES THROUGH THE STREETS.


FOR NOW PLEASE TAKE THIS FLAG AS A TOKEN OF YOUR HARD WORK: GRIZZCTFVIGENERESTRIKESAGAINFLAG

I LONG FOR THE DAYS WHEN WE CAN SIT BY THE FIRE AND SHARE STORIES OF OUR ADVENTURES. UNTIL THEN, I REMAIN EVER YOUR FAITHFUL TO THE ALMIGHTY PAPER.

YOURS TRULY,
A FELLOW VIGENERE ENTHUSIAST
```

---
