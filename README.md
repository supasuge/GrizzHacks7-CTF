# GrizzCTF 2025

- Made by CyberOU, a Cybersecurity club @Oakland University
  - Challenges contributed from [supasuge](https://github.com/supasuge) | [Evan Pardon](https://linkedin.com/in/evan-pardon) 
- This repository contains various categories of Capture The Flag (CTF) challenges. Each category has multiple challenges with varying levels of difficulty.

---

## Categories
- Pwn
- Crypto
- Web
- Forensics
- Misc
- OSINT

---

## Directory Structure

Example:

```
-- {challenge_category}/{challenge_name}/
 |   |- README.md # Challenge name, Description, flag format, author, build instructions, run instrcutions using `docker`, and the file(s) to be distributed to participants.
 |   |- /dist/* # This contains the files to be release to challenge contestants
 |   |- /solution/solve.py  # Solution script/steps taken to solve if no code is required
 |   |- /solution/README.md  # Solution writeup/explaination.
      - /build # This directory should contain all the necessary file's to build/run your challenge and/or release files/archives.
```

### Healthcheck

To make sure the challenges are working as expected, simply run the `healthcheck.py` script. This script contains the solution for all remote challenges.

Expected output:

```bash
❯ python healthcheck.py
[/.......] Opening connection to 167.99.228.17 on port 8001: Trying[+] Opening connection to 167.99.228.17 on port 8001: Done
[+] Receiving all data: Done (3.63KB)
[*] Closed connection to 167.99.228.17 port 8001
[◐] Opening connection to 167.99.228.17 on port 8002: Trying 167.99[+] Opening connection to 167.99.228.17 on port 8002: Done
[+] Receiving all data: Done (755B)
[*] Closed connection to 167.99.228.17 port 8002
[┤] Opening connection to 167.99.228.17 on port 8003: Trying 167.99[+] Opening connection to 167.99.228.17 on port 8003: Done
[+] Receiving all data: Done (60B)
[*] Closed connection to 167.99.228.17 port 8003
[.] Opening connection to 167.99.228.17 on port 9001: Trying 167.99[+] Opening connection to 167.99.228.17 on port 9001: Done
[+] Receiving all data: Done (66B)
[*] Closed connection to 167.99.228.17 port 9001
[.] Opening connection to 167.99.228.17 on port 9002: Trying 167.99[+] Opening connection to 167.99.228.17 on port 9002: Done
[+] Receiving all data: Done (204B)
[*] Closed connection to 167.99.228.17 port 9002
[.] Opening connection to 167.99.228.17 on port 9004: Trying 167.99[+] Opening connection to 167.99.228.17 on port 9004: Done
[*] '/home/supasuge/Projects/CTF_Official_2025/GrizzHacks7-CTF/chal'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    Stripped:   No
[+] Receiving all data: Done (34B)
[*] Closed connection to 167.99.228.17 port 9004
[▖] Opening connection to 167.99.228.17 on port 8845: Trying 167.99[+] Opening connection to 167.99.228.17 on port 8845: Done
[+] Receiving all data: Done (395B)
[*] Closed connection to 167.99.228.17 port 8845
Attempt #1: Connecting to 0.cloud.chals.io:15366
[+] Opening connection to 0.cloud.chals.io on port 15366: Done
[+] Receiving all data: Done (1.05KB)
[*] Closed connection to 0.cloud.chals.io port 15366
Starting Vigenère cipher analysis...

Text length: 675 characters

Performing Kasiski examination...
Testing key lengths: [6, 8, 10, 12, 13, 14, 16, 18, 20, 22, 24, 25, 26, 28, 30]

New best result found:
Key length: 16
Key: DRHBIRBSQFALURWO
Score: 283.6350

New best result found:
Key length: 14
Key: BIBHZFFFYSWJIQ
Score: 272.3607

New best result found:
Key length: 20
Key: YSLHALGNURLGGRCXZHBP
Score: 167.9142

New best result found:
Key length: 25
Key: OFHSPHGIBPYGSDWUHZBQLCFQA
Score: 26.7226
Flag found: GRIZZCTFVIGENERESTFIKESAGAINFLAG

Analysis complete! Time taken: 0.20s
Decrypted candidate: DEARESHFRIENDIHOPETHISMISSIVEFIBDSYOUINGOODHEALTHGOODBEEFANDHIGHSPIRITSTHEDAYSHAVSGROWNLONGANDTHENIGHTSEVEBLONGERASWETOILUNDERTHEWAHCHFULEYESOFOURSUPERIORSTVEWORKISARDUOUSTEDIOUSANDPORINGBUTWEFINDSOLACEINTHSALMIGHTYQUACKLORDTHEFIELRSARERIPEWITHTHEFRUITSOFOIRLABORANDSOONWESHALLREAPHHEREWARDSTHEHARVESTFESTIJALISUPONUSANDTHEVILLAGEIGABUZZWITHPREPARATIONSTHEOIRISFILLEDWITHTHESCENTOFTRESHLYBAKEDBREADANDTHESOINDOFLAUGHTERECHOESTHROUGVTHESTREETSFORNOWPLEASETAYETHISFLAGASATOKENOFYOURHORDWORKGRIZZCTFVIGENERESTFIKESAGAINFLAGILONGFORTHERAYSWHENWECANSITBYTHEFIREONDSHARESTORIESOFOURADVENHURESUNTILTHENIREMAINEVERMOURFAITHFULTOTHEALMIGHTYEUACKLORDYOURSTRULYAFELLOKVIGENEREENTHUSIAST
(Web, mally) Flag (mally, Misc): GrizzCTF{mAlLysReStura0nt}
(Web, xxehhh) Flag (XXehhh, Web): GrizzCTF{XXehhh_pwn3d_n01c3_j0b_g00d_3n0ugh}
(Web, pin-in-the-bin) Flag (pin-in-the-bin, Web): GrizzCTF{br0k3n_2FA_n0_2FA}
(Web, DevSec? No thanks! 1 & 2) User flag: GrizzCTF{us3r_pwn3d_n01c3_j0b_w4tch_0ut_4_pyth0ns}, Root flag:GrizzCTF{DevSec_Inf0S3c_00ps13_pwn3d_n01c3}
(Misc, bp1) Flag (bp1, Misc): GrizzCTF{R34ch3d_br34k1n6_p01nt1}
(Misc, bp2) Flag (bp2, Misc): GrizzCTF{j41l_3x2c4p3d_4g41n_n01c3!}
(Misc, endgame) Flag (endgame, Misc): GrizzCTF{g0t_3m_c04ch}
(Pwn, pwngs) Flag (pwngs, Misc): GrizzCTF{s1mpl3_0v3rf10w_3h}
(Pwn, not_juan) Flag (not_juan, Misc): GrizzCTF{n0t_ju4n_0v3rwr1tt3n_succ3s}
(Pwn, fmterr1) GrizzCTF{s1mpl3_fmt_2tr_3xp101t}
(Misc, quack) Flag (quack, Misc): GrizzCTF{m3rs3nn3_tw12t3r_n0t_so_s4f3}
(Crypto, dad_joke_crypto) Flag (dad_joke_crypto, Web): GrizzCTF{dad_jokes_and_faulty_crypto!}
(Crypto, vigenere) GRIZZCTFVIGENERESTFIKESAGAINFLAG
```
