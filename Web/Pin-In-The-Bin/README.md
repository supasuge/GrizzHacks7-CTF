# Challenge 2
- **author:** [name]
- **category:** {Crypto, Pwn, Web, Forensics, Misc, OSINT}
- **difficulty:** {Easy, Medium, Hard, Expert}

## Description

Super secure authentication system v1, now supports password resets!


## Flag format

```text
GrizzCTF{...}
```

## Build instructions (if any):

```bash
cd Pin-in-the-bin/build
docker build -t pin-in-bin .
```

## Running the challenge container

```bash
docker run -d -it -p 5000:5000 pin-in-bin
```
- Port needed: $5000$

###### Solution


[solve.py](solution/solve.py)

**Output**

```bash
python3 solve.py
[*] Starting exploit against http://localhost:5000
[+] PoW challenge: 5646209db4df6df2 | CSRF: ImNiNjc2MDY1NzJjMTdiMzhiNjVjZTU3OTUzMjBhMmZiYjI3YWY0NjEi.Z2ilMw.6TnFzExdLo3_pjhMGT9DN8yC-s8
[+] PoW solved in 2036720 attempts (2.68s)
[+]     Solution = r8ee94ak
[+]     Hash = 00000014c864167cf839a4d2605d7d7d2f1a1478b269df19765dd647ca945b59
[+] Server accepted our PoW solution.
[*] Attempting forgot-password for admin@secureauth.com...
[-] Could not extract CSRF token from /forgot-password.
[*] Brute-forcing PINs 1000–2499...
[*] Brute-forcing PINs 2500–4999...
[*] Brute-forcing PINs 5000–7499...
[*] Brute-forcing PINs 7500–9999...
[-] Tried PINs 3400–3419...
[+] Found valid PIN = 1911
[+]     Attempts       = 920
[+]     Time           = 10.27 s
[+]     Flag           = GrizzCTF{br0k3n_2FA_n0_2FA}
[+] Challenge completed successfully!
[+] PIN  : 1911
[+] FLAG : GrizzCTF{br0k3n_2FA_n0_2FA}
```
