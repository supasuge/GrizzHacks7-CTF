## Crypto

### Dad Crypto Jokes

- Easy/Medium/Hard
- Author: Evan Pardon [(GitHub: supasuge)](https://github.com/supasuge)
- Description:
- Flag Format: `GrizzCTF{...}`
- [ ] Tested on remote CTFd instance
- [x] Tested on testing server: [http://dad-joke-crypto.spotlessccrb.com:6969/](http://dad-joke-crypto.spotlessccrb.com:6969/)

```bash
python solver.py
=== Step 1: Retrieve PoW Challenge ===
[+] Solving PoW for challenge: e6253db4e3f1b874
[+] Found PoW solution: bkto2 (Hash: 000000fed1dc28f7d8aa812ba16d42f9d219e2122cfc5c85bfe03f08a32c4ac2) in 1.80s
=== Step 2: Submit PoW Solution ===
[+] PoW solved! Authenticated session obtained.
=== Step 3: Fetch Challenge Parameters and Ciphertext ===
[+] Retrieved parameters. n=308 digits
[+] Encrypted flag retrieved: c4b0711a19152806f70f4945f442a1e98bdcb65172c236c911959c96370c...
=== Step 4: Factorization and Key Recovery ===
[+] Flag recovered: GrizzCTF{dad_jokes_and_faulty_crypto!}
[+] All done!
```

### Vigenere Strikes back

- Easy/Medium/Hard
- Author:Evan Pardon [(GitHub: supasuge)](https://github.com/supasuge)
- Description:
- Flag Format:
- [ ] Tested on remote CTFd instance
- [ ] Tested on testing server: `nc vigenere.spotlessccrb.com 7474`
  
### Graham Cracked!

- Hard
- Author:Evan Pardon [(GitHub: supasuge)](https://github.com/supasuge)
- Description:
- Flag Format:
- [ ] Tested on remote CTFd instance
- [ ] Tested on testing server
  
### Stereotypical
- Medium
- Author:Evan Pardon [(GitHub: supasuge)](https://github.com/supasuge)
- Description:
- Flag Format:
- [ ] Tested on remote CTFd instance
- [ ] Tested on testing server

### Challenge 5
- Easy/Medium/Hard
- Author:
- Description:
- Flag Format:
- [ ] Tested on remote CTFd instance
- [ ] Tested on testing server

- [ ] Challenge 6
    - Easy/Medium/Hard
    - Author:
    - Description:
    - Flag Format:
    - [ ] Tested on remote CTFd instance
    - [ ] Tested on testing server

## Misc

### Challenge 1

- Easy/Medium/Hard
- Author:
- Description:
- Flag Format:
- [ ] Tested on remote CTFd instance
- [ ] Tested on testing server

```bash
# Proof here
```

---

### Challenge 2

- Easy/Medium/Hard
- Author:
- Description:
- Flag Format:
- [ ] Tested on remote CTFd instance
- [ ] Tested on testing server

```bash
# Proof here
```

---


### Endgame

- Medium
- Author: Evan Pardon ([GitHub](https://github.com/supasuge))
- Description: *TBD*
- Flag Format: `GrizzCTF{...}`
- [ ] Tested on remote CTFd instance
- [x] Tested on testing server: `nc endgame.spotlessccrb.com 7777`

```bash
Endgame/solution » python solve.py endgame.spotlessccrb.com
[+] Opening connection to endgame.spotlessccrb.com on port 7777: Done


------------------------------------------------------------------------
 ██████╗ ██████╗ ███████╗██████╗  █████╗ ████████╗██╗ ██████╗ ███╗   ██╗
██╔═══██╗██╔══██╗██╔════╝██╔══██╗██╔══██╗╚══██╔══╝██║██╔═══██╗████╗  ██║
██║   ██║██████╔╝█████╗  ██████╔╝███████║   ██║   ██║██║   ██║██╔██╗ ██║
██║   ██║██╔═══╝ ██╔══╝  ██╔══██╗██╔══██║   ██║   ██║██║   ██║██║╚██╗██║
╚██████╔╝██║     ███████╗██║  ██║██║  ██║   ██║   ██║╚██████╔╝██║ ╚████║
 ╚═════╝ ╚═╝     ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝   ╚═╝ ╚═════╝ ╚═╝  ╚═══╝

███████╗███╗   ██╗██████╗  ██████╗  █████╗ ███╗   ███╗███████╗
██╔════╝████╗  ██║██╔══██╗██╔════╝ ██╔══██╗████╗ ████║██╔════╝
█████╗  ██╔██╗ ██║██║  ██║██║  ███╗███████║██╔████╔██║█████╗
██╔══╝  ██║╚██╗██║██║  ██║██║   ██║██╔══██║██║╚██╔╝██║██╔══╝
███████╗██║ ╚████║██████╔╝╚██████╔╝██║  ██║██║ ╚═╝ ██║███████╗
╚══════╝╚═╝  ╚═══╝╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝╚══════╝
------------------------------------------------------------------------

[+]███████████████████████████████████████████████████████████████████████████████████████████████████████████████[+]
[+]                                                                                                               [+]
[+]                                        Operation Chevron Don - Top Secret                                     [+]
[+]                                                                                                               [+]
[+]---------------------------------------------------------------------------------------------------------------[+]
[+]                                                                                                               [+]
[+]     It is the year 2006, and you are an elite intelligence operative working with the FBI to track down an    [+]
[+] Advanced Persistent Threat (APT) individual who was previously believed to be operating abroad. Recent        [+]
[+] intelligence indicates that this individual is temporarily residing in the United States. This active APT     [+]
[+] member is a world renowned world-expert and is well-funded and clever, making him difficult to pin down.      [+]
[+] To locate him, a Stingray (IMSI Catcher) device has been deployed near his known residence in Miami. Over the [+]
[+] past three days, he has been on the move, carrying out clandestine cash pickups and dropoff at various        [+]
[+] inconsipicous locations across the country. Each time he makes a transaction, he activates his mobile device. [+]
[+] Fortunately for us, due to a fundamental design flaw in the device, even if the setting is turned off, it will[+]
[+] still ping the nearest base-station during it's boot sequence.                                                [+]
[+]                                                                                                               [+]
[+]---------------------------------------------------------------------------------------------------------------[+]
[+]                                   |*******CONFIDENTIAL*******|                                                [+]
[+]                                   |--------------------------|                                                [+]
[+] Your task is to solve five triangulation problems to pinpoint his exact locations based on these bearings.    [+]
[+]   - You will be provided the 2 nearest base stations, bearing angle, and the Stingray device location.        [+]
[+]   - Provide the exact (latitude, longitude) coordinates for each location to receive the flag.                [+]
[+]   - Don't F*ck this up.                                                                                       [+]
[+]---------------------------------------------------------------------------------------------------------------[+]
[+]                                                                                                               [+]
[+] Good luck, Operator!
                                                                                          [+]
[+]                                                                                                               [+]
[+]███████████████████████████████████████████████████████████████████████████████████████████████████████████████[+]

Problem 1:
Three base stations have detected a mobile device. Here are the base station details:
  StingrayMiami: Location = (25.733414, -80.241092), Bearing = 309.65°
  BaseStationPE: Location = (33.448380, -112.074040), Bearing = 325.85°
  BaseStationHO: Location = (29.760430, -95.369800), Bearing = 311.52°
These bearings are measured from North, increasing clockwise.
Find the (latitude, longitude) of the mobile device's location.
Format: lat,lon (e.g., 12.34,-56.78)

Enter your answer for Problem 1:
Sending Answer for Problem 1: 44.333852,-122.769416
Correct!
[SNIP]
.
..
...
[SNIP]
Enter your answer for Problem 5:
Sending Answer for Problem 5: 32.158461,-113.706
Correct!
[+] Receiving all data: Done (60B)
[*] Closed connection to endgame.spotlessccrb.com port 7777
Congratulations! Here is your flag: GrizzCTF{g0t_3m_c04ch}
```

---

### Challenge 4
- Easy/Medium/Hard
- Author:
- Description:
- Flag Format:
- [ ] Tested on remote CTFd instance
- [ ] Tested locally

---

```bash
# Proof here
```
---

### Challenge 5
- Easy/Medium/Hard
- Author:
- Description:
- Flag Format:
- [ ] Tested on remote CTFd instance
- [ ] Tested locally

```bash
# Proof here
```

---


### Challenge 6
- Easy/Medium/Hard
- Author:
- Description:
- Flag Format:
- [ ] Tested on remote CTFd instance
- [ ] Tested locally

```bash
# Proof here
```

---

## Rev
- [ ] Challenge 1
    - Easy/Medium/Hard
    - Author:
    - Description:
    - Flag Format:
    - [ ] Tested on remote CTFd instance
    - [ ] Tested locally

- [ ] Challenge 2
    - Easy/Medium/Hard
    - Author:
    - Description:
    - Flag Format:
    - [ ] Tested on remote CTFd instance
    - [ ] Tested locally
- [ ] Challenge 3
    - Easy/Medium/Hard
    - Author:
    - Description:
    - Flag Format:
    - [ ] Tested on remote CTFd instance
    - [ ] Tested locally

- [ ] Challenge 4
    - Easy/Medium/Hard
    - Author:
    - Description:
    - Flag Format:
    - [ ] Tested on remote CTFd instance
    - [ ] Tested locally

- [ ] Challenge 5
    - Easy/Medium/Hard
    - Author:
    - Description:
    - Flag Format:
    - [ ] Tested on remote CTFd instance
    - [ ] Tested locally

- [ ] Challenge 6
    - Easy/Medium/Hard
    - Author:
    - Description:
    - Flag Format:
    - [ ] Tested on remote CTFd instance
    - [ ] Tested locally

## Web
- [ ] Challenge 1
    - Easy/Medium/Hard
    - Author:
    - Description:
    - Flag Format:
    - [ ] Tested on remote CTFd instance
    - [ ] Tested locally
- [ ] Challenge 2
    - Easy/Medium/Hard
    - Author:
    - Description:
    - Flag Format:
    - [ ] Tested on remote CTFd instance
    - [ ] Tested locally
- [ ] Challenge 3
    - Easy/Medium/Hard
    - Author:
    - Description:
    - Flag Format:
    - [ ] Tested on remote CTFd instance
    - [ ] Tested locally
- [ ] Challenge 4
    - Easy/Medium/Hard
    - Author:
    - Description:
    - Flag Format:
    - [ ] Tested on remote CTFd instance
    - [ ] Tested locally
- [ ] Challenge 5
    - Easy/Medium/Hard
    - Author:
    - Description:
    - Flag Format:
    - [ ] Tested on remote CTFd instance
    - [ ] Tested locally
- [ ] Challenge 6
    - Easy/Medium/Hard
    - Author:
    - Description:
    - Flag Format:
    - [ ] Tested on remote CTFd instance
    - [ ] Tested locally

## OSIN
- [ ] Challenge 1
    - Easy/Medium/Hard
    - Author:
    - Description:
    - Flag Format:
    - [ ] Tested on remote CTFd instance
    - [ ] Tested locally
- [ ] Challenge 2
    - Easy/Medium/Hard
    - Author:
    - Description:
    - Flag Format:
    - [ ] Tested on remote CTFd instance
    - [ ] Tested locally
- [ ] Challenge 3
    - Easy/Medium/Hard
    - Author:
    - Description:
    - Flag Format:
    - [ ] Tested on remote CTFd instance
    - [ ] Tested locally
- [ ] Challenge 4
    - Easy/Medium/Hard
    - Author:
    - Description:
    - Flag Format:
    - [ ] Tested on remote CTFd instance
    - [ ] Tested locally
- [ ] Challenge 5
    - Easy/Medium/Hard
    - Author:
    - Description:
    - Flag Format:
    - [ ] Tested on remote CTFd instance
    - [ ] Tested locally
- [ ] Challenge 6
    - Easy/Medium/Hard
    - Author:
    - Description:
    - Flag Format:
    - [ ] Tested on remote CTFd instance
    - [ ] Tested locally

## Pwn
- [ ] Challenge 1
    - Easy/Medium/Hard
    - Author:
    - Description:
    - Flag Format:
    - [ ] Tested on remote CTFd instance
    - [ ] Tested locally
- [ ] Challenge 2
    - Easy/Medium/Hard
    - Author:
    - Description:
    - Flag Format:
    - [ ] Tested on remote CTFd instance
    - [ ] Tested locally
- [ ] Challenge 3
    - Easy/Medium/Hard
    - Author:
    - Description:
    - Flag Format:
    - [ ] Tested on remote CTFd instance
    - [ ] Tested locally
- [ ] Challenge 4
    - Easy/Medium/Hard
    - Author:
    - Description:
    - Flag Format:
    - [ ] Tested on remote CTFd instance
    - [ ] Tested locally
- [ ] Challenge 5
    - Easy/Medium/Hard
    - Author:
    - Description:
    - Flag Format:
    - [ ] Tested on remote CTFd instance
    - [ ] Tested locally
- [ ] Challenge 6
    - Easy/Medium/Hard
    - Author:
    - Description:
    - Flag Format:
    - [ ] Tested on remote CTFd instance
    - [ ] Tested locally
