# Operation Endgame
- **author:** Evan Pardon
- **category:** **Misc**
- **difficulty:** **Hard**

**Port Needed:** $7777$

## Description:

```bash
 ++++++++++++++++++++++++++++++++++++++++++++++++++[CONFIDENTIAL]+++++++++++++++++++++++++++++++++++++++++++++++++++
[+]     It is the year 2006, and you are an elite intelligence operative working with the FBI to track down an    [+]
[+] Advanced Persistent Threat (APT) individual who was previously believed to be operating abroad. Recent        [+]
[+] intelligence indicates that this individual is temporarily residing in the United States. This active APT     [+]
[+] member is a world renowned security-expert with years of experience abroad backed my significant resources.    [+]
[+] To locate him, a Stingray (IMSI Catcher) device has been deployed near his known residence in Miami. Over the [+]
[+] past three days, he has been on the move, carrying out clandestine cash pickups and dropoff at various         [+]
[+] inconsipicous locations across the country. Each time he makes a transaction, he activates his mobile device. [+]
[+] Fortunately for us, due to a fundamental design flaw in the device, even if the setting is turned off, it will  [+]
[+] still ping the nearest base-station during boot sequence.                                                     [+]
[+]                                                                                                               [+]
[+]---------------------------------------------------------------------------------------------------------------[+]
[+]                                   |*******CONFIDENTIAL*******|                                                [+]
[+]                                   |--------------------------|                                                [+]
[+] Your task is to solve five triangulation problems to pinpoint his exact locations based on these bearings.     [+]
[+]   - You will be provided the 2 nearest base stations, bearing angle, and the Stingray device location.        [+]
[+]   - Provide the exact (latitude, longitude) coordinates for each location to receive the flag.                 [+]
```

## Flag format:
`GrizzCTF{...}`


## Build instructions

```bash
~/ [$] cd Endgame/build
~/Endgame/build [$] docker build -t endgame .
```


## Running the challenge container:

```bash
~/Endgame/build [$] docker run -d -it -p 7777:7777 endgame
```
