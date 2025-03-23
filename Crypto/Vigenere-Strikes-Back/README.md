# Vigenere Strikes Back
- **Author:** Evan Pardon
- **Category:** Crypto
- **Difficulty:** Medium

## Description:

The flag is all uppercase letters, starts with GRIZZCTF, and '{}' has been removed from the flag. This is a re-make of the original Vigenere challenge I made for the GrizzHacks 6 CTF in 2024. Key difference here is the key used for encryption is much larger and random each time the particpant connects to the remote service. 

**Ports:** 7474

## Build instructions (if any):

```bash
docker build -t vigenere-challenge .
```

OR using Docker Compose:

```bash
docker compose build
docker compose up --build -d # Builds container and runs it in detached mode
```

## Running the challenge container:

```bash
docker run -p 7474:7474 vigenere-challenge
```

OR using Docker Compose:

```bash
docker compose up --build -d # -d for detached mode
```

## Flag Format

```txt
GRIZZCTF...
```

### Files to be distributed to challenge participant

- `build/chal.py`
- Connection details
