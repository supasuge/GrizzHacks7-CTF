#!/usr/bin/python3
from typing import List
FLAG = open('flag.txt').read().strip()
assert FLAG is not None, "Flag is empty..."

def fmt() -> List[int]:
    global FLAG
    out = []
    try:
        for i in range(len(FLAG)):
            out.append(ord(FLAG[i]))
        return out
    except Exception as e:
        print(f"Error: {e}")
    
new = fmt()
open("output.txt", "w").write(str(new))





