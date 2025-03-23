#!/usr/bin/python3
import sys
cmd = sys.argv[1]
out = []
for i in range(len(cmd)):
    out.append(f"chr({ord(cmd[i])}) + ")

print("".join(out).rstrip(" + "))




