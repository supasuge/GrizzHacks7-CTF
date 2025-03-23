#!/usr/bin/python3

import sys

def print_banner():
    banner = """
    ╔══════════════════════════════════════════════════════════╗
    ║                     Breaking Point 2                     ║
    ║  Being stuck in this Python jail must make you feel      ║
    ║  so confined! Find the breaking point and get the flag!  ║
    ╚══════════════════════════════════════════════════════════╝
    """
    print(banner)

def print_footer():
    footer = """
    ╔══════════════════════════════════════════════════════════╗
    ║                   Game Over!                             ║
    ╚══════════════════════════════════════════════════════════╝
    """
    print(footer)

def main():
    blacklist = [
    '__attr__', '__import__', 'help', 'compile', 'execfile', '*', '&', '^', 
    'pty', 'popen', 'dir', 'locals', 'delattr', 'setattr', 'getattr', 
    '__builtins__', 'write', 'print', 'eval', 'exec', 'import', 'open', 'os', 'read', '"', 
    'write', 'subprocess', 'flag.txt', 'flag','object', 'type', 'class', 'mro',
    'subclasses', 'super', 'io', 'importlib', 'ast', 'pickle', 'marshal', 'sys', 'inspect',
    'ctypes', 'socket', 'tempfile', 'mktemp', 'mkstemp', 'shutil', 'pathlib', 'bash', 'sh', 'cat',
    'ls', 'pwd', 'curl', 'wget', 'base64', 'globals', '__builtins__', 'subprocess', 'mro',
    'globals', 'shutil', 'print', 'open', 'read', 'write', 'exec', 'compile'
    ]

    for submodule in sys.modules:
        if submodule.startswith('sys.'):
            del sys.modules[submodule]
            
    print_banner()
    print("Source Code:")
    print(open(__file__, 'r', encoding='utf-8').read())
    total_commands = 0
    max_commands = 5
    print(f"\nYou have {max_commands} moves to escape. Can you get the flag?")
    allowed_chars = set('chr()+ 0123456789')
    while total_commands < max_commands:
        print(f"\n[{total_commands + 1}/{max_commands}] attempts used")
        try:
            inp = input('<<[cmd]>> ')
        except EOFError:
            print("\nConnection closed...")
            sys.exit(0)
        total_commands += 1
        
        if any(bad in inp for bad in blacklist):
            print("Nice Try! That command is not allowed.")
            continue
        
        if not all(c in allowed_chars for c in inp):
            print("Invalid characters detected!")
            continue
        
        try:
            code = eval(inp)
            exec(code)
        except Exception as e:
            print(f"Error: {e}")
            
    print_footer()

if __name__ == '__main__':
    main()