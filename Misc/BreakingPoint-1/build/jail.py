#!/usr/bin/python3
#-*- coding:utf-8 -*-

blacklist = [
    '__attr__', '__import__', 'help', 'compile', 'execfile', '*', '&', '^', 
    'pty', 'popen', 'dir', 'locals', 'delattr', 'setattr', 'getattr', 
    '__builtins__', 'write', 'print', 'eval', 'exec', 'import', 'open', 'os', 'read', '"', 
    'write', 'subprocess', 'flag.txt', 'flag','object', 'type', 'class', 'mro',
    'subclasses', 'super', 'io', 'importlib', 'ast', 'pickle', 'marshal', 'sys', 'inspect',
    'ctypes', 'socket', 'tempfile', 'mktemp', 'mkstemp', 'shutil', 'pathlib', 'bash', 'sh', 'cat',
    'ls', 'pwd', 'curl', 'wget', 'base64', 'globals', '[', ']', '{', '}', 'numpy', 'cmd'
]

def print_banner():
    banner = """
    ╔══════════════════════════════════════════════════════════╗
    ║  Breaking Point 1 - Can you escape in just two moves?    ║
    ║  Being stuck in this python jail must make you feel      ║
    ║  so confined! Find the breaking point and get the flag!    ║
    ╚══════════════════════════════════════════════════════════╝
    """
    print(banner)

def print_footer():
    footer = """
    ╔══════════════════════════════════════════════════════════╗
    ║                       Game over!                         ║
    ╚══════════════════════════════════════════════════════════╝
    \n"""
    print(footer)

def main():
    global blacklist
    print_banner()
    print("Source Code\n")
    print(open(__file__).read())    
    total_commands = 0
    max_commands = 2
    
    while total_commands < max_commands:
        print(f"\n[{total_commands + 1}/{max_commands}] attempts used")
        inp = input('<<[cmd]>> ')
        
        total_commands += 1
        
        if not any(bad in inp for bad in blacklist):
            try:
                exec(inp)
            except Exception as e:
                print(f"Error: {e}")
        else:
            print("Nice Try!")
            
    print_footer()

if __name__ == '__main__':
    main()
