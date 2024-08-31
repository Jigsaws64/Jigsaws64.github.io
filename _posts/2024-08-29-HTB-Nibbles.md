---
title: "Hack the Box (HTB) - Nibbles"
description: "Weak Password & Poor Sudo Permission"
date: 2024-08-29 12:00:00 -100
image: /assets/images/HTB - Nibbles/Nibbles Thumbnail.jpg
categories: [CTF]
tags: [nibbleblog, cms, weak password, metasploit]    # TAG names should always be lowercase
---

## Enumeration

Let's run [AutoRecon](https://github.com/Tib3rius/AutoRecon) against our box at `10.10.10.75`

```bash
sudo autorecon 10.10.10.75
```

Looking at the results, we see the following services:

- 22/tcp SSH OpenSSH 7.2p2 Ubuntu 4ubuntu2.2
- 80/tcp HTTP Apache httpd 2.4.18

Let's examine the Apache server

![Hello World](/assets/images/HTB%20-%20Nibbles/Hello%20World.png)

Not much here at initial glance, let's check the source HTML

![HTML](/assets/images/HTB%20-%20Nibbles/NibbleBlog.png)

We see `nibbleblog` mentioned in this comment. Let's attempt to navigate to that directory

![Nibble Blog page](/assets/images/HTB%20-%20Nibbles/Nibble%20Blog%20page.png)

On the bottom right we can observe `powered by nibbleblog`. [Nibbleblog](https://github.com/dignajar/nibbleblog) is a open source CMS

Wappalyzer indicates that the server is using php on the backend. Let's check for standard login pages such as  `/login.php` & `/admin.php`

![adminlogin](/assets/images/HTB%20-%20Nibbles/admin%20php.png)

There's an admin login page, but this doesn't help us much as we lack credentials. Let's run a ferox buster scan against the main blog page

![content](/assets/images/HTB%20-%20Nibbles/Content.png)

Looks like there's a `/content` directory. Let's check it out

![Content Directory](/assets/images/HTB%20-%20Nibbles/Content%20Directory.png)

There's some eternally exposed directories, which definitely not good, (but excellent for us). Let's dig into /private

![Admin User](/assets/images/HTB%20-%20Nibbles/admin%20user.png)

Looking inside the /private directory leads us to a users.xml file. This file contains the login user for ID 0 (aka the admin) which so happens to be admin. Let's head back over to the login admin panel and try a few different passwords

![Logged in](/assets/images/HTB%20-%20Nibbles/Logged%20in.png)

Here we were able to login using the username `admin` that we obtained earlier and the password `nibbles`. This password was somewhat predictable, given its presence in the blog title. This approach to login is a bit contrived but is common in CTFs

Scrolling to the bottom, we see some more information

![Version](/assets/images/HTB%20-%20Nibbles/Version.png)

Let's do a google search for the version `4.0.3`

![Nibbleblog search](/assets/images/HTB%20-%20Nibbles/Nibbleblog%20Search.png)

Aha, there's an authenticated file upload  ([CVE-2015-6987](https://nvd.nist.gov/vuln/detail/CVE-2015-6967)). Let's take a look

Examining the exploit in exploit DB, it appears to be a ruby script designed for MSF that lets authenticated users upload a malicious PHP file which grants RCE by accessing it via a direct request to the file in `content/private/plugins/my_image/image.php`

Looking at the gui real quick for the application, this is the culprit

![image plugin](/assets/images/HTB%20-%20Nibbles/myiamge_plugin.png)

## Without Metasploit

Since we have GUI access, we can simply crate a php reverse shell script and upload here. This is essentially all the metasploit exploit is doing

```bash
nano pwned.php
```

![Script](/assets/images/HTB%20-%20Nibbles/bash%20script.png)

Upload the script

![image.php](/assets/images/HTB%20-%20Nibbles/image.php.png)

Our script doesn't execute right away, but navigating back to the web directory in our browser we can see that our image was renamed to `image.php`. Proceeding to click on it gives us a shell

![NO MS Shell](/assets/images/HTB%20-%20Nibbles/No%20MS%20Shell.png)


## With Metasploit

Let's fire up MSF and perform this exploit

```bash
msfdb run
```

Search for "nibbleblog"

![MSF Nibbleblog](/assets/images/HTB%20-%20Nibbles/MSF%20Nibbleblog%20Exploit.png)

Set the options for the exploit, hit run

![User](/assets/images/HTB%20-%20Nibbles/User.png)

Let's upgrade our shell and run a sudo -l

![sudo -l](/assets/images/HTB%20-%20Nibbles/Nibbles%20sudo%20-l.png)

We're able to run this `monitor.sh` file as root with nopasswd. This is 100% the attack vector on an easy rated box. Let's proceed to check out this shell script

![monitor.sh](/assets/images/HTB%20-%20Nibbles/Monitor.sh.png)

This script is writable by us, and with the ability to run it as sudo we can simply edit it to spawn a root shell

![monitor.sh Edited](/assets/images/HTB%20-%20Nibbles/Monitor.sh%20Edited.png)

![root](/assets/images/HTB%20-%20Nibbles/Nibbles%20root.png)

GG, we've rooted Nibbles!

## Vulnerabilities & Mitigation's

| Vulnerability                      | Mitigation |
|------------------------------------|------------|
| Authenticated File Upload (CVE-2015-6967) | Restrict file uploads to safe file types and validate input. |
| Weak Admin Password                | Use strong, complex passwords. |
| Poor Sudo Permissions for `monitor.sh` | Restrict `sudo` permissions and avoid `NOPASSWD` configurations. |

### Remediation References

- [NIST SP 800-63B, Section 5.1.1.2 - Memorized Secret](https://pages.nist.gov/800-63-3/sp800-63b.html)
- [OWASP File Upload Vulnerabilities](https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload)
- [Linux Sudoers Manual](https://linux.die.net/man/5/sudoers)







