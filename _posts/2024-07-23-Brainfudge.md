--- 
title: "Hack the Box (HTB) - Brainf*#k"
description: "Exploiting Shellshock"
date: 2024-07-20 12:00:00 -100
image: /assets/images/HTB - Brainfuck/HTB BrainF#K.jpg
categories: [CTF]
tags: [shellshock,web application]    # TAG names should always be lowercase
---

## Enumeration

Let's start by running a [AutoRecon](https://github.com/Tib3rius/AutoRecon) against our box at `10.10.10.17`

We see the following TCP ports open:

- 22 - SSH, (Ubuntu 4ubuntu2.1)
- 25 SMTP
- POP3
- IMAP
- 443 - HTTPS (nginx 1.10.0 (Ubuntu))

Since we're too familiar with exploiting mail protocols yet, let's start by checking the nginx web server on port 443

![Default web page](/assets/images/HTB%20-%20Brainfuck/nginx%20default%20web%20page.png)

The default web page for nginx, let's check our feroxbuster scan

![Inital Ferox Buster](/assets/images/HTB%20-%20Brainfuck/inital%20durbuster.png))

Nothing useful, the source code reveals nothing useful either

Normally these boxxes operate on HTTP. Since we're dealing with HTTPS we can inpect the SSL/TLS certification to reveal additional information on the 

![Email](/assets/images/HTB%20-%20Brainfuck/Email.png)

We see an email `orestis@brainfuck.htb`, this will most likely be utilized somewhere on this machine, especially with all the mail services

![Secret Domain Name](/assets/images/HTB%20-%20Brainfuck/Secret%20domain%20revealed.png)

Looks like we've two domains here, `sup3rs3cr3t.brainfuck.htb` and `www.brainfuck.htb`

Since these domains are not acessible via public DNS we will need to add them to our `/etc/hosts` file for local DNS

```bash
nano /etc/hosts
```

![etchost](/assets/images/HTB%20-%20Brainfuck/etchosts.png)

Let's start by navigating to `https://brainfuck.htb/` 

![Wordpress](/assets/images/HTB%20-%20Brainfuck/Wordpress%20site.png)

The first thing we see is **Just another WordPress site**. Since this is a WordPress site, we can use [wpscan](https://wpscan.com/), which is a vulnerability scanner for WordPress websites

```bash
# This will enumerate users, passwords, and themes (u,p,t)
wpscan --url https://www.brainfuck.htb --enumerate u,p,t --disable-tls-checks --ignore-main-redirect --verbose
```

We had to **--disble-tls-checks** since the SSL certificate is self signed

Looking at the wpscan results, we see some potential important information

![Outdated Plugin](/assets/images/HTB%20-%20Brainfuck/Outdated%20Plugin.png)

This `wp-support-plus-responsive-ticket-sytem` plugin is outdated (version 7.1.3). Outdated plugins are common attack vectors in WordPress

Let's check searchsploit for this plugin

```bash
searchsploit wp support
```

![searchsploit results](/assets/images/HTB%20-%20Brainfuck/Serachsploit%20wp.png)

Multiple exploits exist for this version. Let's grab the SQLi one since the privilege escalation one probably needs us to have credentials first

Looking at the script we see the following

![Script](/assets/images/HTB%20-%20Brainfuck/SQLi.png)

Reading this, it appears that the `cat_id` is not escaped, which we could easily use to retrieve the admins user name & password hash

In theory, our vulnerable code might look like this

```php
$cat_id = $_POST['cat_id'];
$query = "SELECT * FROM wp_terms WHERE term_id = $cat_id";
```

`$cat_id` here is taken directly from user input. This is obviously vulnerable to union select injections (which we will use)

The proper version of this code should use prepared statements or escape user input to prevent this

```php
$stmt = $pdo->prepare('SELECT * FROM wp_terms WHERE term_id = :cat_id');
$stmt->execute(['cat_id' => $_POST['cat_id']]);
```

Here the user input is treated as a parameter, and not as SQL code




Navigating to `https://sup3rs3cr3t.brainfuck.htb/` we see the following

![Secret Domain Revealed](/assets/images/HTB%20-%20Brainfuck/Secret%20domain%20revealed.png)

Before we investigate potential attack vectors, let's run a feroxbuster scan against this domain. Let's scan for anything that doesn't return a 404, and search recursively

```bash
feroxbuster -u https://sup3rs3cr3t.brainfuck.htb/ -w /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt -t 50 --force-recursion --filter-size 404 --insecure
```

Since this SSL certificate is self signed, we have to add the `--insecure` flag on our scan, otherwise it will reject the connection

While that's running, let's further enumerate

It looks like we have the ability to sign up / login & more. Let's fire up burp and see what we can find





## Summary

1. Initial Enumeration  discovered a web server
2. Directory Busting  found /cgi-bin/user.sh
3. Nmap Scanning  confirmed vulnerability to Shellshock
4. Curl HTTP Request verified Shellshock exploit
5. Reverse Shell established a connection back to your machine
6. Ran sudo -l to discover sudo rights for usr/bin/perl without a password
7. Used perl to execute /bin/sh as root

## Vulnerabilities & Mitigation

| Vulnerability     | Mitigation            |
|-------------------|-----------------------|
| Shellshock (CVE-2014-6271) in CGI scripts  | Update Bash to the latest version. Ensure scripts properly sanitize input.|
| Sudo privilege escalation NOPASSWD | Restrict sudo permissions and require passwords for all commands

### Remediation References

- [Mitre.org - Update Bash to the latest version](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-6271).
- [Restrict sudo permissions and require passwords for all commands](https://www.sudo.ws/security.html).