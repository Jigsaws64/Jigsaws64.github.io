--- 
title: "Hack the Box (HTB) - Brainf*#k"
description: "Exploiting a WordPress plugin, breaching an SMTP server, and decrypting an RSA private key"
date: 2024-07-23 12:00:00 -100
image: /assets/images/HTB - Brainfuck/HTB BrainF.png
categories: [CTF]
tags: [wordpress, RSA encryption, Vigenère cipher,SMTP,IMAP]    # TAG names should always be lowercase
---

## Enumeration

Let's start by running a [AutoRecon](https://github.com/Tib3rius/AutoRecon) scan against our target at `10.10.10.17`

We see the following TCP ports open:

- 22 - SSH, (Ubuntu 4ubuntu2.1)
- 25 - SMTP
- 110 - POP3
- 143 - IMAP
- 443 - HTTPS (nginx 1.10.0 (Ubuntu))

Let's start by checking the nginx web server on port 443

![Default web page](/assets/images/HTB%20-%20Brainfuck/nginx%20default%20web%20page.png)
*The default web page for nginx*

Let's check our feroxbuster scan

![Inital Ferox Buster](/assets/images/HTB%20-%20Brainfuck/inital%20durbuster.png)

No useful directories were found

Normally these boxes operate on HTTP. Since we're dealing with HTTPS we can inspect the SSL/TLS certification to reveal additional information on the domain

![Email](/assets/images/HTB%20-%20Brainfuck/Email.png)

We see an email `orestis@brainfuck.htb`. This will most likely be utilized somewhere on this machine, especially with all the mail services listed

![Secret Domain Name](/assets/images/HTB%20-%20Brainfuck/Secret%20domain%20revealed.png)

We see two domains listed here, `sup3rs3cr3t.brainfuck.htb` and `www.brainfuck.htb`

Since these domains are not accessible via public DNS we will need to add them to our `/etc/hosts` file for local DNS

```bash
nano /etc/hosts
```

![etchost](/assets/images/HTB%20-%20Brainfuck/etchosts.png)

Now that that's done. Let's navigate to `https://brainfuck.htb/`

![Wordpress](/assets/images/HTB%20-%20Brainfuck/Wordpress%20site.png)

The first thing we see is "**Just another WordPress site**". Since this is a WordPress site, we can use [wpscan](https://wpscan.com/), which is a vulnerability scanner for WordPress websites

```bash
# This will enumerate users, passwords, and themes (u,p,t)
wpscan --url https://www.brainfuck.htb --enumerate u,p,t --disable-tls-checks --ignore-main-redirect --verbose
```

We had to **--disble-tls-checks** since the SSL certificate is self signed

Looking at the wpscan results, we see some potential important information

![Outdated Plugin](/assets/images/HTB%20-%20Brainfuck/Outdated%20Plugin.png)

This `wp-support-plus-responsive-ticket-sytem` plugin is outdated (version 7.1.3). Outdated plugins are common attack vectors in WordPress

Let's check searchsploit for this vulnerable plugin

```bash
searchsploit wp support
```

![searchsploit results](/assets/images/HTB%20-%20Brainfuck/Serachsploit%20wp.png)

Two exploits exist for this version. Let's grab the privilege escalation one first

Looking at the script we see the following

![Exploit](/assets/images/HTB%20-%20Brainfuck/Wordpress%20Exploit.png)

The exploit allows unauthorized login to any account without needing a password due to a logic flaw.

The script sends a post request to `admin-ajax.php` with the value of username being the compromised user & the value of email being the compromised email

The vulnerable code might look something like this

```php
 if ($user) {
        wp_set_auth_cookie($user->ID, true);
        wp_redirect(admin_url());
        exit;
```

This directly sets the authentication cookie for the user ID by the username, without verifying authentication

The proper code would be as follows

```php
  if ($user && wp_check_password($password, $user->user_pass, $user->ID)) {
        wp_set_auth_cookie($user->ID, true);
        wp_redirect(admin_url());
        exit;
```

Anyway, let's edit the request to include the following information we've obtained earlier:

- URL = `https://brainfuck.htb/wp-admin/admin-ajax.php`
- name = `admin` (obained from WP scan)
- email = `orestis@brainfuck.htb` (from earlier)

I'll also copy & paste this exploit into a file.html so we can actually execute it in our browser

Now host a local http server with python so we can run the script in our browser

```bash
python3 -m http.server 9001
```

Navigating to our local host on port 9001 we see our web server being hosted with our script

![Exploit Page](/assets/images/HTB%20-%20Brainfuck/Hire%20Me.png)

Clicking on script, we can enter our login information

![Our Script](/assets/images/HTB%20-%20Brainfuck/Our%20Script.png)

Clicking on `Login` will make the following post request as we discussed earlier

![Exploit Request](/assets/images/HTB%20-%20Brainfuck/Exploit%20Request.png)

Now we can navigate to the home directory for this WP site and we'll be logged in as Admin!

Looking around the site, we notice settings that lead to `Easy WP SMTP`

![SMTP](/assets/images/HTB%20-%20Brainfuck/SMTP%20stared%20out.png)

Let's check the source code for this page

![SMTP Password](/assets/images/HTB%20-%20Brainfuck/SMTP%20password.png)

And boom, the SMTP password is `kHGuERB29DNiNE`. We can now authenticate as **orestis** with **orestis@brainfuck.htb**

Let's use the [Thunderbird](https://www.thunderbird.net/en-US/) email client here. We'll login to the orestis mail server and take a look around

![Thunderbird](/assets/images/HTB%20-%20Brainfuck/Thunderbird%20input.png)

After getting errors trying to login, I changed the username field above from the orestis@brainfuck.htb to just orestis and was able to proceed

![New Pass](/assets/images/HTB%20-%20Brainfuck/New%20Password.png)

Reading this message from our dear friend Root, we see they sent us the credentials to the secret fourm

- Username - orestis
- Passowrd - kIEnnfEKJ#9UmdO

Let's head over to the secret forum and login

Navigating to the site, we see talk of SSH login

![SSH](/assets/images/HTB%20-%20Brainfuck/Talk%20of%20SSH.png)

It looks like orestis might have an encrypted chat with the SSH key. Let's find that chat

![Encrypted Key](/assets/images/HTB%20-%20Brainfuck/Encrypted%20Key.png)

This appears to be a simple substitution cipher at first glance.

Noticing the `Orestis - Hacking for fun and profit` signature in the unencrypted chat

- Uncrypted signature: `"Orestis - Hacking for fun and profit"`
- Encrypted signature: `"Pieagnm - Jkoijeg nbw zwx mle grwsnn"`

Using the [Cipher Identifier (Boxentriq)](https://www.boxentriq.com/code-breaking/cipher-identifier). I was able to ascertain the cipher method as [Vigenère](https://en.wikipedia.org/wiki/Vigen%C3%A8re_cipher) cipher

![Vigenère Cipher](/assets/images/HTB%20-%20Brainfuck/Cipher%20found.png)

The main takeaway form this cipher method is that we need a key in order to crack it. Since we know some plaintext that corresponds to the ciphered (Orestis's signature) we can create a script to decode the key

Understanding how this cipher works is important. We can create a python script to spit out the key for us

![Script](/assets/images/HTB%20-%20Brainfuck/Script%20decoder.png)

This isn't my script but in layman's terms the for loop determines the password by comparing both characters in the index from the plain & encrypted phrases. The weakness in this method is obviously that if you know plain text, you can decode the key. This was one of the methods used to crack the enigma machine codes in WW2

Anyway, Let's run the script

![Key Discoverd](/assets/images/HTB%20-%20Brainfuck/Key%20Discoverd.png)

As we can see, the key is `FUCKMYBRAIN`

Using our extremely elegant key name, let's head over to Cyberchef and decode the link to the SSH key

![Cyber Chef cecode chat](/assets/images/HTB%20-%20Brainfuck/Cyber%20Chef%20Decoded.png)

We have a clickable link: `https://brainfuck.htb/8ba5aa10e915218697d1c658cdee0bb8/orestis/id_rsa`

The problem is the SSH key requires a pass code, which is unknown to us. Reading the next message, Orestis writes "No problem, I'll brute force it :)" which leads me to believe it's a simple password

Let's ssh2john to convert the private SSH key into a format John can understand

```bash
ssh2john id_rsa > id_rsa.hash
```

Now use the new file against John & attempt to crack it

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt id_rsa.hash
```

![SSH PassCode](/assets/images/HTB%20-%20Brainfuck/SSH%20passcode.png)

We get the SSH file passcode revealed as `3poulakia!`

Now we can use this pass code with our SSH key to SSH into the machine. First let's change the permission on the key. SSH requires that prviate keys are only readable by the owner

```bash
chmod 600 id_rsa
```

Now lets' SSH!

```bash
ssh -i id_rsa orestis@10.10.10.17
```

Enter our passkey of `3poulakia!` and wee're in!

![SSH User Access](/assets/images/HTB%20-%20Brainfuck/SSH%20BrainFuck.png)
<p align="center"><em>SSH Access</em>

## Escalation

Now is the fun part, escalating. Running sudo -l is useless as we don't have orestis's password

Let's take a look around and see what we can find

![Sage Script](/assets/images/HTB%20-%20Brainfuck/Sage%20Script.png)
<p align="center"><em>Sage Script</em>

Immediately checking our user directory, I notice this `encrypt.sage` file that's owned my us (orestis)

Doing some research, this script is written in [SageMath](https://en.wikipedia.org/wiki/SageMath), a software system for mathematical calculations. The script is creating an RSA public key and using it to encrypt out flag, root.txt. It then puts the contents into `output.txt`. It puts the private key components needed to decrypt it in `debug.txt` such as `p` `q` & `e`. Obviously in the real world debug.txt would be hidden or destroyed as this will let us reconstruct the private key, but this is a CTF after all

![Encrypted Output](/assets/images/HTB%20-%20Brainfuck/Encrypted%20output.png)

Sure enough, this is the encrypted root.txt. We'll need to perform RSA decryption to grab this root flag. First we'll copy the encrypted password and save it to `encrypted_password.txt`

Next, we will need the prime Values `p` `q` & public exponent `e` from `debug.txt` which is:

```bash
p = 7493025776465062819629921475535241674460826792785520881387158343265274170009282504884941039852933109163193651830303308312565580445669284847225535166520307
q = 7020854527787566735458858381555452648322845008266612906844847937070333480373963284146649074252278753696897245898433245929775591091774274652021374143174079
e = 30802007917952508422792869021689193927485016332713622527025219105154254472344627284947779726280995431947454292782426313255523137610532323813714483639434257536830062768286377920010841850346837238015571464755074669373110411870331706974573498912126641409821855678581804467608824177508976254759319210955977053997
```

To compute the RSA private key using the values of p, q, and e we can use the following script

```python
from Crypto.PublicKey import RSA
from Crypto.Util.number import inverse, long_to_bytes
import ast

# Values from debug.txt (replace with actual values)
p = 7493025776465062819629921475535241674460826792785520881387158343265274170009282504884941039852933109163193651830303308312565580445669284847225535166520307
q = 7020854527787566735458858381555452648322845008266612906844847937070333480373963284146649074252278753696897245898433245929775591091774274652021374143174079
e = 30802007917952508422792869021689193927485016332713622527025219105154254472344627284947779726280995431947454292782426313255523137610532323813714483639434257536830062768286377920010841850346837238015571464755074669373110411870331706974573498912126641409821855678581804467608824177508976254759319210955977053997

# Compute the RSA modulus
n = p * q

# Compute the totient (phi(n))
phi_n = (p - 1) * (q - 1)

# Compute the private exponent
d = inverse(e, phi_n)

# Construct the RSA key
private_key = RSA.construct((n, e, d, p, q))

# Save the private key to a PEM file
with open('private_key.pem', 'wb') as key_file:
    key_file.write(private_key.export_key())

```

This script (not mine) in will take the two prime numbers *p* and *q* and the public number *e* to create a private key which will but saved to `private_key.pem`. This obviously be used to decrypt messages that were encrypted with the public key. I.E root.txt

Now that we have our private key `private_key.pem` we can decrypt the message in `encrypted_password.txt`

We will use the follwing python script

```python
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Util.number import long_to_bytes

# Load the private key
with open('private_key.pem', 'rb') as key_file:
    private_key = RSA.import_key(key_file.read())

# Load the encrypted message
with open('encrypted_password.txt', 'r') as file:
    encrypted_data = file.read().strip()
    c = int(encrypted_data)  # Convert to integer

# Create the cipher object
cipher = PKCS1_OAEP.new(private_key)

# Decrypt the data
try:
    decrypted_data = cipher.decrypt(long_to_bytes(c))
    print("Decrypted Password:", decrypted_data.decode())
except Exception as e:
    print(f"Decryption failed: {e}")
```

![Decrypted Root](/assets/images/HTB%20-%20Brainfuck/Decrypted%20key.png)

GG, we've decrypted the root flag

## Summary

1. Discovered ports 22, 443, 25, and 143
2. SSL Certificate revealed a hidden domain leading to a WordPress site
3. Exploited outdated WP plugin
4. Retrieved SMTP credentials from the WordPress site and logged into the mail server
5. Discovered credentials to login to secret forum
6. Found SSH access details in a forum conversation
7. Broke ciphers to obtain and brute-force a private key, then used it to SSH into the machine
8. Reconstructed the private key using given components and decrypted the root flag

## Vulnerabilities & Mitigation

| Vulnerability                                    | Mitigation                                                                                       |
|--------------------------------------------------|--------------------------------------------------------------------------------------------------|
| Outdated WordPress plugin                        | Regularly update plugins to their latest versions and apply security patches.                   |
| SMTP password in cleartext left on admin site   | Use secure methods for storing and transmitting credentials. Implement encryption for sensitive data. |
| Transmitting password over email                 | Avoid sending sensitive information via email. Use secure communication channels and encryption.  |
| Using outdated ciphers (Vigenère cipher) to transmit private keys on public forums | Use modern encryption methods and ensure secure key exchange practices. Avoid sharing sensitive information publicly. |
| Use of weak passphrases on private key           | Use strong, complex passphrases for private keys and implement key management best practices.   |

### Remediation References

1. **Outdated WordPress Plugin**
   - Reference: [WordPress Plugin Security](https://wordpress.org/about/security/)

2. **SMTP Password in Cleartext Left on Admin Site**
   - Reference: [Secure Password Storage](https://owasp.org/www-community/controls/Password_Storage_Cheat_Sheet)

3. **Transmitting Password Over Email**
   - Reference: [Email Security Best Practices](https://www.cisa.gov/publications-library/email-security-best-practices)

4. **Using Outdated Ciphers (Vigenère Cipher) to Transmit Private Keys on Public Forums**
   - Reference: [Modern Encryption Practices](https://en.wikipedia.org/wiki/Encryption)

5. **Use of Weak Passphrases on Private Key**
   - Reference: [Key Management Best Practices](https://csrc.nist.gov/pubs/sp/800/57/pt1/r5/final)
