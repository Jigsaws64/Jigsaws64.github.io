--- 
title: "Hack the Box (HTB) - Validation"
description: "Exploiting asdfasdf"
date: 2024-07-13 12:00:00 -100
image: /assets/images/HTB - Validation Pics/Validation_Thumbnail.png
categories: [CTF]
tags: [grpc, sql injection,port forwarding, ssh, privilege escalation,]    # TAG names should always be lowercase
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
- Various filtered

![Nmap Scan](assets/images/HTB - Validation Pics/Nmap scan_validated.png)

We'll start with the low hanging fruit of this scan and check out the apache web server hosted on port 80

![Web page](/assets/images/HTB - Validation Pics/Web page.png)

Let's type in our user and check the request in burp

![Burp](/assets/images/HTB - Validation Pics/inital_burp.png)

Now we can send the request to repeater with `CTRL + R` and start fuzzing the request to see what kind of response we get

The first thing we notice is sending this request over and over gives us a static cookie

The length of the cookie is 32 characters and is just a `MD5` of our username. MD5 is obviously deprecated and would be a finding on a real vulnerability assessment but for our purposes in this CTF we will move forward

Let's try a simple SQL injection

```bash
username=Jigsaw64&country=Anguilla' 
```

Copying the cookie and editing it into our cookie user field We see the following error:

 `Fatal error: Uncaught Error: Call to a member function fetch_assoc() on bool in
/var/www/html/account.php:33 Stack trace: #0 {main} thrown in /var/www/html/account.php
on line 33`

![Fatal error](/assets/images/HTB%20-%20Validation%20Pics/Fatal%20error.png)

Our backtick ` character caused a SQL error due to incorrect error handling of the SQL statement

Let's try commenting out the rest of the statement with `-- -`

![No SQL error](/assets/images/HTB%20-%20Validation%20Pics/No%20SQL%20error.png)

The error went away once we commented out the rest of the query. This confirms that we have SQLi

Let's