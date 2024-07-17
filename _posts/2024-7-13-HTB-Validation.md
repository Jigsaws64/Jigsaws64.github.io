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

We'll start with the log hanging fruit of this scan and check out the apache web server hosted on port 80

![Web page](/assets/images/HTB - Validation Pics/Web page.png)

Let's type in our user and check the request in burp

![Burp](/assets/images/HTB - Validation Pics/inital_burp.png)

Now we can send the request to repeater with `CTRL + R` and start fuzzing the request to see what kind of response we get
