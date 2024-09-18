---
title: "Hack the Box (HTB) - Mailing"
description: "?"
date: 2027-09-07 12:00:00 -100
image: /assets/images/HTB - Sightless/Sightless Thumbnail.jpg
categories: [CTF]
tags: [?]    # TAG names should always be lowercase
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

Nothing much, let's check for directories

![Gobuster Scan](/assets/images/HTB%20-%20Sightless/Gobuster%20Sightless.png)

Only a 301 on /images which doesn't do much






