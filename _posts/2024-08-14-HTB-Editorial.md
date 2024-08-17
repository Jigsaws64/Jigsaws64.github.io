--- 
title: "Hack the Box (HTB) - Editorial"
description: "???"
date: 2024-08-13 12:00:00 -100
image: 
categories: [CTF]
tags: [acc,]    # TAG names should always be lowercase
---

## Enumeration

Let's run an [AutoRecon](https://github.com/Tib3rius/AutoRecon) scan against our target at `10.10.11.23`

We see the following ports open:

![namp scan](/assets/images/HTB%20-%20Editorial/nmap%20scan%20editorial.png)

The classic duo of 22 & 80. Let's start by checking the nginx web server. First we need to add the domain to our `/etc/hosts` file as indicated by the nmap scan `Did not follow redirect to http://editorial.htb`. This indicates some virtual hosting is happening.

![etchosts](/assets/images/HTB%20-%20Editorial/etchosts%20editorial.png)

Now that we added `editorial.htb` to our local dns file we can navigate to the site web server

![web server](/assets/images/HTB%20-%20Editorial/Web%20server%20editorial.png)

Let's take a look around, shall we

![Finding](/assets/images/HTB%20-%20Editorial/Some%20information.png)

We discover an email here `submissions@tiempoarriba.htb`, which may be indicative of another domain. Let's try adding `tiemoarribe.htb` in our local dns file

![second domain?](/assets/images/HTB%20-%20Editorial/second%20domain.png)

Now let's try to navigate to `tiempoarribe.htb`

Hmm, that site doesn't seem to exist.. Let's keep looking around the main site

![upload ability discovered](/assets/images/HTB%20-%20Editorial/upload%20found.png)

We find this upload section, which could be juicy. Our gobuster scan confirms the finding obviously

![dirbuster](/assets/images/HTB%20-%20Editorial/upload%20directory.png)

Before we proceed, I want to say that I already scanned for vhosts and discovered nothing. This being an easy rated box mixed with the fact that we have an upload section tells me that this is most likely the initial attack vector

Uploading a file & checking the request in burp gives some interesting results

![NoUpload](/assets/images/HTB%20-%20Editorial/No%20Upload.png)

As shown from the picture, my upload goes nowhere and just returns me to the same page

![Wappalyzer](/assets/images/HTB%20-%20Editorial/Wappalyzer.png)

Checking Wappalyzer we see that the site is utilizing a Nginx web server that's serving Hugo. Hugo is a static site generator (similar to the one I am using for this blog), which means there's no backend DB or server side programming

I notice a `preview` button next to the book information that allows a URL to be entered

![Cover URL](/assets/images/HTB%20-%20Editorial/Cover%20URL%20section.png)

Let's fire up a nc listener & enter our IP/port and hit the preview button

![SSRF](/assets/images/HTB%20-%20Editorial/SSRF.png)

Nice, so we have confirmed SSRF through this cover url & preview. The problem is the reverse shell dies immediately. Let's check the request in burp and fix that.

