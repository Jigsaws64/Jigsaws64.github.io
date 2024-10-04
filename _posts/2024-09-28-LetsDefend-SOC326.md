--- 
title: "LetsDefend - SOC326"
description: "Impersonating Domain MX Record Change Detected"
date: 2024-09-28 12:00:00 -100
image: /assets/images/LetsDefend - SOC326/Blog Thumbnail.jpg
categories: [Incident Response]
tags: [mx record, soc analyst, incident response]    # TAG names should always be lowercase
---

## Initial incident

We start by seeing the initial incident

![Initial Incident](/assets/images/LetsDefend%20-%20SOC326/Initial%20Incident.png)

A ***Medium*** severity incident is reported on Sep 17th 2024 at 12:05 PM

An alert was triggered due to a suspicious Mail Exchange (MX) record modification, involving a domain that bears a striking resemblance to ***letsdefend.io***, with a substitute variation `letsdefwnd.io`. This clearly bears the hallmarks of a phishing attack, where a treat actor has intentionally crafted a malicious domain with the aim of deceiving unsuspecting individuals

An MX record is a type of DNS record that identifies the mail servers authorized to receive emails on behalf of the domain

The source address for the alert is no-reply@ctireport.io, which is likely associated with a threat intelligence provider (such as CrowdStrike Falcon, Cisco Talos, etc.). These providers monitor public data sources, including domains and DNS records, for changes that might indicate potential phishing attempts or other malicious activities

### Understanding the attack process

- Register a domain that closely resembles ours `letsdefwnd.io`
- Change the MX record of the impersonating domain **letsdefwnd.io** to point to their mail server `mail.mailerhost.net`. This change will allow them to receive and manage all emails directed to the lookalike domain
- Send phishing emails from the impersonating domain

Let's take ownership of the alert

![Ownedship](/assets/images/LetsDefend%20-%20SOC326/Ownership.png)

Great, now that we have ownership the alert will be in our ***Investigation Channel***

Now, we can begin investigation. Since this is clearly a malicious domain intended to phish emails, let's head over the the ***Email Security Tab*** to look for any phishing emails

![Email Security](/assets/images/LetsDefend%20-%20SOC326/Email%20Security.png)

Here, we can look for the malicious domain in question `letsdwfend.io`

![Phishing request](/assets/images/LetsDefend%20-%20SOC326/Phishing%20email.png)

We successfully find one request. This request came in on `Sep, 28th, 2024, 8:00AM` which is 19h,55m after the initial notification for the malicious domains MX record change

![Actual Email](/assets/images/LetsDefend%20-%20SOC326/Actual%20Email.png)

The phishing attempt was sent to `mateo@letsdefend.io` with what appears to be a fictitious free voucher request with a hyperlink that takes the user to the malicious domain in question

Now that we know one of our users `mateo` might have potentially clicked on this malicious email, we need to investigate further. Let's head over to `Endpoint Security` and checkout Mateos device

![Contained](/assets/images/LetsDefend%20-%20SOC326/Contained.png)

We should probably contain their device for now until we confirm if they clicked on any email

We'll delete this email

![email deleted](/assets/images/LetsDefend%20-%20SOC326/Delete%20Email.png)

Let's check Mateos browser history as we confirmed this phishing email would redirect the user to the malicious domain `letsdefwnd.io`

![Mateo's History](/assets/images/LetsDefend%20-%20SOC326/History.png)

Shame, it appears as though Mateo fell victim to the phishing attempt as incided by the browsing history. They visited the malicious domain on `2024-09-18 13:32:13 (1:32pm)`

Let's take a look at the `Network Action` tab to see any connections that may have been made around that time

![Network Action](/assets/images/LetsDefend%20-%20SOC326/Netowrk%20Action.png)

Let's view any processes that have been ran after Mateo visited the malicious site

We see three IP addresses:
- 169.254.169.254 (Sep 18 2024 01:32:39)
- 45.33.23.183 (Sep 18 2024 01:32:13)
- 23.44.17. (Sep 18 2024 01:32:09)

Let's investigate the IP address that happened after the time of the phishing email. We'll plug in the IP address `45.33.23.183` into [Virus Total](https://www.virustotal.com/gui/home/upload). We can skip and 169.254.169.254 as this is a APIPA  used for local network communication

The IP ***45.33.23.183*** request was made at the exact same time as the phishing email, plugged into virus total yields the following results

![45.33.23.183](/assets/images/LetsDefend%20-%20SOC326/45.33.23.183.png)

As we can see, this IP has been flagged as malicious by six difference sources. It's important to note that this IP is associated with [Akamai Cloud](https://www.akamai.com/cloud-computing) which is a legitimate service. It is possible, however, for attackers to use cloud services for malicious purposes

We should block the IP at the network firewall level

The next logical step is to determine if there is malware or suspicious behavior on this system. Let's navigate to the `Possesses` tab

![System Events](/assets/images/LetsDefend%20-%20SOC326/System%20Events.png)

There are three process that were triggered on or after the pishing email interaction

| Event Time             | Process ID | Process Name         | Parent Process | Command Line                                             | Relevance                                                   |
|------------------------|------------|----------------------|----------------|-----------------------------------------------------------|-------------------------------------------------------------|
| Sep 18, 2024, 01:32:13 PM | 1460       | chrome.exe           | explorer.exe   | "C:\Program Files\Google\Chrome\Application\chrome.exe"    | Likely when the phishing link was clicked.                   |
| Sep 18, 2024, 01:32:50 PM | 100        | services.exe         | wininit.exe    | C:\Windows\system32\services.exe                          | Indicates a service was started or modified post-phishing.   |
| Sep 18, 2024, 01:32:51 PM | 7228       | TrustedInstaller.exe | services.exe  | C:\Windows\servicing\TrustedInstaller.exe                 | Potential system change or installation post-phishing.       |

Looking at these processes, it appears that Mateo clicked on the phishing link, which opened Chrome

37 seconds following this, the `services.exe` process was triggered. This executable manages system services, suggesting this that a malicious script may have modified system services

One second later, `TrustedInstaller.exe` was executed. This executable is associated with Windows updates and system modifications, suggesting malicious activity designed to modify system settings

The next logical steps would be to perform a thorough scan on this endpoint to detect any malware. Since we don't have authorization to do so, we will write up our investigation and escalate this to the Incident Response team for further investigation

![Close Alert](/assets/images/LetsDefend%20-%20SOC326/Create%20Case.png)

### Playbook Questions

#### Are there any  or URLs in the email?

- Yes, as indicated by the fake voucher link to the malicious domain

#### Analyze Url/Attachment

- The IP address `45.33.23.183` associated with the malicious domain `letsdefwnd.io` was ran through VirusTotals database and marked as 

#### Check if Mail Delivered to User?

- Delivered, as indicated by process modifications triggered shortly after user interacted with malicious domain

#### Delete Email from recipient!

- We already deleted this

#### Check if someone opened the Malicious URL

- User did open the email

#### Containment

- We contained the machine

### Artifacts

![Artifacts](/assets/images/LetsDefend%20-%20SOC326/Artifacts.png)

Here we added the malicious IP & Domain in question

### Analyst Note

![Analyst Note](/assets/images/LetsDefend%20-%20SOC326/Analyst%20Note.png)

Now let's close the alert

![Close Alert](/assets/images/LetsDefend%20-%20SOC326/Close%20Alert.png)

It's a ***True Positive*** and here we can just copy and paste our analyst note 

![End](/assets/images/LetsDefend%20-%20SOC326/End.png)

GG, thats SOC326!