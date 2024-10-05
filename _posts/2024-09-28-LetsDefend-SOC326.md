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

![Alert](/assets/images/LetsDefend%20-%20SOC326/Alert.png)

We see only one alert, and it comes from the notification in question

![Email Notification](/assets/images/LetsDefend%20-%20SOC326/Email%20Notification.png)

This email notification outlines the findings that we discussed earlier, providing a bit more detail such as the domain registrar & registrant

Let's search **letsdefwnd.io** against VirusTotals database

![Virtus Total](/assets/images/LetsDefend%20-%20SOC326/Virus%20Total.png)

As we can see, the domain is flagged as a phishing domain

Let's create a playbook for this alert as necessary

### Playbook Questions

#### Are there any  or URLs in the email?

- Technically, yes. However, it wasn't a phishing email as it was the notification email

#### Analyze Url/Attachment

- The domain `letsdefwnd.io` was searched via VirusTotal

#### Check if Mail Delivered to User?

- I answered no here, (this is incorrect) since no actual phishing email was sent

#### Delete Email from recipient!

- Nothing to delete outside of an alert

#### Containment

- Nothing to contain

### Artifacts

![Artifacts](/assets/images/LetsDefend%20-%20SOC326/Artifacts%20-%20Copy.png)

### Analyst Note

![Analyst Note](/assets/images/LetsDefend%20-%20SOC326/Notes.png)

## Results

![Results](/assets/images/LetsDefend%20-%20SOC326/Results.png)

As we can see, I got the `check if mail delivered to user` question incorrect. I'm unsure if the notification email constituted as a yes to this question or not as I could not find an actual phishing email that was sent from the typosquatted email in question

***Feel free to send me a message on YouTube / Linkdin if I got something incorrect***

GG, thats SOC326!

<iframe width="560" height="315" src="https://www.youtube.com/watch?v=n3bTs4HTpak" frameborder="0" allowfullscreen></iframe>
