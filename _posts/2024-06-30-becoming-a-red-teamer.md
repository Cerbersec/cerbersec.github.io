---
layout: article
title: Becoming a Red Teamer
tags: red-teaming
date: 2024-06-30 08:00:00 +0100
article_header:
  type: cover
  image:
    src: /assets/images/banner-wide.png
---

I receive the questions "I want to become a red teamer" or "How do I get started in pentesting / red teaming?" pretty often. Instead of repeating myself, I'll write down my recommended path to take if I had to do it all over again. Here we go. <!--more-->

### 0. What did you do?

Before I dive into my recommendations, let me briefly explain how I got started. I graduated university with a degree in information security. It sounds fancy but it didn't teach me anything useful I still use today during my assessments. In my spare time I made sure to become very proficient at programming in C# and C. I've always had an interest in malware and before I got into an offensive role I practiced a lot of malware analysis which helped me later down the road to write my own capable malware. For those interested I can highly recommend the [Zero2Automated course](https://courses.zero2auto.com/) by [Overfl0w](https://x.com/0verfl0w_). In my spare time I started doing [HackTheBox](https://hackthebox.com) and posting write-ups and walkthroughs on this blog and on X/Twitter.

At this point in time I got hired into a red teaming role after completing two internships with [NVISO Security](https://nviso.eu). What made me stand out was my interest and skills in malware development. After being hired I received on the job training, took the RTO I & II certifications and continued honing my malware development skills through additional training.

If I had to do it all over again, what would I do in 2024?

### 1. Build a solid foundation

It speaks for itself that working in the security industry is not necessarily an entry level job. This field is difficult to work in, with hefty requirements put onto you by customers or potential employers. Before making the transition into any type of security role, you need to build a solid foundation. "What does this foundation consist of exactly?" I hear you ask. When I got started I made sure to have:

#### A solid background in networking

This includes but is not limited to: subnetting, switching, routing, physical network components.

#### A solid background in Linux systems

It sounds stupid, but building your own Arch Linux box from scratch will teach you a lot about the way things work and get you familiar with using the terminal and bash scripting. Additional recommendations are setting up and configuring Apache web server.

#### A solid background in Windows systems

Consider setting up your own Domain Controller, configure a web server, configure a DNS server, configure Active Directory Certificate Services. Bonus points for familiarizing yourself with Kerberos, how Windows authentication works and PowerShell scripting.

#### A solid programming / coding background

I've always loved programming but I realize it's not for everybody. Unfortunately, the core of "hacking" or its commercialized forms "pentesting / red teaming" whatever you want to label it, has always been developing exploits for vulnerabilities and chaining them together to achieve specific goals. Programming is in my opinion a vital skill which every aspiring red teamer should have.

Let me preface that with: you don't need to be full blown software developer or adhere to all coding standards and principles. No, you need to be capable enough to throw together some code to achieve the objective and not fall apart entirely in a production environment. Over time your programming will improve the more you do it.

So what are my recommendations?

* Get comfortable with at least 1 high level language such as C#, Go, Nim, Rust,.... whatever floats your boat. I recommend C#.
* Get comfortable with at least 1 scripted language such as Python.
* If you're interested in Malware Development, get comfortable with C or C++ and x64 intel assembly. I recommend starting with C only.

Now that we've got the basics out of the way, what's next?

### 2. Work on your pentesting skills

The next step is practicing your actual "hacking" skills, familiarizing yourself with day-to-day pentest tooling and understanding how to approach different environments. For this I can only recommend purchasing a [HackTheBox](https://hackthebox.com) subscription and start owning retired boxes with the help of walkthroughs such as the legendary [IppSec](https://www.youtube.com/@ippsec) provides on his YouTube channel. I recommend focusing primarily on Windows machines since this is the most common environment you will be working with during actual pentests or red team engagements. This doesn't mean all Linux boxes can be ignored, knowing some basic Linux exploitation always comes in handy.

If you're willing to throw money at the problem and make it easier to learn instead of learning by doing in a HackTheBox environment, then I recommend [TCM Academy](https://academy.tcm-sec.com/) courses.

Alternatively, you can watch [this](https://www.youtube.com/watch?v=3FNYvj2U0HM) and [this](https://www.youtube.com/watch?v=sH4JCwjybGs) YouTube video by [TheCyberMentor](https://x.com/thecybermentor).

### 3. Become familiar with Red Team tools

The next steps are particulary for red teaming. Pentesting tools are great, but they lack certain "OPSEC" features to be used during stealth engagements when you want to avoid settings off alarms and detections as much as possible. The answer to this problem are Command & Control (C2) frameworks such as [Cobalt Strike](https://www.cobaltstrike.com/) or [BruteRatel](https://bruteratel.com/). Of course there are plenty of Open Source alternatives to practice with such as [Covenant](https://github.com/cobbr/Covenant), [Mythic](https://github.com/its-a-feature/Mythic), [Sliver](https://github.com/BishopFox/sliver) and [Havoc](https://github.com/HavocFramework/Havoc).

Unfortunately this is where the free resources stop and I'll be recommending paid training and platforms. At this stage you should have sufficient knowledge and skills to land a entry level pentesting gig.

### 4. Get proper training

Now it's time to specialize. I recommend to obtain the following certifications:

1. [Red Team Ops I](https://training.zeropointsecurity.co.uk/courses/red-team-ops) by [Zero-Point Security](https://x.com/zeropointsecltd)
2. [Red Team Ops II](https://training.zeropointsecurity.co.uk/courses/red-team-ops-ii) by [Zero-Point Security](https://x.com/zeropointsecltd)

### 5. Pick your poison

After obtaining RTO I & II it's time to pick your poison and specialize into a specific "role" you want to fulfill within a red team. Afterall, there is a "team" in "red team".

* If you're interested in Malware Development, pickup a subscription to [MalDev Academy](https://maldevacademy.com/) and the Sektor7 Malware Development courses: [Essentials](https://institute.sektor7.net/red-team-operator-malware-development-essentials), [Intermediate](https://institute.sektor7.net/rto-maldev-intermediate), [Advanced](https://institute.sektor7.net/rto-maldev-adv1).
* If you're more interested in applications and general pentesting, then obtain the certifications such as [OSCP](https://www.offsec.com/courses/pen-200/) from [Offsec Training](https://www.offsec.com/courses-and-certifications/)
* Last but not least, if you have too much money or your company can pay for your training, you can obtain certifications by [SANS](https://www.sans.org/offensive-operations/). I recommend [SEC565: Red Team Operations and Adversary Emulation](https://www.sans.org/cyber-security-courses/red-team-operations-adversary-emulation/), [SEC660: Advanced Penetration Testing, Exploit Writing, and Ethical Hacking](https://www.sans.org/cyber-security-courses/advanced-penetration-testing-exploits-ethical-hacking/), [SEC699: Advanced Purple Teaming - Adversary Emulation & Detection Engineering](https://www.sans.org/cyber-security-courses/purple-team-tactics-adversary-emulation/)

That's it. There's no other magic sauce. Only hard work and dedication.