---
layout: page
title: Nest
order: 10
hide: true
auto-header: none
---

<a href="#" class="image centered"><img src="/assets/images/nest.png" alt="nest" /></a>

<h2>Nest</h2>
<h3>The Basics</h3>
The first thing we should do is map the box IP address to the box name  .htb in the `/etc/hosts` file.  
`10.10.10.178   nest.htb`

<h3>Initial Scan</h3>
Next up we will run a standard NMAP scan. We get results back for 2 ports: 445 Microsoft-ds open and 4386 unknown open.  
Port 445 will most likely be SMB, if we look closer at port 4386 we can see it runs some sort of Reporting Service which allows us to run queries against databases using the legacy HQK format. A list of available commands is also provided.

![Initial NMAP scan](/assets/images/nest-initial-scan.png)

<h3>Enumerate SMB</h3>
Since we can't immediatly do something useful with port 4386, let's have a look at port 445 SMB first. We can enumerate SMB with tools like smbclient or smbmap.  
`smbmap -H 10.10.10.178 -u root`  
We can see a `Data` and a `Users` share to which we have read access.

![smbmap results](/assets/images/nest-smbmap.png)

Let's mount the SMB filesystem so we can browse it more easily via our terminal, we can do this using the Common Internet File System (CIFS).  
`mount -t cifs //10.10.10.178/Data /mnt/smb/`

![mount smb filesystem](/assets/images/nest-smb-mount.png)

With the filesystem mounted we can now freely browse around. If we check the `HR` directory we find a file called `'Welcome Email.txt'`. The emails tells us we can find our home folder in `\\HTB-NEST\Users\<USERNAME>` and also contains some default credentials `TempUser:welcome2019`.

![welcome email](/assets/images/nest-email.png)

Armed with some credentials, we can try to remount the `Data` share using the credentials we found.  
`mount -t cifs //10.10.10.178/Data /mnt/smb/ -o username=TempUser`

![mount smb with TempUser](/assets/images/nest-mount-tempuser.png)

Continuing with our search, we find a file called `RU_config.xml`. The file contains a new username `c.smith` and password `fTEzAfYDoz1YzkqhQkH6GQFYKp1XY5hm7bjOP86yYxE=` and a reference to port **389**, which is commonly used by the **LDAP** protocol.

![ru_config.xml](/assets/images/nest-ru-scanner.png)

If we have a quick look at the password, it seems to be base64 encoded. This however is not the case, we will come back to this later. When we base64 decode the password we find `}13=XJBAX*Wcf?βc`, but online decoders fail to successfully decode the password.

![creds csmith decoded](/assets/images/nest-creds-csmith.png)

With some more enumeration we also stumble upon a file called `Notepadplusplus` which contains the notepad++ history. The file references a hidden SMB share called `HTB-NEST\Secure$\IT\Carl`.  
Let's add `HTB-NEST` to the `/etc/hosts` file.  
`10.10.10.178 HTB-NEST nest.htb`  
  
Now we can mount the hidden share using the TempUser credentials.  
`mount -t cifs \\\\HTB-NEST\\Secure$\\IT\\Carl /mnt/smb -o username=TempUser`  

![mount secret share](/assets/images/nest-mount-secret-share.png)

In the secret share we find a Visual Basic Project called **RU** in `temp/'VB Projects'/WIP/RU`. Let's copy the project `cp -R tmp/'VB Projects'/WIP` and move it to a Windows machine, because it is a lot easier to work with **.NET** code in a proper IDE like **Visual Studio**.

<h3>Decrypting C.Smith credentials with RU Scanner</h3>
After copying over all the files and the `RU_config.xml` file we have the following structure on our Windows machine:

![RU Scanner](/assets/images/nest-ru-scanner-source.png)

After opening the solution in **Visual Studio** we modify the code to read and decrypt the password from the `RU_Config.xml` file.

![RU Scanner modified code](/assets/images/nest-ru-scanner-code.png)

We make sure to add the `RU_Config.xml` file to the project and set the **Copy to Output Directory** property to `Copy always`.

![Include RU_Config.xml](/assets/images/nest-ru-scanner-config.png)

Now if we build and run the project using the CTRL + F5 shortcut, it outputs the decrypted password `xRxRxPANCAK3SxRxRx`.

![Decrypted password](/assets/images/nest-decrypt-pass.png)

<h3>Getting user through SMB enumeration of the Users share</h3>
With the newly decrypted credentials, we can mount the Users share  
`mount -t cifs //10.10.10.178/Users /mnt/smb/ -o username-C.Smith`  
and grab the user flag.

![user flag](/assets/images/nest-user-flag.png)

We also find `HqkLdap.exe` and `HQK_Config_Backup.xml`. The config file gives us a path to the directory where all queries are stored and a reference to port 4386 which we found earlier using nmap. Let's leave SMB alone and explore port 4386.

Using Telnet we can connect to the service on port 4386. We can list available queries and files with the `LIST` command and traverse directories upwards using `SETDIR ..`.

<h3>Finding the debug password</h3>
To be able to view the contents of files and use the full functionality on port 4386, we need to find a debug password. During our earlier SMB enumeration of the `Users` share we found a file called `Debug Mode Password.txt` in `\C.Smith\HQK Reporting\` which appeared to be empty. A common technique used on Windows to hide information in files, is to use the alternate data stream (ADS). There are a couple of ways to check if a file has an ADS. Because I prefer to do Windows things on a Windows machine, I'll be switching back to my Windows box. However I'll also cover how you can find and read the ADS in Linux below.

On Windows we can open a command prompt and run it as the `C.Smith` user.  
`runas /netonly /user:C.Smith cmd xRxRxPANCAK3SxRxRx`

Next we can use `dir`'s `/R` parameter to call `FindFirstStreamW` and `FindNextStreamW` on each file and directory in the listing.  
`dir /R "\\10.10.10.178\Users\C.Smith\HQK Reporting\Debug Mode Password.txt"`

As expected, we find an ADS called `Password`. We can read the ADS using `type` and specifiying the name of the ADS after the filename with a semi-colon.  
`type "\\10.10.10.178\Users\C.Smith\HQK Reporting\Debug Mode Password.txt:Password"`

We find the debug password `WBQ201******`.

![finding the ADS Windows](/assets/images/nest-alternate-data.png)

To achieve the same in Linux, we can use a tool called **smbclient**.
```
smbclient -U C.Smith "//10.10.10.178/Users/" -c 'allinfo "\C.Smith\\HQK Reporting\\Debug Mode Password.txt"'` 
smbclient -U C.Smith "//10.10.10.178/Users/ -c 'get "\C.Smith\\HQK Reporting\\Debug Mode Password.txt:Password"'
```

![finding the ADS Linux](/assets/images/next-alternate-data-linux.png)

<h3>Using debug mode to find the administrator credentials</h3>
Now that we have the debug mode password, we can go back to our service on port 4386 and enable debug mode.

![enabling debug mode](/assets/images/nest-debug.png)

In debug mode we have access to some new queries, with the `showquery` command we can list the contents of files.

![showquery](/assets/images/nest-showquery.png)

Browsing around the filesystem, we navigate up to the `HQK` directory, and into the `LDAP` directory. If we do a `LIST` we can see there are two files inside, namely `HqKLdap.exe` which we also found earlier on the SMB shares, and `Ldap.conf`. We can use the `showquery 2` command to view the contents of `Ldap.conf`. The configuration file contains the encrypted password for the **Administrator** account on the `nest.local` domain.

![Ldap.conf](/assets/images/nest-hqk-ldap.png)

<h3>Inspecting and decompiling HqkLdap.exe to decrypt the Administrator password</h3>
We will move the `HqkLdap.exe` file we found in the SMB share over to our Windows machine and throw it into Ghidra to look at the defined strings. We are looking for values to use in the decryption routine `Utils.Decrypt` in the `RU Scanner` project.

![Ghidra defined strings](/assets/images/nest-ghidra-defined-string.png)

Decompiling `HqkLdap.exe` with [dotPeek](https://www.jetbrains.com/decompiler/) gives us a better idea of what we are looking for.

![Decompiling into .NET code](/assets/images/nest-dotpeek.png)

We can now adapt our `RU Scanner` project to decrypt the Administrator password using the values we found. We find `XtH4n***********`.

![Decrypting admin password](/assets/images/nest-decrypt-admin-pass.png)

<h3>Getting root through SMB and psexec.py</h3>
We can now mount the SMB `C$\Users` share with **Administrator** privileges.  
`mount -t cifs //10.10.10.178/C$/Users /mnt/smb/ -o username=Administrator`

![mounting Users with Administrator privileges](/assets/images/nest-mount-c-admin.png)

Using [impacket's psexec.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/psexec.py) we can escalate to **nt authority\system**, which is Window's equivalent of root.  
`/usr/share/doc/python3-impacket/examples/psexec.py Administrator:XtH4n***********@10.10.10.178`

![Authority System](/assets/images/nest-system-authority.png)

From there on it is easy to grab root flag!  
`cat root.txt`

![root flag](/assets/images/nest-root-flag.png)