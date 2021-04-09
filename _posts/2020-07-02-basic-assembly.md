---
title: Basic assembly
author: Cerbersec
layout: post
---

THIS POST IS A WORK IN PROGRESS

In this post I'll go over writing a basic Hello World program in C, using MinGW to compile, assemble and link it. I'll be looking at the assembly, writing my own Hello World in NASM and using nasm and ld to assemble and link it.

<h2>Writing "Hello World" in C</h2>

```
# hello world.c

#include <stdio.h>

int main() {
    printf("Hello World");
    return 0
}
```

<h2>Using MinGW</h2>

Generate raw assembly: compile, not assemble, not link<br>
`gcc -S "hello world.c" -o "hello world.S"`

Generate object file: compile, assemble, not link<br>
`gcc -c "hello world.S" -o "hello world.o"`

Generate stripped portable executable (PE): compile, assemble, link, strip<br>
`gcc -s "hello world.o" -o "hello world.exe"`

<h2>Writing "Hello World" in NASM</h2>

```
; hello world.asm

        global  _start
        extern  _ExitProcess@4      ; stdcall calling convention: leading _, trailing @, number of bytes in parameter list in decimal
        extern  _GetStdHandle@4
        extern  _WriteConsoleA@20

        section .data
msg:    db      'Hello, World', 0xA     ; 0xA denotes a new line
handle: db      0

        section .text
_start:
        ; handle = GetStdHandle(-11)
        push    dword -11       ; -11 denotes standard output device, initially this is the active console screen buffer
        call    _GetStdHandle@4
        mov     [handle], eax   ; eax contains return value from GetStdHandle()

        ; WriteConsole(handle, &msg, 13, &written, 0)
        push    dword 0             ; reserved: must be null
        push    dword 0             ; optional out parameter: number of actual characters written
        push    dword 13            ; number of characters to write
        push    msg                 ; buffer to write
        push    dword [handle]      ; handle to console window
        call    _WriteConsoleA@20   ; direct win32 API call

        ; ExitProcess(0)
        push    dword 0
        call    _ExitProcess@4
```

<h2>Using nasm.exe and ld.exe</h2>

Generate object file: assemble with nasm<br>
`nasm -fwin32 "hello world.asm"`

Generate portable executable (PE): link with ld<br>
`ld -e _start "hello world.obj" C:\Windows\System32\kernel32.dll -o "hello world.exe"`