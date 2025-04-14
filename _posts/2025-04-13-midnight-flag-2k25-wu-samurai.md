---
title: 'Midnight Flag CTF 2k25'
date: 2025-04-13
author: "Viking"
layout: post
permalink: /midnight-flag-2k25-wu-samurai/
disqus_identifier: 0000-0000-0000-0021
description: ""
cover: assets/uploads/2025/04/logo_midnight-flag.png
tags:
  - Windows
  - Reverse
  - CTF
translation:
  - en
---

Last weekend I was looking for a reverse Windows challenge. The Midnight Flag CTF provides one challenge of this kind (difficulty : easy). Here is a short write-up & lessons learned about it.    

<!--more-->

## About Midnight Flag CTF   

In the field of computer security, the CTF (Capture the Flag) is a type of competitive event or challenge designed to test participants' skills in various aspect, to find and/or exploit vulnerabilities affecting software, websites or computer systems in order to get a flag (drapeau in French).

The [Midnight Flag CTF][LINK1] is the annual cybersecurity competition organized by ESNA students

## Samurai write-up 

Here is the challenge :  

[![1-chall.png](/assets/uploads/2025/04/1-chall.png)](/assets/uploads/2025/04/1-chall.png)     

The main() of oscur.exe is very simple :  

1. we must start the executable with an argument  

2. after some troll operations using puts + Sleep, the program allocate 0xD1600 which it fill with the shellcode then execute it  

[![2-oscur-main.png](/assets/uploads/2025/04/2-oscur-main.png)](/assets/uploads/2025/04/2-oscur-main.png)    

We will extract the shellcode by breaking just after memcpy then dump the heap.  

[![3-oscur-memcpy.png](/assets/uploads/2025/04/3-oscur-memcpy.png)](/assets/uploads/2025/04/3-oscur-memcpy.png)  

Let's doing it in Windbg.  

[![4-windbg_start.png](/assets/uploads/2025/04/4-windbg_start.png)](/assets/uploads/2025/04/4-windbg_start.png)  

We set the breakpoint at oscur+0x167c, then dump the shellcode to a new file we named midnight.exe (indeed we know it's an exe file thanks to magic bytes at the beginning of the shellcode).   

[![5-windbg_writemem.png](/assets/uploads/2025/04/5-windbg_writemem.png)](/assets/uploads/2025/04/5-windbg_writemem.png)  

When running  midnight.exe for the first time in windbg, this window "You lose" is displayed.  

[![6-youlose.png](/assets/uploads/2025/04/6-youlose.png)](/assets/uploads/2025/04/6-youlose.png)  

We look at the (129 !!) imports in order to find the Windows API used for creating this window :  CreateWindowEx   

[![6-imports.png](/assets/uploads/2025/04/6-imports.png)](/assets/uploads/2025/04/6-imports.png) 

Set a breakpoint onto CreateWindowEx, then check the call stack when the window pop up :

[![7-windb_callstack.png](/assets/uploads/2025/04/7-windb_callstack.png)](/assets/uploads/2025/04/7-windb_callstack.png)  

Then we look at the previous call from the call stack, at midnight+0x1a15. This function tests the registry key **HKCU\I Really Want to Stay at Your House**.   
If the key doesn't exist, then goto FAIL, else goto WIN (MessageBox).   

[![8-goto_fail_goto_win.png](/assets/uploads/2025/04/8-goto_fail_goto_win.png)](/assets/uploads/2025/04/8-goto_fail_goto_win.png)  

Ok let's create the registry key and test : the flag is displayed directly MCTF{ProcMonFTW}   

[![9-flag.png](/assets/uploads/2025/04/9-flag.png)](/assets/uploads/2025/04/9-flag.png)  

## Lessons learned  

A CTF is an opportunity to learn new techniques, and here are the lessons I drew from it :  

1. the [Procmon tool][LINK2] should not be forgotten during reverse operations. The author of the chall probably solve it with Procmon (the flag says ProcMonFTW). Of course we can see the registry key that should be read (HKCU\I Really Want to Stay at Your House) but this idea did not come to my mind   

[![10-procmon.png](/assets/uploads/2025/04/10-procmon.png)](/assets/uploads/2025/04/10-procmon.png)  

2. The `.writemem` command of Windbg writes a section of memory to a file. It is useful when you want to extract a payload / stage 2 / shellcode of RAM.  

[![Challenge file : oscur.exe](/assets/uploads/2025/04/oscur.exe)](/assets/uploads/2025/04/oscur.exe)  

Thanks for reading, I hope you learnt something and your feedbacks are welcome !   

Resources :    
[https://midnightflag.fr/][LINK1]   
[https://learn.microsoft.com/en-us/sysinternals/downloads/procmon][LINK2]  
[https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/-writemem--write-memory-to-file-][LINK3]

[LINK1]: https://midnightflag.fr/    
[LINK2]: https://learn.microsoft.com/en-us/sysinternals/downloads/procmon
[LINK3]: https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/-writemem--write-memory-to-file-