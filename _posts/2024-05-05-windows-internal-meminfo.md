---
title: 'Fixing (Windows Internals) Meminfo.exe'
date: 2024-05-05
author: "Viking"
layout: post
permalink: /windows-internal-meminfo/
disqus_identifier: 0000-0000-0000-0014
description: ""
cover: assets/uploads/2024/05/windows-internal-meminfo.png
tags:
  - Windows
  - Reverse
  - Drivers
translation:
  - en
---

A while ago I started to read Windows Internals books. I've discovered Meminfo.exe tool that allows to retrieve information about physical & virtual memory.  
Some options did not give any output / crash the program, after MemInfo source code analysis and fileinfo.sys driver reversing I found some quick (and dirty) fixes. Maybe it can help if someone encounter the same issues.  

<!--more-->

*Disclaimer : I remain humble: I'm not sure I have the level required to modify a program made by these reference authors. However, I'm sharing what I've found interesting, and I'd be delighted to know if anything is wrong. Tested on Microsoft Windows Version 10.0.19045.4291*

## Context    

I'm looking for information about physical memory management on Windows OS. Reading those books is a must if you want to understand this topic, thanks you authors !  
- [Windows Internals, Part 1][LINK1] By Pavel Yosifovich, Mark E. Russinovich, Alex Ionescu, David A. Solomon
- [Windows Internals, Part 2][LINK2] By Andrea Allievi, Mark E. Russinovich, Alex Ionescu, David A. Solomon  

 The **Chapter 5 - Memory management** explains all we need to know, more specifically both sections named **Address translation** and **Page frame number database**. In the book the *Meminfo.exe* tool is introduced.   

While I was playing with it I tried to use the following options :
- `-a` *Dump full information about each page in the PFN database*  
- `-o` *Display information about each page in the process' working set*  
- `-f` *Display file names associated to memory mapped pages*  

Unfortunately it did not work as expected, it crashed.   

[![meminfo_tests](/assets/uploads/2024/05/meminfo_tests.png)](/assets/uploads/2024/05/meminfo_tests.png)  

## Fix 1 : Windows internal data structures   

Windows internal structures evolved, you can read more information about this on [NtQuerySystemInformation SystemSuperfetchInformation update][LINK13] from *@Midi12*.).  
I proposed to include *Midi12* fix in this PR [Support Win10 - modify _PF_MEMORY_RANGE_INFO #23 ][LINK10], which gives the following results : 
- `-a` works but crashes after displaying some entries 
- `-o` works like a charm
- `-f` doesn't work  

[![meminfo_tests_midi12](/assets/uploads/2024/05/meminfo_tests_midi12.png)](/assets/uploads/2024/05/meminfo_tests_midi12.png)  


## Troubleshoot remaining problems   

Ok first let's have a look at the source code.

### Source code analysis  

The *main()* function catch options provided by the user, then call the *PfiQueryFileInfo()* function when `-f` is provided.  

```cpp  
int main(int argc, const char* argv[]) {
[snip]
    // if -f option is provided, enable ShowFiles
		if (strstr(argv[i], "-f")) ShowFiles = i;
[snip]
    //
    // Query sources and files
    //
    status = PfiQueryPrivateSources();
    if (NT_SUCCESS(status) && ShowFiles)
    	status = PfiQueryFileInfo();
[snip]
}
```  

This function builds the request sent to the kernel using *PfSvFICommand()* which is just a wrapper that calls Windows API *NtDeviceIoControlFile*.  

*Note : this API is now deprecated and superseded by DeviceIoControl*   

Several parameters must be set in order to talk to the kernel driver :  
- symlink is `PfiFileInfoHandle` (an handle on **\\\\Device\\\\FileInfo**)
- IOCTL is set to **0x22000F**  
- buffers are `Request` (input buffer) and `OutputBuffer` :    

```cpp 
NTSTATUS PfiQueryFileInfo() {
	PFFI_ENUMERATE_INFO Request;
	PPFNL_LOG_ENTRY LogEntry;
	PPFFI_UNKNOWN LogHeader;
	PVOID OutputBuffer;
	ULONG OutputLength;
	NTSTATUS Status;

	OutputLength = 16 * 1024 * 1024;
	OutputBuffer = ::HeapAlloc(::GetProcessHeap(), HEAP_ZERO_MEMORY, OutputLength);

	//
	// Build the request
	//
	PfiBuildFileInfoQuery(&Request);

	//
	// Send it
	//
	Status = PfSvFICommand(PfiFileInfoHandle,
		0x22000F,
		&Request,
		sizeof(Request),
		OutputBuffer,
		&OutputLength);
[snip]
}
```   

What does this handle correspond to in the kernel ? Using Sysinternals Winobj you see the TYPE of *\\\\Device\\\\FileInfo* is... *Device* (hello captain obvious lol) which belongs to *FileInfo* driver. 

[![winobj_device_fileinfo](/assets/uploads/2024/05/winobj_device_fileinfo.png)](/assets/uploads/2024/05/winobj_device_fileinfo.png)  

### (Optional) Finding driver kernel addresses using Windbg  

If you want to make live kernel debug, you can get more information about loaded drivers using the following commands in Windbg :   

- find the driver object named *\FileSystem\FileInfo*  

`kd> !drvobj \FileSystem\FileInfo`  

- find the device object named *\Device\FileInfo*  

`kd> !devobj \Device\FileInfo`  

- find the image path of the driver  

`kd> lmDvmfileinfo`  

- if you don't know the name, find it in device objects list or in driver objects list  

`kd> !object \device`  
`kd> !object \driver`  


```
0: kd> !drvobj \FileSystem\FileInfo
Driver object (ffffe28dd0419d40) is for:
 \FileSystem\FileInfo
Driver Extension List: (id , addr)
Device Object list:
ffffe28dd04a6830 

0: kd> !devobj \Device\FileInfo
Device object (ffffe28dd04a6830) is for:
 FileInfo \FileSystem\FileInfo DriverObject ffffe28dd0419d40
Current Irp 00000000 RefCount 1 Type 00000022 Flags 00000040
SecurityDescriptor ffff8f814ba4a960 DevExt 00000000 DevObjExt ffffe28dd04a6980 
ExtensionFlags (0000000000)  
Characteristics (0x00000100)  FILE_DEVICE_SECURE_OPEN
Device queue is not busy.

0: kd> lm Dvm Fileinfo
Browse full module list
start             end                 module name
fffff802`6f4b0000 fffff802`6f4ca000   fileinfo   (pdb symbols)          c:\symbols\fileinfo.pdb\9315E0DB7B3E69E10CE8C62054F75C4D1\fileinfo.pdb
    Loaded symbol image file: fileinfo.sys
    Image path: \SystemRoot\System32\drivers\fileinfo.sys
    Image name: fileinfo.sys
[snip]
]
0: kd> !object \device
Object: ffff8f814b631150  Type: (ffffe28dcec96d20) Directory
    ObjectHeader: ffff8f814b631120 (new version)
    HandleCount: 2  PointerCount: 65729
    Directory Object: ffff8f814b665c60  Name: Device

    Hash Address          Type                      Name
    ---- -------          ----                      ----
     00  ffffe28dd504ce00 Device                    00000030
         ffffe28dd0d05050 Device                    NDMP2
         ffffe28dd0431360 Device                    NTPNP_PCI0002
         [snip]
         ffffe28dd04a6830 Device                    FileInfo         
         [snip]

```   

As you can see *MemInfo.exe* uses the driver *C:\System32\drivers\fileinfo.sys* in order to get file information, let's have a look at this binary.  

### Quick reversing on fileinfo.sys driver  

This topic is introduced in a the previous blogpost [Windows kernel driver static reverse using IDA and GHIDRA][LINK9]. The first step is to locate the code executed when the driver receive IOCTL **0x22000F** : as you can see below it calls the function *FIIterate* providing the parameter named *param_2* by Ghidra (which is the `Request` in the previous section of this article) :  

[![ghidra_FIControlDispatch](/assets/uploads/2024/05/ghidra_FIControlDispatch.png)](/assets/uploads/2024/05/ghidra_FIControlDispatch.png)  

The *FIIterate* is responsible for processing data you sent, let's reverse it and understand what is going on :   

[![ghidra_FIterate](/assets/uploads/2024/05/ghidra_FIterate.png)](/assets/uploads/2024/05/ghidra_FIterate.png)  

You will find below the pseudo-code of *FIIterate()* highlighting information I found interesting (it includes breakpoints if you want to experiment kernel live debug). 

```cpp
int FIIterate(PIRP currentIRP) {
    uint status;
    if (nInBufferSize < 0xC){
        status = 0xC000000D; // STATUS_INVALID_PARAMETER
    } 

    /* checks that a user-mode buffer actually resides in the user portion of the
    address space, and is correctly aligned. */
    ProbeForRead(Type3InputBuffer,*(uint *)(currentStackLocation + 0x10),4);

    if (Request->Version != 0xf ){
        status = 0xC0000355; // STATUS_DS_VERSION_CHECK_FAILURE
    }
    
    /* 
    checks that a user-mode buffer actually resides in the user-mode portion of
    the address space, is writable, and is correctly aligned.
    */
    ProbeForWrite(pauVar2,OutputBufferLength,4);
    if (error) {
        status = 0xC0000005; //STATUS_ACCESS_VIOLATION
    }
    
    /*
    Do the job : retrieve FileInfo information
    */
    KeEnterCriticalRegion();
    while (FIVolumeGetNext(i) {
        FIVolumeLogForNL();
        while (true) {
            FIStreamGetNext ();
            FIStreamLogForNL(); // update realOutputlenght
        }
    }
    status = 0x0; // STATUS_SUCCESS

    if (OutputLength < realOutputlenght){
        status = 0x80000005; //STATUS_BUFFER_OVERFLOW
    }

   return status;
}
    /*
    Memo if you start kernel debugging, here are some breakpoints :     
 	-nInBufferSize stored in eax (Breakpoint 1)
    break on fileinfo!FIIterate+0x42:
    fffff806`3d4d0c32 83f80c          cmp     eax,0Ch

	-Request->Version stored at [rsp+40h] (Breakpoint 2)
    fileinfo!FIIterate+0x90:
    fffff806`3d4d0c80 837c24400f      cmp     dword ptr [rsp+40h],0Fh

	-OutputLength stored in eax, realOutputlenght stored at [rsp+0B8h] (Breakpoint 3)
    fileinfo!FIIterate+0x27f:
    fffff806`3d4d0e6f 3b8424b8000000  cmp     eax,dword ptr [rsp+0B8h]

	-end of function (Breakpoint 4)
    fileinfo!FIIterate+0x2d1:
    fffff806`3d4d0ec1 c3              ret

	-currentIRP stored in r13 (Breakpoint 5)
    fileinfo!FIIterate+0x1d: 
    fffff806`3d4d0c0d 4c8ba9b8000000  mov     r13,qword ptr [rcx+0B8h]

	NB :
	CurrentStackLocation is at currentIRP + 0xB8 (0x078 + 0x040)
    OutputBufferLength = CurrentStackLocation + 0x8
    InputBufferLength = CurrentStackLocation + 0x10
    IoControlCode = CurrentStackLocation + 0x18
    Type3InputBuffer = CurrentStackLocation + 0x20
    */
```   

To sum up, here is the information we have concerning `Request` constraints :   
- sizeof(Request) > 0xC 
- Request->Version = 0xf  
- OutputLength should be large enough to receive the result of the request  

## Fix 2 : modify input / output buffers constraints  

Here are the "patches" : 

- increase the `OutputLenght` in *PfiQueryFileInfo()*  
- set `Version` to 15 (0xF) in *PfiBuildFileInfoQuery()*  

And that's it !

[![PfiQueryFileInfo_patch](/assets/uploads/2024/05/PfiQueryFileInfo_patch.png)](/assets/uploads/2024/05/PfiQueryFileInfo_patch.png)  

Eventually here is the result, you can *Dump full information about each page in the PFN database* and *Display file names associated to memory mapped pages* : 

[![meminfo_patched](/assets/uploads/2024/05/meminfo_tests_midi12_viking.png)](/assets/uploads/2024/05/meminfo_tests_midi12_viking.png)  

And here it is I hope you learnt something. Thanks for reading, feedbacks are welcome !   

Resources :    
[https://www.microsoftpressstore.com/store/windows-internals-part-1-system-architecture-processes-9780735684188][LINK1]  
[https://www.microsoftpressstore.com/store/windows-internals-part-2-9780135462409][LINK2]  
[https://v1k1ngfr.github.io/winkernel-reverse-ida-ghidra/#intro][LINK9]  
[https://github.com/zodiacon/WindowsInternals/pull/23][LINK10]   
[https://blog.midi12.re/systemsuperfetchinformation/][LINK13]   

[LINK1]: https://www.microsoftpressstore.com/store/windows-internals-part-1-system-architecture-processes-9780735684188  
[LINK2]: https://www.microsoftpressstore.com/store/windows-internals-part-2-9780135462409     
[LINK9]: https://v1k1ngfr.github.io/winkernel-reverse-ida-ghidra/#intro
[LINK10]: https://github.com/zodiacon/WindowsInternals/pull/23   
[LINK13]: https://blog.midi12.re/systemsuperfetchinformation/
