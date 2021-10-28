---
title: 'Loading unsigned Windows drivers without reboot'
date: 2021-10-27
author: "Viking"
layout: post
permalink: /loading-windows-unsigned-driver/
disqus_identifier: 0000-0000-0000-0006
description: "Loading unsigned Windows drivers without reboot. Dive into gdrv-loader source code."
cover: assets/uploads/2021/10/DSE-bypass.png
tags:
  - Windows
  - Kernel
  - Rootkit
translation:
  - en
---

The [previous post][WINLOAD-pmp] exposes how to create a weaponized driver. How can we load this unsigned drivers into the Windows kernel bypassing Driver Signing Enforcement (DSE) ? Here are some details about that.

<!--more-->

**Disclaimer**  
It's clear that the following article :
- does not show any new concepts or techniques
- contains many copy/paste from Microsoft official documentation, not for paraphrase purpose but having all needed information in the same place. Don't worry, web links will drive you to the original information.  

This article is a kind of memo aiming at remember which function to use when developing kernel-related stuff. I'm not sure about the first person who published this (*alxbrn* or  *fengjixuchui* ?) but thanks for kindly providing [gdrv-loader][WINLOAD-gdrv-loader] !

## Intro
In the [part 1 (pimp-my-pid)][WINLOAD-pmp], we discovered how to create a Windows driver. It's frustrating to see your driver working but not being able to load it without modifying boot options (enabling debug) and reboot. To workaround this problem here is the plan :
1. getting sufficient privileges, like SeLoadDriverPrivilege (this point is out of scope but here is an interesting [blog][WINLOAD-seloadblog] / [code][WINLOAD-seloadcode] from Oscar Mallo - Taglogic) or running as Administrator
2. load vulnerable signed driver
3. abuse signed driver to set driver enforcement to false
4. load a rootkit (ie: pimpmypid.sys driver)
5. enjoy PimpMyPid features

**Note** : we will only focus on Windows version >= 8 (ie : Win10, Win2012srv, and above).  

As those techniques exists for a while, we do not have to reinvent the wheel : the *gdrv-loader* is a good choice because of its way of working and code clarity / quality. We will reverse the loader (aka vulnerable driver / grdv.sys) in order to clearly understand what's happening, then dive into *gdrv-loader* C++ code and use Windbg for kernel debug purpose. In short, understanding how to safely set "g_CiOptions" to zero. 

Wait, what ? A whole blogpost just for setting a value to zero ? Hmmm not so simple when dealing with an OS kernel, you'd better knowing what you're doing : remember BSOD is never far away when writing somewhere in kernel-space...

## Warm-up  

### Key concepts  
Let's extract some definitions from official [Microsoft documentation][WINLOAD-sectionviews] :  

- **What is a section ?** : 
  - A *section* object represents a section of memory that can be shared.
  - Section objects also provide the mechanism by which a process can map a file into its memory address space. 

- **What is a View ?** : A *view* is a part of the section that is actually visible to a process.  

- **What is Mapping ?** : The act of creating a view for a section is known as *mapping.*  

- **What about the PE Header Format ?**
Before reading *gdrv-loader* source code, we will need to highlight some details about NT Headers. Lets summarize interesting keypoints using the figure below.  

[![winload_IMAGE_NT_structure](/assets/uploads/2021/10/winload_IMAGE_NT_structure.png)](/assets/uploads/2021/10/winload_IMAGE_NT_structure.png)

The [IMAGE_NT_HEADERS32 structure (winnt.h)][WINLOAD-imgntheader] represents the PE header format, which contains the field named [OptionalHeader][WINLOAD-imgntopthead] were we can find the ImageBase value. This particular value is useful when we want to reach a DLL (for example the ci.dll file) mapped into memory because it specifies *the preferred address of the first byte of the image*.

### First trip in memory
Ok it clearly doesn't represent the actual *ci.dll* file we will mapped in the next chapter but it gives an idea of the memory layout : in order to visualize a mapped file we could open Immunity debugger and look at some random DLL already loaded by Windows.  
Here is for example the ntdll.dll memory areas we can observe once loaded in memory :

- The memory map contains several **sections** : .text, .data, etc
[![NTDLL 2](/assets/uploads/2021/10/ntdll_2memmap.png)](/assets/uploads/2021/10/ntdll_2memmap.png)

- The executable modules shows **ImageBase** values. For example the ntdll base address is at `0x77A90000`
[![NTDLL 1](/assets/uploads/2021/10/ntdll_1execmodules.png)](/assets/uploads/2021/10/ntdll_1execmodules.png)

- The **PE header** can also be watched :
[![NTDLL 3](/assets/uploads/2021/10/ntdll_3PEdmp.png)](/assets/uploads/2021/10/ntdll_3PEdmp.png)

- Eventualy here is a **View** of a section (.text section) :
[![NTDLL 4](/assets/uploads/2021/10/ntdll_4TXTdmp.png)](/assets/uploads/2021/10/ntdll_4TXTdmp.png)

## Understand the gdrv.sys vulnerability
What about understanding the vulnerability before exploiting it ? When looking at the *gdrv-loader* code, we see that IOCTL used by *TriggerExploit* is [IOCTL_GIO_MEMCPY][WINLOAD-DriverReverse] :

[![IOCTL_GIO_MEMCPY](/assets/uploads/2021/10/IOCTL_GIO_MEMCPY.png)](/assets/uploads/2021/10/IOCTL_GIO_MEMCPY.png)

The CTL_CODE function is responsible of the IOCTL calculation :

{% highlight CPP %}
#define CTL_CODE( DeviceType, Function, Method, Access ) (                 \
    ((DeviceType) << 16) | ((Access) << 14) | ((Function) << 2) | (Method) \
)
{% endhighlight %}

The result is a IOCTL_GIO_MEMCPY value set to *0xC3502808*. Ok, Ghidra is a good friend for reversing the loader driver (gdrv.sys) and re-discover the vulnerability which will be triggered. When looking at the *Entry point* we can observe the dispatch routine which contains two main functions :

[![dispatch](/assets/uploads/2021/10/dispatch.png)](/assets/uploads/2021/10/dispatch.png)

When looking more closely at the *FUN_00012d10*, it's a big switch on IOCTL values and our IOCTL_GIO_MEMCPY (0xC3502808) is processed by *FUN_00012860*.

[![ioctlswitch](/assets/uploads/2021/10/ioctlswitch.png)](/assets/uploads/2021/10/ioctlswitch.png)

Ahaha thanks to the *DbgPrint* the reversing is straight forward : this function copy **uVar1** (size) bytes from **lVar4** (Src) to **puVar3** (Dest), it's a memcpy-like as indicated in the researcher [full disclosure (CVE-2018-19320)][WINLOAD-CVE].

[![memcpy](/assets/uploads/2021/10/memcpy.png)](/assets/uploads/2021/10/memcpy.png)

It's not common to observe an exploit running from the exploited point of view :-) Thanks to DebugView we can visualize *gdrv.sys* debug messages when running the TriggerExploit function :

[![debugview](/assets/uploads/2021/10/debugview.png)](/assets/uploads/2021/10/debugview.png)

## Dive into gdrv-loader sources  

### Gdrv-loader main function
The DLL named ci.dll is responsible for Windows Driver Signing Enforcement (DSE) management. In order to disable this feature, the first step is to find the [Ci!g_CiOptions][WINLOAD-DSE1] value set in memory. Helping to find this value, [WindLoadDriver][WINLOAD-WindLoadDriver] is the main function of *gdrv-loader* which calls the following sub-functions :

| Function    | Source code comment |
| ------------- |:-------------|
| **AnalyzeCi** | **Find CI!g_CiOptions/nt!g_CiEnabled** |
| RtlAdjustPrivilege | *Enable privileges* |
| CreateDriverService | *Create the target driver service (twice : loader + rootkit drivers)* |
| **TriggerExploit** |**Disable CI**|
| LoadDriver | *Load target driver* |
| TriggerExploit | *Reset original CI status* |
| UnloadDriver | *Unload the loader driver since we are done with it* |
| DeleteService | *Delete the target driver service (twice : loader + rootkit drivers)* |
| RtlAdjustPrivilege | *Revert privileges* |

Crawling Internet we found many references for some of these topics (adjusting privileges, creating driver service, etc) but we will only dig into highlighted functions.

### Step 1 - Mapping ci.dll in memory
Enough about concepts, open the code right now ! The [MapFileSectionView][WINLOAD-MapFileSectionView] function allows to get the pointer named **MappedBase** pointing at the ci.dll base address. Why is it so important to get this pointer ? Because it will be used later for offset calculation (see "STEP 3" below). The main steps for mapping a DLL file in memory are :  
1. Open the file
2. Put the file content into a buffer
3. Obtain a section handle
4. Mapping the view of the section

Indeed we start using [RtlOpenFile][WINLOAD-rtlopen] allowing to open the **Filename** parameter and get an handle on it. Then by using the [NtReadFile][WINLOAD-ntreadfile] routine, it updates the caller-allocated  **HeadersBuffer** parameter which receives the data read from the file. Good, now the ci.dll content is available in a memory buffer !

The gdrv-loader uses [RtlImageNtHeaderEx][WINLOAD-RtlImageNtHeaderEx] which simply finds the location of NT headers in memory. To be able to get information about the file we need to know if it's x32 or x64. The following line allows to get the correct NtHeaders representation, based on the (NtHeaders)->OptionalHeader.Magic value :   

[![PreferredImageBase](/assets/uploads/2021/10/PreferredImageBase.png)](/assets/uploads/2021/10/PreferredImageBase.png)

Eventualy the section is created using [NtCreateSection][WINLOAD-ntcreatesection] making **SectionHandle** parameter available. Then [NtMapViewOfSection][WINLOAD-viewcreate] maps the view of the section into the virtual address space pointed by **ImageBase** variable (also named **MappedBase** from the caller).  

[![mapsection](/assets/uploads/2021/10/mapsection.png)](/assets/uploads/2021/10/mapsection.png)

**Notes** : 
- if, as I did, you're wondering what's the difference between "**Nt**CreateSection" and "**Zw**CreateSection" : Nt prefix indicates this function occurs in user mode, Zw refers to kernel land
- and if you are wondering what is the value `0x20b` stated in the previous picture, it is documented as the state of the image file (aka `Magic` field) : IMAGE_NT_OPTIONAL_HDR64_MAGIC which means `The file is a 64 bits executable image.`  
- avoiding confusion : when talking about the C:\Windows\System32\ci.dll file we write **ci.dll**. If we are talking about the DLL loaded into the kernel memory then the following typo is used : **Ci.dll**  

  
### Step 2 - Retrieve Ci! kernel module address
In the previous step we mapped ci.dll file. Once Windows boot ends, the Ci kernel module is loaded and available in the kernel memory but how can we locate this memory region ?  

We can read that [FindKernelModule][WINLOAD-FindKernelModule] function starts by using [NtQuerySystemInformation][WINLOAD-NtQuerySystemInformation] which allows to *retrieve a specified system information.*  
The kernel module list is the system information we are looking for so we specify the (undocumented) parameter [SystemModuleInformation][WINLOAD-SystemModuleInformation] and get Ci.dll kernel base address thanks to the following search loop :

[![cimodulehunt](/assets/uploads/2021/10/cimodulehunt.png)](/assets/uploads/2021/10/cimodulehunt.png)

The Ci DLL base address aka **ModuleBase** is in our pocket :-)

[![cimodulehuntres](/assets/uploads/2021/10/cimodulehuntres.png)](/assets/uploads/2021/10/cimodulehuntres.png)


### Step 3 - Hunting the gCiOptions
Ok in the step 1 we got **MappedBase** address which point at the ci.dll mapped into memory, we are happy with that but why do we need this ? Our programs are running userland and we can't interact directly with Ci **ModuleBase** kernel address found in step 2. Remember that we want to set the gCiOptions (located in the kernel memory) to 0x0 : we have to find a way to get the address pointing at this variable !  

One point of detail which is nonetheless important is how the *gCiOptions* value can be retrieved. Fortunatly the Ci kernel module exports CiInitialize function and you know what ? This function uses a routine named **Cip**Initialize which leaks *gCiOptions* address, making offset calculation possible :-)

Wonderful, it's time to go back to *gdrv-loader* source code and digg into [QueryCiOptions][WINLOAD-QueryCiOptions] function. The idea here is to use well known *GetProcedureAddress* Windows API against the ci.dll previously mapped in order to locate *CiInitialize* function entry point. 

[![ciinitializehunt](/assets/uploads/2021/10/ciinitializehunt.png)](/assets/uploads/2021/10/ciinitializehunt.png)


{% highlight CPP %}
const PUCHAR CipInitialize = CiInitialize + c + 5 + Rel; // CipInitialize offset calculation
...
const PUCHAR MappedCiOptions = CipInitialize + c + 6 + Rel; // gCiOptions offset calculation
{% endhighlight %}

We store *gCiOptions* **offset** (pointer) in **MappedCiOptions** variable and an then we use it to calculate the long-awaited **gCiOptionsAddress**.   

[![querycioptionscalc](/assets/uploads/2021/10/querycioptionscalc.png)](/assets/uploads/2021/10/querycioptionscalc.png)

### Launching the exploit

#### Overview of the function triggering the vulnerability
Allright we know **where** we have to write in kernel memory. But, **how** can we write 0x0 to this g_CiOptions address ? That's the [TriggerExploit][WINLOAD-TriggerExploit]'s role. Here is how this function is called from *WindLoadDriver* :

[![TriggerExploit](/assets/uploads/2021/10/trigexpcall.png)](/assets/uploads/2021/10/trigexpcall.png)

The parameters answer several questions :  

- Who help us to **WRITE** in memory and disable DSE ? *LoaderServiceName* - value used : the vulnerable driver named **"gdrv.sys"**
- **WHAT** is the value to set to g_CiOptions ? *CiOptionsValue* : - value used : **0x0** for disabling it !
- **WHERE** is the memory space we want to overwrite ? *CiVariableAddress* - value used : **g_CiOptions** kernel address

The last argument *OldCiOptionsValue* is important because we want to be able to quickly restore the initial g_CiOptions value (0x6 = DSE enabled) : indeed g_CiOptions is protected by PatchGuard which implies Windows is watching over this variable and will bluescreen if it observes the value been modified. 

#### Using Arbitrary ring0 VM read/write

First, what is an *exploit primitive* ? Here is the most simple definition I found on [ret2.io][WINLOAD-primitive]) : **"A primitive refers to an action that an attacker can perform to manipulate or disclose the application runtime (eg, memory) in an unintended way."** The vulnerability described in the previous chapter is powerfull because it allows both reading and writing any kernel space memory ! You may wondering how can we use (aka exploit) those primitives ?  

Thanks to Ghidra (cf. previous chapter) we know the vulnerable function waits for three parameters : Src, Dst and Size. We want the gdrv.sys to understand the data (payload) we provide to it : start by defining the data structure :

[![GIOMemcpyInput](/assets/uploads/2021/10/GIOMemcpyInput.png)](/assets/uploads/2021/10/GIOMemcpyInput.png)

The figure below show how to set up this struct for writing the value pointed by **Src** (CiOptionsValue = 0x0) to the value pointed by **Dst** (CiVariableAddress).

[![GIOMemcpyInput_init](/assets/uploads/2021/10/GIOMemcpyInput_init.png)](/assets/uploads/2021/10/GIOMemcpyInput_init.png)

Eventually the NtDeviceIoControlFile API allows the **MemcpyInput** (aka payload) to reache the driver by invoking the IRP_MJ_DEVICE_CONTROL major function (remember the [previous post][WINLOAD-pimpmythread] about it). The **IOCTL_GIO_MEMCPY** is the key opening the right door (vulnerable gdrv.sys!FUN_00012860) and make TriggerExploit to succeed at disabling DSE !

[![sendingpayload](/assets/uploads/2021/10/sendingpayload.png)](/assets/uploads/2021/10/sendingpayload.png)

Nice !

## Live sessions (aka I want more screenshots)
In the previous chapter we looked at the *gdrv-loader* operating mode. Understanding the code is important but it's time to get a (memory) live view of what's happening using Windbg.  

### Kernel land "debug session"

- Opening Windbg first allows to get the CI! kernel module base address : `fffff801``21a20000`

[![CImodule](/assets/uploads/2021/10/CImodule.png)](/assets/uploads/2021/10/CImodule.png)

- Now we unassemble the CI!CiInitialize function and find the `call CipInitialize` address : `fffff801``21a6315f`.

[![CIinitialize](/assets/uploads/2021/10/CIinitialize.png)](/assets/uploads/2021/10/CIinitialize.png)

- Notice that the **Cip**Initialize symbol name should be resolved but sometimes it doesn't, I don't know why... Let's continue unassembling the **Cip**Initialize (located at `CI!CiInitialize+0x8e4`) and reveal the gCiOptions pointer : `fffff801``21a583b8` `(CI+0x383b8)`

[![CIpinitialize](/assets/uploads/2021/10/CIpinitialize.png)](/assets/uploads/2021/10/CIpinitialize.png)

- Eventually read the value of gCiOptions : we can confirm the value of gCiOptions is *0x6*. 

[![gcioptions](/assets/uploads/2021/10/gcioptions.png)](/assets/uploads/2021/10/gcioptions.png)

As stated by [Fuzzysec][WINLOAD-DSE2] : *"In Windows 8+ g_CiEnabled is replaced by another global variable, g_CiOptions, which is a combination of flags "* :
- 0x0=disabled
- 0x6=enabled
- 0x8=Test Mode

### Userland "debug session"
Using a debugger here would be a little overkill, I use my prefered skill : *set a printf in the code to debug*  ;-) The most important point here is we calculate gCiOptions pointer adress and confirm the result previously displayed using Windbg :

[![gcioptionscalc](/assets/uploads/2021/10/gcioptionscalc.png)](/assets/uploads/2021/10/gcioptionscalc.png)

[![gcioptions2](/assets/uploads/2021/10/gcioptions2.png)](/assets/uploads/2021/10/gcioptions2.png)

### Recap diagram
You know, I love diagram. While I was sometimes lost in kernel memory during debug sessions I made a map to overcome this situation :  

1. We map the ci.dll file in memory and calculate the CiOptions offset
2. We hunt the CI kernel module base address
3. We get the real CiOptionsAddress (base+offset) 
4. We give CiOptionsAddress to the TriggerExploit function  

[![AnalyzeCirecap](/assets/uploads/2021/10/AnalyzeCi.png)](/assets/uploads/2021/10/AnalyzeCi.png)

## Use case : dumping LSASS

Now we understand how gdrv-loader works :-) We can use it to load custom (who said evil ?) drivers like [Pimp my PID][WINLOAD-pmp] !

As you probably know, there [number of ways][WINLOAD-lsass] to dump LSASS process. For the demo we use this technique :

{% highlight cmd %}
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
{% endhighlight %}

The main advantage of this technique is it uses Windows binaries, bypassing many (classical) AV products. Well you can see in the following demo that Windows Defender flag this technique.  
But, wait... Yes, you can (manually :-o) copy the lsass dump before Windefender delete operation : this time we win the race ;-) Note that if you write the lsass dump on a network share you don't have to worry about racing for a "backup" : it won't be deleted.

[![lsassdmp](/assets/uploads/2021/10/lsassdmp.gif)](/assets/uploads/2021/10/lsassdmp.gif)

## How to protect or detect
Well, the common recommandations are :
- driver list whitelisting
- the use of [Hypervisor-Protected Code Integrity][WINLOAD-HVCI] (HVCI).

It seems that the gdrv-loader had been [used by attackers][WINLOAD-ransomware], therefore the gdrv.sys file hash is a must have IOC :

{% highlight cmd %}
C:\Users\User\Documents>CertUtil -hashfile gdrv.sys SHA256
SHA256 hash of gdrv.sys:
31f4cfb4c71da44120752721103a16512444c13c2ac2d857a7e6f13cb679b427
{% endhighlight %}

## Outro

Well, I hope you enjoyed reading this and you learnt something :-) Feel free to give me feedback on Discord (viking#6407).



[WINLOAD-seloadblog]: https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/
[WINLOAD-seloadcode]: https://github.com/TarlogicSecurity/EoPLoadDriver/blob/master/eoploaddriver.cpp
[WINLOAD-pmp]:https://v1k1ngfr.github.io/pimp-my-pid/
[WINLOAD-gdrv-loader]: https://github.com/v1k1ngfr/gdrv-loader/
[WINLOAD-sectionviews]: https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/section-objects-and-views
[WINLOAD-sectioncreate]: https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwcreatesection
[WINLOAD-viewcreate]:https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwmapviewofsection
[WINLOAD-imgntheader]: https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_nt_headers32
[WINLOAD-imgntopthead]: https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_optional_header32
[WINLOAD-rtlopen]: https://github.com/v1k1ngfr/gdrv-loader/blob/master/src/pe.cpp#L67
[WINLOAD-ntreadfile]: https://github.com/v1k1ngfr/gdrv-loader/blob/master/src/pe.cpp#L80
[WINLOAD-ntcreatesection]: https://github.com/v1k1ngfr/gdrv-loader/blob/master/src/pe.cpp#L80
[WINLOAD-RtlImageNtHeaderEx]: https://github.com/v1k1ngfr/gdrv-loader/blob/master/src/pe.cpp#L96
[WINLOAD-WindLoadDriver]: https://github.com/v1k1ngfr/gdrv-loader/blob/master/src/swind2.cpp#L452
[WINLOAD-MapFileSectionView]: https://github.com/v1k1ngfr/gdrv-loader/blob/master/src/swind2.cpp#L191
[WINLOAD-QueryCiOptions]: https://github.com/v1k1ngfr/gdrv-loader/blob/master/src/swind2.cpp#L91
[WINLOAD-FindKernelModule]:https://github.com/v1k1ngfr/gdrv-loader/blob/master/src/swind2.cpp#L27
[WINLOAD-DriverReverse]:https://github.com/v1k1ngfr/gdrv-loader/blob/master/src/swind2.cpp#L408
[WINLOAD-TriggerExploit]:https://github.com/v1k1ngfr/gdrv-loader/blob/master/src/swind2.cpp#L358
[WINLOAD-DSE1]: https://j00ru.vexillium.org/2010/06/insight-into-the-driver-signature-enforcement/
[WINLOAD-DSE2]: https://www.fuzzysecurity.com/tutorials/28.html
[WINLOAD-NtQuerySystemInformation]: https://docs.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntquerysysteminformation
[WINLOAD-SystemModuleInformation]: http://undocumented.ntinternals.net/index.html?page=UserMode%2FStructures%2FSYSTEM_MODULE_INFORMATION.html
[WINLOAD-HVCI]: https://docs.microsoft.com/en-us/windows-hardware/drivers/bringup/device-guard-and-credential-guard
[WINLOAD-ransomware]: https://news.sophos.com/en-us/2020/02/06/living-off-another-land-ransomware-borrows-vulnerable-driver-to-remove-security-software/
[WINLOAD-CVE]: https://seclists.org/fulldisclosure/2018/Dec/39
[WINLOAD-primitive]: https://blog.ret2.io/2018/07/11/pwn2own-2018-jsc-exploit/
[WINLOAD-pimpmythread]: https://v1k1ngfr.github.io/pimp-my-pid/#first-simple-driver--pimpmythread
[WINLOAD-lsass]: https://www.picussecurity.com/resource/blog/picus-10-critical-mitre-attck-techniques-t1003-credential-dumping
