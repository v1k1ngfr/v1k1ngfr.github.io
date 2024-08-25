---
title: 'The SuperFetch Query superpower'
date: 2024-08-25
author: "Viking"
layout: post
permalink: /superfetchquery-superpower/
disqus_identifier: 0000-0000-0000-0020
description: ""
cover: assets/uploads/2024/08/SuperFetchQuery-Superpower.png
tags:
  - Windows
  - Exploit Dev
  - Privesc
  - Maldev
translation:
  - en
---

In the previous blogpost - [Fixing (Windows Internals) Meminfo.exe][LINK16] - we dig into the tool Meminfo.exe from Windows Internals Book highlighting "FileInfo requests". I suggest you take a look at some details about another type of request named "SuperFetchQuery" which can be useful for some scenarios like Red Team / Privesc, Pentest, Exploit Dev or Maldev. Let's take a look !  

<!--more-->

## TL;DR   

The **superfetch queries** and [**fileInfo requests**][LINK18] are alternatives methods that allow you to get many Windows interesting information, here are some use case :  

- Maldev : VM sandbox detection trick, get information on memory layout and file names associated to memory mapped pages  
- Red Team / Privesc : get virtual addresses translated into physical addresses, useful when exploiting physical R/W primitives in BYOVD scenarios   
- Pentest : evading some detection areas, for example when enumerating running process list 
- Exploit Dev : get kernel addresses leaks in KASLR bypass scenarios 

*Note : stuffs below tested on Microsoft Windows Version 10.0.19045.4291*

## Superfetch query 101 
 
 The best tool I found for investigating superfetch queries is the Windows Internals [MemInfo project][LINK3] by Alex Ionescu and Pavel Yosifovich, here is what you can do with it:  

```
 MemInfo v3.10 - Show PFN database information
Copyright (C) 2007-2017 Alex Ionescu and Pavel Yosifovich
http://www.windows-internals.com

usage: meminfo [-a][-u][-c][-r][-s][-w][-f][-o PID][-p PFN][-v VA]
    -a    Dump full information about each page in the PFN database
    -u    Show summary page usage information for the system
    -c    Display detailed information about the prioritized page lists
    -r    Show valid physical memory ranges detected
    -s    Display summary information about the pages on the system
    -w    Show detailed page usage information for private working sets
    -f    Display file names associated to memory mapped pages
    -o    Display information about each page in the process' working set
    -p    Display information on the given page frame index (PFN)
    -v    Display information on the given virtual address (must use -o)
```  

Overview of *[MemInfo.cpp main][LINK4]* (only functions useful for the rest of this blogpost are noted):  

```cpp
int main(int argc, const char* argv[]) {
  // EXAMPLE 1 - Query memory ranges
  status = PfiQueryMemoryRanges();

  // EXAMPLE 2 - Initialize the database
  status = PfiInitializePfnDatabase();
  
  // EXAMPLE 3 - Query sources 
  status = PfiQueryPrivateSources();

  // EXAMPLE 4 - Query files
  status = PfiQueryFileInfo();
  
  return 0;
}
```  
In order to retrieve information, each of those "EXAMPLES" uses two steps :  

1. build the query
2. send the query to the kernel
 
Step 1 - the **PfiBuildSuperfetchInfo** function builds the superfetch query using 4 parameters :   

- `SuperfetchInfo` variable stores the REQUEST you send to the kernel   
- `Buffer` variable stores the RESULT received from the kernel
- `Length` variable stores the size of `Buffer`  
- `InfoClass` variable stores the TYPE of information you are looking for


```cpp  
void PfiBuildSuperfetchInfo(
  IN PSUPERFETCH_INFORMATION SuperfetchInfo,
  IN PVOID Buffer,
  IN ULONG Length,
  IN SUPERFETCH_INFORMATION_CLASS InfoClass);
```  

Step 2 - the **NtQuerySystemInformation** Windows API send the superfetch query to the kernel using 4 parameters :

- `SystemInformationClass` variable indicate the kind of system information to be retrieved (set to *SystemSuperfetchInformation*)  
- `SystemInformation` variable points to a buffer that receives the requested information (set to `SuperfetchInfo` prepared in step 1)  
- `Length` variable stores the size of `SystemInformation`
- `ResultLength` the actual size of the information requested  

```cpp  
extern "C" NTSTATUS NTAPI NtQuerySystemInformation(
	IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
	OUT PVOID SystemInformation,
	IN ULONG Length,
	OUT PULONG ResultLength
);
```  

**NtQuerySystemInformation** requires a medium integrity process.  


## About superfetch query "superpower"

Now you are familiar with preparing and sending a superfetch query let's take some examples and look at the opportunities available to you. In the next part you will remember some classical methods used for "situational awareness" purposes and discover alternatives based on superfetch queries. 

For anyone (like me) getting confused by all the structures, some diagrams show how all these data structures fit together (maybe helping you to visualize which information becomes reachable and can be retrieved). Just click on it for zooming !   

## Superfetch query superpower n°1 : VM sandbox detection  

### Usual method   

An interesting sandbox detection trick uses memory ranges, more details are available in the article [VM Detection Tricks][LINK6] By Graham Sutherland. In a nutshell this technique :  

- reads the following Windows registry paths   

```
HKLM\Hardware\ResourceMap\System Resources\Loader Reserved\
HKLM\Hardware\ResourceMap\System Resources\Physical Memory\
HKLM\Hardware\ResourceMap\System Resources\Reserved\
```

- compares the memory resource maps from various physical hosts and VMs, for example :

| Type | OS/Platform | Assigned RAM | Physical Memory Range |
| Host 1 | Win10 x64 | N/A | [00001000 – 0003e000] [5acf6000 – 66e71000] |
| VM2 | Win10 x64 (Hyper-V) | Dynamic | [00001000 – 000a0000] |
| VM5 | Win10 x64 (VirtualBox) | 4GB | [00001000 – 0009f000] |
| VM9 | Win7 x86* (VirtualBox) | 2GB | [00001000 – 0009f000] [00100000 – 7fff0000] |

### Superfetch method   

Using this alternative won't touch Windows registry keys listed above thus removing a detection area. In the following example you use a superfetch query retrieving the valid physical memory ranges detected on your current running Windows.   

Interesting piece of code in Meminfo project :   

```cpp
// Extract from WindowsInternals/MemInfo/MemInfo.cpp
//
// DATA STRUCTURES
//
#define SUPERFETCH_VERSION      45
#define SUPERFETCH_MAGIC        'kuhC'

typedef struct _PF_PHYSICAL_MEMORY_RANGE {
	ULONG_PTR BasePfn;
	ULONG_PTR PageCount;
} PF_PHYSICAL_MEMORY_RANGE, *PPF_PHYSICAL_MEMORY_RANGE;

typedef struct _PF_MEMORY_RANGE_INFO {
	ULONG Version;
	ULONG RangeCount;
	PF_PHYSICAL_MEMORY_RANGE Ranges[ANYSIZE_ARRAY];
} PF_MEMORY_RANGE_INFO, *PPF_MEMORY_RANGE_INFO;

typedef enum _SUPERFETCH_INFORMATION_CLASS {
	SuperfetchMemoryRangesQuery = 17,   // Query
} SUPERFETCH_INFORMATION_CLASS;

//  System Information Classes for NtQuerySystemInformation
typedef enum _SYSTEM_INFORMATION_CLASS {
	SystemBasicInformation,
	SystemSuperfetchInformation = 79,
} SYSTEM_INFORMATION_CLASS;

//
// HELPER FUNCTION
//
void PfiBuildSuperfetchInfo(IN PSUPERFETCH_INFORMATION SuperfetchInfo, IN PVOID Buffer, IN ULONG Length, IN SUPERFETCH_INFORMATION_CLASS InfoClass) {
	SuperfetchInfo->Version = SUPERFETCH_VERSION;
	SuperfetchInfo->Magic = SUPERFETCH_MAGIC;
	SuperfetchInfo->Data = Buffer;
	SuperfetchInfo->Length = Length;
	SuperfetchInfo->InfoClass = InfoClass;
}

//
// GET INFORMATION
//
NTSTATUS PfiQueryMemoryRanges() {
	NTSTATUS Status;
	SUPERFETCH_INFORMATION SuperfetchInfo;
	PF_MEMORY_RANGE_INFO MemoryRangeInfo;
	ULONG ResultLength = 0;

	//
	// Memory Ranges API was added in RTM, this is Version 1
	//
	MemoryRangeInfo.Version = 1;

	//
	// Build the Superfetch Information Buffer
	//
	PfiBuildSuperfetchInfo(&SuperfetchInfo,
		&MemoryRangeInfo,
		sizeof(MemoryRangeInfo),
		SuperfetchMemoryRangesQuery);

	//
	// Query the Memory Ranges
	//
	Status = NtQuerySystemInformation(SystemSuperfetchInformation,
		&SuperfetchInfo,
		sizeof(SuperfetchInfo),
		&ResultLength);
	if (Status == STATUS_BUFFER_TOO_SMALL) {
		//
		// Reallocate memory
		//
		MemoryRanges = static_cast<PPF_MEMORY_RANGE_INFO>(::HeapAlloc(GetProcessHeap(), 0, ResultLength));
		MemoryRanges->Version = 1;

		//
		// Rebuild the buffer
		//
		PfiBuildSuperfetchInfo(&SuperfetchInfo,
			MemoryRanges,
			ResultLength,
			SuperfetchMemoryRangesQuery);

		//
		// Query memory information
		//
		Status = NtQuerySystemInformation(SystemSuperfetchInformation,
			&SuperfetchInfo,
			sizeof(SuperfetchInfo),
			&ResultLength);
		if (!NT_SUCCESS(Status)) {
			printf("Failure querying memory ranges!\n");
			return Status;
		}
	}
	else {
		//
		// Use local buffer
		//
		MemoryRanges = &MemoryRangeInfo;
	}

	return STATUS_SUCCESS;
}
```  

Keypoints :  
- Meminfo function : **PfiQueryMemoryRanges**
- superfetch query type : *SuperfetchMemoryRangesQuery* 
- superfetch query result :  stored in `MemoryRangeInfo` 
- data available : PF_PHYSICAL_MEMORY_RANGE + PF_MEMORY_RANGE_INFO data structures   

(click on image to zoom in)   
[![PfiQueryMemoryRanges.drawio.png](/assets/uploads/2024/08/PfiQueryMemoryRanges.drawio.png)](/assets/uploads/2024/08/PfiQueryMemoryRanges.drawio.png)  

You can use `MemoryRangeInfo` content to retrieve `Ranges` values and add "detection", for example just modifying **PfiQueryMemoryRanges**.  

Modified piece of code in Meminfo project :   

```cpp
void PfiDumpPfnRanges(VOID) {
[ snip ]
		//
		// Print information on the range
		//
		Node = reinterpret_cast<PPHYSICAL_MEMORY_RUN>(&MemoryRanges->Ranges[i]);
#ifdef _WIN64
		printf("Physical Memory Range: %p to %p (%lld pages, %lld KB)\n",
#else
		printf("Physical Memory Range: %p to %p (%d pages, %d KB)\n",
#endif
			reinterpret_cast<void*>(Node->BasePage << PAGE_SHIFT),
			reinterpret_cast<void*>((Node->BasePage + Node->PageCount) << PAGE_SHIFT),
			Node->PageCount,
			(Node->PageCount << PAGE_SHIFT) >> 10);
		// print detected sandbox - quick and dirty code...
		if ((reinterpret_cast<void*>(Node->BasePage << PAGE_SHIFT) == (void*)0x1000)
			&&(reinterpret_cast<void*>((Node->BasePage + Node->PageCount) << PAGE_SHIFT) == (void*)0x9F000)) {
			printf("!! SANDBOX DETECTED : VM5 - 4G - Win10 x64 (VirtualBox)\n");
		}
[snip]
}
```

This will give you the output below. As you can see, the "Physical Memory Range" is 00001000 – 0009f000 : you can check this value in the "Graham Sutherland results" listed in the previous paragraph and deduce that I'm running Win10 x64 on VirtualBox.   

```
C:\windows\system32>C:\MemInfo.exe -r
MemInfo v3.10 - Show PFN database information
Copyright (C) 2007-2017 Alex Ionescu and Pavel Yosifovich
http://www.windows-internals.com

Physical Memory Range: 0000000000001000 to 000000000009F000 (158 pages, 632 KB)
!! SANDBOX DETECTED : VM5 - 4G - Win10 x64 (VirtualBox)
Physical Memory Range: 0000000000100000 to 0000000000102000 (2 pages, 8 KB)
Physical Memory Range: 0000000000103000 to 00000000DFFF0000 (917229 pages, 3668916 KB)
Physical Memory Range: 0000000100000000 to 0000000220000000 (1179648 pages, 4718592 KB)
MmHighestPhysicalPage: 2228224

```      

## Superfetch query superpower n°2 : virtual to physical address translation  

When dealing with physical addresses (PA), you must find a way to translate to the corresponding virtual addresses (VA) because the OS manipulate VA for both kernel and userland. The way in which Windows achieves this translation is well documented, for example in ["Windows Internals, Part 1"][LINK1] the **Chapter 5 - Memory management** which explains all you need to know, more specifically both sections named **Address translation** and **Page frame number database**. You can also read the comprehensive [Turning the Pages: Introduction to Memory Paging on Windows 10 x64][LINK17] by Connor McGarr.

### Usual methods   

When exploiting Windows kernel vulnerabilities some exploit primitives are physical read / write. In this case you need a method for translating VA into PA (or PA into VA).  

The probably oldest technique was reading the kernel land page tables to determine the VA-PA mapping, but Microsoft patched this since Windows 10.   

Another technique consists of finding CR3 in a structure named KSPECIAL_REGISTERS by reading in sequence the DOS "Low Stub" located in the area of physical memory between 0-0x20000. More details are described in [Kernel Talks 0x03 - Exploiting LOLDrivers (part1) Physical Memory Mayhem](/assets/uploads/2024/08/0x003-exploitingloldrivers-physicalmemorymayhem.pdf) by Russell Sanford. This technique seems risky now because I encountered some issues while testing it, for example :   

- Bug Check 0xD1: DRIVER_IRQL_NOT_LESS_OR_EQUAL
- Bug Check 0x1A: MEMORY_MANAGEMENT
- Bug check 0xA: IRQL_NOT_LESS_OR_EQUAL
- Bug Check 0x3B: SYSTEM_SERVICE_EXCEPTION
- Bug Check 0x139: KERNEL_SECURITY_CHECK_FAILURE
- Bug Check 0x7E: SYSTEM_THREAD_EXCEPTION_NOT_HANDLED   

See [Bug Check Code Reference][LINK8] for details.

Last example of well-known technique is scanning the non-paged pool allocations targeting only the pool tag named 'Proc', which purpose is to store process objects in kernel memory. The idea is to locate the structure named `KPROCESS` and retrieve the *DirectoryTableBase* field (CR3 register value for the process).  
But there are some limitations here :  
- you need a memory leak (which is not a big deal when having admin privileges, thanks to NtQuerySystemInformation) 
- you must be able to scan kernel VA space (implies to have a kernel arbitrary READ primitive)
- it is just the starting point of "pointer to pointer jumping" game if your target is not a process (you must find a way to reach the memory area you are interested in, which can be tricky)  

### Superfetch method   

As stated by Cedric Van Bockhaven in [Mapping Virtual to Physical Addresses Using Superfetch][LINK7], using superfetch for exploit development is not new but I think this technique need more visibility on Internet because this alternative has (at least) the following advantages :  
- more stable, using official Windows API  
- less BSOD risk, staying userland   

Interesting piece of code in Meminfo project :   

```cpp
// Extract from WindowsInternals/MemInfo/MemInfo.cpp
//
// DATA STRUCTURES & GLOBAL VARIABLES
//
#define SUPERFETCH_VERSION      45
#define SUPERFETCH_MAGIC        'kuhC'

typedef struct _MMPFN_IDENTITY {
	union {
		MEMORY_FRAME_INFORMATION e1;
		FILEOFFSET_INFORMATION e2;
		PAGEDIR_INFORMATION e3;
		UNIQUE_PROCESS_INFORMATION e4;
	} u1;
	SIZE_T PageFrameIndex;
	union {
		struct {
			ULONG Image : 1;
			ULONG Mismatch : 1;
		} e1;
		PVOID FileObject;
		PVOID UniqueFileObjectKey;
		PVOID ProtoPteAddress;
		PVOID VirtualAddress;
	} u2;
} MMPFN_IDENTITY, *PMMPFN_IDENTITY;

typedef struct _PF_PFN_PRIO_REQUEST {
	ULONG Version;
	ULONG RequestFlags;
	SIZE_T PfnCount;
	SYSTEM_MEMORY_LIST_INFORMATION MemInfo;
	MMPFN_IDENTITY PageData[256];
} PF_PFN_PRIO_REQUEST, *PPF_PFN_PRIO_REQUEST;

typedef enum _SUPERFETCH_INFORMATION_CLASS {
	SuperfetchPfnQuery = 6,             // Query
} SUPERFETCH_INFORMATION_CLASS;

//  System Information Classes for NtQuerySystemInformation
typedef enum _SYSTEM_INFORMATION_CLASS {
	SystemBasicInformation,
	SystemSuperfetchInformation = 79,
} SYSTEM_INFORMATION_CLASS;

PPF_PFN_PRIO_REQUEST MmPfnDatabase;

//
// HELPER FUNCTION
//
void PfiBuildSuperfetchInfo(IN PSUPERFETCH_INFORMATION SuperfetchInfo, IN PVOID Buffer, IN ULONG Length, IN SUPERFETCH_INFORMATION_CLASS InfoClass) {
	SuperfetchInfo->Version = SUPERFETCH_VERSION;
	SuperfetchInfo->Magic = SUPERFETCH_MAGIC;
	SuperfetchInfo->Data = Buffer;
	SuperfetchInfo->Length = Length;
	SuperfetchInfo->InfoClass = InfoClass;
}

//
// GET INFORMATION
//
NTSTATUS PfiInitializePfnDatabase() {
	NTSTATUS Status;
	SUPERFETCH_INFORMATION SuperfetchInfo;
	ULONG ResultLength = 0;
	PMMPFN_IDENTITY Pfn1;
	ULONG PfnCount, i, k;
	ULONG PfnOffset = 0;
	ULONG BadPfn = 0;
	PVOID BitMapBuffer;
	PPF_PFN_PRIO_REQUEST PfnDbStart;
	PPHYSICAL_MEMORY_RUN Node;
	//
	// Calculate maximum amount of memory required
	//
	PfnCount = MmHighestPhysicalPageNumber + 1;
	MmPfnDatabaseSize = FIELD_OFFSET(PF_PFN_PRIO_REQUEST, PageData) +
		PfnCount * sizeof(MMPFN_IDENTITY);
	//
	// Build the PFN List Information Request
	//
	PfnDbStart = MmPfnDatabase = static_cast<PPF_PFN_PRIO_REQUEST>(HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, MmPfnDatabaseSize));
	MmPfnDatabase->Version = 1;
	MmPfnDatabase->RequestFlags = 1;
	//
	// Build the Superfetch Query
	//
	PfiBuildSuperfetchInfo(&SuperfetchInfo,
		MmPfnDatabase,
		MmPfnDatabaseSize,
		SuperfetchPfnQuery);

#if 1
	//
	// Initial request, assume all bits valid
	//
	for (ULONG i = 0; i < PfnCount; i++) {
		//
		// Get the PFN and write the physical page number
		//
		Pfn1 = MI_GET_PFN(i);
		Pfn1->PageFrameIndex = i;
	}

	//
	// Build a bitmap of pages
	//
	BitMapBuffer = ::HeapAlloc(::GetProcessHeap(), 0, PfnCount / 8);
	RtlInitializeBitMap(&MmPfnBitMap, static_cast<PULONG>(BitMapBuffer), PfnCount);
	RtlSetAllBits(&MmPfnBitMap);
	MmVaBitmap = MmPfnBitMap;
#endif

	//
	// Loop all the ranges
	//
	for (k = 0, i = 0; i < MemoryRanges->RangeCount; i++) {
		//
		// Print information on the range
		//
		Node = reinterpret_cast<PPHYSICAL_MEMORY_RUN>(&MemoryRanges->Ranges[i]);
		for (SIZE_T j = Node->BasePage; j < (Node->BasePage + Node->PageCount); j++) {
			//
			// Get the PFN and write the physical page number
			//
			Pfn1 = MI_GET_PFN(k++);
			Pfn1->PageFrameIndex = j;
		}
	}
	//
	// Query all valid PFNs
	//
	MmPfnDatabase->PfnCount = k;
	//
	// Query the PFN Database
	//
	Status = NtQuerySystemInformation(SystemSuperfetchInformation,
		&SuperfetchInfo,
		sizeof(SuperfetchInfo),
		&ResultLength);

	return Status;
}
```  

Keypoints :  
- Meminfo function : **PfiInitializePfnDatabase**
- superfetch query type : *SuperfetchPfnQuery* 
- superfetch query result :  stored in `MmPfnDatabase` 
- data available : PF_PFN_PRIO_REQUEST + MMPFN_IDENTITY + MEMORY_FRAME_INFORMATION + UNIQUE_PROCESS_INFORMATION data structures

(click on image to zoom in)   
[![PfiInitializePfnDatabase.drawio](/assets/uploads/2024/08/PfiInitializePfnDatabase.drawio.png)](/assets/uploads/2024/08/PfiInitializePfnDatabase.drawio.png)  

You can use `MmPfnDatabase` content to retrieve `VirtualAddress` (VA) and `pageFrameIndex` (PA) values and add "translation", for example just modifying **PfiDumpProcessPfnEntry** function.  

Modified piece of code in Meminfo project :   

```cpp
VOID
PfiDumpProcessPfnEntry(ULONG i) {
[ snip ]
	/*
	printf("0x%08p %-11s %d %-10s %-11s %-23s %-7s\n",
		Pfn1->PageFrameIndex << PAGE_SHIFT,
		ShortPfnList[Pfn1->u1.e1.ListDescription],
		(UCHAR)Pfn1->u1.e1.Priority,
		VirtualAddress,
		Type,
		Protect,
		Usage);
	*/
	// print only translation information about process
	printf("VirtualAddress %-10s content is stored at physical address 0x%08p\n",
		VirtualAddress,
		Pfn1->PageFrameIndex << PAGE_SHIFT);
[snip]
}
```

This will give you the output below for a specific process, but you can of course adapt this code to translate any address.  

```
C:\>tasklist | findstr notepad.exe
notepad.exe                   7900 Console                    1     16,296 K

C:\> MemInfo.exe -o 7900
MemInfo v3.10 - Show PFN database information
Copyright (C) 2007-2017 Alex Ionescu and Pavel Yosifovich
http://www.windows-internals.com

Initializing PFN database... Done.

Memory pages for process 3900 (F3C)
Address            List        P VA                 Type        Protection              Usage
VirtualAddress 0x00007FFF72062000 content is stored at physical address 0x0000000149E46000
VirtualAddress 0x0000026762573000 content is stored at physical address 0x00000001A8374000
VirtualAddress 0x00007FFF6DFE3000 content is stored at physical address 0x00000001A8398000
VirtualAddress 0x000002675E351000 content is stored at physical address 0x00000001A839A000
VirtualAddress 0x000002675E3F0000 content is stored at physical address 0x00000001AF68B000
VirtualAddress 0x000002675FCC7000 content is stored at physical address 0x00000001AF752000
VirtualAddress 0x000002675E401000 content is stored at physical address 0x00000001AF770000
VirtualAddress 0x000002675E3ED000 content is stored at physical address 0x00000001AF784000
VirtualAddress 0x000002675FCC8000 content is stored at physical address 0x00000001B1254000
VirtualAddress 0x00007FFF6DA32000 content is stored at physical address 0x00000001B1B53000
VirtualAddress 0x00007FFF64FE8000 content is stored at physical address 0x00000001C1B55000
VirtualAddress 0x00007FFF64FE6000 content is stored at physical address 0x00000001C1B56000
[snip]
```   

### Visualization using Windbg (optional) 
*Note : this paragraph is just a personal note, giving a summary of kernel-mode debugging methodology - feel free to skip this part as it's not very useful for the subject at hand*  

In the example above you get VA to PA translation for the notepad.exe process (PID 7900). The first line shows VA `0x7FFF72062000` translated into PA `0x149e46000`. You can verify this translation by using Windbg, here's how :  

1. retrieve information from the target process :  
`kd> !process 0 0 notepad.exe`  
2. set the process context to target process : `FFFFBD8B172E9080`   
`kd> .process FFFFBD8B172E9080`
3. use the process's directory table base `1c9050000` to convert the virtual address `00007FFF72062000` to corresponding physical address   
*(important : do not include the backtick from Windbg output, for example do not use this format 00007FFF\`72062000)*   
`kd> !vtop 1c9050000 0x00007FFF72062000`

[![windbg_vtop](/assets/uploads/2024/08/windbg_vtop.png)](/assets/uploads/2024/08/windbg_vtop.png)  

Any doubts about the result ? You can check by looking at the content of the memory  :  
- display hexadecimal bytes at VA `0x00007FFF72062000` in the context of notepad process   
`kd> .process FFFFBD8B172E9080; db 0x00007FFF72062000`  

- compare with bytes contained at the translated PA `149e46000`  
*(important : you must prefix db with a "!")*  
`kd> !db 149e46000`  

Any doubts about the PID of the process you're debugging (ex : several processes with the same name) ? You can verify the decimal value of the target process matches the hex value of PROCESS Client ID :   
- the decimal value of notepad.exe PID is `7900` -  equivalent to Cid `1edc`   
*(important : you must prefix with "0n" because Windbg uses hex by default)*  
`kd> .formats 0n7900`  


## Superfetch query superpower n°3 : running processes enumeration   

### Usual method   

Yes there are many ways to enumerate running processes or find a specific PID, you can choose one listed by @modexpblog in [Fourteen Ways to Read the PID for the Local Security Authority Subsystem Service (LSASS)][LINK5].  
  
### Superfetch method   

In the following example you use a superfetch query retrieving the processes informations running currently on your Windows.

Interesting piece of code in Meminfo project :   

```cpp  
// Extract from WindowsInternals/MemInfo/MemInfo.cpp
//
// DATA STRUCTURES & GLOBAL VARIABLES
//
typedef struct _SUPERFETCH_INFORMATION {
	ULONG Version;
	ULONG Magic;
	SUPERFETCH_INFORMATION_CLASS InfoClass;
	PVOID Data;
	ULONG Length;
} SUPERFETCH_INFORMATION, *PSUPERFETCH_INFORMATION;

// Private Source Entry
typedef struct _PF_PRIVSOURCE_INFO {
	PFS_PRIVATE_PAGE_SOURCE DbInfo;
	PVOID EProcess;
	SIZE_T WorkingSetPrivateSize;
	SIZE_T NumberOfPrivatePages;
	ULONG SessionID;
	CHAR ImageName[16];

	union {
		ULONG_PTR WsSwapPages;                 // process only PF_PRIVSOURCE_QUERY_WS_SWAP_PAGES.
		ULONG_PTR SessionPagedPoolPages;       // session only.
		ULONG_PTR StoreSizePages;              // process only PF_PRIVSOURCE_QUERY_STORE_INFO.
	};
	ULONG_PTR WsTotalPages;         // process/session only.
	ULONG DeepFreezeTimeMs;         // process only.
	ULONG ModernApp : 1;            // process only.
	ULONG DeepFrozen : 1;           // process only. If set, DeepFreezeTimeMs contains the time at which the freeze occurred
	ULONG Foreground : 1;           // process only.
	ULONG PerProcessStore : 1;      // process only.
	ULONG Spare : 28;

} PF_PRIVSOURCE_INFO, *PPF_PRIVSOURCE_INFO;

// Query Data Structure for SuperfetchPrivSourceQuery
typedef struct _PF_PRIVSOURCE_QUERY_REQUEST {
	ULONG Version;
	ULONG Flags;
	ULONG InfoCount;
	PF_PRIVSOURCE_INFO InfoArray[ANYSIZE_ARRAY];
} PF_PRIVSOURCE_QUERY_REQUEST, *PPF_PRIVSOURCE_QUERY_REQUEST;

// Superfetch Information Class
typedef enum _SUPERFETCH_INFORMATION_CLASS {
	SuperfetchPrivSourceQuery = 8,      // Query
} SUPERFETCH_INFORMATION_CLASS;

//  System Information Classes for NtQuerySystemInformation
typedef enum _SYSTEM_INFORMATION_CLASS {
	SystemBasicInformation,
	SystemSuperfetchInformation = 79,
} SYSTEM_INFORMATION_CLASS;
//
// HELPER FUNCTION
//
void PfiBuildSuperfetchInfo(IN PSUPERFETCH_INFORMATION SuperfetchInfo, IN PVOID Buffer, IN ULONG Length, IN SUPERFETCH_INFORMATION_CLASS InfoClass) {
	SuperfetchInfo->Version = SUPERFETCH_VERSION;
	SuperfetchInfo->Magic = SUPERFETCH_MAGIC;
	SuperfetchInfo->Data = Buffer;
	SuperfetchInfo->Length = Length;
	SuperfetchInfo->InfoClass = InfoClass;
}

PPF_PRIVSOURCE_QUERY_REQUEST MmPrivateSources;

//
// GET INFORMATION
//
NTSTATUS PfiQueryPrivateSources() {
	NTSTATUS Status;
	SUPERFETCH_INFORMATION SuperfetchInfo;
	PF_PRIVSOURCE_QUERY_REQUEST PrivateSourcesQuery = { 0 };
	ULONG ResultLength = 0;

	/* Version 2 for Beta 2, Version 3 for RTM */
	PrivateSourcesQuery.Version = 8; //3;

	PfiBuildSuperfetchInfo(&SuperfetchInfo,
		&PrivateSourcesQuery,
		sizeof(PrivateSourcesQuery),
		SuperfetchPrivSourceQuery);

	Status = NtQuerySystemInformation(SystemSuperfetchInformation,
		&SuperfetchInfo,
		sizeof(SuperfetchInfo),
		&ResultLength);
	if (Status == STATUS_BUFFER_TOO_SMALL) {
		MmPrivateSources = static_cast<PPF_PRIVSOURCE_QUERY_REQUEST>(::HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, ResultLength));
		MmPrivateSources->Version = 8;

		PfiBuildSuperfetchInfo(&SuperfetchInfo,
			MmPrivateSources,
			ResultLength,
			SuperfetchPrivSourceQuery);

		Status = NtQuerySystemInformation(SystemSuperfetchInformation,
			&SuperfetchInfo,
			sizeof(SuperfetchInfo),
			&ResultLength);
		if (!NT_SUCCESS(Status)) {
			printf("Superfetch Information Query Failed\n");
		}
	}

	//
	// Loop the private sources
	//
	for (ULONG i = 0; i < MmPrivateSources->InfoCount; i++) {
		//
		// Make sure it's a process
		//
		if (MmPrivateSources->InfoArray[i].DbInfo.Type == PfsPrivateSourceProcess) {
			//
			// Do we already know about this process?
			//
			PPF_PROCESS Process;
			CLIENT_ID ClientId;
			OBJECT_ATTRIBUTES ObjectAttributes;
			Process = PfiFindProcess(reinterpret_cast<ULONGLONG>(MmPrivateSources->InfoArray[i].EProcess));
			if (!Process) {
				//
				// We don't, allocate it
				//
				Process = static_cast<PPF_PROCESS>(::HeapAlloc(::GetProcessHeap(), 0, sizeof(PF_PROCESS) +
					MmPrivateSources->InfoArray[i].NumberOfPrivatePages * sizeof(ULONG)));
				InsertTailList(&MmProcessListHead, &Process->ProcessLinks);
				MmProcessCount++;

				//
				// Set it up
				//
				Process->ProcessKey = reinterpret_cast<ULONGLONG>(MmPrivateSources->InfoArray[i].EProcess);
				strncpy_s(Process->ProcessName, MmPrivateSources->InfoArray[i].ImageName, 16);
				Process->ProcessPfnCount = 0;
				Process->PrivatePages = static_cast<ULONG>(MmPrivateSources->InfoArray[i].NumberOfPrivatePages);
				Process->ProcessId = reinterpret_cast<HANDLE>(static_cast<ULONGLONG>(MmPrivateSources->InfoArray[i].DbInfo.ProcessId));
				Process->SessionId = MmPrivateSources->InfoArray[i].SessionID;
				Process->ProcessHandle = NULL;

				//
				// Open a handle to it
				//
				InitializeObjectAttributes(&ObjectAttributes, NULL, 0, NULL, NULL);
				ClientId.UniqueProcess = Process->ProcessId;
				ClientId.UniqueThread = 0;
				NtOpenProcess(&Process->ProcessHandle, PROCESS_ALL_ACCESS, &ObjectAttributes, &ClientId);
			}
			else {
				//
				// Process exists -- clear stats
				//
				Process->ProcessPfnCount = 0;
			}
		}
	}

	::HeapFree(::GetProcessHeap(), 0, MmPrivateSources);
	return Status;
}
```   

Keypoints :  
- Meminfo function : **PfiQueryPrivateSources**
- superfetch query type : *SuperfetchPrivSourceQuery* 
- superfetch query result :  stored in `MmPrivateSources` 
- data available : PF_PRIVSOURCE_QUERY_REQUEST + PF_PRIVSOURCE_INFO + PFS_PRIVATE_PAGE_SOURCE + PPF_PROCESS data structures

(click on image to zoom in)
    
[![PfiQueryPrivateSources.drawio](/assets/uploads/2024/08/PfiQueryPrivateSources.drawio.png)](/assets/uploads/2024/08/PfiQueryPrivateSources.drawio.png)  

You can use `MmPrivateSources` content to retrieve `ProcessName` and `ProcessId` values and print those information, for example just modifying **PfiQueryPrivateSources** function.  

Modified piece of code in Meminfo project :  

```cpp  
NTSTATUS PfiQueryPrivateSources() {
[ snip ]
	//
	// Set it up
	//
	Process->ProcessKey = reinterpret_cast<ULONGLONG>(MmPrivateSources->InfoArray[i].EProcess);
	strncpy_s(Process->ProcessName, MmPrivateSources->InfoArray[i].ImageName, 16);
	Process->ProcessPfnCount = 0;
	Process->PrivatePages = static_cast<ULONG>(MmPrivateSources->InfoArray[i].NumberOfPrivatePages);
	Process->ProcessId = reinterpret_cast<HANDLE>(static_cast<ULONGLONG>(MmPrivateSources->InfoArray[i].DbInfo.ProcessId));
	Process->SessionId = MmPrivateSources->InfoArray[i].SessionID;
	Process->ProcessHandle = NULL;
	// print information about running processes 
	printf("%-14s  %-8lu \n",
		Process->ProcessName,
		Process->ProcessId);
[ snip ]
}
```  

This will give you the following output :  

```
c:\> MemInfo.exe -s
MemInfo v3.10 - Show PFN database information
Copyright (C) 2007-2017 Alex Ionescu and Pavel Yosifovich
http://www.windows-internals.com

Initializing PFN database... Done.
System          4
Registry        108
smss.exe        380
csrss.exe       484
wininit.exe     560
csrss.exe       580
winlogon.exe    660
services.exe    700
lsass.exe       708
svchost.exe     836
fontdrvhost.ex  860
fontdrvhost.ex  868
svchost.exe     972
svchost.exe     68
svchost.exe     776
svchost.exe     992
[snip]
```  

## Superfetch query superpower n°4 : _EPROCESS kernel address leak   

### Usual method   

When you write a kernel exploits abusing tokens for privilege escalation, you must first locate your process _EPROCESS location in the kernel. You will find full information about this in [Token Abuse for Privilege Escalation in Kernel][LINK19] by @spotheplanet.   

In order to get an _EPROCESS location in the kernel, for example you can use :  
- PsInitialSystemProcess
- PsReferencePrimaryToken 
- PsLookupProcessByProcessId
- [token stealing shellcode][LINK20]
  
### Superfetch method   

In the following example you use a superfetch query retrieving the _EPROCESS kernel address of a PID running currently on your Windows.   

Interesting piece of code in Meminfo project (it's the same as superpower n°3):   

```cpp  
// Extract from WindowsInternals/MemInfo/MemInfo.cpp
//
// DATA STRUCTURES & GLOBAL VARIABLES
//
typedef struct _SUPERFETCH_INFORMATION {
	ULONG Version;
	ULONG Magic;
	SUPERFETCH_INFORMATION_CLASS InfoClass;
	PVOID Data;
	ULONG Length;
} SUPERFETCH_INFORMATION, *PSUPERFETCH_INFORMATION;

// Private Source Entry
typedef struct _PF_PRIVSOURCE_INFO {
	PFS_PRIVATE_PAGE_SOURCE DbInfo;
	PVOID EProcess;
	SIZE_T WorkingSetPrivateSize;
	SIZE_T NumberOfPrivatePages;
	ULONG SessionID;
	CHAR ImageName[16];

	union {
		ULONG_PTR WsSwapPages;                 // process only PF_PRIVSOURCE_QUERY_WS_SWAP_PAGES.
		ULONG_PTR SessionPagedPoolPages;       // session only.
		ULONG_PTR StoreSizePages;              // process only PF_PRIVSOURCE_QUERY_STORE_INFO.
	};
	ULONG_PTR WsTotalPages;         // process/session only.
	ULONG DeepFreezeTimeMs;         // process only.
	ULONG ModernApp : 1;            // process only.
	ULONG DeepFrozen : 1;           // process only. If set, DeepFreezeTimeMs contains the time at which the freeze occurred
	ULONG Foreground : 1;           // process only.
	ULONG PerProcessStore : 1;      // process only.
	ULONG Spare : 28;

} PF_PRIVSOURCE_INFO, *PPF_PRIVSOURCE_INFO;

// Query Data Structure for SuperfetchPrivSourceQuery
typedef struct _PF_PRIVSOURCE_QUERY_REQUEST {
	ULONG Version;
	ULONG Flags;
	ULONG InfoCount;
	PF_PRIVSOURCE_INFO InfoArray[ANYSIZE_ARRAY];
} PF_PRIVSOURCE_QUERY_REQUEST, *PPF_PRIVSOURCE_QUERY_REQUEST;

// Superfetch Information Class
typedef enum _SUPERFETCH_INFORMATION_CLASS {
	SuperfetchPrivSourceQuery = 8,      // Query
} SUPERFETCH_INFORMATION_CLASS;

//  System Information Classes for NtQuerySystemInformation
typedef enum _SYSTEM_INFORMATION_CLASS {
	SystemBasicInformation,
	SystemSuperfetchInformation = 79,
} SYSTEM_INFORMATION_CLASS;
//
// HELPER FUNCTION
//
void PfiBuildSuperfetchInfo(IN PSUPERFETCH_INFORMATION SuperfetchInfo, IN PVOID Buffer, IN ULONG Length, IN SUPERFETCH_INFORMATION_CLASS InfoClass) {
	SuperfetchInfo->Version = SUPERFETCH_VERSION;
	SuperfetchInfo->Magic = SUPERFETCH_MAGIC;
	SuperfetchInfo->Data = Buffer;
	SuperfetchInfo->Length = Length;
	SuperfetchInfo->InfoClass = InfoClass;
}

PPF_PRIVSOURCE_QUERY_REQUEST MmPrivateSources;

//
// GET INFORMATION
//
NTSTATUS PfiQueryPrivateSources() {
	NTSTATUS Status;
	SUPERFETCH_INFORMATION SuperfetchInfo;
	PF_PRIVSOURCE_QUERY_REQUEST PrivateSourcesQuery = { 0 };
	ULONG ResultLength = 0;

	/* Version 2 for Beta 2, Version 3 for RTM */
	PrivateSourcesQuery.Version = 8; //3;

	PfiBuildSuperfetchInfo(&SuperfetchInfo,
		&PrivateSourcesQuery,
		sizeof(PrivateSourcesQuery),
		SuperfetchPrivSourceQuery);

	Status = NtQuerySystemInformation(SystemSuperfetchInformation,
		&SuperfetchInfo,
		sizeof(SuperfetchInfo),
		&ResultLength);
	if (Status == STATUS_BUFFER_TOO_SMALL) {
		MmPrivateSources = static_cast<PPF_PRIVSOURCE_QUERY_REQUEST>(::HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, ResultLength));
		MmPrivateSources->Version = 8;

		PfiBuildSuperfetchInfo(&SuperfetchInfo,
			MmPrivateSources,
			ResultLength,
			SuperfetchPrivSourceQuery);

		Status = NtQuerySystemInformation(SystemSuperfetchInformation,
			&SuperfetchInfo,
			sizeof(SuperfetchInfo),
			&ResultLength);
		if (!NT_SUCCESS(Status)) {
			printf("Superfetch Information Query Failed\n");
		}
	}

	//
	// Loop the private sources
	//
	for (ULONG i = 0; i < MmPrivateSources->InfoCount; i++) {
		//
		// Make sure it's a process
		//
		if (MmPrivateSources->InfoArray[i].DbInfo.Type == PfsPrivateSourceProcess) {
			//
			// Do we already know about this process?
			//
			PPF_PROCESS Process;
			CLIENT_ID ClientId;
			OBJECT_ATTRIBUTES ObjectAttributes;
			Process = PfiFindProcess(reinterpret_cast<ULONGLONG>(MmPrivateSources->InfoArray[i].EProcess));
			if (!Process) {
				//
				// We don't, allocate it
				//
				Process = static_cast<PPF_PROCESS>(::HeapAlloc(::GetProcessHeap(), 0, sizeof(PF_PROCESS) +
					MmPrivateSources->InfoArray[i].NumberOfPrivatePages * sizeof(ULONG)));
				InsertTailList(&MmProcessListHead, &Process->ProcessLinks);
				MmProcessCount++;

				//
				// Set it up
				//
				Process->ProcessKey = reinterpret_cast<ULONGLONG>(MmPrivateSources->InfoArray[i].EProcess);
				strncpy_s(Process->ProcessName, MmPrivateSources->InfoArray[i].ImageName, 16);
				Process->ProcessPfnCount = 0;
				Process->PrivatePages = static_cast<ULONG>(MmPrivateSources->InfoArray[i].NumberOfPrivatePages);
				Process->ProcessId = reinterpret_cast<HANDLE>(static_cast<ULONGLONG>(MmPrivateSources->InfoArray[i].DbInfo.ProcessId));
				Process->SessionId = MmPrivateSources->InfoArray[i].SessionID;
				Process->ProcessHandle = NULL;

				//
				// Open a handle to it
				//
				InitializeObjectAttributes(&ObjectAttributes, NULL, 0, NULL, NULL);
				ClientId.UniqueProcess = Process->ProcessId;
				ClientId.UniqueThread = 0;
				NtOpenProcess(&Process->ProcessHandle, PROCESS_ALL_ACCESS, &ObjectAttributes, &ClientId);
			}
			else {
				//
				// Process exists -- clear stats
				//
				Process->ProcessPfnCount = 0;
			}
		}
	}

	::HeapFree(::GetProcessHeap(), 0, MmPrivateSources);
	return Status;
}
```   

Keypoints :  
- Meminfo function : **PfiQueryPrivateSources**
- superfetch query type : *SuperfetchPrivSourceQuery* 
- superfetch query result :  stored in `MmPrivateSources` 
- data available : PF_PRIVSOURCE_QUERY_REQUEST + PF_PRIVSOURCE_INFO + PFS_PRIVATE_PAGE_SOURCE + PPF_PROCESS data structures

(click on image to zoom in)
    
[![PfiQueryPrivateSources.drawio](/assets/uploads/2024/08/PfiQueryPrivateSources.drawio.png)](/assets/uploads/2024/08/PfiQueryPrivateSources.drawio.png)  

You can use `MmPrivateSources` content to retrieve `EProcess` value and print this information, for example just modifying **PfiQueryPrivateSources** function.  

Modified piece of code in Meminfo project :  

```cpp  
NTSTATUS PfiQueryPrivateSources() {
[ snip ]
if (MmPrivateSources->InfoArray[i].DbInfo.Type == PfsPrivateSourceProcess) {
			//
			// Do we already know about this process?
			//
			PPF_PROCESS Process;
			CLIENT_ID ClientId;
			OBJECT_ATTRIBUTES ObjectAttributes;
			Process = PfiFindProcess(reinterpret_cast<ULONGLONG>(MmPrivateSources->InfoArray[i].EProcess));
			// leak e_process kernel address of the System PID n°4
			if (MmPrivateSources->InfoArray[i].DbInfo.ProcessId == 4) {
				PVOID eprocessVA = MmPrivateSources->InfoArray[i].EProcess;
				printf("\t[+] Leak PID %-8d _EPROCESS virtual address : \t\t\t%08p\n", 4, eprocessVA);
			}
[ snip ]
}
```  

This will give you the following output for the famous "System" process (PID 4) :  

```
C:\>z:\MemInfo.exe  -p 4
MemInfo v3.10 - Show PFN database information
Copyright (C) 2007-2017 Alex Ionescu and Pavel Yosifovich
http://www.windows-internals.com

Initializing PFN database... Done.
        [+] Leak PID 4        _EPROCESS virtual address :                       FFFFB587C7661040
0x0000000000004000 Active      Non Paged Pool   0   N/A            0xFFFFF7C600001000 N/A

C:\>
```  

Optional : you can check with Windbg   

[![leak_eprocess_kernelAddress.png](/assets/uploads/2024/08/leak_eprocess_kernelAddress.png)](/assets/uploads/2024/08/leak_eprocess_kernelAddress.png)  


## End

This blogpost focuses on superfetch queries, which require using `NtQuerySystemInformation`. As you probably know this API needs high privileges (SE_PROF_SINGLE_PROCESS_PRIVILEGE & SE_DEBUG_PRIVILEGE) that's why this kind of query is probably more a "feature" than a vulnerability (it's your choice but [MSRC's policy][LINK14] is clear : "Administrator-to-kernel is not a security boundary.") but now you are aware of some opportunities you can take using it !   

Thanks for reading, I hope you learnt something and your feedbacks are welcome !   

Resources :    
[https://www.microsoftpressstore.com/store/windows-internals-part-1-system-architecture-processes-9780735684188][LINK1]   
[https://github.com/zodiacon/WindowsInternals/tree/master/MemInfo][LINK3]      
[https://github.com/zodiacon/WindowsInternals/blob/master/MemInfo/MemInfo.cpp#L922][LINK4]      
[https://www.mdsec.co.uk/2022/08/fourteen-ways-to-read-the-pid-for-the-local-security-authority-subsystem-service-lsass/][LINK5]  
[https://labs.nettitude.com/blog/vm-detection-tricks-part-1-physical-memory-resource-maps/][LINK6]  
[https://www.outflank.nl/blog/2023/12/14/mapping-virtual-to-physical-adresses-using-superfetch/][LINK7]  
[https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/bug-check-code-reference2][LINK8]  
[https://www.microsoft.com/en-us/msrc/windows-security-servicing-criteria][LINK14]   
[https://v1k1ngfr.github.io/windows-internal-meminfo/][LINK16]]   
[https://connormcgarr.github.io/paging/][LINK17]   
[https://v1k1ngfr.github.io/windows-internal-meminfo/#troubleshoot-remaining-problems][LINK18]   
[https://www.ired.team/miscellaneous-reversing-forensics/windows-kernel-internals/how-kernel-exploits-abuse-tokens-for-privilege-escalation][LINK19]   
[https://github.com/v1k1ngfr/winkernel/blob/master/win10x64kernelstealtoken.asm][LINK20]


[LINK1]: https://www.microsoftpressstore.com/store/windows-internals-part-1-system-architecture-processes-9780735684188    
[LINK3]: https://github.com/zodiacon/WindowsInternals/tree/master/MemInfo      
[LINK4]: https://github.com/zodiacon/WindowsInternals/blob/master/MemInfo/MemInfo.cpp#L922      
[LINK5]: https://www.mdsec.co.uk/2022/08/fourteen-ways-to-read-the-pid-for-the-local-security-authority-subsystem-service-lsass/  
[LINK6]: https://labs.nettitude.com/blog/vm-detection-tricks-part-1-physical-memory-resource-maps/  
[LINK7]: https://www.outflank.nl/blog/2023/12/14/mapping-virtual-to-physical-adresses-using-superfetch/  
[LINK8]: https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/bug-check-code-reference2  
[LINK14]: https://www.microsoft.com/en-us/msrc/windows-security-servicing-criteria  
[LINK16]: https://v1k1ngfr.github.io/windows-internal-meminfo/  
[LINK17]: https://connormcgarr.github.io/paging/
[LINK18]: https://v1k1ngfr.github.io/windows-internal-meminfo/#troubleshoot-remaining-problems
[LINK19]: https://www.ired.team/miscellaneous-reversing-forensics/windows-kernel-internals/how-kernel-exploits-abuse-tokens-for-privilege-escalation
[LINK20]: https://github.com/v1k1ngfr/winkernel/blob/master/win10x64kernelstealtoken.asm