# [Microsoft Windows Hardening](https://tryhackme.com/r/room/microsoftwindowshardening)

## Task 2 Understanding General Concepts

**What is the startup type of App Readiness service in the services panel?**

* Execute `services.msc`
* Search for `App Readiness`

**Open Registry Editor and find the key “tryhackme”. What is the default value of the key?**

* Execute `regedit.exe`
* Edit > Find `tryhackme` with Look at = Keys

**Open the Diagnosis folder and go through the various log files. Can you find the flag?**

* Run as Administrator `powershell.exe` 
* Execute `cat $Env:ProgramData\Microsoft\Diagnosis\flag.txt.txt`

**Open the Event Viewer and play with various event viewer filters like Information, Error, Warning etc.**
**Which error type has the maximum number of logs?**

* Execute Event Viewer
* In the first screen "Overview and Summary" you can find the number of logs for each type

## Task 3 Identity & Access Management

**Find the name of the Administrator Account of the attached VM**

* Go to Control Panel > User Accounts

**Go to the User Account Control Setting Panel (Control Panel > All Control Panel Items > User Accounts)**
**What is the default level of Notification?**

* Go to Control Panel > User Accounts > Change User Account Control settings

**How many standard accounts are created in the VM?**

* Go to Control Panel > User Accounts > Manage another account

## Task 4 Network Management

**Open Windows Firewall and click on Monitoring in the left pane - which of the following profiles is active? Domain, Private, Public?**

* Execute Windows Defender Firewall

**Find the IP address resolved for the website tryhack.me in the Virtual Machine as per the local hosts file**

* Run as Administrator `powershell.exe`
* Execute `Select-String -Path C:\windows\system32\drivers\etc\hosts -Pattern tryhack.me`

**Open the command prompt and enter arp -a. What is the Physical address for the IP address 255.255.255.255?**

* Run as Administrator `powershell.exe`
* Execute `arp -a | Select-String 255.255.255.255`

## Task 5 Application Management

**Windows Defender Antivirus is configured to exclude a particular extension from scanning. What is the extension?**

* Execute Virus & threat protection
* Go to Virus & threat protection settings
* Go to Exclusions > Add or remove exclusions

**What is the flag you received after executing the Office Hardening Batch file?**

* Run as Administrator `cmd.exe`
* Execute `C:\Users\Harden\Desktop\office.bat`

## Task 6 Storage Management

**A security engineer has misconfigured the attached VM and stored a BitLocker recovery key in the same computer**
**Can you read the last six digits of the recovery key?**
**How many characters does the BitLocker recovery key have in the attached VM?**

* Run `powershell.exe`
* Execute:
  ```powershell
  $recoveryKey = ((Get-Content -Path 'C:\Users\Harden\Documents\BitLocker Recovery Key AC9D5655-F7CA-4D1D-902F.TXT' -Raw) `
  -replace "`r?`n", " " -replace "\s+", " " | `
  Select-String -Pattern "Recovery Key: (\S+)").Matches.Groups[1].Value

  Write-Output "Key is $recoveryKey"
  Write-Output "Last six digits are $($recoveryKey.Substring($recoveryKey.Length - 6))"
  Write-Output "Length is $(($recoveryKey -replace '-', '').Length)"
  ```

**A backup file is placed on the Desktop of the attached VM**
**What is the extension of that file?**

* Run `powershell.exe`
* Execute `Get-ChildItem -Path "C:\Users\Harden\Desktop" -Filter "*Backup*" -File -Recurse`

## Task 7 Updating Windows

**What is the CVE score for the vulnerability CVE ID CVE-2022-32230?**

* Go to https://www.cvedetails.com/cve/CVE-2022-32230/
