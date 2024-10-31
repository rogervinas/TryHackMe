# [Windows Forensics 2](https://tryhackme.com/room/windowsforensics2)

## Task 3 The NTFS File System

```powershell
C:\Users\THM-4n6\Desktop\EZtools\MFTECmd.exe `
 -f 'C:\users\THM-4n6\Desktop\triage\C\$MFT' `
 --csv C:\Users\THM-4n6\Desktop

C:\Users\THM-4n6\Desktop\EZtools\MFTECmd.exe `
 -f 'C:\users\THM-4n6\Desktop\triage\C\$Boot' `
 --csv C:\Users\THM-4n6\Desktop
```

## Task 5 Evidence of Execution

**How many times was gkape.exe executed?**
**What is the last execution time of gkape.exe**

```powershell
C:\Users\THM-4n6\Desktop\EZtools\PECmd.exe `
 -f C:\users\THM-4n6\Desktop\triage\C\Windows\prefetch\GKAPE.EXE-E935EF56.pf `
 --csv C:\Users\THM-4n6\Desktop
# Run count
# Last run
```

**When Notepad.exe was opened on 11/30/2021 at 10:56, how long did it remain in focus?**

```powershell
C:\Users\THM-4n6\Desktop\EZtools\WxTCmd.exe `
 -f C:\Users\THM-4n6\Desktop\triage\C\Users\THM-4n6\AppData\Local\ConnectedDevicesPlatform\L.THM-4n6\ActivitiesCache.db `
 --csv C:\Users\THM-4n6\Desktop
# Duration
```

**What program was used to open C:\Users\THM-4n6\Desktop\KAPE\KAPE\ChangeLog.txt?**

```powershell
C:\Users\THM-4n6\Desktop\EZtools\JLECmd.exe `
 -d C:\Users\THM-4n6\Desktop\triage\C\Users\THM-4n6\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations `
 --csv C:\Users\THM-4n6\Desktop
# AppIdDescription

C:\Users\THM-4n6\Desktop\EZtools\JLECmd.exe `
 -f C:\Users\THM-4n6\Desktop\triage\C\Users\THM-4n6\AppData\Roaming\Microsoft\Windows\Recent\ChangeLog.lnk `
 --csv C:\Users\THM-4n6\Desktop
```

## Task 6 File/folder knowledge

**When was the folder C:\Users\THM-4n6\Desktop\regripper last opened?**
**When was the above-mentioned folder first opened?**

```powershell
C:\Users\THM-4n6\Desktop\EZtools\JLECmd.exe `
 -d C:\Users\THM-4n6\Desktop\triage\C\Users\THM-4n6\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations `
 --csv C:\Users\THM-4n6\Desktop
# LastModified
# CreationTime
```
