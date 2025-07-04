# [Windows Forensics 1](https://tryhackme.com/room/windowsforensics1)

## Task 10 Hands-on Challenge

**How many user created accounts are present on the system?**
**What is the username of the account that has never been logged in?**
**What's the password hint for the user THM-4n6?**

```powershell
C:\Users\THM-4n6\Desktop\EZtools\RegistryExplorer\RegistryExplorer.exe C:\Users\THM-4n6\Desktop\triage\C\Windows\System32\config\SAM
# Go to SAM\Domains\Account\Users
# Go to SAM\Domains\Account\Users\000003EB F (contains the user's last logon time encrypted) = thm-user2
# Go to SAM\Domains\Account\Users\000003E9 UserPasswordHint
```

**When was the file 'Changelog.txt' accessed?**

```powershell
C:\Users\THM-4n6\Desktop\EZtools\RegistryExplorer\RegistryExplorer.exe C:\Users\THM-4n6\Desktop\triage\C\Users\THM-4n6\NTUSER.DAT
# Go to SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs
```

**What is the complete path from where the python 3.8.2 installer was run?**

```powershell
C:\Users\THM-4n6\Desktop\EZtools\RegistryExplorer\RegistryExplorer.exe C:\Users\THM-4n6\Desktop\triage\C\Users\THM-4n6\NTUSER.DAT
# Go to SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count
```

**When was the USB device with the friendly name 'USB' last connected?**

```powershell
C:\Users\THM-4n6\Desktop\EZtools\RegistryExplorer\RegistryExplorer.exe C:\Users\THM-4n6\Desktop\triage\C\Windows\System32\config\SYSTEM
# Go to ControlSet001\Enum\USBSTOR
```
