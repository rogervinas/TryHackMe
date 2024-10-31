# [Secret Recipe](https://tryhackme.com/r/room/registry4n6)

## Task 2 Windows Registry Forensics

**What is the Computer Name of the Machine found in the registry?**

* C:\Users\Administrator\Desktop\EZ tools\RegistryExplorer\RegistryExplorer.exe
* Load C:\Users\Administrator\Desktop\Artifacts\SYSTEM
* Go to ControlSet001\Control\ComputerName\ComputerName

**When was the Administrator account created on this machine?**

* C:\Users\Administrator\Desktop\EZ tools\RegistryExplorer\RegistryExplorer.exe
* Load C:\Users\Administrator\Desktop\Artifacts\SAM
* Go to SAM\Domains\Account\Users

**What is the RID associated with the Administrator account?**

* C:\Users\Administrator\Desktop\EZ tools\RegistryExplorer\RegistryExplorer.exe
* Load C:\Users\Administrator\Desktop\Artifacts\SAM
* Go to SAM\Domains\Account\Users\Names\Administrator > Value

**How many User accounts were observed on this machine?**

* C:\Users\Administrator\Desktop\EZ tools\RegistryExplorer\RegistryExplorer.exe
* Load C:\Users\Administrator\Desktop\Artifacts\SAM
* Count SAM\Domains\Account\Users\Names

**There seems to be a suspicious account created as a backdoor with RID 1013. What is the Account Name?**

* C:\Users\Administrator\Desktop\EZ tools\RegistryExplorer\RegistryExplorer.exe
* Load C:\Users\Administrator\Desktop\Artifacts\SAM
* Search SAM\Domains\Account\Users\Names for Value = 1013 decimal

**What is the VPN connection this host connected to?**
**When was the first VPN connection observed?**

* C:\Users\Administrator\Desktop\EZ tools\RegistryExplorer\RegistryExplorer.exe
* Load C:\Users\Administrator\Desktop\Artifacts\SOFTWARE
* Go to Microsoft\Windows NT\CurrentVersion\NetworkList

**What is the path of the third share?**

* C:\Users\Administrator\Desktop\EZ tools\RegistryExplorer\RegistryExplorer.exe
* Load C:\Users\Administrator\Desktop\Artifacts\SYSTEM
* Go to ControlSet001\Services\LanmanServer\Shares

**What is the Last DHCP IP assigned to this host?**

* C:\Users\Administrator\Desktop\EZ tools\RegistryExplorer\RegistryExplorer.exe
* Load C:\Users\Administrator\Desktop\Artifacts\SYSTEM
* Go to ControlSet001\Services\Tcpip\Parameters\Interfaces

**The suspect seems to have accessed a file containing the secret coffee recipe. What is the name of the file?**

* C:\Users\Administrator\Desktop\EZ tools\RegistryExplorer\RegistryExplorer.exe
* Load C:\Users\Administrator\Desktop\Artifacts\NTUSER.DAT
* Go to Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs

**What command was run to enumerate the network interfaces?**

* C:\Users\Administrator\Desktop\EZ tools\RegistryExplorer\RegistryExplorer.exe
* Load C:\Users\Administrator\Desktop\Artifacts\NTUSER.DAT
* Go to Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU

**In the file explorer, the user searched for a network utility to transfer files. What is the name of that tool?**

* C:\Users\Administrator\Desktop\EZ tools\RegistryExplorer\RegistryExplorer.exe
* Load C:\Users\Administrator\Desktop\Artifacts\NTUSER.DAT
* Go to Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery

**What is the recent text file opened by the suspect?**

* C:\Users\Administrator\Desktop\EZ tools\RegistryExplorer\RegistryExplorer.exe
* Load C:\Users\Administrator\Desktop\Artifacts\NTUSER.DAT
* Go to Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs\.txt

**How many times was Powershell executed on this host?**
**The suspect also executed a network monitoring tool. What is the name of the tool?**
**For how many seconds was ProtonVPN executed?**
**What is the full path from which everything.exe was executed?**

* C:\Users\Administrator\Desktop\EZ tools\RegistryExplorer\RegistryExplorer.exe
* Load C:\Users\Administrator\Desktop\Artifacts\NTUSER.DAT
* Go to Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count
