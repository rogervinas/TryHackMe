# [KAPE](https://tryhackme.com/r/room/kape)

## Task 7 Hands-on Challenge

Use PowerShell > Run As Administrator and execute:

```powershell
cd C:\Users\THM-4n6\Desktop\KAPE
.\kape.exe --tsource C:\ `
--tdest C:\Users\THM-4n6\Desktop\T-DEST --tflush --target KapeTriage `
--mdest C:\Users\THM-4n6\Desktop\M-DEST --mflush --module !EZParser --gui
```

**What is the Serial Number of the other USB Device?**

```powershell
C:\Users\THM-4n6\Desktop\EZtools\EZViewer\EZViewer.exe `
C:\Users\THM-4n6\Desktop\M-DEST\Registry\20241027113011\20241027113011_USB__C_Windows_System32_config_SYSTEM.csv
```

**7zip, Google Chrome and Mozilla Firefox were installed from a Network drive location on the Virtual Machine. What was the drive letter and path of the directory from where these software were installed?**
**What is the execution date and time of CHROMESETUP.EXE in MM/DD/YYYY HH:MM?**

```powershell
C:\Users\THM-4n6\Desktop\EZtools\EZViewer\EZViewer.exe `
C:\Users\THM-4n6\Desktop\M-DEST\Registry\20241027191234\20241027191234_RecentApps__C_Users_THM-4n6_NTUSER.DAT.csv
```

**What search query was run on the system?**

```powershell
C:\Users\THM-4n6\Desktop\EZtools\EZViewer\EZViewer.exe `
C:\Users\THM-4n6\Desktop\M-DEST\Registry\20241027191234\20241027191234_WordWheelQuery__C_Users_THM-4n6_NTUSER.DAT.csv
```

**When was the network named Network 3 First connected to?**

```powershell
C:\Users\THM-4n6\Desktop\EZtools\EZViewer\EZViewer.exe `
C:\Users\THM-4n6\Desktop\M-DEST\Registry\20241027191234\20241027191234_KnownNetworks__C_Windows_System32_config_SOFTWARE.csv
```

**Can you find out what was the drive letter of the drive where KAPE was copied from?**

```powershell
C:\Users\THM-4n6\Desktop\EZtools\EZViewer\EZViewer.exe `
C:\Users\THM-4n6\Desktop\M-DEST\FileFolderAccess\20241028001118_AutomaticDestinations.csv
```
