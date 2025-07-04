# [Boogeyman 2](https://tryhackme.com/room/boogeyman2)

## Task 2 Spear Phishing Human Resources

**What email was used to send the phishing email?**

```shell
grep "From: " ~/Desktop/Artefacts/Resume*
```

**What is the email of the victim employee?**

```shell
grep "To: " ~/Desktop/Artefacts/Resume*
```

**What is the name of the attached malicious document?**

```shell
grep attachment ~/Desktop/Artefacts/Resume*
```

**What is the MD5 hash of the malicious attachment?**

* Double-click on "~/Desktop/Artefacts/Resume - Application for Junior IT Analyst Role.eml" to open it with the email client
* Save Resume_WesleyTaylor.doc to ~/Desktop/Artefacts

```shell
md5sum ~/Desktop/Artefacts/Resume_WesleyTaylor.doc
```

**What URL is used to download the stage 2 payload based on the document's macro?**

```shell
olevba ~/Desktop/Artefacts/Resume_WesleyTaylor.doc | grep GET
```

**What is the name of the process that executed the newly downloaded stage 2 payload?**
**What is the full file path of the malicious stage 2 payload?**

```shell
olevba ~/Desktop/Artefacts/Resume_WesleyTaylor.doc | grep shell_object.Exec
```

**What is the PID of the process that executed the stage 2 payload?**
**What is the parent PID of the process that executed the stage 2 payload?**

```shell
vol -f WKSTN-2961.raw windows.pstree.PsTree > WKSTN-2961.pstree 
head -3 WKSTN-2961.pstree ; grep -B 4 -A 2 wscript.exe WKSTN-2961.pstree
```

**What URL is used to download the malicious binary executed by the stage 2 payload?**

* Extract the script which downloads the malicious binary:
```shell
strings WKSTN-2961.raw | grep -m 1 -A 17 "var Object = WScript.CreateObject('MSXML2.XMLHTTP');" > update.js
```

**What is the PID of the malicious process used to establish the C2 connection?**

```shell
head -3 WKSTN-2961.pstree ; grep -B 4 -A 2 updater.exe WKSTN-2961.pstree
```

**What is the full file path of the malicious process used to establish the C2 connection?**

* We can deduce it from the script code and also check:
```shell
vol -f WKSTN-2961.raw filescan > WKSTN-2961.filescan
head -3 WKSTN-2961.filescan ; grep updater.exe WKSTN-2961.filescan
```

**What is the IP address and port of the C2 connection initiated by the malicious binary?**

```shell
vol -f WKSTN-2961.raw windows.netscan.NetScan > WKSTN-2961.netscan
head -3 WKSTN-2961.netscan ; grep updater.exe WKSTN-2961.netscan
```

**What is the full file path of the malicious email attachment based on the memory dump?**

```shell

```

**What is the full command used by the attacker to maintain persistent access?**

```shell
strings WKSTN-2961.raw | grep "schtasks /Create"
```

or alternatively:

```shell
grep Resume_WesleyTaylor WKSTN-2961.filescan
```
