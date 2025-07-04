# [Tempest](https://tryhackme.com/r/room/tempestincident)

## Task 3 Preparation - Tools and Artifacts

**What is the SHA256 hash of the capture.pcapng file?**

```powershell
Get-FileHash -Algorithm SHA256 'C:\Users\user\Desktop\Incident Files\capture.pcapng'
```

**What is the SHA256 hash of the sysmon.evtx file?**

```powershell
Get-FileHash -Algorithm SHA256 'C:\Users\user\Desktop\Incident Files\sysmon.evtx'
```

**What is the SHA256 hash of the windows.evtx file?**

```powershell
Get-FileHash -Algorithm SHA256 'C:\Users\user\Desktop\Incident Files\windows.evtx'
```

## Task 4 Initial Access - Malicious Document

Use Event Viewer to convert sysmon.evtx to sysmon.xml:
* Actions > Open Saved Log > C:\Users\user\Desktop\Incident Files\sysmon.evtx
* Context Menu > Save All Events As > C:\Users\user\Desktop\Incident Files\sysmon.xml
* Wait for all the events to be exported

Use EvtxECmd to convert sysmon.evtx to sysmon.csv:
```powershell
C:\Tools\EvtxECmd\EvtxECmd.exe -f 'C:\Users\user\Desktop\Incident Files\sysmon.evtx' `
--csv 'C:\Users\user\Desktop\Incident Files' --csvf sysmon.csv
```

**The user of this machine was compromised by a malicious document. What is the file name of the document?**
**What is the name of the compromised user and machine?**
**What is the PID of the Microsoft Word process that opened the malicious document?**

* Open Sysmon View
* Load C:\Users\user\Desktop\Incident Files\sysmon.xml
* Find WINWORD.EXE
* Click on Image Path = C:\Program Files (x86)\Microsoft Office\Root\Office16\WINWORD.EXE
* Click on Session = {4bbef3ae-aaa8-62b0-2e0a-000000000700}
* Navigate the diagram and click on the "Process Create" box
* All the answers are there

**Based on Sysmon logs, what is the IPv4 address resolved by the malicious domain used in the previous question?**

* Open Sysmon View
* Load C:\Users\user\Desktop\Incident Files\sysmon.xml
* Find WINWORD.EXE
* Click on Image Path = C:\Program Files (x86)\Microsoft Office\Root\Office16\WINWORD.EXE
* Click on Session = {4bbef3ae-aaa8-62b0-2e0a-000000000700}
* Navigate the diagram and click on the "DNS Query" box for the malicious domain

**What is the base64 encoded string in the malicious payload executed by the document?**

* Open Timeline Explorer
* Load C:\Users\user\Desktop\Incident Files\sysmon.csv
* Filter by "User Name" = TEMPEST\benimaru
* Search on "Executable Info" until you see a value that looks like base64

**What is the CVE number of the exploit used by the attacker to achieve a remote code execution?**

* Search for "msdt vulnerability" in google

## Task 5 Initial Access - Stage 2 execution

**The malicious execution of the payload wrote a file on the system. What is the full target path of the payload?**

* Decode the base64 payload from last section
* Get the full target path taking into account that `$app` = `C:\Users\benimaru\AppData\Roaming`

**What is the executed command upon a successful login of the compromised user?**

* Open Timeline Explorer
* Load C:\Users\user\Desktop\Incident Files\sysmon.csv
* Filter by "User Name" = TEMPEST\benimaru
* Search on "Executable Info" after the line with the base64 payload, first command that uses the malicious domain

**What is the SHA256 hash of the malicious binary downloaded for stage 2 execution?**

* Open Sysmon View
* Load C:\Users\user\Desktop\Incident Files\sysmon.xml
* Find first.exe
* Click on the single Image Path
* Click on the single Session
* Navigate the diagram and click on the "Process Create" box
* SHA256 of first.exe is there

**What is the domain and port used by the attacker?**

* Open Sysmon View
* Load C:\Users\user\Desktop\Incident Files\sysmon.xml
* Find first.exe
* Click on the single Image Path
* Click on the single Session
* Navigate the diagram and click on the first "DNS Query" box to know the domain
* Click on the next "Network Connection Detected" box to know the port

## Task 6 Initial Access - Malicious Document Traffic

**What is the URL of the malicious payload embedded in the document?**

* Open Brim
* Load C:\Users\user\Desktop\Incident Files\capture.pcapng
* Filter by `_path=="http" "xyz" method=="GET" | sort ts`
* Check the first uri after the `.doc` one

**What is the encoding used by the attacker on the c2 connection?**
**What is the parameter used by the binary?**
**What is the URL used by the binary?**
**What is the HTTP method used by the binary?**
**Based on the user agent, what programming language was used by the attacker to compile the binary?**

* Open Brim
* Load C:\Users\user\Desktop\Incident Files\capture.pcapng
* Filter by `_path=="http" "xyz" user_agent=="Nim httpclient/1.6.6" | sort ts`
* Check uri, method, query parameter and the encoding used in the query parameter value
* Search user agent on google

## Task 7 Discovery - Internal Reconnaissance

* Open Brim
* Load C:\Users\user\Desktop\Incident Files\capture.pcapng
* Filter by `_path=="http" "xyz" method=="GET" id.resp_p==80 "9ab62b5?q" | sort ts | cut uri`
* Export in CSV format to C:\Users\user\Desktop\Incident Files\9ab62b5-80.csv 

```powershell
Get-Content -Path "C:\Users\user\Desktop\Incident Files\9ab62b5-80.csv" | ForEach-Object {
    if ($_ -match "q=(.*)") {
        $encoded = $matches[1]
        $decoded = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($encoded))
        Write-Output "Decoded value: $decoded"
    }
} | Out-File -FilePath "C:\Users\user\Desktop\Incident Files\9ab62b5-80.log"
```

**What is the password discovered on the aforementioned file?**

* Search for `$pass` in C:\Users\user\Desktop\Incident Files\9ab62b5-80.log

**What is the listening port that could provide a remote shell inside the machine?**

* Search for `Active Connections` in C:\Users\user\Desktop\Incident Files\9ab62b5-80.log
* For all the `LISTENING` ports check which one is most commonly used for remote shell access

**What is the command executed by the attacker to establish the connection?**
**What is the SHA256 hash of the binary used by the attacker to establish the reverse socks proxy connection?**

* Last command in C:\Users\user\Desktop\Incident Files\9ab62b5-80.log downloads C:\Users\benimaru\Downloads\ch.exe
* Open Sysmon View
* Load C:\Users\user\Desktop\Incident Files\sysmon.xml
* Find ch.exe
* Click on the single Image Path
* Click on the single Session
* Navigate the diagram and click on the "Process Create" box
* Full command and SHA256 of ch.exe is there

**What is the name of the tool used by the attacker based on the SHA256 hash?**

* Search the hash in https://www.virustotal.com

**Based on the succeeding process after the execution of the socks proxy, what service did the attacker use to authenticate?**

* Search which windows service uses the port answered in the previous question "What is the listening port that could provide a remote shell inside the machine?"

## Task 8 Privilege Escalation - Exploiting Privileges

**After discovering the privileges of the current user, the attacker then downloaded another binary to be used for privilege escalation. What is the name and the SHA256 hash of the binary?**

* Open Brim
* Load C:\Users\user\Desktop\Incident Files\capture.pcapng
* Filter by `_path=="http" "xyz" | sort ts | cut ts, method, uri`
* The binary is spf.exe
* Open Sysmon View
* Load C:\Users\user\Desktop\Incident Files\sysmon.xml
* Find spf.exe
* Click on the single Image Path
* Click on the single Session
* Navigate the diagram and click on the "Process Create" box
* SHA256 of spf.exe is there

**Based on the SHA256 hash of the binary, what is the name of the tool used?**

* Search the hash in https://www.virustotal.com

**The tool exploits a specific privilege owned by the user. What is the name of the privilege?**

* Search the binary name in google, first results have the answer

**Then, the attacker executed the tool with another binary to establish a c2 connection. What is the name of the binary?**

* Open Sysmon View
* Load C:\Users\user\Desktop\Incident Files\sysmon.xml
* Find spf.exe
* Click on the single Image Path
* Click on the single Session
* Navigate the diagram and click on the "Process Create" box
* Full command of spf.exe is there, first parameter is C:\ProgramData\final.exe

**The binary connects to a different port from the first c2 connection. What is the port used?**

* Open Sysmon View
* Load C:\Users\user\Desktop\Incident Files\sysmon.xml
* Find final.exe
* Click on the single Image Path
* Click on the single Session
* Click on the first "Network Connection Detected" box to know the port

# Task 9 Actions on Objective - Fully-owned Machine

* Open Brim
* Load C:\Users\user\Desktop\Incident Files\capture.pcapng
* Filter by `_path=="http" "xyz" method=="GET" id.resp_p==8080 "9ab62b5?q" | sort ts | cut uri`
* Export in CSV format to C:\Users\user\Desktop\Incident Files\9ab62b5-8080.csv 

```powershell
Get-Content -Path "C:\Users\user\Desktop\Incident Files\9ab62b5-8080.csv" | ForEach-Object {
    if ($_ -match "q=(.*)") {
        $encoded = $matches[1]
        $decoded = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($encoded))
        Write-Output "Decoded value: $decoded"
    }
} | Out-File -FilePath "C:\Users\user\Desktop\Incident Files\9ab62b5-8080.log"
```

**Upon achieving SYSTEM access, the attacker then created two users. What are the account names?**

* Search for `net user /add` in C:\Users\user\Desktop\Incident Files\9ab62b5-8080.log

**Prior to the successful creation of the accounts, the attacker executed commands that failed in the creation attempt. What is the missing option that made the attempt fail?**

* Search for `net user` in C:\Users\user\Desktop\Incident Files\9ab62b5-8080.log

**What is the event ID that indicates the account creation activity?**

* Just Google search it or ask ChatGPT

**The attacker added one of the accounts in the local administrator's group. What is the command used by the attacker?**

* Search for `net localgroup` in C:\Users\user\Desktop\Incident Files\9ab62b5-8080.log

**What is the event ID that indicates the addition to a sensitive local group?**

* Just Google search it or ask ChatGPT

**After the account creation, the attacker executed a technique to establish persistent administrative access. What is the command executed by the attacker to achieve this?**

* Search for `sc.exe` in C:\Users\user\Desktop\Incident Files\9ab62b5-8080.log
