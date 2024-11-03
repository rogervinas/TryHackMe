# [Boogeyman 3](https://tryhackme.com/room/boogeyman3)

## Task 2 The Chaos Inside

* Go to `http://<IP ADDRESS>/app/discover`
* Search between `Aug 29, 2023 @ 23:00:00.000` and `Aug 30, 2023 @ 03:00:00.000`

**What is the PID of the process that executed the initial stage 1 payload?**

* Select fields: `user.name`, `process.parent.pid`, `process.pid`, `event.action` and `process.command_line`
* Search for `ProjectFinancialSummary_Q3.pdf`
* Order by `Time` ascending
* Process that executes `mshta.exe` on `ProjectFinancialSummary_Q3.pdf.hta`
* Note that process is executed by user `evan.hutchinson` 

**What is the full command-line value of this execution?**

* Filter by `process.parent.pid` equal to the PID of last answer
* Order by `Time` ascending
* Process that executes `xcopy.exe`

**What is the full command-line value of this execution?**

* Same search as last question
* Process that executes `rundll32.exe` with file copied by command of last answer

**What is the name of the scheduled task created by the malicious script?**

* Same search as last question
* Process that executes `powershell.exe` with [New-ScheduledTaskAction](https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/new-scheduledtaskaction)
* Name of the task is first parameter to [Register-ScheduledTask](https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/register-scheduledtask)

**What is the IP and port used by this connection?**

* Search for `review.dat`
* PID of first process that executes `"C:\Windows\System32\rundll32.exe" D:\review.dat,DllRegisterServer`
* Filter by that PID and `event.action` equal to `Network connection detected`
* Get `destination.ip` and `destination.port`

**What is the name of the process used by the attacker to execute a UAC bypass?**

* Ask ChatGPT "What windows executables can be used to bypass UAC?" and search for it in the logs:

1. `fodhelper.exe`
  * **Location**: `C:\Windows\System32\fodhelper.exe`
  * **Description**: Used for managing Windows optional features and has `AutoElevate` enabled, meaning it can run with elevated privileges without triggering UAC.
  * **Technique**: Attackers modify registry keys under `HKCU\Software\Classes\ms-settings\shell\open\command` to point to their payload. When `fodhelper.exe` is executed, it runs the payload with elevated privileges.
2. `eventvwr.exe`
  * **Location**: `C:\Windows\System32\eventvwr.exe`
  * **Description**: Opens the Event Viewer, which runs with elevated privileges.
  * **Technique**: Attackers modify `HKCU\Software\Classes\mscfile\shell\open\command` to point to their payload. Running `eventvwr.exe` then executes the attacker’s code with elevation.
3. `computerdefaults.exe`
  * **Location**: `C:\Windows\System32\computerdefaults.exe`
  * **Description**: A system utility with `AutoElevate` enabled, often used in accessibility features.
  * **Technique**: Similar to `fodhelper.exe`, attackers can modify registry entries to execute their payload when `computerdefaults.exe` is run.
4. `schtasks.exe`
  * **Location**: `C:\Windows\System32\schtasks.exe`
  * **Description**: Task Scheduler command-line tool for creating and managing scheduled tasks.
  * **Technique**: Attackers can create a scheduled task set to run with elevated privileges, allowing them to bypass UAC. The task can be set to trigger upon user login or other events to persist and elevate without prompting UAC.
5. `slui.exe`
  * **Location**: `C:\Windows\System32\slui.exe`
  * **Description**: Activates the Windows licensing utility.
  * **Technique**: By modifying `HKCU\Software\Classes\exefile\shell\open\command`, attackers can redirect this executable to execute malicious code.
6. `dccw.exe`
  * **Location**: `C:\Windows\System32\dccw.exe`
  * **Description**: Display Color Calibration Wizard, which has `AutoElevate` enabled.
  * **Technique**: Attackers modify registry keys related to `dccw.exe` to run their payload, exploiting `AutoElevate` to bypass UAC prompts.
7. `cmstp.exe`
  * **Location**: `C:\Windows\System32\cmstp.exe`
  * **Description**: Connection Manager Profile Installer, which can run commands specified in an `.inf` file with elevated privileges.
  * **Technique**: Attackers create a custom `.inf` file with commands to execute and run it through `cmstp.exe` to bypass UAC.
8. `mshta.exe`
  * **Location**: `C:\Windows\System32\mshta.exe`
  * **Description**: Microsoft HTML Application host, used to execute HTML-based applications with scripting capabilities.
  * **Technique**: Attackers use `mshta.exe` to load a malicious script, often with a URL to an external payload. This is commonly used for fileless malware attacks and can sometimes bypass UAC depending on the environment.
9. `cmd.exe` and `powershell.exe` with Registry Hijacking
  * **Location**: `C:\Windows\System32\cmd.exe` and `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
  * **Description**: Both are command-line tools, and while they do not inherently bypass UAC, attackers can use registry hijacking to redirect elevated processes to execute these with higher privileges.
  * **Technique**: Attackers modify registry keys for executables that run with `AutoElevate`, setting them to execute `cmd.exe` or `powershell.exe` with elevated privileges to run their payload.
10. `explorer.exe`
  * **Location**: `C:\Windows\explorer.exe`
  * **Description**: The Windows file explorer can sometimes be exploited when UAC settings are misconfigured.
  * **Technique**: By manipulating how `explorer.exe` launches new elevated processes (e.g., using `ShellExecute` functions), attackers can bypass UAC to execute malicious code, although this method is less common in modern Windows versions.

**What is the GitHub link used by the attacker to download a tool for credential dumping?**

* Search for `network.protocol: dns and dns.question.registered_domain: github.com`
* The `process.pid` are: 5936, 1812, 6968, 6160 
* Search each PID and check `process.command_line`

**What is the username and hash of the new credential pair?**

* Search for executions of `mimikatz.exe` and command `sekurlsa::pth`

**What is the name of the file accessed by the attacker from a remote share?**

* Search for `process.parent.pid: 6160` as `6160` is the parent PID of the process executing `mimikatz.exe` in last question
* Order by `Time` ascending and show `process.command_line`
* Look for the two executions after the one with a `Invoke-ShareFinder` call

**What is the new set of credentials discovered by the attacker?**
**What is the hostname of the attacker's target machine for its lateral movement attempt?**

* Same search as last question
* Look for the next execution after the ones of last answer
* The username and password are passed in `-Credential` argument
* The target machine is passed in `-ComputerName` argument

**What is the parent process name of the malicious command executed on the second compromised machine?**

* Search for `host.hostname: WKSTN-1327 and event.category: process and user.name: allan.smith`
* Order by `Time` ascending and show `process.parent.pid`, `process.pid` and `process.command_line`
* Check the parent process executable of commands executed remotely from the other machine (the ones in previous answers)

**What is the username and hash of the newly dumped credentials?**

* Same search as last question
* Search for executions of `mimikatz.exe` and command `sekurlsa::pth`

**Aside from the administrator account, what account did the attacker dump?**

* Search for `host.hostname: DC01 and event.category: process and user.name: Administrator`
* Order by `Time` ascending and show `process.command_line`
* Search for executions of `mimikatz.exe` and command `lsadump::dcsync`

**What is the link used by the attacker to download the ransomware binary?**

* Same search as last question
* Search for executions of `powershell.exe` using `iwr` (alias for `Invoke-WebRequest`)
