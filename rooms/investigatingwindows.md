# [Investigating Windows](https://tryhackme.com/room/investigatingwindows)

## Task 1 Investigating Windows

**Whats the version and year of the windows machine?**

```powershell
# Manually using "System Information" (msinfo32)
Get-CimInstance Win32_OperatingSystem | Select-Object -Property Caption
```

**Which user logged in last?**

```powershell
# Manually via "Event Viewer" (eventvwr.msc) check Windows Logs > Security
$logonEvents = Get-WinEvent -FilterXPath "*[System[EventID=4624]]" -LogName Security -MaxEvents 1
foreach ($event in $logonEvents) {
    $eventXml = [xml]$event.ToXml()
    $accountName = $eventXml.Event.EventData.Data | Where-Object {$_.Name -eq 'TargetUserName'} | Select-Object -ExpandProperty '#text'
    Write-Output "Account Name: $accountName"
}
```

**When did John log onto the system last?**

```powershell
# Manually via "Event Viewer" (eventvwr.msc) check Windows Logs > Security
Get-WinEvent `
  -FilterXPath "*[System[EventID=4624]] and *[EventData[Data[@Name='TargetUserName']='John']]" `
  -LogName Security -MaxEvents 1 | `
  Format-List *
```

**What IP does the system connect to when it first starts?**

* Just restart the machine a cmd window will be executed

**What two accounts had administrative privileges (other than the Administrator user)?**

```powershell
# Manually via "Local Users and Groups" (lusrmgr.msc) check users member of "Administrators" group
Get-WmiObject win32_groupuser | `
  Where-Object { $_.GroupComponent -match ‘administrators’ } | `
  ForEach-Object { [wmi]$_.PartComponent } | `
  Format-List Name
```

**What is the name of the scheduled task that is malicious?**
**What file was the task trying to run daily?**
**What port did this file listen locally for?**
**What tool was used to get Windows passwords?**

```shell
# Manually via "Task Scheduler" (taskschd.msc)
Get-ScheduledTask | Select-Object -Property TaskName -ExpandProperty Actions | Format-List *
```

**When did Jenny last logon?**

```powershell
Get-WinEvent `
  -FilterXPath "*[System[EventID=4624]] and *[EventData[Data[@Name='TargetUserName']='Jenny']]" `
  -LogName Security -MaxEvents 1 | `
  Format-List *
```

**At what date did the compromise take place?**
**During the compromise, at what time did Windows first assign special privileges to a new logon?**

```powershell
Get-WinEvent -FilterXPath "*[System[EventID=4672]]" -LogName Security | Format-List *
```

**What was the attackers external control and command servers IP?**
**Check for DNS poisoning, what site was targeted?**

```powershell
cat C:\Windows\System32\drivers\etc\hosts
```

**What was the extension name of the shell uploaded via the servers website?**

```powershell
ls C:\inetpub\wwwroot\
```

**What was the last port the attacker opened?**

```shell
$events = Get-WinEvent -LogName "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall"
foreach ($event in $events) {
    $eventXml = [xml]$event.ToXml()
    $ruleName = $eventXml.Event.EventData.Data | `
      Where-Object {$_.Name -eq 'RuleName'} | `
      Select-Object -ErrorAction Ignore -ExpandProperty '#text'
    $localPorts = $eventXml.Event.EventData.Data | `
      Where-Object {$_.Name -eq 'LocalPorts'} | `
      Select-Object -ErrorAction Ignore -ExpandProperty '#text'
    if ($localPorts -ne $null) {
        Write-Output "$($event.Id) $($event.TimeCreated) LocalPorts: $localPorts | $ruleName"
    }
}
```
