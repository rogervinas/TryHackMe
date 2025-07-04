# [Retracted](https://tryhackme.com/r/room/retracted)

## Task 2 The Message

**What is the time of execution of the process that created the text file?**

```powershell
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" | `
Where-Object { $_.Id -eq 1 -and $_.Message -like "*notepad.exe*" -and $_.Message -like "*SOPHIE.txt*" } | `
ForEach-Object {
    [xml]$event = $_.ToXml()
    $utcTime = $event.Event.EventData.Data | Where-Object { $_.Name -eq "UtcTime" } | Select-Object -ExpandProperty "#text"
    $commandLine = $event.Event.EventData.Data | Where-Object { $_.Name -eq "CommandLine" } | Select-Object -ExpandProperty "#text"
    Write-Output "$utcTime $commandLine"
}
```

## Task 3 Something Wrong

**What is the filename of this "installer"?**
**What is the download location of this installer?**

```powershell
$startDate = Get-Date "2024-01-08 14:00:00"
$endDate = Get-Date "2024-01-08 14:25:30"

Get-WinEvent -FilterHashtable @{
    LogName = 'Microsoft-Windows-Sysmon/Operational'
    StartTime = $startDate
    EndTime = $endDate
} | `
Where-Object { $_.Id -eq 1 -and $_.Message -like "*download*.exe*" } | `
ForEach-Object {
    [xml]$event = $_.ToXml()
    $utcTime = $event.Event.EventData.Data | Where-Object { $_.Name -eq "UtcTime" } | Select-Object -ExpandProperty "#text"
    $commandLine = $event.Event.EventData.Data | Where-Object { $_.Name -eq "CommandLine" } | Select-Object -ExpandProperty "#text"
    Write-Output "$utcTime $commandLine"
}
```

**The installer encrypts files and then adds a file extension to the end of the file name. What is this file extension?**

```powershell
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" | `
Where-Object { $_.Id -eq 11 -and $_.Message -like "*antivirus.exe*" } | `
ForEach-Object {
    [xml]$event = $_.ToXml()
    $utcTime = $event.Event.EventData.Data | Where-Object { $_.Name -eq "UtcTime" } | Select-Object -ExpandProperty "#text"
    $image = $event.Event.EventData.Data | Where-Object { $_.Name -eq "Image" } | Select-Object -ExpandProperty "#text"
    $targetFilename = $event.Event.EventData.Data | Where-Object { $_.Name -eq "TargetFilename" } | Select-Object -ExpandProperty "#text"
    Write-Output "$utcTime $image $targetFilename"
}
```

**The installer reached out to an IP. What is this IP?**

```powershell
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" | `
Where-Object { $_.Id -eq 3 -and $_.Message -like "*antivirus.exe*" } | `
ForEach-Object {
    [xml]$event = $_.ToXml()
    $utcTime = $event.Event.EventData.Data | Where-Object { $_.Name -eq "UtcTime" } | Select-Object -ExpandProperty "#text"
    $image = $event.Event.EventData.Data | Where-Object { $_.Name -eq "Image" } | Select-Object -ExpandProperty "#text"
    $destinationIp = $event.Event.EventData.Data | Where-Object { $_.Name -eq "DestinationIp" } | Select-Object -ExpandProperty "#text"
    Write-Output "$utcTime $image $destinationIp"
}
```

## Task 4 Back to Normal

**The threat actor logged in via RDP right after the “installer” was downloaded. What is the source IP?**

```powershell
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" | `
Where-Object { $_.Id -eq 3 -and $_.Message -like "*3389*" } | `
ForEach-Object {
    [xml]$event = $_.ToXml()
    $utcTime = $event.Event.EventData.Data | Where-Object { $_.Name -eq "UtcTime" } | Select-Object -ExpandProperty "#text"
    $image = $event.Event.EventData.Data | Where-Object { $_.Name -eq "Image" } | Select-Object -ExpandProperty "#text"
    $sourceIp = $event.Event.EventData.Data | Where-Object { $_.Name -eq "SourceIp" } | Select-Object -ExpandProperty "#text"
    $sourcePort = $event.Event.EventData.Data | Where-Object { $_.Name -eq "SourcePort" } | Select-Object -ExpandProperty "#text"
    $destinationIp = $event.Event.EventData.Data | Where-Object { $_.Name -eq "DestinationIp" } | Select-Object -ExpandProperty "#text"
    $destinationPort = $event.Event.EventData.Data | Where-Object { $_.Name -eq "DestinationPort" } | Select-Object -ExpandProperty "#text"
    Write-Output "$utcTime $image $sourceIp $sourcePort => $destinationIp $destinationPort"
}
```

**This other person downloaded a file and ran it. When was this file run?**

```powershell
$startDate = Get-Date "2024-01-08 14:00:00"
$endDate = Get-Date "2024-01-08 14:25:30"

Get-WinEvent -FilterHashtable @{
    LogName = 'Microsoft-Windows-Sysmon/Operational'
    StartTime = $startDate
    EndTime = $endDate
} | `
Where-Object { $_.Id -eq 1 -and $_.Message -like "*download*.exe*" } | `
ForEach-Object {
    [xml]$event = $_.ToXml()
    $utcTime = $event.Event.EventData.Data | Where-Object { $_.Name -eq "UtcTime" } | Select-Object -ExpandProperty "#text"
    $commandLine = $event.Event.EventData.Data | Where-Object { $_.Name -eq "CommandLine" } | Select-Object -ExpandProperty "#text"
    Write-Output "$utcTime $commandLine"
}
```
