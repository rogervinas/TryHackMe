# 🎄 [Advent of Cyber 2024](https://tryhackme.com/r/room/adventofcyber2024)

## OPSEC - Day 1: Maybe SOC-mas music, he thought, doesn't come from a store?

**Operational Security (OPSEC)** is a set of principals and tactics used to attempt to protect the security of an operator or operation. An example of this may be using code names instead of your real names, or using a proxy to conceal your IP address.

**Looks like the song.mp3 file is not what we expected! Run "exiftool song.mp3" in your terminal to find out the author of the song. Who is the author?**

```shell
exiftool song.mp3 | grep Artist
```

**The malicious PowerShell script sends stolen info to a C2 server. What is the URL of this C2 server?**

```shell
curl -s https://raw.githubusercontent.com/MM-WarevilleTHM/IS/refs/heads/main/IS.ps1 | grep "c2Url ="
```

**Who is M.M? Maybe his Github profile page would provide clues?**

Go to https://github.com/MM-WarevilleTHM/M.M

**What is the number of commits on the GitHub repo where the issue was raised?**

Go to https://github.com/MM-WarevilleTHM/IS/commits/main/

**What's with all these GitHub repos? Could they hide something else?**

* https://github.com/MM-WarevilleTHM/M.M/commits/main/ has 5 commits
* Both repos have some forks
* Other than that, nothing `¯\_(ツ)_/¯`

## Log analysis - Day 2: One man's false positive is another man's potpourri

**What is the name of the account causing all the failed login attempts?**
**How many failed logon attempts were observed?**

* Select events between "November 29 0:00" and "December 1 23:30"
* Select fields `user.name`, `event.category` and `event.outcome`
* Search/Filter by `event.category = authentication AND event.outcome = failure`

**What is the IP address of Glitch?**

* On the previous search, add field `source.ip`
* Filter by different values of `source.ip` and select the one that caused the spike

**When did Glitch successfully logon to ADM-01?**

* On the previous search ...
* Search/Filter by `event.category = authentication AND event.outcome = success AND source.ip = <Glitch IP>`

**What is the decoded command executed by Glitch to fix the systems of Wareville?**

* Select fields `event.category` and `process.command_line`
* Search/Filter by `event.category = process`
* Check `powershell.exe` executions with a `-EncodedCommand` value
* Put that value in [CyberChef](https://gchq.github.io/CyberChef/#recipe=From_Base64('A-Za-z0-9%2B/%3D',true,false)Decode_text('UTF-16LE%20(1200)')&input=U1FCdUFITUFkQUJoQUd3QWJBQXRBRmNBYVFCdUFHUUFid0IzQUhNQVZRQndBR1FBWVFCMEFHVUFJQUF0QUVFQVl3QmpBR1VBY0FCMEFFRUFiQUJzQUNBQUxRQkJBSFVBZEFCdkFGSUFaUUJpQUc4QWJ3QjBBQT09)
