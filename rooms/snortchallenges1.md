# [Snort Challenge - The Basics](https://tryhackme.com/room/snortchallenges1)

## Task 2 Writing IDS Rules (HTTP)

**What is the number of detected packets?**

```shell
cd ~/Desktop/Exercise-Files/TASK-2\ \(HTTP\)/
echo 'alert tcp any any <> any 80 (msg:"To 80"; sid:1000003;)' > local.rules
echo 'alert tcp any 80 <> any any (msg:"From 80"; sid:1000004;)' >> local.rules
rm alert snort.log.*
snort -c local.rules -A full -l . -r mx-3.pcap
```

**What is the destination address of packet 63?**

```shell
grep "\->" alert | head -63 | tail -1
```

**What is the ACK number of packet 64?**

```shell
grep "Ack" alert | head -64 | tail -1
```

**What is the SEQ number of packet 62?**

```shell
grep "Seq" alert | head -62 | tail -1
```

**What is the TTL of packet 65?**

```shell
grep "TTL" alert | head -65 | tail -1
```

**What is the source IP of packet 65?**
**What is the source port of packet 65?**

```shell
grep "\->" alert | head -65 | tail -1
```

## Task 3 Writing IDS Rules (FTP)

**What is the number of detected packets?**

```shell
cd ~/Desktop/Exercise-Files/TASK-3\ \(FTP\)/
echo 'alert tcp any any <> any 21 (msg:"To 21"; sid:1000003;)' > local.rules
echo 'alert tcp any 21 <> any any (msg:"From 21"; sid:1000004;)' >> local.rules
rm alert snort.log.*
snort -c local.rules -A full -l . -r ftp-png-gif.pcap
```

**What is the FTP service name?**

```shell
grep -a 220 snort.log.*
```

**Write a rule to detect failed FTP login attempts in the given pcap.**
**What is the number of detected packets?**

```shell
echo 'alert tcp any any <> any 21 (msg:"To 21"; sid:1000003; content:"530 User";)' > local.rules
rm alert snort.log.*
snort -c local.rules -A full -l . -r ftp-png-gif.pcap
```

**Write a rule to detect successful FTP logins in the given pcap.**
**What is the number of detected packets?**

```shell
echo 'alert tcp any any <> any 21 (msg:"To 21"; sid:1000003; content:"230 User";)' > local.rules
rm alert snort.log.*
snort -c local.rules -A full -l . -r ftp-png-gif.pcap
```

**Write a rule to detect failed FTP login attempts with a valid username but a bad password or no password.**
**What is the number of detected packets?**

```shell
echo 'alert tcp any any <> any 21 (msg:"To 21"; sid:1000003; content:"331 Password";)' > local.rules
rm alert snort.log.*
snort -c local.rules -A full -l . -r ftp-png-gif.pcap
```

**Write a rule to detect failed FTP login attempts with "Administrator" username but a bad password or no password.**
**What is the number of detected packets?**

```shell
echo 'alert tcp any any <> any 21 (msg:"To 21"; sid:1000003; content:"331 Password"; content:"Administrator";)' > local.rules
rm alert snort.log.*
snort -c local.rules -A full -l . -r ftp-png-gif.pcap
```

## Task 4 Writing IDS Rules (PNG)

**Investigate the logs and identify the software name embedded in the packet.**

```shell
cd ~/Desktop/Exercise-Files/TASK-4\ \(PNG\)/
echo 'alert tcp any any <> any any (msg:"PNG content"; sid:1000003; content:"PNG";)' > local.rules
rm alert snort.log.*
snort -c local.rules -A full -l . -r ftp-png-gif.pcap
xxd snort.log.*
```

```shell
cd ~/Desktop/Exercise-Files/TASK-4\ \(PNG\)/
echo 'alert tcp any any <> any any (msg:"GIF content"; sid:1000003; content:"GIF")' > local.rules
rm alert snort.log.*
snort -c local.rules -A full -l . -r ftp-png-gif.pcap
xxd snort.log.*
```

## Task 5 Writing IDS Rules (Torrent Metafile)

**What is the number of detected packets?**

```shell
cd ~/Desktop/Exercise-Files/TASK-5\ \(TorrentMetafile\)/
echo 'alert tcp any any <> any any (msg:"Torrent content"; sid:1000003; content:".torrent")' > local.rules
rm alert snort.log.*
snort -c local.rules -A full -l . -r torrent.pcap
```

**What is the name of the torrent application?**
**What is the MIME (Multipurpose Internet Mail Extensions) type of the torrent metafile?**
**What is the hostname of the torrent metafile?**

```shell
cat snort.log.*
```

## Task 6 Troubleshooting Rule Syntax Errors

**What is the number of the detected packets?**

```shell
cd ~/Desktop/Exercise-Files/TASK-6\ \(Troubleshooting\)/
echo 'alert tcp any 3372 -> any any (msg: "Troubleshooting 1"; sid:1000001; rev:1;)' > local-1-fixed.rules
sudo snort -c local-1-fixed.rules -r mx-1.pcap -A console
```

**What is the number of the detected packets?**

```shell
echo 'alert icmp any any -> any any (msg: "Troubleshooting 2"; sid:1000001; rev:1;)' > local-2-fixed.rules
sudo snort -c local-2-fixed.rules -r mx-1.pcap -A console
```

**What is the number of the detected packets?**

```shell
echo 'alert icmp any any -> any any (msg: "ICMP Packet Found"; sid:1000001; rev:1;)' > local-3-fixed.rules
echo 'alert tcp any any -> any [80,443] (msg: "HTTPX Packet Found"; sid:1000002; rev:1;)' >> local-3-fixed.rules
sudo snort -c local-3-fixed.rules -r mx-1.pcap -A console
```

**What is the number of the detected packets?**

```shell
echo 'alert icmp any any -> any any (msg: "ICMP Packet Found"; sid:1000001; rev:1;)' > local-4-fixed.rules
echo 'alert tcp any [80,443] -> any any (msg: "HTTPX Packet Found"; sid:1000002; rev:1;)' >> local-4-fixed.rules
sudo snort -c local-4-fixed.rules -r mx-1.pcap -A console
```

**What is the number of the detected packets?**

```shell
echo 'alert icmp any any <> any any (msg: "ICMP Packet Found"; sid:1000001; rev:1;)' > local-5-fixed.rules
echo 'alert icmp any any -> any any (msg: "Inbound ICMP Packet Found"; sid:1000002; rev:1;)' >> local-5-fixed.rules
echo 'alert tcp any any -> any [80,443] (msg: "HTTPX Packet Found"; sid:1000003; rev:1;)' >> local-5-fixed.rules
sudo snort -c local-5-fixed.rules -r mx-1.pcap -A console
```

**What is the number of the detected packets?**

```shell
echo 'alert tcp any any <> any 80 (msg: "GET Request Found"; content:"get"; sid: 100001; rev:1; nocase;)' > local-6-fixed.rules
sudo snort -c local-6-fixed.rules -r mx-1.pcap -A console
```

**What is the number of the detected packets?**

```shell
echo 'alert tcp any any <> any 80 (msg: "HTML content"; content:".html"; sid: 100001; rev:1;)' > local-7-fixed.rules
sudo snort -c local-7-fixed.rules -r mx-1.pcap -A console
```

## Task 7 Using External Rules (MS17-010)

**What is the number of detected packets?**

```shell
cd ~/Desktop/Exercise-Files/TASK-7\ \(MS17-10\)/
sudo snort -c local.rules -r ms-17-010.pcap -A console
```

**What is the number of detected packets?**

```shell
echo 'alert tcp any any <> any any (msg: "IPC content"; content:"\\IPC$"; sid: 100001; rev:1;)' > local-1.rules
rm alert snort.log.*
snort -c local-1.rules -A full -l . -r ms-17-010.pcap
cat snort.log.*
```

**What is the CVSS v2 score of the MS17-010 vulnerability?**

https://nvd.nist.gov/vuln/detail/CVE-2017-0148

## Task 8 Using External Rules (Log4j)

**What is the number of detected packets?**

```shell
cd ~/Desktop/Exercise-Files/TASK-8\ \(Log4j\)/
rm alert snort.log.*
snort -c local.rules -A full -l . -r log4j.pcap
```

**How many rules were triggered?**

```shell
grep '\[\*\*\]' alert | sort -u | wc -l
```

**What are the first six digits of the triggered rule sids?**

```shell
grep '\[\*\*\]' alert | sort -u
```

**What is the number of detected packets?**

```shell
echo 'alert tcp any any <> any any (msg:"Payload size"; dsize:770<>855; sid:1000001; rev:1;)' > local-1.rules
rm alert snort.log.*
snort -c local-1.rules -A full -l . -r log4j.pcap
```

**What is the name of the used encoding algorithm?**

```shell
grep -a Base64 snort.log.*
```

**What is the IP ID of the corresponding packet?**

```shell
grep 45.155.205.233 alert -A 1
```

**What is the attacker's command?**

```shell
grep -aoP 'Base64/\K[^}]+' snort.log.* | sort -u | base64 -d
```

**What is the CVSS v2 score of the Log4j vulnerability?**

https://nvd.nist.gov/vuln/detail/CVE-2021-44228
