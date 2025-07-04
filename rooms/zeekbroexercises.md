# [Zeek Exercises](https://tryhackme.com/room/zeekbroexercises)

## Task 2 Anomalous DNS

**What is the number of DNS records linked to the IPv6 address?**

```shell
cd ~/Desktop/Exercise-Files/anomalous-dns
zeek -C -r dns-tunneling.pcap
grep AAAA dns.log | wc -l
```

**What is the longest connection duration?**

```shell
cat conn.log | zeek-cut duration | sort -n | tail -1
```

**What is the number of unique domain queries?**

```shell
cat dns.log | zeek-cut query | rev |  cut -d '.' -f-2 | sort -u | rev | wc -l
```

**What is the IP address of the source host?**

```shell
cat conn.log | zeek-cut id.orig_h id.resp_p | sort -u | grep 53
```

## Task 3 Phishing

**What is the suspicious source address?**

```shell
cd ~/Desktop/Exercise-Files/phishing
zeek -C -r phishing.pcap
cat http.log | zeek-cut id.orig_h uri
https://gchq.github.io/CyberChef/#recipe=Defang_IP_Addresses()
```

**Which domain address were the malicious files downloaded from?**

```shell
cat http.log | zeek-cut uri host
https://gchq.github.io/CyberChef/#recipe=Defang_URL(true,true,true,'Valid%20domains%20and%20full%20URLs')
```

**What kind of file is associated with the malicious document?**

```shell
./clear-logs.sh
zeek -C -r phishing.pcap file-extract-demo.zeek
fuid=$(cat files.log | zeek-cut mime_type fuid | grep "application/msword" | awk '{print $2}')
md5sum extract_files/*${fuid}*
```

https://www.virustotal.com/gui/file/f808229aa516ba134889f81cd699b8d246d46d796b55e13bee87435889a054fb/relations

**What is the given file name in Virustotal?**

```shell
fuid=$(cat files.log | zeek-cut mime_type fuid | grep "application/x-dosexec" | awk '{print $2}')
md5sum extract_files/*${fuid}*
```

https://www.virustotal.com/gui/file/749e161661290e8a2d190b1a66469744127bc25bf46e5d0c6f2e835f4b92db18/details

**What is the contacted domain name?**

https://www.virustotal.com/gui/file/749e161661290e8a2d190b1a66469744127bc25bf46e5d0c6f2e835f4b92db18/behavior

**What is the request name of the downloaded malicious .exe file?**

```shell
cat http.log | zeek-cut uri | grep .exe
```

## Task 4 Log4J

**What is the number of signature hits?**

```shell
cd ~/Desktop/Exercise-Files/log4j
zeek -C -r log4shell.pcapng detection-log4j.zeek
cat signatures.log | zeek-cut uid | wc -l
```

**Which tool is used for scanning?**

```shell
cat http.log | zeek-cut user_agent | sort -u
```

**What is the extension of the exploit file?**

```shell
cat http.log | zeek-cut uri | sort -u
```

**What is the name of the created file?**

```shell
cat log4j.log | zeek-cut uri | grep -aoP 'Base64/\K[^}]+' | base64 -d
```
