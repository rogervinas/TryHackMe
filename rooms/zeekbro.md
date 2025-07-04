# [Zeek](https://tryhackme.com/room/zeekbro)

## Task 2 Network Security Monitoring and Zeek

**What is the installed Zeek instance version number?**

```shell
zeek -v
```

**What is the version of the ZeekControl module?**

```shell
zeekctl -v
```

**Investigate the "sample.pcap" file. What is the number of generated alert files?**

```shell
cd ~/Desktop/Exercise-Files/TASK-2
zeek -C -r sample.pcap
ls -la *.log | wc -l
```

## Task 3 Zeek Logs

**Investigate the dhcp.log file. What is the available hostname?**

```shell
cd ~/Desktop/Exercise-Files/TASK-3
zeek -C -r sample.pcap
cat dhcp.log | zeek-cut host_name
```

**Investigate the dns.log file. What is the number of unique DNS queries?**

```shell
cat dns.log | zeek-cut query | sort -u | wc -l
```

**Investigate the conn.log file. What is the longest connection duration?**

```shell
cat conn.log | zeek-cut duration | sort -n | tail -1
```

## Task 5 Zeek Signatures

**What is the source IP of the first event?**
**What is the source port of the second event?**

```shell
cd ~/Desktop/Exercise-Files/TASK-5/http
echo '
signature http-password {
    ip-proto == tcp
    dst-port == 80
    payload /.*password.*/
    event "Cleartext Password Found!"
}' > http-password.sig
zeek -C -r http.pcap -s http-password.sig
cat signatures.log | zeek-cut src_addr src_port
```

**What is the total number of the sent and received packets from source port 38706?**

```shell
cat conn.log | zeek-cut id.orig_p orig_pkts resp_pkts | grep 38706
```

**What is the number of unique events?**

```shell
cd ~/Desktop/Exercise-Files/TASK-5/ftp
echo '
signature ftp-username {
    ip-proto == tcp
    ftp /.*USER.*/
    event "FTP Username Input Found!"
}
signature ftp-brute {
    ip-proto == tcp
     payload /.*530.*Login.*incorrect.*/
    event "FTP Brute-force Attempt!"
}' > ftp-bruteforce.sig
zeek -C -r ftp.pcap -s ftp-bruteforce.sig
cat notice.log | zeek-cut uid | sort -u | wc -l
```

**What is the number of ftp-brute signature matches?**

```shell
cat signatures.log | zeek-cut event_msg | grep "FTP Brute-force" | wc -l
```

## Task 6 Zeek Scripts | Fundamentals

**What is the domain value of the "vinlap01" host?**

```shell
cd ~/Desktop/Exercise-Files/TASK-6/smallflow
zeek -C -r smallFlows.pcap dhcp-hostname.zeek
cat dhcp.log | zeek-cut host_name domain | grep vinlap01
```

**What is the number of identified unique hostnames?**

```shell
cd ~/Desktop/Exercise-Files/TASK-6/bigflow
zeek -C -r bigFlows.pcap dhcp-hostname.zeek
cat dhcp.log | zeek-cut host_name | sort -u | grep -v "^-$" | wc -l
```

**What is the identified domain value?**

```shell
cat dhcp.log | zeek-cut domain | sort -u | grep -v "^-$"
```

## Task 7 Zeek Scripts | Scripts and Signatures

**What is the number of the detected new connections?**

```shell
cd ~/Desktop/Exercise-Files/TASK-7/101
zeek -C -r sample.pcap 103.zeek | grep "New Connection Found" | wc -l
```

**What is the number of signature hits?**

```shell
cd ~/Desktop/Exercise-Files/TASK-7/201
zeek -C -r ftp.pcap -s ftp-admin.sig
cat signatures.log | zeek-cut event_msg | grep "FTP Username Input Found" | wc -l
```

**What is the total number of "administrator" username detections?**

```shell
cat signatures.log | zeek-cut event_msg sub_msg | grep "FTP Username Input Found" | grep "USER administrator" | wc -l
```

**What is the total number of loaded scripts?**

```shell
./clear-logs.sh
zeek -C -r ftp.pcap local
cat loaded_scripts.log | zeek-cut name | grep .zeek | wc -l
```

**What is the total number of brute-force detections?**

```shell
cd ~/Desktop/Exercise-Files/TASK-7/202
zeek -C -r ftp-brute.pcap /opt/zeek/share/zeek/policy/protocols/ftp/detect-bruteforcing.zeek
cat notice.log | zeek-cut note
```

## Task 8 Zeek Scripts | Frameworks

**Look at the second finding, where was the intel info found?**

```shell
cd ~/Desktop/Exercise-Files/TASK-8
zeek -C -r case1.pcap intelligence-demo.zeek
cat intel.log | zeek-cut seen.where
```

**What is the name of the downloaded .exe file?**

```shell
cat http.log | zeek-cut uri | grep .exe
```

**What is the MD5 hash of the downloaded .exe file?**

```shell
zeek -C -r case1.pcap hash-demo.zeek
cat files.log | zeek-cut mime_type md5 | grep x-dosexec
```

**What is written in the file?**

```shell
zeek -C -r case1.pcap file-extract-demo.zeek
fuid=$(cat files.log | zeek-cut mime_type fuid | grep "text/plain" | awk '{print $2}')
cat extract_files/*${fuid}*
```

## Task 9 Zeek Scripts | Packages

**Which username has more module hits?**

```shell
cd ~/Desktop/Exercise-Files/TASK-9/cleartext-pass
zeek -C -r http.pcap zeek-sniffpass
cat notice.log | zeek-cut msg
```

**What is the name of the identified City?**

```shell
cd ~/Desktop/Exercise-Files/TASK-9/geoip-conn
zeek -C -r case2.pcap geoip-conn
cat conn.log | zeek-cut geo.resp.city | sort -u
```

**Which IP address is associated with the identified City?**

```shell
cat conn.log | zeek-cut geo.resp.city id.resp_h | sort -u
```

**How many types of status codes are there in the given traffic capture?**

```shell
./clear-logs.sh
zeek -C -r case2.pcap sumstats-counttable.zeek
cat http.log | zeek-cut status_code | sort -u | wc -l
```
