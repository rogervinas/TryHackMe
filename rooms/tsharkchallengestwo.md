# [TShark Challenge II: Directory](https://tryhackme.com/r/room/tsharkchallengestwo)

Use [CyberChef](https://gchq.github.io/CyberChef/) to defang

## Task 2 Case: Directory Curiosity!

**What is the name of the malicious/suspicious domain?**

```shell
tshark -r directory-curiosity.pcap -Y 'dns' -T fields -e dns.qry.name | sort -u
```

**What is the total number of HTTP requests sent to the malicious domain?**

```shell
tshark -r directory-curiosity.pcap -T fields -e http.request.full_uri -Y 'http.request.full_uri contains jx2' | wc -l
```

**What is the IP address associated with the malicious domain?**

```shell
tshark -r directory-curiosity.pcap -Y 'dns' -T fields -e dns.qry.name -e dns.a -Y 'dns.qry.name contains jx2 && dns.flags.response == 1'
```

**What is the server info of the suspicious domain?**

```shell
tshark -r directory-curiosity.pcap -Y 'ip.src == 141.164.41.174' -T fields -e http.server | sort -u
```

**What is the number of listed files?**
**What is the filename of the first file?**

```shell
tshark -r directory-curiosity.pcap -z follow,tcp,ascii,0 -q | grep -oP '(?<=<a href=")[^"?]*'
```

**What is the name of the downloaded executable file?**

```shell
tshark -r directory-curiosity.pcap --export-objects http,/tmp/extracted-by-tshark -q
ls -la /tmp/extracted-by-tshark/
```

**What is the SHA256 value of the malicious file?**

```shell
sha256sum /tmp/extracted-by-tshark/vlauto.exe
```

**What is the "PEiD packer" value?**

https://www.virustotal.com/gui/file/b4851333efaf399889456f78eac0fd532e9d8791b23a86a19402c1164aed20de/details

**What does the "Lastline Sandbox" flag this as?**

https://www.virustotal.com/gui/file/b4851333efaf399889456f78eac0fd532e9d8791b23a86a19402c1164aed20de/behavior
