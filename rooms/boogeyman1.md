# [Boogeyman 1](https://tryhackme.com/room/boogeyman1)

## Task 2 [Email Analysis] Look at that headers!

**What is the email address used to send the phishing email?**

```shell
grep From: ~/Desktop/artefacts/dump.eml
```

**What is the email address of the victim?**

```shell
grep To: ~/Desktop/artefacts/dump.eml
```

**What is the name of the third-party mail relay service used by the attacker based on the DKIM-Signature and List-Unsubscribe headers?**

```shell
grep DKIM-Signature ~/Desktop/artefacts/dump.eml
grep -A 4 List-Unsubscribe ~/Desktop/artefacts/dump.eml
```

**What is the name of the file inside the encrypted attachment?**

* Double-click on ~/Desktop/artefacts/dump.eml to open it with the email client
* Save Invoice.zip to ~/Desktop/artefacts

```shell
unzip -v ~/Desktop/artefacts/Invoice.zip
```

**What is the password of the encrypted attachment?**

```shell
grep encrypted dump.eml
```

**Based on the result of the lnkparse tool, what is the encoded payload found in the Command Line Arguments field?**

```shell
unzip ~/Desktop/artefacts/Invoice.zip
lnkparse Invoice_20230103.lnk | grep -oP '(?<=-enc ).*'
```

## Task 3 [Endpoint Security] Are you sure that’s an invoice?

**What are the domains used by the attacker for file hosting and C2?**

```shell
cat powershell.json | jq .ScriptBlockText | grep -oP '\w+\.\w+\.xyz' | sort -u
```

**What is the name of the enumeration tool downloaded by the attacker?**

```shell
cat powershell.json | jq .ScriptBlockText | grep -o '\b\w\{8\}\.exe\b'
```

**What is the file accessed by the attacker using the downloaded sq3.exe binary?**
**What is the software that uses the file in Q3?**

```shell
cat powershell.json | jq -s -c 'sort_by(.Timestamp) | .[] | .ScriptBlockText' | grep -E 'cd |sq3\.exe'
```

**What is the name of the exfiltrated file?**

```shell
cat powershell.json | jq -s -c 'sort_by(.Timestamp) | .[] | .ScriptBlockText' | grep kdbx
```

**What type of file uses the .kdbx file extension?**

* Just Google search it or ask ChatGPT

**What is the encoding used during the exfiltration attempt of the sensitive file?**

```shell
cat powershell.json | jq -s -c 'sort_by(.Timestamp) | .[] | .ScriptBlockText' | grep ToString
```

* Check [Hexadecimal format specifier (X)](https://learn.microsoft.com/en-us/dotnet/standard/base-types/standard-numeric-format-strings#XFormatString)

**What is the tool used for exfiltration?**

```shell
cat powershell.json | jq -s -c 'sort_by(.Timestamp) | .[] | .ScriptBlockText' | grep '$hex'
```

## Task 4 [Network Traffic Analysis] They got us. Call the bank immediately!

**What software is used by the attacker to host its presumed file/payload server?**

* Get the destination IP:
```shell
cat powershell.json | jq -s -c 'sort_by(.Timestamp) | .[] | .ScriptBlockText' | grep '$destination'
```

* Inpect the http responses from that IP:
```shell
tshark -r capture.pcapng -Y "http.response && ip.src == 167.71.211.113" -T fields -e ip.src -e http.server | sort -u
```

**What HTTP method is used by the C2 for the output of the commands executed by the attacker?**

* Get the IPs of the C2 domains:
```shell
tshark -r capture.pcapng \
-Y "dns.flags.response == 1 && (dns.qry.name == cdn.bpakcaging.xyz || dns.qry.name == files.bpakcaging.xyz)" \
-T fields -e dns.a -e dns.qry.name | sort -u
159.89.205.40	cdn.bpakcaging.xyz
167.71.211.113	files.bpakcaging.xyz
```

* Http methods used:
```shell
tshark -r capture.pcapng \
-Y "http.request && (ip.dst == 159.89.205.40 || ip.dst == 167.71.211.113)" \
-T fields -e http.request.method | sort -u
```

**What is the protocol used during the exfiltration activity?**

Already answered that the tool used for exfiltration was nslookup ...

```shell
tshark -r capture.pcapng -Y 'dns.flags.response == 0 && dns.qry.name matches "\.bpakcaging\.xyz$"' -T fields -e dns.qry.name
```

**What is the password of the exfiltrated file?**

* Extract all the data sent to the C2:
```shell
tshark -r capture.pcapng \
-Y "http.request && (ip.dst == 159.89.205.40 || ip.dst == 167.71.211.113) && http.request.method == POST" \
-T fields -e http.file_data | \
while read -r -a codes; do
  for code in "${codes[@]}"; do
    printf "\\$(printf '%o' "$code")"
  done
done > c2_data.log
```

* Search the sq3.exe output:
```shell
grep -a -A 5 "Master Password" c2_data.log
```

**What is the credit card number stored inside the exfiltrated file?**

* Extract all the data exfiltrated via DNS:
```shell
tshark -r capture.pcapng \
-Y 'dns.flags.response == 0 && dns.qry.name matches "\.bpakcaging\.xyz$" && dns.qry.name != cdn.bpakcaging.xyz && dns.qry.name != files.bpakcaging.xyz' \
-T fields -e dns.qry.name | \
sed 's/\.bpakcaging\.xyz//' | tr -d '\n' | \
xxd -r -p > dns_exfiltrated_data.kdbx
```

* Open the file using the password of previous question:
```shell
keepass2 dns_exfiltrated_data.kdbx
```
