# [Brim](https://tryhackme.com/room/brim)

## Task 6 Exercise: Threat Hunting with Brim | Malware C2 Detection

**What is the name of the file downloaded from the CobaltStrike C2 connection?**

```
_path=="http" | cut id.orig_h, id.resp_h, id.resp_p, method, host, uri | uniq -c | sort value.uri
```

**What is the number of CobaltStrike connections using port 443?**

```
_path=="conn" id.resp_h == 104.168.44.45 id.resp_p == 443 | cut id.resp_h | uniq -c
```

**What is the name of the secondary C2 channel?**

```
event_type=="alert" | cut alert.signature | sort -r | uniq -c | sort -r count
event_type=="alert" alert.signature=="ET MALWARE Win32/IcedID Request Cookie"
```

## Task 7 Exercise: Threat Hunting with Brim | Crypto Mining

**How many connections used port 19999?**

```
_path=="conn" id.resp_p == 19999 | cut id.resp_p | uniq -c
```

**What is the name of the service used by port 6666?**

```
_path=="conn" id.resp_p == 6666 | cut service | uniq -c
```

**What is the amount of transferred total bytes to "101.201.172.235:8888"?**

```
_path=="conn" id.resp_h == 101.201.172.235 id.resp_p == 8888 | summarize sum(orig_bytes + resp_bytes)
```

**What is the detected MITRE tactic id?**

```
event_type=="alert" | cut alert.metadata.mitre_tactic_id | sort | uniq -c
```