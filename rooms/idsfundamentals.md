# [IDS Fundamentals](https://tryhackme.com/r/room/idsfundamentals)

## Task 5 Practical Lab

**What is the IP address of the machine that tried to connect to the subject machine using SSH?**

```shell
sudo snort -q -l /var/log/snort -r /etc/snort/Intro_to_IDS.pcap -A console -c /etc/snort/snort.conf | \
  grep "SSH Connection Detected" | awk '{print $11}' | sort -u
```

**What other rule message besides the SSH message is detected in the PCAP file?**

```shell
sudo snort -q -l /var/log/snort -r /etc/snort/Intro_to_IDS.pcap -A console -c /etc/snort/snort.conf | \
  awk -F] '{print $3}' | sort -u
```

**What is the sid of the rule that detects SSH?**

```shell
sudo snort -q -l /var/log/snort -r /etc/snort/Intro_to_IDS.pcap -A console -c /etc/snort/snort.conf | \
  grep "SSH Connection Detected" | awk '{print $3}'
```
