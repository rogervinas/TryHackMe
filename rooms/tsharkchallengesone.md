# [TShark Challenge I: Teamwork](https://tryhackme.com/r/room/tsharkchallengesone)

Use [CyberChef](https://gchq.github.io/CyberChef/) to defang

## Task 2 Case: Teamwork!

**What is the full URL of the malicious/suspicious domain address?**

```shell
tshark -r teamwork.pcap -Y 'dns' -T fields -e dns.qry.name -e dns.a | sort -u
```

**When was the URL of the malicious/suspicious domain address first submitted to VirusTotal?**

https://www.virustotal.com/gui/domain/www.paypal.com4uswebappsresetaccountrecovery.timeseaways.com/relations

**What is the IP address of the malicious domain?**

```shell
tshark -r teamwork.pcap -Y 'dns' -T fields -e dns.qry.name -e dns.a -Y 'dns.qry.name contains paypal && dns.flags.response == 1'
```

**What is the email address that was used?**

```shell
tshark -r teamwork.pcap -V | grep -o '[a-zA-Z0-9._%+-]\+@[a-zA-Z0-9.-]\+\.[a-zA-Z]\{3,\}'
```
