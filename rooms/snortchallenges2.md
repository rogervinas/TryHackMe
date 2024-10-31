# [Snort Challenge - Live Attacks](https://tryhackme.com/room/snortchallenges2)

## Task 2 Scenario 1 | Brute-Force

**First of all, start Snort in sniffer mode and try to figure out the attack source, service and port.**

```shell
sudo snort -X -n 1000 > snort.log
more snort.log
```

**Stop the attack and get the flag (which will appear on your Desktop)**

```shell
echo 'reject tcp any any <> any 22 (msg:"Drop SSH"; sid:1000001; rev:1;)' > local.rules
sudo snort -c local.rules -A full
```

## Task 3 Scenario 2 | Reverse-Shell

**First of all, start Snort in sniffer mode and try to figure out the attack source, service and port.**

```shell
sudo snort -X -n 1000 > snort.log
more snort.log
```

**Stop the attack and get the flag (which will appear on your Desktop)**

```shell
echo 'reject tcp any any <> any 4444 (msg:"Drop metasploit"; sid:1000001; rev:1;)' > local.rules
sudo snort -c local.rules -A full
```
