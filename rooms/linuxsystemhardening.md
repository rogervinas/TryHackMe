# [Linux System Hardening](https://tryhackme.com/r/room/linuxsystemhardening)

## Task 3 Filesystem Partitioning and Encryption

**What is the flag in the secret vault?**

```shell
sudo cryptsetup open --type luks secretvault.img myvault && sudo mount /dev/mapper/myvault myvault/
cat myvault/task3_flag.txt
```
## Task 4 Firewall

**It is allowing another TCP port; what is it?**

```shell
sudo ufw status | grep ALLOW | grep tcp
```

**What is the allowed UDP port?**

```shell
sudo ufw status | grep ALLOW | grep udp
```

## Task 5 Remote Access

**What flag is hidden in the sshd_config file?**

```shell
grep THM /etc/ssh/sshd_config
```

## Task 6 Securing User Accounts

**Other than tryhackme and ubuntu, what is the username that belongs to the sudoers group?**

```shell
grep '^sudo' /etc/group
```

## Task 8 Update and Upgrade Policies

**What flag is hidden in the sources.list file?**

```shell
grep THM /etc/apt/sources.list
```

## Task 9 Audit and Log Configuration

**What command can you use to display the last 15 lines of kern.log?**

```shell
sudo tail -15 /var/log/kern.log
```

**What command can you use to display the lines containing the word denied in the file secure?**

```shell
sudo grep denied /var/log/secure
```
