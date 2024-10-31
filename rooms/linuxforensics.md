# [Linux Forensics](https://tryhackme.com/r/room/linuxforensics)

## Task 3 OS and account information

**Which two users are the members of the group audio?**

```shell
getent group audio
```

**What is the uid of this account?**

```shell
id -u tryhackme
```

**How long did this session last?**

```shell
sudo last -f /var/log/wtmp | grep "Sat Apr 16 20:10 -"
```

## Task 4 System Configuration

**What is the hostname of the attached VM?**

```shell
hostname
```

**What is the timezone of the attached VM?**

```shell
cat /etc/timezone
```

**What program is listening on the address 127.0.0.1:5901?**

```shell
sudo netstat -natp | grep 127.0.0.1:5901 | grep LISTEN
```

**What is the full path of this program?**

```shell
ps -fe | grep Xtigervnc
```

## Task 5 Persistence mechanisms

**What is the size of the history file that is set for the user Ubuntu in the attached machine?**

```shell
grep HISTFILESIZE /home/ubuntu/.bashrc
```

## Task 6 Evidence of Execution

**What was the command that was issued?**

```shell
sudo grep apt-get /home/tryhackme/.bash_history
```

**What was the current working directory when the command to install net-tools was issued?**

```shell
grep "apt-get install net-tools" /var/log/auth.log* | grep -o 'PWD=[^;]*;'
```

## Task 7 Log files

**What was the previous hostname of the machine?**

```shell
mkdir /tmp/syslog
cp /var/log/syslog* /tmp/syslog
for file in /tmp/syslog/syslog.*.gz; do gzip -d $file; done
cat /tmp/syslog/syslog* | awk '{print $1" "$2" "$4}' | sort -u
```
