# [Disgruntled](https://tryhackme.com/r/room/disgruntled)

## Task 3 Nothing suspicious... So far

**The user installed a package on the machine using elevated privileges. According to the logs, what is the full COMMAND?**
**What was the present working directory (PWD) when the previous command was run?**

```shell
grep apt /home/cybert/.bash_history
```

## Task 4 Let’s see if you did anything bad

**Which user was created after the package from the previous task was installed?**

```shell
grep adduser /home/cybert/.bash_history
```

**When was the sudoers file updated?**

```shell
grep visudo /var/log/auth.log | grep cybert
```

**A script file was opened using the "vi" text editor. What is the name of this file?**

```shell
grep /usr/bin/vi /var/log/auth.log
```

## Task 5 Bomb has been planted. But when and where?

**What is the command used that created the file bomb.sh?**

```shell
grep bomb /home/it-admin/.bash_history
```

**What is the full path of this file now?**

```shell
grep :saveas /home/it-admin/.viminfo
```

**When was the file from the previous question last modified?**

```shell
SAVEAS_TIMESTAMP=$(grep \"saveas /home/it-admin/.viminfo | awk -F, '{print $3}')
date -d @$SAVEAS_TIMESTAMP +"%b %d %H:%M"
```

**What is the name of the file that will get created when the file from the first question executes?**

```shell
grep -E '> .+' /bin/os-update.sh
```

## Task 6 Following the fuse

**At what time will the malicious file trigger?**

```shell
grep os-update.sh /etc/crontab
```
