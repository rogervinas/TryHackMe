# [Auditing and Monitoring](https://tryhackme.com/r/room/auditingandmonitoringse)

## Task 6 Log Management on Linux

**Using aureport, how many failed logins have occurred so far?**

```shell
aureport | grep "Number of failed logins"
```

**Using ausearch, how many failed logins are related to the username mike?**

```shell
ausearch -m USER_LOGIN -sv no -i | grep acct=mike | wc -l
```

**Using ausearch, how many failed logins are related to the username root?**

```shell
ausearch -m USER_LOGIN -sv no -i | grep acct=root | wc -l
```
