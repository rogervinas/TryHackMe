# [Slingshot](https://tryhackme.com/room/slingshot)

## Task 2: The Slingshot Investigation

1. Ensure you're using the `apache_logs` Data view
2. Set the time frame from `Jul 26, 2023 @ 00:00:00.000 → now`

### What is the attacker's IP address?

apache_logs > Break down by `transaction.remote_address`

The one with more hits is `10.0.2.15`

### What is the first scanner that the attacker ran against the web server?

apache_logs > Filter by:
```
transaction.remote_address: 10.0.2.15
```

### What is the User Agent of the directory enumeration tool that the attacker used on the web server?

apache_logs > Filter by:
```
transaction.remote_address: 10.0.2.15
```

### In total, how many 404 responses did the attacker receive when enumerating the web server?

apache_logs > Filter by:
```
transaction.remote_address: 10.0.2.15 AND response.status: 404
```

### What flag was discovered in one of the directories identified during enumeration?

apache_logs > Filter by:
```
transaction.remote_address: 10.0.2.15 AND request.headers.User-Agent: "Mozilla/5.0 (Gobuster)" AND NOT response.status: 404 AND message: flag
```

### What login page did the attacker discover using the directory enumeration tool?

apache_logs > Filter by:
```
transaction.remote_address: 10.0.2.15 AND request.headers.User-Agent: "Mozilla/5.0 (Gobuster)" AND NOT response.status: 404 AND message: login
```

### What is the User-Agent of the brute-force tool that the attacker used on the admin panel?

apache_logs > Filter by:
```
transaction.remote_address: 10.0.2.15 AND http.url: /admin-login.php AND response.status: 401
```

### What username:password combination did the attacker use to gain access to the admin page?

apache_logs > Filter by:
```
transaction.remote_address: 10.0.2.15 AND http.url: /admin-login.php AND NOT response.status: 401
```

Find the `Authorization":"Basic xxxx"` header and Base64 decode it:
```shell
echo xxxx | base64 -d
```

### What flag was included in the file that the attacker uploaded to the /admin/upload.php directory?

apache_logs > Filter by:
```
transaction.remote_address: 10.0.2.15 AND http.url: /admin/upload.php* AND http.method: POST
```

### What was the first command the attacker ran using the web shell?

apache_logs > Filter by:
```
transaction.remote_address: 10.0.2.15 AND http.url: /uploads/easy-simple-php-webshell.php?cmd=* AND http.method: GET
```

Check the value of the `cmd` query parameter.

### Which file was accessed via Local File Inclusion (LFI) to retrieve database credentials?

apache_logs > Filter by:
```
transaction.remote_address: 10.0.2.15 AND message: config-db.php
```

### What is the name of the database the attacker exported via /phpmyadmin?

apache_logs > Filter by:
```
transaction.remote_address: 10.0.2.15 AND http.url: /phpmyadmin/* AND message: db=
```

### What flag does the attacker insert into the database using import.php?

apache_logs > Filter by:
```
transaction.remote_address: 10.0.2.15 AND http.url: /import.php
```

Check the INSERT statement.
