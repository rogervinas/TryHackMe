# [Network Device Hardening](https://tryhackme.com/r/room/networkdevicehardening)

## Task 4 Hardening Virtual Private Networks

**Update the config file to use cipher AES-128-CBC. What is the flag value linked with the cipher directive?**

```shell
sudo sed -i 's/cipher AES-256-CBC/cipher AES-128-CBC/' /etc/openvpn/server/server.conf
grep cipher /etc/openvpn/server/server.conf
```

**Update the config file to use auth SHA512. What is the flag value linked with the auth directive?**

```shell
sudo sed -i 's/auth SHA256/auth SHA512/' /etc/openvpn/server/server.conf
grep auth /etc/openvpn/server/server.conf
```

**As per the config file, what is the port number for the OpenVPN server?**

```shell
grep port /etc/openvpn/server/server.conf
```

## Task 5 Hardening Routers, Switches & Firewalls

**Update the password of the router to TryHackMe123**

* Go to http://MACHINE_IP:8080
* User root, password TryHackMe
* Go to System > Administration > Router Password
* Change password to TryHackMe123 and Save
* Confirmation message is "The system password has been successfully changed"

**What is the default SSH port configured for OpenWrt in the attached VM?**

* Go to System > Administration > SSH Access
* Check Port

**Go through the General Settings option under the System tab in the attached VM. The administrator has left a special message in the Notes section. What is the flag value?**

* Go to System > System > General Settings
* Check Notes

**What is the default system log buffer size value for the OpenWrt router in the attached VM?**

* Go to System > System > Logging
* Check System log buffer size

**What is the start priority for the script uhttpd?**

* Go to System > Startup > Initscripts
* Check Initscript = uhttpd

## Task 6 Hardening Routers, Switches & Firewalls - More Techniques

**What is the name of the rule that accepts ICMP traffic from source zone WAN and destination zone as this device?**

* Go to Network > Firewall > Traffic Rules
* Search rule with: Incoming IPv4 protocol ICMP From wan To this device

**What is the name of the rule that forwards data coming from WAN port 9001 to LAN port 9002?**

* Go to Network > Firewall > Port Forwards
* Search rule with: Incoming IPv4 From wan To this device port 9001 Forward to lan port 9002

**What is the version number for the available apk package?**

* Go to System > Software
* Search package apk
