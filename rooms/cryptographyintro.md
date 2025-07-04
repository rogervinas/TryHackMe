# [Introduction to Cryptography](https://tryhackme.com/r/room/cryptographyintro)

## Task 2 Symmetric Encryption

**Decrypt the file quote01 encrypted (using AES256) with the key s!kR3T55 using gpg.**
**What is the third word in the file?**

```shell
# rm -fR ~/.gnupg/ if passphrase does not work
cd ~/Rooms/cryptographyintro/task02
gpg --decrypt quote01.txt.gpg > quote01.txt
cat quote01.txt | awk '{print $3}'
```

**Decrypt the file quote02 encrypted (using AES256-CBC) with the key s!kR3T55 using openssl.**
**What is the third word in the file?**

```shell
cd ~/Rooms/cryptographyintro/task02
openssl aes-256-cbc -d -in quote02 -pass 'pass:s!kR3T55' 2>/dev/null | awk '{print $3}'
```

**Decrypt the file quote03 encrypted (using CAMELLIA256) with the key s!kR3T55 using gpg.**
**What is the third word in the file?**

```shell
# rm -fR ~/.gnupg/ if passphrase does not work
cd ~/Rooms/cryptographyintro/task02
gpg --decrypt quote03.txt.gpg > quote03.txt
cat quote03.txt | awk '{print $3}'
```

## Task 3 Asymmetric Encryption

**Bob has received the file ciphertext_message sent to him from Alice.**
**You can find the key you need in the same folder.**
**What is the first word of the original plaintext?**

```shell
cd ~/Rooms/cryptographyintro/task03
openssl pkeyutl -decrypt -in ciphertext_message -inkey private-key-bob.pem | head -1 | awk '{print $1}'
```

**Take a look at Bob’s private RSA key. What is the last byte of p?**

```shell
cd ~/Rooms/cryptographyintro/task03
openssl rsa -in private-key-bob.pem -text -noout | grep prime1: -A 9 | tail -1
```

**Take a look at Bob’s private RSA key. What is the last byte of q?**

```shell
cd ~/Rooms/cryptographyintro/task03
openssl rsa -in private-key-bob.pem -text -noout | grep prime2: -A 9 | tail -1
```

## Task 4 Diffie-Hellman Key Exchange

**A set of Diffie-Hellman parameters can be found in the file dhparam.pem.**
**What is the size of the prime number in bits?**

```shell
cd ~/Rooms/cryptographyintro/task04
openssl dhparam -in dhparams.pem -text -noout | grep "DH Parameters:"
```

**What is the prime number’s last byte (least significant byte)?**

```shell
cd ~/Rooms/cryptographyintro/task04
openssl dhparam -in dhparams.pem -text -noout | tail -2
```

## Task 5 Hashing

**What is the SHA256 checksum of the file order.json?**

```shell
cd ~/Rooms/cryptographyintro/task05
sha256sum order.json
```

**Open the file order.json and change the amount from 1000 to 9000. What is the new SHA256 checksum?**

```shell
cd ~/Rooms/cryptographyintro/task05
sed 's/1000/9000/' order.json | sha256sum
```

**Using SHA256 and the key 3RfDFz82, what is the HMAC of order.txt?**

```shell
cd ~/Rooms/cryptographyintro/task05
hmac256 3RfDFz82 order.txt
```

## Task 6 PKI and SSL/TLS

**What is the size of the public key in bits?**

```shell
cd ~/Rooms/cryptographyintro/task06
openssl x509 -in cert.pem --noout -text | grep Public-Key
```

**Till which year is this certificate valid?**

```shell
cd ~/Rooms/cryptographyintro/task06
openssl x509 -in cert.pem --noout --enddate
```

## Task 7 Authenticating with Passwords

**You were auditing a system when you discovered that the MD5 hash of the admin password is 3fc0a7acf087f549ac2b266baf94b8b1**
**What is the original password?**

* Alternative 1: use https://crackstation.net/ and submit the hash
* Alternative 2: use [hashcat](https://www.kali.org/tools/hashcat/):
  ```shell
  echo "3fc0a7acf087f549ac2b266baf94b8b1" > hash.txt
  hashcat -m 0 -a 0 hash.txt /usr/share/wordlists/rockyou.txt
  ```
