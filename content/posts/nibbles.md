
---
featured_image: "/posts/nibbles/nibbles.png"
title : HTB 2/20 Nibbles
published : true
date: 2021-04-11
author : PS
---

*Nmap*

```bash
Nmap scan report for 10.10.10.75
Host is up (0.081s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 c4:f8:ad:e8:f8:04:77:de:cf:15:0d:63:0a:18:7e:49 (RSA)
|   256 22:8f:b1:97:bf:0f:17:08:fc:7e:2c:8f:e9:77:3a:48 (ECDSA)
|_  256 e6:ac:27:a3:b5:a9:f1:12:3c:34:a5:5d:5b:eb:3d:e9 (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.29 seconds
```
Going on the port 80 :  

![test](1.png)
Seeing the page source we find an interesting directory:  

![test](2.png)

![test](3.png)
There we find that it runs Nibbleblog  

Before trying exploits , I ran some scans so I can get more info about the target  
```bash
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          10.10.10.75
+ Target Hostname:    10.10.10.75
+ Target Port:        80
+ Start Time:         2021-04-11 16:22:57 (GMT3)
---------------------------------------------------------------------------
+ Server: Apache/2.4.18 (Ubuntu)
+ Cookie PHPSESSID created without the httponly flag
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Allowed HTTP Methods: POST, OPTIONS, GET, HEAD 
+ Web Server returns a valid response with junk HTTP methods, this may cause false positives.
+ OSVDB-29786: /nibbleblog/admin.php?en_log_id=0&action=config: EasyNews from http://www.webrc.ca version 4.3 allows remote admin access. This PHP file should be protected.
+ OSVDB-29786: /nibbleblog/admin.php?en_log_id=0&action=users: EasyNews from http://www.webrc.ca version 4.3 allows remote admin access. This PHP file should be protected.
+ OSVDB-3268: /nibbleblog/admin/: Directory indexing found.
```
Now we exploit  : <https://www.rapid7.com/db/modules/exploit/multi/http/nibbleblog_file_upload/>
I saw that we need some creds, after some research :
![test](4.png)
We have the username but no password , so i guessed it :)) nibbles
I decided to abandon the msfconsole exploit since I couldn't figure it out how to configure it corectly  
So https://github.com/pentestmonkey/php-reverse-shell.git
![test](5.png)
Login with the creds
![test](6.png)
![test](7.png)
Settings before exploit :
![test](8.png)
Shell  after going on 

```bash 
http://10.10.10.75/nibbleblog/content/private/plugins/my_image/
```

![test](9.png)
Basic commands 
![test](11.png)

Interesting find!  
After grabbing the user.txt we will cat the file  
While grabbing the user i saw something interesting 
![test](12.png)
personal.zip ?? Oh PS is stupid again :)))
![test](13.png)
The script is pretty big and not important , the interesting thing is that it can run any command and not ask for the root passwd so :
![test](14.png)
And we get root on the other netcat
![test](15.png)
 PS out!
